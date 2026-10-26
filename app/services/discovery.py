import os
import shutil
import socket
import struct
import subprocess
import ipaddress
import xml.etree.ElementTree as ET
import ctypes
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path

from app.config import detect_windows_network, settings
from app.database import get_db_connection
from app.services.vendor import vendor_service

logger = logging.getLogger("netsentinel.discovery")

def get_nmap_path() -> Optional[str]:
    """Check if nmap binary is available in PATH or common Windows directories."""
    path = shutil.which("nmap")
    if path:
        return path
    
    common_win_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Nmap\nmap.exe")
    ]
    for p in common_win_paths:
        if os.path.isfile(p):
            return p
    return None

class DiscoveredHost:
    def __init__(
        self,
        ip: str,
        mac: Optional[str] = None,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        response_time_ms: Optional[float] = None
    ):
        self.ip = ip
        self.mac = vendor_service.normalize_mac(mac)
        self.hostname = hostname
        self.vendor = vendor or (vendor_service.lookup_vendor(self.mac) if self.mac else None)
        self.response_time_ms = response_time_ms

def windows_send_arp(ip_str: str) -> Optional[str]:
    """
    Query MAC address via Windows Win32 SendARP API in iphlpapi.dll.
    Returns normalized MAC or None.
    """
    try:
        dest_ip = struct.unpack('<I', socket.inet_aton(ip_str))[0]
        mac_buffer = (ctypes.c_byte * 6)()
        mac_len = ctypes.c_ulong(6)
        res = ctypes.windll.iphlpapi.SendARP(dest_ip, 0, ctypes.byref(mac_buffer), ctypes.byref(mac_len))
        if res == 0:
            return ':'.join(f'{b & 0xff:02x}' for b in bytearray(mac_buffer))
    except Exception:
        pass
    return None

def probe_single_ip(ip_str: str) -> Optional[DiscoveredHost]:
    """
    Probes a single IP address using fast Win32 SendARP API.
    Returns DiscoveredHost if reachable, else None.
    """
    t0 = time.perf_counter()
    mac = windows_send_arp(ip_str)
    
    if mac and mac != "00:00:00:00:00:00":
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        # Attempt quick reverse DNS lookup
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except Exception:
            pass
        return DiscoveredHost(ip=ip_str, mac=mac, hostname=hostname, response_time_ms=elapsed_ms)
    
    return None

class DiscoveryService:
    def __init__(self):
        self.net_info = detect_windows_network()

    def get_network_info(self) -> Dict[str, Any]:
        """Returns detected network parameters and tool availability."""
        self.net_info = detect_windows_network()
        nmap_path = get_nmap_path()
        return {
            "host_ip": self.net_info.ip_address,
            "host_mac": self.net_info.mac_address,
            "gateway_ip": self.net_info.gateway,
            "subnet": self.net_info.subnet,
            "nmap_installed": nmap_path is not None,
            "nmap_path": nmap_path,
        }

    def scan_with_native_engine(self, network_cidr: str) -> List[DiscoveredHost]:
        """High-concurrency native Windows ARP & ICMP host discovery."""
        net = ipaddress.IPv4Network(network_cidr, strict=False)
        hosts = [str(ip) for ip in net.hosts()]
        results: List[DiscoveredHost] = []

        max_workers = min(64, max(10, len(hosts)))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_ip = {executor.submit(probe_single_ip, ip): ip for ip in hosts}
            for future in as_completed(future_to_ip):
                host = future.result()
                if host:
                    results.append(host)

        # Ensure the host machine itself is present if within this subnet
        host_ip = self.net_info.ip_address
        if any(ipaddress.IPv4Address(host_ip) in net.hosts() or ipaddress.IPv4Address(host_ip) == net.network_address for _ in [1]):
            if not any(h.ip == host_ip for h in results):
                results.append(DiscoveredHost(
                    ip=host_ip,
                    mac=self.net_info.mac_address,
                    hostname=socket.gethostname(),
                    response_time_ms=0.1
                ))

        return results

    def scan_with_nmap(self, network_cidr: str) -> List[DiscoveredHost]:
        """Executes Nmap host-discovery scan with safe XML output parsing."""
        nmap_bin = get_nmap_path()
        if not nmap_bin:
            raise FileNotFoundError("Nmap executable not found in PATH or standard directories.")

        # Safe subprocess execution with array arguments (no shell=True)
        # -sn: Ping Scan (disable port scan)
        # -PR: ARP ping (local network)
        # -PE: ICMP echo ping
        # -oX -: Output XML to stdout
        cmd = [nmap_bin, "-sn", "-PR", "-PE", "-oX", "-", network_cidr]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.SCAN_TIMEOUT_SEC * 2, check=False)
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError(f"Nmap scan failed: {proc.stderr}")

        results: List[DiscoveredHost] = []
        try:
            root = ET.fromstring(proc.stdout)
            for host_elem in root.findall("host"):
                status = host_elem.find("status")
                if status is None or status.get("state") != "up":
                    continue

                ip_str = None
                mac_str = None
                vendor_str = None
                for addr in host_elem.findall("address"):
                    addr_type = addr.get("addrtype")
                    if addr_type == "ipv4":
                        ip_str = addr.get("addr")
                    elif addr_type == "mac":
                        mac_str = addr.get("addr")
                        vendor_str = addr.get("vendor")

                hostname_str = None
                hostnames = host_elem.find("hostnames")
                if hostnames is not None:
                    first_hn = hostnames.find("hostname")
                    if first_hn is not None:
                        hostname_str = first_hn.get("name")

                if ip_str:
                    results.append(DiscoveredHost(
                        ip=ip_str,
                        mac=mac_str,
                        hostname=hostname_str,
                        vendor=vendor_str
                    ))
        except ET.ParseError as e:
            raise RuntimeError(f"Failed to parse Nmap XML output: {e}")

        return results

    def run_scan(self, subnet: Optional[str] = None, engine_preference: str = "auto") -> Dict[str, Any]:
        """
        Executes a network scan, updates SQLite device inventory,
        computes new/offline deltas, and stores audit & history entries.
        """
        self.net_info = detect_windows_network()
        target_subnet = subnet or self.net_info.subnet
        
        # Validate RFC 1918 safety
        net = ipaddress.IPv4Network(target_subnet, strict=False)
        if not net.is_private and not net.is_loopback:
            raise ValueError(f"Scanning target {target_subnet} rejected: Only private subnets are permitted.")

        start_time = datetime.now(timezone.utc).isoformat()
        engine_used = "windows_arp"
        nmap_available = get_nmap_path() is not None

        # Create scan record in DB
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scans (start_time, subnet, engine_used, status)
                VALUES (?, ?, ?, 'running')
            """, (start_time, target_subnet, engine_preference))
            scan_id = cursor.lastrowid
            conn.commit()

        discovered_hosts: List[DiscoveredHost] = []
        scan_error: Optional[str] = None

        try:
            if engine_preference == "nmap" or (engine_preference == "auto" and nmap_available):
                try:
                    discovered_hosts = self.scan_with_nmap(target_subnet)
                    engine_used = "nmap"
                except Exception as ex:
                    logger.warning("Nmap scan failed (%s), falling back to Windows Native ARP engine.", ex)
                    discovered_hosts = self.scan_with_native_engine(target_subnet)
                    engine_used = "windows_arp_fallback"
            else:
                discovered_hosts = self.scan_with_native_engine(target_subnet)
                engine_used = "windows_arp"

        except Exception as ex:
            scan_error = str(ex)
            logger.error("Scan error on subnet %s: %s", target_subnet, ex)
            with get_db_connection() as conn:
                conn.execute("""
                    UPDATE scans
                    SET end_time = ?, status = 'failed', error_message = ?
                    WHERE id = ?
                """, (datetime.now(timezone.utc).isoformat(), scan_error, scan_id))
                conn.commit()
            raise

        end_time = datetime.now(timezone.utc).isoformat()
        
        # Reconcile discovered hosts with SQLite inventory
        new_count = 0
        now_iso = end_time

        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Fetch all existing devices
            existing_rows = cursor.execute("SELECT * FROM devices").fetchall()
            existing_by_mac = {r["mac_address"]: dict(r) for r in existing_rows if r["mac_address"]}
            existing_by_ip = {r["ip_address"]: dict(r) for r in existing_rows}

            seen_device_ids = set()

            for h in discovered_hosts:
                # Identify if this is gateway or host
                is_gw = (h.ip == self.net_info.gateway)
                is_host_lap = (h.ip == self.net_info.ip_address)
                
                # Check vendor & device classification
                vendor = h.vendor or vendor_service.lookup_vendor(h.mac)
                dev_type = vendor_service.classify_device(
                    vendor=vendor,
                    hostname=h.hostname,
                    is_gateway=is_gw,
                    is_host=is_host_lap
                )

                dev_id = None
                # Match by MAC address first, or IP
                matched_row = None
                if h.mac and h.mac in existing_by_mac:
                    matched_row = existing_by_mac[h.mac]
                elif h.ip in existing_by_ip:
                    matched_row = existing_by_ip[h.ip]

                if matched_row:
                    dev_id = matched_row["id"]
                    seen_device_ids.add(dev_id)
                    # Update dynamic fields while preserving custom_name, classification, notes
                    cursor.execute("""
                        UPDATE devices
                        SET ip_address = ?,
                            hostname = COALESCE(?, hostname),
                            vendor = COALESCE(?, vendor),
                            status = 'online',
                            last_seen = ?,
                            is_gateway = ?,
                            is_host = ?
                        WHERE id = ?
                    """, (h.ip, h.hostname, vendor, now_iso, 1 if is_gw else 0, 1 if is_host_lap else 0, dev_id))
                else:
                    # New device
                    new_count += 1
                    cursor.execute("""
                        INSERT INTO devices (
                            ip_address, mac_address, hostname, custom_name,
                            vendor, device_type, status, classification,
                            notes, first_seen, last_seen, block_status,
                            is_gateway, is_host
                        ) VALUES (?, ?, ?, NULL, ?, ?, 'online', 'unknown', NULL, ?, ?, 'unblocked', ?, ?)
                    """, (
                        h.ip, h.mac, h.hostname, vendor, dev_type,
                        now_iso, now_iso, 1 if is_gw else 0, 1 if is_host_lap else 0
                    ))
                    dev_id = cursor.lastrowid
                    seen_device_ids.add(dev_id)

                # Record observation
                cursor.execute("""
                    INSERT INTO device_observations (
                        device_id, scan_id, ip_address, mac_address, hostname, response_time_ms, timestamp
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (dev_id, scan_id, h.ip, h.mac, h.hostname, h.response_time_ms, now_iso))

            # Mark devices in the same subnet that were not seen as 'offline'
            offline_count = 0
            for r in existing_rows:
                if r["id"] not in seen_device_ids:
                    try:
                        # Check if device belongs to scanned subnet
                        if ipaddress.IPv4Address(r["ip_address"]) in net:
                            cursor.execute("UPDATE devices SET status = 'offline' WHERE id = ?", (r["id"],))
                            offline_count += 1
                    except Exception:
                        pass

            # Update scan record
            cursor.execute("""
                UPDATE scans
                SET end_time = ?,
                    engine_used = ?,
                    devices_found = ?,
                    new_devices = ?,
                    offline_devices = ?,
                    status = 'completed'
                WHERE id = ?
            """, (end_time, engine_used, len(discovered_hosts), new_count, offline_count, scan_id))

            # Add audit log
            cursor.execute("""
                INSERT INTO audit_logs (timestamp, action, actor, target, details, success)
                VALUES (?, 'SCAN_COMPLETED', 'system', ?, ?, 1)
            """, (now_iso, target_subnet, f"Found {len(discovered_hosts)} devices ({new_count} new, {offline_count} offline) using {engine_used}"))

            conn.commit()

        return {
            "scan_id": scan_id,
            "subnet": target_subnet,
            "engine_used": engine_used,
            "devices_found": len(discovered_hosts),
            "new_devices": new_count,
            "offline_devices": offline_count,
            "status": "completed",
            "start_time": start_time,
            "end_time": end_time
        }

discovery_service = DiscoveryService()
