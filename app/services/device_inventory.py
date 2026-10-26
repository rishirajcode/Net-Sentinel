import csv
import io
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from app.database import get_db_connection

logger = logging.getLogger("netsentinel.inventory")

class DeviceInventoryService:
    @staticmethod
    def get_devices(
        status_filter: Optional[str] = None,
        classification_filter: Optional[str] = None,
        blocked_filter: Optional[bool] = None,
        search_query: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Fetch devices with optional filtering and search."""
        query = "SELECT * FROM devices WHERE 1=1"
        params: List[Any] = []

        if status_filter and status_filter.lower() != "all":
            query += " AND status = ?"
            params.append(status_filter.lower())

        if classification_filter and classification_filter.lower() != "all":
            query += " AND classification = ?"
            params.append(classification_filter.lower())

        if blocked_filter is not None:
            if blocked_filter:
                query += " AND block_status IN ('blocked', 'manual_rule')"
            else:
                query += " AND block_status = 'unblocked'"

        if search_query:
            q = f"%{search_query.strip().lower()}%"
            query += """ AND (
                LOWER(ip_address) LIKE ? OR
                LOWER(COALESCE(mac_address, '')) LIKE ? OR
                LOWER(COALESCE(hostname, '')) LIKE ? OR
                LOWER(COALESCE(custom_name, '')) LIKE ? OR
                LOWER(COALESCE(vendor, '')) LIKE ? OR
                LOWER(COALESCE(device_type, '')) LIKE ?
            )"""
            params.extend([q, q, q, q, q, q])

        query += " ORDER BY is_gateway DESC, is_host DESC, ip_address ASC"

        with get_db_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    @staticmethod
    def get_device_by_id(device_id: int) -> Optional[Dict[str, Any]]:
        """Fetch single device with full history of observations and past IPs."""
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
            if not row:
                return None
            device = dict(row)

            # Observations
            obs_rows = conn.execute("""
                SELECT id, scan_id, ip_address, mac_address, hostname, response_time_ms, timestamp
                FROM device_observations
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT 50
            """, (device_id,)).fetchall()
            device["observations"] = [dict(r) for r in obs_rows]

            # IP History
            ip_rows = conn.execute("""
                SELECT DISTINCT ip_address
                FROM device_observations
                WHERE device_id = ?
                ORDER BY timestamp DESC
            """, (device_id,)).fetchall()
            device["ip_history"] = [r["ip_address"] for r in ip_rows]

            return device

    @staticmethod
    def update_device(
        device_id: int,
        custom_name: Optional[str] = None,
        classification: Optional[str] = None,
        notes: Optional[str] = None,
        device_type: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Update user-defined metadata on a device."""
        fields = []
        params = []

        if custom_name is not None:
            fields.append("custom_name = ?")
            params.append(custom_name.strip() if custom_name else None)

        if classification is not None:
            c = classification.lower()
            if c not in ("trusted", "unknown"):
                raise ValueError("Classification must be 'trusted' or 'unknown'")
            fields.append("classification = ?")
            params.append(c)

        if notes is not None:
            fields.append("notes = ?")
            params.append(notes.strip() if notes else None)

        if device_type is not None:
            fields.append("device_type = ?")
            params.append(device_type.strip() if device_type else "Unclassified Device")

        if not fields:
            return DeviceInventoryService.get_device_by_id(device_id)

        params.append(device_id)
        with get_db_connection() as conn:
            conn.execute(f"UPDATE devices SET {', '.join(fields)} WHERE id = ?", params)
            conn.commit()

        return DeviceInventoryService.get_device_by_id(device_id)

    @staticmethod
    def get_summary_metrics(router_status_str: str = "Unavailable") -> Dict[str, Any]:
        """Aggregate 8 key summary cards for the dashboard."""
        with get_db_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            online = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'online'").fetchone()[0]
            offline = conn.execute("SELECT COUNT(*) FROM devices WHERE status = 'offline'").fetchone()[0]
            trusted = conn.execute("SELECT COUNT(*) FROM devices WHERE classification = 'trusted'").fetchone()[0]
            unknown = conn.execute("SELECT COUNT(*) FROM devices WHERE classification = 'unknown'").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM devices WHERE block_status IN ('blocked', 'manual_rule')").fetchone()[0]

            last_scan_row = conn.execute("""
                SELECT * FROM scans WHERE status = 'completed' ORDER BY id DESC LIMIT 1
            """).fetchone()

            last_scan = dict(last_scan_row) if last_scan_row else None

        return {
            "total_discovered": total,
            "online_devices": online,
            "offline_devices": offline,
            "trusted_devices": trusted,
            "unknown_devices": unknown,
            "blocked_devices": blocked,
            "most_recent_scan": last_scan,
            "router_status": router_status_str
        }

    @staticmethod
    def export_csv() -> str:
        """Generates RFC 4180 CSV representation of device inventory."""
        devices = DeviceInventoryService.get_devices()
        output = io.StringIO()
        fieldnames = [
            "id", "ip_address", "mac_address", "hostname", "custom_name",
            "vendor", "device_type", "status", "classification",
            "block_status", "first_seen", "last_seen", "notes"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for d in devices:
            writer.writerow(d)
        return output.getvalue()

device_inventory = DeviceInventoryService()
