import abc
import requests
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone
from app.config import settings
from app.database import get_db_connection
from app.services.audit_log import audit_logger

logger = logging.getLogger("netsentinel.router")

class BaseRouterAdapter(abc.ABC):
    """Abstract base class for all router adapters."""

    @abc.abstractmethod
    def inspect_capabilities(self, gateway_ip: str) -> Dict[str, Any]:
        """Inspect and return verified router model, web server, and automation capability."""
        pass

    @abc.abstractmethod
    def test_connection(self, gateway_ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str]:
        """Verify reachability and authentication to router management interface."""
        pass

    @abc.abstractmethod
    def block_device(self, mac_address: str, ip_address: Optional[str] = None, device_name: Optional[str] = None) -> Dict[str, Any]:
        """Apply access-control restriction to block a device."""
        pass

    @abc.abstractmethod
    def unblock_device(self, mac_address: str) -> Dict[str, Any]:
        """Remove access-control restriction to restore a device."""
        pass

    @abc.abstractmethod
    def get_active_rules(self) -> List[Dict[str, Any]]:
        """Retrieve confirmed access-control rules."""
        pass


class DbcHguAdapter(BaseRouterAdapter):
    """
    Adapter specifically designed for DBC HGU-V210-4AC GPON/EPON ONT Router.
    Default administration address: http://192.168.1.1
    """

    def __init__(self):
        self.router_model = "DBC HGU-V210-4AC"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "NetSentinel/1.0 (Windows 11)"})
        # Disable slow retry loops when host is offline or in sandbox
        adapter = requests.adapters.HTTPAdapter(max_retries=0)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def inspect_capabilities(self, gateway_ip: str) -> Dict[str, Any]:
        url = f"http://{gateway_ip}"
        capabilities = {
            "model": self.router_model,
            "gateway_url": url,
            "http_reachable": False,
            "server_header": "Unknown",
            "auth_type": "Web Form Login",
            "access_control_support": "MAC Filter (Blacklist / Whitelist)",
            "automated_api_verified": False,
            "status_message": "Inspection pending"
        }

        try:
            resp = self.session.get(url, timeout=1.5)
            capabilities["http_reachable"] = True
            capabilities["server_header"] = resp.headers.get("Server", "Embedded Web Server")
            text = resp.text.lower()
            
            if "dbc" in text or "hgu" in text or "gpon" in text or "epon" in text:
                capabilities["status_message"] = "Verified DBC ONT Router web management interface."
            else:
                capabilities["status_message"] = "Web interface detected, manual login required."
        except Exception as e:
            capabilities["http_reachable"] = False
            capabilities["status_message"] = f"Router at {gateway_ip} unreachable or blocked by firewall: {e}"

        return capabilities

    def test_connection(self, gateway_ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str]:
        url = f"http://{gateway_ip}"
        try:
            resp = self.session.get(url, timeout=1.5)
            if resp.status_code == 200:
                if not username or not password:
                    return True, "Router web interface is reachable. Admin credentials required for access control."
                return True, "Router reachable. Credentials stored for manual guided assistance."
            return False, f"Router returned HTTP {resp.status_code}"
        except Exception as e:
            return False, f"Could not connect to {url}: {e}"

    def block_device(self, mac_address: str, ip_address: Optional[str] = None, device_name: Optional[str] = None) -> Dict[str, Any]:
        # DBC HGU-V210-4AC requires authenticated administrative web session to modify NVRAM MAC filter table.
        # Fallback to Manual Workflow with exact instructions to ensure safety and zero risk of misconfiguration.
        return {
            "success": False,
            "mode": "manual_required",
            "message": (
                f"Automatic blocking on DBC HGU-V210-4AC requires router firmware API authentication. "
                f"Please apply rule manually in router interface at http://{settings.ROUTER_GATEWAY} "
                f"under Security -> MAC Filter."
            ),
            "mac_address": mac_address,
            "ip_address": ip_address
        }

    def unblock_device(self, mac_address: str) -> Dict[str, Any]:
        return {
            "success": False,
            "mode": "manual_required",
            "message": (
                f"Please remove MAC {mac_address} from router MAC Filter table at "
                f"http://{settings.ROUTER_GATEWAY} under Security -> MAC Filter."
            ),
            "mac_address": mac_address
        }

    def get_active_rules(self) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM router_rules ORDER BY timestamp DESC").fetchall()
            return [dict(r) for r in rows]


class MockRouterAdapter(BaseRouterAdapter):
    """
    Mock router adapter for automated tests, offline environments, and dry runs.
    """
    def __init__(self):
        self.rules: Dict[str, Dict[str, Any]] = {}

    def inspect_capabilities(self, gateway_ip: str) -> Dict[str, Any]:
        return {
            "model": "DBC HGU-V210-4AC (Test Mode)",
            "gateway_url": f"http://{gateway_ip}",
            "http_reachable": True,
            "server_header": "DBC-Embedded-Http/2.1",
            "auth_type": "Session Cookie / Form",
            "access_control_support": "MAC Filter (Blacklist Mode)",
            "automated_api_verified": True,
            "status_message": "Mock Router operational for validation and testing."
        }

    def test_connection(self, gateway_ip: str, username: Optional[str] = None, password: Optional[str] = None) -> Tuple[bool, str]:
        return True, "Mock router connected successfully."

    def block_device(self, mac_address: str, ip_address: Optional[str] = None, device_name: Optional[str] = None) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        self.rules[mac_address] = {
            "mac_address": mac_address,
            "ip_address": ip_address,
            "action": "block",
            "status": "verified",
            "timestamp": now_iso
        }
        return {
            "success": True,
            "mode": "automated",
            "message": f"Successfully applied block rule for MAC {mac_address} on router.",
            "rule": self.rules[mac_address]
        }

    def unblock_device(self, mac_address: str) -> Dict[str, Any]:
        if mac_address in self.rules:
            del self.rules[mac_address]
        return {
            "success": True,
            "mode": "automated",
            "message": f"Successfully removed block rule for MAC {mac_address} on router."
        }

    def get_active_rules(self) -> List[Dict[str, Any]]:
        return list(self.rules.values())


class RouterService:
    def __init__(self):
        self.adapter: BaseRouterAdapter = DbcHguAdapter()
        self.use_mock: bool = False

    def set_mock_mode(self, enabled: bool) -> None:
        self.use_mock = enabled
        self.adapter = MockRouterAdapter() if enabled else DbcHguAdapter()

    def get_status(self) -> Dict[str, Any]:
        caps = self.adapter.inspect_capabilities(settings.ROUTER_GATEWAY)
        conn_ok, msg = self.adapter.test_connection(settings.ROUTER_GATEWAY)
        return {
            "router_model": settings.ROUTER_MODEL,
            "gateway_ip": settings.ROUTER_GATEWAY,
            "connection_status": "online" if conn_ok else "unreachable",
            "integration_mode": "mock" if self.use_mock else "dbc_hgu_guided",
            "capabilities": caps,
            "active_rules": self.get_active_db_rules(),
            "message": msg
        }

    def validate_safety(self, mac_address: str, ip_address: Optional[str], client_ip: Optional[str]) -> Tuple[bool, str]:
        """
        Enforce strict safety guards:
        - NEVER block the default gateway (192.168.1.1).
        - NEVER block the host machine's own IP/MAC.
        - NEVER block the client making the request.
        """
        from app.services.discovery import discovery_service
        net_info = discovery_service.net_info

        # Check Gateway
        if ip_address and ip_address == net_info.gateway:
            return False, f"SAFETY GUARD: Cannot block the default gateway router ({ip_address})."

        # Check Host Laptop IP & MAC
        if ip_address and ip_address == net_info.ip_address:
            return False, f"SAFETY GUARD: Cannot block the host monitoring server ({ip_address})."
        if mac_address and mac_address.lower() == net_info.mac_address.lower():
            return False, f"SAFETY GUARD: Cannot block the host server physical MAC ({mac_address})."

        # Check Client IP (if different from host)
        if client_ip and ip_address and client_ip == ip_address:
            return False, f"SAFETY GUARD: Cannot block your own management device ({client_ip})."

        return True, "Safety checks passed."

    def block_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        device_name: Optional[str] = None,
        confirmed: bool = False,
        client_ip: Optional[str] = None,
        actor: str = "admin"
    ) -> Dict[str, Any]:
        if not confirmed:
            return {
                "success": False,
                "error": "Explicit user confirmation is required before modifying router access-control rules."
            }

        is_safe, safety_msg = self.validate_safety(mac_address, ip_address, client_ip)
        if not is_safe:
            audit_logger.log_event("BLOCK_DEVICE_REFUSED", actor=actor, target=mac_address, details=safety_msg, success=False)
            return {"success": False, "error": safety_msg}

        result = self.adapter.block_device(mac_address, ip_address, device_name)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Update database rule and device state
        rule_status = "verified" if result.get("success") else "manual_required"
        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO router_rules (mac_address, ip_address, action, status, rule_type, details, timestamp)
                VALUES (?, ?, 'block', ?, 'denylist', ?, ?)
            """, (mac_address, ip_address, rule_status, result.get("message"), now_iso))

            conn.execute("""
                UPDATE devices
                SET block_status = ?
                WHERE mac_address = ? OR ip_address = ?
            """, ("blocked" if result.get("success") else "manual_rule", mac_address, ip_address))
            conn.commit()

        audit_logger.log_event(
            "BLOCK_DEVICE",
            actor=actor,
            target=mac_address,
            details=f"Block applied: status={rule_status}, msg={result.get('message')}",
            success=result.get("success", False) or rule_status == "manual_required"
        )
        return result

    def unblock_device(
        self,
        mac_address: str,
        ip_address: Optional[str] = None,
        confirmed: bool = False,
        actor: str = "admin"
    ) -> Dict[str, Any]:
        if not confirmed:
            return {"success": False, "error": "Explicit confirmation required."}

        result = self.adapter.unblock_device(mac_address)
        now_iso = datetime.now(timezone.utc).isoformat()

        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO router_rules (mac_address, ip_address, action, status, rule_type, details, timestamp)
                VALUES (?, ?, 'unblock', ?, 'denylist', ?, ?)
            """, (mac_address, ip_address, "verified" if result.get("success") else "manual_required", result.get("message"), now_iso))

            conn.execute("""
                UPDATE devices
                SET block_status = 'unblocked'
                WHERE mac_address = ? OR ip_address = ?
            """, (mac_address, ip_address))
            conn.commit()

        audit_logger.log_event(
            "UNBLOCK_DEVICE",
            actor=actor,
            target=mac_address,
            details=f"Unblock requested: msg={result.get('message')}",
            success=True
        )
        return result

    def get_active_db_rules(self) -> List[Dict[str, Any]]:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT * FROM router_rules ORDER BY id DESC LIMIT 50").fetchall()
            return [dict(r) for r in rows]

router_service = RouterService()
