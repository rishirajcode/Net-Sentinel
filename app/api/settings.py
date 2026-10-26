from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends
from app.config import settings
from app.database import get_setting, set_setting, backup_database
from app.services.vendor import vendor_service
from app.services.discovery import discovery_service, get_nmap_path
from app.services.audit_log import audit_logger
from app.models import SettingsUpdateRequest, AuditLogResponse
from app.api.auth import require_auth

router = APIRouter(prefix="/api/settings", tags=["Settings"])

@router.get("")
def get_app_settings():
    """Retrieve application configuration, network targets, and status."""
    net_info = discovery_service.get_network_info()
    lan_enabled = get_setting("lan_access_enabled", "false").lower() == "true"
    
    return {
        "app_name": settings.APP_NAME,
        "app_version": settings.APP_VERSION,
        "developer": settings.DEVELOPER,
        "tagline": settings.APP_TAGLINE,
        "router_gateway": get_setting("router_gateway", settings.ROUTER_GATEWAY),
        "router_model": settings.ROUTER_MODEL,
        "current_subnet": get_setting("subnet", net_info["subnet"]),
        "host_ip": net_info["host_ip"],
        "host_mac": net_info["host_mac"],
        "scan_interval_minutes": int(get_setting("scan_interval_minutes", str(settings.SCAN_INTERVAL_MINUTES))),
        "nmap_installed": net_info["nmap_installed"],
        "nmap_path": net_info["nmap_path"],
        "vendor_db_entries": len(vendor_service.oui_db),
        "lan_access_enabled": lan_enabled,
        "lan_access_url": f"http://{net_info['host_ip']}:{settings.PORT}" if lan_enabled else None
    }

@router.post("")
def update_app_settings(payload: SettingsUpdateRequest, user: str = Depends(require_auth)):
    """Update configurable settings."""
    if payload.router_gateway:
        set_setting("router_gateway", payload.router_gateway.strip())
        settings.ROUTER_GATEWAY = payload.router_gateway.strip()

    if payload.subnet:
        set_setting("subnet", payload.subnet.strip())

    if payload.scan_interval_minutes:
        if payload.scan_interval_minutes < 1:
            raise HTTPException(status_code=400, detail="Scan interval must be at least 1 minute.")
        set_setting("scan_interval_minutes", str(payload.scan_interval_minutes))
        settings.SCAN_INTERVAL_MINUTES = payload.scan_interval_minutes

    if payload.lan_access_enabled is not None:
        set_setting("lan_access_enabled", "true" if payload.lan_access_enabled else "false")

    audit_logger.log_event("SETTINGS_UPDATED", actor=user, details="System parameters updated")
    return {"success": True, "message": "Settings saved successfully."}

@router.post("/backup")
def trigger_backup(user: str = Depends(require_auth)):
    """Create a point-in-time SQLite backup."""
    backup_file = backup_database()
    audit_logger.log_event("DB_BACKUP_CREATED", actor=user, target=backup_file.name)
    return {
        "success": True,
        "backup_filename": backup_file.name,
        "backup_path": str(backup_file)
    }

@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(limit: int = 100, user: str = Depends(require_auth)):
    """View security and operational audit trail."""
    return audit_logger.get_logs(limit=limit)
