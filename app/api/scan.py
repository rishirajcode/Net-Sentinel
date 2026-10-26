from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends
from app.models import ScanTriggerRequest, ScanResponse
from app.services.discovery import discovery_service
from app.services.audit_log import audit_logger
from app.database import get_db_connection
from app.api.auth import require_auth

router = APIRouter(prefix="/api/scan", tags=["Scan"])

@router.post("")
def trigger_scan(
    payload: Optional[ScanTriggerRequest] = None,
    user: str = Depends(require_auth)
):
    """
    Trigger an immediate network scan.
    Optionally accepts a custom subnet or engine preference ('native', 'nmap', 'auto').
    """
    subnet = payload.subnet if payload else None
    engine_pref = payload.engine_preference if payload else "auto"

    audit_logger.log_event(
        "SCAN_TRIGGERED",
        actor=user,
        target=subnet or "auto-detected",
        details=f"Engine preference: {engine_pref}"
    )

    try:
        result = discovery_service.run_scan(subnet=subnet, engine_preference=engine_pref)
        return {
            "success": True,
            "message": f"Scan completed successfully using {result['engine_used']}.",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

@router.get("/history", response_model=List[ScanResponse])
def get_scan_history(limit: int = 50):
    """Retrieve historical scan runs."""
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, start_time, end_time, subnet, engine_used, devices_found, new_devices, offline_devices, status, error_message
            FROM scans
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]

@router.get("/network-info")
def get_network_info():
    """Retrieve current network parameters (IP, Subnet, Gateway, Nmap status)."""
    return discovery_service.get_network_info()
