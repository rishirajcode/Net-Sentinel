from typing import Optional
from fastapi import APIRouter, HTTPException, Depends, Request
from app.models import RouterActionRequest, RouterStatusResponse
from app.services.router_adapter import router_service
from app.api.auth import require_auth
from app.config import settings

router = APIRouter(prefix="/api/router", tags=["Router"])

@router.get("/status", response_model=RouterStatusResponse)
def get_router_status():
    """Retrieve verified capabilities and connection status for DBC HGU-V210-4AC router."""
    return router_service.get_status()

@router.post("/block")
def block_device(
    payload: RouterActionRequest,
    request: Request,
    user: str = Depends(require_auth)
):
    """
    Block a device on the router.
    Enforces explicit confirmation, safety guards, and audit logging.
    """
    client_ip = request.client.host if request.client else None
    result = router_service.block_device(
        mac_address=payload.mac_address,
        ip_address=payload.ip_address,
        device_name=payload.device_name,
        confirmed=payload.confirmed,
        client_ip=client_ip,
        actor=user
    )
    if not result.get("success") and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.post("/unblock")
def unblock_device(
    payload: RouterActionRequest,
    user: str = Depends(require_auth)
):
    """Unblock a device on the router."""
    result = router_service.unblock_device(
        mac_address=payload.mac_address,
        ip_address=payload.ip_address,
        confirmed=payload.confirmed,
        actor=user
    )
    if not result.get("success") and "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result

@router.post("/toggle-mock")
def toggle_mock_mode(enabled: bool, user: str = Depends(require_auth)):
    """Toggle mock router adapter for testing / demonstration."""
    router_service.set_mock_mode(enabled)
    return {
        "success": True,
        "mock_mode": enabled,
        "message": f"Router adapter mode switched to {'Mock' if enabled else 'DBC HGU Production'}."
    }
