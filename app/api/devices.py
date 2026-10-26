from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, Response
from fastapi.responses import PlainTextResponse

from app.models import DeviceResponse, DeviceDetailResponse, DeviceUpdate
from app.services.device_inventory import device_inventory
from app.services.audit_log import audit_logger
from app.api.auth import require_auth

router = APIRouter(prefix="/api/devices", tags=["Devices"])

@router.get("", response_model=List[DeviceResponse])
def list_devices(
    status: Optional[str] = None,
    classification: Optional[str] = None,
    blocked: Optional[bool] = None,
    q: Optional[str] = None
):
    """Retrieve list of devices matching optional filters."""
    return device_inventory.get_devices(
        status_filter=status,
        classification_filter=classification,
        blocked_filter=blocked,
        search_query=q
    )

@router.get("/export/csv")
def export_csv():
    """Download device inventory as CSV."""
    csv_data = device_inventory.export_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=netsentinel_device_inventory.csv"}
    )

@router.get("/{device_id}", response_model=DeviceDetailResponse)
def get_device(device_id: int):
    """Fetch single device with complete observation history and past IP records."""
    device = device_inventory.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found in inventory.")
    return device

@router.put("/{device_id}", response_model=DeviceDetailResponse)
def update_device(
    device_id: int,
    payload: DeviceUpdate,
    user: str = Depends(require_auth)
):
    """Update device metadata (custom name, classification, notes, type)."""
    device = device_inventory.get_device_by_id(device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found.")

    updated = device_inventory.update_device(
        device_id=device_id,
        custom_name=payload.custom_name,
        classification=payload.classification,
        notes=payload.notes,
        device_type=payload.device_type
    )

    audit_logger.log_event(
        "DEVICE_UPDATED",
        actor=user,
        target=f"Device #{device_id} ({device.get('ip_address')})",
        details=f"Name={payload.custom_name}, Class={payload.classification}"
    )
    return updated

@router.post("/{device_id}/trust")
def mark_as_trusted(device_id: int, user: str = Depends(require_auth)):
    """Mark device as trusted."""
    updated = device_inventory.update_device(device_id=device_id, classification="trusted")
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found.")
    audit_logger.log_event("DEVICE_TRUSTED", actor=user, target=f"Device #{device_id}")
    return {"success": True, "device": updated}

@router.post("/{device_id}/unknown")
def mark_as_unknown(device_id: int, user: str = Depends(require_auth)):
    """Mark device as unknown."""
    updated = device_inventory.update_device(device_id=device_id, classification="unknown")
    if not updated:
        raise HTTPException(status_code=404, detail="Device not found.")
    audit_logger.log_event("DEVICE_MARKED_UNKNOWN", actor=user, target=f"Device #{device_id}")
    return {"success": True, "device": updated}
