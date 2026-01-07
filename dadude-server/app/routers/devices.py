"""
DaDude - Devices Router
API endpoints per gestione dispositivi
"""
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List
from loguru import logger

from ..models import Device, DeviceListResponse, DeviceStatus
from ..services import get_dude_service, get_sync_service

router = APIRouter(prefix="/devices", tags=["Devices"])


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    status: Optional[str] = Query(None, description="Filter by status (up, down, unknown)"),
    use_cache: bool = Query(True, description="Use cached data if available"),
):
    """
    Ottiene lista di tutti i dispositivi monitorati dal Dude.
    
    - **status**: Filtra per stato (up, down, unknown, disabled, partial)
    - **use_cache**: Se True usa cache locale, altrimenti interroga Dude direttamente
    """
    try:
        if use_cache:
            sync = get_sync_service()
            devices = sync.devices
            if status:
                devices = [d for d in devices if d.status.value == status]
        else:
            dude = get_dude_service()
            devices = dude.get_devices(status_filter=status)
        
        return DeviceListResponse(total=len(devices), devices=devices)
        
    except Exception as e:
        logger.error(f"Error listing devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def devices_summary():
    """
    Ottiene riepilogo rapido stato dispositivi.
    """
    sync = get_sync_service()
    devices = sync.devices
    
    summary = {
        "total": len(devices),
        "up": len([d for d in devices if d.status == DeviceStatus.UP]),
        "down": len([d for d in devices if d.status == DeviceStatus.DOWN]),
        "unknown": len([d for d in devices if d.status == DeviceStatus.UNKNOWN]),
        "disabled": len([d for d in devices if d.status == DeviceStatus.DISABLED]),
        "partial": len([d for d in devices if d.status == DeviceStatus.PARTIAL]),
        "last_sync": sync.last_sync.isoformat() if sync.last_sync else None,
    }
    
    return summary


@router.get("/{device_id}", response_model=Device)
async def get_device(device_id: str):
    """
    Ottiene dettagli singolo dispositivo per ID.
    """
    try:
        dude = get_dude_service()
        device = dude.get_device(device_id)
        
        if not device:
            raise HTTPException(status_code=404, detail=f"Device {device_id} not found")
        
        return device
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{device_id}/probes")
async def get_device_probes(device_id: str):
    """
    Ottiene tutte le probe di un dispositivo specifico.
    """
    try:
        dude = get_dude_service()
        probes = dude.get_probes(device_id=device_id)
        return {"device_id": device_id, "total": len(probes), "probes": probes}
        
    except Exception as e:
        logger.error(f"Error getting probes for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
