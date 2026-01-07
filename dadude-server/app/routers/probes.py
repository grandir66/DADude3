"""
DaDude - Probes Router
API endpoints per gestione sonde/probe
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from loguru import logger

from ..models import Probe, ProbeListResponse, ProbeStatus
from ..services import get_dude_service, get_sync_service

router = APIRouter(prefix="/probes", tags=["Probes"])


@router.get("", response_model=ProbeListResponse)
async def list_probes(
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    status: Optional[str] = Query(None, description="Filter by status"),
    probe_type: Optional[str] = Query(None, description="Filter by probe type"),
    use_cache: bool = Query(True, description="Use cached data"),
):
    """
    Ottiene lista di tutte le probe/sonde.
    """
    try:
        if use_cache:
            sync = get_sync_service()
            probes = sync.probes
        else:
            dude = get_dude_service()
            probes = dude.get_probes(device_id=device_id)
        
        # Applica filtri
        if device_id:
            probes = [p for p in probes if p.device_id == device_id]
        if status:
            probes = [p for p in probes if p.status.value == status]
        if probe_type:
            probes = [p for p in probes if p.probe_type == probe_type]
        
        return ProbeListResponse(total=len(probes), probes=probes)
        
    except Exception as e:
        logger.error(f"Error listing probes: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def probes_summary():
    """
    Ottiene riepilogo stato probe.
    """
    sync = get_sync_service()
    probes = sync.probes
    
    summary = {
        "total": len(probes),
        "ok": len([p for p in probes if p.status == ProbeStatus.OK]),
        "warning": len([p for p in probes if p.status == ProbeStatus.WARNING]),
        "critical": len([p for p in probes if p.status == ProbeStatus.CRITICAL]),
        "unknown": len([p for p in probes if p.status == ProbeStatus.UNKNOWN]),
    }
    
    return summary
