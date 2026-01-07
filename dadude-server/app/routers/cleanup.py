"""
DaDude - Cleanup Router
Gestisce la pulizia di device obsoleti e dati non più necessari
"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from typing import Optional
from datetime import datetime, timedelta
from loguru import logger

from ..models.database import init_db, get_session
from ..models.inventory import InventoryDevice
from ..config import get_settings

router = APIRouter(tags=["Cleanup"])


@router.post("/cleanup/stale-devices")
async def cleanup_stale_devices(
    days: int = Query(90, ge=1, le=365, description="Giorni di inattività per considerare un device obsoleto"),
    dry_run: bool = Query(True, description="Se True, mostra solo cosa verrebbe eliminato senza eliminare"),
    customer_id: Optional[str] = Query(None, description="Filtra per cliente specifico"),
):
    """
    Rimuove device obsoleti (non visti da più di X giorni)
    """
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        query = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.last_seen < cutoff_date
        )
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        stale_devices = query.all()
        
        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "devices_found": len(stale_devices),
                "cutoff_date": cutoff_date.isoformat(),
                "devices": [
                    {
                        "id": d.id,
                        "name": d.name,
                        "primary_ip": d.primary_ip,
                        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                        "monitored": d.monitored,
                    }
                    for d in stale_devices[:100]  # Limita a 100 per la preview
                ]
            }
        
        # Elimina realmente
        deleted_count = 0
        for device in stale_devices:
            # Se il device è monitorato, imposta come inattivo invece di eliminarlo
            if device.monitored:
                device.active = False
                device.monitored = False
                logger.info(f"Disattivato device obsoleto monitorato: {device.name} ({device.primary_ip})")
            else:
                session.delete(device)
                logger.info(f"Eliminato device obsoleto: {device.name} ({device.primary_ip})")
            deleted_count += 1
        
        session.commit()
        
        return {
            "success": True,
            "dry_run": False,
            "devices_deleted": deleted_count,
            "cutoff_date": cutoff_date.isoformat(),
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error cleaning up stale devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.post("/cleanup/mark-inactive")
async def mark_devices_inactive(
    days: int = Query(90, ge=1, le=365, description="Giorni di inattività per considerare un device inattivo"),
    customer_id: Optional[str] = Query(None, description="Filtra per cliente specifico"),
):
    """
    Marca come inattivi device non visti da più di X giorni (senza eliminarli)
    """
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        query = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.last_seen < cutoff_date
        )
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        stale_devices = query.all()
        
        marked_count = 0
        for device in stale_devices:
            device.active = False
            if device.monitored:
                device.monitored = False
            marked_count += 1
        
        session.commit()
        
        return {
            "success": True,
            "devices_marked": marked_count,
            "cutoff_date": cutoff_date.isoformat(),
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error marking devices as inactive: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()

