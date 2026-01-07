"""
DaDude - Backup Router
Endpoint per gestione backup
v3.0.0: Nuovo router
"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Optional
from loguru import logger

from ..services.backup_scheduler import get_backup_scheduler
from ..services.version_manager import get_version_manager

router = APIRouter(prefix="/backup", tags=["Backup"])


@router.get("/list")
async def list_backups():
    """
    Lista tutti i backup disponibili.
    
    Returns:
        Lista backup con metadati (nome, dimensione, data)
    """
    try:
        scheduler = get_backup_scheduler()
        backups = scheduler.list_backups()
        return {
            "success": True,
            "count": len(backups),
            "backups": backups,
        }
    except Exception as e:
        logger.error(f"Error listing backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/create")
async def create_backup(
    background_tasks: BackgroundTasks,
    reason: Optional[str] = "manual"
):
    """
    Crea un nuovo backup completo.
    
    Il backup include:
    - Database PostgreSQL (dump)
    - File di configurazione
    - Certificati PKI
    
    Args:
        reason: Motivo del backup (default: manual)
    
    Returns:
        Info sul backup creato
    """
    try:
        scheduler = get_backup_scheduler()
        result = await scheduler.create_backup(reason=reason)
        return result
    except Exception as e:
        logger.error(f"Error creating backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cleanup")
async def cleanup_old_backups():
    """
    Rimuove backup più vecchi del periodo di retention.
    
    Returns:
        Numero backup rimossi
    """
    try:
        scheduler = get_backup_scheduler()
        removed = await scheduler.cleanup_old_backups()
        return {
            "success": True,
            "removed_count": removed,
        }
    except Exception as e:
        logger.error(f"Error cleaning up backups: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/version")
async def get_version():
    """
    Ottiene informazioni sulla versione corrente.
    
    Returns:
        Info versione (major, minor, patch, storia)
    """
    try:
        version_manager = get_version_manager()
        return version_manager.get_version_info()
    except Exception as e:
        logger.error(f"Error getting version: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/version/history")
async def get_version_history():
    """
    Ottiene storico delle versioni.
    
    Returns:
        Lista versioni con date e note
    """
    try:
        version_manager = get_version_manager()
        history = version_manager.get_version_history()
        return {
            "success": True,
            "count": len(history),
            "history": history,
        }
    except Exception as e:
        logger.error(f"Error getting version history: {e}")
        raise HTTPException(status_code=500, detail=str(e))
