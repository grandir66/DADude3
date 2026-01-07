"""
Device Backup Router - NUOVO MODULO
API endpoints per backup configurazioni dispositivi
Non modifica router esistenti
"""
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends, BackgroundTasks, Response
from fastapi.responses import FileResponse, StreamingResponse
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from loguru import logger
from sqlalchemy.orm import Session
import os
from pathlib import Path

# Import database dependency (usa quello esistente)
from ..models.database import init_db, get_session
from ..config import get_settings

def get_db():
    """Dependency per ottenere sessione database"""
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    try:
        yield session
    finally:
        session.close()

from ..models.backup_models import DeviceBackup, BackupJob, BackupSchedule
from ..services.device_backup_service import DeviceBackupService


router = APIRouter(prefix="/device-backup", tags=["Device Backup"])


# ==========================================
# PYDANTIC SCHEMAS
# ==========================================

class BackupDeviceRequest(BaseModel):
    """Request per backup singolo device"""
    device_assignment_id: Optional[str] = Field(None, description="ID assignment (se device assegnato)")
    device_ip: Optional[str] = Field(None, description="IP device (se non assegnato)")
    customer_id: Optional[str] = Field(None, description="ID cliente (richiesto se device_ip)")
    device_type: str = Field("auto", description="Tipo device: hp_aruba, mikrotik, proxmox, auto")
    backup_type: str = Field("config", description="Tipo: config, binary, both, full")
    credential_id: Optional[str] = Field(None, description="ID credenziale da usare (opzionale, altrimenti usa default)")


class BackupCustomerRequest(BaseModel):
    """Request per backup tutti device cliente"""
    customer_id: str = Field(..., description="ID cliente")
    backup_type: str = Field("config", description="Tipo backup")
    device_type_filter: Optional[List[str]] = Field(None, description="Filtra per tipo device")


class BackupResponse(BaseModel):
    """Response backup operazione"""
    success: bool
    backup_id: Optional[str] = None
    job_id: Optional[str] = None
    message: Optional[str] = None
    device_info: Optional[dict] = None
    file_path: Optional[str] = None
    error: Optional[str] = None


class BackupHistoryResponse(BaseModel):
    """Response storico backup"""
    total: int
    backups: List[dict]


class ScheduleBackupRequest(BaseModel):
    """Request per configurare schedule backup"""
    customer_id: str
    enabled: bool = True
    schedule_type: str = Field("daily", description="daily, weekly, monthly")
    schedule_time: str = Field("03:00", description="HH:MM formato 24h")
    schedule_days: Optional[List[int]] = Field(None, description="Giorni settimana (0=Lun)")
    backup_types: List[str] = Field(["config"], description="Tipi backup")
    retention_days: int = Field(30, description="Giorni retention")
    device_type_filter: Optional[List[str]] = None


# ==========================================
# DEPENDENCY HELPERS
# ==========================================

def get_backup_service(db: Session = Depends(get_db)) -> DeviceBackupService:
    """Dependency per ottenere istanza DeviceBackupService"""
    return DeviceBackupService(db=db)


# ==========================================
# BACKUP ENDPOINTS
# ==========================================

@router.post("/device", response_model=BackupResponse)
async def backup_device(
    request: BackupDeviceRequest,
    background_tasks: BackgroundTasks,
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Esegue backup di un singolo dispositivo

    Modalità:
    1. Con device_assignment_id: backup device assegnato
    2. Con device_ip + customer_id: backup device standalone (può includere credential_id)

    Il backup viene eseguito in background
    """
    try:
        # Validazione input
        if not request.device_assignment_id and not (request.device_ip and request.customer_id):
            raise HTTPException(
                status_code=400,
                detail="Fornire device_assignment_id oppure device_ip + customer_id"
            )

        # Esegui backup (sincrono per ora, TODO: async task)
        if request.device_assignment_id:
            result = service.backup_device_by_assignment(
                device_assignment_id=request.device_assignment_id,
                backup_type=request.backup_type,
                triggered_by="api"
            )
        else:
            result = service.backup_device_by_ip(
                device_ip=request.device_ip,
                customer_id=request.customer_id,
                device_type=request.device_type,
                backup_type=request.backup_type,
                triggered_by="api",
                credential_id=request.credential_id
            )

        if result["success"]:
            return BackupResponse(
                success=True,
                backup_id=result.get("backup_id"),
                message="Backup completed successfully",
                device_info=result.get("device_info"),
                file_path=result.get("file_path") or result.get("export_file_path")
            )
        else:
            return BackupResponse(
                success=False,
                error=result.get("error", "Backup failed")
            )

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        logger.error(f"Backup device API error: {e}", exc_info=True)
        error_detail = str(e)
        # Fornisci messaggio più chiaro se possibile
        if "credential" in error_detail.lower() or "password" in error_detail.lower():
            error_detail = f"Errore credenziali: {error_detail}"
        elif "connection" in error_detail.lower() or "timeout" in error_detail.lower():
            error_detail = f"Errore connessione: {error_detail}"
        raise HTTPException(status_code=500, detail=error_detail)


@router.post("/customer", response_model=BackupResponse)
async def backup_customer_devices(
    request: BackupCustomerRequest,
    background_tasks: BackgroundTasks,
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Esegue backup di tutti i dispositivi di un cliente

    Ritorna job_id per tracking del progresso
    """
    try:
        result = service.backup_customer_devices(
            customer_id=request.customer_id,
            backup_type=request.backup_type,
            device_type_filter=request.device_type_filter,
            triggered_by="api"
        )

        if result["success"]:
            return BackupResponse(
                success=True,
                job_id=result.get("job_id"),
                message=f"Backup job started. Devices: {result.get('total_devices')}"
            )
        else:
            return BackupResponse(
                success=False,
                error=result.get("error", "Backup job failed")
            )

    except Exception as e:
        logger.error(f"Backup customer API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# HISTORY & STATUS ENDPOINTS
# ==========================================

@router.get("/history/device/{device_assignment_id}", response_model=BackupHistoryResponse)
async def get_device_backup_history(
    device_assignment_id: str,
    limit: int = Query(50, ge=1, le=200),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Recupera storico backup di un dispositivo
    """
    try:
        backups = service.get_device_backup_history(
            device_assignment_id=device_assignment_id,
            limit=limit
        )

        # Serializza backups
        backups_data = [
            {
                "id": b.id,
                "device_hostname": b.device_hostname,
                "device_type": b.device_type,
                "backup_type": b.backup_type,
                "file_name": b.file_name,
                "file_size": b.file_size,
                "success": b.success,
                "created_at": b.created_at.isoformat() if b.created_at else None,
                "triggered_by": b.triggered_by,
                "error_message": b.error_message
            }
            for b in backups
        ]

        return BackupHistoryResponse(
            total=len(backups_data),
            backups=backups_data
        )

    except Exception as e:
        logger.error(f"Get history API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/customer/{customer_id}", response_model=BackupHistoryResponse)
async def get_customer_backup_history(
    customer_id: str,
    days: int = Query(30, ge=1, le=365),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Recupera storico backup di un cliente
    """
    try:
        backups = service.get_customer_backups(
            customer_id=customer_id,
            days=days
        )

        backups_data = [
            {
                "id": b.id,
                "device_ip": b.device_ip,
                "device_hostname": b.device_hostname,
                "device_type": b.device_type,
                "backup_type": b.backup_type,
                "file_name": b.file_name,
                "file_size": b.file_size,
                "success": b.success,
                "created_at": b.created_at.isoformat() if b.created_at else None,
                "error_message": b.error_message
            }
            for b in backups
        ]

        return BackupHistoryResponse(
            total=len(backups_data),
            backups=backups_data
        )

    except Exception as e:
        logger.error(f"Get customer history API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/download/{backup_id}")
async def download_backup(
    backup_id: str,
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Download file backup
    """
    try:
        backup = service.get_backup_by_id(backup_id)

        if not backup:
            raise HTTPException(status_code=404, detail="Backup not found")

        # Converti file_path a Path se è una stringa
        from pathlib import Path
        file_path = Path(backup.file_path) if isinstance(backup.file_path, str) else backup.file_path
        
        if not file_path or not file_path.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")

        # Leggi file
        with open(file_path, 'rb') as f:
            content = f.read()

        # Determina content type
        if backup.backup_format == "rsc":
            media_type = "text/plain"
        elif backup.backup_format == "cfg":
            media_type = "text/plain"
        elif backup.backup_format == "backup":
            media_type = "application/octet-stream"
        else:
            media_type = "text/plain"

        return Response(
            content=content,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{backup.file_name}"'
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download backup API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/job/{job_id}")
async def get_job_status(
    job_id: str,
    db: Session = Depends(get_db)
):
    """
    Verifica stato job di backup
    """
    try:
        job = db.query(BackupJob).filter_by(id=job_id).first()

        if not job:
            raise HTTPException(status_code=404, detail="Job not found")

        return {
            "job_id": job.id,
            "status": job.status,
            "progress_percent": job.progress_percent,
            "devices_total": job.devices_total,
            "devices_success": job.devices_success,
            "devices_failed": job.devices_failed,
            "started_at": job.started_at.isoformat() if job.started_at else None,
            "completed_at": job.completed_at.isoformat() if job.completed_at else None,
            "error_message": job.error_message,
            "result_summary": job.result_summary
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get job status API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# SCHEDULE ENDPOINTS
# ==========================================

@router.post("/schedule", response_model=dict)
async def create_backup_schedule(
    request: ScheduleBackupRequest,
    db: Session = Depends(get_db)
):
    """
    Crea o aggiorna schedule automatico backup per cliente
    """
    try:
        # Verifica se esiste già uno schedule per questo cliente
        existing = db.query(BackupSchedule).filter_by(
            customer_id=request.customer_id
        ).first()

        if existing:
            # Aggiorna esistente
            existing.enabled = request.enabled
            existing.schedule_type = request.schedule_type
            existing.schedule_time = request.schedule_time
            existing.schedule_days = request.schedule_days
            existing.backup_types = request.backup_types
            existing.retention_days = request.retention_days
            existing.device_type_filter = request.device_type_filter
            existing.updated_at = datetime.now()

            schedule = existing
        else:
            # Crea nuovo
            schedule = BackupSchedule(
                customer_id=request.customer_id,
                enabled=request.enabled,
                schedule_type=request.schedule_type,
                schedule_time=request.schedule_time,
                schedule_days=request.schedule_days,
                backup_types=request.backup_types,
                retention_days=request.retention_days,
                device_type_filter=request.device_type_filter
            )
            db.add(schedule)

        db.commit()
        db.refresh(schedule)

        return {
            "success": True,
            "schedule_id": schedule.id,
            "message": "Schedule created/updated successfully"
        }

    except Exception as e:
        logger.error(f"Create schedule API error: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/schedule/{customer_id}")
async def get_backup_schedule(
    customer_id: str,
    db: Session = Depends(get_db)
):
    """
    Recupera schedule backup del cliente
    """
    try:
        schedule = db.query(BackupSchedule).filter_by(
            customer_id=customer_id
        ).first()

        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")

        return {
            "id": schedule.id,
            "customer_id": schedule.customer_id,
            "enabled": schedule.enabled,
            "schedule_type": schedule.schedule_type,
            "schedule_time": schedule.schedule_time,
            "schedule_days": schedule.schedule_days,
            "backup_types": schedule.backup_types,
            "retention_days": schedule.retention_days,
            "device_type_filter": schedule.device_type_filter,
            "last_run_at": schedule.last_run_at.isoformat() if schedule.last_run_at else None,
            "next_run_at": schedule.next_run_at.isoformat() if schedule.next_run_at else None,
            "total_runs": schedule.total_runs,
            "total_successes": schedule.total_successes,
            "total_failures": schedule.total_failures
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get schedule API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/schedule/{customer_id}")
async def delete_backup_schedule(
    customer_id: str,
    db: Session = Depends(get_db)
):
    """
    Elimina schedule backup del cliente
    """
    try:
        schedule = db.query(BackupSchedule).filter_by(
            customer_id=customer_id
        ).first()

        if not schedule:
            raise HTTPException(status_code=404, detail="Schedule not found")

        db.delete(schedule)
        db.commit()

        return {
            "success": True,
            "message": "Schedule deleted successfully"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete schedule API error: {e}", exc_info=True)
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# MAINTENANCE ENDPOINTS
# ==========================================

@router.post("/cleanup/{customer_id}")
async def cleanup_old_backups(
    customer_id: str,
    retention_days: int = Query(30, ge=1, le=365),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Pulizia backup vecchi secondo retention policy
    """
    try:
        result = service.cleanup_old_backups(
            customer_id=customer_id,
            retention_days=retention_days
        )

        return {
            "success": True,
            "deleted_count": result["deleted_count"],
            "freed_bytes": result["freed_bytes"],
            "freed_mb": round(result["freed_bytes"] / 1024 / 1024, 2)
        }

    except Exception as e:
        logger.error(f"Cleanup API error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# FILE BROWSER ENDPOINTS
# ==========================================

@router.get("/files/list")
async def list_backup_files(
    device_type: Optional[str] = Query(None, description="Filtra per tipo device (mikrotik, hp_aruba)"),
    customer_code: Optional[str] = Query(None, description="Filtra per codice cliente"),
    path: Optional[str] = Query("", description="Path relativo nella directory backup"),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Elenca file di backup disponibili
    
    Restituisce struttura directory con file e metadata
    """
    try:
        backup_path = service.backup_base_path
        
        # Costruisci path completo
        if path:
            # Sanitizza path per evitare directory traversal
            safe_path = os.path.normpath(path).lstrip('/')
            if '..' in safe_path or safe_path.startswith('/'):
                raise HTTPException(status_code=400, detail="Invalid path")
            full_path = os.path.join(backup_path, safe_path)
        else:
            full_path = backup_path
        
        # Verifica che il path sia dentro backup_path
        full_path = os.path.abspath(full_path)
        backup_path_abs = os.path.abspath(backup_path)
        if not full_path.startswith(backup_path_abs):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="Path not found")
        
        items = []
        
        # Se è una directory, elenca contenuto
        if os.path.isdir(full_path):
            for item_name in sorted(os.listdir(full_path)):
                item_path = os.path.join(full_path, item_name)
                rel_path = os.path.relpath(item_path, backup_path)
                
                stat = os.stat(item_path)
                is_dir = os.path.isdir(item_path)
                
                item_info = {
                    "name": item_name,
                    "path": rel_path.replace('\\', '/'),  # Normalizza separatori
                    "type": "directory" if is_dir else "file",
                    "size": stat.st_size if not is_dir else None,
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
                
                # Filtri
                if device_type and not rel_path.startswith(device_type):
                    continue
                if customer_code and customer_code not in rel_path:
                    continue
                
                items.append(item_info)
        else:
            # È un file singolo
            stat = os.stat(full_path)
            rel_path = os.path.relpath(full_path, backup_path)
            items.append({
                "name": os.path.basename(full_path),
                "path": rel_path.replace('\\', '/'),
                "type": "file",
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        
        return {
            "success": True,
            "path": path or "/",
            "items": items,
            "total": len(items)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing backup files: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/files/download")
async def download_backup_file(
    path: str = Query(..., description="Path relativo del file da scaricare"),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Scarica un file di backup
    """
    try:
        backup_path = service.backup_base_path
        
        # Sanitizza path
        safe_path = os.path.normpath(path).lstrip('/')
        if '..' in safe_path or safe_path.startswith('/'):
            raise HTTPException(status_code=400, detail="Invalid path")
        
        full_path = os.path.join(backup_path, safe_path)
        
        # Verifica sicurezza
        full_path = os.path.abspath(full_path)
        backup_path_abs = os.path.abspath(backup_path)
        if not full_path.startswith(backup_path_abs):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        if os.path.isdir(full_path):
            raise HTTPException(status_code=400, detail="Path is a directory, not a file")
        
        # Determina media type
        ext = os.path.splitext(full_path)[1].lower()
        media_types = {
            '.rsc': 'text/plain',
            '.backup': 'application/octet-stream',
            '.txt': 'text/plain',
            '.cfg': 'text/plain',
            '.conf': 'text/plain',
        }
        media_type = media_types.get(ext, 'application/octet-stream')
        
        return FileResponse(
            full_path,
            media_type=media_type,
            filename=os.path.basename(full_path),
            headers={
                "Content-Disposition": f'attachment; filename="{os.path.basename(full_path)}"'
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading backup file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/files/delete")
async def delete_backup_file(
    path: str = Query(..., description="Path relativo del file da eliminare"),
    service: DeviceBackupService = Depends(get_backup_service)
):
    """
    Elimina un file di backup
    """
    try:
        backup_path = service.backup_base_path
        
        # Sanitizza path
        safe_path = os.path.normpath(path).lstrip('/')
        if '..' in safe_path or safe_path.startswith('/'):
            raise HTTPException(status_code=400, detail="Invalid path")
        
        full_path = os.path.join(backup_path, safe_path)
        
        # Verifica sicurezza
        full_path = os.path.abspath(full_path)
        backup_path_abs = os.path.abspath(backup_path)
        if not full_path.startswith(backup_path_abs):
            raise HTTPException(status_code=403, detail="Access denied")
        
        if not os.path.exists(full_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        if os.path.isdir(full_path):
            raise HTTPException(status_code=400, detail="Cannot delete directories via API")
        
        os.remove(full_path)
        
        return {"success": True, "message": "File deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting backup file: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
