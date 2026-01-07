"""
DaDude - Device Cleanup Service
Servizio per pulizia automatica device non più presenti nelle scansioni
"""
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from ..models.inventory import InventoryDevice
from ..config import get_settings


class DeviceCleanupService:
    """Servizio per pulizia automatica device"""
    
    def mark_devices_for_cleanup(
        self,
        customer_id: Optional[str],
        network_id: Optional[str],
        days_threshold: int,
        session: Session
    ) -> int:
        """
        Marca device non visti per X giorni per pulizia.
        
        Args:
            customer_id: ID cliente (opzionale, se None applica a tutti)
            network_id: ID rete (opzionale, se None applica a tutte le reti)
            days_threshold: Giorni senza verifica prima di marcare
            session: Sessione database
            
        Returns:
            Numero di device marcati
        """
        threshold_date = datetime.utcnow() - timedelta(days=days_threshold)
        
        query = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.cleanup_marked_at.is_(None),  # Non già marcati
            or_(
                InventoryDevice.last_verified_at.is_(None),
                InventoryDevice.last_verified_at < threshold_date
            )
        )
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        if network_id:
            query = query.filter(InventoryDevice.last_scan_network_id == network_id)
        
        devices_to_mark = query.all()
        marked_count = 0
        
        for device in devices_to_mark:
            device.cleanup_marked_at = datetime.utcnow()
            marked_count += 1
            logger.info(f"Marked device {device.id} ({device.name}) for cleanup (last verified: {device.last_verified_at})")
        
        session.commit()
        return marked_count
    
    def cleanup_marked_devices(
        self,
        customer_id: Optional[str],
        dry_run: bool = True,
        session: Session = None
    ) -> Dict[str, Any]:
        """
        Rimuove device marcati (marca active=False).
        
        Args:
            customer_id: ID cliente (opzionale)
            dry_run: Se True, solo preview senza modifiche
            session: Sessione database (opzionale, creata se None)
            
        Returns:
            Dizionario con risultati pulizia
        """
        settings = get_settings()
        grace_period_days = settings.device_cleanup_grace_period_days
        grace_threshold = datetime.utcnow() - timedelta(days=grace_period_days)
        
        if session is None:
            from ..models.database import init_db, get_session
            from ..config import get_settings
            settings = get_settings()
            engine = init_db(settings.database_url)
            session = get_session(engine)
            close_session = True
        else:
            close_session = False
        
        try:
            query = session.query(InventoryDevice).filter(
                InventoryDevice.active == True,
                InventoryDevice.cleanup_marked_at.isnot(None),
                InventoryDevice.cleanup_marked_at < grace_threshold
            )
            
            if customer_id:
                query = query.filter(InventoryDevice.customer_id == customer_id)
            
            devices_to_cleanup = query.all()
            
            if dry_run:
                return {
                    "dry_run": True,
                    "devices_to_cleanup": [
                        {
                            "id": d.id,
                            "name": d.name,
                            "primary_ip": d.primary_ip,
                            "mac_address": d.mac_address,
                            "last_verified_at": d.last_verified_at.isoformat() if d.last_verified_at else None,
                            "cleanup_marked_at": d.cleanup_marked_at.isoformat() if d.cleanup_marked_at else None,
                            "verification_count": d.verification_count,
                        }
                        for d in devices_to_cleanup
                    ],
                    "count": len(devices_to_cleanup),
                }
            
            cleaned_count = 0
            for device in devices_to_cleanup:
                device.active = False
                cleaned_count += 1
                logger.info(f"Cleaned up device {device.id} ({device.name}) - marked at {device.cleanup_marked_at}")
            
            session.commit()
            
            return {
                "dry_run": False,
                "cleaned_count": cleaned_count,
                "message": f"Puliti {cleaned_count} device",
            }
            
        finally:
            if close_session:
                session.close()
    
    def get_devices_not_seen_in_network(
        self,
        network_id: str,
        days: int,
        session: Session
    ) -> List[InventoryDevice]:
        """
        Trova device non visti in una rete specifica.
        
        Args:
            network_id: ID rete
            days: Giorni senza verifica
            session: Sessione database
            
        Returns:
            Lista device non visti
        """
        threshold_date = datetime.utcnow() - timedelta(days=days)
        
        devices = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.last_scan_network_id == network_id,
            or_(
                InventoryDevice.last_verified_at.is_(None),
                InventoryDevice.last_verified_at < threshold_date
            )
        ).all()
        
        return devices
    
    def get_cleanup_preview(
        self,
        customer_id: Optional[str],
        days_threshold: int,
        network_id: Optional[str] = None,
        session: Session = None
    ) -> Dict[str, Any]:
        """
        Preview di device da pulire.
        
        Args:
            customer_id: ID cliente (opzionale)
            days_threshold: Giorni senza verifica
            network_id: ID rete (opzionale)
            session: Sessione database (opzionale)
            
        Returns:
            Dizionario con preview device
        """
        if session is None:
            from ..models.database import init_db, get_session
            from ..config import get_settings
            settings = get_settings()
            engine = init_db(settings.database_url)
            session = get_session(engine)
            close_session = True
        else:
            close_session = False
        
        try:
            threshold_date = datetime.utcnow() - timedelta(days=days_threshold)
            
            query = session.query(InventoryDevice).filter(
                InventoryDevice.active == True,
                or_(
                    InventoryDevice.last_verified_at.is_(None),
                    InventoryDevice.last_verified_at < threshold_date
                )
            )
            
            if customer_id:
                query = query.filter(InventoryDevice.customer_id == customer_id)
            
            if network_id:
                query = query.filter(InventoryDevice.last_scan_network_id == network_id)
            
            devices = query.all()
            
            preview = {
                "total_devices": len(devices),
                "devices": [
                    {
                        "id": d.id,
                        "name": d.name,
                        "primary_ip": d.primary_ip,
                        "mac_address": d.mac_address,
                        "hostname": d.hostname,
                        "device_type": d.device_type,
                        "last_verified_at": d.last_verified_at.isoformat() if d.last_verified_at else None,
                        "cleanup_marked_at": d.cleanup_marked_at.isoformat() if d.cleanup_marked_at else None,
                        "verification_count": d.verification_count,
                        "days_since_verification": (
                            (datetime.utcnow() - d.last_verified_at).days 
                            if d.last_verified_at else None
                        ),
                    }
                    for d in devices
                ],
            }
            
            return preview
            
        finally:
            if close_session:
                session.close()


class DeviceCleanupScheduler:
    """
    Scheduler automatico per pulizia periodica device
    Usa APScheduler per gestire job ricorrenti
    """
    
    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.cleanup_service = DeviceCleanupService()
        self.logger = logger
        self.running = False
    
    def start(self):
        """Avvia lo scheduler"""
        try:
            if not self.running:
                self.scheduler.start()
                self.running = True
                self.logger.info("DeviceCleanupScheduler started")
                
                # Aggiungi job per pulizia periodica
                settings = get_settings()
                if settings.device_cleanup_schedule_enabled:
                    cron_trigger = CronTrigger.from_crontab(settings.device_cleanup_schedule_cron)
                    self.scheduler.add_job(
                        func=self._execute_scheduled_cleanup,
                        trigger=cron_trigger,
                        id="device_cleanup_job",
                        replace_existing=True,
                        max_instances=1
                    )
                    self.logger.info(f"Scheduled device cleanup job: {settings.device_cleanup_schedule_cron}")
        except Exception as e:
            self.logger.error(f"Error starting DeviceCleanupScheduler: {e}", exc_info=True)
    
    def stop(self):
        """Ferma lo scheduler"""
        try:
            if self.running:
                self.scheduler.shutdown()
                self.running = False
                self.logger.info("DeviceCleanupScheduler stopped")
        except Exception as e:
            self.logger.error(f"Error stopping DeviceCleanupScheduler: {e}", exc_info=True)
    
    async def _execute_scheduled_cleanup(self):
        """Esegue pulizia schedulata"""
        try:
            self.logger.info("Executing scheduled device cleanup...")
            settings = get_settings()
            
            from ..models.database import init_db, get_session
            engine = init_db(settings.database_url)
            session = get_session(engine)
            
            try:
                # Step 1: Marca device per pulizia
                marked_count = self.cleanup_service.mark_devices_for_cleanup(
                    customer_id=None,  # Tutti i clienti
                    network_id=None,  # Tutte le reti
                    days_threshold=settings.device_cleanup_threshold_days,
                    session=session
                )
                self.logger.info(f"Marked {marked_count} devices for cleanup")
                
                # Step 2: Pulisci device marcati (dopo periodo di grazia)
                cleanup_result = self.cleanup_service.cleanup_marked_devices(
                    customer_id=None,
                    dry_run=False,
                    session=session
                )
                cleaned_count = cleanup_result.get("cleaned_count", 0)
                self.logger.info(f"Cleaned up {cleaned_count} devices")
                
            finally:
                session.close()
            
            self.logger.info(f"Scheduled cleanup completed: {marked_count} marked, {cleaned_count} cleaned")
            
        except Exception as e:
            self.logger.error(f"Error executing scheduled cleanup: {e}", exc_info=True)


# Singleton
_cleanup_service: Optional[DeviceCleanupService] = None
_cleanup_scheduler: Optional[DeviceCleanupScheduler] = None


def get_device_cleanup_service() -> DeviceCleanupService:
    """Ottiene istanza singleton del servizio cleanup"""
    global _cleanup_service
    if _cleanup_service is None:
        _cleanup_service = DeviceCleanupService()
    return _cleanup_service


def get_device_cleanup_scheduler() -> DeviceCleanupScheduler:
    """Ottiene istanza singleton dello scheduler cleanup"""
    global _cleanup_scheduler
    if _cleanup_scheduler is None:
        _cleanup_scheduler = DeviceCleanupScheduler()
    return _cleanup_scheduler


def start_device_cleanup_scheduler():
    """Avvia scheduler globale"""
    scheduler = get_device_cleanup_scheduler()
    if not scheduler.running:
        scheduler.start()


def stop_device_cleanup_scheduler():
    """Ferma scheduler globale"""
    scheduler = get_device_cleanup_scheduler()
    if scheduler.running:
        scheduler.stop()
