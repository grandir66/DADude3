"""
DaDude - Polling/Sync Service
Gestisce il polling periodico e la sincronizzazione dei dati
"""
import asyncio
from typing import Optional, Callable, List, Dict, Any
from datetime import datetime
from loguru import logger
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ..config import Settings, get_settings
from ..models import Device, Probe, Alert, DeviceStatus
from .dude_service import DudeService, get_dude_service


class SyncService:
    """Servizio per sincronizzazione periodica con Dude"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.dude = get_dude_service()
        self.scheduler = AsyncIOScheduler()
        
        # Cache dati
        self._devices: List[Device] = []
        self._probes: List[Probe] = []
        self._alerts: List[Alert] = []
        self._last_sync: Optional[datetime] = None
        
        # Callbacks per notifiche
        self._on_device_change: List[Callable] = []
        self._on_probe_change: List[Callable] = []
        self._on_alert: List[Callable] = []
    
    @property
    def devices(self) -> List[Device]:
        return self._devices
    
    @property
    def probes(self) -> List[Probe]:
        return self._probes
    
    @property
    def last_sync(self) -> Optional[datetime]:
        return self._last_sync
    
    def on_device_change(self, callback: Callable):
        """Registra callback per cambio stato dispositivo"""
        self._on_device_change.append(callback)
    
    def on_probe_change(self, callback: Callable):
        """Registra callback per cambio stato probe"""
        self._on_probe_change.append(callback)
    
    def on_alert(self, callback: Callable):
        """Registra callback per nuovi alert"""
        self._on_alert.append(callback)
    
    async def sync_devices(self):
        """Sincronizza dispositivi dal Dude"""
        try:
            logger.debug("Syncing devices from Dude...")
            
            # Ottieni nuovi dispositivi
            new_devices = await asyncio.to_thread(self.dude.get_devices)
            
            # Rileva cambiamenti
            old_devices_map = {d.id: d for d in self._devices}
            
            for device in new_devices:
                old_device = old_devices_map.get(device.id)
                if old_device and old_device.status != device.status:
                    logger.info(f"Device {device.name} status changed: {old_device.status} -> {device.status}")
                    for callback in self._on_device_change:
                        try:
                            await callback(device, old_device.status, device.status)
                        except Exception as e:
                            logger.error(f"Error in device change callback: {e}")
            
            self._devices = new_devices
            self._last_sync = datetime.utcnow()
            logger.debug(f"Synced {len(self._devices)} devices")
            
        except Exception as e:
            logger.error(f"Error syncing devices: {e}")
    
    async def sync_probes(self):
        """Sincronizza probe dal Dude"""
        try:
            logger.debug("Syncing probes from Dude...")
            new_probes = await asyncio.to_thread(self.dude.get_probes)
            
            # Rileva cambiamenti
            old_probes_map = {p.id: p for p in self._probes}
            
            for probe in new_probes:
                old_probe = old_probes_map.get(probe.id)
                if old_probe and old_probe.status != probe.status:
                    logger.info(f"Probe {probe.name} status changed: {old_probe.status} -> {probe.status}")
                    for callback in self._on_probe_change:
                        try:
                            await callback(probe, old_probe.status, probe.status)
                        except Exception as e:
                            logger.error(f"Error in probe change callback: {e}")
            
            self._probes = new_probes
            logger.debug(f"Synced {len(self._probes)} probes")
            
        except Exception as e:
            logger.error(f"Error syncing probes: {e}")
    
    async def full_sync(self):
        """Esegue sincronizzazione completa"""
        logger.info("Starting full sync...")
        await self.sync_devices()
        await self.sync_probes()
        logger.info("Full sync completed")
    
    def start(self):
        """Avvia scheduler polling"""
        logger.info(f"Starting sync scheduler (poll: {self.settings.poll_interval}s, full: {self.settings.full_sync_interval}s)")
        
        # Job polling rapido (solo stato)
        self.scheduler.add_job(
            self.sync_devices,
            trigger=IntervalTrigger(seconds=self.settings.poll_interval),
            id="poll_devices",
            name="Poll Devices Status",
        )
        
        # Job sync completo
        self.scheduler.add_job(
            self.full_sync,
            trigger=IntervalTrigger(seconds=self.settings.full_sync_interval),
            id="full_sync",
            name="Full Sync",
        )
        
        self.scheduler.start()
        logger.success("Sync scheduler started")
    
    def stop(self):
        """Ferma scheduler"""
        self.scheduler.shutdown()
        logger.info("Sync scheduler stopped")


# Singleton
_sync_service: Optional[SyncService] = None


def get_sync_service() -> SyncService:
    """Get singleton SyncService instance"""
    global _sync_service
    if _sync_service is None:
        _sync_service = SyncService()
    return _sync_service
