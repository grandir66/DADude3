"""
DaDude - Device Monitoring Service
Gestisce il monitoraggio periodico dei dispositivi (ICMP, TCP, Agent)
"""
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from loguru import logger
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from ..config import Settings, get_settings
from ..models.database import init_db, get_session
from ..models.inventory import InventoryDevice
from ..services.customer_service import get_customer_service
from ..services.device_probe_service import get_device_probe_service
from ..services.websocket_hub import get_websocket_hub, CommandType
from ..services.agent_service import get_agent_service


class DeviceMonitoringService:
    """Servizio per monitoraggio periodico dispositivi"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.scheduler = AsyncIOScheduler()
        self.probe_service = get_device_probe_service()
        self.customer_service = get_customer_service()
        self.agent_service = get_agent_service()
        self.check_interval = 30  # Secondi tra un check e l'altro
        self._started = False
        
    async def _find_connected_agent_id(self, ws_hub, agent_name: str, dude_agent_id: Optional[str] = None) -> Optional[str]:
        """
        Trova l'ID WebSocket dell'agent connesso.
        Cerca prima per dude_agent_id esatto, poi per nome parziale.
        """
        if dude_agent_id:
            # Prova con dude_agent_id completo
            if dude_agent_id.startswith("agent-"):
                ws_id = dude_agent_id
            else:
                ws_id = f"agent-{dude_agent_id}"
            
            if await ws_hub.is_connected(ws_id):
                return ws_id
        
        # Se non trovato, cerca per nome parziale tra gli agent connessi (thread-safe)
        if agent_name:
            # Rimuovi "agent-" se presente nel nome
            name_base = agent_name.replace("agent-", "").upper()
            connected_agents_list = await ws_hub.get_connected_agents()
            for conn_info in connected_agents_list:
                conn_id = conn_info["agent_id"]
                # Confronta nome base (es: "OVH-51" in "agent-OVH-51-4151")
                conn_name_base = conn_id.replace("agent-", "").upper()
                if name_base in conn_name_base or conn_name_base.startswith(name_base):
                    return conn_id
        
        return None
    
    async def check_device(self, device: InventoryDevice) -> Dict[str, Any]:
        """Esegue un check di monitoraggio su un dispositivo"""
        result = {
            "device_id": device.id,
            "device_ip": device.primary_ip,
            "monitoring_type": device.monitoring_type,
            "success": False,
            "status": "unknown",
            "error": None,
        }
        
        try:
            # Trova agent per questo dispositivo (configurato o del cliente)
            agent = None
            ws_hub = get_websocket_hub()
            
            if device.monitoring_agent_id:
                # Usa agent configurato esplicitamente
                agent = self.customer_service.get_agent(device.monitoring_agent_id, include_password=True)
            elif device.customer_id:
                # Cerca automaticamente un agent del cliente
                agent_dict = self.agent_service.get_agent_for_customer(device.customer_id)
                if agent_dict:
                    # Converti dict in oggetto simile ad agent
                    agent = type('Agent', (), agent_dict)()
                    logger.debug(f"Using auto-detected agent {agent_dict.get('name')} for device {device.primary_ip}")
            
            if device.monitoring_type == "icmp":
                # Ping check - usa nmap quando disponibile sull'agent
                if agent and getattr(agent, 'agent_type', None) == "docker":
                    # Via Docker agent
                    dude_agent_id = getattr(agent, 'dude_agent_id', None)
                    agent_name = getattr(agent, 'name', None)
                    # Trova agent connesso (per nome se dude_agent_id è vuoto)
                    ws_agent_id = await self._find_connected_agent_id(ws_hub, agent_name, dude_agent_id)
                    
                    if ws_agent_id:
                        # Usa il comando PING che funziona correttamente nella scansione di rete
                        ping_result = await ws_hub.send_command(
                            ws_agent_id,
                            CommandType.PING,
                            params={"target": device.primary_ip, "count": 3},
                            timeout=15.0
                        )
                        # CommandResult ha status="success" se comando riuscito
                        if ping_result.status == "success":
                            result["success"] = True
                            result["status"] = "up"
                            result["agent_used"] = agent_name or dude_agent_id or ws_agent_id
                            result["method"] = "ping"
                            logger.info(f"ICMP check via ping: {device.primary_ip} = up")
                        else:
                            # Ping fallito = host down
                            result["success"] = True
                            result["status"] = "down"
                            result["agent_used"] = agent_name or dude_agent_id or ws_agent_id
                            result["method"] = "ping"
                            logger.info(f"ICMP check via ping: {device.primary_ip} = down")
                    else:
                        # Agent non connesso
                        agent_display = agent_name or dude_agent_id or "sconosciuto"
                        result["error"] = f"Agent {agent_display} non connesso via WebSocket"
                elif agent and getattr(agent, 'agent_type', None) == "mikrotik":
                    # Via MikroTik agent - esegui ping via SSH/API
                    try:
                        from ..services.mikrotik_service import get_mikrotik_service
                        mikrotik_service = get_mikrotik_service()
                        ping_ok = await mikrotik_service.ping_via_router(
                            address=getattr(agent, 'address', None),
                            port=getattr(agent, 'port', 8728),
                            username=getattr(agent, 'username', 'admin'),
                            password=getattr(agent, 'password', ''),
                            target=device.primary_ip,
                            use_ssl=getattr(agent, 'use_ssl', False),
                        )
                        result["success"] = True
                        result["status"] = "up" if ping_ok else "down"
                        result["agent_used"] = getattr(agent, 'name', 'MikroTik')
                    except Exception as e:
                        result["error"] = f"MikroTik ping failed: {e}"
                else:
                    # Ping locale (fallback)
                    result["success"] = True
                    result["status"] = "up" if await self._ping_check(device.primary_ip) else "down"
                    
            elif device.monitoring_type == "tcp":
                # TCP port check - usa nmap quando disponibile sull'agent
                port = device.monitoring_port or 80
                
                if agent and getattr(agent, 'agent_type', None) == "docker":
                    # Via Docker agent
                    dude_agent_id = getattr(agent, 'dude_agent_id', None)
                    agent_name = getattr(agent, 'name', None)
                    # Trova agent connesso (per nome se dude_agent_id è vuoto)
                    ws_agent_id = await self._find_connected_agent_id(ws_hub, agent_name, dude_agent_id)
                    
                    if ws_agent_id:
                        # Usa il comando PORT_SCAN che funziona correttamente nella scansione di rete
                        port_result = await ws_hub.send_command(
                            ws_agent_id,
                            CommandType.SCAN_PORTS,
                            params={"target": device.primary_ip, "ports": [port], "timeout": 2.0},
                            timeout=15.0
                        )
                        if port_result.status == "success":
                            # Parse risultato come nella scansione di rete
                            port_data = port_result.data or {}
                            open_ports = port_data.get("open_ports", [])
                            # Verifica se la porta specifica è nella lista delle porte aperte
                            is_open = any(p.get("port") == port or (isinstance(p, dict) and p.get("port") == port) for p in open_ports)
                            result["success"] = True
                            result["status"] = "up" if is_open else "down"
                            result["agent_used"] = agent_name or dude_agent_id or ws_agent_id
                            result["method"] = "port_scan"
                            logger.info(f"TCP check via port_scan: {device.primary_ip}:{port} = {'up' if is_open else 'down'} (open_ports: {open_ports})")
                        else:
                            result["error"] = port_result.error or "Port check failed"
                            logger.warning(f"Port scan failed for {device.primary_ip}:{port}: {port_result.error}")
                    else:
                        agent_display = agent_name or dude_agent_id or "sconosciuto"
                        result["error"] = f"Agent {agent_display} non connesso via WebSocket"
                elif agent and getattr(agent, 'agent_type', None) == "mikrotik":
                    # Via MikroTik agent - tool fetch o /tool/netwatch
                    try:
                        from ..services.mikrotik_service import get_mikrotik_service
                        mikrotik_service = get_mikrotik_service()
                        port_ok = await mikrotik_service.check_port_via_router(
                            address=getattr(agent, 'address', None),
                            port=getattr(agent, 'port', 8728),
                            username=getattr(agent, 'username', 'admin'),
                            password=getattr(agent, 'password', ''),
                            target=device.primary_ip,
                            target_port=port,
                            use_ssl=getattr(agent, 'use_ssl', False),
                        )
                        result["success"] = True
                        result["status"] = "up" if port_ok else "down"
                        result["agent_used"] = getattr(agent, 'name', 'MikroTik')
                    except Exception as e:
                        result["error"] = f"MikroTik port check failed: {e}"
                else:
                    # Check locale (fallback)
                    result["success"] = True
                    result["status"] = "up" if await self.probe_service.probe_port(device.primary_ip, port) else "down"
                    
            elif device.monitoring_type == "agent":
                # Agent-based monitoring (ICMP o TCP a seconda di monitoring_port)
                # Usa l'agent già trovato sopra, o cerca quello configurato
                if not agent and device.monitoring_agent_id:
                    agent = self.customer_service.get_agent(device.monitoring_agent_id, include_password=True)
                
                if not agent:
                    result["error"] = "Agent non trovato"
                    return result
                
                if getattr(agent, 'agent_type', None) == "docker":
                    dude_agent_id = getattr(agent, 'dude_agent_id', None) or getattr(agent, 'name', None)
                    # Costruisci ws_agent_id: se già inizia con "agent-", usalo direttamente
                    if dude_agent_id and dude_agent_id.startswith("agent-"):
                        ws_agent_id = dude_agent_id
                    else:
                        ws_agent_id = f"agent-{dude_agent_id}" if dude_agent_id else None
                    
                    if ws_agent_id and await ws_hub.is_connected(ws_agent_id):
                        if device.monitoring_port:
                            # TCP check
                            port_result = await ws_hub.send_command(
                                ws_agent_id,
                                CommandType.SCAN_PORTS,
                                params={"target": device.primary_ip, "ports": [device.monitoring_port]},
                                timeout=10.0
                            )
                            if port_result.status == "success":
                                open_ports = port_result.data.get("open_ports", [])
                                result["success"] = True
                                result["status"] = "up" if any(p.get("port") == device.monitoring_port for p in open_ports) else "down"
                            else:
                                result["error"] = port_result.error or "Port check failed"
                        else:
                            # ICMP check
                            ping_result = await ws_hub.send_command(
                                ws_agent_id,
                                CommandType.PING,
                                params={"target": device.primary_ip, "count": 3},
                                timeout=10.0
                            )
                            if ping_result.status == "success":
                                result["success"] = True
                                result["status"] = "up" if ping_result.data.get("packet_loss", 100) < 100 else "down"
                            else:
                                result["error"] = ping_result.error or "Ping failed"
                    else:
                        result["error"] = "Agent non connesso via WebSocket"
                else:
                    result["error"] = "Agent type non supportato per monitoring"
                    
        except Exception as e:
            logger.error(f"Error checking device {device.primary_ip}: {e}")
            result["error"] = str(e)
            result["status"] = "unknown"
        
        return result
    
    async def _ping_check(self, address: str) -> bool:
        """Esegue un ping check locale"""
        try:
            import subprocess
            import platform
            
            # Comando ping dipende dal sistema operativo
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", address]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", address]
            
            result = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, timeout=2)
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"Ping check failed for {address}: {e}")
            return False
    
    async def check_all_monitored_devices(self):
        """Esegue check su tutti i dispositivi monitorati"""
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        try:
            # Carica tutti i dispositivi con monitoraggio attivo
            # Include device con monitored=True O con monitoring_type configurato (per retrocompatibilità)
            from sqlalchemy import or_, and_
            devices = session.query(InventoryDevice).filter(
                InventoryDevice.active == True,
                or_(
                    InventoryDevice.monitored == True,
                    and_(
                        InventoryDevice.monitoring_type.isnot(None),
                        InventoryDevice.monitoring_type != "none",
                        InventoryDevice.monitoring_type != "netwatch"  # Netwatch gestito da MikroTik stesso
                    )
                )
            ).all()
            
            logger.info(f"Checking {len(devices)} monitored devices...")
            
            if len(devices) == 0:
                logger.debug("No devices to check - skipping monitoring cycle")
                return
            
            # Esegui check in parallelo (max 10 alla volta)
            semaphore = asyncio.Semaphore(10)
            
            async def check_with_semaphore(device):
                async with semaphore:
                    return await self.check_device(device)
            
            tasks = [check_with_semaphore(device) for device in devices]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Aggiorna database con risultati
            updated_count = 0
            status_changed_count = 0
            
            for device, result in zip(devices, results):
                if isinstance(result, Exception):
                    logger.error(f"Error checking device {device.id} ({device.primary_ip}): {result}")
                    device.status = "unknown"
                    device.last_check = datetime.utcnow()
                    updated_count += 1
                    continue
                
                if result.get("success"):
                    old_status = device.status
                    new_status = result.get("status", "unknown")
                    
                    # Aggiorna status
                    device.status = new_status
                    device.last_check = datetime.utcnow()
                    
                    if new_status == "up":
                        device.last_seen = datetime.utcnow()
                    
                    # Log cambio stato
                    if old_status != new_status:
                        logger.info(f"Device {device.id} ({device.primary_ip}) status changed: {old_status} -> {new_status} (type: {device.monitoring_type})")
                        status_changed_count += 1
                    
                    updated_count += 1
                else:
                    error_msg = result.get('error', 'Unknown error')
                    logger.warning(f"Device {device.id} ({device.primary_ip}) check failed: {error_msg} (type: {device.monitoring_type})")
                    device.status = "unknown"
                    device.last_check = datetime.utcnow()
                    updated_count += 1
            
            session.commit()
            logger.info(f"Completed monitoring check: {updated_count}/{len(devices)} devices updated, {status_changed_count} status changes")
            
        except Exception as e:
            logger.error(f"Error in check_all_monitored_devices: {e}")
            session.rollback()
        finally:
            session.close()
    
    async def start_async(self):
        """Avvia scheduler monitoring (versione async per FastAPI lifespan)"""
        # Evita doppio avvio (in dual-port mode entrambe le app potrebbero chiamare start)
        if self._started or self.scheduler.running:
            logger.debug("Device monitoring scheduler already running - skipping")
            return
        
        self._started = True
        
        logger.info(f"Starting device monitoring scheduler (interval: {self.check_interval}s)")
        
        # Esegui un check immediato all'avvio
        try:
            await self.check_all_monitored_devices()
            logger.info("Initial monitoring check completed")
        except Exception as e:
            logger.warning(f"Initial monitoring check failed: {e}")
        
        # Configura scheduler per eseguire check periodici
        self.scheduler.add_job(
            self.check_all_monitored_devices,
            trigger=IntervalTrigger(seconds=self.check_interval),
            id="monitor_devices",
            name="Monitor Devices",
            max_instances=1,  # Evita sovrapposizioni
            coalesce=True,  # Raggruppa esecuzioni multiple
        )
        
        self.scheduler.start()
        logger.success(f"Device monitoring scheduler started (check every {self.check_interval}s)")
    
    def start(self):
        """Avvia scheduler monitoring (versione sincrona per retrocompatibilità)"""
        logger.info(f"Starting device monitoring scheduler (interval: {self.check_interval}s)")
        
        # Configura scheduler per eseguire check periodici
        self.scheduler.add_job(
            self.check_all_monitored_devices,
            trigger=IntervalTrigger(seconds=self.check_interval),
            id="monitor_devices",
            name="Monitor Devices",
            max_instances=1,  # Evita sovrapposizioni
            coalesce=True,  # Raggruppa esecuzioni multiple
        )
        
        self.scheduler.start()
        logger.success(f"Device monitoring scheduler started (check every {self.check_interval}s)")
    
    def stop(self):
        """Ferma scheduler"""
        self.scheduler.shutdown()
        logger.info("Device monitoring scheduler stopped")


# Singleton
_monitoring_service: Optional[DeviceMonitoringService] = None


def get_monitoring_service() -> DeviceMonitoringService:
    """Ottiene istanza singleton del monitoring service"""
    global _monitoring_service
    if _monitoring_service is None:
        _monitoring_service = DeviceMonitoringService()
    return _monitoring_service

