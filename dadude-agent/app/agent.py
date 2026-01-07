"""
DaDude Agent v2.0 - WebSocket mTLS Client
Entry point principale per l'agent con architettura agent-initiated
"""
import asyncio
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from loguru import logger

from .connection.ws_client import AgentWebSocketClient, ConnectionState, ReconnectionPolicy
from .connection.state_machine import ConnectionStateMachine, ConnectionEvent, ConnectionManager
from .commands.handler import CommandHandler
from .storage.local_queue import LocalQueue
from .workers.queue_worker import QueueWorker, StoreForwardManager
from .fallback.sftp_uploader import SFTPFallbackUploader, SFTPConfig
from .updater.self_update import SelfUpdater
from .scheduler.local_scheduler import LocalScheduler
from .config import get_settings

# Import opzionale per VersionManager (potrebbe non essere presente in versioni vecchie)
try:
    from .services.version_manager import VersionManager
except ImportError:
    VersionManager = None
    logger.warning("VersionManager not available - auto-update features disabled")


# Version
AGENT_VERSION = "3.0.0"  # DaDude v3.0.0 - Unified Scanner, UDP Scan, Auto-update


class DaDudeAgent:
    """
    Agent principale DaDude v2.0
    
    Architettura:
    - Connessione WebSocket bidirezionale al server (agent-initiated)
    - mTLS per autenticazione reciproca
    - Coda locale persistente per offline mode
    - Fallback SFTP quando server irraggiungibile
    - Scheduler locale per task periodici
    - Self-update automatico
    """
    
    def __init__(self):
        self.settings = get_settings()
        
        # Info agent
        self.agent_id = self.settings.agent_id
        self.agent_name = self.settings.agent_name or self.agent_id
        self.server_url = self.settings.server_url
        
        # Paths
        self.data_dir = Path(self.settings.data_dir or "/var/lib/dadude-agent")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Certificati mTLS
        self.certs_dir = self.data_dir / "certs"
        self.certs_dir.mkdir(exist_ok=True)
        
        # Componenti
        self._ws_client: Optional[AgentWebSocketClient] = None
        self._command_handler: Optional[CommandHandler] = None
        self._local_queue: Optional[LocalQueue] = None
        self._queue_worker: Optional[QueueWorker] = None
        self._sftp_uploader: Optional[SFTPFallbackUploader] = None
        self._store_forward: Optional[StoreForwardManager] = None
        self._connection_manager: Optional[ConnectionManager] = None
        self._scheduler: Optional[LocalScheduler] = None
        self._updater: Optional[SelfUpdater] = None
        self._version_manager: Optional[VersionManager] = None
        
        # State
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._connection_verified = False
        self._health_check_task: Optional[asyncio.Task] = None
    
    def _setup_logging(self):
        """Configura logging"""
        logger.remove()
        
        # Console
        logger.add(
            sys.stderr,
            level=self.settings.log_level or "INFO",
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan> - <level>{message}</level>",
        )
        
        # File
        log_file = self.data_dir / "logs" / "agent.log"
        log_file.parent.mkdir(exist_ok=True)
        
        logger.add(
            str(log_file),
            level="DEBUG",
            rotation="10 MB",
            retention="7 days",
            compression="gz",
        )
    
    def _setup_signal_handlers(self):
        """Configura handler per segnali"""
        for sig in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_event_loop().add_signal_handler(
                sig,
                lambda: asyncio.create_task(self.shutdown())
            )
    
    async def _initialize_components(self):
        """Inizializza tutti i componenti"""
        logger.info(f"Initializing DaDude Agent v{AGENT_VERSION}")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"Server URL: {self.server_url}")
        
        # Command Handler
        self._command_handler = CommandHandler()
        
        # Local Queue (SQLite)
        queue_path = self.data_dir / "queue.db"
        self._local_queue = LocalQueue(db_path=str(queue_path))
        
        # WebSocket Client
        self._ws_client = AgentWebSocketClient(
            server_url=self.server_url,
            agent_id=self.agent_id,
            agent_token=self.settings.agent_token,
            agent_version=AGENT_VERSION,
            client_cert_path=str(self.certs_dir / "agent.crt") if (self.certs_dir / "agent.crt").exists() else None,
            client_key_path=str(self.certs_dir / "agent.key") if (self.certs_dir / "agent.key").exists() else None,
            ca_cert_path=str(self.certs_dir / "ca.crt") if (self.certs_dir / "ca.crt").exists() else None,
            reconnect_policy=ReconnectionPolicy(
                initial_delay=1.0,
                max_delay=300.0,
                multiplier=2.0,
            ),
        )
        
        # Registra command handler
        self._ws_client.set_command_handler(self._command_handler.handle)
        self._ws_client.set_state_change_handler(self._on_connection_state_change)
        
        # Queue Worker (Store & Forward)
        self._store_forward = StoreForwardManager(
            ws_client=self._ws_client,
            db_path=str(queue_path),
        )
        
        # SFTP Fallback
        sftp_config = SFTPConfig.from_env()
        if sftp_config.enabled:
            self._sftp_uploader = SFTPFallbackUploader(
                agent_id=self.agent_id,
                config=sftp_config,
            )
        
        # Connection Manager (state machine + SFTP fallback)
        if self._sftp_uploader:
            self._connection_manager = ConnectionManager(
                ws_client=self._ws_client,
                sftp_uploader=self._sftp_uploader,
                local_queue=self._local_queue,
                sftp_timeout_minutes=int(os.getenv("SFTP_FALLBACK_TIMEOUT_MINUTES", "30")),
            )
        
        # Self-Updater
        self._updater = SelfUpdater(
            current_version=AGENT_VERSION,
            agent_dir=os.getenv("AGENT_DIR", "/opt/dadude-agent"),
            is_docker=os.path.exists("/.dockerenv"),
        )
        
        # Version Manager (per backup/rollback automatico)
        agent_dir = os.getenv("AGENT_DIR", "/opt/dadude-agent")
        self._version_manager = VersionManager(agent_dir=agent_dir)
        
        # Registra update callback nel command handler
        self._command_handler.set_update_callback(self._handle_update_command)
        
        # Scheduler
        self._scheduler = LocalScheduler(
            command_handler=self._command_handler,
            local_queue=self._local_queue,
            state_file=str(self.data_dir / "scheduler_state.json"),
        )
        
        logger.info("All components initialized")
    
    async def _on_connection_state_change(self, state: ConnectionState):
        """Handler per cambi stato connessione"""
        logger.info(f"Connection state changed: {state.value}")
        
        if state == ConnectionState.CONNECTED:
            # Marca connessione verificata per health check
            self._connection_verified = True
            
            # Flush coda pendente
            pending = await self._local_queue.get_pending_count()
            if pending > 0:
                logger.info(f"Flushing {pending} pending items")
                await self._ws_client.flush_pending_queue()
            
            # Se siamo in fase di health check dopo update, conferma versione stabile
            if self._version_manager:
                current_version = self._version_manager.get_current_commit()
                if current_version:
                    logger.info(f"Version {current_version[:8]} verified as stable (connected successfully)")
                    # Elimina backup vecchi, mantieni solo l'ultimo funzionante
                    try:
                        cleanup_stats = self._version_manager.cleanup_old_backups(force=True)
                        if cleanup_stats.get("deleted_backups"):
                            logger.info(f"Cleaned up {len(cleanup_stats['deleted_backups'])} old backups, keeping only the last working version")
                    except Exception as e:
                        logger.warning(f"Error cleaning up old backups: {e}")
    
    async def _cleanup_disk_space(self):
        """Esegue pulizia spazio disco all'avvio."""
        if not self._version_manager:
            return
        
        try:
            logger.info("Running disk cleanup on startup...")
            cleanup_stats = self._version_manager.cleanup_all()
            
            if cleanup_stats["total_freed_mb"] > 0:
                logger.info(f"Disk cleanup freed {cleanup_stats['total_freed_mb']}MB")
            else:
                logger.info("Disk cleanup: no cleanup needed")
        except Exception as e:
            logger.warning(f"Disk cleanup error: {e}")
    
    async def _check_and_update_on_startup(self):
        """
        Verifica aggiornamenti all'avvio e applica se necessario.
        Se l'update fallisce la connessione, esegue rollback automatico.
        """
        if not self._version_manager:
            logger.debug("VersionManager not available, skipping update check")
            return
        
        try:
            agent_dir = os.getenv("AGENT_DIR", "/opt/dadude-agent")
            logger.info(f"Checking for updates on startup (agent_dir={agent_dir})...")
            
            # Verifica se ci sono aggiornamenti disponibili
            new_commit = self._version_manager.check_for_updates()
            current_commit = self._version_manager.get_current_commit()
            
            if not new_commit:
                if current_commit:
                    logger.info(f"No updates available (current: {current_commit[:8]})")
                else:
                    logger.info("No updates available (could not determine current version)")
                return
            
            # Verifica se la nuova versione è marcata come bad
            if self._version_manager.is_bad_version(new_commit):
                logger.warning(f"Update {new_commit[:8]} is marked as bad, skipping")
                return
            
            logger.info(f"Update available: {current_commit[:8] if current_commit else 'unknown'} -> {new_commit[:8]}")
            
            # Backup versione corrente
            backup_path = self._version_manager.backup_current_version()
            if not backup_path:
                logger.error("Failed to create backup, aborting update")
                return
            
            # Aggiorna alla nuova versione
            if not self._version_manager.update_to_version(new_commit):
                logger.error("Failed to update, restoring backup...")
                self._version_manager.restore_backup(backup_path)
                return
            
            logger.info(f"Updated to {new_commit[:8]}, code updated on disk")
            logger.warning("IMPORTANT: Container restart required to load new code. Creating restart flag...")
            
            # Crea flag file per richiedere restart (gestito da watchdog esterno o manuale)
            restart_flag = Path(agent_dir) / ".restart_required"
            try:
                restart_flag.write_text(f"Updated to {new_commit[:8]} at {datetime.now().isoformat()}\n")
                logger.info(f"Restart flag created: {restart_flag}")
            except Exception as e:
                logger.warning(f"Could not create restart flag: {e}")
            
            # Avvia health check: se non ci connettiamo entro il timeout, rollback
            self._connection_verified = False
            self._health_check_task = asyncio.create_task(self._health_check_after_update(new_commit, backup_path))
            
        except Exception as e:
            logger.error(f"Error during startup update check: {e}", exc_info=True)
    
    async def _health_check_after_update(self, new_commit: str, backup_path: str):
        """
        Health check dopo update: verifica connessione entro timeout.
        Se fallisce, esegue rollback automatico.
        """
        if not self._version_manager:
            return
        
        timeout = self._version_manager.health_check_timeout
        check_interval = 10  # Verifica ogni 10 secondi
        elapsed = 0
        
        logger.info(f"Health check started: waiting up to {timeout}s for connection...")
        
        while elapsed < timeout:
            await asyncio.sleep(check_interval)
            elapsed += check_interval
            
            if self._connection_verified:
                logger.success(f"Version {new_commit[:8]} verified as stable (connected successfully)")
                # Versione stabile, rimuovi il flag di restart se presente
                restart_flag = Path(self._version_manager.agent_dir) / ".restart_required"
                if restart_flag.exists():
                    restart_flag.unlink()
                
                # Elimina backup vecchi, mantieni solo l'ultimo funzionante
                try:
                    cleanup_stats = self._version_manager.cleanup_old_backups(force=True)
                    if cleanup_stats.get("deleted_backups"):
                        logger.info(f"Cleaned up {len(cleanup_stats['deleted_backups'])} old backups, keeping only the last working version")
                except Exception as e:
                    logger.warning(f"Error cleaning up old backups: {e}")
                
                return
        
        # Timeout: rollback automatico
        logger.error(f"Health check failed: no connection after {timeout}s, rolling back...")
        self._version_manager.mark_version_bad(new_commit)
        
        if self._version_manager.restore_backup(backup_path):
            logger.info("Rollback completed, restarting container...")
            # Crea flag per restart (il container si riavvierà)
            restart_flag = Path(self._version_manager.agent_dir) / ".restart_required"
            restart_flag.touch()
            
            # Termina l'agent per forzare restart
            await asyncio.sleep(2)
            logger.info("Shutting down to trigger container restart...")
            await self.shutdown()
            os._exit(1)  # Exit forzato per triggerare restart policy
    
    async def _handle_update_command(self, download_url: str, checksum: str) -> bool:
        """Handler per comando update"""
        result = await self._updater.update(
            download_url=download_url if download_url else None,
            expected_checksum=checksum if checksum else None,
        )
        return result.success
    
    async def _enrollment_if_needed(self):
        """Esegue enrollment certificato se necessario"""
        cert_file = self.certs_dir / "agent.crt"
        key_file = self.certs_dir / "agent.key"
        ca_file = self.certs_dir / "ca.crt"
        
        if cert_file.exists() and key_file.exists() and ca_file.exists():
            logger.info("Certificates already present")
            return True
        
        logger.info("Certificates not found, requesting enrollment...")
        
        try:
            import httpx
            
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.server_url}/api/v1/agents/enroll",
                    json={
                        "agent_id": self.agent_id,
                        "agent_name": self.agent_name,
                    },
                    headers={"Authorization": f"Bearer {self.settings.agent_token}"},
                    timeout=30.0,
                )
                
                if response.status_code == 403:
                    logger.warning("Agent not approved yet - waiting for admin approval")
                    return False
                
                if response.status_code != 200:
                    logger.error(f"Enrollment failed: {response.status_code} {response.text}")
                    return False
                
                data = response.json()
                
                # Salva certificati
                with open(cert_file, "w") as f:
                    f.write(data["certificate"])
                
                with open(key_file, "w") as f:
                    f.write(data["private_key"])
                os.chmod(key_file, 0o600)
                
                with open(ca_file, "w") as f:
                    f.write(data["ca_certificate"])
                
                logger.success("Certificate enrollment successful")
                
                # Aggiorna paths nel ws_client
                self._ws_client.client_cert_path = str(cert_file)
                self._ws_client.client_key_path = str(key_file)
                self._ws_client.ca_cert_path = str(ca_file)
                
                return True
                
        except Exception as e:
            logger.error(f"Enrollment error: {e}")
            return False
    
    async def _auto_register(self) -> bool:
        """
        Auto-registrazione dell'agent al server.
        Deve essere fatto PRIMA di tentare la connessione WebSocket.
        """
        logger.info("Attempting auto-registration with server...")
        
        try:
            import httpx
            import platform
            import re
            
            # Leggi la versione direttamente dal file invece di usare la costante in memoria
            # Questo assicura che dopo un update, venga inviata la versione corretta
            agent_version = AGENT_VERSION
            try:
                agent_file = Path(__file__).parent / "agent.py"
                if agent_file.exists():
                    content = agent_file.read_text()
                    match = re.search(r'AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                    if match:
                        agent_version = match.group(1)
                        if agent_version != AGENT_VERSION:
                            logger.info(f"Version mismatch detected: memory={AGENT_VERSION}, file={agent_version}, using file version")
            except Exception as e:
                logger.warning(f"Could not read version from file: {e}, using memory version")
            
            # Non inviamo detected_ip - il server lo rileverà dalla connessione HTTP
            # Questo evita problemi con IP interni Docker
            
            registration_data = {
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "agent_type": "docker",
                "version": agent_version,
                "agent_token": self.settings.agent_token,  # Invia token per sincronizzazione
                "detected_ip": None,  # Server userà request.client.host
                "detected_hostname": platform.node(),
                "capabilities": ["ssh", "snmp", "wmi", "nmap", "dns"],
                "os_info": platform.platform(),
                "python_version": platform.python_version(),
            }
            
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.server_url}/api/v1/agents/register",
                    json=registration_data,
                    headers={"Authorization": f"Bearer {self.settings.agent_token}"},
                    timeout=30.0,
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get("registered"):
                        # Nuovo agent registrato
                        new_token = data.get("agent_token")
                        if new_token:
                            logger.info(f"New token received from server")
                            # Aggiorna token in memoria (il .env va aggiornato manualmente o via update)
                            self._ws_client.agent_token = new_token
                        
                        logger.success(f"Agent registered: {data.get('agent_db_id')}")
                        logger.warning("Agent is pending approval - waiting for admin to approve")
                        return True
                    
                    elif data.get("updated"):
                        # Agent già esistente, info aggiornate
                        logger.info(f"Agent info updated: {data.get('agent_db_id')}")
                        return True
                    
                    else:
                        logger.info("Registration response: " + str(data))
                        return True
                
                else:
                    logger.warning(f"Registration failed: {response.status_code} - {response.text}")
                    return False
                    
        except Exception as e:
            logger.error(f"Auto-registration error: {e}")
            return False
    
    async def run(self):
        """Loop principale dell'agent"""
        self._setup_logging()
        
        logger.info("=" * 60)
        logger.info(f"DaDude Agent v{AGENT_VERSION}")
        logger.info("=" * 60)
        
        try:
            self._setup_signal_handlers()
        except Exception:
            # Signal handlers non disponibili (es. Windows)
            pass
        
        # Inizializza Version Manager per check aggiornamenti (se disponibile)
        if VersionManager is not None:
            try:
                agent_dir = os.getenv("AGENT_DIR", "/opt/dadude-agent")
                self._version_manager = VersionManager(agent_dir=agent_dir)
                
                # Verifica e applica aggiornamenti all'avvio (PRIMA di inizializzare componenti)
                await self._check_and_update_on_startup()
                
                # Esegui pulizia spazio disco all'avvio
                await self._cleanup_disk_space()
            except Exception as e:
                logger.warning(f"VersionManager initialization failed: {e}, continuing without auto-update")
                self._version_manager = None
        else:
            logger.info("VersionManager not available, skipping auto-update checks")
        
        await self._initialize_components()
        
        self._running = True
        
        # Step 1: Auto-registrazione (HTTP) - con retry infinito fino al successo
        max_registration_retries = 10
        registration_retry_delay = 30  # secondi
        registered = False
        
        for attempt in range(max_registration_retries):
            registered = await self._auto_register()
            if registered:
                logger.success("Auto-registration successful")
                break
            else:
                if attempt < max_registration_retries - 1:
                    logger.warning(f"Auto-registration failed (attempt {attempt + 1}/{max_registration_retries}), retrying in {registration_retry_delay}s...")
                    await asyncio.sleep(registration_retry_delay)
                else:
                    logger.error("Auto-registration failed after all retries, but continuing anyway")
        
        # Step 2: Prova enrollment certificati (se approvato) - con retry
        enrolled = False
        for attempt in range(3):
            enrolled = await self._enrollment_if_needed()
            if enrolled:
                break
            elif attempt < 2:
                logger.warning(f"Enrollment failed (attempt {attempt + 1}/3), retrying in 10s...")
                await asyncio.sleep(10)
        
        if not enrolled:
            logger.warning("Running without mTLS certificates (token auth only)")
        
        # Avvia componenti background
        await self._store_forward.start()
        await self._scheduler.start()
        
        logger.info("Agent running - connecting to server...")
        
        # Loop principale con retry infinito per connessione
        try:
            if self._connection_manager:
                # ConnectionManager gestisce già retry automatici
                await self._connection_manager.start()
            else:
                # WebSocket client con retry infinito
                while self._running:
                    try:
                        await self._ws_client.run()
                        # Se run() ritorna senza errore, la connessione è stata chiusa normalmente
                        # Riprova dopo un breve delay
                        if self._running:
                            logger.warning("WebSocket connection closed, reconnecting in 10s...")
                            await asyncio.sleep(10)
                    except Exception as e:
                        logger.error(f"WebSocket error: {e}, reconnecting in 10s...")
                        await asyncio.sleep(10)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Agent error: {e}")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Shutdown pulito dell'agent"""
        if not self._running:
            return
        
        logger.info("Shutting down agent...")
        self._running = False
        
        # Ferma scheduler
        if self._scheduler:
            await self._scheduler.stop()
        
        # Ferma store & forward
        if self._store_forward:
            await self._store_forward.stop()
        
        # Disconnetti
        if self._connection_manager:
            await self._connection_manager.stop()
        elif self._ws_client:
            await self._ws_client.disconnect()
        
        logger.info("Agent shutdown complete")
        self._shutdown_event.set()
    
    async def get_status(self) -> dict:
        """Ottiene stato corrente dell'agent"""
        import platform
        
        queue_stats = await self._local_queue.get_stats() if self._local_queue else {}
        scheduler_stats = self._scheduler.get_stats() if self._scheduler else {}
        
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "version": AGENT_VERSION,
            "connected": self._ws_client.is_connected if self._ws_client else False,
            "connection_state": self._ws_client.state.value if self._ws_client else "unknown",
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "queue": queue_stats,
            "scheduler": scheduler_stats,
        }


def main():
    """Entry point"""
    agent = DaDudeAgent()
    
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

