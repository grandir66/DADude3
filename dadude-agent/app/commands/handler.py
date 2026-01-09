"""
DaDude Agent - Command Handler
Gestisce comandi ricevuti dal server via WebSocket
"""
import asyncio
import os
import subprocess
import random
from typing import Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from loguru import logger


class CommandAction(str, Enum):
    """Azioni comando supportate"""
    # Network scanning
    SCAN_NETWORK = "scan_network"
    PORT_SCAN = "port_scan"
    DNS_REVERSE = "dns_reverse"
    
    # Device probing
    PROBE_WMI = "probe_wmi"
    PROBE_SSH = "probe_ssh"
    PROBE_SSH_ADVANCED = "probe_ssh_advanced"
    PROBE_SNMP = "probe_snmp"
    PROBE_UNIFIED = "probe_unified"  # Scan multi-protocollo unificato
    
    # ARP table lookup (MikroTik API o SNMP)
    GET_ARP_TABLE = "get_arp_table"
    
    # Agent management
    UPDATE_AGENT = "update_agent"
    RESTART = "restart"
    REBOOT = "reboot"
    GET_STATUS = "get_status"
    GET_CONFIG = "get_config"
    SET_CONFIG = "set_config"
    SYNC_CONFIG = "sync_config"  # Sincronizza configurazione dal server
    
    # Scheduled tasks
    DAILY_RESTART = "daily_restart"
    CONNECTION_WATCHDOG = "connection_watchdog"
    CLEANUP_QUEUE = "cleanup_queue"
    CHECK_UPDATES = "check_updates"
    
    # Diagnostics
    PING = "ping"
    TRACEROUTE = "traceroute"
    NMAP_SCAN = "nmap_scan"
    
    # Remote shell
    EXEC_COMMAND = "exec_command"
    EXEC_SSH = "exec_ssh"
    UPDATE_AGENT_PROXMOX = "update_agent_proxmox"


@dataclass
class CommandResult:
    """Risultato esecuzione comando"""
    success: bool
    status: str  # "success", "error", "timeout", "cancelled"
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    execution_time_ms: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "status": self.status,
            "data": self.data,
            "error": self.error,
            "execution_time_ms": self.execution_time_ms,
        }


@dataclass
class UpdateCheckpoint:
    """Checkpoint durante update per rollback"""
    step: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    backup_paths: Dict[str, str] = field(default_factory=dict)
    git_commit: Optional[str] = None
    docker_image: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class UpdateManager:
    """
    Manager per update agent con checkpoint, retry automatico e health check.
    Gestisce rollback automatico su fallimento.
    """
    
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
        health_check_timeout: float = 120.0,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.health_check_timeout = health_check_timeout
        self.checkpoints: list[UpdateCheckpoint] = []
    
    def create_checkpoint(self, step: str, **metadata) -> UpdateCheckpoint:
        """Crea checkpoint durante update"""
        checkpoint = UpdateCheckpoint(step=step, metadata=metadata)
        self.checkpoints.append(checkpoint)
        logger.debug(f"Update checkpoint created: {step}")
        return checkpoint
    
    def get_latest_checkpoint(self) -> Optional[UpdateCheckpoint]:
        """Ottiene ultimo checkpoint"""
        return self.checkpoints[-1] if self.checkpoints else None
    
    async def execute_with_retry(
        self,
        operation: Callable[[], Awaitable[CommandResult]],
        operation_name: str = "operation"
    ) -> CommandResult:
        """
        Esegue operazione con retry automatico e exponential backoff.
        
        Args:
            operation: Funzione async che ritorna CommandResult
            operation_name: Nome operazione per logging
            
        Returns:
            CommandResult dell'ultimo tentativo
        """
        last_result = None
        
        for attempt in range(1, self.max_retries + 1):
            try:
                logger.info(f"{operation_name} - Attempt {attempt}/{self.max_retries}")
                result = await operation()
                
                if result.success:
                    logger.success(f"{operation_name} succeeded on attempt {attempt}")
                    return result
                
                last_result = result
                logger.warning(f"{operation_name} failed on attempt {attempt}: {result.error}")
                
                # Se non è l'ultimo tentativo, aspetta prima di riprovare
                if attempt < self.max_retries:
                    delay = min(
                        self.base_delay * (2.0 ** (attempt - 1)),
                        self.max_delay
                    )
                    jitter = random.uniform(0, delay * 0.1)
                    total_delay = delay + jitter
                    logger.info(f"Retrying {operation_name} in {total_delay:.1f}s...")
                    await asyncio.sleep(total_delay)
                
            except Exception as e:
                logger.error(f"{operation_name} exception on attempt {attempt}: {e}")
                last_result = CommandResult(
                    success=False,
                    status="error",
                    error=f"Exception: {str(e)}"
                )
                if attempt < self.max_retries:
                    delay = min(
                        self.base_delay * (2.0 ** (attempt - 1)),
                        self.max_delay
                    )
                    await asyncio.sleep(delay)
        
        logger.error(f"{operation_name} failed after {self.max_retries} attempts")
        return last_result or CommandResult(
            success=False,
            status="error",
            error=f"{operation_name} failed after {self.max_retries} attempts"
        )
    
    async def verify_update_success(self) -> bool:
        """
        Verifica che l'update sia stato completato con successo.
        Controlla:
        - Container riavviato correttamente
        - WebSocket si riconnette (se disponibile)
        - Health check passa
        
        Returns:
            True se update verificato con successo
        """
        logger.info("Verifying update success...")
        
        # Check 1: Container in esecuzione
        try:
            result = subprocess.run(
                ["docker", "ps", "--filter", "name=dadude-agent", "--format", "{{.Status}}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or "Up" not in result.stdout:
                logger.warning("Container not running after update")
                return False
            logger.info("✓ Container is running")
        except Exception as e:
            logger.warning(f"Could not verify container status: {e}")
        
        # Check 2: Health check endpoint (se disponibile)
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get("http://localhost:8080/health")
                if response.status_code == 200:
                    logger.info("✓ Health check passed")
                else:
                    logger.warning(f"Health check returned {response.status_code}")
                    return False
        except Exception as e:
            logger.debug(f"Health check endpoint not available: {e}")
            # Non critico se non disponibile
        
        # Check 3: Attendi riconnessione WebSocket (se disponibile)
        # Questo viene gestito automaticamente dal client WebSocket
        
        logger.success("Update verification completed")
        return True
    
    async def rollback(self, checkpoint: Optional[UpdateCheckpoint] = None) -> bool:
        """
        Esegue rollback a un checkpoint specifico o all'ultimo.
        
        Args:
            checkpoint: Checkpoint a cui tornare (None = ultimo)
            
        Returns:
            True se rollback completato con successo
        """
        target = checkpoint or self.get_latest_checkpoint()
        if not target:
            logger.warning("No checkpoint available for rollback")
            return False
        
        logger.warning(f"Rolling back to checkpoint: {target.step}")
        
        try:
            # Ripristina backup files
            for original_path, backup_path in target.backup_paths.items():
                if os.path.exists(backup_path):
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    import shutil
                    shutil.copy(backup_path, original_path)
                    logger.info(f"Restored {original_path}")
            
            # Ripristina git commit se disponibile
            if target.git_commit:
                agent_dir = "/opt/dadude-agent"
                result = subprocess.run(
                    ["git", "reset", "--hard", target.git_commit],
                    cwd=agent_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if result.returncode == 0:
                    logger.info(f"Restored git commit: {target.git_commit[:8]}")
            
            logger.success("Rollback completed")
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False


class CommandHandler:
    """
    Handler per comandi dal server.
    Esegue probe, scan e operazioni di gestione.
    """
    
    def __init__(self):
        # Import probe modules
        from ..probes import wmi_probe, ssh_probe, snmp_probe
        from ..scanners import port_scanner, dns_resolver
        
        self._wmi_probe = wmi_probe
        self._ssh_probe = ssh_probe
        self._snmp_probe = snmp_probe
        self._port_scanner = port_scanner
        self._dns_resolver = dns_resolver
        
        # Custom handlers
        self._custom_handlers: Dict[str, Callable[[Dict], Awaitable[CommandResult]]] = {}
        
        # Update callback (per self-update)
        self._update_callback: Optional[Callable[[str, str], Awaitable[bool]]] = None
    
    async def handle(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Gestisce comando e ritorna risultato.
        
        Args:
            command: Dict con id, action, params
            
        Returns:
            Dict con status, data, error
        """
        action = command.get("action", "")
        params = command.get("params", {})
        command_id = command.get("id", "unknown")
        
        start_time = datetime.utcnow()
        
        logger.info(f"Executing command: {action} (id={command_id})")
        
        try:
            result = await self._execute_action(action, params)
            
        except asyncio.TimeoutError:
            result = CommandResult(
                success=False,
                status="timeout",
                error="Command execution timed out",
            )
        except asyncio.CancelledError:
            result = CommandResult(
                success=False,
                status="cancelled",
                error="Command was cancelled",
            )
        except Exception as e:
            logger.error(f"Command error: {e}")
            result = CommandResult(
                success=False,
                status="error",
                error=str(e),
            )
        
        # Calcola tempo esecuzione
        execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        result.execution_time_ms = int(execution_time)
        
        return result.to_dict()
    
    async def _execute_action(self, action: str, params: Dict) -> CommandResult:
        """Esegue azione specifica"""
        
        # Check custom handlers first
        if action in self._custom_handlers:
            return await self._custom_handlers[action](params)
        
        # Network scanning
        if action == CommandAction.SCAN_NETWORK.value:
            return await self._scan_network(params)
        
        elif action == CommandAction.PORT_SCAN.value:
            return await self._port_scan(params)
        
        elif action == CommandAction.DNS_REVERSE.value:
            return await self._dns_reverse(params)
        
        # Device probing
        elif action == CommandAction.PROBE_WMI.value:
            return await self._probe_wmi(params)
        
        elif action == CommandAction.PROBE_SSH.value:
            return await self._probe_ssh(params)
        
        elif action == CommandAction.PROBE_SSH_ADVANCED.value:
            return await self._probe_ssh_advanced(params)
        
        elif action == CommandAction.PROBE_SNMP.value:
            logger.debug(f"[HANDLER] PROBE_SNMP action matched, calling _probe_snmp with params: {list(params.keys())}")
            return await self._probe_snmp(params)
        
        elif action == CommandAction.PROBE_UNIFIED.value:
            logger.debug(f"[HANDLER] PROBE_UNIFIED action matched, calling _probe_unified with params: {list(params.keys())}")
            return await self._probe_unified(params)
        
        elif action == CommandAction.GET_ARP_TABLE.value:
            return await self._get_arp_table(params)
        
        # Agent management
        elif action == CommandAction.UPDATE_AGENT.value:
            return await self._update_agent(params)
        
        elif action == CommandAction.RESTART.value:
            return await self._restart()
        
        elif action == CommandAction.REBOOT.value:
            return await self._reboot()
        
        elif action == CommandAction.GET_STATUS.value:
            return await self._get_status()
        
        # Diagnostics
        elif action == CommandAction.PING.value:
            return await self._ping(params)
        
        elif action == CommandAction.NMAP_SCAN.value:
            return await self._nmap_scan(params)
        
        # Scheduled tasks
        elif action == CommandAction.DAILY_RESTART.value:
            return await self._daily_restart(params)
        
        elif action == CommandAction.CONNECTION_WATCHDOG.value:
            return await self._connection_watchdog(params)
        
        elif action == CommandAction.CLEANUP_QUEUE.value:
            return await self._cleanup_queue(params)
        
        elif action == CommandAction.CHECK_UPDATES.value:
            return await self._check_updates(params)
        
        # Remote shell
        elif action == CommandAction.EXEC_COMMAND.value:
            return await self._exec_command(params)
        
        elif action == CommandAction.EXEC_SSH.value:
            return await self._exec_ssh(params)
        elif action == CommandAction.UPDATE_AGENT_PROXMOX.value:
            return await self._update_agent_proxmox(params)
        
        elif action == CommandAction.SYNC_CONFIG.value or action == "SYNC_CONFIG":
            return await self._sync_config(params)
        
        else:
            return CommandResult(
                success=False,
                status="error",
                error=f"Unknown action: {action}",
            )
    
    # ==========================================
    # NETWORK SCANNING
    # ==========================================
    
    async def _scan_network(self, params: Dict) -> CommandResult:
        """Scansione rete"""
        network = params.get("network")
        scan_type = params.get("scan_type", "ping")
        
        if not network:
            return CommandResult(success=False, status="error", error="Missing 'network' parameter")
        
        try:
            # Usa nmap se disponibile
            if self._is_nmap_available():
                result = await self._nmap_network_scan(network, scan_type)
            else:
                # Fallback a scan ping base
                result = await self._basic_ping_scan(network)
            
            return CommandResult(
                success=True,
                status="success",
                data={"hosts": result},
            )
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _port_scan(self, params: Dict) -> CommandResult:
        """Scansione porte"""
        target = params.get("target")
        ports = params.get("ports")
        timeout = params.get("timeout", 1.0)
        
        if not target:
            return CommandResult(success=False, status="error", error="Missing 'target' parameter")
        
        try:
            result = await asyncio.to_thread(
                self._port_scanner.scan_ports,
                target, ports, timeout
            )
            return CommandResult(success=True, status="success", data=result)
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _dns_reverse(self, params: Dict) -> CommandResult:
        """Reverse DNS lookup"""
        targets = params.get("targets", [])
        dns_server = params.get("dns_server")
        
        if not targets:
            return CommandResult(success=False, status="error", error="Missing 'targets' parameter")
        
        try:
            result = await asyncio.to_thread(
                self._dns_resolver.reverse_lookup_batch,
                targets, dns_server
            )
            return CommandResult(success=True, status="success", data={"results": result})
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    # ==========================================
    # DEVICE PROBING
    # ==========================================
    
    async def _probe_wmi(self, params: Dict) -> CommandResult:
        """Probe WMI"""
        target = params.get("target")
        username = params.get("username")
        password = params.get("password")
        domain = params.get("domain") or ""  # Handle None explicitly
        
        if not all([target, username, password]):
            return CommandResult(
                success=False, 
                status="error", 
                error="Missing required parameters: target, username, password"
            )
        
        try:
            logger.debug(f"WMI probe: target={target}, user={domain}\\{username if domain else username}")
            # wmi_probe.probe è già async, chiamalo direttamente
            result = await self._wmi_probe.probe(
                target, username, password, domain
            )
            logger.debug(f"WMI probe result: {len(result) if result else 0} fields")
            return CommandResult(success=True, status="success", data=result)
        except Exception as e:
            import traceback
            logger.error(f"WMI probe error: {e}")
            logger.error(traceback.format_exc())
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _probe_ssh(self, params: Dict) -> CommandResult:
        """Probe SSH"""
        target = params.get("target")
        username = params.get("username")
        password = params.get("password")
        private_key = params.get("private_key")
        port = params.get("port", 22)
        
        if not target or not username:
            return CommandResult(
                success=False,
                status="error",
                error="Missing required parameters: target, username"
            )
        
        if not password and not private_key:
            return CommandResult(
                success=False,
                status="error",
                error="Either password or private_key required"
            )
        
        try:
            # ssh_probe.probe è già async, chiamalo direttamente
            result = await self._ssh_probe.probe(
                target, username, password, private_key, port
            )
            # Log summary dei dati raccolti
            if isinstance(result, dict):
                result_keys = list(result.keys())
                logger.debug(f"SSH probe handler: Returning {len(result_keys)} fields: {sorted(result_keys)[:30]}")
                if result.get("running_services_count"):
                    logger.debug(f"SSH probe handler: running_services_count={result.get('running_services_count')}, cron_jobs_count={result.get('cron_jobs_count')}, neighbors_count={result.get('neighbors_count')}")
            return CommandResult(success=True, status="success", data=result)
        except Exception as e:
            logger.error(f"SSH probe handler error: {e}", exc_info=True)
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _probe_ssh_advanced(self, params: Dict) -> CommandResult:
        """Probe SSH Advanced - scan completo"""
        target = params.get("target")
        username = params.get("username")
        password = params.get("password")
        private_key = params.get("private_key")
        port = params.get("port", 22)
        
        if not target or not username:
            return CommandResult(
                success=False,
                status="error",
                error="Missing required parameters: target, username"
            )
        
        if not password and not private_key:
            return CommandResult(
                success=False,
                status="error",
                error="Either password or private_key required"
            )
        
        try:
            from ..probes.ssh_advanced_scanner import scan_advanced
            
            logger.debug(f"SSH Advanced probe: target={target}, user={username}, port={port}")
            result = await scan_advanced(
                target=target,
                username=username,
                password=password,
                private_key=private_key,
                port=port,
                timeout=30,
            )
            
            # Log summary dei dati raccolti
            if isinstance(result, dict):
                result_keys = list(result.keys())
                logger.debug(f"SSH Advanced probe handler: Returning {len(result_keys)} fields")
            return CommandResult(success=True, status="success", data=result)
        except Exception as e:
            import traceback
            logger.error(f"SSH Advanced probe handler error: {e}")
            logger.error(traceback.format_exc())
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _probe_snmp(self, params: Dict) -> CommandResult:
        """Probe SNMP"""
        target = params.get("target")
        community = params.get("community", "public")
        version = params.get("version", "2c")
        port = params.get("port", 161)
        
        logger.debug(f"[PROBE_SNMP] Starting SNMP probe for {target}:{port} with community '{community}' (v{version})")
        
        if not target:
            logger.error(f"[PROBE_SNMP] Missing 'target' parameter")
            return CommandResult(success=False, status="error", error="Missing 'target' parameter")
        
        try:
            # snmp_probe.probe è già async, chiamalo direttamente
            logger.debug(f"[PROBE_SNMP] Calling snmp_probe.probe({target}, {community}, {version}, {port})")
            result = await self._snmp_probe.probe(
                target, community, version, port
            )
            
            logger.debug(f"[PROBE_SNMP] SNMP probe completed for {target}, result keys: {list(result.keys())[:30]}")
            
            # Log what fields are being returned
            basic_fields = ['sysDescr', 'sysName', 'sysObjectID', 'device_type', 'category', 'vendor', 'manufacturer', 'model', 'serial_number', 'firmware_version', 'interface_count', 'uptime_formatted']
            advanced_fields = ['neighbors', 'lldp_neighbors', 'cdp_neighbors', 'routing_table', 'arp_table', 'interfaces', 'interface_details']
            returned_basic = [f for f in basic_fields if f in result]
            returned_advanced = [f for f in advanced_fields if f in result]
            
            logger.debug(f"[PROBE_SNMP] Basic fields returned: {returned_basic}")
            logger.debug(f"[PROBE_SNMP] Advanced fields returned: {returned_advanced}")
            
            if result.get("neighbors") or result.get("lldp_neighbors"):
                neighbors_count = len(result.get("neighbors", [])) or len(result.get("lldp_neighbors", []))
                logger.debug(f"[PROBE_SNMP] ✓ Found {neighbors_count} neighbors")
            else:
                logger.debug(f"[PROBE_SNMP] ✗ No neighbors found")
            
            logger.debug(f"SNMP probe handler: Returning {len(result)} fields for {target}")
            logger.debug(f"SNMP probe handler: Basic fields: {len(returned_basic)}/{len(basic_fields)}, Advanced fields: {len(returned_advanced)}/{len(advanced_fields)}")
            if returned_advanced:
                logger.debug(f"SNMP probe handler: Advanced data returned: {returned_advanced}")
            else:
                logger.warning(f"SNMP probe handler: No advanced data returned for {target} (device_type={result.get('device_type')}, is_network={result.get('device_type') in ['router', 'switch', 'ap', 'network']})")
            
            return CommandResult(success=True, status="success", data=result)
        except Exception as e:
            logger.error(f"SNMP probe handler error: {e}", exc_info=True)
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _probe_unified(self, params: Dict) -> CommandResult:
        """
        Esegue scan multi-protocollo unificato usando unified_scanner_probe
        (con port scan preventivo per evitare timeout inutili)
        
        Params:
            target: IP o hostname
            protocols: Lista protocolli ['ssh', 'snmp', 'winrm'] o None per auto
            ssh_user, ssh_password, ssh_key, ssh_port: Credenziali SSH
            winrm_user, winrm_password, winrm_domain, winrm_port: Credenziali WinRM
            snmp_community, snmp_port, snmp_version: Credenziali SNMP
            timeout: Timeout per scansioni
        """
        from ..probes.unified_scanner_probe import probe as unified_probe
        
        target = params.get("target")
        if not target:
            return CommandResult(success=False, status="error", error="Missing 'target' parameter")
        
        protocols = params.get("protocols", ["auto"])
        if isinstance(protocols, str):
            protocols = [protocols]
        
        timeout = params.get("timeout", 30)
        
        try:
            logger.debug(f"[UNIFIED] Starting probe for {target} with protocols {protocols}, timeout={timeout}s")
            
            # Prepara credenziali nel formato atteso da unified_scanner_probe
            credentials = {
                "snmp": {
                    "community": params.get("snmp_community", "public"),
                    "port": params.get("snmp_port", 161),
                    "version": str(params.get("snmp_version", 2)) + "c" if params.get("snmp_version", 2) != 3 else "3",
                },
                "ssh": {
                    "username": params.get("ssh_user"),
                    "password": params.get("ssh_password"),
                    "port": params.get("ssh_port", 22),
                },
                "wmi": {
                    "username": params.get("winrm_user"),
                    "password": params.get("winrm_password"),
                    "domain": params.get("winrm_domain", ""),
                },
            }
            
            # Log credenziali per debug (senza password)
            logger.debug(f"[UNIFIED] SSH credentials: username={credentials['ssh'].get('username')}, "
                       f"password={'***' if credentials['ssh'].get('password') else 'None'}, "
                       f"port={credentials['ssh'].get('port')}")
            logger.debug(f"[UNIFIED] WMI credentials: username={credentials['wmi'].get('username')}, "
                       f"password={'***' if credentials['wmi'].get('password') else 'None'}, "
                       f"domain={credentials['wmi'].get('domain')}")
            
            result = await unified_probe(
                target=target,
                protocols=protocols,
                credentials=credentials,
                timeout=timeout,
                include_software=True,
                include_services=True,
                include_users=False,
            )
            
            # Verifica risultato
            protocol_used = result.get("protocol_used", "")
            has_data = bool(result.get("system_info", {}).get("hostname"))
            
            if protocol_used and has_data:
                logger.info(f"[UNIFIED] Probe successful for {target}, protocol: {protocol_used}")
                return CommandResult(
                    success=True,
                    status="success",
                    data=result,
                )
            elif result.get("errors"):
                error_msg = "; ".join(result.get("errors", []))
                logger.warning(f"[UNIFIED] Probe failed for {target}: {error_msg}")
                return CommandResult(
                    success=False,
                    status="error",
                    error=error_msg,
                    data=result,  # Ritorna comunque i dati parziali
                )
            else:
                # Nessun errore esplicito ma nessun dato
                warnings = result.get("warnings", [])
                open_ports = result.get("open_ports", [])
                open_list = [p["port"] for p in open_ports if p.get("open")]
                msg = f"Nessun dato ottenuto. Porte aperte: {open_list}. Warnings: {warnings}"
                logger.warning(f"[UNIFIED] {msg}")
                return CommandResult(
                    success=False,
                    status="error",
                    error=msg,
                    data=result,
                )
                
        except Exception as e:
            logger.error(f"[UNIFIED] Probe handler error for {target}: {e}", exc_info=True)
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _get_arp_table(self, params: Dict) -> CommandResult:
        """
        Ottiene tabella ARP da un gateway (MikroTik API o SNMP generico).
        
        Params:
            method: "mikrotik" o "snmp"
            network_cidr: es. "192.168.1.0/24" per filtrare
            
            Per MikroTik:
                address, port, username, password, use_ssl
                
            Per SNMP:
                address, community, version (1, 2c)
        """
        method = params.get("method", "mikrotik")
        network_cidr = params.get("network_cidr")
        
        if method == "mikrotik":
            return await self._get_arp_mikrotik(params, network_cidr)
        elif method == "snmp":
            return await self._get_arp_snmp(params, network_cidr)
        else:
            return CommandResult(
                success=False, 
                status="error", 
                error=f"Unknown method: {method}. Use 'mikrotik' or 'snmp'"
            )
    
    async def _get_arp_mikrotik(self, params: Dict, network_cidr: str = None) -> CommandResult:
        """Query ARP table via MikroTik RouterOS API"""
        import ipaddress
        
        address = params.get("address")
        port = params.get("port", 8728)
        username = params.get("username", "admin")
        password = params.get("password", "")
        use_ssl = params.get("use_ssl", False)
        
        if not address:
            return CommandResult(success=False, status="error", error="Missing 'address' parameter")
        
        try:
            import routeros_api
            
            loop = asyncio.get_event_loop()
            
            def connect_and_get_arp():
                # Connessione MikroTik
                connection = routeros_api.RouterOsApiPool(
                    address,
                    port=port,
                    username=username,
                    password=password,
                    use_ssl=use_ssl,
                    ssl_verify=False,
                    plaintext_login=True,
                )
                api = connection.get_api()
                
                # Ottieni ARP table
                arp_resource = api.get_resource('/ip/arp')
                arps = arp_resource.get()
                
                connection.disconnect()
                return arps
            
            arps = await loop.run_in_executor(None, connect_and_get_arp)
            
            # Filtra per network se specificato
            entries = []
            net = None
            if network_cidr:
                try:
                    net = ipaddress.ip_network(network_cidr, strict=False)
                except:
                    pass
            
            for a in arps:
                ip = a.get("address", "")
                mac = a.get("mac-address", "")
                
                if not ip or not mac:
                    continue
                    
                # Filtra per network
                if net:
                    try:
                        if ipaddress.ip_address(ip) not in net:
                            continue
                    except:
                        continue
                
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "interface": a.get("interface", ""),
                })
            
            logger.info(f"[ARP MikroTik] Got {len(entries)} entries from {address}")
            return CommandResult(
                success=True, 
                status="success", 
                data={"entries": entries, "count": len(entries), "source": f"mikrotik:{address}"}
            )
            
        except Exception as e:
            logger.error(f"[ARP MikroTik] Error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _get_arp_snmp(self, params: Dict, network_cidr: str = None) -> CommandResult:
        """Query ARP table via SNMP (generic router) - pysnmp 7.x async API"""
        import ipaddress
        
        address = params.get("address")
        community = params.get("community", "public")
        version = params.get("version", "2c")
        
        if not address:
            return CommandResult(success=False, status="error", error="Missing 'address' parameter")
        
        try:
            # pysnmp 7.x usa v3arch con API async
            from pysnmp.hlapi.v3arch import (
                SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                ObjectType, ObjectIdentity, walk_cmd
            )
            
            # OID per ipNetToMediaPhysAddress (ARP table)
            OID_ARP_TABLE = "1.3.6.1.2.1.4.22.1.2"
            
            # Parse network filter
            net = None
            if network_cidr:
                try:
                    net = ipaddress.ip_network(network_cidr, strict=False)
                except:
                    pass
            
            mp_model = 1 if version == "2c" else 0
            
            # Crea transport target (async in pysnmp 7.x)
            logger.debug(f"[ARP SNMP] Querying {address} with community {community}")
            transport = await UdpTransportTarget.create((address, 161), timeout=5, retries=2)
            
            entries = []
            
            # Walk ARP table - async iterator in pysnmp 7.x
            async for (errorIndication, errorStatus, errorIndex, varBinds) in walk_cmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(OID_ARP_TABLE)),
            ):
                if errorIndication:
                    logger.debug(f"[ARP SNMP] Error: {errorIndication}")
                    break
                if errorStatus:
                    logger.debug(f"[ARP SNMP] Status error: {errorStatus.prettyPrint()}")
                    break
                
                for varBind in varBinds:
                    oid = str(varBind[0])
                    value = varBind[1]
                    
                    # Debug: log raw values
                    logger.debug(f"[ARP SNMP] OID: {oid}, Value type: {type(value).__name__}, Value: {value}")
                    
                    # Estrai IP dall'OID
                    # OID format: 1.3.6.1.2.1.4.22.1.2.<ifIndex>.<ip1>.<ip2>.<ip3>.<ip4>
                    try:
                        parts = oid.split('.')
                        # L'OID base è 1.3.6.1.2.1.4.22.1.2 (10 parti), poi ifIndex (1), poi IP (4)
                        # Quindi le ultime 4 parti sono l'IP
                        if len(parts) >= 4:
                            ip = '.'.join(parts[-4:])
                            
                            # Verifica che sia un IP valido
                            try:
                                ipaddress.ip_address(ip)
                            except:
                                logger.debug(f"[ARP SNMP] Invalid IP from OID: {ip}")
                                continue
                            
                            # Estrai MAC address dal valore
                            mac = None
                            
                            # Metodo 1: asOctets() per OctetString
                            if hasattr(value, 'asOctets'):
                                try:
                                    mac_bytes = value.asOctets()
                                    if len(mac_bytes) == 6:
                                        mac = ':'.join(format(b, '02X') for b in mac_bytes)
                                except:
                                    pass
                            
                            # Metodo 2: hasValue e __bytes__
                            if not mac and hasattr(value, '__bytes__'):
                                try:
                                    mac_bytes = bytes(value)
                                    if len(mac_bytes) == 6:
                                        mac = ':'.join(format(b, '02X') for b in mac_bytes)
                                except:
                                    pass
                            
                            # Metodo 3: prettyPrint per format 0x...
                            if not mac and hasattr(value, 'prettyPrint'):
                                try:
                                    pretty = value.prettyPrint()
                                    # Format: "0xAABBCCDDEEFF" o "AA:BB:CC:DD:EE:FF"
                                    if pretty.startswith('0x'):
                                        hex_str = pretty[2:].upper()
                                        if len(hex_str) == 12:
                                            mac = ':'.join(hex_str[i:i+2] for i in range(0, 12, 2))
                                    elif ':' in pretty and len(pretty) == 17:
                                        mac = pretty.upper()
                                except:
                                    pass
                            
                            # Metodo 4: raw string
                            if not mac:
                                try:
                                    raw = str(value)
                                    # Potrebbe essere in formato hex senza 0x
                                    clean = raw.replace(':', '').replace('-', '').replace(' ', '').upper()
                                    if len(clean) == 12 and all(c in '0123456789ABCDEF' for c in clean):
                                        mac = ':'.join(clean[i:i+2] for i in range(0, 12, 2))
                                except:
                                    pass
                            
                            if not mac:
                                logger.debug(f"[ARP SNMP] Could not parse MAC for IP {ip}: {value} (type: {type(value).__name__})")
                                continue
                            
                            # Ignora MAC invalidi
                            if mac in ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"]:
                                continue
                            
                            # Filtra per network se specificato
                            if net:
                                try:
                                    if ipaddress.ip_address(ip) not in net:
                                        continue
                                except:
                                    continue
                            
                            logger.debug(f"[ARP SNMP] Found: {ip} -> {mac}")
                            entries.append({"ip": ip, "mac": mac})
                    except Exception as e:
                        logger.debug(f"[ARP SNMP] Parse error: {e}")
                        continue
            
            logger.info(f"[ARP SNMP] Got {len(entries)} entries from {address}")
            return CommandResult(
                success=True, 
                status="success", 
                data={"entries": entries, "count": len(entries), "source": f"snmp:{address}"}
            )
            
        except Exception as e:
            logger.error(f"[ARP SNMP] Error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    # ==========================================
    # AGENT MANAGEMENT
    # ==========================================
    
    async def _update_agent(self, params: Dict) -> CommandResult:
        """
        Self-update agent usando script esterno robusto.
        Lo script viene eseguito FUORI dal container per evitare problemi di mount e permessi.
        """
        logger.info("Update agent requested")
        
        agent_dir = "/opt/dadude-agent"
        update_script = os.path.join(agent_dir, "dadude-agent", "deploy", "proxmox", "update-agent.sh")
        
        # Se siamo dentro un container Docker, dobbiamo eseguire lo script FUORI dal container
        # usando docker exec o pct exec (se siamo in Proxmox LXC)
        try:
            # Verifica se siamo in un container Docker
            if os.path.exists("/.dockerenv"):
                logger.info("Running inside Docker container, executing update script via host")
                
                # Prova a identificare il container ID o CTID
                # Metodo 1: Leggi hostname che potrebbe contenere il CTID
                import socket
                hostname = socket.gethostname()
                
                # Metodo 2: Cerca script di update nel filesystem montato
                # Lo script deve essere eseguito FUORI dal container
                
                # Per ora, fallback al metodo vecchio ma migliorato
                logger.warning("Cannot execute external script from inside container, using internal method")
                return await self._update_agent_internal(params)
            else:
                # Siamo fuori dal container, possiamo eseguire direttamente
                if os.path.exists(update_script):
                    logger.info(f"Executing external update script: {update_script}")
                    result = subprocess.run(
                        ["bash", update_script],
                        cwd=agent_dir,
                        capture_output=True,
                        text=True,
                        timeout=600,
                    )
                    if result.returncode == 0:
                        return CommandResult(
                            success=True,
                            status="success",
                            data={
                                "message": "Update completed successfully",
                                "output": result.stdout,
                            },
                        )
                    else:
                        return CommandResult(
                            success=False,
                            status="error",
                            error=f"Update script failed: {result.stderr[:500]}",
                        )
                else:
                    logger.warning(f"Update script not found at {update_script}, using internal method")
                    return await self._update_agent_internal(params)
                    
        except subprocess.TimeoutExpired:
            return CommandResult(success=False, status="error", error="Update timed out")
        except Exception as e:
            logger.error(f"Update error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _update_agent_internal(self, params: Dict) -> CommandResult:
        """
        Metodo interno di update con stessa logica dello script remoto.
        Preserva file di configurazione e fa rebuild completo Docker.
        Usa UpdateManager per checkpoint, retry e rollback automatico.
        """
        logger.info("Using internal update method with UpdateManager (checkpoint, retry, rollback)")
        
        agent_dir = "/opt/dadude-agent"
        compose_dir = os.path.join(agent_dir, "dadude-agent")
        update_manager = UpdateManager(max_retries=3)
        
        try:
            import shutil
            import tempfile
            import re
            import json
            
            # Step 1: Verifica spazio disco (pulisce se necessario)
            logger.info("[1/8] Checking disk space...")
            try:
                import shutil
                disk_usage = shutil.disk_usage(agent_dir)
                disk_percent = (disk_usage.used / disk_usage.total) * 100
                
                if disk_percent >= 90:
                    logger.error(f"Disk space insufficient: {disk_percent:.1f}% used")
                    return CommandResult(
                        success=False,
                        status="error",
                        error=f"Disk space insufficient ({disk_percent:.1f}% used). Please free space before updating.",
                    )
                elif disk_percent >= 80:
                    logger.warning(f"Disk space limited: {disk_percent:.1f}% used, cleaning Docker cache...")
                    # Pulisci cache Docker
                    cleanup_result = subprocess.run(
                        ["docker", "system", "prune", "-f"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    if cleanup_result.returncode == 0:
                        # Ricontrolla dopo pulizia
                        disk_usage_after = shutil.disk_usage(agent_dir)
                        disk_percent_after = (disk_usage_after.used / disk_usage_after.total) * 100
                        logger.info(f"Disk space after cleanup: {disk_percent_after:.1f}% used")
                        if disk_percent_after >= 90:
                            return CommandResult(
                                success=False,
                                status="error",
                                error=f"Disk space still insufficient after cleanup ({disk_percent_after:.1f}% used).",
                            )
                else:
                    logger.info(f"Disk space OK: {disk_percent:.1f}% used")
            except Exception as e:
                logger.warning(f"Could not check disk space: {e}, continuing anyway...")
            
            # Step 2: Verifica repository git
            git_dir = os.path.join(agent_dir, ".git")
            if not os.path.exists(git_dir):
                logger.warning("Directory is not a git repository, initializing...")
                init_result = subprocess.run(
                    ["git", "init"],
                    cwd=agent_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if init_result.returncode == 0:
                    subprocess.run(
                        ["git", "remote", "add", "origin", "https://github.com/grandir66/Dadude.git"],
                        cwd=agent_dir,
                        capture_output=True,
                        text=True,
                        timeout=30,
                    )
                else:
                    return CommandResult(
                        success=False,
                        status="error",
                        error="Agent directory is not a git repository and cannot initialize it.",
                    )
            
            # Step 3: Fetch updates
            logger.info("[3/8] Fetching latest code from GitHub...")
            fetch_result = subprocess.run(
                ["git", "fetch", "origin", "main"],
                cwd=agent_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if fetch_result.returncode != 0:
                return CommandResult(
                    success=False,
                    status="error",
                    error=f"Git fetch failed: {fetch_result.stderr[:200]}",
                )
            
            # Step 4: Backup file di configurazione
            logger.info("[4/8] Backing up configuration files...")
            env_backups = {}
            config_backup_dir = None
            
            # Backup .env principale
            env_file = os.path.join(agent_dir, ".env")
            if os.path.exists(env_file):
                backup = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env.backup')
                with open(env_file, 'r') as f:
                    backup.write(f.read())
                backup.close()
                env_backups[env_file] = backup.name
                logger.info(f"Backed up {env_file}")
            
            # Backup .env subdirectory
            env_file_subdir = os.path.join(compose_dir, ".env")
            if os.path.exists(env_file_subdir):
                backup = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.env.backup')
                with open(env_file_subdir, 'r') as f:
                    backup.write(f.read())
                backup.close()
                env_backups[env_file_subdir] = backup.name
                logger.info(f"Backed up {env_file_subdir}")
            
            # Backup directory config personalizzati
            config_dir = os.path.join(compose_dir, "config")
            if os.path.exists(config_dir) and os.path.isdir(config_dir):
                config_backup_dir = tempfile.mkdtemp(prefix="dadude_config_backup_")
                shutil.copytree(config_dir, os.path.join(config_backup_dir, "config"), dirs_exist_ok=True)
                logger.info(f"Backed up config directory to {config_backup_dir}")
            
            # Step 5: Verifica versione corrente
            logger.info("[5/8] Checking current version...")
            current_commit_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=agent_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            current_commit = current_commit_result.stdout.strip()[:8] if current_commit_result.returncode == 0 else "unknown"
            
            remote_commit_result = subprocess.run(
                ["git", "rev-parse", "origin/main"],
                cwd=agent_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            remote_commit = remote_commit_result.stdout.strip()[:8] if remote_commit_result.returncode == 0 else "unknown"
            
            # Leggi versione corrente dal file
            current_version = "unknown"
            agent_py_file = os.path.join(compose_dir, "app", "agent.py")
            if os.path.exists(agent_py_file):
                try:
                    with open(agent_py_file, 'r') as f:
                        content = f.read()
                        match = re.search(r'AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            current_version = match.group(1)
                except:
                    pass
            
            logger.info(f"   Current commit: {current_commit}")
            logger.info(f"   Remote commit:   {remote_commit}")
            logger.info(f"   Current version: v{current_version}")
            
            if current_commit == remote_commit and current_commit != "unknown":
                logger.info("Already up to date")
                # Cleanup backups
                for backup_path in env_backups.values():
                    if os.path.exists(backup_path):
                        os.unlink(backup_path)
                if config_backup_dir and os.path.exists(config_backup_dir):
                    shutil.rmtree(config_backup_dir)
                return CommandResult(
                    success=True,
                    status="success",
                    data={"message": "Already at latest version", "version": current_version},
                )
            
            # Checkpoint prima di applicare aggiornamenti
            checkpoint = update_manager.create_checkpoint(
                step="before_git_reset",
                git_commit=current_commit,
                backup_paths=env_backups.copy(),
                metadata={"config_backup_dir": config_backup_dir}
            )
            
            # Step 6: Applicazione aggiornamenti con retry
            logger.info("[6/8] Applying updates...")
            
            async def apply_updates():
                reset_result = subprocess.run(
                    ["git", "reset", "--hard", "origin/main"],
                    cwd=agent_dir,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                
                if reset_result.returncode != 0:
                    return CommandResult(
                        success=False,
                        status="error",
                        error=f"Git reset failed: {reset_result.stderr[:200]}",
                    )
                return CommandResult(success=True, status="success")
            
            reset_result = await update_manager.execute_with_retry(
                apply_updates,
                operation_name="Git reset"
            )
            
            if not reset_result.success:
                # Rollback automatico
                await update_manager.rollback(checkpoint)
                return reset_result
            
            # Leggi nuova versione
            new_version = "unknown"
            if os.path.exists(agent_py_file):
                try:
                    with open(agent_py_file, 'r') as f:
                        content = f.read()
                        match = re.search(r'AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                        if match:
                            new_version = match.group(1)
                except:
                    pass
            
            logger.info(f"   New version: v{new_version}")
            
            # Step 7: Ripristino file di configurazione
            logger.info("[7/8] Restoring configuration files...")
            
            # Ripristina .env principale
            if env_file in env_backups and os.path.exists(env_backups[env_file]):
                os.makedirs(os.path.dirname(env_file), exist_ok=True)
                shutil.copy(env_backups[env_file], env_file)
                logger.info(f"Restored {env_file}")
            
            # Ripristina .env subdirectory
            if env_file_subdir in env_backups and os.path.exists(env_backups[env_file_subdir]):
                os.makedirs(os.path.dirname(env_file_subdir), exist_ok=True)
                shutil.copy(env_backups[env_file_subdir], env_file_subdir)
                logger.info(f"Restored {env_file_subdir}")
            elif env_file in env_backups and os.path.exists(env_backups[env_file]):
                # Se non esiste backup subdirectory, copia dalla root
                os.makedirs(os.path.dirname(env_file_subdir), exist_ok=True)
                shutil.copy(env_file, env_file_subdir)
                logger.info("Copied .env to subdirectory")
            
            # Ripristina config personalizzati
            if config_backup_dir and os.path.exists(os.path.join(config_backup_dir, "config")):
                os.makedirs(config_dir, exist_ok=True)
                shutil.copytree(
                    os.path.join(config_backup_dir, "config"),
                    config_dir,
                    dirs_exist_ok=True
                )
                logger.info("Restored config directory")
            
            # Cleanup backup files
            for backup_path in env_backups.values():
                if os.path.exists(backup_path):
                    os.unlink(backup_path)
            if config_backup_dir and os.path.exists(config_backup_dir):
                shutil.rmtree(config_backup_dir)
            
            # Checkpoint prima di rebuild Docker
            build_checkpoint = update_manager.create_checkpoint(
                step="before_docker_build",
                git_commit=current_commit,
                backup_paths=env_backups.copy(),
            )
            
            # Step 8: Rebuild immagine Docker con retry
            logger.info("[8/8] Rebuilding Docker image...")
            
            # Verifica docker-compose.yml
            compose_file = os.path.join(compose_dir, "docker-compose.yml")
            if not os.path.exists(compose_file):
                # Cerca nella root
                compose_file = os.path.join(agent_dir, "docker-compose.yml")
                if os.path.exists(compose_file):
                    compose_dir = agent_dir
            
            if os.path.exists(compose_file):
                async def docker_build():
                    build_result = subprocess.run(
                        ["docker", "compose", "build", "--quiet"],
                        cwd=compose_dir,
                        capture_output=True,
                        text=True,
                        timeout=300,
                    )
                    
                    if build_result.returncode != 0:
                        return CommandResult(
                            success=False,
                            status="error",
                            error=f"Docker build failed: {build_result.stderr[:200]}",
                        )
                    return CommandResult(success=True, status="success")
                
                build_result = await update_manager.execute_with_retry(
                    docker_build,
                    operation_name="Docker build"
                )
                
                if not build_result.success:
                    await update_manager.rollback(build_checkpoint)
                    return build_result
                
                logger.info("Docker build completed")
                
                # Step 9: Riavvio container con force-recreate e retry
                logger.info("[9/9] Restarting container with force-recreate...")
                
                async def restart_container():
                    """
                    Riavvia il container usando Docker API via socket.
                    Questo è più stabile perché non dipende da docker compose che potrebbe terminare il processo.
                    """
                    import socket
                    import json
                    
                    # Metodo 1: Usa Docker API via socket (più stabile)
                    docker_sock = "/var/run/docker.sock"
                    if os.path.exists(docker_sock):
                        try:
                            # Leggi container name da env o hostname
                            container_name = os.environ.get("HOSTNAME", "dadude-agent")
                            if not container_name:
                                container_name = "dadude-agent"
                            
                            # Usa Docker API per riavviare il container
                            # Prima prova con docker compose (più pulito)
                            recreate_result = None
                            for cmd in [["docker", "compose", "up", "-d", "--force-recreate", "--no-deps"], 
                                       ["docker-compose", "up", "-d", "--force-recreate", "--no-deps"]]:
                                try:
                                    recreate_result = subprocess.run(
                                        cmd,
                                        cwd=compose_dir,
                                        capture_output=True,
                                        text=True,
                                        timeout=120,
                                    )
                                    if recreate_result.returncode == 0:
                                        logger.info("Container restarted via docker compose")
                                        # Attendi un po' per verificare che il container si sia avviato
                                        await asyncio.sleep(5)
                                        return CommandResult(success=True, status="success", data={"output": recreate_result.stdout, "method": "docker-compose"})
                                except FileNotFoundError:
                                    continue
                            
                            # Metodo 2: Se docker compose fallisce, usa Docker API direttamente
                            # Ottieni container ID
                            inspect_result = subprocess.run(
                                ["docker", "inspect", "--format", "{{.Id}}", container_name],
                                capture_output=True,
                                text=True,
                                timeout=10,
                            )
                            
                            if inspect_result.returncode == 0:
                                container_id = inspect_result.stdout.strip()
                                logger.info(f"Found container ID: {container_id[:12]}")
                                
                                # Riavvia usando docker restart (più sicuro)
                                restart_result = subprocess.run(
                                    ["docker", "restart", container_name],
                                    capture_output=True,
                                    text=True,
                                    timeout=30,
                                )
                                
                                if restart_result.returncode == 0:
                                    logger.info("Container restarted via docker restart")
                                    await asyncio.sleep(5)
                                    return CommandResult(success=True, status="success", data={"output": restart_result.stdout, "method": "docker-restart"})
                                else:
                                    logger.warning(f"Docker restart failed: {restart_result.stderr}")
                            
                        except Exception as e:
                            logger.warning(f"Docker API restart failed: {e}, falling back to docker compose")
                    
                    # Metodo 3: Fallback a docker compose normale
                    recreate_result = None
                    for cmd in [["docker", "compose", "up", "-d", "--force-recreate"], 
                               ["docker-compose", "up", "-d", "--force-recreate"]]:
                        try:
                            recreate_result = subprocess.run(
                                cmd,
                                cwd=compose_dir,
                                capture_output=True,
                                text=True,
                                timeout=120,
                            )
                            if recreate_result.returncode == 0:
                                logger.info("Container restarted via docker compose (fallback)")
                                await asyncio.sleep(5)
                                return CommandResult(success=True, status="success", data={"output": recreate_result.stdout, "method": "docker-compose-fallback"})
                        except FileNotFoundError:
                            continue
                    
                    if recreate_result is None:
                        return CommandResult(
                            success=False,
                            status="error",
                            error="Neither 'docker compose' nor 'docker-compose' found"
                        )
                    
                    if recreate_result.returncode != 0:
                        return CommandResult(
                            success=False,
                            status="error",
                            error=f"Container restart failed: {recreate_result.stderr[:200]}"
                        )
                    
                    await asyncio.sleep(5)
                    return CommandResult(success=True, status="success", data={"output": recreate_result.stdout, "method": "docker-compose-final"})
                
                restart_result = await update_manager.execute_with_retry(
                    restart_container,
                    operation_name="Container restart"
                )
                
                if not restart_result.success:
                    # Se restart fallisce, crea flag file per restart esterno
                    restart_flag_file = os.path.join(agent_dir, ".restart_required")
                    try:
                        with open(restart_flag_file, 'w') as f:
                            f.write(json.dumps({
                                "timestamp": datetime.utcnow().isoformat(),
                                "reason": "update_completed",
                                "new_version": new_version,
                                "compose_dir": compose_dir,
                            }))
                        logger.warning(f"Created restart flag file: {restart_flag_file}")
                    except Exception as e:
                        logger.warning(f"Could not create restart flag file: {e}")
                    
                    # Non facciamo rollback se solo il restart fallisce - il build è OK
                    return CommandResult(
                        success=True,
                        status="success",
                        data={
                            "message": "Update completed, restart required",
                            "old_version": current_version,
                            "new_version": new_version,
                            "restart_flag": restart_flag_file,
                            "warning": "Container restart may require manual intervention",
                        },
                    )
                
                # Verifica successo update
                logger.info("Verifying update success...")
                await asyncio.sleep(10)  # Attendi che container si avvii
                verification_success = await update_manager.verify_update_success()
                
                if not verification_success:
                    logger.warning("Update verification failed, but update may still be successful")
                    # Non facciamo rollback automatico se solo la verifica fallisce
                
                logger.success("Container restarted successfully")
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "message": "Update completed successfully",
                        "old_version": current_version,
                        "new_version": new_version,
                        "output": restart_result.data.get("output") if restart_result.data else "",
                        "verification_passed": verification_success,
                    },
                )
            else:
                logger.warning("docker-compose.yml not found, skipping Docker rebuild")
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "message": "Git update completed, but Docker rebuild skipped (no docker-compose.yml)",
                        "old_version": current_version,
                        "new_version": new_version,
                    },
                )
            
        except subprocess.TimeoutExpired as e:
            # Rollback su timeout
            latest_checkpoint = update_manager.get_latest_checkpoint()
            if latest_checkpoint:
                await update_manager.rollback(latest_checkpoint)
            return CommandResult(success=False, status="error", error=f"Update timed out: {e}")
        except Exception as e:
            logger.error(f"Update error: {e}")
            # Rollback su eccezione
            latest_checkpoint = update_manager.get_latest_checkpoint()
            if latest_checkpoint:
                await update_manager.rollback(latest_checkpoint)
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _restart(self) -> CommandResult:
        """Riavvia agent (container/service)"""
        try:
            # Se in Docker, riavvia container
            if os.path.exists("/.dockerenv"):
                # Segnala al sistema di riavviare
                import signal
                os.kill(os.getpid(), signal.SIGTERM)
                return CommandResult(
                    success=True,
                    status="success",
                    data={"message": "Restart initiated"},
                )
            else:
                # Riavvia servizio systemd
                subprocess.Popen(
                    ["systemctl", "restart", "dadude-agent"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return CommandResult(
                    success=True,
                    status="success",
                    data={"message": "Service restart initiated"},
                )
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _reboot(self) -> CommandResult:
        """Riavvia sistema host"""
        try:
            # Richiede privilegi elevati
            subprocess.Popen(
                ["reboot"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return CommandResult(
                success=True,
                status="success",
                data={"message": "System reboot initiated"},
            )
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _sync_config(self, params: Dict) -> CommandResult:
        """Sincronizza configurazione dal server (es: porte di scansione)"""
        import json
        from pathlib import Path
        
        config_type = params.get("config_type", "")
        
        try:
            if config_type == "scan_ports":
                # Salva configurazione porte
                tcp_ports = params.get("tcp_ports", {})
                udp_ports = params.get("udp_ports", {})
                
                # Path al file di configurazione
                config_dir = Path(__file__).parent.parent.parent / "config"
                config_dir.mkdir(parents=True, exist_ok=True)
                config_file = config_dir / "scan_ports.json"
                
                # Salva configurazione
                config_data = {
                    "tcp_ports": tcp_ports,
                    "udp_ports": udp_ports
                }
                
                with open(config_file, 'w', encoding='utf-8') as f:
                    json.dump(config_data, f, indent=2, ensure_ascii=False)
                
                logger.info(f"Scan ports configuration synced: {len(tcp_ports)} TCP, {len(udp_ports)} UDP ports")
                
                # Invalida cache nel port_scanner
                try:
                    from ..scanners.port_scanner import invalidate_port_config_cache
                    invalidate_port_config_cache()
                    logger.debug("Port scanner cache invalidated")
                except Exception as e:
                    logger.warning(f"Could not invalidate port scanner cache: {e}")
                
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "config_type": config_type,
                        "tcp_ports_count": len(tcp_ports),
                        "udp_ports_count": len(udp_ports),
                        "config_path": str(config_file)
                    }
                )
            else:
                return CommandResult(
                    success=False,
                    status="error",
                    error=f"Unknown config_type: {config_type}"
                )
        except Exception as e:
            logger.error(f"Error syncing config: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _get_status(self) -> CommandResult:
        """Ottieni stato agent"""
        import platform
        import psutil
        
        try:
            status = {
                "agent_version": "2.0.0",
                "python_version": platform.python_version(),
                "platform": platform.platform(),
                "hostname": platform.node(),
                "uptime_seconds": int(psutil.boot_time()),
                "cpu_percent": psutil.cpu_percent(interval=0.5),
                "memory": {
                    "total_mb": psutil.virtual_memory().total // (1024*1024),
                    "used_mb": psutil.virtual_memory().used // (1024*1024),
                    "percent": psutil.virtual_memory().percent,
                },
                "disk": {
                    "total_gb": psutil.disk_usage("/").total // (1024*1024*1024),
                    "free_gb": psutil.disk_usage("/").free // (1024*1024*1024),
                    "percent": psutil.disk_usage("/").percent,
                },
                "network_interfaces": [
                    {"name": name, "addresses": [addr.address for addr in addrs if addr.family.name == "AF_INET"]}
                    for name, addrs in psutil.net_if_addrs().items()
                ],
                "timestamp": datetime.utcnow().isoformat(),
            }
            
            return CommandResult(success=True, status="success", data=status)
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    # ==========================================
    # DIAGNOSTICS
    # ==========================================
    
    async def _ping(self, params: Dict) -> CommandResult:
        """Ping host"""
        target = params.get("target")
        count = params.get("count", 4)
        
        if not target:
            return CommandResult(success=False, status="error", error="Missing 'target' parameter")
        
        try:
            result = subprocess.run(
                ["ping", "-c", str(count), target],
                capture_output=True,
                text=True,
                timeout=30
            )
            return CommandResult(
                success=result.returncode == 0,
                status="success" if result.returncode == 0 else "error",
                data={
                    "output": result.stdout,
                    "error": result.stderr if result.returncode != 0 else None,
                },
            )
        except subprocess.TimeoutExpired:
            return CommandResult(success=False, status="timeout", error="Ping timed out")
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _nmap_scan(self, params: Dict) -> CommandResult:
        """Scansione Nmap avanzata"""
        target = params.get("target")
        options = params.get("options", "-sV -sC")
        
        if not target:
            return CommandResult(success=False, status="error", error="Missing 'target' parameter")
        
        if not self._is_nmap_available():
            return CommandResult(success=False, status="error", error="Nmap not available")
        
        try:
            result = subprocess.run(
                ["nmap"] + options.split() + [target],
                capture_output=True,
                text=True,
                timeout=300
            )
            return CommandResult(
                success=result.returncode == 0,
                status="success" if result.returncode == 0 else "error",
                data={"output": result.stdout},
            )
        except subprocess.TimeoutExpired:
            return CommandResult(success=False, status="timeout", error="Nmap scan timed out")
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    # ==========================================
    # HELPERS
    # ==========================================
    
    def _is_nmap_available(self) -> bool:
        """Verifica se nmap è disponibile"""
        try:
            result = subprocess.run(
                ["which", "nmap"],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _nmap_network_scan(self, network: str, scan_type: str) -> list:
        """Scansione rete con nmap (asincrono per non bloccare heartbeat)"""
        try:
            # Scan con parametri ottimizzati per affidabilità
            # -sn = no port scan (solo discovery)
            # -PE = ICMP echo ping
            # -PP = ICMP timestamp ping  
            # -PS22,80,443 = TCP SYN ping su porte comuni
            # --max-retries=3 = riprova 3 volte
            # --host-timeout=30s = timeout per host
            # --max-rtt-timeout=1000ms = attendi fino a 1s per risposta
            # -T3 = timing normale (non troppo veloce)
            cmd = [
                "nmap", "-sn", "-PE", "-PP", "-PS22,80,443,3389", 
                "-n", "-T3", 
                "--max-retries=3", 
                "--host-timeout=30s",
                "--max-rtt-timeout=1000ms",
                network
            ]
            
            if scan_type == "arp":
                # ARP scan - funziona solo su subnet locale
                cmd = ["nmap", "-sn", "-PR", "--send-eth", "-T3", network]
            elif scan_type == "aggressive" or scan_type == "slow":
                # Scan lento ma completo
                cmd = [
                    "nmap", "-sn", "-PE", "-PP", "-PM", 
                    "-PS21,22,23,25,80,443,445,3389,8080", 
                    "-PA80,443", "-PU53,161", 
                    "-n", "-T2",  # Timing più lento
                    "--max-retries=5",
                    "--host-timeout=60s",
                    "--max-rtt-timeout=2000ms",
                    network
                ]
            elif scan_type == "all":
                cmd = ["nmap", "-sS", "-sV", "-O", "--top-ports", "100", "-T3", network]
            
            # Usa subprocess asincrono per non bloccare l'event loop
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
                output = stdout.decode('utf-8', errors='replace')
            except asyncio.TimeoutError:
                proc.kill()
                raise TimeoutError("Nmap scan timed out after 600 seconds")
            
            # Parse output
            hosts = []
            current_host = None
            
            for line in output.split("\n"):
                if "Nmap scan report for" in line:
                    if current_host:
                        hosts.append(current_host)
                    # Estrai IP
                    parts = line.split()
                    ip = parts[-1].strip("()")
                    current_host = {"ip": ip, "status": "up"}
                elif "MAC Address:" in line and current_host:
                    parts = line.split()
                    if len(parts) >= 3:
                        current_host["mac"] = parts[2]
                        if len(parts) > 3:
                            current_host["vendor"] = " ".join(parts[3:]).strip("()")
            
            if current_host:
                hosts.append(current_host)
            
            return hosts
            
        except Exception as e:
            logger.error(f"Nmap scan error: {e}")
            raise
    
    async def _basic_ping_scan(self, network: str) -> list:
        """Scansione base con ping (fallback senza nmap)"""
        import ipaddress
        
        hosts = []
        
        try:
            net = ipaddress.ip_network(network, strict=False)
            
            # Limita a /24 max
            if net.num_addresses > 256:
                logger.warning(f"Network too large, limiting scan to first 256 addresses")
                net = list(net.hosts())[:256]
            else:
                net = list(net.hosts())
            
            # Ping parallelo
            async def ping_host(ip):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "ping", "-c", "1", "-W", "1", str(ip),
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL
                    )
                    await asyncio.wait_for(proc.wait(), timeout=2)
                    if proc.returncode == 0:
                        return {"ip": str(ip), "status": "up"}
                except Exception:
                    pass
                return None
            
            results = await asyncio.gather(*[ping_host(ip) for ip in net])
            hosts = [r for r in results if r is not None]
            
        except Exception as e:
            logger.error(f"Ping scan error: {e}")
        
        return hosts
    
    def register_handler(self, action: str, handler: Callable[[Dict], Awaitable[CommandResult]]):
        """Registra handler custom per azione"""
        self._custom_handlers[action] = handler
    
    def set_update_callback(self, callback: Callable[[str, str], Awaitable[bool]]):
        """Imposta callback per self-update"""
        self._update_callback = callback
    
    # ==========================================
    # SCHEDULED TASKS
    # ==========================================
    
    async def _daily_restart(self, params: Dict) -> CommandResult:
        """
        Riavvio giornaliero programmato alle 4 di mattina.
        Usa la stessa logica robusta di _update_agent_internal ma eseguita in modo non bloccante.
        NOTA: Su MikroTik RouterOS container, questo comando viene saltato
        perché il container è gestito da RouterOS, non da docker-compose.
        """
        logger.info("Daily restart triggered at 4 AM - performing full update and restart")
        
        try:
            # Controlla se siamo su MikroTik RouterOS container
            agent_dir = "/opt/dadude-agent"
            agent_compose_dir = os.path.join(agent_dir, "dadude-agent")
            has_docker_compose = os.path.exists(os.path.join(agent_compose_dir, "docker-compose.yml"))
            
            # Controlla anche se siamo in un container RouterOS
            is_routeros = (
                os.path.exists("/proc/version") and "RouterOS" in open("/proc/version").read()
            ) or os.environ.get("ROUTEROS_CONTAINER") == "1"
            
            # Se non c'è docker-compose O siamo su RouterOS, saltiamo il Daily Restart
            if not has_docker_compose or is_routeros:
                logger.info("Daily restart skipped: running in MikroTik RouterOS container (no docker-compose)")
                return CommandResult(
                    success=True,
                    status="skipped",
                    data={"message": "Daily restart skipped: MikroTik RouterOS container"},
                )
            
            # IMPORTANTE: Esegui l'update usando direttamente _update_agent_internal
            # che ha tutta la logica robusta (backup, verifica spazio, DNS, ecc.)
            # Ma eseguiamolo in modo asincrono senza bloccare il funzionamento normale
            
            # Per evitare blocchi durante il daily restart:
            # 1. Eseguiamo l'update in modo asincrono (non blocca)
            # 2. Usiamo timeout brevi per operazioni critiche
            # 3. Il container continuerà a funzionare normalmente fino al restart finale
            
            # Esegui l'update direttamente (è già asincrono)
            # _update_agent_internal gestisce tutto: backup, verifica spazio, git, rebuild, restart
            logger.info("Starting daily restart update (same logic as manual update)...")
            
            # Esegui l'update in modo asincrono (non blocca)
            # Il risultato verrà loggato ma non bloccherà il funzionamento
            try:
                result = await self._update_agent_internal({})
                
                if result.success:
                    logger.success("Daily restart update completed successfully")
                    return CommandResult(
                        success=True,
                        status="success",
                        data={
                            "message": "Daily restart update completed",
                            "old_version": result.data.get("old_version") if result.data else None,
                            "new_version": result.data.get("new_version") if result.data else None,
                        },
                    )
                else:
                    logger.error(f"Daily restart update failed: {result.error}")
                    return CommandResult(
                        success=False,
                        status="error",
                        error=f"Daily restart update failed: {result.error}",
                    )
            except Exception as e:
                logger.error(f"Daily restart update exception: {e}")
                return CommandResult(
                    success=False,
                    status="error",
                    error=f"Daily restart update exception: {str(e)}",
                )
                
        except Exception as e:
            logger.error(f"Daily restart error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _connection_watchdog(self, params: Dict) -> CommandResult:
        """
        Watchdog connessione: se disconnesso per più di N ore, 
        esegue reset completo da git e riavvia.
        """
        max_hours = params.get("max_disconnected_hours", 24)
        
        try:
            # Leggi stato connessione da file
            state_file = "/var/lib/dadude-agent/connection_state.json"
            last_connected = None
            
            if os.path.exists(state_file):
                import json
                with open(state_file, "r") as f:
                    state = json.load(f)
                    last_connected_str = state.get("last_connected")
                    if last_connected_str:
                        from datetime import datetime
                        last_connected = datetime.fromisoformat(last_connected_str)
            
            if last_connected is None:
                # Prima esecuzione, salva stato attuale
                await self._save_connection_state(connected=False)
                return CommandResult(
                    success=True,
                    status="success",
                    data={"message": "Connection watchdog initialized"},
                )
            
            # Calcola ore di disconnessione
            from datetime import datetime, timedelta
            now = datetime.utcnow()
            disconnected_hours = (now - last_connected).total_seconds() / 3600
            
            logger.info(f"Connection watchdog: last connected {disconnected_hours:.1f} hours ago")
            
            if disconnected_hours >= max_hours:
                logger.warning(f"Disconnected for {disconnected_hours:.1f} hours - triggering full reset")
                
                # Reset completo
                result = await self._daily_restart({"force": True})
                
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "message": f"Full reset triggered after {disconnected_hours:.1f}h disconnect",
                        "action_taken": "full_reset",
                        "restart_result": result.data if result.success else result.error,
                    },
                )
            else:
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "message": f"Connection OK - last connected {disconnected_hours:.1f}h ago",
                        "action_taken": "none",
                    },
                )
                
        except Exception as e:
            logger.error(f"Connection watchdog error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _save_connection_state(self, connected: bool):
        """Salva stato connessione su file"""
        import json
        from datetime import datetime
        
        state_file = "/var/lib/dadude-agent/connection_state.json"
        
        try:
            state = {}
            if os.path.exists(state_file):
                with open(state_file, "r") as f:
                    state = json.load(f)
            
            if connected:
                state["last_connected"] = datetime.utcnow().isoformat()
            
            state["last_check"] = datetime.utcnow().isoformat()
            state["is_connected"] = connected
            
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving connection state: {e}")
    
    async def _cleanup_queue(self, params: Dict) -> CommandResult:
        """Pulizia coda locale"""
        try:
            # Placeholder - la coda si pulisce automaticamente
            return CommandResult(
                success=True,
                status="success",
                data={"message": "Queue cleanup completed"},
            )
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _check_updates(self, params: Dict) -> CommandResult:
        """Verifica aggiornamenti disponibili"""
        try:
            agent_dir = "/opt/dadude-agent"
            
            if os.path.exists(os.path.join(agent_dir, ".git")):
                # Fetch per vedere se ci sono update
                result = subprocess.run(
                    ["git", "fetch", "--dry-run", "origin", "main"],
                    cwd=agent_dir,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                
                has_updates = bool(result.stdout.strip() or result.stderr.strip())
                
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "has_updates": has_updates,
                        "message": "Updates available" if has_updates else "No updates",
                    },
                )
            else:
                return CommandResult(
                    success=False,
                    status="error",
                    error="Not a git repository",
                )
        except Exception as e:
            return CommandResult(success=False, status="error", error=str(e))
    
    # ==========================================
    # REMOTE SHELL / COMMAND EXECUTION
    # ==========================================
    
    async def _exec_command(self, params: Dict) -> CommandResult:
        """
        Esegue un comando localmente sull'agent.
        
        Params:
            command: str - comando da eseguire
            timeout: int - timeout in secondi (default 60)
            shell: bool - esegui in shell (default True)
        """
        command = params.get("command")
        timeout = params.get("timeout", 60)
        use_shell = params.get("shell", True)
        
        if not command:
            return CommandResult(success=False, status="error", error="Missing 'command' parameter")
        
        # Limita comandi pericolosi
        dangerous = ["rm -rf /", "mkfs", "dd if=", "> /dev/sd", "shutdown", "reboot", "init 0", "init 6"]
        for d in dangerous:
            if d in command.lower():
                return CommandResult(
                    success=False, 
                    status="error", 
                    error=f"Command contains dangerous pattern: {d}"
                )
        
        logger.info(f"[EXEC] Running command: {command[:100]}...")
        
        try:
            if use_shell:
                proc = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *command.split(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except asyncio.TimeoutError:
                proc.kill()
                return CommandResult(
                    success=False,
                    status="timeout",
                    error=f"Command timed out after {timeout}s",
                )
            
            stdout_str = stdout.decode('utf-8', errors='replace') if stdout else ""
            stderr_str = stderr.decode('utf-8', errors='replace') if stderr else ""
            
            return CommandResult(
                success=proc.returncode == 0,
                status="success" if proc.returncode == 0 else "error",
                data={
                    "stdout": stdout_str,
                    "stderr": stderr_str,
                    "exit_code": proc.returncode,
                    "command": command,
                },
                error=stderr_str if proc.returncode != 0 else None,
            )
            
        except Exception as e:
            logger.error(f"[EXEC] Error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _exec_ssh(self, params: Dict) -> CommandResult:
        """
        Esegue un comando su un host remoto via SSH.
        
        Params:
            host: str - indirizzo host
            command: str - comando da eseguire
            username: str - username SSH (default root)
            password: str - password (opzionale)
            port: int - porta SSH (default 22)
            timeout: int - timeout in secondi (default 60)
            key_file: str - path chiave privata (opzionale)
        """
        host = params.get("host")
        command = params.get("command")
        username = params.get("username", "root")
        password = params.get("password")
        port = params.get("port", 22)
        timeout = params.get("timeout", 60)
        key_file = params.get("key_file")
        
        if not host:
            return CommandResult(success=False, status="error", error="Missing 'host' parameter")
        if not command:
            return CommandResult(success=False, status="error", error="Missing 'command' parameter")
        
        logger.info(f"[SSH] Executing on {host}: {command[:100]}...")
        
        try:
            import paramiko
            
            # Crea client SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connetti
            connect_kwargs = {
                "hostname": host,
                "port": port,
                "username": username,
                "timeout": 30,
                "allow_agent": False,
                "look_for_keys": False,
            }
            
            if key_file and os.path.exists(key_file):
                connect_kwargs["key_filename"] = key_file
            elif password:
                connect_kwargs["password"] = password
            else:
                # Prova senza autenticazione (chiavi di sistema)
                connect_kwargs["allow_agent"] = True
                connect_kwargs["look_for_keys"] = True
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: ssh.connect(**connect_kwargs))
            
            # Esegui comando
            stdin, stdout, stderr = await loop.run_in_executor(
                None, 
                lambda: ssh.exec_command(command, timeout=timeout)
            )
            
            # Leggi output
            stdout_str = await loop.run_in_executor(None, stdout.read)
            stderr_str = await loop.run_in_executor(None, stderr.read)
            exit_code = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            stdout_decoded = stdout_str.decode('utf-8', errors='replace') if stdout_str else ""
            stderr_decoded = stderr_str.decode('utf-8', errors='replace') if stderr_str else ""
            
            return CommandResult(
                success=exit_code == 0,
                status="success" if exit_code == 0 else "error",
                data={
                    "stdout": stdout_decoded,
                    "stderr": stderr_decoded,
                    "exit_code": exit_code,
                    "host": host,
                    "command": command,
                },
                error=stderr_decoded if exit_code != 0 else None,
            )
            
        except paramiko.AuthenticationException:
            return CommandResult(success=False, status="error", error="SSH authentication failed")
        except paramiko.SSHException as e:
            return CommandResult(success=False, status="error", error=f"SSH error: {e}")
        except Exception as e:
            logger.error(f"[SSH] Error: {e}")
            return CommandResult(success=False, status="error", error=str(e))
    
    async def _update_agent_proxmox(self, params: Dict) -> CommandResult:
        """
        Aggiorna un agent su Proxmox LXC da dentro il container agent.
        
        Params:
            proxmox_ip: str - IP del server Proxmox
            container_id: str - ID del container LXC (es: "600", "610")
            ssh_user: str - Username SSH (default: "root")
            ssh_password: Optional[str] - Password SSH (se non usa key)
            ssh_key: Optional[str] - Private key SSH
            ssh_port: int - Porta SSH (default: 22)
        """
        proxmox_ip = params.get("proxmox_ip")
        container_id = params.get("container_id")
        ssh_user = params.get("ssh_user", "root")
        ssh_password = params.get("ssh_password")
        ssh_key = params.get("ssh_key")
        ssh_port = params.get("ssh_port", 22)
        
        if not proxmox_ip or not container_id:
            return CommandResult(
                success=False,
                status="error",
                error="proxmox_ip and container_id are required"
            )
        
        logger.info(f"[PROXMOX UPDATE] Updating agent on Proxmox {proxmox_ip}, container {container_id}")
        
        try:
            import paramiko
            from io import StringIO
            
            # Comando da eseguire sul Proxmox
            update_command = f"""pct exec {container_id} -- bash -c '
                cd /opt/dadude-agent/dadude-agent 2>/dev/null || cd /opt/dadude-agent || exit 1
                echo "1. Fetching latest changes..."
                git fetch origin main 2>&1
                echo "2. Checking versions..."
                CURRENT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
                LATEST=$(git rev-parse origin/main 2>/dev/null || echo "unknown")
                echo "   Current: ${CURRENT:0:8}"
                echo "   Latest:  ${LATEST:0:8}"
                if [ "$CURRENT" != "$LATEST" ] && [ "$LATEST" != "unknown" ]; then
                    echo "3. Update available! Applying..."
                    git reset --hard origin/main 2>&1
                    echo "4. Restarting agent container..."
                    docker restart dadude-agent 2>&1 || docker compose restart 2>&1
                    echo "✅ Update completed"
                else
                    echo "3. Already up to date"
                fi
            '"""
            
            # Connetti via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": proxmox_ip,
                "port": ssh_port,
                "username": ssh_user,
                "timeout": 30,
                "allow_agent": False,
                "look_for_keys": False,
            }
            
            if ssh_key:
                key_file = StringIO(ssh_key)
                key = paramiko.RSAKey.from_private_key(key_file)
                connect_kwargs["pkey"] = key
            else:
                connect_kwargs["password"] = ssh_password
            
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, lambda: ssh.connect(**connect_kwargs))
            
            # Esegui comando
            stdin, stdout, stderr = await loop.run_in_executor(
                None,
                lambda: ssh.exec_command(update_command, timeout=120)
            )
            
            output = stdout.read().decode()
            error_output = stderr.read().decode()
            exit_status = stdout.channel.recv_exit_status()
            
            ssh.close()
            
            if exit_status == 0:
                logger.success(f"[PROXMOX UPDATE] Agent updated successfully on {proxmox_ip}:{container_id}")
                return CommandResult(
                    success=True,
                    status="success",
                    data={
                        "message": f"Agent updated on Proxmox {proxmox_ip}, container {container_id}",
                        "output": output,
                    }
                )
            else:
                logger.error(f"[PROXMOX UPDATE] Update failed: {error_output}")
                return CommandResult(
                    success=False,
                    status="error",
                    error=f"Update failed: {error_output or output}",
                )
                
        except paramiko.AuthenticationException:
            return CommandResult(success=False, status="error", error="SSH authentication failed")
        except paramiko.SSHException as e:
            return CommandResult(success=False, status="error", error=f"SSH error: {e}")
        except Exception as e:
            logger.error(f"[PROXMOX UPDATE] Error: {e}")
            return CommandResult(success=False, status="error", error=str(e))

