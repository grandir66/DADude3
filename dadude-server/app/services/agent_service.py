"""
DaDude - Agent Service
Servizio unificato per gestire agent MikroTik e Docker
Supporta sia agent HTTP legacy che WebSocket
"""
import asyncio
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from loguru import logger

from .agent_client import AgentClient, AgentConfig, get_agent_manager
from .mikrotik_service import get_mikrotik_service
from .device_probe_service import MikroTikAgent
from .customer_service import get_customer_service
from .encryption_service import get_encryption_service
from .websocket_hub import get_websocket_hub, CommandType


@dataclass
class AgentProbeResult:
    """Risultato di un probe via agent"""
    success: bool
    target: str
    protocol: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    agent_id: Optional[str] = None
    duration_ms: Optional[int] = None


class AgentService:
    """
    Servizio unificato per gestire probe via agent.
    Supporta sia MikroTik nativo che DaDude Agent Docker.
    """
    
    def __init__(self):
        self._customer_service = get_customer_service()
        self._mikrotik_service = get_mikrotik_service()
        self._agent_manager = get_agent_manager()
        self._encryption = get_encryption_service()
    
    def get_agent_for_customer(
        self,
        customer_id: str,
        network_id: Optional[str] = None,
        target_ip: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Ottiene l'agent appropriato per un cliente/rete.
        Priorità: 1) agent assegnato a network_id, 2) agent che copre target_ip, 3) primo agent attivo
        Ritorna dict con info agent o None se non trovato.
        """
        agents = self._customer_service.list_agents(customer_id=customer_id)
        
        if not agents:
            return None
        
        # Se network_id specificato, cerca agent assegnato a quella rete
        if network_id:
            for agent in agents:
                if agent.assigned_networks and network_id in agent.assigned_networks:
                    full_agent = self._customer_service.get_agent(agent.id, include_password=True)
                    if full_agent:
                        logger.info(f"Agent selected by network_id {network_id}: {agent.name}")
                        return self._agent_to_dict(full_agent)
        
        # Se target_ip specificato, cerca agent che copre quella subnet
        if target_ip:
            target_subnet = self._get_subnet_from_ip(target_ip)
            if target_subnet:
                for agent in agents:
                    if agent.assigned_networks:
                        for net in agent.assigned_networks:
                            # Verifica se l'IP target appartiene a una delle reti dell'agent
                            if self._ip_in_network(target_ip, net):
                                full_agent = self._customer_service.get_agent(agent.id, include_password=True)
                                if full_agent:
                                    logger.info(f"Agent selected by target_ip {target_ip} (subnet {net}): {agent.name}")
                                    return self._agent_to_dict(full_agent)
        
        # Fallback: primo agent attivo
        for agent in agents:
            if agent.active:
                full_agent = self._customer_service.get_agent(agent.id, include_password=True)
                if full_agent:
                    logger.info(f"Agent selected as fallback (first active): {agent.name}")
                    return self._agent_to_dict(full_agent)
        
        return None
    
    def _get_subnet_from_ip(self, ip: str) -> Optional[str]:
        """Estrae la subnet /24 da un IP"""
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            pass
        return None
    
    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Verifica se un IP appartiene a una rete (supporta /24, /16, etc.)"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            net_obj = ipaddress.ip_network(network, strict=False)
            return ip_obj in net_obj
        except:
            # Fallback: confronto semplice per /24
            try:
                ip_parts = ip.split('.')
                net_parts = network.split('/')[0].split('.')
                # Confronta i primi 3 ottetti per /24
                return ip_parts[:3] == net_parts[:3]
            except:
                return False
    
    def _agent_to_dict(self, agent) -> Dict[str, Any]:
        """Converte agent in dict con password decriptate"""
        result = {
            "id": agent.id,
            "name": agent.name,
            "address": agent.address,
            "port": getattr(agent, 'port', 8728),
            "agent_type": getattr(agent, 'agent_type', 'mikrotik'),
            "dude_agent_id": getattr(agent, 'dude_agent_id', None),
            "username": getattr(agent, 'username', None),
            "use_ssl": getattr(agent, 'use_ssl', False),
            "ssh_port": getattr(agent, 'ssh_port', 22),
            "agent_api_port": getattr(agent, 'agent_api_port', 8080),
            "agent_url": getattr(agent, 'agent_url', None),
            "dns_server": getattr(agent, 'dns_server', None),
            "status": getattr(agent, 'status', 'unknown'),
        }
        
        # Decripta password (potrebbe non esistere in AgentAssignmentSafe)
        password = getattr(agent, 'password', None)
        if password:
            try:
                result["password"] = self._encryption.decrypt(password)
            except:
                result["password"] = password
        else:
            result["password"] = None
        
        # Decripta token agent
        agent_token = getattr(agent, 'agent_token', None)
        if agent_token:
            try:
                result["agent_token"] = self._encryption.decrypt(agent_token)
            except:
                result["agent_token"] = agent_token
        else:
            result["agent_token"] = None
        
        return result
    
    async def _get_ws_agent_id(self, agent_info: Dict[str, Any]) -> Optional[str]:
        """
        Cerca l'agent_id WebSocket per un agent.
        Ritorna l'ID se l'agent è connesso via WebSocket, altrimenti None.
        """
        hub = get_websocket_hub()
        agent_name = agent_info.get("name", "")
        agent_id = agent_info.get("id", "")
        dude_agent_id = agent_info.get("dude_agent_id", "")
        
        # Cerca connessione WebSocket (thread-safe)
        connected_agents_list = await hub.get_connected_agents()
        connected_agents = [a["agent_id"] for a in connected_agents_list]
        logger.info(f"Looking for WebSocket agent '{agent_name}' (id={agent_id}, dude_id={dude_agent_id}). Connected agents: {connected_agents}")
        
        # 1. Priorità massima: match esatto con dude_agent_id (es: agent-Domarc-5193)
        # Usa is_connected() invece di controllare la lista per evitare problemi di timing
        # Aggiungi retry breve per gestire race condition durante riconnessione
        if dude_agent_id:
            import asyncio
            logger.info(f"Trying to find WebSocket agent with dude_id={dude_agent_id}, starting retry loop")
            for attempt in range(3):
                is_conn = await hub.is_connected(dude_agent_id)
                logger.info(f"Retry attempt {attempt + 1}/3: is_connected('{dude_agent_id}') = {is_conn}")
                if is_conn:
                    logger.info(f"WebSocket agent DIRECT matched: {dude_agent_id} (attempt {attempt + 1})")
                    return dude_agent_id
                if attempt < 2:  # Non aspettare dopo l'ultimo tentativo
                    logger.info(f"Waiting 500ms before retry {attempt + 2}/3...")
                    await asyncio.sleep(0.5)  # Attendi 500ms per riconnessione
            logger.info(f"Agent {dude_agent_id} not connected after 3 retries")
        
        # Normalizza per matching: lowercase, spazi -> trattini
        def normalize(s: str) -> str:
            return s.lower().replace(" ", "-").replace("_", "-")
        
        agent_name_norm = normalize(agent_name) if agent_name else ""
        
        if not agent_name_norm:
            logger.warning(f"No agent name provided for WebSocket lookup")
            return None
        
        # Strategia di matching a priorità:
        # 1. Match esatto del nome (agent-NomeEsatto-xxxx)
        # 2. Match con ID agent nel connection ID
        # 3. Match parziale ma preferendo nomi più corti (più specifici)
        
        exact_matches = []
        partial_matches = []
        
        for conn_id in connected_agents:
            conn_id_norm = normalize(conn_id)
            
            # Estrai il nome dall'agent connection ID (format: agent-NOME-xxxx)
            parts = conn_id.split('-')
            if len(parts) >= 2:
                # Il nome è la parte centrale (esclude "agent-" e "-xxxx")
                conn_agent_name = '-'.join(parts[1:-1]) if len(parts) > 2 else parts[1]
                conn_agent_name_norm = normalize(conn_agent_name)
                
                # Match esatto del nome
                if agent_name_norm == conn_agent_name_norm:
                    exact_matches.append((conn_id, len(conn_id)))
                    continue
                
                # Match parziale: il nome agent è contenuto nel connection ID
                # ma deve matchare come parola intera (non come parte di altra parola)
                # Es: "domarc" deve matchare "agent-Domarc-5193" ma NON "agent-DOMARC-RG-6991"
                if agent_name_norm == conn_agent_name_norm.split('-')[0]:
                    # Match solo se è la prima parte del nome (senza suffissi)
                    exact_matches.append((conn_id, len(conn_id)))
                elif agent_name_norm in conn_agent_name_norm:
                    # Match parziale - da usare solo come fallback
                    partial_matches.append((conn_id, len(conn_id)))
        
        # Preferisci match esatti, ordinati per lunghezza (più corti = più specifici)
        if exact_matches:
            exact_matches.sort(key=lambda x: x[1])
            best_match = exact_matches[0][0]
            logger.info(f"WebSocket agent EXACT matched: {best_match} for {agent_name}")
            return best_match
        
        # Fallback a match parziali solo se non ci sono esatti
        if partial_matches:
            partial_matches.sort(key=lambda x: x[1])
            best_match = partial_matches[0][0]
            logger.info(f"WebSocket agent PARTIAL matched: {best_match} for {agent_name}")
            return best_match
        
        logger.warning(f"WebSocket agent not found for: {agent_name}. Connected: {connected_agents}")
        return None
    
    async def _execute_via_websocket(
        self,
        ws_agent_id: str,
        command: CommandType,
        params: Dict[str, Any],
        timeout: float = 60.0,
    ) -> Dict[str, Any]:
        """Esegue un comando via WebSocket Hub"""
        hub = get_websocket_hub()
        
        logger.debug(f"WebSocket command: sending {command.value} to {ws_agent_id} with params keys: {list(params.keys())}")
        result = await hub.send_command(
            ws_agent_id,
            command,
            params=params,
            timeout=timeout,
        )
        
        if result.status == "success":
            data_keys = list(result.data.keys()) if isinstance(result.data, dict) else []
            logger.info(f"WebSocket command {command.value} succeeded, returned {len(data_keys)} fields: {sorted(data_keys)[:30]}")
            if isinstance(result.data, dict) and result.data.get("running_services_count"):
                logger.info(f"WebSocket result includes: running_services_count={result.data.get('running_services_count')}, cron_jobs_count={result.data.get('cron_jobs_count')}, neighbors_count={result.data.get('neighbors_count')}")
            return {
                "success": True,
                "data": result.data,
            }
        else:
            logger.warning(f"WebSocket command {command.value} failed: {result.error}")
            return {
                "success": False,
                "error": result.error or "WebSocket command failed",
            }
    
    def _get_docker_client(self, agent_info: Dict[str, Any]) -> AgentClient:
        """Crea/ottiene client per agent Docker (HTTP legacy)"""
        agent_id = agent_info["id"]
        
        # URL dell'agent
        agent_url = agent_info.get("agent_url")
        if not agent_url:
            address = agent_info["address"]
            port = agent_info.get("agent_api_port", 8080)
            agent_url = f"http://{address}:{port}"
        
        config = AgentConfig(
            agent_id=agent_id,
            agent_url=agent_url,
            agent_token=agent_info.get("agent_token", ""),
            timeout=30,
        )
        
        return self._agent_manager.register_agent(config)
    
    def _get_mikrotik_agent(self, agent_info: Dict[str, Any]) -> MikroTikAgent:
        """Crea oggetto MikroTikAgent per agent MikroTik nativo"""
        return MikroTikAgent(
            address=agent_info["address"],
            username=agent_info.get("username", "admin"),
            password=agent_info.get("password", ""),
            port=agent_info.get("ssh_port", 22),
            api_port=agent_info.get("port", 8728),
            use_ssl=agent_info.get("use_ssl", False),
            dns_server=agent_info.get("dns_server"),
        )
    
    async def probe_wmi(
        self,
        agent_info: Dict[str, Any],
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> AgentProbeResult:
        """
        Esegue probe WMI via agent.
        Solo agent Docker può eseguire WMI.
        Supporta sia WebSocket che HTTP.
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        if agent_type != "docker":
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="wmi",
                error="WMI probe requires Docker agent",
                agent_id=agent_info.get("id"),
            )
        
        try:
            # Prima prova WebSocket
            ws_agent_id = await self._get_ws_agent_id(agent_info)
            
            if ws_agent_id:
                logger.info(f"Executing WMI probe via WebSocket to {target}")
                result = await self._execute_via_websocket(
                    ws_agent_id,
                    CommandType.PROBE_WMI,
                    params={
                        "target": target,
                        "username": username,
                        "password": password,
                        "domain": domain,
                    },
                    timeout=120.0,
                )
            else:
                # Fallback a HTTP
                logger.info(f"Executing WMI probe via HTTP to {target}")
                client = self._get_docker_client(agent_info)
                result = await client.probe_wmi(
                    target=target,
                    username=username,
                    password=password,
                    domain=domain,
                )
            
            return AgentProbeResult(
                success=result.get("success", False),
                target=target,
                protocol="wmi",
                data=result.get("data"),
                error=result.get("error"),
                agent_id=agent_info.get("id"),
                duration_ms=result.get("duration_ms"),
            )
        except Exception as e:
            logger.error(f"Agent WMI probe failed: {e}")
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="wmi",
                error=str(e),
                agent_id=agent_info.get("id"),
            )
    
    async def probe_ssh(
        self,
        agent_info: Dict[str, Any],
        target: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
    ) -> AgentProbeResult:
        """
        Esegue probe SSH via agent.
        Solo agent Docker può eseguire SSH probe.
        Supporta sia WebSocket che HTTP.
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        if agent_type != "docker":
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="ssh",
                error="SSH probe requires Docker agent",
                agent_id=agent_info.get("id"),
            )
        
        try:
            # Prima prova WebSocket
            ws_agent_id = await self._get_ws_agent_id(agent_info)
            
            if ws_agent_id:
                logger.info(f"Executing SSH probe via WebSocket to {target}")
                result = await self._execute_via_websocket(
                    ws_agent_id,
                    CommandType.PROBE_SSH,
                    params={
                        "target": target,
                        "username": username,
                        "password": password,
                        "private_key": private_key,
                        "port": port,
                    },
                    timeout=60.0,
                )
            else:
                # Fallback a HTTP
                logger.info(f"Executing SSH probe via HTTP to {target}")
                client = self._get_docker_client(agent_info)
                result = await client.probe_ssh(
                    target=target,
                    username=username,
                    password=password,
                    private_key=private_key,
                    port=port,
                )
            
            return AgentProbeResult(
                success=result.get("success", False),
                target=target,
                protocol="ssh",
                data=result.get("data"),
                error=result.get("error"),
                agent_id=agent_info.get("id"),
                duration_ms=result.get("duration_ms"),
            )
        except Exception as e:
            logger.error(f"Agent SSH probe failed: {e}")
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="ssh",
                error=str(e),
                agent_id=agent_info.get("id"),
            )
    
    async def probe_ssh_advanced(
        self,
        agent_info: Dict[str, Any],
        target: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
    ) -> AgentProbeResult:
        """
        Esegue scansione SSH avanzata via agent.
        Solo agent Docker può eseguire SSH advanced probe.
        Supporta sia WebSocket che HTTP.
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        if agent_type != "docker":
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="ssh-advanced",
                error="SSH advanced probe requires Docker agent",
                agent_id=agent_info.get("id"),
            )
        
        try:
            # Prima prova WebSocket
            ws_agent_id = await self._get_ws_agent_id(agent_info)
            
            if ws_agent_id:
                logger.info(f"Executing SSH advanced probe via WebSocket to {target}")
                result = await self._execute_via_websocket(
                    ws_agent_id,
                    CommandType.PROBE_SSH_ADVANCED,
                    params={
                        "target": target,
                        "username": username,
                        "password": password,
                        "private_key": private_key,
                        "port": port,
                    },
                    timeout=120.0,  # Timeout più lungo per scan avanzato
                )
            else:
                # Fallback a HTTP
                logger.info(f"Executing SSH advanced probe via HTTP to {target}")
                client = self._get_docker_client(agent_info)
                result = await client.probe_ssh_advanced(
                    target=target,
                    username=username,
                    password=password,
                    private_key=private_key,
                    port=port,
                )
            
            return AgentProbeResult(
                success=result.get("success", False),
                target=target,
                protocol="ssh-advanced",
                data=result.get("data"),
                error=result.get("error"),
                agent_id=agent_info.get("id"),
                duration_ms=result.get("duration_ms"),
            )
        except Exception as e:
            logger.error(f"Agent SSH advanced probe failed: {e}")
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="ssh-advanced",
                error=str(e),
                agent_id=agent_info.get("id"),
            )
    
    async def probe_unified(
        self,
        agent_info: Dict[str, Any],
        target: str,
        protocols: List[str],
        ssh_user: Optional[str] = None,
        ssh_password: Optional[str] = None,
        ssh_key: Optional[str] = None,
        ssh_port: int = 22,
        winrm_user: Optional[str] = None,
        winrm_password: Optional[str] = None,
        winrm_domain: str = "",
        winrm_port: int = 5985,
        snmp_community: str = "public",
        snmp_port: int = 161,
        snmp_version: int = 2,
        timeout: int = 30,
    ) -> AgentProbeResult:
        """
        Esegue scansione multi-protocollo unificata via agent.
        Solo agent Docker può eseguire unified probe.
        PRIORITÀ: WebSocket (più affidabile), poi HTTP come fallback.
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        dude_agent_id = agent_info.get("dude_agent_id")
        
        logger.info(f"[PROBE_UNIFIED] Starting for {target}, agent_type={agent_type}, "
                   f"dude_agent_id={dude_agent_id}, protocols={protocols}")
        logger.info(f"[PROBE_UNIFIED] Credentials: ssh_user={ssh_user}, snmp_community={snmp_community}")
        
        if agent_type != "docker":
            logger.warning(f"[PROBE_UNIFIED] Agent type '{agent_type}' is not docker, rejecting")
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="unified",
                error="Unified probe requires Docker agent",
                agent_id=agent_info.get("id"),
            )
        
        ws_params = {
            "target": target,
            "protocols": protocols,
            "ssh_user": ssh_user,
            "ssh_password": ssh_password,
            "ssh_key": ssh_key,
            "ssh_port": ssh_port,
            "winrm_user": winrm_user,
            "winrm_password": winrm_password,
            "winrm_domain": winrm_domain,
            "winrm_port": winrm_port,
            "snmp_community": snmp_community,
            "snmp_port": snmp_port,
            "snmp_version": snmp_version,
            "timeout": timeout,
        }
        
        result = None
        ws_success = False
        
        try:
            # PRIORITÀ 1: WebSocket via dude_agent_id (connessione diretta)
            if dude_agent_id:
                logger.info(f"[PROBE_UNIFIED] Trying WebSocket to {dude_agent_id}")
                try:
                    result = await self._execute_via_websocket(
                        dude_agent_id,
                        CommandType.PROBE_UNIFIED,
                        params=ws_params,
                        timeout=180.0,  # Timeout più lungo per scan multi-protocollo
                    )
                    if result.get("success"):
                        logger.info(f"[PROBE_UNIFIED] WebSocket SUCCESS via {dude_agent_id}")
                        data_keys = list(result["data"].keys()) if isinstance(result.get("data"), dict) else []
                        logger.info(f"[PROBE_UNIFIED] Data fields ({len(data_keys)}): {sorted(data_keys)[:15]}")
                        return AgentProbeResult(
                            success=True,
                            target=target,
                            protocol="unified",
                            data=result.get("data"),
                            agent_id=agent_info.get("id"),
                        )
                    else:
                        logger.warning(f"[PROBE_UNIFIED] WebSocket returned success=False: {result.get('error')}")
                except Exception as ws_err:
                    logger.warning(f"[PROBE_UNIFIED] WebSocket to {dude_agent_id} failed: {ws_err}")
            
            # PRIORITÀ 2: WebSocket via _get_ws_agent_id (cerca l'agent connesso per nome)
            # Sempre chiamato se il primo tentativo fallisce
            logger.info(f"[PROBE_UNIFIED] Searching for connected agent by name...")
            ws_agent_id = await self._get_ws_agent_id(agent_info)
            
            if ws_agent_id:
                logger.info(f"[PROBE_UNIFIED] Found connected agent: {ws_agent_id}")
                try:
                    result = await self._execute_via_websocket(
                        ws_agent_id,
                        CommandType.PROBE_UNIFIED,
                        params=ws_params,
                        timeout=180.0,
                    )
                    if result.get("success"):
                        logger.info(f"[PROBE_UNIFIED] WebSocket SUCCESS via {ws_agent_id}")
                        data_keys = list(result["data"].keys()) if isinstance(result.get("data"), dict) else []
                        logger.info(f"[PROBE_UNIFIED] Data fields ({len(data_keys)}): {sorted(data_keys)[:15]}")
                        return AgentProbeResult(
                            success=True,
                            target=target,
                            protocol="unified",
                            data=result.get("data"),
                            agent_id=agent_info.get("id"),
                        )
                    else:
                        logger.warning(f"[PROBE_UNIFIED] WebSocket via {ws_agent_id} returned success=False: {result.get('error')}")
                except Exception as ws_err:
                    logger.warning(f"[PROBE_UNIFIED] WebSocket via {ws_agent_id} failed: {ws_err}")
            else:
                logger.warning(f"[PROBE_UNIFIED] No connected agent found for {agent_info.get('name')}")
            
            # PRIORITÀ 3: HTTP Fallback
            agent_address = agent_info.get("address")
            agent_api_port = agent_info.get("agent_api_port", 8080)
            agent_url = agent_info.get("agent_url") or f"http://{agent_address}:{agent_api_port}"
            
            logger.info(f"[PROBE_UNIFIED] Trying HTTP fallback to {agent_url}")
            
            client = self._get_docker_client(agent_info)
            result = await client.probe_unified(
                target=target,
                protocols=protocols,
                ssh_user=ssh_user,
                ssh_password=ssh_password,
                ssh_key=ssh_key,
                ssh_port=ssh_port,
                winrm_user=winrm_user,
                winrm_password=winrm_password,
                winrm_domain=winrm_domain,
                winrm_port=winrm_port,
                snmp_community=snmp_community,
                snmp_port=snmp_port,
                snmp_version=snmp_version,
                timeout=timeout,
            )
            
            logger.info(f"[PROBE_UNIFIED] HTTP result: success={result.get('success')}, error={result.get('error')}")
            
            if result.get("data"):
                data_keys = list(result["data"].keys()) if isinstance(result["data"], dict) else []
                logger.info(f"[PROBE_UNIFIED] Data fields ({len(data_keys)}): {sorted(data_keys)[:15]}")
            
            return AgentProbeResult(
                success=result.get("success", False),
                target=target,
                protocol="unified",
                data=result.get("data"),
                error=result.get("error"),
                agent_id=agent_info.get("id"),
                duration_ms=result.get("duration_ms"),
            )
            
        except Exception as e:
            logger.error(f"[PROBE_UNIFIED] Exception: {e}", exc_info=True)
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="unified",
                error=str(e),
                agent_id=agent_info.get("id"),
            )
    
    async def probe_snmp(
        self,
        agent_info: Dict[str, Any],
        target: str,
        community: str = "public",
        version: str = "2c",
        port: int = 161,
    ) -> AgentProbeResult:
        """
        Esegue probe SNMP via agent.
        Solo agent Docker può eseguire SNMP probe.
        Supporta sia WebSocket che HTTP.
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        if agent_type != "docker":
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="snmp",
                error="SNMP probe requires Docker agent",
                agent_id=agent_info.get("id"),
            )
        
        try:
            # Prima prova WebSocket
            ws_agent_id = await self._get_ws_agent_id(agent_info)
            
            if ws_agent_id:
                logger.info(f"Executing SNMP probe via WebSocket to {target}")
                result = await self._execute_via_websocket(
                    ws_agent_id,
                    CommandType.PROBE_SNMP,
                    params={
                        "target": target,
                        "community": community,
                        "version": version,
                        "port": port,
                    },
                    timeout=60.0,
                )
            else:
                # Fallback a HTTP
                logger.info(f"Executing SNMP probe via HTTP to {target}")
                client = self._get_docker_client(agent_info)
                result = await client.probe_snmp(
                    target=target,
                    community=community,
                    version=version,
                    port=port,
                )
            
            return AgentProbeResult(
                success=result.get("success", False),
                target=target,
                protocol="snmp",
                data=result.get("data"),
                error=result.get("error"),
                agent_id=agent_info.get("id"),
                duration_ms=result.get("duration_ms"),
            )
        except Exception as e:
            logger.error(f"Agent SNMP probe failed: {e}")
            return AgentProbeResult(
                success=False,
                target=target,
                protocol="snmp",
                error=str(e),
                agent_id=agent_info.get("id"),
            )
    
    async def scan_ports(
        self,
        agent_info: Dict[str, Any],
        target: str,
        ports: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """
        Esegue port scan via agent.
        Docker: usa API agent (WebSocket o HTTP)
        MikroTik: usa /tool fetch per ogni porta
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        try:
            if agent_type == "docker":
                # Prima prova WebSocket
                ws_agent_id = self._get_ws_agent_id(agent_info)
                
                if ws_agent_id:
                    logger.info(f"Executing port scan via WebSocket to {target}")
                    result = await self._execute_via_websocket(
                        ws_agent_id,
                        CommandType.SCAN_PORTS,
                        params={
                            "target": target,
                            "ports": ports,
                        },
                        timeout=120.0,
                    )
                    if result.get("success"):
                        return {
                            "success": True,
                            "target": target,
                            "open_ports": result.get("data", {}).get("open_ports", []),
                        }
                    return result
                else:
                    # Fallback a HTTP
                    logger.info(f"Executing port scan via HTTP to {target}")
                    client = self._get_docker_client(agent_info)
                    result = await client.scan_ports(target, ports)
                    return result
            else:
                # MikroTik nativo: scan limitato via API
                mikrotik = self._get_mikrotik_agent(agent_info)
                open_ports = await self._scan_ports_mikrotik(mikrotik, target, ports)
                return {
                    "success": True,
                    "target": target,
                    "open_ports": open_ports,
                }
        except Exception as e:
            logger.error(f"Agent port scan failed: {e}")
            return {
                "success": False,
                "target": target,
                "error": str(e),
            }
    
    async def _scan_ports_mikrotik(
        self,
        agent: MikroTikAgent,
        target: str,
        ports: Optional[List[int]] = None,
    ) -> List[Dict[str, Any]]:
        """Scansiona porte via MikroTik (limitato)"""
        from .mikrotik_service import get_mikrotik_service
        
        mikrotik = get_mikrotik_service()
        
        # Porte di default
        if ports is None:
            ports = [22, 80, 443, 3389, 445, 161, 8728]
        
        results = []
        loop = asyncio.get_event_loop()
        
        for port in ports:
            try:
                is_open = await loop.run_in_executor(
                    None,
                    lambda p=port: mikrotik.check_port(
                        agent.address,
                        agent.port,
                        agent.username,
                        agent.password,
                        target,
                        p
                    )
                )
                if is_open:
                    results.append({
                        "port": port,
                        "protocol": "tcp",
                        "open": True,
                    })
            except:
                pass
        
        return results
    
    async def reverse_dns(
        self,
        agent_info: Dict[str, Any],
        targets: List[str],
    ) -> Dict[str, Optional[str]]:
        """
        Esegue reverse DNS via agent.
        Docker: usa API agent
        MikroTik: usa /resolve
        """
        agent_type = agent_info.get("agent_type", "mikrotik")
        dns_server = agent_info.get("dns_server")
        
        try:
            if agent_type == "docker":
                client = self._get_docker_client(agent_info)
                result = await client.dns_reverse(targets, dns_server)
                return result.get("results", {})
            else:
                # MikroTik nativo
                mikrotik = self._get_mikrotik_agent(agent_info)
                return await self._reverse_dns_mikrotik(mikrotik, targets)
        except Exception as e:
            logger.error(f"Agent DNS reverse failed: {e}")
            return {}
    
    async def _reverse_dns_mikrotik(
        self,
        agent: MikroTikAgent,
        targets: List[str],
    ) -> Dict[str, Optional[str]]:
        """Esegue reverse DNS via MikroTik"""
        from .mikrotik_service import get_mikrotik_service
        
        mikrotik = get_mikrotik_service()
        loop = asyncio.get_event_loop()
        
        return await loop.run_in_executor(
            None,
            lambda: mikrotik.batch_reverse_dns_lookup(
                agent.address,
                agent.port,
                agent.username,
                agent.password,
                targets,
                agent.dns_server,
            )
        )
    
    async def check_agent_health(self, agent_info: Dict[str, Any]) -> Dict[str, Any]:
        """Verifica stato agent"""
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        try:
            if agent_type == "docker":
                client = self._get_docker_client(agent_info)
                return await client.health_check()
            else:
                # MikroTik: verifica connessione API
                mikrotik = self._get_mikrotik_agent(agent_info)
                loop = asyncio.get_event_loop()
                
                from .mikrotik_service import get_mikrotik_service
                svc = get_mikrotik_service()
                
                info = await loop.run_in_executor(
                    None,
                    lambda: svc.get_system_info(
                        mikrotik.address,
                        mikrotik.api_port,
                        mikrotik.username,
                        mikrotik.password,
                        mikrotik.use_ssl,
                    )
                )
                
                if info:
                    return {
                        "status": "healthy",
                        "agent_type": "mikrotik",
                        "version": info.get("version"),
                        "board_name": info.get("board_name"),
                    }
                else:
                    return {"status": "error", "error": "Connection failed"}
                    
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def auto_probe(
        self,
        agent_info: Dict[str, Any],
        target: str,
        open_ports: List[Dict[str, Any]],
        credentials: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Esegue auto-probe basato su porte aperte.
        Prova WMI, SNMP, SSH in ordine di priorità.
        Se ci sono credenziali assegnate, prova anche senza porte aperte rilevate.
        """
        results = {
            "target": target,
            "probes": [],
            "best_result": None,
        }
        
        agent_type = agent_info.get("agent_type", "mikrotik")
        
        # Solo Docker agent può fare probe avanzati
        if agent_type != "docker":
            results["error"] = "Advanced probing requires Docker agent"
            return results
        
        # Determina quali probe fare
        open_port_nums = {p.get("port") for p in open_ports if p.get("open")}
        logger.info(f"Agent auto_probe: Target {target}, open ports: {open_port_nums}, credentials: {[c.get('type') for c in credentials]}")
        
        # Ordine priorità: WMI (più info), SNMP, SSH
        probe_order = []
        
        # Windows ports
        if open_port_nums & {3389, 445, 139, 135, 5985}:
            for cred in credentials:
                if cred.get("type") == "wmi":
                    probe_order.append(("wmi", cred))
                    break
        
        # SNMP - prova sempre se ci sono credenziali SNMP (UDP potrebbe non essere rilevato)
        for cred in credentials:
            if cred.get("type") == "snmp":
                logger.info(f"Agent auto_probe: Adding SNMP probe for {target} (community: {cred.get('snmp_community', 'public')})")
                probe_order.append(("snmp", cred))
                break
        
        # SSH - prova sempre se ci sono credenziali SSH (porta potrebbe essere filtrata o non rilevata)
        # Se c'è una credenziale SSH assegnata, prova sempre SSH anche senza porte aperte
        for cred in credentials:
            if cred.get("type") == "ssh":
                # Prova SSH se porta 22 è aperta OPPURE se non ci sono porte aperte (fallback)
                if 22 in open_port_nums or len(open_port_nums) == 0:
                    probe_order.append(("ssh", cred))
                    logger.info(f"Agent auto_probe: Adding SSH probe for {target} (port 22 {'detected' if 22 in open_port_nums else 'not detected, trying anyway'})")
                    break
        
        # Esegui probe
        for probe_type, cred in probe_order:
            try:
                if probe_type == "wmi":
                    result = await self.probe_wmi(
                        agent_info,
                        target,
                        cred.get("username", ""),
                        cred.get("password", ""),
                        cred.get("wmi_domain", ""),
                    )
                elif probe_type == "snmp":
                    logger.info(f"Agent auto_probe: Executing SNMP probe for {target} via agent {agent_info.get('id')}")
                    result = await self.probe_snmp(
                        agent_info,
                        target,
                        cred.get("snmp_community", "public"),
                        cred.get("snmp_version", "2c"),
                        cred.get("snmp_port", 161),
                    )
                    logger.info(f"Agent auto_probe: SNMP probe result: success={result.success}, has_data={result.data is not None}, error={result.error}")
                    if result.data:
                        data_keys = list(result.data.keys()) if isinstance(result.data, dict) else []
                        logger.info(f"Agent auto_probe: SNMP probe returned {len(data_keys)} fields: {sorted(data_keys)[:30]}")
                        if isinstance(result.data, dict):
                            neighbors_count = len(result.data.get("neighbors", [])) or len(result.data.get("lldp_neighbors", []))
                            if neighbors_count > 0:
                                logger.info(f"Agent auto_probe: SNMP probe found {neighbors_count} neighbors")
                            else:
                                logger.warning(f"Agent auto_probe: SNMP probe found NO neighbors (device_type={result.data.get('device_type')}, is_network={result.data.get('device_type') in ['router', 'switch', 'ap', 'network']})")
                elif probe_type == "ssh":
                    result = await self.probe_ssh(
                        agent_info,
                        target,
                        cred.get("username", ""),
                        cred.get("password"),
                        cred.get("ssh_private_key"),
                        cred.get("ssh_port", 22),
                    )
                else:
                    continue
                
                probe_info = {
                    "type": probe_type,
                    "success": result.success,
                    "data": result.data,
                    "error": result.error,
                    "credential": {  # Traccia quale credenziale è stata usata
                        "id": cred.get("id"),
                        "name": cred.get("name"),
                        "username": cred.get("username"),
                        "type": cred.get("type"),
                    }
                }
                results["probes"].append(probe_info)
                
                if result.success and not results["best_result"]:
                    data_keys = list(result.data.keys()) if isinstance(result.data, dict) else []
                    logger.info(f"Agent auto_probe: {probe_type} probe succeeded, collected {len(data_keys)} fields: {sorted(data_keys)[:30]}")
                    if isinstance(result.data, dict) and result.data.get("running_services_count"):
                        logger.info(f"Agent auto_probe: result.data includes: running_services_count={result.data.get('running_services_count')}, cron_jobs_count={result.data.get('cron_jobs_count')}, neighbors_count={result.data.get('neighbors_count')}")
                    results["best_result"] = {
                        "type": probe_type,
                        "data": result.data,
                        "credential": probe_info["credential"],  # Includi anche la credenziale nel best_result
                    }
                    
            except Exception as e:
                logger.error(f"Agent auto_probe: {probe_type} probe failed: {e}", exc_info=True)
                results["probes"].append({
                    "type": probe_type,
                    "success": False,
                    "error": str(e),
                })
        
        if results["best_result"]:
            best_data_keys = list(results["best_result"]["data"].keys()) if isinstance(results["best_result"]["data"], dict) else []
            logger.info(f"Agent auto_probe: Returning best_result with {len(best_data_keys)} fields: {sorted(best_data_keys)[:30]}")
        
        return results


# Singleton
_agent_service: Optional[AgentService] = None


def get_agent_service() -> AgentService:
    global _agent_service
    if _agent_service is None:
        _agent_service = AgentService()
    return _agent_service

