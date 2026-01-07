"""
DaDude - Agent Client
Client per comunicare con gli agent remoti
"""
import asyncio
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
import httpx
from loguru import logger


@dataclass
class AgentConfig:
    """Configurazione agent remoto"""
    agent_id: str
    agent_url: str  # es: http://192.168.1.254:8080
    agent_token: str
    timeout: int = 300  # 5 minuti per network scan


class AgentClient:
    """Client per comunicare con un DaDude Agent remoto"""
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Ottiene client HTTP"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.config.agent_url,
                headers={
                    "Authorization": f"Bearer {self.config.agent_token}",
                    "Content-Type": "application/json",
                },
                timeout=self.config.timeout,
            )
        return self._client
    
    async def close(self):
        """Chiude connessione"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def health_check(self) -> Dict[str, Any]:
        """Verifica stato agent"""
        client = await self._get_client()
        try:
            response = await client.get("/health")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent health check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def probe_wmi(
        self,
        target: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> Dict[str, Any]:
        """Esegue probe WMI tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/probe/wmi", json={
                "target": target,
                "username": username,
                "password": password,
                "domain": domain,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent WMI probe failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def probe_ssh(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
    ) -> Dict[str, Any]:
        """Esegue probe SSH tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/probe/ssh", json={
                "target": target,
                "username": username,
                "password": password,
                "private_key": private_key,
                "port": port,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent SSH probe failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def probe_ssh_advanced(
        self,
        target: str,
        username: str,
        password: Optional[str] = None,
        private_key: Optional[str] = None,
        port: int = 22,
    ) -> Dict[str, Any]:
        """Esegue scansione SSH avanzata tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/probe/ssh-advanced", json={
                "target": target,
                "username": username,
                "password": password,
                "private_key": private_key,
                "port": port,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent SSH advanced probe failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def probe_snmp(
        self,
        target: str,
        community: str = "public",
        version: str = "2c",
        port: int = 161,
    ) -> Dict[str, Any]:
        """Esegue probe SNMP tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/probe/snmp", json={
                "target": target,
                "community": community,
                "version": version,
                "port": port,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent SNMP probe failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def probe_unified(
        self,
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
    ) -> Dict[str, Any]:
        """Esegue scan multi-protocollo unificato tramite agent"""
        client = await self._get_client()
        
        request_body = {
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
        
        logger.info(f"[AGENT_CLIENT] Calling POST /probe/unified to {self.config.agent_url}")
        logger.info(f"[AGENT_CLIENT] Request: target={target}, protocols={protocols}, ssh_user={ssh_user}")
        
        try:
            response = await client.post("/probe/unified", json=request_body)
            logger.info(f"[AGENT_CLIENT] Response status: {response.status_code}")
            
            response.raise_for_status()
            result = response.json()
            
            logger.info(f"[AGENT_CLIENT] Response success={result.get('success')}, "
                       f"has_data={result.get('data') is not None}")
            
            return result
        except httpx.HTTPStatusError as e:
            logger.error(f"[AGENT_CLIENT] HTTP error: {e.response.status_code} - {e.response.text}")
            return {"success": False, "error": f"HTTP {e.response.status_code}: {e.response.text}"}
        except httpx.ConnectError as e:
            logger.error(f"[AGENT_CLIENT] Connection error: {e}")
            return {"success": False, "error": f"Connection failed: {str(e)}"}
        except Exception as e:
            logger.error(f"[AGENT_CLIENT] Agent unified probe failed: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    async def scan_ports(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """Esegue port scan tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/scan/ports", json={
                "target": target,
                "ports": ports,
                "timeout": timeout,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent port scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def scan_network(
        self,
        network: str,
        scan_type: str = "ping",
        timeout: float = 1.0,
    ) -> Dict[str, Any]:
        """Esegue network scan tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/scan/network", json={
                "network": network,
                "scan_type": scan_type,
                "timeout": timeout,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent network scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def dns_reverse(
        self,
        targets: List[str],
        dns_server: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Esegue reverse DNS tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/dns/reverse", json={
                "targets": targets,
                "dns_server": dns_server,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent DNS reverse failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def batch_probe(
        self,
        task_id: str,
        targets: List[Dict[str, Any]],
        credentials: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Esegue probe batch tramite agent"""
        client = await self._get_client()
        
        try:
            response = await client.post("/batch/probe", json={
                "task_id": task_id,
                "targets": targets,
                "credentials": credentials,
                "options": options,
            })
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"Agent batch probe failed: {e}")
            return {"success": False, "error": str(e)}


class AgentManager:
    """Manager per gestire più agent"""
    
    def __init__(self):
        self._agents: Dict[str, AgentClient] = {}
    
    def register_agent(self, config: AgentConfig) -> AgentClient:
        """Registra un nuovo agent"""
        if config.agent_id in self._agents:
            return self._agents[config.agent_id]
        
        client = AgentClient(config)
        self._agents[config.agent_id] = client
        logger.info(f"Registered agent: {config.agent_id} at {config.agent_url}")
        return client
    
    def get_agent(self, agent_id: str) -> Optional[AgentClient]:
        """Ottiene un agent registrato"""
        return self._agents.get(agent_id)
    
    async def close_all(self):
        """Chiude tutti gli agent"""
        for agent in self._agents.values():
            await agent.close()
        self._agents.clear()


# Singleton
_agent_manager: Optional[AgentManager] = None


def get_agent_manager() -> AgentManager:
    global _agent_manager
    if _agent_manager is None:
        _agent_manager = AgentManager()
    return _agent_manager

