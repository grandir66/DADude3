"""
DaDude - RouterOS/Dude API Service
Gestisce la connessione e le query al server Dude tramite API RouterOS
"""
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime
from loguru import logger
import routeros_api

from ..config import Settings, get_settings
from ..models import Device, Probe, Alert, DeviceStatus, ProbeStatus, DudeServerInfo


class DudeService:
    """Servizio per comunicazione con Dude Server via RouterOS API"""
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self._connection = None
        self._api = None
        self._connected = False
        self._last_sync: Optional[datetime] = None
        
        # Override runtime per credenziali
        self._host_override: Optional[str] = None
        self._port_override: Optional[int] = None
        self._username_override: Optional[str] = None
        self._password_override: Optional[str] = None
        self._use_ssl_override: Optional[bool] = None
    
    @property
    def host(self) -> str:
        return self._host_override or self.settings.dude_host
    
    @host.setter
    def host(self, value: str):
        self._host_override = value
    
    @property
    def port(self) -> int:
        return self._port_override or self.settings.dude_api_port
    
    @port.setter
    def port(self, value: int):
        self._port_override = value
    
    @property
    def username(self) -> str:
        return self._username_override or self.settings.dude_username
    
    @username.setter
    def username(self, value: str):
        self._username_override = value
    
    @property
    def password(self) -> str:
        return self._password_override or self.settings.dude_password
    
    @password.setter
    def password(self, value: str):
        self._password_override = value
    
    @property
    def use_ssl(self) -> bool:
        return self._use_ssl_override if self._use_ssl_override is not None else self.settings.dude_use_ssl
    
    @use_ssl.setter
    def use_ssl(self, value: bool):
        self._use_ssl_override = value
        
    @property
    def is_connected(self) -> bool:
        return self._connected and self._api is not None
    
    def connect(self) -> bool:
        """Stabilisce connessione al server Dude"""
        try:
            # Chiudi connessione esistente se presente
            if self._connection:
                try:
                    self._connection.disconnect()
                except:
                    pass
            
            logger.info(f"Connecting to Dude Server at {self.host}:{self.port}")
            
            self._connection = routeros_api.RouterOsApiPool(
                host=self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                use_ssl=self.use_ssl,
                ssl_verify=False,
                plaintext_login=True,
            )
            
            self._api = self._connection.get_api()
            self._connected = True
            logger.success(f"Connected to Dude Server at {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Dude Server: {e}")
            self._connected = False
            self._api = None
            self._connection = None
            return False
    
    def disconnect(self):
        """Chiude la connessione"""
        try:
            if self._connection:
                self._connection.disconnect()
            self._connected = False
            self._api = None
            logger.info("Disconnected from Dude Server")
        except Exception as e:
            logger.warning(f"Error during disconnect: {e}")
    
    def _ensure_connected(self):
        """Assicura che la connessione sia attiva"""
        if not self.is_connected:
            if not self.connect():
                raise ConnectionError("Cannot connect to Dude Server")
    
    def _reconnect_if_needed(self):
        """Riconnette se la connessione è persa"""
        try:
            # Prova una query semplice per verificare se la connessione è ancora valida
            if self._api:
                self._api.get_resource('/system/resource').get()
        except (OSError, ConnectionError, AttributeError, Exception) as e:
            error_str = str(e)
            # Ignora errori di parsing che non indicano connessione persa
            if "Malformed" in error_str or "Unknown tag" in error_str:
                # Errore di parsing, non di connessione - non riconnettere
                logger.debug(f"Parsing error (not connection issue): {e}")
                return
            
            logger.warning(f"Connection lost, reconnecting: {e}")
            self._connected = False
            self._api = None
            if self._connection:
                try:
                    self._connection.disconnect()
                except:
                    pass
            self._connection = None
            try:
                if not self.connect():
                    raise ConnectionError("Cannot reconnect to Dude Server")
            except Exception as reconnect_error:
                logger.error(f"Failed to reconnect: {reconnect_error}")
                raise ConnectionError(f"Cannot reconnect to Dude Server: {reconnect_error}")
    
    def get_devices(self, status_filter: Optional[str] = None) -> List[Device]:
        """Ottiene lista dispositivi dal Dude"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                self._ensure_connected()
                self._reconnect_if_needed()
                
                dude_resource = self._api.get_resource('/dude/device')
                raw_devices = dude_resource.get()
                
                devices = []
                for raw in raw_devices:
                    try:
                        # Mappa status Dude -> DeviceStatus
                        status_map = {
                            "up": DeviceStatus.UP,
                            "down": DeviceStatus.DOWN,
                            "disabled": DeviceStatus.DISABLED,
                            "partial": DeviceStatus.PARTIAL,
                        }
                        status_str = raw.get("status", "") or ""
                        status = status_map.get(status_str.lower(), DeviceStatus.UNKNOWN)
                        
                        if status_filter and status.value != status_filter:
                            continue
                        
                        device = Device(
                            id=raw.get(".id", "") or "",
                            name=raw.get("name") or "Unknown",
                            address=raw.get("address"),
                            mac_address=raw.get("mac-address"),
                            status=status,
                            device_type=raw.get("type"),
                            group=raw.get("group"),
                            location=raw.get("location"),
                            note=raw.get("note"),
                        )
                        devices.append(device)
                    except Exception as e:
                        logger.warning(f"Error parsing device {raw.get('.id', 'unknown')}: {e}")
                        continue
                
                logger.debug(f"Retrieved {len(devices)} devices from Dude")
                return devices
                
            except (OSError, ConnectionError) as e:
                error_str = str(e)
                if "Bad file descriptor" in error_str or "Errno 9" in error_str:
                    logger.warning(f"Connection lost (attempt {attempt + 1}/{max_retries}): {e}")
                    self._connected = False
                    self._api = None
                    self._connection = None
                    if attempt < max_retries - 1:
                        # Prova a riconnettere
                        try:
                            if self.connect():
                                continue  # Riprova la query
                        except Exception as reconnect_error:
                            logger.error(f"Reconnection failed: {reconnect_error}")
                    raise
                else:
                    logger.error(f"Connection error getting devices: {e}")
                    raise
            except Exception as e:
                error_str = str(e)
                # Se è un errore di parsing malformato, logga ma non fallire completamente
                if "Malformed" in error_str or "Unknown tag" in error_str:
                    logger.error(f"Malformed data from Dude server: {e}")
                    # Ritorna lista vuota invece di fallire completamente
                    return []
                logger.error(f"Error getting devices: {e}")
                raise
    
    def get_device(self, device_id: str) -> Optional[Device]:
        """Ottiene singolo dispositivo per ID"""
        devices = self.get_devices()
        return next((d for d in devices if d.id == device_id), None)
    
    def get_probes(self, device_id: Optional[str] = None) -> List[Probe]:
        """Ottiene lista probe dal Dude"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                self._ensure_connected()
                self._reconnect_if_needed()
                
                probe_resource = self._api.get_resource('/dude/probe')
                raw_probes = probe_resource.get()
                
                probes = []
                for raw in raw_probes:
                    try:
                        if device_id and raw.get("device") != device_id:
                            continue
                        
                        status_map = {
                            "ok": ProbeStatus.OK,
                            "warning": ProbeStatus.WARNING,
                            "critical": ProbeStatus.CRITICAL,
                        }
                        status_str = raw.get("status", "") or ""
                        status = status_map.get(status_str.lower(), ProbeStatus.UNKNOWN)
                        
                        probe = Probe(
                            id=raw.get(".id", "") or "",
                            name=raw.get("name") or "Unknown",
                            device_id=raw.get("device", "") or "",
                            probe_type=raw.get("type", "unknown") or "unknown",
                            status=status,
                            value=raw.get("value"),
                            unit=raw.get("unit"),
                        )
                        probes.append(probe)
                    except Exception as e:
                        logger.warning(f"Error parsing probe {raw.get('.id', 'unknown')}: {e}")
                        continue
                
                logger.debug(f"Retrieved {len(probes)} probes from Dude")
                return probes
                
            except (OSError, ConnectionError) as e:
                error_str = str(e)
                if "Bad file descriptor" in error_str or "Errno 9" in error_str:
                    logger.warning(f"Connection lost (attempt {attempt + 1}/{max_retries}): {e}")
                    self._connected = False
                    self._api = None
                    self._connection = None
                    if attempt < max_retries - 1:
                        # Prova a riconnettere
                        try:
                            if self.connect():
                                continue  # Riprova la query
                        except Exception as reconnect_error:
                            logger.error(f"Reconnection failed: {reconnect_error}")
                    raise
                else:
                    logger.error(f"Connection error getting probes: {e}")
                    raise
            except Exception as e:
                error_str = str(e)
                # Se è un errore di parsing malformato, logga ma non fallire completamente
                if "Malformed" in error_str or "Unknown tag" in error_str:
                    logger.error(f"Malformed data from Dude server: {e}")
                    # Ritorna lista vuota invece di fallire completamente
                    return []
                logger.error(f"Error getting probes: {e}")
                raise
    
    def get_server_info(self) -> DudeServerInfo:
        """Ottiene informazioni sul server Dude"""
        try:
            self._ensure_connected()
            
            # Conta dispositivi e probe
            devices = self.get_devices()
            probes = self.get_probes()
            
            # Ottieni info sistema RouterOS
            system_resource = self._api.get_resource('/system/resource')
            system_info = system_resource.get()[0] if system_resource.get() else {}
            
            return DudeServerInfo(
                version=system_info.get("version"),
                uptime=system_info.get("uptime"),
                device_count=len(devices),
                probe_count=len(probes),
                alert_count=0,
                connected=True,
                last_sync=datetime.utcnow(),
            )
            
        except Exception as e:
            logger.error(f"Error getting server info: {e}")
            return DudeServerInfo(connected=False)
    
    def execute_command(self, path: str, command: str = "print", params: Dict[str, Any] = None) -> List[Dict]:
        """Esegue comando generico via API"""
        self._ensure_connected()
        
        try:
            resource = self._api.get_resource(path)
            
            if command == "print" or command == "get":
                return resource.get(**(params or {}))
            elif command == "set":
                return resource.set(**(params or {}))
            elif command == "add":
                return resource.add(**(params or {}))
            elif command == "remove":
                return resource.remove(**(params or {}))
            else:
                return resource.call(command, params or {})
                
        except Exception as e:
            logger.error(f"Error executing command {path}/{command}: {e}")
            raise

    def get_agents(self) -> List[Dict[str, Any]]:
        """Ottiene lista agenti/sonde The Dude"""
        self._ensure_connected()
        
        try:
            agent_resource = self._api.get_resource('/dude/agent')
            raw_agents = agent_resource.get()
            
            agents = []
            for raw in raw_agents:
                agent = {
                    "id": raw.get(".id", ""),
                    "name": raw.get("name", "Unknown"),
                    "address": raw.get("address", ""),
                    "status": raw.get("status", "unknown"),
                    "version": raw.get("version", ""),
                    "enabled": raw.get("disabled", "false") != "true",
                }
                agents.append(agent)
            
            logger.debug(f"Retrieved {len(agents)} agents from Dude")
            return agents
            
        except Exception as e:
            logger.error(f"Error getting agents: {e}")
            return []

    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Ottiene singolo agente per ID"""
        agents = self.get_agents()
        return next((a for a in agents if a["id"] == agent_id), None)

    def start_discovery(
        self,
        network: str,
        agent_id: Optional[str] = None,
        scan_type: str = "ping",
        add_devices: bool = False,
    ) -> Dict[str, Any]:
        """
        Avvia discovery di rete via The Dude.
        
        Args:
            network: Rete da scansionare (CIDR, es: 192.168.1.0/24)
            agent_id: ID dell'agente da usare (None = server locale)
            scan_type: Tipo di scan (ping, arp, snmp, all)
            add_devices: Se True, aggiunge automaticamente i dispositivi trovati
        
        Returns:
            Dict con info sulla discovery avviata
        """
        self._ensure_connected()
        
        try:
            # Parametri discovery
            params = {
                "address-range": network,
                "type": scan_type,
            }
            
            if agent_id:
                params["agent"] = agent_id
            
            if add_devices:
                params["add-devices"] = "yes"
            
            # Avvia discovery
            discovery_resource = self._api.get_resource('/dude/discovery')
            result = discovery_resource.add(**params)
            
            logger.info(f"Started discovery on {network} with agent {agent_id or 'local'}")
            
            return {
                "success": True,
                "discovery_id": result,
                "network": network,
                "agent_id": agent_id,
                "scan_type": scan_type,
            }
            
        except Exception as e:
            logger.error(f"Error starting discovery: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    def get_discoveries(self) -> List[Dict[str, Any]]:
        """Ottiene lista discovery attive/completate"""
        self._ensure_connected()
        
        try:
            discovery_resource = self._api.get_resource('/dude/discovery')
            raw_discoveries = discovery_resource.get()
            
            discoveries = []
            for raw in raw_discoveries:
                discovery = {
                    "id": raw.get(".id", ""),
                    "address_range": raw.get("address-range", ""),
                    "status": raw.get("status", "unknown"),
                    "found": raw.get("found", "0"),
                    "added": raw.get("added", "0"),
                    "progress": raw.get("progress", ""),
                    "agent": raw.get("agent", ""),
                    "type": raw.get("type", ""),
                }
                discoveries.append(discovery)
            
            return discoveries
            
        except Exception as e:
            logger.error(f"Error getting discoveries: {e}")
            return []

    def get_discovery_results(self, discovery_id: str) -> List[Dict[str, Any]]:
        """Ottiene risultati di una discovery specifica"""
        self._ensure_connected()
        
        try:
            # I risultati sono nella tabella device con riferimento alla discovery
            device_resource = self._api.get_resource('/dude/device')
            all_devices = device_resource.get()
            
            # Filtra dispositivi trovati dalla discovery
            results = []
            for raw in all_devices:
                if raw.get("discovery") == discovery_id:
                    results.append({
                        "id": raw.get(".id", ""),
                        "name": raw.get("name", ""),
                        "address": raw.get("address", ""),
                        "mac_address": raw.get("mac-address", ""),
                        "type": raw.get("type", ""),
                        "status": raw.get("status", ""),
                    })
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting discovery results: {e}")
            return []

    def stop_discovery(self, discovery_id: str) -> bool:
        """Ferma una discovery in corso"""
        self._ensure_connected()
        
        try:
            discovery_resource = self._api.get_resource('/dude/discovery')
            discovery_resource.remove(id=discovery_id)
            logger.info(f"Stopped discovery {discovery_id}")
            return True
        except Exception as e:
            logger.error(f"Error stopping discovery: {e}")
            return False

    def add_device(
        self,
        name: str,
        address: str,
        device_type: str = "generic",
        agent_id: Optional[str] = None,
        **kwargs
    ) -> Optional[str]:
        """
        Aggiunge un dispositivo a The Dude.
        
        Returns:
            ID del dispositivo creato o None se errore
        """
        self._ensure_connected()
        
        try:
            params = {
                "name": name,
                "address": address,
                "type": device_type,
            }
            
            if agent_id:
                params["agent"] = agent_id
            
            # Aggiungi parametri extra
            params.update(kwargs)
            
            device_resource = self._api.get_resource('/dude/device')
            result = device_resource.add(**params)
            
            logger.info(f"Added device {name} ({address}) to Dude")
            return result
            
        except Exception as e:
            logger.error(f"Error adding device: {e}")
            return None

    # ==========================================
    # AGENT/PROBE MANAGEMENT IN THE DUDE
    # ==========================================

    def add_agent_to_dude(
        self,
        name: str,
        address: str,
        port: int = 8728,
        username: str = "admin",
        password: str = "",
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Verifica se un router è già presente come agent in The Dude.
        Gli agent in The Dude sono router con Dude Agent Package che si connettono
        automaticamente - non possono essere aggiunti via API.
        
        Questa funzione verifica se l'agent esiste già, oppure aggiunge il router
        come device per poterlo usare come punto di monitoraggio.
        
        Returns:
            Dict con success, agent_id, message
        """
        self._ensure_connected()
        
        try:
            # Verifica se l'agent esiste già (connesso automaticamente)
            existing = self.find_agent_by_address(address)
            if existing:
                return {
                    "success": True,
                    "agent_id": existing.get(".id"),
                    "name": existing.get("name"),
                    "message": f"Agent trovato in The Dude: {existing.get('name')}",
                    "existing": True
                }
            
            # L'agent non esiste - verifica se esiste come device
            try:
                device_resource = self._api.get_resource('/dude/device')
                devices = device_resource.get()
                
                for dev in devices:
                    if dev.get("address") == address:
                        return {
                            "success": True,
                            "agent_id": dev.get(".id"),
                            "name": dev.get("name"),
                            "message": f"Device trovato in The Dude: {dev.get('name')} (può essere usato per discovery)",
                            "existing": True,
                            "is_device": True
                        }
            except:
                pass
            
            # Né agent né device trovato - aggiungiamo come device
            try:
                device_resource = self._api.get_resource('/dude/device')
                result = device_resource.add(
                    name=name,
                    address=address,
                    type="RouterOS",
                )
                
                # Trova il device appena creato
                devices = device_resource.get()
                new_device = None
                for dev in devices:
                    if dev.get("address") == address:
                        new_device = dev
                        break
                
                device_id = new_device.get(".id") if new_device else None
                
                logger.info(f"Added {name} ({address}) as device to Dude")
                
                return {
                    "success": True,
                    "agent_id": device_id,
                    "name": name,
                    "address": address,
                    "message": f"Router aggiunto come device in The Dude. Per usarlo come agent remoto, installa Dude Agent Package sul router.",
                    "existing": False,
                    "is_device": True,
                    "note": "Per scansioni remote, usa la funzione 'Scansiona Reti' che si connette direttamente al router."
                }
                
            except Exception as e:
                logger.warning(f"Cannot add as device: {e}")
                return {
                    "success": True,  # Non blocchiamo l'utente
                    "agent_id": None,
                    "name": name,
                    "address": address,
                    "message": "Sonda registrata in DaDude. Per scansioni remote usa la connessione diretta.",
                    "existing": False,
                    "note": "The Dude non permette di aggiungere agent via API. Usa 'Scansiona Reti' per discovery diretta."
                }
            
        except Exception as e:
            logger.error(f"Error in add_agent_to_dude: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore: {e}"
            }

    def find_agent_by_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Trova un agent per indirizzo IP"""
        self._ensure_connected()
        
        try:
            agent_resource = self._api.get_resource('/dude/agent')
            agents = agent_resource.get()
            
            for agent in agents:
                if agent.get("address") == address:
                    return agent
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding agent: {e}")
            return None

    def remove_agent_from_dude(self, agent_id: str) -> Dict[str, Any]:
        """
        Rimuove un agent da The Dude.
        
        Args:
            agent_id: ID dell'agent in The Dude
            
        Returns:
            Dict con success e message
        """
        self._ensure_connected()
        
        try:
            agent_resource = self._api.get_resource('/dude/agent')
            agent_resource.remove(id=agent_id)
            
            logger.info(f"Removed agent {agent_id} from Dude")
            
            return {
                "success": True,
                "message": f"Agent {agent_id} rimosso da The Dude"
            }
            
        except Exception as e:
            logger.error(f"Error removing agent: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore rimozione agent: {e}"
            }

    def test_agent_connection(self, agent_id: str) -> Dict[str, Any]:
        """
        Testa la connessione a un agent in The Dude.
        
        Returns:
            Dict con status e info dell'agent
        """
        self._ensure_connected()
        
        try:
            agent_resource = self._api.get_resource('/dude/agent')
            agents = agent_resource.get()
            
            agent = None
            for a in agents:
                if a.get(".id") == agent_id:
                    agent = a
                    break
            
            if not agent:
                return {
                    "success": False,
                    "message": "Agent non trovato"
                }
            
            status = agent.get("status", "unknown")
            
            return {
                "success": status in ["up", "connected", "ok"],
                "status": status,
                "name": agent.get("name"),
                "address": agent.get("address"),
                "uptime": agent.get("uptime", ""),
                "version": agent.get("version", ""),
                "message": f"Agent {agent.get('name')}: {status}"
            }
            
        except Exception as e:
            logger.error(f"Error testing agent: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore test agent: {e}"
            }

    def start_discovery_with_agent(
        self,
        network: str,
        agent_id: str,
        scan_type: str = "ping",
        add_devices: bool = False,
    ) -> Dict[str, Any]:
        """
        Avvia una discovery usando uno specifico agent.
        
        Args:
            network: Rete da scansionare (es: "192.168.1.0/24")
            agent_id: ID dell'agent da usare per la scansione
            scan_type: Tipo di scansione (ping, arp, snmp, all)
            add_devices: Se aggiungere automaticamente i device trovati
            
        Returns:
            Dict con risultato dell'operazione
        """
        self._ensure_connected()
        
        try:
            params = {
                "address-range": network,
                "agent": agent_id,
            }
            
            # Configura tipo scansione
            if scan_type == "ping":
                params["ping"] = "yes"
            elif scan_type == "arp":
                params["arp"] = "yes"
            elif scan_type == "snmp":
                params["snmp"] = "yes"
            elif scan_type == "all":
                params["ping"] = "yes"
                params["arp"] = "yes"
                params["snmp"] = "yes"
            
            if add_devices:
                params["add-devices"] = "yes"
            
            discovery_resource = self._api.get_resource('/dude/discovery')
            result = discovery_resource.add(**params)
            
            logger.info(f"Started discovery on {network} via agent {agent_id}")
            
            return {
                "success": True,
                "discovery_id": result if isinstance(result, str) else None,
                "network": network,
                "agent_id": agent_id,
                "scan_type": scan_type,
                "message": f"Discovery avviata su {network}"
            }
            
        except Exception as e:
            logger.error(f"Error starting discovery: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore avvio discovery: {e}"
            }


# Singleton instance
_dude_service: Optional[DudeService] = None


def get_dude_service() -> DudeService:
    """Get singleton DudeService instance"""
    global _dude_service
    if _dude_service is None:
        _dude_service = DudeService()
    return _dude_service
