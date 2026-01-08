"""
DaDude - Unified Scanner Service
v3.0.0: Scanner multi-protocollo unificato (SSH, SNMP, WinRM)

Questo servizio integra le funzionalità del unified_infrastructure_scanner
per acquisire dati dettagliati dai dispositivi tramite agent.
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict
from enum import Enum
from loguru import logger


class DeviceType(str, Enum):
    """Tipo di dispositivo"""
    UNKNOWN = "unknown"
    SWITCH = "switch"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    FIREWALL = "firewall"
    LINUX_SERVER = "linux_server"
    WINDOWS_SERVER = "windows_server"
    PROXMOX = "proxmox"
    VMWARE = "vmware"
    SYNOLOGY = "synology"
    QNAP = "qnap"
    WINDOWS_WORKSTATION = "windows_workstation"
    LINUX_WORKSTATION = "linux_workstation"
    PRINTER = "printer"
    UPS = "ups"
    CAMERA = "camera"
    STORAGE = "storage"
    ILO_IDRAC = "ilo_idrac"


class Protocol(str, Enum):
    """Protocollo di comunicazione"""
    SNMP = "snmp"
    SSH = "ssh"
    WINRM = "winrm"
    WMI = "wmi"
    AUTO = "auto"


class ScanStatus(str, Enum):
    """Stato della scansione"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class UnifiedScanRequest:
    """Richiesta scansione unificata"""
    device_id: str
    target_address: str
    customer_id: str
    agent_id: Optional[str] = None
    protocols: List[str] = field(default_factory=lambda: ["auto"])
    credentials: Dict[str, Any] = field(default_factory=dict)  # Backward compat: singola credenziale per tipo
    credentials_list: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)  # Nuovo: lista credenziali per tipo
    timeout: int = 120
    include_software: bool = True
    include_services: bool = True
    include_users: bool = False


@dataclass
class UnifiedScanResult:
    """Risultato scansione unificata"""
    device_id: str
    target: str
    status: str = "pending"
    protocol_used: str = ""
    scan_timestamp: str = ""
    scan_duration_seconds: float = 0
    
    # System Info
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    device_type: str = "unknown"
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    firmware_version: str = ""
    uptime: str = ""
    
    # Hardware
    cpu_model: str = ""
    cpu_cores: int = 0
    cpu_threads: int = 0
    cpu_usage_percent: float = 0
    ram_total_gb: float = 0
    ram_used_gb: float = 0
    ram_usage_percent: float = 0
    
    # Storage
    disk_total_gb: float = 0
    disk_used_gb: float = 0
    disk_free_gb: float = 0
    disks: List[Dict] = field(default_factory=list)
    volumes: List[Dict] = field(default_factory=list)
    raid_arrays: List[Dict] = field(default_factory=list)
    
    # Network
    interfaces: List[Dict] = field(default_factory=list)
    primary_ip: str = ""
    primary_mac: str = ""
    lldp_neighbors: List[Dict] = field(default_factory=list)
    
    # Vendor-specific data
    routing_table: List[Dict] = field(default_factory=list)
    arp_table: List[Dict] = field(default_factory=list)
    dhcp_leases: List[Dict] = field(default_factory=list)
    cdp_neighbors: List[Dict] = field(default_factory=list)
    vlan_info: List[Dict] = field(default_factory=list)
    firewall_rules_count: int = 0
    
    # Services & Software
    services: List[Dict] = field(default_factory=list)
    services_count: int = 0
    software: List[Dict] = field(default_factory=list)
    software_count: int = 0
    shares: List[Dict] = field(default_factory=list)
    shares_count: int = 0
    
    # Users
    users: List[Dict] = field(default_factory=list)
    logged_in_users: List[str] = field(default_factory=list)
    
    # VMs (per Proxmox/VMware)
    vms: List[Dict] = field(default_factory=list)
    hypervisor_type: str = ""
    
    # Security
    antivirus_status: str = ""
    firewall_status: str = ""
    
    # Open ports rilevate
    open_ports: List[Dict] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class UnifiedScannerService:
    """
    Servizio scanner unificato multi-protocollo.
    
    Flusso:
    1. Determina protocolli disponibili in base alle porte aperte
    2. Testa credenziali per ogni protocollo
    3. Esegue scansione con protocolli funzionanti
    4. Unifica risultati in formato standardizzato
    """
    
    def __init__(self):
        self._scan_cache: Dict[str, UnifiedScanResult] = {}
    
    async def scan_device(
        self,
        request: UnifiedScanRequest,
        ws_hub = None,
        agent_service = None
    ) -> UnifiedScanResult:
        """
        Esegue scansione unificata su un dispositivo.
        
        Args:
            request: Parametri scansione
            ws_hub: WebSocket Hub per comunicazione agent
            agent_service: Servizio agent per invio comandi
        
        Returns:
            UnifiedScanResult con tutti i dati raccolti
        """
        start_time = datetime.utcnow()
        result = UnifiedScanResult(
            device_id=request.device_id,
            target=request.target_address,
            scan_timestamp=start_time.isoformat()
        )
        
        logger.info(f"Unified scan starting for {request.target_address}")
        
        try:
            # 0. Recupera device_type e manufacturer dal database per scegliere protocollo corretto
            existing_device_type = None
            existing_manufacturer = None
            try:
                from ..models.database import init_db, get_session
                from ..models.inventory import InventoryDevice
                from ..config import get_settings
                
                settings = get_settings()
                engine = init_db(settings.database_url)
                session = get_session(engine)
                
                device = session.query(InventoryDevice).filter(
                    InventoryDevice.id == request.device_id
                ).first()
                
                if device:
                    existing_device_type = device.device_type
                    existing_manufacturer = device.manufacturer
                    logger.info(f"[UNIFIED] Device {request.device_id}: type={existing_device_type}, manufacturer={existing_manufacturer}")
                
                session.close()
            except Exception as e:
                logger.warning(f"Could not retrieve device info: {e}")
            
            # 1. Determina protocolli da usare BASANDOSI SUL TIPO DI DEVICE E MANUFACTURER
            protocols_to_try = await self._determine_protocols(
                request.target_address,
                request.protocols,
                request.credentials,
                device_type=existing_device_type,
                manufacturer=existing_manufacturer
            )
            
            if not protocols_to_try:
                result.status = "failed"
                result.errors.append("No protocols available for scanning")
                return result
            
            logger.debug(f"Protocols to try: {protocols_to_try}")
            
            # 2. Esegui scansione con agent se disponibile
            if agent_service and request.agent_id:
                await self._scan_via_agent(
                    result, request, agent_service, protocols_to_try
                )
            else:
                # Fallback: scansione diretta (se implementata)
                result.warnings.append("No agent available, using fallback methods")
                await self._scan_direct(result, request, protocols_to_try)
            
            # 3. Determina tipo dispositivo
            if not result.device_type or result.device_type == "unknown":
                result.device_type = self._determine_device_type(result)
            
            # 4. Calcola durata
            end_time = datetime.utcnow()
            result.scan_duration_seconds = (end_time - start_time).total_seconds()
            
            # 5. Imposta status
            if result.errors and not result.hostname:
                result.status = "failed"
            elif result.errors or result.warnings:
                result.status = "partial"
            else:
                result.status = "success"
            
            logger.info(f"Unified scan completed for {request.target_address}: {result.status}")
            
        except Exception as e:
            logger.error(f"Unified scan error for {request.target_address}: {e}")
            result.status = "failed"
            result.errors.append(str(e))
        
        # Cache result
        self._scan_cache[request.device_id] = result
        
        return result
    
    async def _determine_protocols(
        self,
        target: str,
        requested: List[str],
        credentials: Dict,
        device_type: str = None,
        manufacturer: str = None
    ) -> List[str]:
        """
        Determina quali protocolli usare basandosi sul TIPO DI DEVICE.
        
        Regole:
        - Linux → SSH, eventualmente SNMP
        - Proxmox → SSH o API
        - UniFi → prima SNMP, poi SSH
        - MikroTik → SSH, SNMP o API
        - Synology/QNAP → SSH, poi SNMP
        - Windows → WMI o WinRM
        - Altri device → prima SNMP poi SSH
        """
        available = []
        device_type_lower = (device_type or "").lower()
        manufacturer_lower = (manufacturer or "").lower()
        
        # Determina protocollo ottimale per tipo device
        # IMPORTANTE: I controlli specifici (manufacturer) devono venire PRIMA di quelli generici (device_type)
        if "auto" in requested or not requested:
            
            # === CONTROLLI BASATI SU MANUFACTURER (priorità alta) ===
            
            # SYNOLOGY / QNAP (NAS) → SSH, poi SNMP
            # Deve venire prima di linux_server perché spesso hanno device_type=linux_server
            if manufacturer_lower in ["synology", "qnap", "asustor", "terramaster"]:
                available = ["ssh", "snmp"]
                logger.info(f"[PROTOCOL] Manufacturer '{manufacturer}' (NAS) → SSH then SNMP")
            
            # UNIFI → prima SNMP, poi SSH
            elif "ubiquiti" in manufacturer_lower or "unifi" in manufacturer_lower or "ubnt" in manufacturer_lower:
                available = ["snmp", "ssh"]
                logger.info(f"[PROTOCOL] Manufacturer '{manufacturer}' (UniFi) → SNMP then SSH")
            
            # MIKROTIK → SSH, SNMP
            elif "mikrotik" in manufacturer_lower:
                available = ["ssh", "snmp"]
                logger.info(f"[PROTOCOL] Manufacturer '{manufacturer}' (MikroTik) → SSH, SNMP")
            
            # === CONTROLLI BASATI SU DEVICE_TYPE ===
            
            # PROXMOX → SSH (API fallback interno via proxmox_collector)
            elif device_type_lower in ["proxmox", "hypervisor"]:
                available = ["ssh"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' → SSH (API fallback interno)")
            
            # NAS / STORAGE → SSH, poi SNMP
            elif device_type_lower in ["synology", "qnap", "nas", "storage"]:
                available = ["ssh", "snmp"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' (NAS) → SSH then SNMP")
            
            # MIKROTIK / ROUTER → SSH, SNMP
            elif device_type_lower in ["mikrotik", "router"]:
                available = ["ssh", "snmp"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' (Router) → SSH, SNMP")
            
            # AP / ACCESS POINT → SNMP, poi SSH
            elif device_type_lower in ["ap", "access_point", "wireless"]:
                available = ["snmp", "ssh"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' (AP) → SNMP then SSH")
            
            # SWITCH / FIREWALL / NETWORK → prima SNMP poi SSH
            elif device_type_lower in ["switch", "firewall", "network"]:
                available = ["snmp", "ssh"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' → SNMP then SSH")
            
            # WINDOWS → WMI o WinRM
            elif device_type_lower in ["windows_server", "windows_workstation", "windows"]:
                available = ["winrm", "wmi"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' → WinRM/WMI")
            
            # LINUX → SSH, poi SNMP (controllo generico dopo i NAS)
            elif device_type_lower in ["linux_server", "linux"]:
                available = ["ssh", "snmp"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' → SSH then SNMP")
            
            # UNKNOWN / ALTRI → prima SNMP poi SSH (più safe)
            else:
                available = ["snmp", "ssh"]
                logger.info(f"[PROTOCOL] Device type '{device_type}' unknown → SNMP then SSH")
        else:
            # Usa i protocolli esplicitamente richiesti
            available = [p for p in requested if p != "auto"]
        
        return available
    
    async def _scan_via_agent(
        self,
        result: UnifiedScanResult,
        request: UnifiedScanRequest,
        agent_service,
        protocols: List[str]
    ):
        """
        Esegue scansione tramite agent.
        
        Prova TUTTE le credenziali disponibili per ogni protocollo fino a trovare
        quella che funziona.
        """
        from ..services.customer_service import get_customer_service
        
        logger.info(f"[UNIFIED_SCAN] Starting agent scan for {request.target_address} with protocols {protocols}")
        
        try:
            # Recupera info agent dal customer_service CON PASSWORD/TOKEN DECRIPTATI
            customer_service = get_customer_service()
            agent_obj = customer_service.get_agent(request.agent_id, include_password=True)
            if not agent_obj:
                logger.error(f"[UNIFIED_SCAN] Agent {request.agent_id} not found in customer_service")
                result.errors.append(f"Agent {request.agent_id} not found")
                return
            
            # Converti AgentAssignment in dict per agent_service
            agent_info = {
                "id": agent_obj.id,
                "name": agent_obj.name,
                "agent_type": agent_obj.agent_type,
                "address": agent_obj.address,
                "dude_agent_id": getattr(agent_obj, 'dude_agent_id', None),
                "agent_api_port": getattr(agent_obj, 'agent_api_port', 8080),
                "agent_url": getattr(agent_obj, 'agent_url', None),
                "agent_token": getattr(agent_obj, 'agent_token', None),
            }
            
            logger.info(f"[UNIFIED_SCAN] Agent info: id={agent_info['id']}, name={agent_info['name']}, "
                       f"type={agent_info['agent_type']}, address={agent_info['address']}")
            
            # Usa credentials_list se disponibile, altrimenti fallback a credentials singolo
            creds_list = request.credentials_list or {}
            creds_single = request.credentials or {}
            
            # Costruisci liste credenziali da provare
            ssh_creds_list = creds_list.get("ssh", [])
            wmi_creds_list = creds_list.get("wmi", [])
            snmp_creds_list = creds_list.get("snmp", [])
            
            # Fallback: se non ci sono liste, usa credenziale singola
            if not ssh_creds_list and creds_single.get("ssh"):
                ssh_creds_list = [creds_single["ssh"]]
            if not wmi_creds_list and creds_single.get("wmi"):
                wmi_creds_list = [creds_single["wmi"]]
            if not snmp_creds_list and creds_single.get("snmp"):
                snmp_creds_list = [creds_single["snmp"]]
            
            # Fallback SNMP public
            if not snmp_creds_list:
                snmp_creds_list = [{"community": "public", "version": "2c", "port": 161}]
            
            logger.info(f"[UNIFIED_SCAN] Credentials to try - SSH: {len(ssh_creds_list)}, "
                       f"WMI: {len(wmi_creds_list)}, SNMP: {len(snmp_creds_list)}")
            
            # Debug: mostra dettagli credenziali SNMP ricevute
            for idx, snmp_c in enumerate(snmp_creds_list):
                logger.info(f"[UNIFIED_SCAN] SNMP cred {idx+1}: community={snmp_c.get('community')}, name={snmp_c.get('credential_name')}")
            
            # Prova le credenziali in sequenza
            agent_result = None
            successful_cred = None
            all_errors = []
            
            # Determina quali protocolli provare
            protos_to_try = []
            if "auto" in protocols or "ssh" in protocols:
                protos_to_try.append(("ssh", ssh_creds_list))
            if "auto" in protocols or "snmp" in protocols:
                protos_to_try.append(("snmp", snmp_creds_list))
            if "auto" in protocols or "wmi" in protocols or "winrm" in protocols:
                protos_to_try.append(("wmi", wmi_creds_list))
            
            for proto_type, creds_to_try in protos_to_try:
                if agent_result and agent_result.success:
                    break  # Già trovato credenziale funzionante
                
                for idx, cred in enumerate(creds_to_try):
                    cred_name = cred.get("credential_name", f"{proto_type}-{idx+1}")
                    
                    if proto_type == "ssh":
                        logger.info(f"[UNIFIED_SCAN] Trying SSH credential {idx+1}/{len(creds_to_try)}: "
                                   f"{cred.get('username')} ({cred_name})")
                        
                        agent_result = await agent_service.probe_unified(
                            agent_info,
                            request.target_address,
                            ["ssh"],
                            ssh_user=cred.get("username"),
                            ssh_password=cred.get("password"),
                            ssh_port=cred.get("port", 22),
                            timeout=min(request.timeout, 30),  # Timeout ridotto per singolo tentativo
                        )
                        
                    elif proto_type == "snmp":
                        logger.info(f"[UNIFIED_SCAN] Trying SNMP credential {idx+1}/{len(creds_to_try)}: "
                                   f"{cred.get('community')} ({cred_name})")
                        
                        agent_result = await agent_service.probe_unified(
                            agent_info,
                            request.target_address,
                            ["snmp"],
                            snmp_community=cred.get("community", "public"),
                            snmp_port=cred.get("port", 161),
                            snmp_version=int(str(cred.get("version", "2c")).replace("c", "")),
                            timeout=min(request.timeout, 20),
                        )
                        
                    elif proto_type == "wmi":
                        logger.info(f"[UNIFIED_SCAN] Trying WMI credential {idx+1}/{len(creds_to_try)}: "
                                   f"{cred.get('username')} ({cred_name})")
                        
                        agent_result = await agent_service.probe_unified(
                            agent_info,
                            request.target_address,
                            ["winrm"],
                            winrm_user=cred.get("username"),
                            winrm_password=cred.get("password"),
                            winrm_domain=cred.get("domain", ""),
                            winrm_port=cred.get("port", 5985),
                            timeout=min(request.timeout, 30),
                        )
                    
                    if agent_result and agent_result.success:
                        successful_cred = {"type": proto_type, "name": cred_name, "username": cred.get("username") or cred.get("community")}
                        logger.info(f"[UNIFIED_SCAN] ✓ Credential {cred_name} ({proto_type}) WORKED for {request.target_address}")
                        break
                    else:
                        error_msg = agent_result.error if agent_result else "No response"
                        all_errors.append(f"{proto_type}/{cred_name}: {error_msg}")
                        logger.debug(f"[UNIFIED_SCAN] ✗ Credential {cred_name} ({proto_type}) failed: {error_msg}")
            
            # Log risultato
            if agent_result and agent_result.success:
                logger.info(f"[UNIFIED_SCAN] Agent result received: success=True, "
                           f"credential_used={successful_cred}")
            else:
                logger.warning(f"[UNIFIED_SCAN] All credentials failed for {request.target_address}")
                for err in all_errors[-5:]:  # Log ultimi 5 errori
                    logger.debug(f"[UNIFIED_SCAN] - {err}")
            
            if agent_result and agent_result.success:
                # agent_result è un AgentProbeResult, estrai data
                data_keys = list(agent_result.data.keys()) if isinstance(agent_result.data, dict) else []
                logger.info(f"[UNIFIED_SCAN] Agent returned {len(data_keys)} fields: {sorted(data_keys)[:15]}")
                
                # DEBUG: Log dettagliato storage data
                volumes = agent_result.data.get("volumes", [])
                disks = agent_result.data.get("disks", [])
                raid_arrays = agent_result.data.get("raid_arrays", [])
                shares = agent_result.data.get("shares", [])
                logger.info(f"[UNIFIED_SCAN] Storage data from agent: volumes={len(volumes)}, disks={len(disks)}, raid_arrays={len(raid_arrays)}, shares={len(shares)}")
                
                # DEBUG: Log dettagliato degli interface e LLDP
                ni = agent_result.data.get("network_interfaces", [])
                lldp = agent_result.data.get("lldp_neighbors", [])
                logger.info(f"[UNIFIED_SCAN] network_interfaces count: {len(ni)}")
                if ni:
                    logger.info(f"[UNIFIED_SCAN] First interface: {ni[0]}")
                logger.info(f"[UNIFIED_SCAN] lldp_neighbors count: {len(lldp)}")
                if lldp:
                    logger.info(f"[UNIFIED_SCAN] First LLDP: {lldp[0]}")
                
                self._merge_agent_result(result, agent_result.data or {}, protocols)
            elif agent_result:
                logger.warning(f"[UNIFIED_SCAN] Agent probe failed: {agent_result.error}")
                result.errors.append(agent_result.error or "Agent returned no data")
            else:
                logger.warning(f"[UNIFIED_SCAN] Agent returned None")
                result.errors.append("Agent returned no data")
                
        except Exception as e:
            logger.error(f"[UNIFIED_SCAN] Agent scan error: {e}", exc_info=True)
            result.errors.append(f"Agent error: {str(e)}")
    
    async def _scan_direct(
        self,
        result: UnifiedScanResult,
        request: UnifiedScanRequest,
        protocols: List[str]
    ):
        """Scansione diretta (fallback senza agent)"""
        # Per ora solo placeholder - la scansione reale avviene tramite agent
        result.warnings.append("Direct scan not implemented, use agent")
    
    def _merge_agent_result(
        self,
        result: UnifiedScanResult,
        agent_data: Dict,
        protocols: List[str]
    ):
        """Merge risultati dall'agent nel risultato finale"""
        if not agent_data:
            return
        
        # Log per debug
        logger.info(f"[MERGE_AGENT] agent_data keys: {sorted(list(agent_data.keys()))[:20]}")
        logger.info(f"[MERGE_AGENT] volumes={len(agent_data.get('volumes', []))}, disks={len(agent_data.get('disks', []))}, raid_arrays={len(agent_data.get('raid_arrays', []))}, shares={len(agent_data.get('shares', []))}")
        
        # Protocollo usato
        result.protocol_used = agent_data.get("protocol_used", ",".join(protocols))
        
        # System info
        if agent_data.get("system_info"):
            si = agent_data["system_info"]
            result.hostname = si.get("hostname", "")
            result.os_name = si.get("os_name", "")
            result.os_version = si.get("os_version", "")
            result.manufacturer = si.get("manufacturer", "")
            result.model = si.get("model", "")
            result.serial_number = si.get("serial_number", "")
            result.firmware_version = si.get("firmware_version", "")
            result.uptime = si.get("uptime", "")
            result.device_type = si.get("device_type", "unknown")
        
        # CPU
        if agent_data.get("cpu"):
            cpu = agent_data["cpu"]
            result.cpu_model = cpu.get("model", "")
            result.cpu_cores = cpu.get("cores_physical", 0)
            result.cpu_threads = cpu.get("cores_logical", 0)
            result.cpu_usage_percent = cpu.get("load_percent", 0)
        
        # Memory
        if agent_data.get("memory"):
            mem = agent_data["memory"]
            result.ram_total_gb = mem.get("total_bytes", 0) / (1024**3)
            result.ram_used_gb = mem.get("used_bytes", 0) / (1024**3)
            if mem.get("total_bytes"):
                result.ram_usage_percent = (mem.get("used_bytes", 0) / mem["total_bytes"]) * 100
        
        # Disks & Volumes
        result.disks = agent_data.get("disks", [])
        result.volumes = agent_data.get("volumes", [])
        result.raid_arrays = agent_data.get("raid_arrays", [])
        
        # Log dopo merge
        logger.info(f"[MERGE_AGENT] After merge: volumes={len(result.volumes)}, disks={len(result.disks)}, raid_arrays={len(result.raid_arrays)}, shares={len(result.shares)}")
        
        # Calculate totals
        for vol in result.volumes:
            result.disk_total_gb += vol.get("total_bytes", 0) / (1024**3)
            result.disk_used_gb += vol.get("used_bytes", 0) / (1024**3)
        result.disk_free_gb = result.disk_total_gb - result.disk_used_gb
        
        # Network - prova network_interfaces, poi interfaces (usato da alcuni probe)
        result.interfaces = agent_data.get("network_interfaces", []) or agent_data.get("interfaces", [])
        if result.interfaces:
            for iface in result.interfaces:
                if iface.get("ipv4_addresses"):
                    result.primary_ip = iface["ipv4_addresses"][0]
                if iface.get("mac_address"):
                    result.primary_mac = iface["mac_address"]
                if result.primary_ip:
                    break
        
        result.lldp_neighbors = agent_data.get("lldp_neighbors", [])
        
        # Vendor-specific data
        result.routing_table = agent_data.get("routing_table", [])
        result.arp_table = agent_data.get("arp_table", [])
        result.dhcp_leases = agent_data.get("dhcp_leases", [])
        result.cdp_neighbors = agent_data.get("cdp_neighbors", [])
        result.vlan_info = agent_data.get("vlan_info", [])
        result.firewall_rules_count = agent_data.get("firewall_rules_count", 0)
        
        # Services & Software
        result.services = agent_data.get("services", [])
        result.services_count = len(result.services)
        result.software = agent_data.get("software", [])
        result.software_count = len(result.software)
        
        # Shares (se presente)
        if "shares" in agent_data:
            result.shares = agent_data.get("shares", [])
            result.shares_count = len(result.shares) if result.shares else 0
        
        # Users
        result.users = agent_data.get("users", [])
        result.logged_in_users = agent_data.get("logged_in_users", [])
        
        # VMs
        result.vms = agent_data.get("vms", [])
        result.hypervisor_type = agent_data.get("hypervisor_type", "")
        
        # Security
        result.antivirus_status = agent_data.get("antivirus_status", "")
        result.firewall_status = agent_data.get("firewall_status", "")
        
        # Ports
        result.open_ports = agent_data.get("open_ports", [])
        
        # Errors/warnings
        if agent_data.get("errors"):
            result.errors.extend(agent_data["errors"])
        if agent_data.get("warnings"):
            result.warnings.extend(agent_data["warnings"])
    
    def _determine_device_type(self, result: UnifiedScanResult) -> str:
        """Determina tipo dispositivo in base ai dati raccolti"""
        os_name = result.os_name.lower() if result.os_name else ""
        hostname = result.hostname.lower() if result.hostname else ""
        
        # Proxmox
        if "proxmox" in os_name or result.hypervisor_type == "pve":
            return DeviceType.PROXMOX.value
        
        # VMware
        if "vmware" in os_name or "esxi" in os_name:
            return DeviceType.VMWARE.value
        
        # Windows
        if "windows" in os_name:
            if "server" in os_name:
                return DeviceType.WINDOWS_SERVER.value
            return DeviceType.WINDOWS_WORKSTATION.value
        
        # Linux
        if any(x in os_name for x in ["linux", "ubuntu", "debian", "centos", "rhel", "fedora"]):
            return DeviceType.LINUX_SERVER.value
        
        # Synology
        if "synology" in os_name or "dsm" in os_name:
            return DeviceType.SYNOLOGY.value
        
        # QNAP
        if "qnap" in os_name or "qts" in os_name:
            return DeviceType.QNAP.value
        
        # Network devices
        manufacturer = (result.manufacturer or "").lower()
        if any(x in manufacturer for x in ["cisco", "juniper", "arista", "dell"]):
            if "switch" in hostname:
                return DeviceType.SWITCH.value
            if "router" in hostname:
                return DeviceType.ROUTER.value
            return DeviceType.SWITCH.value  # Default network
        
        # Ubiquiti
        if "ubiquiti" in manufacturer or "ubnt" in manufacturer:
            return DeviceType.ACCESS_POINT.value
        
        # Fortinet
        if "fortinet" in manufacturer or "fortigate" in manufacturer:
            return DeviceType.FIREWALL.value
        
        # iLO/iDRAC
        if any(x in hostname for x in ["ilo", "idrac", "ipmi"]):
            return DeviceType.ILO_IDRAC.value
        
        return DeviceType.UNKNOWN.value
    
    def get_cached_result(self, device_id: str) -> Optional[UnifiedScanResult]:
        """Ottiene risultato dalla cache"""
        return self._scan_cache.get(device_id)
    
    def clear_cache(self, device_id: str = None):
        """Pulisce cache"""
        if device_id:
            self._scan_cache.pop(device_id, None)
        else:
            self._scan_cache.clear()


# Singleton
_unified_scanner: Optional[UnifiedScannerService] = None


def get_unified_scanner_service() -> UnifiedScannerService:
    """Ottiene istanza singleton"""
    global _unified_scanner
    if _unified_scanner is None:
        _unified_scanner = UnifiedScannerService()
    return _unified_scanner
