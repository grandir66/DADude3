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
    identified_by: str = ""  # Metodo di identificazione (ssh, snmp, wmi, multiplo)
    credential_used: str = ""  # Nome credenziale usata
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
    
    # VM Detection (se questo device è una VM)
    vm_type: str = ""  # "qemu", "vmware", "hyperv", "virtualbox", etc.
    is_virtual_machine: bool = False
    
    # Security
    antivirus_status: str = ""
    firewall_status: str = ""
    
    # Open ports rilevate
    open_ports: List[Dict] = field(default_factory=list)
    
    # Custom fields (per dati aggiuntivi Linux/Windows/etc)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    # === Linux-specific fields ===
    # Distro info
    kernel_version: str = ""
    distro_name: str = ""
    distro_id: str = ""
    distro_codename: str = ""
    architecture: str = ""
    
    # Package management
    package_manager: str = ""  # apt, yum, dnf, pacman
    packages_installed: int = 0
    
    # System
    init_system: str = ""  # systemd, sysvinit
    selinux_status: str = ""
    apparmor_status: str = ""
    timezone: str = ""
    locale: str = ""
    boot_time: str = ""
    last_reboot: str = ""
    load_average: str = ""
    
    # Docker/Container
    docker_installed: bool = False
    docker_version: str = ""
    containers_running: int = 0
    containers_total: int = 0
    
    # Network config
    default_gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    hostname_fqdn: str = ""
    
    # Storage details
    lvm_volumes: List[Dict] = field(default_factory=list)
    volume_groups: List[Dict] = field(default_factory=list)
    partitions: List[Dict] = field(default_factory=list)
    fstab_entries: List[Dict] = field(default_factory=list)
    swap_info: List[Dict] = field(default_factory=list)
    
    # Firewall
    firewall_type: str = ""  # ufw, iptables, firewalld
    firewall_enabled: bool = False
    firewall_rules: List[str] = field(default_factory=list)
    
    # Cron jobs
    cron_jobs: List[Dict] = field(default_factory=list)
    
    # Running processes (top by CPU/RAM)
    running_processes: List[Dict] = field(default_factory=list)
    
    # Listening ports
    listening_ports: List[Dict] = field(default_factory=list)
    
    # Installed databases
    databases: List[Dict] = field(default_factory=list)
    
    # Web servers
    web_servers: List[Dict] = field(default_factory=list)
    
    # Kernel modules
    kernel_modules: List[str] = field(default_factory=list)
    
    # NTP servers
    ntp_servers: List[str] = field(default_factory=list)
    
    # Windows-specific (already partially present)
    windows_details: Dict[str, Any] = field(default_factory=dict)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Credential tests tracking
    credential_tests: List[Dict[str, Any]] = field(default_factory=list)  # Lista test credenziali con risultati
    
    # Agent connection error
    agent_error: Optional[str] = None  # Errore di connessione agent (es. "Agent non raggiungibile")
    
    # Scan tracking
    scan_id: Optional[str] = None  # ID scansione per tracciamento stato
    
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
        self._active_scans: Dict[str, Dict[str, Any]] = {}  # scan_id -> {status, protocol, credential, progress}
    
    def get_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Ottiene lo stato corrente di una scansione"""
        return self._active_scans.get(scan_id)
    
    def _update_scan_status(self, scan_id: str, **kwargs):
        """Aggiorna lo stato di una scansione"""
        if scan_id in self._active_scans:
            self._active_scans[scan_id].update(kwargs)
            logger.debug(f"[SCAN_STATUS] {scan_id}: {kwargs}")
    
    async def scan_device(
        self,
        request: UnifiedScanRequest,
        ws_hub = None,
        agent_service = None,
        scan_id: Optional[str] = None
    ) -> UnifiedScanResult:
        """
        Esegue scansione unificata su un dispositivo.
        
        Args:
            request: Parametri scansione
            ws_hub: WebSocket Hub per comunicazione agent
            agent_service: Servizio agent per invio comandi
            scan_id: ID scansione per tracciamento stato (generato se None)
        
        Returns:
            UnifiedScanResult con tutti i dati raccolti
        """
        # Genera scan_id se non fornito
        if not scan_id:
            import uuid
            scan_id = str(uuid.uuid4())
        
        # INIZIALIZZA STATO IMMEDIATAMENTE - prima di qualsiasi operazione
        # Questo permette al polling di vedere lo stato anche se la scansione è già iniziata
        self._active_scans[scan_id] = {
            "scan_id": scan_id,
            "device_id": request.device_id,
            "target": request.target_address,
            "status": "starting",
            "protocol": None,
            "credential": None,
            "progress": 0,
            "message": "Inizializzazione scansione..."
        }
        
        start_time = datetime.utcnow()
        result = UnifiedScanResult(
            device_id=request.device_id,
            target=request.target_address,
            scan_timestamp=start_time.isoformat()
        )
        
        logger.info(f"Unified scan starting for {request.target_address} (scan_id: {scan_id})")
        
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
                    logger.debug(f"[UNIFIED] Device {request.device_id}: type={existing_device_type}, manufacturer={existing_manufacturer}")
                
                session.close()
            except Exception as e:
                logger.warning(f"Could not retrieve device info: {e}")
            
            # 1. Determina protocolli da usare BASANDOSI SUL TIPO DI DEVICE E MANUFACTURER
            # Combina credentials e credentials_list per il check
            combined_creds = dict(request.credentials or {})
            if request.credentials_list:
                for cred_type, cred_list in request.credentials_list.items():
                    if cred_list and len(cred_list) > 0:
                        combined_creds[cred_type] = cred_list[0]  # Prima credenziale di ogni tipo
            
            protocols_to_try = await self._determine_protocols(
                request.target_address,
                request.protocols,
                combined_creds,
                device_type=existing_device_type,
                manufacturer=existing_manufacturer
            )
            
            if not protocols_to_try:
                result.status = "failed"
                result.errors.append("No protocols available for scanning")
                return result
            
            logger.debug(f"Protocols to try: {protocols_to_try}")
            
            self._update_scan_status(scan_id, status="running", message=f"Scansione in corso: {len(protocols_to_try)} protocollo(i) da testare")
            
            # 2. Esegui scansione con agent se disponibile
            if agent_service and request.agent_id:
                await self._scan_via_agent(
                    result, request, agent_service, protocols_to_try, scan_id=scan_id
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
                self._update_scan_status(scan_id, status="failed", message="Scansione fallita", progress=100)
            elif result.errors or result.warnings:
                result.status = "partial"
                self._update_scan_status(scan_id, status="completed", message="Scansione completata (parziale)", progress=100)
            else:
                result.status = "success"
                self._update_scan_status(scan_id, status="completed", message="Scansione completata", progress=100)
            
            # Salva scan_id nel risultato per riferimento frontend
            result.scan_id = scan_id
            
            # Rimuovi stato dopo 5 minuti (cleanup automatico)
            import asyncio
            async def cleanup_scan_status():
                await asyncio.sleep(300)  # 5 minuti
                if scan_id in self._active_scans:
                    del self._active_scans[scan_id]
            asyncio.create_task(cleanup_scan_status())
            
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
                logger.debug(f"[PROTOCOL] Manufacturer '{manufacturer}' (NAS) → SSH then SNMP")
            
            # UNIFI → prima SNMP, poi SSH
            elif "ubiquiti" in manufacturer_lower or "unifi" in manufacturer_lower or "ubnt" in manufacturer_lower:
                available = ["snmp", "ssh"]
                logger.debug(f"[PROTOCOL] Manufacturer '{manufacturer}' (UniFi) → SNMP then SSH")
            
            # MIKROTIK → SSH, SNMP
            elif "mikrotik" in manufacturer_lower:
                available = ["ssh", "snmp"]
                logger.debug(f"[PROTOCOL] Manufacturer '{manufacturer}' (MikroTik) → SSH, SNMP")
            
            # === CONTROLLI BASATI SU DEVICE_TYPE ===
            
            # PROXMOX → SSH (API fallback interno via proxmox_collector)
            elif device_type_lower in ["proxmox", "hypervisor"]:
                available = ["ssh"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' → SSH (API fallback interno)")
            
            # NAS / STORAGE → SSH, poi SNMP
            elif device_type_lower in ["synology", "qnap", "nas", "storage"]:
                available = ["ssh", "snmp"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' (NAS) → SSH then SNMP")
            
            # MIKROTIK / ROUTER → SSH, SNMP
            elif device_type_lower in ["mikrotik", "router"]:
                available = ["ssh", "snmp"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' (Router) → SSH, SNMP")
            
            # AP / ACCESS POINT → SNMP, poi SSH
            elif device_type_lower in ["ap", "access_point", "wireless"]:
                available = ["snmp", "ssh"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' (AP) → SNMP then SSH")
            
            # SWITCH / FIREWALL / NETWORK → prima SNMP poi SSH
            elif device_type_lower in ["switch", "firewall", "network"]:
                available = ["snmp", "ssh"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' → SNMP then SSH")
            
            # WINDOWS → WMI o WinRM
            elif device_type_lower in ["windows_server", "windows_workstation", "windows"]:
                available = ["winrm", "wmi"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' → WinRM/WMI")
            
            # LINUX → SSH, poi SNMP (controllo generico dopo i NAS)
            elif device_type_lower in ["linux_server", "linux"]:
                available = ["ssh", "snmp"]
                logger.debug(f"[PROTOCOL] Device type '{device_type}' → SSH then SNMP")
            
            # UNKNOWN / ALTRI → determina in base alle credenziali disponibili
            else:
                # Se abbiamo credenziali WMI/WinRM, proviamo WinRM per Windows
                if credentials.get("wmi") or credentials.get("winrm"):
                    available = ["snmp", "winrm", "ssh"]
                    logger.debug(f"[PROTOCOL] Device type '{device_type}' unknown, WMI creds available → SNMP, WinRM, SSH")
                else:
                    available = ["snmp", "ssh"]
                    logger.debug(f"[PROTOCOL] Device type '{device_type}' unknown → SNMP then SSH")
        else:
            # Usa i protocolli esplicitamente richiesti
            available = [p for p in requested if p != "auto"]
        
        return available
    
    async def _scan_via_agent(
        self,
        result: UnifiedScanResult,
        request: UnifiedScanRequest,
        agent_service,
        protocols: List[str],
        scan_id: Optional[str] = None
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
                # Assicura che credential_tests sia sempre inizializzato
                if not hasattr(result, 'credential_tests') or result.credential_tests is None:
                    result.credential_tests = []
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
            
            # VERIFICA CONNESSIONE AGENT PRIMA DI TESTARE CREDENZIALI
            # Se l'agent non è connesso, non ha senso testare le credenziali
            from ..services.websocket_hub import get_websocket_hub
            hub = get_websocket_hub()
            
            # Verifica se l'agent è connesso via WebSocket
            dude_agent_id = agent_info.get("dude_agent_id")
            agent_name = agent_info.get("name", "")
            agent_connected = False
            
            if dude_agent_id:
                # Prova con dude_agent_id (priorità massima)
                agent_connected = await hub.is_connected(dude_agent_id)
                if agent_connected:
                    logger.info(f"[UNIFIED_SCAN] ✓ Agent '{agent_name}' (dude_id={dude_agent_id}) is connected via WebSocket")
                else:
                    logger.warning(f"[UNIFIED_SCAN] ✗ Agent '{agent_name}' (dude_id={dude_agent_id}) is NOT connected via WebSocket")
            
            # Se non connesso via WebSocket, verifica se c'è un fallback HTTP disponibile
            if not agent_connected:
                agent_address = agent_info.get("address")
                agent_api_port = agent_info.get("agent_api_port", 8080)
                agent_url = agent_info.get("agent_url") or (f"http://{agent_address}:{agent_api_port}" if agent_address else None)
                
                if agent_url:
                    logger.info(f"[UNIFIED_SCAN] Agent not connected via WebSocket, will try HTTP fallback to {agent_url}")
                    # HTTP fallback disponibile - procediamo con i test credenziali
                    # L'errore verrà catturato durante i test se anche HTTP fallisce
                else:
                    # Nessun metodo di connessione disponibile
                    error_msg = f"Agent '{agent_name}' non raggiungibile: connessione WebSocket chiusa e nessun endpoint HTTP configurato"
                    logger.error(f"[UNIFIED_SCAN] {error_msg}")
                    result.agent_error = error_msg
                    result.status = "failed"
                    result.errors.append(error_msg)
                    result.credential_tests = []  # NON popolare credential_tests con errori di connessione
                    return
            
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
                snmp_creds_list = [{"community": "public", "version": "2c", "port": 161, "credential_id": None, "credential_name": "public (fallback)"}]
            
            logger.info(f"[UNIFIED_SCAN] Credentials to try - SSH: {len(ssh_creds_list)}, "
                       f"WMI: {len(wmi_creds_list)}, SNMP: {len(snmp_creds_list)}")
            
            # Prova le credenziali in sequenza rispettando l'ordine dei protocolli
            # L'ordine è già determinato da _determine_protocols in base al tipo di device
            agent_result = None
            successful_cred_id = None
            successful_cred_name = None
            successful_proto = None
            all_errors = []
            tested_credentials = []
            
            # Log iniziale per debug
            logger.info(f"[UNIFIED_SCAN] Starting credential tests for {request.target_address} with protocols: {protocols}")
            
            # Mappa protocolli alle liste di credenziali
            protocol_creds_map = {
                "ssh": ssh_creds_list,
                "snmp": snmp_creds_list,
                "wmi": wmi_creds_list,
                "winrm": wmi_creds_list,  # WinRM usa credenziali WMI
            }
            
            # Risultati per ogni protocollo testato
            # Testa TUTTI i protocolli per trovare quello con più dati
            successful_results = []  # Lista di (proto, cred_id, cred_name, result, data_count)
            
            # Itera attraverso i protocolli nell'ordine determinato
            total_protocols = len([p for p in protocols if p != "auto"])
            protocol_idx = 0
            for proto_type in protocols:
                if proto_type == "auto":
                    continue  # Skip "auto", già espanso in lista protocolli
                
                protocol_idx += 1
                protocol_progress = int((protocol_idx - 1) / total_protocols * 100) if total_protocols > 0 else 0
                
                # Ottieni lista credenziali per questo protocollo
                creds_to_try = protocol_creds_map.get(proto_type, [])
                if not creds_to_try:
                    logger.info(f"[CRED_TEST] No credentials available for protocol {proto_type}, skipping")
                    continue
                
                logger.info(f"[CRED_TEST] Testing {len(creds_to_try)} {proto_type.upper()} credential(s) for {request.target_address}")
                
                # Aggiorna stato: nuovo protocollo
                if scan_id:
                    self._update_scan_status(
                        scan_id,
                        protocol=proto_type.upper(),
                        credential=None,
                        progress=protocol_progress,
                        message=f"Testando protocollo {proto_type.upper()} ({protocol_idx}/{total_protocols})..."
                    )
                
                # Prova ogni credenziale per questo protocollo
                total_creds = len(creds_to_try)
                for idx, cred in enumerate(creds_to_try):
                    cred_id = cred.get("credential_id")
                    cred_name = cred.get("credential_name", f"{proto_type}-{idx+1}")
                    
                    # Aggiorna stato: nuova credenziale
                    if scan_id:
                        cred_display = cred_name
                        if proto_type == "ssh":
                            cred_display = f"{cred.get('username', 'N/A')} ({cred_name})"
                        elif proto_type == "snmp":
                            cred_display = f"{cred.get('community', 'N/A')} ({cred_name})"
                        elif proto_type in ("wmi", "winrm"):
                            cred_display = f"{cred.get('username', 'N/A')} ({cred_name})"
                        
                        cred_progress = protocol_progress + int((idx + 1) / total_creds * (100 - protocol_progress) / total_protocols) if total_protocols > 0 else protocol_progress
                        self._update_scan_status(
                            scan_id,
                            credential=cred_display,
                            progress=min(cred_progress, 95),  # Max 95% durante test
                            message=f"Testando {proto_type.upper()}: {cred_display} ({idx+1}/{total_creds})"
                        )
                    
                    # Log dettagliato del tentativo
                    if proto_type == "ssh":
                        logger.info(f"[CRED_TEST] Testing SSH credential '{cred_name}' (ID: {cred_id}) - user: {cred.get('username')}")
                    elif proto_type == "snmp":
                        logger.info(f"[CRED_TEST] Testing SNMP credential '{cred_name}' (ID: {cred_id}) - community: {cred.get('community')}")
                    elif proto_type in ("wmi", "winrm"):
                        logger.info(f"[CRED_TEST] Testing WMI/WinRM credential '{cred_name}' (ID: {cred_id}) - user: {cred.get('username')}")
                    
                    # Crea entry test con tutti i dettagli necessari per la visualizzazione
                    test_entry = {
                        "protocol": proto_type,
                        "credential_id": cred_id,
                        "credential_name": cred_name,
                        "status": "testing"
                    }
                    
                    # Aggiungi dettagli specifici per protocollo
                    if proto_type == "ssh":
                        test_entry["username"] = cred.get("username")
                    elif proto_type == "snmp":
                        test_entry["community"] = cred.get("community")
                    elif proto_type in ("wmi", "winrm"):
                        test_entry["username"] = cred.get("username")
                        test_entry["domain"] = cred.get("domain", "")
                    
                    tested_credentials.append(test_entry)
                    
                    try:
                        if proto_type == "ssh":
                            ssh_password = cred.get("password")
                            ssh_user = cred.get("username")
                            ssh_port = cred.get("port", 22)
                            
                            # Log dettagliato per debug
                            if not ssh_password:
                                logger.warning(f"[CRED_TEST] ⚠️ SSH credential '{cred_name}' (ID: {cred_id}) has NO PASSWORD - username={ssh_user}, port={ssh_port}")
                            else:
                                logger.debug(f"[CRED_TEST] SSH credential '{cred_name}' (ID: {cred_id}) - username={ssh_user}, password_length={len(ssh_password)}, port={ssh_port}")
                            
                            agent_result = await agent_service.probe_unified(
                                agent_info,
                                request.target_address,
                                ["ssh"],
                                ssh_user=ssh_user,
                                ssh_password=ssh_password,
                                ssh_port=ssh_port,
                                timeout=min(request.timeout, 30),
                            )
                            
                        elif proto_type == "snmp":
                            # Verifica che ci sia una community valida
                            snmp_community = cred.get("community")
                            if not snmp_community or not snmp_community.strip():
                                logger.warning(f"[CRED_RESULT] ❌ SNMP credential '{cred_name}' has no community, skipping")
                                tested_credentials[-1]["status"] = "skipped"
                                tested_credentials[-1]["error"] = "No community"
                                continue
                            
                            # Passa anche le credenziali SSH disponibili per permettere fallback SSH
                            # se SNMP restituisce dati minimi (es. QNAP, Synology)
                            ssh_user = None
                            ssh_password = None
                            ssh_port = 22
                            if ssh_creds_list and len(ssh_creds_list) > 0:
                                first_ssh_cred = ssh_creds_list[0]
                                ssh_user = first_ssh_cred.get("username")
                                ssh_password = first_ssh_cred.get("password")
                                ssh_port = first_ssh_cred.get("port", 22)
                            
                            agent_result = await agent_service.probe_unified(
                                agent_info,
                                request.target_address,
                                ["snmp"],
                                ssh_user=ssh_user,
                                ssh_password=ssh_password,
                                ssh_port=ssh_port,
                                snmp_community=snmp_community,
                                snmp_port=cred.get("port", 161),
                                snmp_version=int(str(cred.get("version", "2c")).replace("c", "")),
                                timeout=min(request.timeout, 20),
                            )
                            
                        elif proto_type in ("wmi", "winrm"):
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
                        
                        # Verifica risultato
                        if agent_result and agent_result.success:
                            tested_credentials[-1]["status"] = "success"
                            # Conta quanti campi sono stati restituiti
                            data_count = len(agent_result.data.keys()) if isinstance(agent_result.data, dict) else 0
                            tested_credentials[-1]["data_fields"] = data_count
                            logger.info(f"[CRED_RESULT] ✅ SUCCESS - Credential '{cred_name}' (ID: {cred_id}, Protocol: {proto_type}) WORKED for {request.target_address} - {data_count} fields")
                            
                            # Salva risultato per confronto successivo
                            successful_results.append({
                                "protocol": proto_type,
                                "cred_id": cred_id,
                                "cred_name": cred_name,
                                "result": agent_result,
                                "data_count": data_count
                            })
                            
                            # Per questo protocollo, usa la prima credenziale che funziona
                            # Non serve testare altre credenziali dello stesso tipo
                            break  # Esci dal loop credenziali (ma continua con altri protocolli)
                        else:
                            error_msg = agent_result.error if agent_result else "No response"
                            tested_credentials[-1]["status"] = "failed"
                            tested_credentials[-1]["error"] = error_msg
                            all_errors.append(f"{proto_type}/{cred_name}: {error_msg}")
                            logger.info(f"[CRED_RESULT] ❌ FAILED - Credential '{cred_name}' (ID: {cred_id}, Protocol: {proto_type}): {error_msg}")
                    
                    except Exception as e:
                        error_msg = str(e)
                        tested_credentials[-1]["status"] = "error"
                        tested_credentials[-1]["error"] = error_msg
                        all_errors.append(f"{proto_type}/{cred_name}: {error_msg}")
                        logger.error(f"[CRED_RESULT] ❌ ERROR - Credential '{cred_name}' (ID: {cred_id}, Protocol: {proto_type}): {error_msg}")
                
                # NON uscire dal loop protocolli - continua a testare altri protocolli
                # per trovare quello che restituisce più dati
            
            # Scegli il risultato migliore (quello con più campi)
            if successful_results:
                # Ordina per numero di campi (discendente) e prendi il migliore
                successful_results.sort(key=lambda x: x["data_count"], reverse=True)
                best = successful_results[0]
                
                agent_result = best["result"]
                successful_cred_id = best["cred_id"]
                successful_cred_name = best["cred_name"]
                successful_proto = best["protocol"]
                
                logger.info(f"[UNIFIED_SCAN] Best result: {successful_proto} with {best['data_count']} fields (tested {len(successful_results)} successful protocols)")
            
            # Log risultato finale
            if successful_results:
                logger.info(f"[UNIFIED_SCAN] ✅ Scan SUCCESSFUL for {request.target_address}")
                logger.info(f"[UNIFIED_SCAN] Working credential: '{successful_cred_name}' (ID: {successful_cred_id}, Protocol: {successful_proto})")
                logger.info(f"[UNIFIED_SCAN] Credentials tested: {len(tested_credentials)}")
                # Log riepilogo credenziali testate
                for tested in tested_credentials:
                    status_icon = "✅" if tested["status"] == "success" else "❌" if tested["status"] == "failed" else "⏭️"
                    logger.info(f"[UNIFIED_SCAN]   {status_icon} {tested['protocol'].upper()}: '{tested['credential_name']}' (ID: {tested['credential_id']}) - {tested['status']}")
                    if tested.get("error"):
                        logger.debug(f"[UNIFIED_SCAN]      Error: {tested['error']}")
                
                # Salva ID credenziale nel risultato
                result.credential_used = successful_cred_id or successful_cred_name
                
                # Salva lista completa dei test delle credenziali
                result.credential_tests = tested_credentials
            else:
                logger.warning(f"[UNIFIED_SCAN] ❌ All credentials failed for {request.target_address}")
                logger.warning(f"[UNIFIED_SCAN] Credentials tested: {len(tested_credentials)}")
                
                # Verifica se tutti gli errori sono di connessione agent (non di autenticazione)
                # Se sì, impostiamo agent_error invece di popolare credential_tests
                connection_error_keywords = [
                    "connection failed", "all connection attempts failed", "connection error",
                    "could not connect", "connection refused", "timeout", "unreachable",
                    "agent not connected", "websocket", "http fallback"
                ]
                
                all_connection_errors = True
                for tested in tested_credentials:
                    error_msg = (tested.get("error") or "").lower()
                    if error_msg and not any(keyword in error_msg for keyword in connection_error_keywords):
                        # Questo errore NON è di connessione (probabilmente autenticazione)
                        all_connection_errors = False
                        break
                
                if all_connection_errors and len(tested_credentials) > 0:
                    # Tutti gli errori sono di connessione agent - NON sono problemi di credenziali
                    error_msg = f"Agent '{agent_name}' non raggiungibile: connessione WebSocket chiusa e fallback HTTP fallito"
                    logger.error(f"[UNIFIED_SCAN] {error_msg}")
                    logger.error(f"[UNIFIED_SCAN] Tutti i test sono falliti per errore di connessione agent, non per credenziali errate")
                    result.agent_error = error_msg
                    result.status = "failed"
                    result.errors.append(error_msg)
                    result.credential_tests = []  # NON popolare credential_tests con errori di connessione
                elif len(tested_credentials) == 0:
                    # Nessuna credenziale testata - problema di connessione agent
                    error_msg = f"Agent '{agent_name}' non raggiungibile: impossibile testare credenziali"
                    logger.error(f"[UNIFIED_SCAN] ⚠️ No credentials were tested! This indicates an agent connection issue.")
                    logger.error(f"[UNIFIED_SCAN] Available credentials - SSH: {len(ssh_creds_list)}, SNMP: {len(snmp_creds_list)}, WMI: {len(wmi_creds_list)}")
                    logger.error(f"[UNIFIED_SCAN] Protocols to try: {protocols}")
                    result.agent_error = error_msg
                    result.status = "failed"
                    result.errors.append(error_msg)
                    result.credential_tests = []  # NON popolare credential_tests
                else:
                    # Alcuni errori potrebbero essere di autenticazione - mostra credential_tests normalmente
                    for tested in tested_credentials:
                        logger.warning(f"[UNIFIED_SCAN]   ❌ {tested['protocol'].upper()}: '{tested['credential_name']}' (ID: {tested.get('credential_id', 'N/A')}) - {tested['status']}")
                        if tested.get("error"):
                            logger.warning(f"[UNIFIED_SCAN]      Error: {tested['error']}")
                    for err in all_errors[-5:]:  # Log ultimi 5 errori
                        logger.debug(f"[UNIFIED_SCAN] - {err}")
                    
                    # Salva la lista dei test (potrebbero esserci errori di autenticazione misti a errori di connessione)
                    result.credential_tests = tested_credentials
            
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
            # Assicura che credential_tests sia sempre inizializzato anche in caso di errore
            if not hasattr(result, 'credential_tests') or result.credential_tests is None:
                result.credential_tests = []
    
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
        
        # Preserva credential_tests se già impostati (non sovrascrivere)
        # I credential_tests vengono impostati prima del merge in _scan_via_agent
        
        # Protocollo usato
        result.protocol_used = agent_data.get("protocol_used", ",".join(protocols))
        
        # Identified by - formatta in modo user-friendly
        protocols_list = result.protocol_used.split(",") if result.protocol_used else protocols
        protocols_list = [p.strip().upper() for p in protocols_list if p.strip()]
        if len(protocols_list) > 1:
            result.identified_by = "Multiplo (" + ", ".join(protocols_list) + ")"
        elif len(protocols_list) == 1:
            result.identified_by = protocols_list[0]
        else:
            result.identified_by = "Unknown"
        
        # Credential used (se disponibile nei dati)
        result.credential_used = agent_data.get("credential_used", "")
        
        # System info - cerca prima in system_info, poi fallback al livello top (per Synology/QNAP)
        si = agent_data.get("system_info", {})
        
        # Hostname
        result.hostname = si.get("hostname") or agent_data.get("hostname") or result.hostname
        
        # OS name - importante per Synology (DSM) e QNAP (QTS/QuTS Hero)
        result.os_name = si.get("os_name") or agent_data.get("os_name") or result.os_name
        
        # OS version
        result.os_version = si.get("os_version") or agent_data.get("os_version") or result.os_version
        
        # Manufacturer
        result.manufacturer = si.get("manufacturer") or agent_data.get("manufacturer") or result.manufacturer
        
        # Model
        result.model = si.get("model") or agent_data.get("model") or result.model
        
        # Serial number - critico per NAS
        result.serial_number = si.get("serial_number") or agent_data.get("serial_number") or result.serial_number
        
        # Firmware version
        result.firmware_version = si.get("firmware_version") or agent_data.get("firmware_version") or result.firmware_version
        
        # Uptime
        result.uptime = si.get("uptime") or agent_data.get("uptime") or result.uptime
        
        # Device type
        result.device_type = si.get("device_type") or agent_data.get("device_type") or result.device_type or "unknown"
        
        # Log per debug NAS
        if result.manufacturer and result.manufacturer.lower() in ["synology", "qnap"]:
            # Log dettagliato di TUTTI i campi serial/RAM da agent_data
            logger.info(f"[MERGE_AGENT] NAS data: os_name={result.os_name}, os_version={result.os_version}, serial={result.serial_number}, model={result.model}")
            logger.info(f"[MERGE_AGENT] agent_data serial_number={agent_data.get('serial_number')}, si.serial_number={si.get('serial_number')}")
            logger.info(f"[MERGE_AGENT] agent_data ram_total_gb={agent_data.get('ram_total_gb')}, ram_total_mb={agent_data.get('ram_total_mb')}")
        
        # CPU
        if agent_data.get("cpu"):
            cpu = agent_data["cpu"]
            result.cpu_model = cpu.get("model", "")
            result.cpu_cores = cpu.get("cores_physical", 0)
            result.cpu_threads = cpu.get("cores_logical", 0)
            result.cpu_usage_percent = cpu.get("load_percent", 0)
        
        # Memory - cerca in più formati
        if agent_data.get("memory"):
            mem = agent_data["memory"]
            logger.info(f"[MERGE_AGENT] memory dict: {mem}")
            if mem.get("total_bytes"):
                result.ram_total_gb = mem.get("total_bytes", 0) / (1024**3)
                result.ram_used_gb = mem.get("used_bytes", 0) / (1024**3)
                result.ram_usage_percent = (mem.get("used_bytes", 0) / mem["total_bytes"]) * 100
                logger.info(f"[MERGE_AGENT] RAM from memory.total_bytes: {result.ram_total_gb:.2f}GB")
        
        # Fallback 1: ram_total_gb diretto (usato da QNAP probe aggiornato)
        if result.ram_total_gb == 0:
            ram_gb = agent_data.get("ram_total_gb", 0)
            if ram_gb > 0:
                result.ram_total_gb = ram_gb
                logger.debug(f"[MERGE_AGENT] RAM from ram_total_gb: {ram_gb}GB")
        
        # Fallback 2: ram_total_mb/ram_free_mb (usato da Synology/QNAP)
        if result.ram_total_gb == 0:
            ram_mb = agent_data.get("ram_total_mb", 0)
            if ram_mb > 0:
                result.ram_total_gb = ram_mb / 1024
                result.ram_used_gb = (ram_mb - agent_data.get("ram_free_mb", 0)) / 1024
                result.ram_usage_percent = ((ram_mb - agent_data.get("ram_free_mb", 0)) / ram_mb) * 100 if ram_mb else 0
                logger.debug(f"[MERGE_AGENT] RAM from mb: {ram_mb}MB -> {result.ram_total_gb:.2f}GB")
        
        # Disks & Volumes
        result.disks = agent_data.get("disks", [])
        result.volumes = agent_data.get("volumes", [])
        result.raid_arrays = agent_data.get("raid_arrays", [])
        result.shares = agent_data.get("shares", [])
        result.shares_count = len(result.shares)
        
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
                # Supporta sia ipv4_addresses (array) che ipv4 (singolo)
                ipv4 = None
                if iface.get("ipv4_addresses"):
                    ipv4 = iface["ipv4_addresses"][0] if isinstance(iface["ipv4_addresses"], list) else iface["ipv4_addresses"]
                elif iface.get("ipv4"):
                    ipv4 = iface["ipv4"]
                
                if ipv4 and not result.primary_ip:
                    result.primary_ip = ipv4
                
                # MAC address
                mac = iface.get("mac_address") or iface.get("mac")
                if mac and not result.primary_mac:
                    result.primary_mac = mac
                
                if result.primary_ip and result.primary_mac:
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
        
        # === LINUX-SPECIFIC FIELDS ===
        # Mappa direttamente ai campi dedicati di UnifiedScanResult
        
        # Kernel e distro
        result.kernel_version = agent_data.get("kernel_version", "") or result.kernel_version
        result.distro_name = agent_data.get("os_name", "") or agent_data.get("distro_name", "") or result.distro_name
        result.distro_id = agent_data.get("os_id", "") or agent_data.get("distro_id", "") or result.distro_id
        result.architecture = agent_data.get("architecture", "") or result.architecture
        result.load_average = agent_data.get("load_average", "") or result.load_average
        
        # Package manager
        result.package_manager = agent_data.get("package_manager", "") or result.package_manager
        result.packages_installed = agent_data.get("packages_installed", 0) or agent_data.get("installed_software_count", 0) or result.packages_installed
        
        # System
        result.init_system = agent_data.get("init_system", "") or result.init_system
        result.selinux_status = agent_data.get("selinux_status", "") or result.selinux_status
        result.apparmor_status = agent_data.get("apparmor_status", "") or result.apparmor_status
        result.timezone = agent_data.get("timezone", "") or result.timezone
        result.locale = agent_data.get("locale", "") or result.locale
        result.boot_time = agent_data.get("boot_time", "") or result.boot_time
        result.last_reboot = agent_data.get("last_reboot", "") or result.last_reboot
        
        # Docker/Container
        result.docker_installed = agent_data.get("docker_installed", False) or result.docker_installed
        result.docker_version = agent_data.get("docker_version", "") or result.docker_version
        result.containers_running = agent_data.get("containers_running", 0) or result.containers_running
        result.containers_total = agent_data.get("containers_total", 0) or result.containers_total
        
        # Network config
        result.default_gateway = agent_data.get("default_gateway", "") or result.default_gateway
        result.dns_servers = agent_data.get("dns_servers", []) or result.dns_servers
        result.hostname_fqdn = agent_data.get("hostname_fqdn", "") or result.hostname_fqdn
        
        # Storage details
        result.lvm_volumes = agent_data.get("lvm_volumes", []) or result.lvm_volumes
        result.volume_groups = agent_data.get("volume_groups", []) or result.volume_groups
        result.partitions = agent_data.get("partitions", []) or result.partitions
        result.fstab_entries = agent_data.get("fstab_entries", []) or result.fstab_entries
        result.swap_info = agent_data.get("swap", []) or result.swap_info
        
        # Firewall
        result.firewall_type = agent_data.get("firewall_type", "") or result.firewall_type
        result.firewall_enabled = agent_data.get("firewall_enabled", False) or result.firewall_enabled
        result.firewall_rules = agent_data.get("firewall_rules", []) or result.firewall_rules
        
        # Cron jobs
        result.cron_jobs = agent_data.get("cron_jobs", []) or result.cron_jobs
        
        # Running processes
        result.running_processes = agent_data.get("running_processes", []) or result.running_processes
        
        # Listening ports
        result.listening_ports = agent_data.get("listening_ports", []) or result.listening_ports
        
        # Databases
        result.databases = agent_data.get("databases", []) or result.databases
        
        # Web servers
        result.web_servers = agent_data.get("web_servers", []) or result.web_servers
        
        # Kernel modules
        result.kernel_modules = agent_data.get("kernel_modules", []) or result.kernel_modules
        
        # NTP servers
        result.ntp_servers = agent_data.get("ntp_servers", []) or result.ntp_servers
        
        # Installed services (all, not just running) - salva anche in custom_fields per retrocompatibilità
        if "installed_services" in agent_data:
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["installed_services"] = agent_data.get("installed_services", [])
            result.custom_fields["installed_services_count"] = agent_data.get("installed_services_count", 0)
        
        # Installed software (dpkg/rpm) - usa il campo software già presente + custom_fields
        if "installed_software" in agent_data:
            result.software = agent_data.get("installed_software", [])
            result.software_count = len(result.software)
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["installed_software_count"] = agent_data.get("installed_software_count", 0)
        
        # Salva anche in custom_fields per retrocompatibilità e dati aggiuntivi
        if agent_data.get("disk_usage"):
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["disk_usage"] = agent_data.get("disk_usage", {})
        if agent_data.get("inode_usage"):
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["inode_usage"] = agent_data.get("inode_usage", [])
        if agent_data.get("network_connections"):
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["network_connections"] = agent_data.get("network_connections", [])
        if agent_data.get("firewall_services"):
            result.custom_fields = result.custom_fields or {}
            result.custom_fields["firewall_services"] = agent_data.get("firewall_services")
        
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
        
        # VM Detection (se questo device è una VM)
        # Cerca in system_info o direttamente in agent_data
        result.vm_type = si.get("vm_type") or agent_data.get("vm_type", "")
        result.is_virtual_machine = si.get("is_virtual_machine", False) or agent_data.get("is_virtual_machine", False)
        
        # Fallback: rileva VM da manufacturer se non già rilevato
        if not result.is_virtual_machine and result.manufacturer:
            vm_manufacturers = ["qemu", "vmware", "vmware, inc.", "microsoft corporation", "xen", "kvm", "virtualbox", "innotek"]
            if result.manufacturer.lower() in vm_manufacturers:
                result.is_virtual_machine = True
                if not result.vm_type:
                    # Estrai tipo VM dal manufacturer
                    mfr_lower = result.manufacturer.lower()
                    if "qemu" in mfr_lower:
                        result.vm_type = "qemu"
                    elif "vmware" in mfr_lower:
                        result.vm_type = "vmware"
                    elif "microsoft" in mfr_lower:
                        result.vm_type = "hyperv"
                    elif "virtualbox" in mfr_lower or "innotek" in mfr_lower:
                        result.vm_type = "virtualbox"
                    else:
                        result.vm_type = mfr_lower.split(",")[0].split()[0]
                logger.info(f"[MERGE_AGENT] Detected VM by manufacturer: {result.manufacturer} -> vm_type={result.vm_type}")
        
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
            if "switch" in hostname:
                return DeviceType.SWITCH.value
            if "router" in hostname or "gateway" in hostname:
                return DeviceType.ROUTER.value
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
