"""
Servizio centralizzato per determinare Category e Subcategory dei device.
La CATEGORIA è la root, la SOTTOCATEGORIA è il dettaglio specifico.
"""
from typing import Optional, List, Dict, Tuple
from loguru import logger


# ============================================================================
# UBIQUITI/UNIFI MODEL PREFIXES
# ============================================================================
# Switch prefixes (USW = UniFi Switch)
UNIFI_SWITCH_PREFIXES = [
    "USW",           # UniFi Switch (tutti i modelli)
    "US-",           # Legacy UniFi Switch
    "USL",           # UniFi Switch Lite
    "USP",           # UniFi Switch Pro (PoE)
    "USF",           # UniFi Switch Flex
    "USE",           # UniFi Switch Enterprise
    "USMINI",        # UniFi Switch Mini
]

# Access Point prefixes
UNIFI_AP_PREFIXES = [
    "UAP",           # UniFi Access Point (legacy)
    "U6",            # UniFi 6 (WiFi 6) - U6-Lite, U6-LR, U6-Pro, U6-Enterprise, U6+
    "U7",            # UniFi 7 (WiFi 7)
    "UWB",           # UniFi Wall/Building AP
    "UBB",           # UniFi Building Bridge
    "UMR",           # UniFi Mobile Router
    "NANOHD",        # NanoHD
    "FLEXHD",        # FlexHD
    "NANOSTATION",   # NanoStation
    "NANOBEAM",      # NanoBeam
    "POWERBEAM",     # PowerBeam
    "LITEBEAM",      # LiteBeam
    "AIRMAX",        # AirMax
]

# Gateway/Router prefixes
UNIFI_GATEWAY_PREFIXES = [
    "UDM",           # UniFi Dream Machine (tutti i modelli: UDM, UDM-Pro, UDM-SE)
    "UDR",           # UniFi Dream Router
    "UDW",           # UniFi Dream Wall
    "USG",           # UniFi Security Gateway
    "UCG",           # UniFi Cloud Gateway
    "UXG",           # UniFi Next-Gen Gateway
    "EDGEROUTER",    # EdgeRouter
    "ER-",           # EdgeRouter
]

# Camera prefixes
UNIFI_CAMERA_PREFIXES = [
    "UVC",           # UniFi Video Camera
    "AI",            # AI Camera series
    "G3",            # G3 Camera series
    "G4",            # G4 Camera series
    "G5",            # G5 Camera series
]


def _get_unifi_device_type(model: str) -> Optional[str]:
    """
    Determina il tipo di dispositivo UniFi dal nome del modello.
    
    Returns:
        "Switch", "Access Point", "Gateway", "IP Camera", o None se non determinabile
    """
    if not model:
        return None
    
    model_upper = model.upper().replace("-", "").replace("_", "").replace(" ", "")
    
    # Check Switch first (priorità alta perché USW è specifico)
    for prefix in UNIFI_SWITCH_PREFIXES:
        prefix_clean = prefix.replace("-", "")
        if model_upper.startswith(prefix_clean):
            return "Switch"
    
    # Check Gateway/Router
    for prefix in UNIFI_GATEWAY_PREFIXES:
        prefix_clean = prefix.replace("-", "")
        if model_upper.startswith(prefix_clean):
            return "Gateway"
    
    # Check Camera
    for prefix in UNIFI_CAMERA_PREFIXES:
        prefix_clean = prefix.replace("-", "")
        if model_upper.startswith(prefix_clean):
            return "IP Camera"
    
    # Check Access Point (ultimo perché alcuni prefissi sono generici)
    for prefix in UNIFI_AP_PREFIXES:
        prefix_clean = prefix.replace("-", "")
        if model_upper.startswith(prefix_clean):
            return "Access Point"
    
    # Fallback: cerca pattern comuni
    if "SWITCH" in model_upper:
        return "Switch"
    if "GATEWAY" in model_upper or "ROUTER" in model_upper:
        return "Gateway"
    if "CAMERA" in model_upper or "CAM" in model_upper:
        return "IP Camera"
    
    return None


# ============================================================================
# CATEGORY HIERARCHY
# ============================================================================
# Mapping gerarchico CATEGORIA -> SOTTOCATEGORIA
CATEGORY_HIERARCHY = {
    "Network": ["Router", "Switch", "Firewall", "Access Point", "Gateway"],
    "Server": ["Physical Server", "Hypervisor", "VM Windows", "VM Linux"],
    "Storage": ["NAS", "SAN"],
    "Security": ["Firewall Appliance", "VPN Gateway", "IDS/IPS", "Proxy"],
    "Endpoint": ["Desktop", "Laptop", "Thin Client", "Mobile Device"],
    "Telephony": ["PBX", "VoIP Gateway", "IP Phone"],
    "Infrastructure": ["UPS", "PDU", "Rack"],
    "Peripheral": ["Printer", "Scanner", "MFP"],
    "Surveillance": ["IP Camera", "NVR"],
}


def determine_category_and_subcategory(
    device_type: Optional[str] = None,
    os_name: Optional[str] = None,
    os_family: Optional[str] = None,
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
    open_ports: Optional[List[Dict]] = None,
    probe_result_category: Optional[str] = None,
    scan_result_category: Optional[str] = None,
    hypervisor_type: Optional[str] = None,
    vm_type: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Determina Category e Subcategory in modo uniforme seguendo la gerarchia.
    
    Priorità:
    1. scan_result_category esplicito
    2. probe_result_category
    3. Inferenza da device_type + porte + OS + vendor
    
    Returns:
        (category, subcategory) - entrambi possono essere None se non determinabili
    """
    
    # =========================================================================
    # OVERRIDE: Correzioni per falsi positivi da probe agent
    # =========================================================================
    # Caso 1: Linux/Ubuntu erroneamente classificato come access_point
    # Questo accade quando l'agent rileva erroneamente un dispositivo UniFi
    os_name_lower = (os_name or "").lower()
    os_family_lower = (os_family or "").lower()
    device_type_lower = (device_type or "").lower()
    manufacturer_lower = (manufacturer or "").lower()
    
    # Lista di OS Linux noti
    linux_distros = ["ubuntu", "debian", "centos", "rhel", "fedora", "arch", 
                     "suse", "opensuse", "alpine", "rocky", "alma", "oracle linux",
                     "linux mint", "manjaro", "elementary", "pop!_os", "kali"]
    
    is_linux_os = any(distro in os_name_lower for distro in linux_distros) or \
                  any(distro in os_family_lower for distro in linux_distros) or \
                  "linux" in os_name_lower or "linux" in os_family_lower
    
    # Se device_type è access_point MA os_name indica Linux -> correggere
    if device_type_lower == "access_point" and is_linux_os:
        logger.info(f"[CATEGORY_OVERRIDE] Correcting misclassified Linux device: "
                   f"device_type={device_type} but os_name={os_name}")
        # È una VM?
        if manufacturer_lower in ["qemu", "vmware", "microsoft", "xen", "kvm", "virtualbox"]:
            logger.info(f"[CATEGORY_OVERRIDE] Detected as VM (manufacturer={manufacturer})")
            return ("Server", "VM Linux")
        else:
            return ("Server", "Physical Server")
    
    # Caso 2: Se manufacturer è QEMU/VMware ma device_type indica network device -> VM
    if manufacturer_lower in ["qemu", "vmware", "xen", "kvm", "virtualbox"]:
        if device_type_lower in ["access_point", "switch", "router", "network"]:
            if is_linux_os:
                logger.info(f"[CATEGORY_OVERRIDE] VM with network device_type but Linux OS: "
                           f"device_type={device_type}, os_name={os_name}, manufacturer={manufacturer}")
                return ("Server", "VM Linux")
            elif "windows" in os_name_lower or "windows" in os_family_lower:
                logger.info(f"[CATEGORY_OVERRIDE] VM with network device_type but Windows OS")
                return ("Server", "VM Windows")
    
    # =========================================================================
    # Fine OVERRIDE - continua con logica normale
    # =========================================================================
    
    # Priorità 1: scan_result esplicito (massima priorità)
    if scan_result_category:
        category = scan_result_category
        subcategory = _infer_subcategory_from_category(
            category, device_type, os_name, os_family, manufacturer, 
            model, open_ports, hypervisor_type, vm_type
        )
        return (category, subcategory)
    
    # Priorità 2: probe_result category
    if probe_result_category:
        category = probe_result_category
        subcategory = _infer_subcategory_from_category(
            category, device_type, os_name, os_family, manufacturer,
            model, open_ports, hypervisor_type, vm_type
        )
        return (category, subcategory)
    
    # Priorità 3: Determina da device_type + porte + OS + vendor
    category, subcategory = _determine_from_device_info(
        device_type, os_name, os_family, manufacturer, model,
        open_ports, hypervisor_type, vm_type
    )
    
    return (category, subcategory)


def _infer_subcategory_from_category(
    category: str,
    device_type: Optional[str] = None,
    os_name: Optional[str] = None,
    os_family: Optional[str] = None,
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
    open_ports: Optional[List[Dict]] = None,
    hypervisor_type: Optional[str] = None,
    vm_type: Optional[str] = None,
) -> Optional[str]:
    """Inferisce subcategory da category e altri dati disponibili."""
    
    if not category:
        return None
    
    category = category.strip()
    available_subcategories = CATEGORY_HIERARCHY.get(category, [])
    
    if not available_subcategories:
        return None
    
    # Normalizza input
    device_type = (device_type or "").lower()
    os_name = (os_name or "").lower()
    os_family = (os_family or "").lower()
    manufacturer = (manufacturer or "").lower()
    model = (model or "").lower()
    
    port_numbers = set()
    if open_ports:
        port_numbers = {p.get("port") for p in open_ports if p.get("open")}
    
    # Network devices
    if category == "Network":
        # Prima controlla device_type esplicito (alta priorità)
        if device_type in ["switch", "router", "access_point", "firewall", "gateway", "ap"]:
            subcategory_map = {
                "switch": "Switch",
                "router": "Router", 
                "access_point": "Access Point",
                "ap": "Access Point",
                "firewall": "Firewall",
                "gateway": "Gateway"
            }
            return subcategory_map.get(device_type, "Switch")
        
        # MikroTik
        if device_type == "mikrotik" or "mikrotik" in manufacturer:
            return "Router"
        
        # Ubiquiti/UniFi - usa la funzione dedicata per riconoscimento accurato
        if "ubiquiti" in manufacturer or "ubnt" in manufacturer or "unifi" in manufacturer or "unifi" in os_name:
            unifi_type = _get_unifi_device_type(model)
            if unifi_type and unifi_type != "IP Camera":  # IP Camera va in Surveillance
                return unifi_type
            # Fallback se modello non riconosciuto
            return "Access Point"
        
        if "router" in model or "gateway" in model:
            return "Router"
        if "switch" in model or "usw" in model:
            return "Switch"
        if "firewall" in model:
            return "Firewall"
        if "ap" in model or "access point" in model or "uap" in model:
            return "Access Point"
        
        # Da porte aperte
        if {8728, 8729, 8291} & port_numbers:  # MikroTik
            return "Router"
        if 161 in port_numbers:  # SNMP
            return "Switch"  # Default SNMP
        
        return "Router"  # Default Network
    
    # Server devices
    elif category == "Server":
        # Hypervisor detection
        if hypervisor_type or "proxmox" in os_name or "proxmox" in os_family:
            return "Hypervisor"
        
        # VMware ESXi è un hypervisor, non una VM
        if "vmware" in os_name and ("esxi" in os_name or "vsphere" in os_name):
            return "Hypervisor"
        
        # VM detection - basata su vm_type esplicito
        if vm_type:
            if vm_type in ["qemu", "kvm", "vmware", "virtualbox", "hyperv", "xen"]:
                if "windows" in os_name or "windows" in os_family:
                    return "VM Windows"
                else:
                    return "VM Linux"
        
        # VM detection - basata su manufacturer (QEMU, VMware, etc.)
        # Questo copre i casi in cui vm_type non è impostato ma il manufacturer indica una VM
        vm_manufacturers = ["qemu", "vmware", "vmware, inc.", "microsoft corporation", "xen", "kvm", "virtualbox", "innotek"]
        if manufacturer and manufacturer.lower() in vm_manufacturers:
            logger.debug(f"[SUBCATEGORY] Detected VM by manufacturer: {manufacturer}")
            if "windows" in os_name or "windows" in os_family:
                return "VM Windows"
            else:
                return "VM Linux"
        
        # VM detection - basata su model (contiene "virtual")
        if model and "virtual" in model.lower():
            logger.debug(f"[SUBCATEGORY] Detected VM by model: {model}")
            if "windows" in os_name or "windows" in os_family:
                return "VM Windows"
            else:
                return "VM Linux"
        
        # Physical server (default)
        return "Physical Server"
    
    # Storage devices
    elif category == "Storage":
        if "synology" in manufacturer or "qnap" in manufacturer:
            return "NAS"
        if "san" in model:
            return "SAN"
        return "NAS"  # Default Storage
    
    # Security devices
    elif category == "Security":
        if "firewall" in model:
            return "Firewall Appliance"
        if "vpn" in model or "gateway" in model:
            return "VPN Gateway"
        if "ids" in model or "ips" in model:
            return "IDS/IPS"
        if "proxy" in model:
            return "Proxy"
        return "Firewall Appliance"  # Default Security
    
    # Endpoint devices
    elif category == "Endpoint":
        if "laptop" in model or "notebook" in model:
            return "Laptop"
        if "thin client" in model:
            return "Thin Client"
        if "mobile" in model or "phone" in model or "tablet" in model:
            return "Mobile Device"
        return "Desktop"  # Default Endpoint
    
    # Telephony devices
    elif category == "Telephony":
        if "pbx" in model:
            return "PBX"
        if "gateway" in model:
            return "VoIP Gateway"
        if "phone" in model:
            return "IP Phone"
        return "PBX"  # Default Telephony
    
    # Infrastructure devices
    elif category == "Infrastructure":
        if "ups" in model:
            return "UPS"
        if "pdu" in model:
            return "PDU"
        if "rack" in model:
            return "Rack"
        return "UPS"  # Default Infrastructure
    
    # Peripheral devices
    elif category == "Peripheral":
        if "scanner" in model and "mfp" not in model:
            return "Scanner"
        if "mfp" in model or "multifunction" in model:
            return "MFP"
        return "Printer"  # Default Peripheral
    
    # Surveillance devices
    elif category == "Surveillance":
        if "nvr" in model or "recorder" in model:
            return "NVR"
        return "IP Camera"  # Default Surveillance
    
    return None


def _determine_from_device_info(
    device_type: Optional[str] = None,
    os_name: Optional[str] = None,
    os_family: Optional[str] = None,
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
    open_ports: Optional[List[Dict]] = None,
    hypervisor_type: Optional[str] = None,
    vm_type: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Determina category e subcategory da informazioni del device."""
    
    # Normalizza input
    device_type = (device_type or "").lower()
    os_name = (os_name or "").lower()
    os_family = (os_family or "").lower()
    manufacturer = (manufacturer or "").lower()
    model = (model or "").lower()
    
    port_numbers = set()
    if open_ports:
        port_numbers = {p.get("port") for p in open_ports if p.get("open")}
    
    # Network devices - Explicit device_type handling
    # Se device_type è già determinato come switch/router/access_point/firewall, usalo direttamente
    if device_type in ["switch", "router", "access_point", "firewall", "gateway"]:
        subcategory_map = {
            "switch": "Switch",
            "router": "Router",
            "access_point": "Access Point",
            "firewall": "Firewall",
            "gateway": "Gateway"
        }
        return ("Network", subcategory_map.get(device_type, "Switch"))
    
    # Network devices - Ubiquiti/UniFi
    if "ubiquiti" in manufacturer or "ubnt" in manufacturer or "unifi" in manufacturer:
        # Prima controlla device_type (più affidabile del modello)
        if device_type == "switch":
            return ("Network", "Switch")
        elif device_type == "router" or device_type == "gateway":
            return ("Network", "Gateway")
        elif device_type == "access_point" or device_type == "ap":
            return ("Network", "Access Point")
        
        # Poi usa la funzione di riconoscimento modello UniFi
        unifi_type = _get_unifi_device_type(model)
        if unifi_type:
            if unifi_type == "IP Camera":
                return ("Surveillance", "IP Camera")
            return ("Network", unifi_type)
        # Fallback: Access Point (default per Ubiquiti senza modello riconosciuto)
        return ("Network", "Access Point")
    
    # UniFi OS detection from os_name
    if "unifi" in os_name or "unifi" in os_family:
        # Prima controlla device_type
        if device_type == "switch":
            return ("Network", "Switch")
        elif device_type == "router" or device_type == "gateway":
            return ("Network", "Gateway")
        elif device_type == "access_point" or device_type == "ap":
            return ("Network", "Access Point")
        
        # Poi usa la funzione di riconoscimento modello UniFi
        unifi_type = _get_unifi_device_type(model)
        if unifi_type:
            if unifi_type == "IP Camera":
                return ("Surveillance", "IP Camera")
            return ("Network", unifi_type)
        # Fallback: Access Point
        return ("Network", "Access Point")
    
    # Network devices - MikroTik
    if device_type == "mikrotik" or "mikrotik" in manufacturer:
        return ("Network", "Router")
    
    if device_type == "network":
        if {8728, 8729, 8291} & port_numbers:  # MikroTik
            return ("Network", "Router")
        if 161 in port_numbers:  # SNMP
            # Prova a distinguere switch/router da vendor
            if "cisco" in manufacturer:
                if "catalyst" in model:
                    return ("Network", "Switch")
                elif "asa" in model or "firewall" in model:
                    return ("Security", "Firewall Appliance")
                else:
                    return ("Network", "Router")
            return ("Network", "Switch")  # Default SNMP
        return ("Network", "Router")  # Default network
    
    # Hypervisor
    if hypervisor_type or "proxmox" in os_name or "proxmox" in os_family or "vmware" in os_name or "esxi" in os_name:
        return ("Server", "Hypervisor")
    
    # VM
    if vm_type:
        if vm_type == "qemu" or vm_type == "kvm":
            if "windows" in os_name or "windows" in os_family:
                return ("Server", "VM Windows")
            else:
                return ("Server", "VM Linux")
    
    # Storage devices
    if device_type == "storage" or "synology" in manufacturer or "qnap" in manufacturer:
        return ("Storage", "NAS")
    
    # Windows devices
    if device_type == "windows" or "windows" in os_name or "windows" in os_family:
        # Determina se server o endpoint
        if "server" in os_name:
            return ("Server", "Physical Server")
        elif 3389 in port_numbers and 445 not in port_numbers:  # RDP senza SMB
            return ("Endpoint", "Desktop")
        elif 389 in port_numbers or 636 in port_numbers:  # LDAP/LDAPS (Domain Controller)
            return ("Server", "Physical Server")
        else:
            # Default: server se ha porte server, altrimenti endpoint
            server_ports = {3306, 5432, 1433, 1521, 27017, 6379, 80, 443}
            if server_ports & port_numbers:
                return ("Server", "Physical Server")
            return ("Endpoint", "Desktop")
    
    # Linux devices
    if device_type == "linux" or device_type == "server" or "linux" in os_name or "linux" in os_family:
        # Linux è sempre Server di default, non Endpoint
        # Solo se esplicitamente indicato come workstation/desktop
        if "desktop" in device_type or "workstation" in device_type or "laptop" in device_type:
            return ("Endpoint", "Desktop")
        
        # Determina tipo server
        if hypervisor_type:
            return ("Server", "Hypervisor")
        
        # Se ha porte server tipiche, è sicuramente un server
        server_ports = {3306, 5432, 1433, 1521, 27017, 6379, 80, 443, 25, 110, 143, 993, 995}
        if server_ports & port_numbers:
            return ("Server", "Physical Server")
        
        # Default: Linux con SSH è sempre un server, non un desktop
        # Un desktop Linux non avrebbe SSH esposto normalmente
        return ("Server", "Physical Server")
    
    # Security devices (firewall appliances)
    if "firewall" in model or "pfsense" in os_name or "opnsense" in os_name:
        return ("Security", "Firewall Appliance")
    
    # Telephony devices
    if "pbx" in model or "asterisk" in os_name:
        return ("Telephony", "PBX")
    
    # Peripheral devices
    if device_type == "printer" or "printer" in model:
        if "mfp" in model or "multifunction" in model:
            return ("Peripheral", "MFP")
        elif "scanner" in model:
            return ("Peripheral", "Scanner")
        return ("Peripheral", "Printer")
    
    # Surveillance devices
    if device_type == "camera" or "camera" in model:
        return ("Surveillance", "IP Camera")
    if "nvr" in model or "recorder" in model:
        return ("Surveillance", "NVR")
    
    # Infrastructure devices
    if "ups" in model:
        return ("Infrastructure", "UPS")
    if "pdu" in model:
        return ("Infrastructure", "PDU")
    
    # Default: Other
    return (None, None)


def get_all_categories() -> List[str]:
    """Ritorna lista di tutte le categorie disponibili."""
    return list(CATEGORY_HIERARCHY.keys())


def get_subcategories_for_category(category: str) -> List[str]:
    """Ritorna lista di sottocategorie per una categoria."""
    return CATEGORY_HIERARCHY.get(category, [])


def validate_category_subcategory(category: str, subcategory: str) -> bool:
    """Valida che subcategory appartenga a category."""
    if category not in CATEGORY_HIERARCHY:
        return False
    return subcategory in CATEGORY_HIERARCHY[category]
