"""
DaDude - Inventory Models
Database models per inventario dispositivi: Windows, Linux, Network Devices, MikroTik
"""
from sqlalchemy import (
    Column, String, Integer, BigInteger, Float, Boolean, DateTime, Text, JSON,
    ForeignKey, Index, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from enum import Enum
import uuid

from .database import Base


def generate_uuid():
    return uuid.uuid4().hex[:8]


# ==========================================
# ENUMS
# ==========================================

class DeviceType(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MIKROTIK = "mikrotik"
    NETWORK = "network"  # Switch, Firewall, AP generico
    PRINTER = "printer"
    CAMERA = "camera"
    VOIP = "voip"
    OTHER = "other"


class DeviceStatus(str, Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"  # Parzialmente funzionante
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class MonitorSource(str, Enum):
    DUDE = "dude"  # Monitorato da The Dude
    AGENT = "agent"  # Agent locale installato
    SNMP = "snmp"  # Polling SNMP
    WMI = "wmi"  # Windows WMI
    SSH = "ssh"  # SSH polling
    API = "api"  # API specifica


# ==========================================
# INVENTARIO BASE
# ==========================================

class InventoryDevice(Base):
    """
    Dispositivo inventariato - tabella base per tutti i tipi
    """
    __tablename__ = "inventory_devices"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    
    # Credenziale associata per accesso al device
    credential_id = Column(String(8), ForeignKey("credentials.id"), nullable=True)
    credential_ids = Column(Text, nullable=True)  # JSON array of credential IDs for multiple credentials
    
    # Identificazione
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    
    # Tipo e categoria
    device_type = Column(String(20), default="other")  # windows, linux, mikrotik, network, etc
    category = Column(String(50), nullable=True)  # Network, Server, Storage, Security, etc
    subcategory = Column(String(50), nullable=True)  # Router, Switch, Physical Server, VM Windows, etc.
    manufacturer = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    serial_number = Column(String(100), nullable=True)
    asset_tag = Column(String(50), nullable=True)  # Codice inventario aziendale
    
    # Rete principale
    primary_ip = Column(String(50), nullable=True)
    primary_mac = Column(String(20), nullable=True)
    mac_address = Column(String(20), nullable=True)  # Alias per retrocompatibilità

    # Identificazione
    identified_by = Column(String(50), nullable=True)  # probe_wmi, probe_ssh, probe_snmp, mac_vendor
    credential_used = Column(String(255), nullable=True)  # Nome della credenziale usata
    open_ports = Column(JSON, nullable=True)  # Servizi rilevati: [{"port": 80, "protocol": "tcp", "service": "http"}]

    # Location
    site_name = Column(String(100), nullable=True)
    location = Column(String(255), nullable=True)  # Rack, stanza, piano
    
    # Stato e monitoring
    status = Column(String(20), default="unknown")
    monitored = Column(Boolean, default=False)  # Monitoraggio attivo
    monitoring_type = Column(String(20), default="none")  # none, icmp, tcp, mikrotik, agent
    monitoring_port = Column(Integer, nullable=True)  # Porta TCP per monitoraggio (se monitoring_type == "tcp")
    monitor_source = Column(String(20), nullable=True)  # dude, agent, snmp, etc
    monitoring_agent_id = Column(String(8), nullable=True)  # ID sonda per monitoring
    netwatch_id = Column(String(50), nullable=True)  # ID entry Netwatch su MikroTik
    dude_device_id = Column(String(50), nullable=True)  # ID in The Dude se presente
    last_seen = Column(DateTime, nullable=True)
    last_scan = Column(DateTime, nullable=True)
    last_check = Column(DateTime, nullable=True)  # Ultimo check monitoring
    
    # Sistema operativo (generico)
    os_family = Column(String(50), nullable=True)  # Windows, Linux, RouterOS, IOS
    os_version = Column(String(100), nullable=True)
    os_build = Column(String(50), nullable=True)
    architecture = Column(String(20), nullable=True)  # x64, x86, ARM
    
    # Hardware base
    cpu_model = Column(String(200), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    cpu_threads = Column(Integer, nullable=True)
    ram_total_gb = Column(Float, nullable=True)
    
    # Storage base (unified scanner)
    disk_total_gb = Column(Float, nullable=True)
    disk_free_gb = Column(Float, nullable=True)
    firmware_version = Column(String(100), nullable=True)
    
    # Note e metadata
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)  # Note (da compilare manualmente)
    tags = Column(JSON, nullable=True)  # ["critical", "production", "backup"]
    custom_fields = Column(JSON, nullable=True)  # Campi personalizzati
    
    # Campi aggiuntivi per inventario
    feature = Column(String(100), nullable=True)  # ES: DC, File Server, Print Server
    location = Column(String(255), nullable=True)  # Location (da compilare manualmente)
    cespite = Column(String(100), nullable=True)  # Cespite (da compilare manualmente)
    
    # Audit
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Tracking fields for intelligent management
    first_seen_at = Column(DateTime, nullable=True)  # Prima volta che il device è stato visto
    last_verified_at = Column(DateTime, nullable=True)  # Ultima volta che è stato trovato in una scansione
    verification_count = Column(Integer, default=0)  # Numero di volte che è stato verificato
    last_scan_network_id = Column(String(8), ForeignKey("networks.id"), nullable=True)  # ID dell'ultima rete dove è stato visto
    cleanup_marked_at = Column(DateTime, nullable=True)  # Data in cui è stato marcato per pulizia
    
    # Relationships
    credential = relationship("Credential", foreign_keys=[credential_id])
    last_scan_network = relationship("Network", foreign_keys=[last_scan_network_id])
    network_interfaces = relationship("NetworkInterface", back_populates="device", cascade="all, delete-orphan")
    disks = relationship("DiskInfo", back_populates="device", cascade="all, delete-orphan")
    software = relationship("InstalledSoftware", back_populates="device", cascade="all, delete-orphan")
    services = relationship("ServiceInfo", back_populates="device", cascade="all, delete-orphan")
    windows_details = relationship("WindowsDetails", back_populates="device", uselist=False, cascade="all, delete-orphan")
    linux_details = relationship("LinuxDetails", back_populates="device", uselist=False, cascade="all, delete-orphan")
    mikrotik_details = relationship("MikroTikDetails", back_populates="device", uselist=False, cascade="all, delete-orphan")
    network_device_details = relationship("NetworkDeviceDetails", back_populates="device", uselist=False, cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_inventory_customer', 'customer_id'),
        Index('idx_inventory_type', 'device_type'),
        Index('idx_inventory_category', 'category'),
        Index('idx_inventory_subcategory', 'subcategory'),
        Index('idx_inventory_category_subcategory', 'category', 'subcategory'),
        Index('idx_inventory_ip', 'primary_ip'),
        Index('idx_inventory_status', 'status'),
        Index('idx_inventory_dude', 'dude_device_id'),
        Index('idx_inventory_last_verified', 'last_verified_at'),
        Index('idx_inventory_cleanup_marked', 'cleanup_marked_at'),
    )


# ==========================================
# COMPONENTI COMUNI
# ==========================================

class NetworkInterface(Base):
    """Interfacce di rete del dispositivo"""
    __tablename__ = "inventory_network_interfaces"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    name = Column(String(100), nullable=False)  # eth0, ether1, Ethernet 1
    description = Column(String(255), nullable=True)
    interface_type = Column(String(50), nullable=True)  # ethernet, wifi, bridge, vlan
    
    mac_address = Column(String(20), nullable=True)
    ip_addresses = Column(JSON, nullable=True)  # [{"ip": "192.168.1.1", "mask": "24", "type": "static"}]
    
    speed_mbps = Column(Integer, nullable=True)
    duplex = Column(String(20), nullable=True)
    mtu = Column(Integer, nullable=True)
    
    admin_status = Column(String(20), nullable=True)  # up, down
    oper_status = Column(String(20), nullable=True)  # up, down
    
    vlan_id = Column(Integer, nullable=True)
    is_management = Column(Boolean, default=False)
    
    # Campi avanzati per switch/router
    lldp_enabled = Column(Boolean, nullable=True)
    cdp_enabled = Column(Boolean, nullable=True)
    poe_enabled = Column(Boolean, nullable=True)
    poe_power_watts = Column(Float, nullable=True)
    vlan_native = Column(Integer, nullable=True)
    vlan_trunk_allowed = Column(JSON, nullable=True)  # [10, 20, 30]
    stp_state = Column(String(20), nullable=True)  # forwarding, blocking, disabled
    lacp_enabled = Column(Boolean, nullable=True)
    
    # Traffic stats (ultimo polling)
    bytes_in = Column(Integer, nullable=True)
    bytes_out = Column(Integer, nullable=True)
    packets_in = Column(Integer, nullable=True)
    packets_out = Column(Integer, nullable=True)
    errors_in = Column(Integer, nullable=True)
    errors_out = Column(Integer, nullable=True)
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="network_interfaces")
    
    __table_args__ = (
        Index('idx_nic_device', 'device_id'),
        Index('idx_nic_mac', 'mac_address'),
    )


class DiskInfo(Base):
    """Informazioni dischi/storage"""
    __tablename__ = "inventory_disks"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    name = Column(String(100), nullable=False)  # C:, /dev/sda, disk1
    mount_point = Column(String(255), nullable=True)
    
    disk_type = Column(String(50), nullable=True)  # hdd, ssd, nvme, raid, Fixed hard disk media, etc.
    filesystem = Column(String(50), nullable=True)  # NTFS, ext4, ZFS
    
    size_gb = Column(Float, nullable=True)
    used_gb = Column(Float, nullable=True)
    free_gb = Column(Float, nullable=True)
    percent_used = Column(Float, nullable=True)
    
    model = Column(String(200), nullable=True)
    serial = Column(String(100), nullable=True)
    smart_status = Column(String(50), nullable=True)  # OK, Warning, Critical
    
    is_system = Column(Boolean, default=False)
    is_removable = Column(Boolean, default=False)
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="disks")
    
    __table_args__ = (
        Index('idx_disk_device', 'device_id'),
    )


class InstalledSoftware(Base):
    """Software installato"""
    __tablename__ = "inventory_software"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    version = Column(String(100), nullable=True)
    vendor = Column(String(200), nullable=True)
    
    install_date = Column(DateTime, nullable=True)
    install_location = Column(String(500), nullable=True)
    
    size_mb = Column(Float, nullable=True)
    is_update = Column(Boolean, default=False)  # Windows Update/Patch
    
    license_key = Column(String(255), nullable=True)  # Se rilevabile
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="software")
    
    __table_args__ = (
        Index('idx_software_device', 'device_id'),
        Index('idx_software_name', 'name'),
    )


class ServiceInfo(Base):
    """Servizi/daemon in esecuzione"""
    __tablename__ = "inventory_services"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    display_name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    
    service_type = Column(String(50), nullable=True)  # windows_service, systemd, docker
    
    status = Column(String(20), nullable=True)  # running, stopped, disabled
    start_type = Column(String(20), nullable=True)  # auto, manual, disabled
    
    user_account = Column(String(100), nullable=True)  # Account che esegue il servizio
    executable_path = Column(String(500), nullable=True)
    
    pid = Column(Integer, nullable=True)
    memory_mb = Column(Float, nullable=True)
    cpu_percent = Column(Float, nullable=True)
    
    port = Column(Integer, nullable=True)  # Porta in ascolto se applicabile
    
    is_critical = Column(Boolean, default=False)  # Marcato come critico
    monitored = Column(Boolean, default=False)  # Se monitorato attivamente
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="services")
    
    __table_args__ = (
        Index('idx_service_device', 'device_id'),
        Index('idx_service_status', 'status'),
    )


# ==========================================
# DETTAGLI WINDOWS
# ==========================================

class WindowsDetails(Base):
    """Dettagli specifici Windows"""
    __tablename__ = "inventory_windows_details"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False, unique=True)
    
    # Windows specifico
    edition = Column(String(100), nullable=True)  # Pro, Enterprise, Server Standard
    product_key = Column(String(50), nullable=True)
    activation_status = Column(String(50), nullable=True)
    
    # Domain
    domain_role = Column(String(50), nullable=True)  # Workstation, Member Server, DC
    domain_name = Column(String(255), nullable=True)
    ou_path = Column(String(500), nullable=True)  # Distinguished Name in AD
    
    # Hardware extra
    bios_version = Column(String(100), nullable=True)
    bios_date = Column(DateTime, nullable=True)
    secure_boot = Column(Boolean, nullable=True)
    tpm_version = Column(String(20), nullable=True)
    
    # Updates
    last_update_check = Column(DateTime, nullable=True)
    pending_updates = Column(Integer, nullable=True)
    last_reboot = Column(DateTime, nullable=True)
    uptime_days = Column(Float, nullable=True)
    
    # Security
    antivirus_name = Column(String(100), nullable=True)
    antivirus_status = Column(String(50), nullable=True)
    firewall_enabled = Column(Boolean, nullable=True)
    bitlocker_status = Column(String(50), nullable=True)
    
    # Users
    local_admins = Column(JSON, nullable=True)  # Lista admin locali
    logged_users = Column(JSON, nullable=True)  # Utenti loggati
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="windows_details")


# ==========================================
# DETTAGLI LINUX
# ==========================================

class LinuxDetails(Base):
    """Dettagli specifici Linux"""
    __tablename__ = "inventory_linux_details"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False, unique=True)
    
    # Distro
    distro_name = Column(String(100), nullable=True)  # Ubuntu, CentOS, Debian
    distro_version = Column(String(50), nullable=True)
    distro_codename = Column(String(50), nullable=True)
    
    # Kernel
    kernel_version = Column(String(100), nullable=True)
    kernel_arch = Column(String(20), nullable=True)
    
    # Package manager
    package_manager = Column(String(20), nullable=True)  # apt, yum, dnf, pacman
    packages_installed = Column(Integer, nullable=True)
    packages_upgradable = Column(Integer, nullable=True)
    
    # System
    init_system = Column(String(20), nullable=True)  # systemd, sysvinit
    selinux_status = Column(String(20), nullable=True)
    
    # Hardware
    virtualization = Column(String(50), nullable=True)  # KVM, VMware, Hyper-V, bare-metal
    
    # Uptime
    last_reboot = Column(DateTime, nullable=True)
    uptime_days = Column(Float, nullable=True)
    load_average = Column(String(50), nullable=True)  # "0.5, 0.3, 0.2"
    
    # Users
    root_login_enabled = Column(Boolean, nullable=True)
    ssh_port = Column(Integer, nullable=True)
    logged_users = Column(JSON, nullable=True)
    
    # Docker/Containers
    docker_installed = Column(Boolean, nullable=True)
    docker_version = Column(String(50), nullable=True)
    containers_running = Column(Integer, nullable=True)
    containers_stopped = Column(Integer, nullable=True)
    containers_total = Column(Integer, nullable=True)
    docker_images_count = Column(Integer, nullable=True)
    
    # CPU dettagliato
    cpu_frequency_mhz = Column(Float, nullable=True)
    cpu_cache_size = Column(String(50), nullable=True)
    cpu_usage_percent = Column(Float, nullable=True)
    cpu_temperature_celsius = Column(Float, nullable=True)
    cpu_load_1min = Column(Float, nullable=True)
    cpu_load_5min = Column(Float, nullable=True)
    cpu_load_15min = Column(Float, nullable=True)
    
    # Memory dettagliato
    memory_available_bytes = Column(BigInteger, nullable=True)
    memory_used_bytes = Column(BigInteger, nullable=True)
    memory_free_bytes = Column(BigInteger, nullable=True)
    memory_cached_bytes = Column(BigInteger, nullable=True)
    memory_buffers_bytes = Column(BigInteger, nullable=True)
    memory_usage_percent = Column(Float, nullable=True)
    swap_total_bytes = Column(BigInteger, nullable=True)
    swap_used_bytes = Column(BigInteger, nullable=True)
    swap_free_bytes = Column(BigInteger, nullable=True)
    swap_usage_percent = Column(Float, nullable=True)
    
    # Storage avanzato (JSON per volumi, RAID, dischi)
    storage_data = Column(JSON, nullable=True)  # Volumi, RAID arrays, storage pools
    disks_data = Column(JSON, nullable=True)  # Dettagli dischi fisici
    network_interfaces_data = Column(JSON, nullable=True)  # Interfacce di rete dettagliate
    services_data = Column(JSON, nullable=True)  # Servizi dettagliati
    vms_data = Column(JSON, nullable=True)  # VM/Container (per Proxmox)
    
    # Network
    default_gateway = Column(String(50), nullable=True)
    dns_servers = Column(JSON, nullable=True)  # Lista DNS servers
    
    # Timezone
    timezone = Column(String(100), nullable=True)
    
    # Boot time
    boot_time = Column(DateTime, nullable=True)
    uptime_seconds = Column(Integer, nullable=True)
    
    # NAS specific (Synology/QNAP)
    nas_model = Column(String(100), nullable=True)
    nas_serial = Column(String(100), nullable=True)
    firmware_version = Column(String(100), nullable=True)
    firmware_build = Column(String(50), nullable=True)
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="linux_details")


# ==========================================
# DETTAGLI MIKROTIK
# ==========================================

class MikroTikDetails(Base):
    """Dettagli specifici MikroTik RouterOS"""
    __tablename__ = "inventory_mikrotik_details"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False, unique=True)
    
    # RouterOS
    routeros_version = Column(String(50), nullable=True)
    routeros_channel = Column(String(20), nullable=True)  # stable, long-term, testing
    firmware_version = Column(String(50), nullable=True)
    factory_firmware = Column(String(50), nullable=True)
    
    # Hardware
    board_name = Column(String(100), nullable=True)
    platform = Column(String(50), nullable=True)  # tile, arm, x86, mipsbe
    cpu_model = Column(String(100), nullable=True)
    cpu_count = Column(Integer, nullable=True)
    cpu_frequency = Column(Integer, nullable=True)  # MHz
    cpu_load = Column(Float, nullable=True)  # %
    
    memory_total_mb = Column(Integer, nullable=True)
    memory_free_mb = Column(Integer, nullable=True)
    hdd_total_mb = Column(Integer, nullable=True)
    hdd_free_mb = Column(Integer, nullable=True)
    
    # Identity
    identity = Column(String(100), nullable=True)
    
    # License
    license_level = Column(String(20), nullable=True)  # free, p1, p2, ...
    license_key = Column(String(50), nullable=True)
    
    # Features enabled
    has_wireless = Column(Boolean, nullable=True)
    has_lte = Column(Boolean, nullable=True)
    has_gps = Column(Boolean, nullable=True)
    
    # Dude Agent
    dude_agent_enabled = Column(Boolean, nullable=True)
    dude_agent_status = Column(String(20), nullable=True)  # connected, disconnected
    dude_server_address = Column(String(100), nullable=True)
    
    # Uptime
    uptime = Column(String(100), nullable=True)
    last_reboot = Column(DateTime, nullable=True)
    
    # Routing
    bgp_peers = Column(Integer, nullable=True)
    ospf_neighbors = Column(Integer, nullable=True)
    
    # Firewall rules count
    filter_rules = Column(Integer, nullable=True)
    nat_rules = Column(Integer, nullable=True)
    mangle_rules = Column(Integer, nullable=True)
    
    # VPN
    ipsec_peers = Column(Integer, nullable=True)
    l2tp_clients = Column(Integer, nullable=True)
    pptp_clients = Column(Integer, nullable=True)
    wireguard_peers = Column(Integer, nullable=True)
    
    # Queues
    simple_queues = Column(Integer, nullable=True)
    queue_trees = Column(Integer, nullable=True)
    
    # Netwatch configured
    netwatch_count = Column(Integer, nullable=True)
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="mikrotik_details")


# ==========================================
# DETTAGLI APPARATI DI RETE GENERICI
# ==========================================

class NetworkDeviceDetails(Base):
    """Dettagli apparati di rete (switch, firewall, AP)"""
    __tablename__ = "inventory_network_device_details"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False, unique=True)
    
    # Tipo apparato
    device_class = Column(String(50), nullable=True)  # switch, router, firewall, ap, controller
    
    # Vendor specific
    vendor = Column(String(50), nullable=True)  # Cisco, HP, Ubiquiti, Fortinet
    firmware_version = Column(String(100), nullable=True)
    
    # Capabilities
    is_managed = Column(Boolean, nullable=True)
    supports_snmp = Column(Boolean, nullable=True)
    snmp_version = Column(String(10), nullable=True)  # v1, v2c, v3
    snmp_community = Column(String(100), nullable=True)
    
    supports_ssh = Column(Boolean, nullable=True)
    supports_telnet = Column(Boolean, nullable=True)
    supports_web = Column(Boolean, nullable=True)
    
    # Switch specifico
    total_ports = Column(Integer, nullable=True)
    ports_up = Column(Integer, nullable=True)
    poe_capable = Column(Boolean, nullable=True)
    poe_budget_watts = Column(Float, nullable=True)
    poe_consumed_watts = Column(Float, nullable=True)
    
    stacking_enabled = Column(Boolean, nullable=True)
    stack_member_id = Column(Integer, nullable=True)
    
    # VLANs
    vlans_configured = Column(JSON, nullable=True)  # [{"id": 10, "name": "Management"}, ...]
    
    # Spanning Tree
    stp_enabled = Column(Boolean, nullable=True)
    stp_root_bridge = Column(Boolean, nullable=True)
    
    # Wireless AP specifico
    ap_clients_connected = Column(Integer, nullable=True)
    ssids_configured = Column(JSON, nullable=True)
    radio_channels = Column(JSON, nullable=True)
    
    # Firewall specifico
    fw_policies_count = Column(Integer, nullable=True)
    fw_active_sessions = Column(Integer, nullable=True)
    vpn_tunnels_count = Column(Integer, nullable=True)
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice", back_populates="network_device_details")


# ==========================================
# NETWATCH / MONITORING CONFIG
# ==========================================

class NetwatchConfig(Base):
    """Configurazione Netwatch su router MikroTik"""
    __tablename__ = "netwatch_configs"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    agent_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=False)
    
    # Target
    name = Column(String(100), nullable=False)
    host = Column(String(255), nullable=False)  # IP o hostname da monitorare
    port = Column(Integer, nullable=True)  # Se vuoto = ICMP
    
    # Timing
    interval = Column(String(20), default="30s")
    timeout = Column(String(20), default="3s")
    
    # Status
    status = Column(String(20), default="unknown")  # up, down, unknown
    last_check = Column(DateTime, nullable=True)
    last_change = Column(DateTime, nullable=True)
    
    # Actions (script RouterOS)
    up_script = Column(Text, nullable=True)
    down_script = Column(Text, nullable=True)
    
    # Config sul router
    mikrotik_id = Column(String(20), nullable=True)  # ID del netwatch su RouterOS
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        Index('idx_netwatch_customer', 'customer_id'),
        Index('idx_netwatch_agent', 'agent_id'),
    )


# ==========================================
# DUDE AGENT REGISTRY
# ==========================================

class DudeAgent(Base):
    """Registry agent The Dude - sincronizzato dal server"""
    __tablename__ = "dude_agents"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    dude_id = Column(String(50), nullable=False, unique=True)  # ID in The Dude
    
    name = Column(String(100), nullable=False)
    address = Column(String(255), nullable=False)
    
    status = Column(String(20), default="unknown")  # online, offline
    version = Column(String(50), nullable=True)
    
    # Collegamento a customer (opzionale)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=True)
    agent_assignment_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=True)
    
    last_seen = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    __table_args__ = (
        Index('idx_dude_agent_dude_id', 'dude_id'),
        Index('idx_dude_agent_customer', 'customer_id'),
    )


# ==========================================
# LLDP/CDP NEIGHBORS
# ==========================================

class LLDPNeighbor(Base):
    """Neighbor LLDP rilevati su switch/router"""
    __tablename__ = "inventory_lldp_neighbors"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    local_interface = Column(String(100), nullable=False)  # ether1, GigabitEthernet0/1
    remote_device_name = Column(String(255), nullable=True)
    remote_device_description = Column(String(500), nullable=True)
    remote_port = Column(String(100), nullable=True)  # Porta remota
    remote_mac = Column(String(20), nullable=True)
    remote_ip = Column(String(50), nullable=True)
    
    chassis_id = Column(String(100), nullable=True)
    chassis_id_type = Column(String(20), nullable=True)  # mac, network, local
    capabilities = Column(JSON, nullable=True)  # {"router": true, "switch": true, "bridge": false}
    
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice")
    
    __table_args__ = (
        Index('idx_lldp_device', 'device_id'),
        Index('idx_lldp_local_interface', 'local_interface'),
        Index('idx_lldp_remote_mac', 'remote_mac'),
    )


class CDPNeighbor(Base):
    """Neighbor CDP rilevati (Cisco)"""
    __tablename__ = "inventory_cdp_neighbors"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False)
    
    local_interface = Column(String(100), nullable=False)
    remote_device_id = Column(String(255), nullable=True)  # Device ID Cisco
    remote_device_name = Column(String(255), nullable=True)
    remote_port = Column(String(100), nullable=True)
    remote_ip = Column(String(50), nullable=True)
    remote_version = Column(String(255), nullable=True)  # IOS version
    platform = Column(String(100), nullable=True)  # Platform type
    capabilities = Column(JSON, nullable=True)  # {"router": true, "switch": true}
    
    last_seen = Column(DateTime, default=func.now())
    created_at = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice")
    
    __table_args__ = (
        Index('idx_cdp_device', 'device_id'),
        Index('idx_cdp_local_interface', 'local_interface'),
        Index('idx_cdp_remote_device_id', 'remote_device_id'),
    )


# ==========================================
# PROXMOX INFORMATION
# ==========================================

class ProxmoxHost(Base):
    """Informazioni host Proxmox"""
    __tablename__ = "inventory_proxmox_hosts"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    device_id = Column(String(8), ForeignKey("inventory_devices.id"), nullable=False, unique=True)
    
    node_name = Column(String(100), nullable=False)
    cluster_name = Column(String(100), nullable=True)
    
    proxmox_version = Column(String(50), nullable=True)
    kernel_version = Column(String(100), nullable=True)
    
    cpu_model = Column(String(200), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    cpu_sockets = Column(Integer, nullable=True)
    cpu_threads = Column(Integer, nullable=True)
    cpu_total_cores = Column(Integer, nullable=True)
    
    memory_total_gb = Column(Float, nullable=True)
    memory_used_gb = Column(Float, nullable=True)
    memory_free_gb = Column(Float, nullable=True)
    memory_usage_percent = Column(Float, nullable=True)
    
    storage_list = Column(JSON, nullable=True)  # Lista storage configurati
    network_interfaces = Column(JSON, nullable=True)  # Configurazione network
    
    license_status = Column(String(50), nullable=True)
    license_message = Column(Text, nullable=True)
    license_level = Column(String(50), nullable=True)
    subscription_type = Column(String(50), nullable=True)
    subscription_key = Column(String(255), nullable=True)
    
    uptime_seconds = Column(Integer, nullable=True)
    uptime_human = Column(String(100), nullable=True)
    
    load_average_1m = Column(Float, nullable=True)
    load_average_5m = Column(Float, nullable=True)
    load_average_15m = Column(Float, nullable=True)
    
    cpu_usage_percent = Column(Float, nullable=True)
    io_delay_percent = Column(Float, nullable=True)
    
    # Swap info
    swap_total_gb = Column(Float, nullable=True)
    swap_used_gb = Column(Float, nullable=True)
    swap_free_gb = Column(Float, nullable=True)
    swap_usage_percent = Column(Float, nullable=True)
    
    # Rootfs info
    rootfs_total_gb = Column(Float, nullable=True)
    rootfs_used_gb = Column(Float, nullable=True)
    rootfs_free_gb = Column(Float, nullable=True)
    rootfs_usage_percent = Column(Float, nullable=True)
    
    # KSM sharing
    ksm_sharing_gb = Column(Float, nullable=True)
    
    # Subscription dettagliata
    subscription_server_id = Column(String(255), nullable=True)
    subscription_sockets = Column(Integer, nullable=True)
    subscription_last_check = Column(String(100), nullable=True)
    subscription_next_due = Column(String(100), nullable=True)
    
    # Repository status
    repository_status = Column(Text, nullable=True)
    
    # Boot mode
    boot_mode = Column(String(50), nullable=True)
    
    # Manager version
    manager_version = Column(String(50), nullable=True)
    
    # Temperature
    temperature_summary = Column(JSON, nullable=True)  # Lista temperature formattate
    temperature_highest_c = Column(Float, nullable=True)  # Temperatura più alta
    
    # BIOS info
    bios_vendor = Column(String(100), nullable=True)
    bios_version = Column(String(100), nullable=True)
    bios_release_date = Column(String(50), nullable=True)
    
    # System info
    system_manufacturer = Column(String(100), nullable=True)
    system_product = Column(String(200), nullable=True)
    system_serial = Column(String(100), nullable=True)
    
    # Board info
    board_vendor = Column(String(100), nullable=True)
    board_name = Column(String(200), nullable=True)
    
    # Boot devices
    boot_devices = Column(JSON, nullable=True)  # Lista formattata dispositivi boot
    boot_devices_details = Column(JSON, nullable=True)  # Dettagli completi dispositivi boot
    boot_entries = Column(JSON, nullable=True)  # Entries EFI boot
    
    # Hardware info (lshw)
    hardware_system = Column(JSON, nullable=True)
    hardware_bus = Column(JSON, nullable=True)
    hardware_memory = Column(JSON, nullable=True)
    hardware_processor = Column(JSON, nullable=True)
    hardware_storage = Column(JSON, nullable=True)
    hardware_disk = Column(JSON, nullable=True)
    hardware_volume = Column(JSON, nullable=True)
    hardware_network = Column(JSON, nullable=True)
    hardware_product = Column(String(200), nullable=True)
    
    # PCI/USB devices
    pci_devices = Column(JSON, nullable=True)  # Lista dispositivi PCI
    usb_devices = Column(JSON, nullable=True)  # Lista dispositivi USB
    
    last_updated = Column(DateTime, default=func.now())
    
    device = relationship("InventoryDevice")
    
    __table_args__ = (
        Index('idx_proxmox_host_device', 'device_id'),
        Index('idx_proxmox_host_node', 'node_name'),
    )


class ProxmoxVM(Base):
    """Informazioni VM Proxmox"""
    __tablename__ = "inventory_proxmox_vms"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    host_id = Column(String(8), ForeignKey("inventory_proxmox_hosts.id"), nullable=False)
    
    vm_id = Column(Integer, nullable=False)  # ID VM in Proxmox (100, 101, ecc.)
    name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=True)  # running, stopped, paused
    
    vm_type = Column(String(20), nullable=True)  # qemu, lxc
    cpu_cores = Column(Integer, nullable=True)
    cpu_sockets = Column(Integer, nullable=True)
    cpu_total = Column(Integer, nullable=True)
    memory_mb = Column(Integer, nullable=True)
    disk_total_gb = Column(Float, nullable=True)
    
    # BIOS e Machine
    bios = Column(String(50), nullable=True)  # seabios, ovmf
    machine = Column(String(50), nullable=True)  # pc, q35, ecc.
    agent_installed = Column(Boolean, nullable=True)
    
    # Network
    network_interfaces = Column(JSON, nullable=True)  # Lista interfacce di rete dettagliate
    num_networks = Column(Integer, nullable=True)
    networks = Column(String(500), nullable=True)  # Lista nomi interfacce (net0, net1, ecc.)
    ip_addresses = Column(String(500), nullable=True)  # IP addresses separati da "; "
    
    # Dischi
    num_disks = Column(Integer, nullable=True)
    disks = Column(String(500), nullable=True)  # Lista nomi dischi (scsi0, virtio0, ecc.)
    disks_details = Column(JSON, nullable=True)  # Dettagli dischi
    
    os_type = Column(String(50), nullable=True)  # l26, win10, win11, ecc.
    template = Column(Boolean, default=False)
    
    # Performance metrics
    uptime = Column(BigInteger, nullable=True)  # Uptime in secondi (può essere molto grande)
    cpu_usage = Column(Float, nullable=True)  # CPU usage percentuale
    mem_used = Column(BigInteger, nullable=True)  # Memoria usata in bytes (può superare INTEGER max)
    netin = Column(BigInteger, nullable=True)  # Network in bytes (può superare INTEGER max)
    netout = Column(BigInteger, nullable=True)  # Network out bytes (può superare INTEGER max)
    diskread = Column(BigInteger, nullable=True)  # Disk read bytes (può superare INTEGER max)
    diskwrite = Column(BigInteger, nullable=True)  # Disk write bytes (può superare INTEGER max)
    
    backup_enabled = Column(Boolean, nullable=True)
    last_backup = Column(DateTime, nullable=True)
    
    created_at = Column(DateTime, nullable=True)  # Data creazione VM
    last_updated = Column(DateTime, default=func.now())
    
    host = relationship("ProxmoxHost")
    
    __table_args__ = (
        Index('idx_proxmox_vm_host', 'host_id'),
        Index('idx_proxmox_vm_vm_id', 'vm_id'),
        Index('idx_proxmox_vm_status', 'status'),
    )


class ProxmoxStorage(Base):
    """Storage Proxmox"""
    __tablename__ = "inventory_proxmox_storage"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    host_id = Column(String(8), ForeignKey("inventory_proxmox_hosts.id"), nullable=False)
    
    storage_name = Column(String(100), nullable=False)
    storage_type = Column(String(50), nullable=True)  # dir, lvm, lvm-thin, zfs, nfs, cifs
    content_types = Column(JSON, nullable=True)  # ["images", "iso", "backup"]
    
    total_gb = Column(Float, nullable=True)
    used_gb = Column(Float, nullable=True)
    available_gb = Column(Float, nullable=True)
    usage_percent = Column(Float, nullable=True)
    
    last_updated = Column(DateTime, default=func.now())
    
    host = relationship("ProxmoxHost")
    
    __table_args__ = (
        Index('idx_proxmox_storage_host', 'host_id'),
        Index('idx_proxmox_storage_name', 'storage_name'),
    )


class ProxmoxBackup(Base):
    """Backup Proxmox"""
    __tablename__ = "inventory_proxmox_backups"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    vm_id = Column(String(8), ForeignKey("inventory_proxmox_vms.id"), nullable=False)
    
    backup_id = Column(String(255), nullable=False)  # ID backup in Proxmox
    backup_type = Column(String(20), nullable=True)  # vzdump, pbs
    size_gb = Column(Float, nullable=True)
    status = Column(String(20), nullable=True)  # ok, failed, running
    
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    
    vm = relationship("ProxmoxVM")
    
    __table_args__ = (
        Index('idx_proxmox_backup_vm', 'vm_id'),
        Index('idx_proxmox_backup_status', 'status'),
        Index('idx_proxmox_backup_start_time', 'start_time'),
    )
