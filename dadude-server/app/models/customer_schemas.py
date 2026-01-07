"""
DaDude - Customer/Tenant Schemas
Modelli Pydantic per gestione clienti multi-tenant
"""
from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import re


class NetworkType(str, Enum):
    """Tipi di rete"""
    LAN = "lan"
    WAN = "wan"
    DMZ = "dmz"
    GUEST = "guest"
    MANAGEMENT = "management"
    VOIP = "voip"
    IOT = "iot"
    OTHER = "other"


class CredentialType(str, Enum):
    """Tipi di credenziali"""
    DEVICE = "device"
    SNMP = "snmp"
    API = "api"
    VPN = "vpn"
    SSH = "ssh"
    WMI = "wmi"
    MIKROTIK = "mikrotik"
    OTHER = "other"


class DeviceRole(str, Enum):
    """Ruoli dispositivo"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    ACCESS_POINT = "access_point"
    SERVER = "server"
    NAS = "nas"
    UPS = "ups"
    PRINTER = "printer"
    CAMERA = "camera"
    OTHER = "other"


class ContractType(str, Enum):
    """Tipi contratto"""
    STANDARD = "standard"
    PREMIUM = "premium"
    H24 = "24x7"
    ON_DEMAND = "on_demand"


class SLALevel(str, Enum):
    """Livelli SLA"""
    GOLD = "gold"
    SILVER = "silver"
    BRONZE = "bronze"


# ============================================
# Customer Schemas
# ============================================

class CustomerBase(BaseModel):
    """Base schema cliente"""
    code: str = Field(..., min_length=2, max_length=20, description="Codice univoco cliente")
    name: str = Field(..., min_length=2, max_length=255, description="Nome cliente")
    description: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v):
        # Solo alfanumerici e underscore/trattino
        if not re.match(r'^[A-Za-z0-9_-]+$', v):
            raise ValueError('Il codice può contenere solo lettere, numeri, _ e -')
        return v.upper()


class CustomerCreate(CustomerBase):
    """Schema creazione cliente"""
    pass


class CustomerUpdate(BaseModel):
    """Schema aggiornamento cliente"""
    name: Optional[str] = None
    description: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    address: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = None


class Customer(CustomerBase):
    """Schema cliente completo"""
    id: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CustomerWithDetails(Customer):
    """Cliente con dettagli (reti, credenziali, device)"""
    networks: List["Network"] = []
    credentials: List["CredentialSafe"] = []  # Senza password
    device_count: int = 0


# ============================================
# Network Schemas
# ============================================

class NetworkBase(BaseModel):
    """Base schema rete"""
    name: str = Field(..., min_length=2, max_length=100)
    network_type: NetworkType = NetworkType.LAN
    ip_network: str = Field(..., description="CIDR notation, es: 192.168.1.0/24")
    gateway: Optional[str] = None
    vlan_id: Optional[int] = Field(None, ge=1, le=4094)
    vlan_name: Optional[str] = None
    dns_primary: Optional[str] = None
    dns_secondary: Optional[str] = None
    dhcp_start: Optional[str] = None
    dhcp_end: Optional[str] = None
    gateway_agent_id: Optional[str] = Field(None, description="MikroTik agent ID per ARP lookup su reti remote")
    # Alternativa SNMP per router non-MikroTik
    gateway_snmp_address: Optional[str] = Field(None, description="IP router per ARP via SNMP")
    gateway_snmp_community: Optional[str] = Field(None, description="SNMP community string")
    gateway_snmp_version: Optional[str] = Field(None, description="SNMP version: 1, 2c, 3")
    description: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True
    
    @field_validator('ip_network')
    @classmethod
    def validate_cidr(cls, v):
        # Validazione base CIDR
        pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if not re.match(pattern, v):
            raise ValueError('Formato IP network non valido (usa CIDR: x.x.x.x/xx)')
        return v


class NetworkCreate(NetworkBase):
    """Schema creazione rete"""
    customer_id: Optional[str] = None  # Opzionale, viene impostato dal router


class NetworkUpdate(BaseModel):
    """Schema aggiornamento rete"""
    name: Optional[str] = None
    network_type: Optional[NetworkType] = None
    ip_network: Optional[str] = None
    gateway: Optional[str] = None
    vlan_id: Optional[int] = None
    vlan_name: Optional[str] = None
    dns_primary: Optional[str] = None
    dns_secondary: Optional[str] = None
    dhcp_start: Optional[str] = None
    dhcp_end: Optional[str] = None
    gateway_agent_id: Optional[str] = None
    gateway_snmp_address: Optional[str] = None
    gateway_snmp_community: Optional[str] = None
    gateway_snmp_version: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = None


class Network(NetworkBase):
    """Schema rete completo"""
    id: str
    customer_id: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ============================================
# Credential Schemas
# ============================================

class CredentialBase(BaseModel):
    """Base schema credenziali"""
    name: str = Field(..., min_length=2, max_length=100)
    credential_type: CredentialType = CredentialType.DEVICE
    username: Optional[str] = None
    # SSH
    ssh_port: Optional[int] = Field(None, ge=1, le=65535)
    ssh_key_type: Optional[str] = None  # rsa, ed25519, etc
    # SNMP
    snmp_community: Optional[str] = None
    snmp_version: Optional[str] = Field(None, pattern="^(1|2c|3)$")  # 1, 2c, 3
    snmp_port: Optional[int] = Field(None, ge=1, le=65535)
    snmp_security_level: Optional[str] = None  # noAuthNoPriv, authNoPriv, authPriv
    snmp_auth_protocol: Optional[str] = None  # MD5, SHA
    snmp_priv_protocol: Optional[str] = None  # DES, AES
    # WMI
    wmi_domain: Optional[str] = None
    wmi_namespace: Optional[str] = None  # default: root/cimv2
    # MikroTik API
    mikrotik_api_port: Optional[int] = Field(None, ge=1, le=65535)
    mikrotik_api_ssl: Optional[bool] = None
    # API generico
    api_endpoint: Optional[str] = None
    # VPN
    vpn_type: Optional[str] = None
    # Common
    is_default: bool = False
    device_filter: Optional[str] = None  # Regex per filtrare device
    description: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True


class CredentialCreate(CredentialBase):
    """Schema creazione credenziali (con password)"""
    customer_id: Optional[str] = None  # Opzionale, viene impostato dal router
    is_global: bool = False  # True = credenziale globale disponibile a tutti
    password: Optional[str] = None
    # SSH
    ssh_private_key: Optional[str] = None
    ssh_passphrase: Optional[str] = None
    # SNMP v3
    snmp_auth_password: Optional[str] = None
    snmp_priv_password: Optional[str] = None
    # API
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    # VPN
    vpn_config: Optional[str] = None


class CredentialUpdate(BaseModel):
    """Schema aggiornamento credenziali"""
    name: Optional[str] = None
    credential_type: Optional[CredentialType] = None
    username: Optional[str] = None
    password: Optional[str] = None
    # SSH
    ssh_port: Optional[int] = None
    ssh_private_key: Optional[str] = None
    ssh_passphrase: Optional[str] = None
    ssh_key_type: Optional[str] = None
    # SNMP
    snmp_community: Optional[str] = None
    snmp_version: Optional[str] = None
    snmp_port: Optional[int] = None
    snmp_security_level: Optional[str] = None
    snmp_auth_protocol: Optional[str] = None
    snmp_auth_password: Optional[str] = None
    snmp_priv_protocol: Optional[str] = None
    snmp_priv_password: Optional[str] = None
    # WMI
    wmi_domain: Optional[str] = None
    wmi_namespace: Optional[str] = None
    # MikroTik
    mikrotik_api_port: Optional[int] = None
    mikrotik_api_ssl: Optional[bool] = None
    # API
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    api_endpoint: Optional[str] = None
    # VPN
    vpn_type: Optional[str] = None
    vpn_config: Optional[str] = None
    # Common
    is_default: Optional[bool] = None
    device_filter: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = None


class Credential(CredentialBase):
    """Schema credenziali completo (con password - uso interno)"""
    id: str
    customer_id: Optional[str] = None  # NULL = credenziale globale
    is_global: bool = False
    password: Optional[str] = None
    # SSH secrets
    ssh_private_key: Optional[str] = None
    ssh_passphrase: Optional[str] = None
    # SNMP secrets
    snmp_auth_password: Optional[str] = None
    snmp_priv_password: Optional[str] = None
    # API secrets
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    # VPN secrets
    vpn_config: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CredentialSafe(CredentialBase):
    """Schema credenziali senza dati sensibili (per API)"""
    id: str
    customer_id: Optional[str] = None  # NULL = credenziale globale
    is_global: bool = False
    has_password: bool = False
    has_ssh_key: bool = False
    has_api_key: bool = False
    has_vpn_config: bool = False
    used_by_count: int = 0  # Quanti clienti usano questa credenziale
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ============================================
# Device Assignment Schemas
# ============================================

class DeviceAssignmentBase(BaseModel):
    """Base schema assegnazione device"""
    dude_device_id: str = Field(..., description="ID device dal Dude")
    dude_device_name: Optional[str] = None
    local_name: Optional[str] = None
    location: Optional[str] = None
    role: Optional[DeviceRole] = None
    management_ip: Optional[str] = None
    # Hardware/Software Inventory Data
    serial_number: Optional[str] = None
    os_version: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_total_mb: Optional[int] = None
    disk_total_gb: Optional[int] = None
    disk_free_gb: Optional[int] = None
    # Porte aperte rilevate
    open_ports: Optional[List[Dict[str, Any]]] = None  # [{"port": 80, "protocol": "tcp", "service": "http", "open": true}, ...]
    contract_type: Optional[ContractType] = None
    sla_level: Optional[SLALevel] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict[str, Any]] = None
    active: bool = True
    monitored: bool = True


class DeviceAssignmentCreate(DeviceAssignmentBase):
    """Schema creazione assegnazione"""
    customer_id: Optional[str] = None  # Opzionale, viene impostato dal router
    primary_network_id: Optional[str] = None
    credential_id: Optional[str] = None


class DeviceAssignmentUpdate(BaseModel):
    """Schema aggiornamento assegnazione"""
    customer_id: Optional[str] = None
    local_name: Optional[str] = None
    location: Optional[str] = None
    role: Optional[DeviceRole] = None
    primary_network_id: Optional[str] = None
    management_ip: Optional[str] = None
    # Hardware/Software Inventory Data
    serial_number: Optional[str] = None
    os_version: Optional[str] = None
    cpu_model: Optional[str] = None
    cpu_cores: Optional[int] = None
    ram_total_mb: Optional[int] = None
    disk_total_gb: Optional[int] = None
    disk_free_gb: Optional[int] = None
    # Porte aperte rilevate
    open_ports: Optional[List[Dict[str, Any]]] = None
    credential_id: Optional[str] = None
    contract_type: Optional[ContractType] = None
    sla_level: Optional[SLALevel] = None
    notes: Optional[str] = None
    tags: Optional[List[str]] = None
    custom_fields: Optional[Dict[str, Any]] = None
    active: Optional[bool] = None
    monitored: Optional[bool] = None


class DeviceAssignment(DeviceAssignmentBase):
    """Schema assegnazione completo"""
    id: str
    customer_id: str
    primary_network_id: Optional[str] = None
    credential_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class DeviceAssignmentWithDetails(DeviceAssignment):
    """Assegnazione con dettagli relazioni"""
    customer: Optional[Customer] = None
    primary_network: Optional[Network] = None
    credential: Optional[CredentialSafe] = None


# ============================================
# Response Schemas
# ============================================

class CustomerListResponse(BaseModel):
    """Response lista clienti"""
    total: int
    customers: List[Customer]


class NetworkListResponse(BaseModel):
    """Response lista reti"""
    total: int
    networks: List[Network]


class CredentialListResponse(BaseModel):
    """Response lista credenziali"""
    total: int
    credentials: List[CredentialSafe]


class DeviceAssignmentListResponse(BaseModel):
    """Response lista assegnazioni"""
    total: int
    assignments: List[DeviceAssignment]


# ============================================
# Agent/Sonda Schemas
# ============================================

class AgentType(str, Enum):
    """Tipi di agent"""
    MIKROTIK = "mikrotik"  # RouterOS nativo (API + SSH)
    DOCKER = "docker"      # DaDude Agent container


class AgentAssignmentBase(BaseModel):
    """Base schema sonda assegnata"""
    name: str = Field(..., min_length=2, max_length=100)
    address: str = Field(..., description="IP o hostname della sonda")
    port: int = Field(8728, ge=1, le=65535, description="Porta API RouterOS")
    
    # Tipo agent
    agent_type: AgentType = Field(AgentType.MIKROTIK, description="Tipo: mikrotik, docker")
    
    # Ubicazione
    location: Optional[str] = None
    site_name: Optional[str] = None
    
    # Tipo connessione (per MikroTik)
    connection_type: str = Field("api", description="Tipo: api, ssh, both")
    
    # Credenziali sonda (MikroTik)
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = False
    
    # SSH settings (MikroTik)
    ssh_port: int = Field(22, ge=1, le=65535, description="Porta SSH")
    ssh_key: Optional[str] = Field(None, description="Chiave privata SSH")
    
    # Docker Agent settings
    agent_api_port: int = Field(8080, ge=1, le=65535, description="Porta API agent Docker")
    agent_token: Optional[str] = Field(None, description="Token autenticazione agent")
    agent_url: Optional[str] = Field(None, description="URL completo agent (se diverso)")
    
    # DNS per reverse lookup
    dns_server: Optional[str] = Field(None, description="IP DNS locale per reverse lookup")
    
    # Configurazione scansioni
    default_scan_type: str = "ping"
    auto_add_devices: bool = False
    
    # Per agent MikroTik: Docker agent remoto per eseguire comandi
    docker_agent_id: Optional[str] = Field(None, description="ID agent Docker per eseguire comandi remoti")
    
    # Per agent Docker: Gateway per risoluzione ARP
    arp_gateway_agent_id: Optional[str] = Field(None, description="ID agent MikroTik per ARP resolution")
    arp_gateway_snmp_address: Optional[str] = Field(None, description="IP device SNMP per ARP resolution")
    arp_gateway_snmp_community: Optional[str] = Field(None, description="SNMP community per ARP")
    arp_gateway_snmp_version: Optional[str] = Field(None, description="SNMP version (1, 2c, 3)")
    
    description: Optional[str] = None
    notes: Optional[str] = None
    active: bool = True


class AgentAssignmentCreate(AgentAssignmentBase):
    """Schema creazione sonda"""
    customer_id: Optional[str] = None  # Impostato dal router
    dude_agent_id: Optional[str] = None
    assigned_networks: Optional[List[str]] = None  # Lista ID reti


class AgentAssignmentUpdate(BaseModel):
    """Schema aggiornamento sonda"""
    name: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None
    agent_type: Optional[AgentType] = None
    location: Optional[str] = None
    site_name: Optional[str] = None
    connection_type: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: Optional[bool] = None
    ssh_port: Optional[int] = None
    ssh_key: Optional[str] = None
    agent_api_port: Optional[int] = None
    agent_token: Optional[str] = None
    agent_url: Optional[str] = None
    dns_server: Optional[str] = None
    default_scan_type: Optional[str] = None
    auto_add_devices: Optional[bool] = None
    assigned_networks: Optional[List[str]] = None
    dude_agent_id: Optional[str] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = None


class AgentAssignment(AgentAssignmentBase):
    """Schema sonda completo"""
    id: str
    customer_id: Optional[str] = None  # Nullable per agent in attesa di approvazione
    dude_agent_id: Optional[str] = None
    status: str = "unknown"
    last_seen: Optional[datetime] = None
    version: Optional[str] = None
    assigned_networks: Optional[List[str]] = None
    docker_agent_id: Optional[str] = None
    arp_gateway_agent_id: Optional[str] = None
    arp_gateway_snmp_address: Optional[str] = None
    arp_gateway_snmp_community: Optional[str] = None
    arp_gateway_snmp_version: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class AgentAssignmentSafe(BaseModel):
    """Schema sonda senza password, token e chiave SSH"""
    id: str
    customer_id: Optional[str] = None  # Nullable per agent in attesa di approvazione
    name: str
    address: str
    port: Optional[int] = 8728
    docker_agent_id: Optional[str] = None
    arp_gateway_agent_id: Optional[str] = None
    arp_gateway_snmp_address: Optional[str] = None
    arp_gateway_snmp_community: Optional[str] = None
    arp_gateway_snmp_version: Optional[str] = None
    agent_type: Optional[str] = "mikrotik"
    dude_agent_id: Optional[str] = None
    status: Optional[str] = "unknown"
    last_seen: Optional[datetime] = None
    version: Optional[str] = None
    location: Optional[str] = None
    site_name: Optional[str] = None
    connection_type: Optional[str] = "api"
    username: Optional[str] = None
    use_ssl: Optional[bool] = False
    ssh_port: Optional[int] = 22
    agent_api_port: Optional[int] = 8080
    agent_url: Optional[str] = None
    dns_server: Optional[str] = None
    default_scan_type: Optional[str] = "ping"
    auto_add_devices: Optional[bool] = False
    assigned_networks: Optional[List[str]] = None
    description: Optional[str] = None
    notes: Optional[str] = None
    active: Optional[bool] = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    @model_validator(mode='before')
    @classmethod
    def set_defaults(cls, values):
        """Imposta valori di default per campi NULL"""
        if isinstance(values, dict):
            defaults = {
                'port': 8728, 'agent_type': 'mikrotik', 'status': 'unknown',
                'connection_type': 'api', 'use_ssl': False, 'ssh_port': 22,
                'agent_api_port': 8080, 'default_scan_type': 'ping',
                'auto_add_devices': False, 'active': True
            }
            for key, default in defaults.items():
                if key in values and values[key] is None:
                    values[key] = default
        return values
    
    class Config:
        from_attributes = True


class AgentAssignmentListResponse(BaseModel):
    """Response lista sonde"""
    total: int
    agents: List[AgentAssignmentSafe]


# Forward references per relazioni circolari
CustomerWithDetails.model_rebuild()
