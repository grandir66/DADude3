"""
DaDude - Database Models
Modelli SQLAlchemy per persistenza dati
"""
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, ForeignKey,
    JSON, UniqueConstraint, Index, create_engine
)
from sqlalchemy.orm import relationship, declarative_base, sessionmaker
from sqlalchemy.sql import func
from datetime import datetime
import uuid

Base = declarative_base()


def generate_uuid():
    return str(uuid.uuid4())[:8]


class Customer(Base):
    """
    Cliente/Tenant
    Ogni cliente ha un codice univoco e può avere più dispositivi
    """
    __tablename__ = "customers"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    code = Column(String(20), unique=True, nullable=False, index=True)  # Es: "CUST001"
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    contact_name = Column(String(255), nullable=True)
    contact_email = Column(String(255), nullable=True)
    contact_phone = Column(String(50), nullable=True)
    address = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    networks = relationship("Network", back_populates="customer", cascade="all, delete-orphan")
    credentials = relationship("Credential", back_populates="customer", cascade="all, delete-orphan")
    devices = relationship("DeviceAssignment", back_populates="customer", cascade="all, delete-orphan")
    agents = relationship("AgentAssignment", back_populates="customer", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Customer {self.code}: {self.name}>"


class Network(Base):
    """
    Rete IP/VLAN associata a un cliente
    Le reti possono sovrapporsi tra clienti diversi (es: 192.168.1.0/24 usata da più clienti)
    """
    __tablename__ = "networks"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    
    name = Column(String(100), nullable=False)  # Es: "LAN Uffici", "DMZ", "Guest"
    network_type = Column(String(50), default="lan")  # lan, wan, dmz, guest, management, voip
    
    # Network details
    ip_network = Column(String(50), nullable=False)  # Es: "192.168.1.0/24"
    gateway = Column(String(50), nullable=True)       # Es: "192.168.1.1"
    vlan_id = Column(Integer, nullable=True)          # Es: 100
    vlan_name = Column(String(100), nullable=True)    # Es: "VLAN_UFFICI"
    
    # DNS
    dns_primary = Column(String(50), nullable=True)
    dns_secondary = Column(String(50), nullable=True)
    
    # DHCP range (se applicabile)
    dhcp_start = Column(String(50), nullable=True)
    dhcp_end = Column(String(50), nullable=True)
    
    # Gateway router per ARP lookup su reti remote
    # Se specificato, usa questo agent per leggere la tabella ARP
    gateway_agent_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=True)
    
    # Alternativa: gateway SNMP generico (per router non-MikroTik)
    # Se gateway_agent_id è NULL ma questi sono valorizzati, usa SNMP
    gateway_snmp_address = Column(String(50), nullable=True)  # IP del router
    gateway_snmp_community = Column(String(100), nullable=True)  # Community string
    gateway_snmp_version = Column(String(10), nullable=True)  # 1, 2c, 3
    
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationship
    customer = relationship("Customer", back_populates="networks")
    
    # Index per ricerche veloci
    __table_args__ = (
        Index('idx_network_customer', 'customer_id'),
        Index('idx_network_vlan', 'vlan_id'),
    )
    
    def __repr__(self):
        return f"<Network {self.name}: {self.ip_network} (VLAN {self.vlan_id})>"


class Credential(Base):
    """
    Credenziali per accesso ai dispositivi del cliente
    Possono essere di default per il cliente o specifiche per device
    Credenziali globali hanno customer_id=NULL e is_global=True
    """
    __tablename__ = "credentials"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=True)  # NULL = globale
    is_global = Column(Boolean, default=False)  # True = disponibile per tutti i clienti
    
    name = Column(String(100), nullable=False)  # Es: "Router Admin", "Switch Default"
    credential_type = Column(String(50), default="device")  # device, snmp, ssh, wmi, mikrotik, api, vpn, other
    
    # Credenziali base
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)  # Encrypted
    
    # SSH
    ssh_port = Column(Integer, nullable=True)
    ssh_private_key = Column(Text, nullable=True)  # Encrypted
    ssh_passphrase = Column(String(255), nullable=True)  # Encrypted
    ssh_key_type = Column(String(20), nullable=True)  # rsa, ed25519, ecdsa
    
    # SNMP
    snmp_community = Column(String(100), nullable=True)
    snmp_version = Column(String(10), nullable=True)  # 1, 2c, 3
    snmp_port = Column(Integer, nullable=True)
    snmp_security_level = Column(String(20), nullable=True)  # noAuthNoPriv, authNoPriv, authPriv
    snmp_auth_protocol = Column(String(20), nullable=True)  # MD5, SHA
    snmp_priv_protocol = Column(String(20), nullable=True)  # DES, AES
    snmp_auth_password = Column(String(255), nullable=True)  # Encrypted
    snmp_priv_password = Column(String(255), nullable=True)  # Encrypted
    
    # WMI
    wmi_domain = Column(String(255), nullable=True)
    wmi_namespace = Column(String(255), nullable=True)  # default: root/cimv2
    
    # MikroTik API
    mikrotik_api_port = Column(Integer, nullable=True)  # default: 8728
    mikrotik_api_ssl = Column(Boolean, nullable=True)
    
    # API generico
    api_key = Column(String(500), nullable=True)  # Encrypted
    api_secret = Column(String(500), nullable=True)  # Encrypted
    api_endpoint = Column(String(500), nullable=True)
    
    # VPN
    vpn_type = Column(String(50), nullable=True)  # ipsec, openvpn, wireguard
    vpn_config = Column(Text, nullable=True)  # Configurazione VPN (JSON o testo)
    
    # Scope
    is_default = Column(Boolean, default=False)  # Credenziale di default per il cliente
    device_filter = Column(String(255), nullable=True)  # Pattern per matching device (es: "router-*")
    
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationship
    customer = relationship("Customer", back_populates="credentials")
    
    __table_args__ = (
        Index('idx_credential_customer', 'customer_id'),
        Index('idx_credential_type', 'credential_type'),
    )
    
    def __repr__(self):
        return f"<Credential {self.name} ({self.credential_type})>"


class CustomerCredentialLink(Base):
    """
    Associazione Credenziale → Cliente
    Permette di linkare credenziali centrali ai clienti che le usano
    Una credenziale può essere usata da più clienti
    """
    __tablename__ = "customer_credential_links"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    credential_id = Column(String(8), ForeignKey("credentials.id"), nullable=False)
    
    # Se True, questa credenziale è il default per questo tipo per questo cliente
    is_default = Column(Boolean, default=False)
    
    # Note specifiche per questa associazione
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    customer = relationship("Customer", backref="credential_links")
    credential = relationship("Credential", backref="customer_links")
    
    __table_args__ = (
        UniqueConstraint('customer_id', 'credential_id', name='uq_customer_credential'),
        Index('idx_cred_link_customer', 'customer_id'),
        Index('idx_cred_link_credential', 'credential_id'),
    )
    
    def __repr__(self):
        return f"<CustomerCredentialLink {self.customer_id} -> {self.credential_id}>"


class DeviceAssignment(Base):
    """
    Associazione Device Dude → Cliente
    Permette di tracciare quale device appartiene a quale cliente
    """
    __tablename__ = "device_assignments"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    
    # Riferimento al device Dude (ID dal Dude)
    dude_device_id = Column(String(50), nullable=False, unique=True, index=True)
    dude_device_name = Column(String(255), nullable=True)
    
    # Cliente associato
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    
    # Info aggiuntive sul device per questo cliente
    local_name = Column(String(255), nullable=True)  # Nome locale/alias
    location = Column(String(255), nullable=True)    # Sede/ubicazione
    role = Column(String(100), nullable=True)        # router, switch, firewall, server, ap
    
    # Rete principale del device
    primary_network_id = Column(String(8), ForeignKey("networks.id"), nullable=True)
    management_ip = Column(String(50), nullable=True)
    
    # Hardware/Software Inventory Data
    serial_number = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    cpu_model = Column(String(255), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    ram_total_mb = Column(Integer, nullable=True)
    disk_total_gb = Column(Integer, nullable=True)
    disk_free_gb = Column(Integer, nullable=True)
    
    # Porte aperte rilevate (TCP/UDP)
    open_ports = Column(JSON, nullable=True)  # [{"port": 80, "protocol": "tcp", "service": "http", "open": true}, ...]
    
    # Credenziali specifiche per questo device
    credential_id = Column(String(8), ForeignKey("credentials.id"), nullable=True)
    
    # Contratto/SLA
    contract_type = Column(String(50), nullable=True)  # standard, premium, 24x7
    sla_level = Column(String(20), nullable=True)      # gold, silver, bronze
    
    notes = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # Lista tag per categorizzazione
    custom_fields = Column(JSON, nullable=True)  # Campi custom
    
    active = Column(Boolean, default=True)
    monitored = Column(Boolean, default=True)  # Se monitorare attivamente
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    customer = relationship("Customer", back_populates="devices")
    primary_network = relationship("Network", foreign_keys=[primary_network_id])
    credential = relationship("Credential", foreign_keys=[credential_id])
    
    __table_args__ = (
        Index('idx_assignment_customer', 'customer_id'),
        Index('idx_assignment_dude_id', 'dude_device_id'),
    )
    
    def __repr__(self):
        return f"<DeviceAssignment {self.dude_device_name} -> {self.customer_id}>"


class AlertHistory(Base):
    """
    Storico alert per analisi e reporting
    """
    __tablename__ = "alert_history"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Riferimenti
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=True)
    dude_device_id = Column(String(50), nullable=True, index=True)
    device_name = Column(String(255), nullable=True)
    
    # Alert info
    alert_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)  # critical, warning, info
    message = Column(Text, nullable=True)
    
    # Status tracking
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), index=True)
    
    # Extra data
    extra_data = Column(JSON, nullable=True)
    
    __table_args__ = (
        Index('idx_alert_customer', 'customer_id'),
        Index('idx_alert_created', 'created_at'),
        Index('idx_alert_severity', 'severity'),
    )


class AgentAssignment(Base):
    """
    Sonda/Agent assegnata a un cliente
    Le sonde possono essere registrate manualmente o sincronizzate da The Dude
    """
    __tablename__ = "agent_assignments"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    
    # Riferimento all'agent Dude (se esiste)
    dude_agent_id = Column(String(50), nullable=True, index=True)
    
    # Cliente associato (nullable per agent in attesa di approvazione)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=True)
    
    # Info sonda
    name = Column(String(100), nullable=False)  # Nome descrittivo
    address = Column(String(255), nullable=False)  # IP o hostname della sonda
    port = Column(Integer, default=8728)  # Porta API
    
    # Stato
    status = Column(String(20), default="unknown")  # online, offline, unknown
    last_seen = Column(DateTime, nullable=True)
    version = Column(String(50), nullable=True)
    
    # Ubicazione
    location = Column(String(255), nullable=True)  # Sede cliente
    site_name = Column(String(100), nullable=True)  # Nome sito (es: "Milano HQ")
    
    # Credenziali per connessione alla sonda
    username = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)  # Encrypted
    use_ssl = Column(Boolean, default=False)
    
    # Tipo connessione: api (RouterOS API), ssh, both
    connection_type = Column(String(20), default="api")
    
    # SSH settings
    ssh_port = Column(Integer, default=22)
    ssh_key = Column(Text, nullable=True)  # Chiave privata SSH (encrypted)
    
    # Tipo agent: mikrotik (RouterOS nativo), docker (DaDude Agent container)
    agent_type = Column(String(20), default="mikrotik")  # mikrotik, docker
    
    # Docker Agent settings (quando agent_type = docker)
    agent_api_port = Column(Integer, default=8080)  # Porta API dell'agent Docker
    agent_token = Column(String(255), nullable=True)  # Token autenticazione agent (encrypted)
    agent_url = Column(String(255), nullable=True)  # URL completo se diverso da http://{address}:{agent_api_port}
    
    # DNS Server per reverse lookup
    dns_server = Column(String(255), nullable=True)  # IP del DNS locale per reverse lookup
    
    # Configurazione scansioni
    default_scan_type = Column(String(20), default="ping")  # ping, arp, snmp, all
    auto_add_devices = Column(Boolean, default=False)  # Aggiungere device automaticamente
    
    # Reti assegnate per scansione (JSON array di network_id)
    assigned_networks = Column(JSON, nullable=True)
    
    # Per agent MikroTik: Docker agent remoto per eseguire comandi
    docker_agent_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=True)
    
    # Per agent Docker: Gateway MikroTik o SNMP per risoluzione ARP
    arp_gateway_agent_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=True)  # MikroTik agent per ARP
    arp_gateway_snmp_address = Column(String(50), nullable=True)  # IP device SNMP per ARP (alternativa a arp_gateway_agent_id)
    arp_gateway_snmp_community = Column(String(100), nullable=True)  # SNMP community
    arp_gateway_snmp_version = Column(String(10), nullable=True)  # SNMP version (1, 2c, 3)
    
    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationship
    customer = relationship("Customer", back_populates="agents")
    
    __table_args__ = (
        Index('idx_agent_customer', 'customer_id'),
        Index('idx_agent_dude_id', 'dude_agent_id'),
    )
    
    def __repr__(self):
        return f"<AgentAssignment {self.name} ({self.address}) -> {self.customer_id}>"


class ScanResult(Base):
    """
    Risultato di una scansione di rete
    """
    __tablename__ = "scan_results"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    agent_id = Column(String(8), ForeignKey("agent_assignments.id"), nullable=True)
    network_id = Column(String(8), ForeignKey("networks.id"), nullable=True)
    
    # Info scansione
    network_cidr = Column(String(50), nullable=True)
    scan_type = Column(String(20), default="arp")
    devices_found = Column(Integer, default=0)
    
    # Status
    status = Column(String(20), default="completed")  # running, completed, failed
    error_message = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    devices = relationship("DiscoveredDevice", back_populates="scan", cascade="all, delete-orphan")
    
    __table_args__ = (
        Index('idx_scan_customer', 'customer_id'),
        Index('idx_scan_created', 'created_at'),
    )


class DiscoveredDevice(Base):
    """
    Dispositivo scoperto durante una scansione
    """
    __tablename__ = "discovered_devices"
    
    id = Column(String(8), primary_key=True, default=generate_uuid)
    scan_id = Column(String(8), ForeignKey("scan_results.id"), nullable=False)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False)
    
    # Info dispositivo
    address = Column(String(50), nullable=True)
    mac_address = Column(String(20), nullable=True)
    identity = Column(String(255), nullable=True)  # Nome/identity dal protocollo (SNMP, WMI, etc)
    hostname = Column(String(255), nullable=True)  # Hostname reale (da probe del device)
    reverse_dns = Column(String(255), nullable=True)  # Nome da reverse DNS lookup (PTR record)
    platform = Column(String(100), nullable=True)  # MikroTik, Cisco, etc
    board = Column(String(100), nullable=True)  # Modello
    interface = Column(String(100), nullable=True)  # Interfaccia di scoperta
    source = Column(String(20), nullable=True)  # neighbor, arp
    
    # Inventory details
    device_type = Column(String(50), nullable=True)  # windows, linux, mikrotik, network, etc
    os_family = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)
    vendor = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    category = Column(String(50), nullable=True)
    identified_by = Column(String(50), nullable=True)  # probe_snmp, probe_ssh, probe_wmi, mac_vendor, port_inference
    
    # Hardware stats (se rilevati in fase di discovery)
    cpu_cores = Column(Integer, nullable=True)
    ram_total_mb = Column(Integer, nullable=True)
    disk_total_gb = Column(Integer, nullable=True)
    serial_number = Column(String(100), nullable=True)
    
    # Porte aperte rilevate
    open_ports = Column(JSON, nullable=True)  # [{"port": 80, "protocol": "tcp", "service": "http", "open": true}, ...]
    
    # Status
    imported = Column(Boolean, default=False)  # Se importato come DeviceAssignment
    imported_at = Column(DateTime, nullable=True)  # Data di importazione nell'inventory (se importato)
    
    created_at = Column(DateTime, default=func.now())
    
    # Relationship
    scan = relationship("ScanResult", back_populates="devices")
    
    __table_args__ = (
        Index('idx_discovered_scan', 'scan_id'),
        Index('idx_discovered_customer', 'customer_id'),
        Index('idx_discovered_address', 'address'),
    )


# Database setup
def init_db(database_url: str = None):
    """
    Inizializza database e crea tabelle.
    
    v3.0.0: Default è PostgreSQL (configurato in config.py)
    SQLite NON è più supportato per il server.
    """
    if database_url is None:
        # Usa configurazione da settings
        from ..config import get_settings
        database_url = get_settings().database_url
    
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)
    return engine


def get_session(engine):
    """Crea sessione database"""
    Session = sessionmaker(bind=engine)
    return Session()
