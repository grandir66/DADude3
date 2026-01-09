#!/usr/bin/env python3
"""
Unified Infrastructure Scanner
===============================
Scanner multi-protocollo per inventory completo infrastruttura IT.

Protocolli supportati:
- SNMP: Switch, Router, Access Point, Firewall
- SSH: Linux, Synology, QNAP, Proxmox
- WMI/WinRM: Windows Server, Windows Client

Autore: Script generato per Riccardo @ Domarc Srl
"""

import json
import sys
import argparse
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from abc import ABC, abstractmethod
import socket
import warnings
from loguru import logger

# Suppress warnings
warnings.filterwarnings('ignore')

# =============================================================================
# PROTOCOL IMPORTS
# =============================================================================

# SNMP - pysnmp v7.x usa API completamente diversa
try:
    # pysnmp v7.x - nuova API asincrona
    from pysnmp.hlapi.v1arch.asyncio import (
        SnmpDispatcher as SnmpDispatcherV7,
        CommunityData as CommunityDataV7,
        UdpTransportTarget as UdpTransportTargetV7,
        ObjectType as ObjectTypeV7,
        ObjectIdentity as ObjectIdentityV7,
        get_cmd as get_cmd_v7,
        next_cmd as next_cmd_v7,
    )
    HAS_SNMP = True
    SNMP_V7 = True
    print("INFO: pysnmp v7.x detected - using v1arch.asyncio API")
except ImportError:
    try:
        # pysnmp v4/v5/v6 - vecchia API sincrona
        from pysnmp.hlapi import (
            SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity,
            getCmd, nextCmd
        )
        HAS_SNMP = True
        SNMP_V7 = False
        print("INFO: pysnmp v4/v5/v6 detected - using legacy hlapi API")
    except ImportError:
        HAS_SNMP = False
        SNMP_V7 = False
        print("AVVISO: pysnmp non installato. SNMP disabilitato.")

# SSH
try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key
    HAS_SSH = True
except ImportError:
    HAS_SSH = False
    print("AVVISO: paramiko non installato. SSH disabilitato.")

# WMI/WinRM
try:
    import winrm
    from winrm.protocol import Protocol
    HAS_WINRM = True
except ImportError:
    HAS_WINRM = False
    print("AVVISO: pywinrm non installato. WinRM disabilitato.")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class DeviceType(Enum):
    """Tipo di dispositivo"""
    UNKNOWN = "unknown"
    # Network devices
    SWITCH = "switch"
    ROUTER = "router"
    ACCESS_POINT = "access_point"
    FIREWALL = "firewall"
    # Servers
    LINUX_SERVER = "linux_server"
    WINDOWS_SERVER = "windows_server"
    PROXMOX = "proxmox"
    VMWARE = "vmware"
    # NAS
    SYNOLOGY = "synology"
    QNAP = "qnap"
    # Workstations
    WINDOWS_WORKSTATION = "windows_workstation"
    LINUX_WORKSTATION = "linux_workstation"


class Protocol(Enum):
    """Protocollo di comunicazione"""
    SNMP = "snmp"
    SSH = "ssh"
    WINRM = "winrm"
    AUTO = "auto"


class ScanStatus(Enum):
    """Stato della scansione"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


# =============================================================================
# UNIFIED DATA CLASSES
# =============================================================================

@dataclass
class SystemInfo:
    """Informazioni di sistema unificate"""
    hostname: str = ""
    fqdn: str = ""
    domain: str = ""
    device_type: str = ""
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    kernel_version: str = ""
    architecture: str = ""
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    asset_tag: str = ""
    bios_version: str = ""
    firmware_version: str = ""
    uptime: str = ""
    uptime_seconds: int = 0
    last_boot: str = ""
    timezone: str = ""
    install_date: str = ""
    mac_address: str = ""
    license: str = ""
    temperature: Optional[float] = None
    board_temperature: Optional[float] = None
    voltage: Optional[float] = None
    wireless_ssids: List[str] = field(default_factory=list)
    cpu_usage_percent: Optional[float] = None
    memory_usage_percent: Optional[float] = None
    wifi_clients_count: Optional[int] = None
    load_average_1m: Optional[float] = None
    ram_available_mb: Optional[int] = None


@dataclass
class CPUInfo:
    """Informazioni CPU"""
    model: str = ""
    manufacturer: str = ""
    cores_physical: int = 0
    cores_logical: int = 0
    sockets: int = 0
    threads_per_core: int = 0
    frequency_mhz: float = 0
    frequency_max_mhz: float = 0
    cache_l2_kb: int = 0
    cache_l3_kb: int = 0
    load_percent: float = 0
    load_1min: float = 0
    load_5min: float = 0
    load_15min: float = 0
    temperature_celsius: Optional[float] = None


@dataclass
class MemoryInfo:
    """Informazioni memoria"""
    total_bytes: int = 0
    available_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    cached_bytes: int = 0
    usage_percent: float = 0
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0
    swap_free_bytes: int = 0
    swap_usage_percent: float = 0
    # Slot info (for servers)
    slots_used: int = 0
    slots_total: int = 0


@dataclass
class DiskInfo:
    """Informazioni disco fisico"""
    device: str = ""
    model: str = ""
    serial: str = ""
    manufacturer: str = ""
    size_bytes: int = 0
    size_human: str = ""
    type: str = ""  # HDD, SSD, NVMe
    interface: str = ""  # SATA, SAS, NVMe, USB
    bus_type: str = ""
    media_type: str = ""
    partition_style: str = ""  # GPT, MBR
    status: str = ""
    health_status: str = ""
    smart_status: str = ""
    temperature_celsius: Optional[float] = None
    power_on_hours: int = 0
    firmware: str = ""
    slot: str = ""


@dataclass
class VolumeInfo:
    """Informazioni volume/partizione"""
    name: str = ""
    mount_point: str = ""
    drive_letter: str = ""  # Windows
    device: str = ""
    filesystem: str = ""
    label: str = ""
    total_bytes: int = 0
    used_bytes: int = 0
    available_bytes: int = 0
    usage_percent: float = 0
    is_system: bool = False
    is_boot: bool = False
    status: str = ""


@dataclass
class NetworkInterface:
    """Informazioni interfaccia di rete"""
    name: str = ""
    description: str = ""
    adapter_type: str = ""
    interface_type: str = ""  # ethernet, wireless, loopback, tunnel, etc.
    mac_address: str = ""
    ipv4_addresses: List[str] = field(default_factory=list)
    ipv6_addresses: List[str] = field(default_factory=list)
    subnet_mask: str = ""
    default_gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    dhcp_enabled: bool = False
    dhcp_server: str = ""
    mtu: int = 0
    speed_mbps: int = 0
    duplex: str = ""
    state: str = ""
    is_physical: bool = True
    is_virtual: bool = False
    vlan_id: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    rx_errors: int = 0
    tx_errors: int = 0


@dataclass
class ServiceInfo:
    """Informazioni servizio"""
    name: str = ""
    display_name: str = ""
    description: str = ""
    status: str = ""  # running, stopped, paused
    start_type: str = ""  # auto, manual, disabled
    account: str = ""  # Service account
    pid: int = 0
    memory_bytes: int = 0
    cpu_percent: float = 0
    path: str = ""
    dependencies: List[str] = field(default_factory=list)


@dataclass
class SoftwareInfo:
    """Informazioni software installato"""
    name: str = ""
    version: str = ""
    publisher: str = ""
    install_date: str = ""
    install_location: str = ""
    size_bytes: int = 0


@dataclass
class UserInfo:
    """Informazioni utente"""
    username: str = ""
    domain: str = ""
    full_name: str = ""
    is_local: bool = True
    is_admin: bool = False
    is_logged_in: bool = False
    last_logon: str = ""
    password_expires: str = ""
    status: str = ""


@dataclass
class ShareInfo:
    """Informazioni share"""
    name: str = ""
    path: str = ""
    description: str = ""
    share_type: str = ""  # SMB, NFS, etc
    status: str = ""
    max_connections: int = 0
    current_connections: int = 0
    permissions: str = ""


@dataclass
class VMInfo:
    """Informazioni VM"""
    id: str = ""
    name: str = ""
    status: str = ""
    type: str = ""  # qemu, lxc, hyperv
    os: str = ""
    cpus: int = 0
    memory_bytes: int = 0
    disk_bytes: int = 0
    uptime: str = ""
    host: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    cpu_usage: float = 0.0
    mem_used: int = 0


@dataclass
class RAIDInfo:
    """Informazioni RAID"""
    name: str = ""
    level: str = ""
    status: str = ""
    size_bytes: int = 0
    disks: List[str] = field(default_factory=list)
    healthy_disks: int = 0
    total_disks: int = 0
    spare_disks: int = 0
    rebuild_percent: float = 0


@dataclass
class LLDPNeighbor:
    """LLDP Neighbor"""
    local_port: str = ""
    remote_device: str = ""
    remote_port: str = ""
    remote_description: str = ""
    remote_ip: str = ""
    capabilities: str = ""


@dataclass
class ScanResult:
    """Risultato scansione unificato"""
    # Metadata
    target: str = ""
    protocol_used: str = ""
    scan_status: str = ""
    scan_timestamp: str = ""
    scan_duration_seconds: float = 0
    scanner_host: str = ""
    
    # System
    system_info: SystemInfo = field(default_factory=SystemInfo)
    cpu: CPUInfo = field(default_factory=CPUInfo)
    memory: MemoryInfo = field(default_factory=MemoryInfo)
    
    # Storage
    disks: List[DiskInfo] = field(default_factory=list)
    volumes: List[VolumeInfo] = field(default_factory=list)
    raid_arrays: List[RAIDInfo] = field(default_factory=list)
    
    # Network
    network_interfaces: List[NetworkInterface] = field(default_factory=list)
    default_gateway: str = ""
    dns_servers: List[str] = field(default_factory=list)
    routing_table: List[Dict] = field(default_factory=list)
    lldp_neighbors: List[LLDPNeighbor] = field(default_factory=list)
    
    # Services/Software
    services: List[ServiceInfo] = field(default_factory=list)
    software: List[SoftwareInfo] = field(default_factory=list)
    
    # Users
    users: List[UserInfo] = field(default_factory=list)
    logged_in_users: List[str] = field(default_factory=list)
    
    # Shares
    shares: List[ShareInfo] = field(default_factory=list)
    
    # Virtualization
    vms: List[VMInfo] = field(default_factory=list)
    hypervisor_type: str = ""
    
    # Additional
    updates_pending: int = 0
    last_update: str = ""
    antivirus_status: str = ""
    firewall_status: str = ""
    
    # Errors
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def human_size(size_bytes: int) -> str:
    """Converte bytes in formato leggibile"""
    if size_bytes == 0:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} EB"


def parse_uptime_seconds(seconds: int) -> str:
    """Converte secondi in formato leggibile"""
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    return f"{days}d {hours}h {minutes}m"


def detect_protocol(host: str, timeout: int = 3) -> Protocol:
    """Rileva il protocollo migliore per un host"""
    # Prova WinRM (5985)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, 5985))
        sock.close()
        if result == 0:
            return Protocol.WINRM
    except:
        pass
    
    # Prova SSH (22)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, 22))
        sock.close()
        if result == 0:
            return Protocol.SSH
    except:
        pass
    
    # Prova SNMP (161)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b'\x30\x26\x02\x01\x01', (host, 161))
        sock.close()
        return Protocol.SNMP
    except:
        pass
    
    return Protocol.SNMP  # Default


# =============================================================================
# BASE COLLECTOR CLASS
# =============================================================================

class BaseCollector(ABC):
    """Classe base per tutti i collector"""
    
    def __init__(self, host: str, verbose: bool = False):
        self.host = host
        self.verbose = verbose
        self.result = ScanResult(
            target=host,
            scan_timestamp=datetime.now().isoformat(),
            scanner_host=socket.gethostname()
        )
        self.start_time = datetime.now()
    
    def log(self, message: str):
        """Log con prefisso host"""
        if self.verbose:
            logger.debug(f"[{self.host}] {message}")
    
    def finalize(self):
        """Finalizza la scansione"""
        duration = (datetime.now() - self.start_time).total_seconds()
        self.result.scan_duration_seconds = round(duration, 2)
        
        if self.result.errors:
            if len(self.result.errors) > 5:
                self.result.scan_status = ScanStatus.FAILED.value
            else:
                self.result.scan_status = ScanStatus.PARTIAL.value
        else:
            self.result.scan_status = ScanStatus.SUCCESS.value
    
    @abstractmethod
    def connect(self) -> bool:
        """Stabilisce connessione"""
        pass
    
    @abstractmethod
    def disconnect(self):
        """Chiude connessione"""
        pass
    
    @abstractmethod
    def collect(self) -> ScanResult:
        """Esegue raccolta dati"""
        pass


# =============================================================================
# WINRM/WMI COLLECTOR FOR WINDOWS
# =============================================================================

class WindowsCollector(BaseCollector):
    """Collector per Windows via WinRM/PowerShell"""
    
    def __init__(self, host: str, username: str, password: str,
                 domain: str = "", port: int = 5985, use_ssl: bool = False,
                 verbose: bool = False):
        super().__init__(host, verbose)
        
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.use_ssl = use_ssl
        self.session = None
        
        # Build auth string
        if domain:
            self.auth_user = f"{domain}\\{username}"
        else:
            self.auth_user = username
        
        self.result.protocol_used = Protocol.WINRM.value
    
    def connect(self) -> bool:
        """Stabilisce connessione WinRM"""
        if not HAS_WINRM:
            self.result.errors.append("pywinrm not installed")
            return False
        
        self.log("Connessione WinRM...")
        
        try:
            protocol = 'https' if self.use_ssl else 'http'
            endpoint = f"{protocol}://{self.host}:{self.port}/wsman"
            
            self.session = winrm.Session(
                target=endpoint,
                auth=(self.auth_user, self.password),
                transport='ntlm',
                server_cert_validation='ignore'
            )
            
            # Test connection
            result = self.session.run_ps("$env:COMPUTERNAME")
            if result.status_code == 0:
                self.log("Connesso!")
                return True
            else:
                self.result.errors.append(f"WinRM test failed: {result.std_err}")
                return False
            
        except Exception as e:
            self.log(f"Errore connessione: {e}")
            self.result.errors.append(f"WinRM connection failed: {e}")
            return False
    
    def disconnect(self):
        """Chiude connessione"""
        self.session = None
        self.log("Disconnesso")
    
    def run_powershell(self, script: str, timeout: int = 60) -> Tuple[str, str, int]:
        """Esegue script PowerShell"""
        if not self.session:
            return "", "Not connected", -1
        
        try:
            result = self.session.run_ps(script)
            stdout = result.std_out.decode('utf-8', errors='replace').strip()
            stderr = result.std_err.decode('utf-8', errors='replace').strip()
            return stdout, stderr, result.status_code
        except Exception as e:
            return "", str(e), -1
    
    def run_ps_json(self, script: str) -> Optional[Any]:
        """Esegue PowerShell e ritorna JSON"""
        full_script = f"{script} | ConvertTo-Json -Depth 5"
        stdout, stderr, code = self.run_powershell(full_script)
        
        if code == 0 and stdout:
            try:
                return json.loads(stdout)
            except json.JSONDecodeError:
                return None
        return None
    
    def collect(self) -> ScanResult:
        """Raccoglie tutti i dati Windows"""
        if not self.connect():
            return self.result
        
        try:
            self.collect_system_info()
            self.collect_cpu_info()
            self.collect_memory_info()
            self.collect_disk_info()
            self.collect_volume_info()
            self.collect_network_info()
            self.collect_services()
            self.collect_software()
            self.collect_users()
            self.collect_shares()
            self.collect_hyperv()
            self.collect_security_info()
            
        finally:
            self.disconnect()
            self.finalize()
        
        return self.result
    
    def collect_system_info(self):
        """Raccoglie info sistema Windows"""
        self.log("Raccolta info sistema...")
        si = self.result.system_info
        
        # Computer System
        cs = self.run_ps_json("Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, TotalPhysicalMemory, NumberOfProcessors, NumberOfLogicalProcessors")
        if cs:
            si.hostname = cs.get('Name', '')
            si.domain = cs.get('Domain', '')
            si.manufacturer = cs.get('Manufacturer', '')
            si.model = cs.get('Model', '')
        
        # Operating System
        os_info = self.run_ps_json("Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, LocalDateTime")
        if os_info:
            si.os_name = os_info.get('Caption', '')
            si.os_version = os_info.get('Version', '')
            si.os_build = os_info.get('BuildNumber', '')
            si.architecture = os_info.get('OSArchitecture', '')
            
            # Install date
            if os_info.get('InstallDate'):
                si.install_date = self._parse_cim_date(os_info['InstallDate'])
            
            # Last boot
            if os_info.get('LastBootUpTime'):
                si.last_boot = self._parse_cim_date(os_info['LastBootUpTime'])
            
            # Uptime
            uptime_script = "(Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime | Select-Object Days, Hours, Minutes, TotalSeconds"
            uptime = self.run_ps_json(uptime_script)
            if uptime:
                si.uptime_seconds = int(uptime.get('TotalSeconds', 0))
                si.uptime = f"{uptime.get('Days', 0)}d {uptime.get('Hours', 0)}h {uptime.get('Minutes', 0)}m"
        
        # BIOS
        bios = self.run_ps_json("Get-CimInstance Win32_BIOS | Select-Object SerialNumber, SMBIOSBIOSVersion, Manufacturer")
        if bios:
            si.serial_number = bios.get('SerialNumber', '')
            si.bios_version = bios.get('SMBIOSBIOSVersion', '')
        
        # Timezone
        tz = self.run_ps_json("Get-TimeZone | Select-Object Id")
        if tz:
            si.timezone = tz.get('Id', '')
        
        # FQDN
        fqdn, _, _ = self.run_powershell("[System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName")
        si.fqdn = fqdn.strip()
        
        # Device type
        if 'Server' in si.os_name:
            si.device_type = DeviceType.WINDOWS_SERVER.value
        else:
            si.device_type = DeviceType.WINDOWS_WORKSTATION.value
    
    def collect_cpu_info(self):
        """Raccoglie info CPU"""
        self.log("Raccolta info CPU...")
        cpu = self.result.cpu
        
        # Processor info
        proc = self.run_ps_json("Get-CimInstance Win32_Processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, L2CacheSize, L3CacheSize, LoadPercentage | Select-Object -First 1")
        if proc:
            cpu.model = proc.get('Name', '')
            cpu.manufacturer = proc.get('Manufacturer', '')
            cpu.cores_physical = proc.get('NumberOfCores', 0)
            cpu.cores_logical = proc.get('NumberOfLogicalProcessors', 0)
            cpu.frequency_max_mhz = proc.get('MaxClockSpeed', 0)
            cpu.cache_l2_kb = proc.get('L2CacheSize', 0)
            cpu.cache_l3_kb = proc.get('L3CacheSize', 0)
            cpu.load_percent = proc.get('LoadPercentage', 0) or 0
        
        # Socket count
        sockets = self.run_ps_json("(Get-CimInstance Win32_Processor).Count")
        if sockets:
            cpu.sockets = int(sockets) if isinstance(sockets, (int, float)) else 1
        
        # Temperature (if available)
        temp = self.run_ps_json("Get-CimInstance MSAcpi_ThermalZoneTemperature -Namespace root/wmi -ErrorAction SilentlyContinue | Select-Object CurrentTemperature | Select-Object -First 1")
        if temp and temp.get('CurrentTemperature'):
            # Convert from tenths of Kelvin to Celsius
            cpu.temperature_celsius = (temp['CurrentTemperature'] / 10) - 273.15
    
    def collect_memory_info(self):
        """Raccoglie info memoria"""
        self.log("Raccolta info memoria...")
        mem = self.result.memory
        
        # Memory info
        os_mem = self.run_ps_json("Get-CimInstance Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory, TotalVirtualMemorySize, FreeVirtualMemory")
        if os_mem:
            mem.total_bytes = (os_mem.get('TotalVisibleMemorySize', 0) or 0) * 1024
            mem.free_bytes = (os_mem.get('FreePhysicalMemory', 0) or 0) * 1024
            mem.available_bytes = mem.free_bytes
            mem.used_bytes = mem.total_bytes - mem.free_bytes
            
            if mem.total_bytes > 0:
                mem.usage_percent = round((mem.used_bytes / mem.total_bytes) * 100, 1)
            
            # Virtual memory (Swap/PageFile)
            mem.swap_total_bytes = (os_mem.get('TotalVirtualMemorySize', 0) or 0) * 1024
            mem.swap_free_bytes = (os_mem.get('FreeVirtualMemory', 0) or 0) * 1024
            mem.swap_used_bytes = mem.swap_total_bytes - mem.swap_free_bytes
            
            if mem.swap_total_bytes > 0:
                mem.swap_usage_percent = round((mem.swap_used_bytes / mem.swap_total_bytes) * 100, 1)
        
        # Physical memory modules
        dimms = self.run_ps_json("Get-CimInstance Win32_PhysicalMemory | Measure-Object")
        if dimms:
            mem.slots_used = dimms.get('Count', 0)
        
        slots = self.run_ps_json("Get-CimInstance Win32_PhysicalMemoryArray | Select-Object MemoryDevices")
        if slots:
            mem.slots_total = slots.get('MemoryDevices', 0)
    
    def collect_disk_info(self):
        """Raccoglie info dischi fisici"""
        self.log("Raccolta info dischi...")
        
        # Physical disks
        disks = self.run_ps_json("""
            Get-PhysicalDisk | Select-Object 
                DeviceId, FriendlyName, MediaType, BusType, 
                Size, HealthStatus, OperationalStatus,
                SerialNumber, FirmwareVersion, Manufacturer
        """)
        
        if disks:
            if not isinstance(disks, list):
                disks = [disks]
            
            for d in disks:
                disk = DiskInfo()
                disk.device = f"PhysicalDisk{d.get('DeviceId', '')}"
                disk.model = d.get('FriendlyName', '')
                disk.serial = d.get('SerialNumber', '') or ''
                disk.manufacturer = d.get('Manufacturer', '') or ''
                disk.size_bytes = d.get('Size', 0) or 0
                disk.size_human = human_size(disk.size_bytes)
                disk.media_type = d.get('MediaType', '')
                disk.bus_type = d.get('BusType', '')
                disk.health_status = d.get('HealthStatus', '')
                disk.status = d.get('OperationalStatus', '')
                disk.firmware = d.get('FirmwareVersion', '') or ''
                
                # Determine type
                media = disk.media_type.lower() if disk.media_type else ''
                if 'ssd' in media:
                    disk.type = 'SSD'
                elif 'hdd' in media:
                    disk.type = 'HDD'
                elif 'nvme' in disk.bus_type.lower():
                    disk.type = 'NVMe'
                else:
                    disk.type = disk.media_type or 'Unknown'
                
                disk.interface = disk.bus_type
                
                self.result.disks.append(disk)
    
    def collect_volume_info(self):
        """Raccoglie info volumi/partizioni"""
        self.log("Raccolta info volumi...")
        
        volumes = self.run_ps_json("""
            Get-Volume | Where-Object {$_.DriveLetter -ne $null} | Select-Object 
                DriveLetter, FileSystemLabel, FileSystem, 
                Size, SizeRemaining, HealthStatus
        """)
        
        if volumes:
            if not isinstance(volumes, list):
                volumes = [volumes]
            
            for v in volumes:
                vol = VolumeInfo()
                letter = v.get('DriveLetter', '')
                vol.drive_letter = f"{letter}:" if letter else ''
                vol.mount_point = vol.drive_letter
                vol.label = v.get('FileSystemLabel', '') or ''
                vol.filesystem = v.get('FileSystem', '') or ''
                vol.total_bytes = v.get('Size', 0) or 0
                vol.available_bytes = v.get('SizeRemaining', 0) or 0
                vol.used_bytes = vol.total_bytes - vol.available_bytes
                vol.status = v.get('HealthStatus', '')
                
                if vol.total_bytes > 0:
                    vol.usage_percent = round((vol.used_bytes / vol.total_bytes) * 100, 1)
                
                # Check if system/boot
                if vol.drive_letter == 'C:':
                    vol.is_system = True
                    vol.is_boot = True
                
                self.result.volumes.append(vol)
    
    def collect_network_info(self):
        """Raccoglie info rete"""
        self.log("Raccolta info rete...")
        
        # Network adapters
        adapters = self.run_ps_json("""
            Get-NetAdapter | Select-Object 
                Name, InterfaceDescription, MacAddress, 
                Status, LinkSpeed, MediaType, 
                Virtual, VlanID
        """)
        
        if adapters:
            if not isinstance(adapters, list):
                adapters = [adapters]
            
            for a in adapters:
                iface = NetworkInterface()
                iface.name = a.get('Name', '')
                iface.description = a.get('InterfaceDescription', '')
                iface.mac_address = (a.get('MacAddress', '') or '').replace('-', ':')
                iface.state = a.get('Status', '').lower()
                iface.is_virtual = a.get('Virtual', False)
                iface.is_physical = not iface.is_virtual
                
                # Parse speed
                speed = a.get('LinkSpeed', '')
                if speed:
                    match = re.search(r'(\d+)', speed)
                    if match:
                        speed_val = int(match.group(1))
                        if 'Gbps' in speed:
                            speed_val *= 1000
                        iface.speed_mbps = speed_val
                
                if a.get('VlanID'):
                    iface.vlan_id = a['VlanID']
                
                self.result.network_interfaces.append(iface)
        
        # IP Configuration
        ip_config = self.run_ps_json("""
            Get-NetIPConfiguration | Select-Object 
                InterfaceAlias, 
                @{N='IPv4';E={$_.IPv4Address.IPAddress}},
                @{N='Gateway';E={$_.IPv4DefaultGateway.NextHop}},
                @{N='DNS';E={$_.DNSServer.ServerAddresses}}
        """)
        
        if ip_config:
            if not isinstance(ip_config, list):
                ip_config = [ip_config]
            
            for cfg in ip_config:
                alias = cfg.get('InterfaceAlias', '')
                for iface in self.result.network_interfaces:
                    if iface.name == alias:
                        ipv4 = cfg.get('IPv4')
                        if ipv4:
                            if isinstance(ipv4, list):
                                iface.ipv4_addresses = ipv4
                            else:
                                iface.ipv4_addresses = [ipv4]
                        
                        gw = cfg.get('Gateway')
                        if gw:
                            iface.default_gateway = gw if isinstance(gw, str) else gw[0] if gw else ''
                            if not self.result.default_gateway:
                                self.result.default_gateway = iface.default_gateway
                        
                        dns = cfg.get('DNS')
                        if dns:
                            iface.dns_servers = dns if isinstance(dns, list) else [dns]
                            if not self.result.dns_servers:
                                self.result.dns_servers = iface.dns_servers
                        break
    
    def collect_services(self):
        """Raccoglie info servizi Windows"""
        self.log("Raccolta info servizi...")
        
        # Only important services
        important = [
            'wuauserv', 'BITS', 'W32Time', 'Spooler', 'MSSQLSERVER', 
            'MySQL', 'postgresql', 'Apache', 'W3SVC', 'IISADMIN',
            'RemoteRegistry', 'WinRM', 'TermService', 'LanmanServer',
            'LanmanWorkstation', 'Dnscache', 'DHCP', 'eventlog',
            'MpsSvc', 'WinDefend', 'SecurityHealthService'
        ]
        
        services = self.run_ps_json(f"""
            Get-Service | Where-Object {{$_.Status -eq 'Running' -or $_.Name -in @('{("','".join(important))}')}} |
            Select-Object Name, DisplayName, Status, StartType | Select-Object -First 50
        """)
        
        if services:
            if not isinstance(services, list):
                services = [services]
            
            for s in services:
                svc = ServiceInfo()
                svc.name = s.get('Name', '')
                svc.display_name = s.get('DisplayName', '')
                svc.status = str(s.get('Status', '')).lower()
                svc.start_type = str(s.get('StartType', '')).lower()
                
                self.result.services.append(svc)
    
    def collect_software(self):
        """Raccoglie software installato"""
        self.log("Raccolta software installato...")
        
        software = self.run_ps_json("""
            Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
            Where-Object {$_.DisplayName -ne $null} |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Select-Object -First 100
        """)
        
        if software:
            if not isinstance(software, list):
                software = [software]
            
            for s in software:
                sw = SoftwareInfo()
                sw.name = s.get('DisplayName', '')
                sw.version = s.get('DisplayVersion', '') or ''
                sw.publisher = s.get('Publisher', '') or ''
                sw.install_date = s.get('InstallDate', '') or ''
                
                self.result.software.append(sw)
    
    def collect_users(self):
        """Raccoglie info utenti"""
        self.log("Raccolta utenti...")
        
        # Logged in users
        logged = self.run_ps_json("query user 2>$null | ForEach-Object { ($_ -split '\\s+')[1] } | Where-Object { $_ -and $_ -ne 'USERNAME' }")
        if logged:
            if isinstance(logged, list):
                self.result.logged_in_users = logged
            else:
                self.result.logged_in_users = [logged]
        
        # Local users
        users = self.run_ps_json("""
            Get-LocalUser | Select-Object Name, FullName, Enabled, LastLogon, 
                PasswordExpires, Description | Select-Object -First 20
        """)
        
        if users:
            if not isinstance(users, list):
                users = [users]
            
            for u in users:
                user = UserInfo()
                user.username = u.get('Name', '')
                user.full_name = u.get('FullName', '') or ''
                user.status = 'enabled' if u.get('Enabled') else 'disabled'
                user.is_local = True
                
                if u.get('LastLogon'):
                    user.last_logon = self._parse_cim_date(u['LastLogon'])
                
                self.result.users.append(user)
    
    def collect_shares(self):
        """Raccoglie share SMB"""
        self.log("Raccolta share...")
        
        shares = self.run_ps_json("""
            Get-SmbShare | Where-Object {$_.Name -notlike '*$'} |
            Select-Object Name, Path, Description, CurrentUsers, ShareType
        """)
        
        if shares:
            if not isinstance(shares, list):
                shares = [shares]
            
            for s in shares:
                share = ShareInfo()
                share.name = s.get('Name', '')
                share.path = s.get('Path', '')
                share.description = s.get('Description', '') or ''
                share.share_type = 'SMB'
                share.current_connections = s.get('CurrentUsers', 0) or 0
                
                self.result.shares.append(share)
    
    def collect_hyperv(self):
        """Raccoglie VM Hyper-V se presente"""
        self.log("Controllo Hyper-V...")
        
        # Check if Hyper-V is installed
        hyperv = self.run_ps_json("Get-WindowsFeature Hyper-V -ErrorAction SilentlyContinue | Select-Object Installed")
        
        if hyperv and hyperv.get('Installed'):
            self.result.hypervisor_type = "Hyper-V"
            
            vms = self.run_ps_json("""
                Get-VM | Select-Object VMId, Name, State, 
                    @{N='CPUs';E={$_.ProcessorCount}},
                    @{N='MemoryMB';E={$_.MemoryAssigned/1MB}},
                    Uptime
            """)
            
            if vms:
                if not isinstance(vms, list):
                    vms = [vms]
                
                for v in vms:
                    vm = VMInfo()
                    vm.id = str(v.get('VMId', ''))
                    vm.name = v.get('Name', '')
                    vm.status = str(v.get('State', '')).lower()
                    vm.type = 'hyperv'
                    vm.cpus = v.get('CPUs', 0)
                    vm.memory_bytes = (v.get('MemoryMB', 0) or 0) * 1024 * 1024
                    
                    uptime = v.get('Uptime')
                    if uptime:
                        vm.uptime = str(uptime)
                    
                    self.result.vms.append(vm)
    
    def collect_security_info(self):
        """Raccoglie info sicurezza"""
        self.log("Raccolta info sicurezza...")
        
        # Windows Defender status
        defender = self.run_ps_json("""
            Get-MpComputerStatus -ErrorAction SilentlyContinue | 
            Select-Object AntivirusEnabled, RealTimeProtectionEnabled, 
                AntispywareEnabled, AMServiceEnabled
        """)
        
        if defender:
            if defender.get('AntivirusEnabled') and defender.get('RealTimeProtectionEnabled'):
                self.result.antivirus_status = "Windows Defender - Active"
            else:
                self.result.antivirus_status = "Windows Defender - Inactive"
        
        # Firewall
        fw = self.run_ps_json("Get-NetFirewallProfile | Select-Object Name, Enabled")
        if fw:
            if not isinstance(fw, list):
                fw = [fw]
            
            enabled_profiles = [f['Name'] for f in fw if f.get('Enabled')]
            if enabled_profiles:
                self.result.firewall_status = f"Enabled ({', '.join(enabled_profiles)})"
            else:
                self.result.firewall_status = "Disabled"
        
        # Pending updates
        updates = self.run_ps_json("""
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
            if ($UpdateSession) {
                $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
                $Updates = $UpdateSearcher.Search("IsInstalled=0").Updates
                $Updates.Count
            }
        """)
        
        if updates is not None:
            self.result.updates_pending = int(updates) if isinstance(updates, (int, float)) else 0
    
    def _parse_cim_date(self, date_str: str) -> str:
        """Parse CIM datetime to ISO format"""
        if not date_str:
            return ""
        
        # Handle /Date(timestamp)/ format
        if '/Date(' in str(date_str):
            match = re.search(r'/Date\((\d+)', str(date_str))
            if match:
                ts = int(match.group(1)) / 1000
                return datetime.fromtimestamp(ts).isoformat()
        
        return str(date_str)


# =============================================================================
# SSH COLLECTOR (LINUX/NAS)
# =============================================================================

class LinuxSSHCollector(BaseCollector):
    """Collector per Linux/NAS via SSH"""
    
    def __init__(self, host: str, username: str, password: str = None,
                 key_file: str = None, port: int = 22, timeout: int = 30,
                 verbose: bool = False):
        super().__init__(host, verbose)
        
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.client: Optional[SSHClient] = None
        self.system_type = None
        self.is_mikrotik = False
        self.is_ubiquiti = False
        
        self.result.protocol_used = Protocol.SSH.value
    
    def connect(self) -> bool:
        """Stabilisce connessione SSH"""
        if not HAS_SSH:
            self.result.errors.append("paramiko not installed")
            return False
        
        self.log("Connessione SSH...")
        
        try:
            self.client = SSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                # Disabilita agent e key lookup quando si usa password (compatibilità Ubiquiti)
                'allow_agent': False,
                'look_for_keys': False,
            }
            
            if self.key_file:
                try:
                    key = RSAKey.from_private_key_file(self.key_file)
                except:
                    try:
                        key = Ed25519Key.from_private_key_file(self.key_file)
                    except:
                        key = None
                
                if key:
                    connect_kwargs['pkey'] = key
                    # Se abbiamo una chiave, possiamo permettere agent/key lookup
                    connect_kwargs['allow_agent'] = True
                    connect_kwargs['look_for_keys'] = True
            
            if self.password:
                connect_kwargs['password'] = self.password
            
            self.client.connect(**connect_kwargs)
            self.log("Connesso!")
            return True
            
        except Exception as e:
            self.log(f"Errore connessione: {e}")
            self.result.errors.append(f"SSH connection failed: {e}")
            return False
    
    def disconnect(self):
        """Chiude connessione"""
        if self.client:
            self.client.close()
        self.log("Disconnesso")
    
    def run_command(self, command: str, timeout: int = 30) -> str:
        """Esegue comando e ritorna stdout"""
        if not self.client:
            return ""
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            return stdout.read().decode('utf-8', errors='replace').strip()
        except Exception as e:
            return ""
    
    def file_exists(self, path: str) -> bool:
        """Verifica se un file esiste"""
        result = self.run_command(f"test -e {path} && echo 1 || echo 0")
        return result == "1"
    
    def read_file(self, path: str) -> str:
        """Legge contenuto file"""
        return self.run_command(f"cat {path} 2>/dev/null")
    
    def detect_system_type(self):
        """Rileva tipo sistema"""
        # MikroTik RouterOS (non supporta comandi Linux standard)
        ros_out = self.run_command("/system resource print", timeout=10)
        if ros_out and ("version:" in ros_out.lower() or "uptime:" in ros_out.lower() or "routeros" in ros_out.lower()):
            self.system_type = DeviceType.ROUTER  # Usiamo ROUTER come tipo per MikroTik
            self.is_mikrotik = True
            return
        
        # Ubiquiti switch/device (BusyBox + Ubiquiti banner o /etc/version con US.)
        version_check = self.run_command("cat /etc/version 2>/dev/null", timeout=5)
        if version_check and version_check.startswith("US."):
            self.system_type = DeviceType.SWITCH
            self.is_ubiquiti = True
            return
        
        # Synology
        if self.file_exists("/etc/synoinfo.conf"):
            self.system_type = DeviceType.SYNOLOGY
            return
        
        # QNAP
        if self.file_exists("/etc/config/uLinux.conf"):
            self.system_type = DeviceType.QNAP
            return
        
        # Proxmox
        if self.file_exists("/etc/pve"):
            self.system_type = DeviceType.PROXMOX
            return
        
        self.system_type = DeviceType.LINUX_SERVER
    
    def collect(self) -> ScanResult:
        """Raccoglie tutti i dati"""
        if not self.connect():
            return self.result
        
        try:
            self.detect_system_type()
            self.result.system_info.device_type = self.system_type.value
            
            self.collect_system_info()
            self.collect_cpu_info()
            self.collect_memory_info()
            self.collect_disk_info()
            self.collect_volume_info()
            self.collect_raid_info()
            self.collect_network_info()
            self.collect_services()
            self.collect_users()
            
            # NAS specific
            if self.system_type in (DeviceType.SYNOLOGY, DeviceType.QNAP):
                self.collect_nas_info()
                self.collect_shares()
            
            # Proxmox specific
            if self.system_type == DeviceType.PROXMOX:
                self.collect_proxmox_vms()
            
            # MikroTik RouterOS specific
            if self.is_mikrotik or self.system_type == DeviceType.ROUTER:
                # Verifica se è MikroTik
                ros_test = self.run_command("/system resource print", timeout=5)
                if ros_test and ("version:" in ros_test.lower() or "routeros" in ros_test.lower()):
                    self.collect_mikrotik_ssh()
            
            # Ubiquiti switch specific
            if self.is_ubiquiti or self.system_type == DeviceType.SWITCH:
                # Verifica se è Ubiquiti
                version_check = self.run_command("cat /etc/version 2>/dev/null", timeout=5)
                if version_check and version_check.startswith("US."):
                    self.collect_ubiquiti_ssh()
            
        finally:
            self.disconnect()
            self.finalize()
        
        return self.result
    
    def collect_system_info(self):
        """Raccoglie info sistema"""
        self.log("Raccolta info sistema...")
        si = self.result.system_info
        
        si.hostname = self.run_command("hostname -s")
        si.fqdn = self.run_command("hostname -f")
        
        # OS info
        os_release = self.read_file("/etc/os-release")
        for line in os_release.split('\n'):
            if line.startswith('NAME='):
                si.os_name = line.split('=')[1].strip('"')
            elif line.startswith('VERSION='):
                si.os_version = line.split('=')[1].strip('"')
            elif line.startswith('VERSION_ID='):
                si.os_build = line.split('=')[1].strip('"')
        
        si.kernel_version = self.run_command("uname -r")
        si.architecture = self.run_command("uname -m")
        
        # Uptime
        uptime_str = self.run_command("cat /proc/uptime")
        if uptime_str:
            try:
                secs = float(uptime_str.split()[0])
                si.uptime_seconds = int(secs)
                si.uptime = parse_uptime_seconds(int(secs))
            except:
                pass
        
        # Hardware info
        dmi_product = self.run_command("cat /sys/class/dmi/id/product_name 2>/dev/null")
        dmi_vendor = self.run_command("cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
        dmi_serial = self.run_command("cat /sys/class/dmi/id/product_serial 2>/dev/null")
        
        si.model = dmi_product
        si.manufacturer = dmi_vendor
        si.serial_number = dmi_serial
        
        # Timezone
        si.timezone = self.run_command("cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null")
    
    def collect_cpu_info(self):
        """Raccoglie info CPU"""
        self.log("Raccolta info CPU...")
        cpu = self.result.cpu
        
        cpuinfo = self.read_file("/proc/cpuinfo")
        cores_physical = set()
        cores_logical = 0
        
        for line in cpuinfo.split('\n'):
            if line.startswith('model name'):
                if not cpu.model:
                    cpu.model = line.split(':')[1].strip()
            elif line.startswith('cpu MHz'):
                try:
                    cpu.frequency_mhz = float(line.split(':')[1].strip())
                except:
                    pass
            elif line.startswith('physical id'):
                cores_physical.add(line.split(':')[1].strip())
            elif line.startswith('processor'):
                cores_logical += 1
        
        cpu.cores_physical = len(cores_physical) if cores_physical else 1
        cpu.cores_logical = cores_logical
        cpu.sockets = cpu.cores_physical
        
        # Load average
        loadavg = self.read_file("/proc/loadavg")
        if loadavg:
            parts = loadavg.split()
            try:
                cpu.load_1min = float(parts[0])
                cpu.load_5min = float(parts[1])
                cpu.load_15min = float(parts[2])
            except:
                pass
        
        # CPU usage
        stat = self.read_file("/proc/stat")
        if stat:
            try:
                cpu_line = stat.split('\n')[0].split()[1:]
                total = sum(int(x) for x in cpu_line)
                idle = int(cpu_line[3]) + int(cpu_line[4])
                cpu.load_percent = round((1 - idle / total) * 100, 1)
            except:
                pass
        
        # Temperature
        temp = self.run_command("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
        if temp and temp.isdigit():
            cpu.temperature_celsius = float(temp) / 1000
    
    def collect_memory_info(self):
        """Raccoglie info memoria"""
        self.log("Raccolta info memoria...")
        mem = self.result.memory
        
        meminfo = self.read_file("/proc/meminfo")
        
        for line in meminfo.split('\n'):
            parts = line.split()
            if len(parts) < 2:
                continue
            
            key = parts[0].rstrip(':')
            try:
                value = int(parts[1]) * 1024
            except:
                continue
            
            if key == 'MemTotal':
                mem.total_bytes = value
            elif key == 'MemFree':
                mem.free_bytes = value
            elif key == 'MemAvailable':
                mem.available_bytes = value
            elif key == 'Cached':
                mem.cached_bytes = value
            elif key == 'SwapTotal':
                mem.swap_total_bytes = value
            elif key == 'SwapFree':
                mem.swap_free_bytes = value
        
        mem.used_bytes = mem.total_bytes - mem.available_bytes
        mem.swap_used_bytes = mem.swap_total_bytes - mem.swap_free_bytes
        
        if mem.total_bytes > 0:
            mem.usage_percent = round((mem.used_bytes / mem.total_bytes) * 100, 1)
        
        if mem.swap_total_bytes > 0:
            mem.swap_usage_percent = round((mem.swap_used_bytes / mem.swap_total_bytes) * 100, 1)
    
    def collect_disk_info(self):
        """Raccoglie info dischi"""
        self.log("Raccolta info dischi...")
        
        lsblk = self.run_command("lsblk -d -b -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA,TRAN -n 2>/dev/null")
        
        for line in lsblk.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split(None, 6)
            if len(parts) < 3 or parts[2] != 'disk':
                continue
            
            disk = DiskInfo()
            disk.device = f"/dev/{parts[0]}"
            
            try:
                disk.size_bytes = int(parts[1])
                disk.size_human = human_size(disk.size_bytes)
            except:
                pass
            
            if len(parts) > 3:
                disk.model = parts[3]
            if len(parts) > 4:
                disk.serial = parts[4]
            if len(parts) > 5:
                disk.type = "SSD" if parts[5] == '0' else "HDD"
            if len(parts) > 6:
                disk.interface = parts[6].upper()
            
            if 'nvme' in parts[0]:
                disk.type = "NVMe"
                disk.interface = "NVMe"
            
            self.result.disks.append(disk)
    
    def collect_volume_info(self):
        """Raccoglie info volumi"""
        self.log("Raccolta info volumi...")
        
        df = self.run_command("df -B1 -T --output=source,fstype,size,used,avail,pcent,target 2>/dev/null")
        
        for line in df.split('\n')[1:]:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 7:
                continue
            
            device = parts[0]
            if device in ('tmpfs', 'devtmpfs', 'overlay', 'none') or device.startswith('/dev/loop'):
                continue
            
            vol = VolumeInfo()
            vol.device = device
            vol.filesystem = parts[1]
            vol.mount_point = parts[6]
            
            try:
                vol.total_bytes = int(parts[2])
                vol.used_bytes = int(parts[3])
                vol.available_bytes = int(parts[4])
                vol.usage_percent = float(parts[5].rstrip('%'))
            except:
                pass
            
            self.result.volumes.append(vol)
    
    def collect_raid_info(self):
        """Raccoglie info RAID"""
        self.log("Raccolta info RAID...")
        
        mdstat = self.read_file("/proc/mdstat")
        if not mdstat or 'Personalities' not in mdstat:
            return
        
        current_raid = None
        
        for line in mdstat.split('\n'):
            md_match = re.match(r'^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)', line)
            if md_match:
                if current_raid:
                    self.result.raid_arrays.append(current_raid)
                
                current_raid = RAIDInfo()
                current_raid.name = f"/dev/{md_match.group(1)}"
                current_raid.status = md_match.group(2)
                current_raid.level = md_match.group(3).upper()
                
                for dev_match in re.finditer(r'(\w+)\[\d+\]', md_match.group(4)):
                    current_raid.disks.append(f"/dev/{dev_match.group(1)}")
                current_raid.total_disks = len(current_raid.disks)
            
            elif current_raid and 'blocks' in line:
                size_match = re.search(r'(\d+)\s*blocks', line)
                if size_match:
                    current_raid.size_bytes = int(size_match.group(1)) * 512
                
                state_match = re.search(r'\[([U_]+)\]', line)
                if state_match:
                    state = state_match.group(1)
                    current_raid.healthy_disks = state.count('U')
                    if '_' in state:
                        current_raid.status = "degraded"
                    else:
                        current_raid.status = "healthy"
        
        if current_raid:
            self.result.raid_arrays.append(current_raid)
    
    def collect_network_info(self):
        """Raccoglie info rete"""
        self.log("Raccolta info rete...")
        
        ip_addr = self.run_command("ip -o addr show")
        ip_link = self.run_command("ip -o link show")
        
        interfaces = {}
        
        for line in ip_link.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'\d+:\s+(\S+?)(?:@\S+)?:\s+<(.*)>\s+mtu\s+(\d+)', line)
            if match:
                name = match.group(1)
                flags = match.group(2)
                
                iface = NetworkInterface()
                iface.name = name
                iface.mtu = int(match.group(3))
                iface.state = "up" if "UP" in flags else "down"
                iface.is_virtual = name.startswith(('lo', 'veth', 'docker', 'br-', 'virbr'))
                iface.is_physical = not iface.is_virtual
                
                mac_match = re.search(r'link/\w+\s+([0-9a-f:]{17})', line)
                if mac_match:
                    iface.mac_address = mac_match.group(1).upper()
                
                interfaces[name] = iface
        
        for line in ip_addr.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            name = parts[1]
            if name not in interfaces:
                continue
            
            iface = interfaces[name]
            
            if 'inet ' in line:
                ip_match = re.search(r'inet\s+([0-9.]+)/(\d+)', line)
                if ip_match:
                    iface.ipv4_addresses.append(ip_match.group(1))
            
            elif 'inet6 ' in line:
                ip6_match = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line)
                if ip6_match:
                    addr = ip6_match.group(1)
                    if not addr.startswith('fe80'):
                        iface.ipv6_addresses.append(addr)
        
        self.result.network_interfaces = list(interfaces.values())
        
        # Gateway
        route = self.run_command("ip route show default")
        gw_match = re.search(r'default via ([0-9.]+)', route)
        if gw_match:
            self.result.default_gateway = gw_match.group(1)
        
        # DNS
        resolv = self.read_file("/etc/resolv.conf")
        for line in resolv.split('\n'):
            if line.startswith('nameserver'):
                self.result.dns_servers.append(line.split()[1])
    
    def collect_services(self):
        """Raccoglie servizi"""
        self.log("Raccolta servizi...")
        
        services = self.run_command("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | head -30")
        
        for line in services.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                svc = ServiceInfo()
                svc.name = parts[0].replace('.service', '')
                svc.status = 'running'
                
                self.result.services.append(svc)
    
    def collect_users(self):
        """Raccoglie utenti connessi"""
        who = self.run_command("who")
        users = set()
        
        for line in who.split('\n'):
            if line:
                parts = line.split()
                if parts:
                    users.add(parts[0])
        
        self.result.logged_in_users = list(users)
    
    def collect_nas_info(self):
        """Raccoglie info NAS specifiche"""
        self.log("Raccolta info NAS...")
        si = self.result.system_info
        
        if self.system_type == DeviceType.SYNOLOGY:
            synoinfo = self.read_file("/etc/synoinfo.conf")
            for line in synoinfo.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip('"')
                    if key == 'upnpmodelname':
                        si.model = value
            
            version = self.read_file("/etc.defaults/VERSION")
            for line in version.split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    value = value.strip('"')
                    if key == 'productversion':
                        si.firmware_version = value
            
            si.os_name = "Synology DSM"
        
        elif self.system_type == DeviceType.QNAP:
            model = self.run_command("getsysinfo model 2>/dev/null")
            if model:
                si.model = model
            
            firmware = self.run_command("getsysinfo fwver 2>/dev/null")
            if firmware:
                si.firmware_version = firmware
            
            si.os_name = "QNAP QTS"
    
    def collect_shares(self):
        """Raccoglie share NAS"""
        self.log("Raccolta share...")
        
        # SMB
        smb_conf = self.read_file("/etc/samba/smb.conf") or self.read_file("/etc/config/smb.conf")
        current_share = None
        
        for line in smb_conf.split('\n'):
            line = line.strip()
            
            if line.startswith('[') and line.endswith(']'):
                if current_share:
                    self.result.shares.append(current_share)
                
                share_name = line[1:-1]
                if share_name not in ('global', 'homes', 'printers'):
                    current_share = ShareInfo()
                    current_share.name = share_name
                    current_share.share_type = "SMB"
                else:
                    current_share = None
            
            elif current_share and '=' in line:
                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                if key == 'path':
                    current_share.path = value
        
        if current_share:
            self.result.shares.append(current_share)
        
        # NFS
        exports = self.read_file("/etc/exports")
        for line in exports.split('\n'):
            if line.strip() and not line.startswith('#'):
                parts = line.split()
                if parts:
                    share = ShareInfo()
                    share.path = parts[0]
                    share.name = parts[0].split('/')[-1]
                    share.share_type = "NFS"
                    self.result.shares.append(share)
    
    def collect_proxmox_vms(self):
        """Raccoglie VM Proxmox con dettagli completi"""
        self.log("Raccolta VM Proxmox...")
        self.result.hypervisor_type = "Proxmox VE"
        
        # QEMU VMs - raccogli lista base
        qm_list = self.run_command("qm list 2>/dev/null")
        vm_ids = []
        for line in qm_list.split('\n')[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 3:
                vm_ids.append(parts[0])
        
        # Per ogni VM QEMU, raccogli dettagli completi
        for vm_id in vm_ids:
            try:
                vm = VMInfo()
                vm.id = vm_id
                vm.type = "qemu"
                
                # Config completo della VM
                config = self.run_command(f"qm config {vm_id} 2>/dev/null")
                for line in config.split('\n'):
                    if not line.strip() or ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'name':
                        vm.name = value
                    elif key == 'cores':
                        try:
                            vm.cpus = int(value)
                        except:
                            pass
                    elif key == 'memory':
                        try:
                            vm.memory_bytes = int(value) * 1024 * 1024  # MB to bytes
                        except:
                            pass
                    elif key == 'net' and value:
                        # Estrai IP dalla configurazione di rete
                        if 'ip=' in value:
                            ip_part = value.split('ip=')[1].split()[0]
                            if ip_part and '/' in ip_part:
                                vm.ip_addresses = [ip_part.split('/')[0]]
                
                # Status dalla lista
                for line in qm_list.split('\n'):
                    if line.startswith(vm_id):
                        parts = line.split()
                        if len(parts) >= 3:
                            vm.status = parts[2].lower()
                            if not vm.name:
                                vm.name = parts[1]
                        break
                
                # Uptime e statistiche runtime
                status_json = self.run_command(f"qm status {vm_id} --output json 2>/dev/null")
                if status_json:
                    try:
                        import json
                        status_data = json.loads(status_json)
                        if isinstance(status_data, dict):
                            if 'uptime' in status_data:
                                vm.uptime = str(status_data['uptime'])
                            if 'cpu' in status_data:
                                try:
                                    vm.cpu_usage = float(status_data['cpu']) * 100
                                except:
                                    pass
                            if 'mem' in status_data:
                                try:
                                    vm.mem_used = int(status_data['mem'])
                                except:
                                    pass
                    except:
                        pass
                
                self.result.vms.append(vm)
            except Exception as e:
                self.log(f"Error collecting QEMU VM {vm_id}: {e}")
                # Fallback: aggiungi almeno info base
                vm = VMInfo()
                vm.id = vm_id
                vm.type = "qemu"
                for line in qm_list.split('\n'):
                    if line.startswith(vm_id):
                        parts = line.split()
                        if len(parts) >= 3:
                            vm.name = parts[1]
                            vm.status = parts[2].lower()
                        break
                self.result.vms.append(vm)
        
        # LXC Containers - raccogli lista base
        pct_list = self.run_command("pct list 2>/dev/null")
        lxc_ids = []
        for line in pct_list.split('\n')[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                lxc_ids.append(parts[0])
        
        # Per ogni LXC, raccogli dettagli completi
        for lxc_id in lxc_ids:
            try:
                vm = VMInfo()
                vm.id = lxc_id
                vm.type = "lxc"
                
                # Config completo del container
                config = self.run_command(f"pct config {lxc_id} 2>/dev/null")
                for line in config.split('\n'):
                    if not line.strip() or ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'hostname':
                        vm.name = value
                    elif key == 'cores':
                        try:
                            vm.cpus = int(value)
                        except:
                            pass
                    elif key == 'memory':
                        try:
                            vm.memory_bytes = int(value) * 1024 * 1024  # MB to bytes
                        except:
                            pass
                    elif key == 'net' and value:
                        # Estrai IP dalla configurazione di rete
                        if 'ip=' in value:
                            ip_part = value.split('ip=')[1].split()[0]
                            if ip_part and '/' in ip_part:
                                vm.ip_addresses = [ip_part.split('/')[0]]
                
                # Status dalla lista
                for line in pct_list.split('\n'):
                    if line.startswith(lxc_id):
                        parts = line.split()
                        if len(parts) >= 2:
                            vm.status = parts[1].lower()
                            if len(parts) >= 3 and not vm.name:
                                vm.name = parts[2]
                        break
                
                # Uptime e statistiche runtime
                status_json = self.run_command(f"pct status {lxc_id} --output json 2>/dev/null")
                if status_json:
                    try:
                        import json
                        status_data = json.loads(status_json)
                        if isinstance(status_data, dict):
                            if 'uptime' in status_data:
                                vm.uptime = str(status_data['uptime'])
                            if 'cpu' in status_data:
                                try:
                                    vm.cpu_usage = float(status_data['cpu']) * 100
                                except:
                                    pass
                            if 'mem' in status_data:
                                try:
                                    vm.mem_used = int(status_data['mem'])
                                except:
                                    pass
                    except:
                        pass
                
                self.result.vms.append(vm)
            except Exception as e:
                self.log(f"Error collecting LXC {lxc_id}: {e}")
                # Fallback: aggiungi almeno info base
                vm = VMInfo()
                vm.id = lxc_id
                vm.type = "lxc"
                for line in pct_list.split('\n'):
                    if line.startswith(lxc_id):
                        parts = line.split()
                        if len(parts) >= 2:
                            vm.status = parts[1].lower()
                            if len(parts) >= 3:
                                vm.name = parts[2]
                        break
                self.result.vms.append(vm)
    
    def collect_mikrotik_ssh(self):
        """Raccoglie dati completi MikroTik RouterOS via SSH"""
        self.log("Raccolta dati MikroTik RouterOS via SSH...")
        si = self.result.system_info
        
        # Imposta tipo e manufacturer
        si.device_type = "router"
        si.manufacturer = "MikroTik"
        si.os_name = "RouterOS"
        
        # ===== /system resource print =====
        ros_out = self.run_command("/system resource print", timeout=10)
        if ros_out:
            for line in ros_out.split('\n'):
                ll = line.lower().strip()
                if ll.startswith('version:'):
                    si.os_version = line.split(':', 1)[1].strip()
                elif ll.startswith('board-name:'):
                    si.model = line.split(':', 1)[1].strip()
                elif ll.startswith('cpu:') and 'cpu-count' not in ll:
                    if not self.result.cpu.model:
                        self.result.cpu.model = line.split(':', 1)[1].strip()
                elif ll.startswith('cpu-count:'):
                    try:
                        self.result.cpu.cores_physical = int(line.split(':', 1)[1].strip())
                        self.result.cpu.cores_logical = self.result.cpu.cores_physical
                    except:
                        pass
                elif ll.startswith('total-memory:'):
                    try:
                        mem_str = line.split(':', 1)[1].strip()
                        if 'MiB' in mem_str:
                            self.result.memory.total_bytes = int(float(mem_str.replace('MiB', '').strip())) * 1024 * 1024
                        elif 'GiB' in mem_str:
                            self.result.memory.total_bytes = int(float(mem_str.replace('GiB', '').strip()) * 1024 * 1024 * 1024)
                    except:
                        pass
                elif ll.startswith('free-memory:'):
                    try:
                        mem_str = line.split(':', 1)[1].strip()
                        if 'MiB' in mem_str:
                            self.result.memory.free_bytes = int(float(mem_str.replace('MiB', '').strip())) * 1024 * 1024
                    except:
                        pass
                elif ll.startswith('architecture-name:'):
                    si.architecture = line.split(':', 1)[1].strip()
                elif ll.startswith('uptime:'):
                    uptime_str = line.split(':', 1)[1].strip()
                    si.uptime = uptime_str
                    # Parse uptime per ottenere secondi
                    try:
                        # Format: "1w2d3h4m5s" o "1d2h3m4s"
                        import re
                        weeks = re.search(r'(\d+)w', uptime_str)
                        days = re.search(r'(\d+)d', uptime_str)
                        hours = re.search(r'(\d+)h', uptime_str)
                        minutes = re.search(r'(\d+)m', uptime_str)
                        seconds = re.search(r'(\d+)s', uptime_str)
                        total_secs = 0
                        if weeks:
                            total_secs += int(weeks.group(1)) * 7 * 24 * 3600
                        if days:
                            total_secs += int(days.group(1)) * 24 * 3600
                        if hours:
                            total_secs += int(hours.group(1)) * 3600
                        if minutes:
                            total_secs += int(minutes.group(1)) * 60
                        if seconds:
                            total_secs += int(seconds.group(1))
                        si.uptime_seconds = total_secs
                    except:
                        pass
        
        # ===== /system identity print =====
        identity_out = self.run_command("/system identity print", timeout=5)
        if identity_out:
            for line in identity_out.split('\n'):
                if 'name:' in line.lower():
                    si.hostname = line.split(':', 1)[1].strip()
                    break
        
        # ===== /system routerboard print =====
        rb_out = self.run_command("/system routerboard print", timeout=5)
        if rb_out:
            for line in rb_out.split('\n'):
                ll = line.lower().strip()
                if ll.startswith('serial-number:'):
                    si.serial_number = line.split(':', 1)[1].strip()
                elif ll.startswith('model:') and not si.model:
                    si.model = line.split(':', 1)[1].strip()
                elif ll.startswith('current-firmware:'):
                    si.firmware_version = line.split(':', 1)[1].strip()
        
        # ===== /system license print =====
        lic_out = self.run_command("/system license print", timeout=5)
        if lic_out:
            for line in lic_out.split('\n'):
                if 'level:' in line.lower():
                    si.license = line.split(':', 1)[1].strip()
        
        # ===== Interface count =====
        iface_count = self.run_command("/interface print count-only", timeout=5)
        if iface_count and iface_count.isdigit():
            # Aggiungi come metadata
            pass
        
        # ===== NEIGHBOR DISCOVERY (LLDP/CDP/MNDP) =====
        neighbor_out = self.run_command("/ip neighbor print detail", timeout=10)
        if neighbor_out and "interface=" in neighbor_out:
            neighbors = []
            current_neighbor = {}
            for line in neighbor_out.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                # Nuovo neighbor (inizia con numero)
                if line and line[0].isdigit() and 'interface=' in line:
                    if current_neighbor:
                        neighbor = LLDPNeighbor()
                        neighbor.local_port = current_neighbor.get('local_interface', '')
                        neighbor.remote_device = current_neighbor.get('remote_device_name', '')
                        neighbor.remote_ip = current_neighbor.get('remote_ip', '')
                        neighbor.remote_description = f"Platform: {current_neighbor.get('platform', '')}, Version: {current_neighbor.get('version', '')}"
                        self.result.lldp_neighbors.append(neighbor)
                    current_neighbor = {}
                    # Parse la prima riga
                    parts = line.split(' ', 1)
                    if len(parts) > 1:
                        line = parts[1]
                
                # Parse attributi
                for attr in line.split(' '):
                    if '=' in attr:
                        key, value = attr.split('=', 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        if key == 'interface':
                            current_neighbor['local_interface'] = value.split(',')[0]
                        elif key == 'identity':
                            current_neighbor['remote_device_name'] = value
                        elif key == 'mac-address':
                            current_neighbor['remote_mac'] = value
                        elif key == 'address' or key == 'address4':
                            if not current_neighbor.get('remote_ip'):
                                current_neighbor['remote_ip'] = value
                        elif key == 'platform':
                            current_neighbor['platform'] = value
                        elif key == 'version':
                            current_neighbor['version'] = value
                        elif key == 'board':
                            current_neighbor['board'] = value
                        elif key == 'interface-name':
                            current_neighbor['remote_interface'] = value
                        elif key == 'discovered-by':
                            current_neighbor['discovered_by'] = value
                        elif key == 'uptime':
                            current_neighbor['uptime'] = value
            
            # Aggiungi ultimo neighbor
            if current_neighbor:
                neighbor = LLDPNeighbor()
                neighbor.local_port = current_neighbor.get('local_interface', '')
                neighbor.remote_device = current_neighbor.get('remote_device_name', '')
                neighbor.remote_ip = current_neighbor.get('remote_ip', '')
                neighbor.remote_description = f"Platform: {current_neighbor.get('platform', '')}, Version: {current_neighbor.get('version', '')}"
                self.result.lldp_neighbors.append(neighbor)
        
        # ===== ROUTING TABLE =====
        routes_out = self.run_command("/ip route print terse where active", timeout=10)
        if routes_out:
            for line in routes_out.split('\n'):
                if 'dst-address=' in line:
                    route = {}
                    for attr in line.split(' '):
                        if '=' in attr:
                            key, value = attr.split('=', 1)
                            route[key.strip()] = value.strip()
                    if route:
                        self.result.routing_table.append(route)
        
        # ===== ARP TABLE =====
        arp_out = self.run_command("/ip arp print terse", timeout=10)
        if arp_out:
            for line in arp_out.split('\n'):
                if 'address=' in line:
                    entry = {}
                    for attr in line.split(' '):
                        if '=' in attr:
                            key, value = attr.split('=', 1)
                            entry[key.strip()] = value.strip()
                    if entry:
                        # Aggiungi come metadata o in una struttura dedicata
                        pass
        
        self.log(f"Raccolti dati MikroTik: hostname={si.hostname}, model={si.model}, serial={si.serial_number}, neighbors={len(self.result.lldp_neighbors)}, routes={len(self.result.routing_table)}")

    def collect_ubiquiti_ssh(self):
        """Raccoglie dati Ubiquiti switch via SSH con CLI Cisco-style"""
        self.log("Raccolta dati Ubiquiti via SSH CLI...")
        si = self.result.system_info
        
        # Imposta tipo e manufacturer
        si.device_type = "switch"
        si.manufacturer = "Ubiquiti"
        
        # Ubiquiti richiede modalità CLI interattiva
        # Usa invoke_shell per entrare in CLI mode
        try:
            import time
            shell = self.client.invoke_shell()
            time.sleep(1)
            
            # Leggi banner iniziale
            shell.recv(4096)
            
            # Entra in CLI mode
            shell.send("cli\n")
            time.sleep(1)
            shell.recv(4096)
            
            # ===== show version =====
            shell.send("show version\n")
            time.sleep(2)
            version_out = shell.recv(8192).decode('utf-8', errors='replace')
            
            for line in version_out.split('\n'):
                ll = line.strip()
                if '..' in ll:  # Linee con punti sono chiave-valore
                    parts = ll.split('..')
                    if len(parts) >= 2:
                        key = parts[0].strip().lower()
                        value = parts[-1].strip().lstrip('.')
                        
                        if 'system description' in key:
                            si.os_name = value
                        elif 'machine type' in key:
                            si.device_type = "switch"
                        elif 'machine model' in key:
                            si.model = value
                        elif 'serial number' in key:
                            si.serial_number = value
                        elif 'burned in mac' in key or 'mac address' in key:
                            si.mac_address = value
                        elif 'software version' in key:
                            si.firmware_version = value
                            si.os_version = value
            
            # ===== show sysinfo =====
            shell.send("show sysinfo\n")
            time.sleep(2)
            sysinfo_out = shell.recv(8192).decode('utf-8', errors='replace')
            
            for line in sysinfo_out.split('\n'):
                ll = line.strip()
                if '..' in ll:
                    parts = ll.split('..')
                    if len(parts) >= 2:
                        key = parts[0].strip().lower()
                        value = parts[-1].strip().lstrip('.')
                        
                        if 'system name' in key:
                            si.hostname = value
                        elif 'system location' in key:
                            pass  # location
                        elif 'system up time' in key:
                            si.uptime = value
                            # Parse uptime: "166 days 10 hrs 40 mins 30 secs"
                            try:
                                import re
                                days = re.search(r'(\d+)\s*day', value)
                                hours = re.search(r'(\d+)\s*hr', value)
                                mins = re.search(r'(\d+)\s*min', value)
                                secs = re.search(r'(\d+)\s*sec', value)
                                total_secs = 0
                                if days:
                                    total_secs += int(days.group(1)) * 86400
                                if hours:
                                    total_secs += int(hours.group(1)) * 3600
                                if mins:
                                    total_secs += int(mins.group(1)) * 60
                                if secs:
                                    total_secs += int(secs.group(1))
                                si.uptime_seconds = total_secs
                            except:
                                pass
            
            # ===== show hardware =====
            shell.send("show hardware\n")
            time.sleep(2)
            hw_out = shell.recv(8192).decode('utf-8', errors='replace')
            
            for line in hw_out.split('\n'):
                ll = line.strip()
                if '..' in ll:
                    parts = ll.split('..')
                    if len(parts) >= 2:
                        key = parts[0].strip().lower()
                        value = parts[-1].strip().lstrip('.')
                        
                        if 'switch' in key and 'description' not in key:
                            # Potrebbe essere "Switch: 1"
                            pass
                        elif not si.model and 'model' in key:
                            si.model = value
            
            # ===== show environment =====
            shell.send("show environment\n")
            time.sleep(2)
            env_out = shell.recv(8192).decode('utf-8', errors='replace')
            
            for line in env_out.split('\n'):
                ll = line.strip()
                if '..' in ll:
                    parts = ll.split('..')
                    if len(parts) >= 2:
                        key = parts[0].strip().lower()
                        value = parts[-1].strip().lstrip('.')
                        
                        if 'temperature' in key:
                            try:
                                # Valore tipo "45 C"
                                temp_val = int(value.split()[0])
                                si.temperature = temp_val
                            except:
                                pass
            
            # ===== show vlan =====
            shell.send("show vlan\n")
            time.sleep(2)
            vlan_out = shell.recv(16384).decode('utf-8', errors='replace')
            
            # Parse VLAN info se necessario
            # Per ora salviamo solo come warning/log
            vlan_count = vlan_out.count('VLAN ID')
            if vlan_count > 0:
                self.log(f"Trovati {vlan_count} VLAN")
            
            # Chiudi shell
            shell.send("exit\n")
            shell.close()
            
            self.log(f"Raccolti dati Ubiquiti: hostname={si.hostname}, model={si.model}, serial={si.serial_number}, firmware={si.firmware_version}")
            
        except Exception as e:
            self.log(f"Errore CLI Ubiquiti: {type(e).__name__}: {e}")
            self.result.errors.append(f"Ubiquiti CLI error: {e}")


# =============================================================================
# SNMP COLLECTOR (brief version - full version in separate file)
# =============================================================================

class SNMPCollector(BaseCollector):
    """Collector per dispositivi di rete via SNMP"""
    
    STANDARD_OIDS = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
    }
    
    def __init__(self, host: str, community: str = 'public',
                 port: int = 161, timeout: int = 10, retries: int = 2,
                 snmp_version: int = 2, verbose: bool = False):
        super().__init__(host, verbose)
        
        self.community = community or 'public'  # Fallback a public se None o vuoto
        self.port = port
        self.timeout = max(timeout, 10)  # Minimo 10 secondi per dispositivi lenti come Ubiquiti
        self.retries = max(retries, 3)  # Minimo 3 retry per dispositivi lenti
        self.snmp_version = snmp_version
        
        self.result.protocol_used = Protocol.SNMP.value
        
        # Log sempre per debug
        self.log(f"SNMPCollector init: host={host}, community='{self.community}', port={port}, version={snmp_version}, timeout={self.timeout}, retries={self.retries}")
    
    def connect(self) -> bool:
        """Verifica connettività SNMP"""
        if not HAS_SNMP:
            self.result.errors.append("pysnmp not installed")
            return False
        
        self.log(f"Test connessione SNMP: host={self.host}, port={self.port}, community='{self.community}', version={self.snmp_version}, timeout={self.timeout}, retries={self.retries}")
        
        try:
            # Prova prima con sysDescr che è più affidabile
            result = self._get_single(self.STANDARD_OIDS['sysDescr'])
            if result:
                self.log(f"Connesso! sysDescr={result[:100]}")
                return True
            
            # Se sysDescr fallisce, prova sysName
            result = self._get_single(self.STANDARD_OIDS['sysName'])
            if result:
                self.log(f"Connesso! sysName={result}")
                return True
            
            # Se anche sysName fallisce, prova sysObjectID
            result = self._get_single(self.STANDARD_OIDS['sysObjectID'])
            if result:
                self.log(f"Connesso! sysObjectID={result}")
                return True
            
            # Nessuna risposta
            self.log(f"SNMP no response dopo {self.retries} tentativi con timeout {self.timeout}s")
            self.result.errors.append(f"SNMP no response (host={self.host}, community='{self.community}', version={self.snmp_version})")
            return False
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            self.log(f"SNMP exception: {type(e).__name__}: {e}")
            self.log(f"SNMP traceback: {error_detail}")
            self.result.errors.append(f"SNMP error: {type(e).__name__}: {e}")
            return False
    
    def disconnect(self):
        """Chiude dispatcher SNMP se presente"""
        if hasattr(self, '_dispatcher') and self._dispatcher:
            try:
                self._dispatcher.transport_dispatcher.close_dispatcher()
            except:
                pass
            self._dispatcher = None
    
    def _get_single(self, oid: str) -> Optional[str]:
        """Ottiene singolo valore OID - wrapper sincrono per API async v7"""
        import asyncio
        
        try:
            # Usa event loop esistente o creane uno nuovo
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Se siamo già in un loop async, usa run_in_executor non funziona
                    # Creiamo un nuovo loop in un thread
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(self._get_single_sync_wrapper, oid)
                        return future.result(timeout=self.timeout + 5)
                else:
                    return loop.run_until_complete(self._get_single_async(oid))
            except RuntimeError:
                # Nessun event loop, creane uno
                return asyncio.run(self._get_single_async(oid))
        except Exception as e:
            if self.verbose:
                self.log(f"SNMP _get_single exception for OID {oid}: {type(e).__name__}: {e}")
            return None
    
    def _get_single_sync_wrapper(self, oid: str) -> Optional[str]:
        """Wrapper per eseguire _get_single_async in un nuovo event loop"""
        import asyncio
        return asyncio.run(self._get_single_async(oid))
    
    async def _get_single_async(self, oid: str) -> Optional[str]:
        """Ottiene singolo valore OID - API async pysnmp v7"""
        try:
            if self.verbose:
                self.log(f"SNMP GET: OID={oid}, host={self.host}, port={self.port}, community='{self.community}', version={self.snmp_version}")
            
            if SNMP_V7:
                # pysnmp v7.x - API asincrona
                dispatcher = SnmpDispatcherV7()
                
                try:
                    transport = await UdpTransportTargetV7.create(
            (self.host, self.port),
            timeout=self.timeout,
            retries=self.retries
        )
    
                    errorIndication, errorStatus, errorIndex, varBinds = await get_cmd_v7(
                        dispatcher,
                        CommunityDataV7(self.community),
                        transport,
                        ObjectTypeV7(ObjectIdentityV7(oid))
                    )
                finally:
                    try:
                        dispatcher.transport_dispatcher.close_dispatcher()
                    except:
                        pass
            else:
                # pysnmp v4/v5/v6 - API sincrona (legacy)
                mp_model = 0 if self.snmp_version == 1 else 1
                errorIndication, errorStatus, errorIndex, varBinds = next(
                    getCmd(SnmpEngine(),
                           CommunityData(self.community, mpModel=mp_model),
                           UdpTransportTarget((self.host, self.port), timeout=self.timeout, retries=self.retries),
                           ContextData(),
                           ObjectType(ObjectIdentity(oid)))
                )
            
            if errorIndication:
                if self.verbose:
                    self.log(f"SNMP errorIndication: {errorIndication}")
                return None
            
            if errorStatus:
                error_msg = errorStatus.prettyPrint() if hasattr(errorStatus, 'prettyPrint') else str(errorStatus)
                if self.verbose:
                    self.log(f"SNMP errorStatus: {error_msg}, errorIndex={errorIndex}")
                return None
            
            for varBind in varBinds:
                value = varBind[1]
                if hasattr(value, 'prettyPrint'):
                    value_str = value.prettyPrint()
                elif isinstance(value, bytes):
                    value_str = value.decode('utf-8', errors='replace')
                else:
                    value_str = str(value)
                if self.verbose:
                    self.log(f"SNMP GET success: OID={oid}, value={value_str[:100]}")
                return value_str
                
        except Exception as e:
            if self.verbose:
                import traceback
                self.log(f"SNMP _get_single_async exception for OID {oid}: {type(e).__name__}: {e}")
                self.log(f"Traceback: {traceback.format_exc()}")
            return None
    
    def _walk(self, oid: str) -> List[Tuple[str, str]]:
        """Esegue SNMP walk - wrapper sincrono per API async v7"""
        import asyncio
        
        try:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(self._walk_sync_wrapper, oid)
                        return future.result(timeout=self.timeout * 3 + 10)
                else:
                    return loop.run_until_complete(self._walk_async(oid))
            except RuntimeError:
                return asyncio.run(self._walk_async(oid))
        except Exception as e:
            if self.verbose:
                self.log(f"SNMP _walk exception for OID {oid}: {type(e).__name__}: {e}")
            return []
    
    def _walk_sync_wrapper(self, oid: str) -> List[Tuple[str, str]]:
        """Wrapper per eseguire _walk_async in un nuovo event loop"""
        import asyncio
        return asyncio.run(self._walk_async(oid))
    
    async def _walk_async(self, oid: str) -> List[Tuple[str, str]]:
        """Esegue SNMP walk - API async pysnmp v7"""
        results = []
        
        try:
            if SNMP_V7:
                # pysnmp v7.x - await next_cmd restituisce un singolo GETNEXT, serve loop manuale
                dispatcher = SnmpDispatcherV7()
                
                try:
                    transport = await UdpTransportTargetV7.create(
                        (self.host, self.port),
                        timeout=self.timeout,
                        retries=self.retries
                    )
                    
                    # Limita il walk a 200 elementi per evitare timeout
                    max_items = 200
                    count = 0
                    current_oid = oid
                    base_oid = oid.rstrip('.0')  # Rimuovi .0 finale per confronto
                    
                    # Loop manuale per GETNEXT
                    while count < max_items:
                        errorIndication, errorStatus, errorIndex, varBinds = await next_cmd_v7(
                            dispatcher,
                            CommunityDataV7(self.community),
                            transport,
                            ObjectTypeV7(ObjectIdentityV7(current_oid))
                        )
                        
                        if errorIndication:
                            if self.verbose:
                                self.log(f"SNMP walk errorIndication: {errorIndication}")
                            break
                        
                        if errorStatus:
                            if self.verbose:
                                self.log(f"SNMP walk errorStatus: {errorStatus}")
                            break
                        
                        if not varBinds:
                            if self.verbose:
                                self.log("No varBinds, exiting loop")
                            break
                        
                        exit_loop = False
                        for varBind in varBinds:
                            # Usa rappresentazione numerica dell'OID (non prettyPrint)
                            oid_obj = varBind[0]
                            oid_str = '.'.join(map(str, oid_obj)) if hasattr(oid_obj, '__iter__') else str(oid_obj)
                            value = varBind[1]
                            
                            # Verifica se siamo ancora nel subtree richiesto
                            if not oid_str.startswith(base_oid):
                                exit_loop = True
                                break
                            
                            if hasattr(value, 'prettyPrint'):
                                value_str = value.prettyPrint()
                            elif isinstance(value, bytes):
                                value_str = value.decode('utf-8', errors='replace')
                            else:
                                value_str = str(value)
                            
                            # Ignora valori "No Such Object"
                            if "No Such" in value_str:
                                continue
                            
                            results.append((oid_str, value_str))
                            current_oid = oid_str  # Prossimo OID
                            count += 1
                        
                        if exit_loop:
                            break
                        
                finally:
                    try:
                        dispatcher.transport_dispatcher.close_dispatcher()
                    except:
                        pass
            else:
                # pysnmp v4/v5/v6 - API sincrona (legacy)
                mp_model = 0 if self.snmp_version == 1 else 1
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(self.community, mpModel=mp_model),
                    UdpTransportTarget((self.host, self.port), timeout=self.timeout, retries=self.retries),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid)),
                    lexicographicMode=False
                ):
                    if errorIndication or errorStatus:
                        break
                    
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        value = varBind[1]
                        
                        if hasattr(value, 'prettyPrint'):
                            value_str = value.prettyPrint()
                        elif isinstance(value, bytes):
                            value_str = value.decode('utf-8', errors='replace')
                        else:
                            value_str = str(value)
                        
                        results.append((oid_str, value_str))
                    
                    # Limita a 100 elementi
                    if len(results) >= 100:
                        break
                        
        except Exception as e:
            if self.verbose:
                self.log(f"SNMP _walk_async exception for OID {oid}: {type(e).__name__}: {e}")
        
        return results
    
    def collect(self) -> ScanResult:
        """Raccoglie dati SNMP"""
        if not self.connect():
            return self.result
        
        try:
            self.collect_system_info()
            self.collect_interfaces()
            self.collect_routing()
            self.collect_lldp()
            
        finally:
            self.finalize()
        
        return self.result
    
    def collect_system_info(self):
        """Raccoglie info sistema via SNMP"""
        self.log("Raccolta info sistema SNMP...")
        si = self.result.system_info
        
        si.hostname = self._get_single(self.STANDARD_OIDS['sysName']) or ""
        si.device_type = DeviceType.SWITCH.value  # Default per SNMP
        
        descr = self._get_single(self.STANDARD_OIDS['sysDescr']) or ""
        si.os_name = descr[:100]
        
        # Parse vendor from sysObjectID
        sys_oid = self._get_single(self.STANDARD_OIDS['sysObjectID']) or ""
        
        if '14988' in sys_oid:
            si.manufacturer = "MikroTik"
            self._collect_mikrotik_info(si)
        elif '11863' in sys_oid:
            si.manufacturer = "TP-Link"
        elif '41112' in sys_oid:
            si.manufacturer = "Ubiquiti"
            self._collect_ubiquiti_info(si)
        elif '14823' in sys_oid:
            si.manufacturer = "Aruba"
        elif '11.2.3.7' in sys_oid:
            si.manufacturer = "HP ProCurve"
        elif '25506' in sys_oid:
            si.manufacturer = "HP Comware"
        
        # Uptime
        uptime = self._get_single(self.STANDARD_OIDS['sysUpTime'])
        if uptime:
            try:
                ticks = int(uptime)
                seconds = ticks // 100
                si.uptime_seconds = seconds
                si.uptime = parse_uptime_seconds(seconds)
            except:
                pass
    
    def _collect_mikrotik_info(self, si):
        """Raccoglie informazioni specifiche MikroTik complete"""
        self.log("Raccolta info MikroTik...")
        
        # Model
        model = self._get_single("1.3.6.1.4.1.14988.1.1.7.1.0")
        if model:
            si.model = model
        
        # Serial
        serial = self._get_single("1.3.6.1.4.1.14988.1.1.7.3.0")
        if serial:
            si.serial_number = serial
        
        # Firmware version
        firmware = self._get_single("1.3.6.1.4.1.14988.1.1.7.4.0")
        if firmware:
            si.os_version = firmware
        
        # Board name
        board = self._get_single("1.3.6.1.4.1.14988.1.1.7.8.0")
        if board:
            if not si.model:
                si.model = board
        
        # RouterOS version
        ros_version = self._get_single("1.3.6.1.4.1.14988.1.1.4.4.0")
        if ros_version:
            si.os_version = ros_version
        
        # License info
        license_id = self._get_single("1.3.6.1.4.1.14988.1.1.4.1.0")
        if license_id:
            si.license = license_id
        
        # Temperature (CPU)
        cpu_temp = self._get_single("1.3.6.1.4.1.14988.1.1.3.10.0")
        if cpu_temp:
            try:
                si.temperature = float(cpu_temp) / 10.0  # MikroTik temperature è in decimi di grado
            except:
                pass
        
        # Board temperature
        board_temp = self._get_single("1.3.6.1.4.1.14988.1.1.3.11.0")
        if board_temp:
            try:
                si.board_temperature = float(board_temp) / 10.0
            except:
                pass
        
        # Voltage
        voltage = self._get_single("1.3.6.1.4.1.14988.1.1.3.8.0")
        if voltage:
            try:
                si.voltage = float(voltage) / 10.0  # MikroTik voltage è in decimi di volt
            except:
                pass
        
        # Wireless info (se AP mode)
        wl_ssid = self._walk("1.3.6.1.4.1.14988.1.1.1.3.1.4")  # wlApSsid
        if wl_ssid:
            ssids = [v for _, v in wl_ssid if v]
            if ssids:
                si.wireless_ssids = ssids
    
    def _collect_ubiquiti_info(self, si):
        """Raccoglie informazioni specifiche Ubiquiti UniFi complete"""
        self.log("Raccolta info Ubiquiti UniFi...")
        
        # Prova OID scalari con .0 (UniFi AP/Device)
        model = self._get_single("1.3.6.1.4.1.41112.1.6.3.3.0")
        if not model:
            # Fallback: prova senza .0
            model = self._get_single("1.3.6.1.4.1.41112.1.6.3.3")
        if model:
            si.model = model
        
        # Firmware version
        version = self._get_single("1.3.6.1.4.1.41112.1.6.3.6.0")
        if not version:
            version = self._get_single("1.3.6.1.4.1.41112.1.6.3.6")
        if version:
            si.os_version = version
        
        # MAC address
        mac = self._get_single("1.3.6.1.4.1.41112.1.6.3.1.0")
        if mac:
            # Formatta MAC address
            if len(mac) == 12:
                mac = ':'.join(mac[i:i+2] for i in range(0, 12, 2))
            si.mac_address = mac.upper()
        
        # Prova anche OID specifici per Switch
        sw_model = self._get_single("1.3.6.1.4.1.41112.1.4.1.1.1")
        if sw_model and not si.model:
            si.model = sw_model
        
        sw_version = self._get_single("1.3.6.1.4.1.41112.1.4.1.1.2")
        if sw_version and not si.os_version:
            si.os_version = sw_version
        
        sw_serial = self._get_single("1.3.6.1.4.1.41112.1.4.1.1.3")
        if sw_serial:
            si.serial_number = sw_serial
        
        # CPU usage (per switch)
        cpu_usage = self._get_single("1.3.6.1.4.1.41112.1.4.7.1.5.1")
        if cpu_usage:
            try:
                si.cpu_usage_percent = float(cpu_usage)
            except:
                pass
        
        # Memory usage (per switch)
        mem_usage = self._get_single("1.3.6.1.4.1.41112.1.4.7.1.5.2")
        if mem_usage:
            try:
                si.memory_usage_percent = float(mem_usage)
            except:
                pass
        
        # Temperature (per switch)
        temp = self._get_single("1.3.6.1.4.1.41112.1.4.7.1.5.3")
        if temp:
            try:
                si.temperature = float(temp)
            except:
                pass
        
        # WiFi clients (per AP)
        wifi_clients = self._get_single("1.3.6.1.4.1.41112.1.6.1.2.1.8.0")
        if wifi_clients:
            try:
                si.wifi_clients_count = int(wifi_clients)
            except:
                pass
        
        # Load average (per Linux-based UniFi devices)
        load_avg = self._get_single("1.3.6.1.4.1.2021.10.1.3.1.0")
        if load_avg:
            try:
                si.load_average_1m = float(load_avg)
            except:
                pass
        
        # RAM available (per Linux-based UniFi devices)
        ram_avail = self._get_single("1.3.6.1.4.1.2021.4.6.0")
        if ram_avail:
            try:
                si.ram_available_mb = int(ram_avail)
            except:
                pass
    
    def collect_interfaces(self):
        """Raccoglie interfacce via SNMP con dettagli completi"""
        self.log("Raccolta interfacce SNMP...")
        
        if_descr = self._walk('1.3.6.1.2.1.2.2.1.2')      # ifDescr
        if_speed = self._walk('1.3.6.1.2.1.31.1.1.1.15')  # ifHighSpeed (Mbps)
        if_admin = self._walk('1.3.6.1.2.1.2.2.1.7')      # ifAdminStatus
        if_oper = self._walk('1.3.6.1.2.1.2.2.1.8')       # ifOperStatus
        if_mac = self._walk('1.3.6.1.2.1.2.2.1.6')        # ifPhysAddress
        if_type = self._walk('1.3.6.1.2.1.2.2.1.3')       # ifType
        if_mtu = self._walk('1.3.6.1.2.1.2.2.1.4')        # ifMtu
        if_in_octets = self._walk('1.3.6.1.2.1.2.2.1.10') # ifInOctets
        if_out_octets = self._walk('1.3.6.1.2.1.2.2.1.16') # ifOutOctets
        
        interfaces = {}
        
        # Build interface index map
        for oid, value in if_descr:
            idx = oid.split('.')[-1]
            interfaces[idx] = NetworkInterface()
            interfaces[idx].name = value
        
        # Add speed
        for oid, value in if_speed:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                try:
                    interfaces[idx].speed_mbps = int(value)
                except:
                    pass
        
        # Add admin status
        for oid, value in if_admin:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                interfaces[idx].state = "up" if value == '1' else "down"
        
        # Add operational status
        for oid, value in if_oper:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                if value == '1':
                    interfaces[idx].state = "up"
                elif value == '2':
                    interfaces[idx].state = "down"
                else:
                    interfaces[idx].state = "unknown"
        
        # Add MAC address
        for oid, value in if_mac:
            idx = oid.split('.')[-1]
            if idx in interfaces and value:
                try:
                    if isinstance(value, bytes):
                        mac = ':'.join(f'{b:02x}' for b in value[:6])
                    elif len(value) >= 6:
                        mac = ':'.join(f'{b:02x}' for b in value.encode('latin-1')[:6])
                    else:
                        mac = value
                    interfaces[idx].mac_address = mac.upper()
                except:
                    pass
        
        # Add interface type
        for oid, value in if_type:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                try:
                    if_type_map = {
                        6: "ethernet",
                        24: "loopback",
                        131: "tunnel",
                        161: "ieee80211",  # Wireless
                    }
                    type_num = int(value)
                    interfaces[idx].interface_type = if_type_map.get(type_num, f"type_{type_num}")
                except:
                    pass
        
        # Add MTU
        for oid, value in if_mtu:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                try:
                    interfaces[idx].mtu = int(value)
                except:
                    pass
        
        # Add traffic stats
        for oid, value in if_in_octets:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                try:
                    interfaces[idx].rx_bytes = int(value)
                except:
                    pass
        
        for oid, value in if_out_octets:
            idx = oid.split('.')[-1]
            if idx in interfaces:
                try:
                    interfaces[idx].tx_bytes = int(value)
                except:
                    pass
        
        self.result.network_interfaces = list(interfaces.values())
    
    def collect_routing(self):
        """Raccoglie routing table via SNMP completa"""
        self.log("Raccolta routing SNMP...")
        
        # IP Forwarding Table MIB
        ip_route_dest = self._walk('1.3.6.1.2.1.4.21.1.1')    # ipRouteDest
        ip_route_mask = self._walk('1.3.6.1.2.1.4.21.1.11')   # ipRouteMask
        ip_route_next_hop = self._walk('1.3.6.1.2.1.4.21.1.7') # ipRouteNextHop
        ip_route_type = self._walk('1.3.6.1.2.1.4.21.1.8')     # ipRouteType
        ip_route_proto = self._walk('1.3.6.1.2.1.4.21.1.9')   # ipRouteProto
        
        # Build route index map
        routes = {}
        for oid, value in ip_route_dest:
            idx = oid.split('.')[-1]
            routes[idx] = {'destination': value}
        
        # Add mask
        for oid, value in ip_route_mask:
            idx = oid.split('.')[-1]
            if idx in routes:
                routes[idx]['mask'] = value
        
        # Add next hop
        for oid, value in ip_route_next_hop:
            idx = oid.split('.')[-1]
            if idx in routes:
                routes[idx]['next_hop'] = value
        
        # Add type
        for oid, value in ip_route_type:
            idx = oid.split('.')[-1]
            if idx in routes:
                route_type_map = {
                    1: "other",
                    2: "invalid",
                    3: "direct",
                    4: "indirect",
                }
                routes[idx]['type'] = route_type_map.get(int(value), f"type_{value}")
        
        # Add protocol
        for oid, value in ip_route_proto:
            idx = oid.split('.')[-1]
            if idx in routes:
                proto_map = {
                    1: "other",
                    2: "local",
                    3: "netmgmt",
                    4: "icmp",
                    5: "egp",
                    6: "ggp",
                    7: "hello",
                    8: "rip",
                    9: "is-is",
                    10: "es-is",
                    11: "ciscoIgrp",
                    12: "bbnSpfIgrp",
                    13: "ospf",
                    14: "bgp",
                }
                routes[idx]['protocol'] = proto_map.get(int(value), f"proto_{value}")
        
        # Convert to list
        for route in routes.values():
            self.result.routing_table.append(route)
    
    def collect_lldp(self):
        """Raccoglie LLDP neighbors con dettagli completi"""
        self.log("Raccolta LLDP neighbors...")
        
        # LLDP Remote Table OIDs
        # Il formato OID è ...timeMark.localPortNum.remoteIndex
        lldp_sysname = self._walk('1.0.8802.1.1.2.1.4.1.1.9')     # lldpRemSysName
        lldp_sysdesc = self._walk('1.0.8802.1.1.2.1.4.1.1.10')    # lldpRemSysDesc
        lldp_chassis_id = self._walk('1.0.8802.1.1.2.1.4.1.1.5')  # lldpRemChassisId
        lldp_port_id = self._walk('1.0.8802.1.1.2.1.4.1.1.7')     # lldpRemPortId
        lldp_man_addr = self._walk('1.0.8802.1.1.2.1.4.2.1.4')    # lldpRemManAddr (Management IP)
        
        # Build index maps: OID format is ...timeMark.localPortNum.remoteIndex
        # Il port number locale è il secondo-ultimo elemento dell'OID index
        sys_names = {}    # Key: "timeMark.localPortNum.remoteIndex", Value: (local_port, system name)
        sys_descs = {}    # Key: "timeMark.localPortNum.remoteIndex", Value: system description
        chassis_ids = {}  # Key: "timeMark.localPortNum.remoteIndex", Value: chassis ID (MAC)
        remote_port_ids = {}  # Key: "timeMark.localPortNum.remoteIndex", Value: remote port ID
        mgmt_ips = {}     # Key: localPortNum, Value: IP address (per matching con neighbor)
        
        # Parse system names - estrai anche local port dall'OID
        for oid, value in lldp_sysname:
            oid_parts = oid.split('.')
            if len(oid_parts) >= 3:
                index_key = '.'.join(oid_parts[-3:])
                # Il localPortNum è il secondo-ultimo elemento dell'indice
                local_port = oid_parts[-2]  # es: "23" da ".26.23.9"
                sys_names[index_key] = (local_port, value if value else "")
        
        # Parse system descriptions
        for oid, value in lldp_sysdesc:
            if value and "No Such" not in value:
                oid_parts = oid.split('.')
                if len(oid_parts) >= 3:
                    index_key = '.'.join(oid_parts[-3:])
                    sys_descs[index_key] = value
        
        # Parse chassis IDs
        for oid, value in lldp_chassis_id:
            if value and "No Such" not in value:
                oid_parts = oid.split('.')
                if len(oid_parts) >= 3:
                    index_key = '.'.join(oid_parts[-3:])
                    # Chassis ID è spesso MAC address in formato hex
                    if isinstance(value, bytes):
                        try:
                            chassis_ids[index_key] = ':'.join(f'{b:02x}' for b in value[:6])
                        except:
                            chassis_ids[index_key] = str(value)
                    elif value.startswith('0x'):
                        # Converti hex string in MAC
                        try:
                            hex_str = value[2:]
                            if len(hex_str) >= 12:
                                chassis_ids[index_key] = ':'.join(hex_str[i:i+2] for i in range(0, 12, 2))
                            else:
                                chassis_ids[index_key] = value
                        except:
                            chassis_ids[index_key] = str(value)
                    else:
                        chassis_ids[index_key] = str(value)
        
        # Parse remote port IDs
        for oid, value in lldp_port_id:
            if value and "No Such" not in value:
                oid_parts = oid.split('.')
                if len(oid_parts) >= 3:
                    index_key = '.'.join(oid_parts[-3:])
                    remote_port_ids[index_key] = value
        
        # Parse management addresses (IP remoti)
        # OID format: ...timeMark.localPortNum.index.addrSubtype.addrLen.IP1.IP2.IP3.IP4
        # Es: 1.0.8802.1.1.2.1.4.2.1.4.8329387.32.2936429.1.4.192.168.15.254
        # Dove: localPortNum=32, addrSubtype=1 (IPv4), addrLen=4, IP=192.168.15.254
        for oid, value in lldp_man_addr:
            oid_parts = oid.split('.')
            # Cerca pattern .1.4. che indica IPv4 (subtype=1, len=4)
            try:
                # Trova la posizione di .1.4. nell'OID
                oid_str = oid
                if '.1.4.' in oid_str:
                    # L'IP è dopo .1.4.
                    ip_start = oid_str.rfind('.1.4.') + 5
                    ip_octets = oid_str[ip_start:].split('.')
                    if len(ip_octets) >= 4:
                        ip_addr = '.'.join(ip_octets[:4])
                        # Verifica che sia un IP valido
                        if all(0 <= int(o) <= 255 for o in ip_octets[:4]):
                            # Trova il localPortNum (subito prima dell'index)
                            # Format: base_oid.timeMark.localPortNum.index.1.4.IP
                            base_oid = '1.0.8802.1.1.2.1.4.2.1.4'
                            suffix = oid_str[len(base_oid)+1:]  # Rimuovi base OID e punto
                            suffix_parts = suffix.split('.')
                            if len(suffix_parts) >= 2:
                                local_port = suffix_parts[1]  # secondo elemento è localPortNum
                                if local_port not in mgmt_ips:
                                    mgmt_ips[local_port] = ip_addr
            except (ValueError, IndexError):
                pass
        
        if mgmt_ips:
            self.log(f"Trovati {len(mgmt_ips)} management IP: {dict(list(mgmt_ips.items())[:5])}")
        
        # Build neighbor list - usa sys_names come base (ha sempre i dati)
        count = 0
        for index_key, (local_port, sys_name) in list(sys_names.items())[:50]:
            # Crea neighbor anche senza nome (usando chassis ID come identificativo)
            chassis_id = chassis_ids.get(index_key, "")
            remote_name = sys_name if sys_name else chassis_id if chassis_id else f"unknown-{index_key}"
            
            if remote_name and remote_name != f"unknown-{index_key}":  # Salta se non abbiamo nessuna info
                neighbor = LLDPNeighbor()
                neighbor.local_port = f"Port {local_port}"
                neighbor.remote_device = remote_name
                neighbor.remote_description = sys_descs.get(index_key, "")
                neighbor.remote_port = remote_port_ids.get(index_key, "")
                
                # Cerca IP di management per questa porta locale
                neighbor.remote_ip = mgmt_ips.get(local_port, "")
                
                # Aggiungi chassis ID come info extra nel remote_description se manca
                if not neighbor.remote_description and chassis_id and sys_name:
                    neighbor.remote_description = f"MAC: {chassis_id}"
                
                self.result.lldp_neighbors.append(neighbor)
                count += 1
        
        if self.result.lldp_neighbors:
            self.log(f"Trovati {len(self.result.lldp_neighbors)} LLDP neighbors")


# =============================================================================
# UNIFIED SCANNER
# =============================================================================

class UnifiedScanner:
    """Scanner unificato multi-protocollo"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def scan(self, target: str, protocol: Protocol = Protocol.AUTO,
             # Common
             timeout: int = 30,
             # SSH
             ssh_user: str = None, ssh_password: str = None, ssh_key: str = None, ssh_port: int = 22,
             # WinRM
             winrm_user: str = None, winrm_password: str = None, winrm_domain: str = "",
             winrm_port: int = 5985, winrm_ssl: bool = False,
             # SNMP
             snmp_community: str = 'public', snmp_port: int = 161, snmp_version: int = 2
             ) -> ScanResult:
        """
        Scansiona un target con il protocollo specificato
        
        Args:
            target: IP o hostname
            protocol: Protocollo da usare (AUTO per rilevamento automatico)
            ... parametri specifici per protocollo
        
        Returns:
            ScanResult con tutti i dati raccolti
        """
        
        # Auto-detect protocol if needed
        if protocol == Protocol.AUTO:
            protocol = detect_protocol(target)
            if self.verbose:
                logger.debug(f"[{target}] Protocollo rilevato: {protocol.value}")
        
        # Select collector
        if protocol == Protocol.WINRM:
            if not winrm_user or not winrm_password:
                result = ScanResult(target=target, scan_status=ScanStatus.FAILED.value)
                result.errors.append("WinRM requires username and password")
                return result
            
            collector = WindowsCollector(
                host=target,
                username=winrm_user,
                password=winrm_password,
                domain=winrm_domain,
                port=winrm_port,
                use_ssl=winrm_ssl,
                verbose=self.verbose
            )
        
        elif protocol == Protocol.SSH:
            if not ssh_user:
                result = ScanResult(target=target, scan_status=ScanStatus.FAILED.value)
                result.errors.append("SSH requires username")
                return result
            
            collector = LinuxSSHCollector(
                host=target,
                username=ssh_user,
                password=ssh_password,
                key_file=ssh_key,
                port=ssh_port,
                timeout=timeout,
                verbose=self.verbose
            )
        
        elif protocol == Protocol.SNMP:
            collector = SNMPCollector(
                host=target,
                community=snmp_community,
                port=snmp_port,
                timeout=timeout,
                snmp_version=snmp_version,
                verbose=self.verbose
            )
        
        else:
            result = ScanResult(target=target, scan_status=ScanStatus.FAILED.value)
            result.errors.append(f"Unknown protocol: {protocol}")
            return result
        
        return collector.collect()


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

def format_text_report(data: ScanResult) -> str:
    """Formatta report testuale"""
    lines = []
    sep = "=" * 80
    
    lines.append(sep)
    lines.append(f"REPORT: {data.target}")
    lines.append(f"Protocollo: {data.protocol_used} | Status: {data.scan_status}")
    lines.append(f"Scansione: {data.scan_timestamp} ({data.scan_duration_seconds}s)")
    lines.append(sep)
    
    # System Info
    si = data.system_info
    lines.append("\n### SISTEMA ###")
    lines.append(f"  Hostname:       {si.hostname}")
    if si.domain:
        lines.append(f"  Domain:         {si.domain}")
    lines.append(f"  Tipo:           {si.device_type}")
    lines.append(f"  OS:             {si.os_name} {si.os_version}")
    if si.kernel_version:
        lines.append(f"  Kernel:         {si.kernel_version}")
    lines.append(f"  Arch:           {si.architecture}")
    if si.manufacturer:
        lines.append(f"  Produttore:     {si.manufacturer}")
    if si.model:
        lines.append(f"  Modello:        {si.model}")
    if si.serial_number:
        lines.append(f"  Seriale:        {si.serial_number}")
    lines.append(f"  Uptime:         {si.uptime}")
    
    # CPU
    cpu = data.cpu
    if cpu.model:
        lines.append("\n### CPU ###")
        lines.append(f"  Modello:        {cpu.model}")
        lines.append(f"  Core:           {cpu.cores_physical} fisici / {cpu.cores_logical} logici")
        if cpu.load_percent:
            lines.append(f"  Utilizzo:       {cpu.load_percent:.1f}%")
        if cpu.load_1min:
            lines.append(f"  Load:           {cpu.load_1min:.2f} / {cpu.load_5min:.2f} / {cpu.load_15min:.2f}")
        if cpu.temperature_celsius:
            lines.append(f"  Temperatura:    {cpu.temperature_celsius:.1f}°C")
    
    # Memory
    mem = data.memory
    if mem.total_bytes:
        lines.append("\n### MEMORIA ###")
        lines.append(f"  Totale:         {human_size(mem.total_bytes)}")
        lines.append(f"  Usata:          {human_size(mem.used_bytes)} ({mem.usage_percent:.1f}%)")
        if mem.swap_total_bytes:
            lines.append(f"  Swap:           {human_size(mem.swap_used_bytes)} / {human_size(mem.swap_total_bytes)}")
    
    # Disks
    if data.disks:
        lines.append(f"\n### DISCHI ({len(data.disks)}) ###")
        for disk in data.disks:
            status = f" [{disk.health_status}]" if disk.health_status else ""
            lines.append(f"  {disk.device}: {disk.model} - {disk.size_human} {disk.type}{status}")
    
    # Volumes
    if data.volumes:
        lines.append(f"\n### VOLUMI ({len(data.volumes)}) ###")
        for vol in data.volumes:
            mount = vol.mount_point or vol.drive_letter
            lines.append(f"  {mount}: {human_size(vol.used_bytes)} / {human_size(vol.total_bytes)} ({vol.usage_percent:.1f}%)")
    
    # Network
    if data.network_interfaces:
        active = [i for i in data.network_interfaces if i.state == 'up' and i.ipv4_addresses]
        lines.append(f"\n### RETE ({len(active)} attive / {len(data.network_interfaces)} totali) ###")
        for iface in active:
            ips = ', '.join(iface.ipv4_addresses)
            speed = f" {iface.speed_mbps}Mbps" if iface.speed_mbps else ""
            lines.append(f"  {iface.name}: {ips}{speed}")
        
        if data.default_gateway:
            lines.append(f"  Gateway:        {data.default_gateway}")
        if data.dns_servers:
            lines.append(f"  DNS:            {', '.join(data.dns_servers)}")
    
    # LLDP Neighbors
    if data.lldp_neighbors:
        lines.append(f"\n### LLDP NEIGHBORS ({len(data.lldp_neighbors)}) ###")
        for n in data.lldp_neighbors:
            lines.append(f"  {n.local_port} -> {n.remote_device}")
    
    # Services
    if data.services:
        running = [s for s in data.services if s.status == 'running' or s.status == 'active']
        lines.append(f"\n### SERVIZI ({len(running)} running) ###")
        for svc in running[:10]:
            lines.append(f"  {svc.name}: {svc.status}")
        if len(running) > 10:
            lines.append(f"  ... e altri {len(running) - 10}")
    
    # Shares
    if data.shares:
        lines.append(f"\n### SHARE ({len(data.shares)}) ###")
        for share in data.shares:
            lines.append(f"  [{share.share_type}] {share.name}: {share.path}")
    
    # VMs
    if data.vms:
        lines.append(f"\n### VM ({len(data.vms)}) - {data.hypervisor_type} ###")
        for vm in data.vms:
            lines.append(f"  [{vm.id}] {vm.name} ({vm.type}) - {vm.status}")
    
    # Security (Windows)
    if data.antivirus_status:
        lines.append("\n### SICUREZZA ###")
        lines.append(f"  Antivirus:      {data.antivirus_status}")
        lines.append(f"  Firewall:       {data.firewall_status}")
        if data.updates_pending:
            lines.append(f"  Update pending: {data.updates_pending}")
    
    # Errors
    if data.errors:
        lines.append("\n### ERRORI ###")
        for err in data.errors:
            lines.append(f"  - {err}")
    
    lines.append("\n" + sep)
    
    return "\n".join(lines)


def result_to_dict(data: ScanResult) -> dict:
    """Converte ScanResult in dizionario"""
    d = asdict(data)
    return d


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Unified Infrastructure Scanner (SNMP/SSH/WinRM)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Protocolli supportati:
  SNMP   - Switch, Router, Access Point (HP, Aruba, UniFi, MikroTik, TP-Link)
  SSH    - Linux, Synology, QNAP, Proxmox
  WinRM  - Windows Server, Windows Client

Esempi:
  # Auto-detect protocol
  %(prog)s 192.168.1.1 --ssh-user admin --ssh-pass password
  
  # Force specific protocol
  %(prog)s 192.168.1.1 -P winrm --winrm-user admin --winrm-pass password
  %(prog)s 192.168.1.1 -P snmp --snmp-community public
  
  # Multiple targets
  %(prog)s -f hosts.txt --ssh-user root --ssh-key ~/.ssh/id_rsa -o results/
        """
    )
    
    # Targets
    parser.add_argument('targets', nargs='*', help='IP o hostname dei target')
    parser.add_argument('-f', '--file', help='File con lista target (uno per riga)')
    
    # Protocol selection
    parser.add_argument('-P', '--protocol', choices=['auto', 'snmp', 'ssh', 'winrm'], 
                        default='auto', help='Protocollo (default: auto)')
    
    # SSH options
    ssh_group = parser.add_argument_group('SSH Options')
    ssh_group.add_argument('--ssh-user', help='SSH username')
    ssh_group.add_argument('--ssh-pass', help='SSH password')
    ssh_group.add_argument('--ssh-key', help='SSH private key file')
    ssh_group.add_argument('--ssh-port', type=int, default=22, help='SSH port (default: 22)')
    
    # WinRM options
    winrm_group = parser.add_argument_group('WinRM Options')
    winrm_group.add_argument('--winrm-user', help='WinRM username')
    winrm_group.add_argument('--winrm-pass', help='WinRM password')
    winrm_group.add_argument('--winrm-domain', default='', help='Windows domain')
    winrm_group.add_argument('--winrm-port', type=int, default=5985, help='WinRM port (default: 5985)')
    winrm_group.add_argument('--winrm-ssl', action='store_true', help='Use HTTPS for WinRM')
    
    # SNMP options
    snmp_group = parser.add_argument_group('SNMP Options')
    snmp_group.add_argument('--snmp-community', default='public', help='SNMP community (default: public)')
    snmp_group.add_argument('--snmp-port', type=int, default=161, help='SNMP port (default: 161)')
    snmp_group.add_argument('--snmp-version', type=int, choices=[1, 2], default=2, help='SNMP version')
    
    # Output options
    parser.add_argument('-o', '--output', help='Output file or directory')
    parser.add_argument('--format', choices=['text', 'json', 'both'], default='both', help='Output format')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout (default: 30)')
    parser.add_argument('-j', '--parallel', type=int, default=1, help='Parallel scans (default: 1)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Collect targets
    targets = list(args.targets) if args.targets else []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line.split()[0])
        except FileNotFoundError:
            print(f"ERRORE: File non trovato: {args.file}")
            sys.exit(1)
    
    if not targets:
        parser.print_help()
        print("\nERRORE: Specificare almeno un target")
        sys.exit(1)
    
    # Map protocol
    protocol_map = {
        'auto': Protocol.AUTO,
        'snmp': Protocol.SNMP,
        'ssh': Protocol.SSH,
        'winrm': Protocol.WINRM
    }
    protocol = protocol_map[args.protocol]
    
    # Scanner
    scanner = UnifiedScanner(verbose=args.verbose)
    
    # Scan function
    def scan_target(target: str) -> ScanResult:
        print(f"\n{'='*60}")
        print(f"Scansione: {target}")
        print(f"{'='*60}")
        
        result = scanner.scan(
            target=target,
            protocol=protocol,
            timeout=args.timeout,
            # SSH
            ssh_user=args.ssh_user,
            ssh_password=args.ssh_pass,
            ssh_key=args.ssh_key,
            ssh_port=args.ssh_port,
            # WinRM
            winrm_user=args.winrm_user,
            winrm_password=args.winrm_pass,
            winrm_domain=args.winrm_domain,
            winrm_port=args.winrm_port,
            winrm_ssl=args.winrm_ssl,
            # SNMP
            snmp_community=args.snmp_community,
            snmp_port=args.snmp_port,
            snmp_version=args.snmp_version
        )
        
        if args.format in ('text', 'both'):
            print(format_text_report(result))
        
        return result
    
    # Execute scans
    all_results = []
    
    if args.parallel > 1 and len(targets) > 1:
        with ThreadPoolExecutor(max_workers=args.parallel) as executor:
            futures = {executor.submit(scan_target, t): t for t in targets}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_results.append(result)
    else:
        for target in targets:
            result = scan_target(target)
            all_results.append(result)
    
    # Save output
    if args.output and all_results:
        import os
        
        if os.path.isdir(args.output) or args.output.endswith('/'):
            os.makedirs(args.output, exist_ok=True)
            
            for data in all_results:
                base_name = data.target.replace('.', '_').replace(':', '_')
                
                if args.format in ('json', 'both'):
                    json_path = os.path.join(args.output, f"{base_name}.json")
                    with open(json_path, 'w') as f:
                        json.dump(result_to_dict(data), f, indent=2, default=str)
                    print(f"Salvato: {json_path}")
                
                if args.format in ('text', 'both'):
                    text_path = os.path.join(args.output, f"{base_name}.txt")
                    with open(text_path, 'w') as f:
                        f.write(format_text_report(data))
                    print(f"Salvato: {text_path}")
        
        else:
            if args.output.endswith('.json') or args.format == 'json':
                with open(args.output, 'w') as f:
                    if len(all_results) == 1:
                        json.dump(result_to_dict(all_results[0]), f, indent=2, default=str)
                    else:
                        json.dump([result_to_dict(d) for d in all_results], f, indent=2, default=str)
                print(f"Salvato: {args.output}")
            else:
                with open(args.output, 'w') as f:
                    for data in all_results:
                        f.write(format_text_report(data))
                        f.write("\n\n")
                print(f"Salvato: {args.output}")
    
    # Summary
    success = len([r for r in all_results if r.scan_status == ScanStatus.SUCCESS.value])
    partial = len([r for r in all_results if r.scan_status == ScanStatus.PARTIAL.value])
    failed = len([r for r in all_results if r.scan_status == ScanStatus.FAILED.value])
    
    print(f"\n{'='*60}")
    print(f"RIEPILOGO: {len(all_results)} target scansionati")
    print(f"  Successo: {success} | Parziale: {partial} | Falliti: {failed}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
