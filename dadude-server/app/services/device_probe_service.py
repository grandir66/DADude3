"""
DaDude - Device Probe Service
Identifica tipo dispositivo tramite SSH, SNMP, WMI
Supporta esecuzione tramite agente MikroTik remoto
"""
from typing import Optional, Dict, Any, List
from loguru import logger
import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from .mac_lookup_service import get_mac_lookup_service


class ProbeProtocol(Enum):
    SSH = "ssh"
    SNMP = "snmp"
    WMI = "wmi"
    MIKROTIK_API = "mikrotik_api"
    HTTP = "http"
    HTTPS = "https"


@dataclass
class ProbeResult:
    """Risultato di un probe"""
    success: bool
    protocol: str
    device_type: Optional[str] = None
    category: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    hostname: Optional[str] = None
    model: Optional[str] = None
    extra_info: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class MikroTikAgent:
    """
    Rappresenta un agente MikroTik per operazioni remote.
    Tutte le operazioni di rete (port scan, DNS, ping) possono essere eseguite
    tramite questo agente invece che dalla macchina locale.
    """
    address: str
    username: str
    password: str
    port: int = 22  # SSH port
    api_port: int = 8728
    use_ssl: bool = False
    dns_server: Optional[str] = None  # DNS server da usare per le query
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "address": self.address,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "api_port": self.api_port,
            "use_ssl": self.use_ssl,
            "dns_server": self.dns_server,
        }


class DeviceProbeService:
    """Servizio per identificare dispositivi tramite probe attivi"""
    
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=10)
    
    async def probe_device(
        self,
        address: str,
        credentials: Dict[str, Any],
        protocols: List[str] = None
    ) -> List[ProbeResult]:
        """
        Esegue probe su un dispositivo con le credenziali fornite.
        
        Args:
            address: IP del dispositivo
            credentials: Dict con username, password, snmp_community, etc
            protocols: Lista protocolli da provare (default: tutti applicabili)
            
        Returns:
            Lista di ProbeResult per ogni protocollo testato
        """
        if protocols is None:
            protocols = ["mikrotik_api", "ssh", "snmp", "wmi"]
        
        results = []
        
        for protocol in protocols:
            try:
                if protocol == "mikrotik_api":
                    result = await self._probe_mikrotik_api(address, credentials)
                elif protocol == "ssh":
                    result = await self._probe_ssh(address, credentials)
                elif protocol == "snmp":
                    result = await self._probe_snmp(address, credentials)
                elif protocol == "wmi":
                    result = await self._probe_wmi(address, credentials)
                else:
                    continue
                
                results.append(result)
                
                # Se trovato, possiamo fermarci
                if result.success and result.device_type:
                    break
                    
            except Exception as e:
                logger.error(f"Probe {protocol} failed for {address}: {e}")
                results.append(ProbeResult(
                    success=False,
                    protocol=protocol,
                    error=str(e)
                ))
        
        return results
    
    async def _probe_mikrotik_api(self, address: str, credentials: Dict) -> ProbeResult:
        """Probe via RouterOS API"""
        try:
            import routeros_api

            username = credentials.get("username", "admin")
            password = credentials.get("password", "")
            # Fix: supporta sia api_port che mikrotik_api_port
            port = credentials.get("mikrotik_api_port") or credentials.get("api_port", 8728)

            logger.debug(f"Attempting MikroTik API probe on {address}:{port} with user {username}")
            
            # Test connessione
            loop = asyncio.get_event_loop()
            
            def connect():
                # Timeout impostato a 10 secondi
                import socket
                default_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(10.0)

                try:
                    connection = routeros_api.RouterOsApiPool(
                        address,
                        username=username,
                        password=password,
                        port=port,
                        plaintext_login=True
                    )
                    api = connection.get_api()

                    # Get identity
                    identity = api.get_resource('/system/identity').get()[0]['name']

                    # Get resource info
                    resource = api.get_resource('/system/resource').get()[0]

                    # Get routerboard info
                    try:
                        rb = api.get_resource('/system/routerboard').get()[0]
                        board_name = rb.get('board-name', '')
                        model = rb.get('model', '')
                        serial = rb.get('serial-number', '')
                    except:
                        board_name = ""
                        model = ""
                        serial = ""

                    connection.disconnect()

                    return {
                        "identity": identity,
                        "version": resource.get("version", ""),
                        "board_name": board_name or resource.get("board-name", ""),
                        "model": model,
                        "platform": resource.get("platform", ""),
                        "cpu": resource.get("cpu", ""),
                        "architecture": resource.get("architecture-name", ""),
                        "memory_total_mb": int(resource.get("total-memory", 0)) // (1024*1024),
                        "disk_total_mb": int(resource.get("total-hdd-space", 0)) // (1024*1024),
                        "serial_number": serial
                    }
                finally:
                    socket.setdefaulttimeout(default_timeout)
            
            info = await loop.run_in_executor(self._executor, connect)

            logger.success(f"MikroTik probe successful for {address}: {info.get('identity')}")
            return ProbeResult(
                success=True,
                protocol="mikrotik_api",
                device_type="mikrotik",
                category="router",
                os_family="RouterOS",
                os_version=info.get("version"),
                hostname=info.get("identity"),
                model=info.get("board_name") or info.get("model"),
                extra_info=info
            )

        except Exception as e:
            logger.error(f"MikroTik API probe failed for {address}:{port} - {type(e).__name__}: {str(e)}")
            return ProbeResult(
                success=False,
                protocol="mikrotik_api",
                error=str(e)
            )
    
    async def _probe_ssh(self, address: str, credentials: Dict) -> ProbeResult:
        """Probe via SSH - identifica Linux/Unix"""
        try:
            import paramiko

            username = credentials.get("username", "root")
            password = credentials.get("password")
            ssh_key = credentials.get("ssh_private_key") or credentials.get("ssh_key")
            port = credentials.get("ssh_port", 22)

            logger.info(f"SSH probe: Attempting connection to {address}:{port} with user '{username}', password={'Yes' if password else 'No'}, key={'Yes' if ssh_key else 'No'}")
            loop = asyncio.get_event_loop()
            
            def connect():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                connect_kwargs = {
                    "hostname": address,
                    "port": port,
                    "username": username,
                    "timeout": 10,
                    "banner_timeout": 10,
                    "auth_timeout": 10,
                    "allow_agent": False,
                    "look_for_keys": False,
                }

                if ssh_key:
                    import io
                    # Supporta diversi tipi di chiavi
                    try:
                        key = paramiko.RSAKey.from_private_key(io.StringIO(ssh_key))
                    except:
                        try:
                            key = paramiko.Ed25519Key.from_private_key(io.StringIO(ssh_key))
                        except:
                            key = paramiko.ECDSAKey.from_private_key(io.StringIO(ssh_key))
                    connect_kwargs["pkey"] = key
                elif password:
                    connect_kwargs["password"] = password
                else:
                    raise ValueError("SSH credentials require either password or private key")

                logger.info(f"SSH probe: Connecting to {address}:{port}...")
                client.connect(**connect_kwargs)
                logger.info(f"SSH probe: ✓ Connected successfully to {address}:{port}")
                
                info = {}
                device_detected = False
                uname_all = ""
                os_info = ""
                
                # ==== DEVICE TYPE DETECTION ====
                # Prima prova MikroTik (non supporta comandi Linux standard)
                # 1. Check for MikroTik RouterOS FIRST
                stdin, stdout, stderr = client.exec_command("/system resource print", timeout=5)
                ros_out = stdout.read().decode()
                if "routeros" in ros_out.lower() or "uptime:" in ros_out.lower() or "version:" in ros_out.lower():
                    info["os_family"] = "RouterOS"
                    info["device_type"] = "mikrotik"
                    info["category"] = "router"
                    info["manufacturer"] = "MikroTik"
                    device_detected = True
                    # Extract RouterOS specific info
                    for line in ros_out.split('\n'):
                        ll = line.lower().strip()
                        if ll.startswith('version:'):
                            info["os_version"] = line.split(':', 1)[1].strip()
                        elif ll.startswith('board-name:'):
                            info["model"] = line.split(':', 1)[1].strip()
                        elif ll.startswith('cpu:') and 'cpu-count' not in ll:
                            info["cpu_model"] = line.split(':', 1)[1].strip()
                        elif ll.startswith('cpu-count:'):
                            try:
                                info["cpu_cores"] = int(line.split(':', 1)[1].strip())
                            except:
                                pass
                        elif ll.startswith('total-memory:'):
                            try:
                                mem_str = line.split(':', 1)[1].strip()
                                if 'MiB' in mem_str:
                                    info["memory_total_mb"] = int(float(mem_str.replace('MiB', '').strip()))
                                elif 'GiB' in mem_str:
                                    info["memory_total_mb"] = int(float(mem_str.replace('GiB', '').strip()) * 1024)
                            except:
                                pass
                        elif ll.startswith('architecture-name:'):
                            info["arch"] = line.split(':', 1)[1].strip()
                    # Get hostname
                    stdin, stdout, stderr = client.exec_command("/system identity print", timeout=5)
                    for line in stdout.read().decode().split('\n'):
                        if 'name:' in line.lower():
                            info["hostname"] = line.split(':', 1)[1].strip()
                    # Get serial
                    stdin, stdout, stderr = client.exec_command("/system routerboard print", timeout=5)
                    for line in stdout.read().decode().split('\n'):
                        ll = line.lower().strip()
                        if ll.startswith('serial-number:'):
                            info["serial_number"] = line.split(':', 1)[1].strip()
                        elif ll.startswith('model:') and not info.get("model"):
                            info["model"] = line.split(':', 1)[1].strip()
                
                # Per device non-MikroTik, leggi info OS standard
                if not device_detected:
                    stdin, stdout, stderr = client.exec_command("uname -a 2>/dev/null", timeout=5)
                    uname_all = stdout.read().decode().strip().lower()
                    stdin, stdout, stderr = client.exec_command("cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null", timeout=5)
                    os_info = stdout.read().decode()
                    stdin, stdout, stderr = client.exec_command("hostname 2>/dev/null", timeout=5)
                    info["hostname"] = stdout.read().decode().strip()
                
                # 2. Check for Ubiquiti UniFi/EdgeOS
                if not device_detected:
                    stdin, stdout, stderr = client.exec_command("cat /etc/board.info 2>/dev/null || mca-cli-op info 2>/dev/null", timeout=5)
                    ubnt_out = stdout.read().decode()
                    if ubnt_out and ('ubnt' in ubnt_out.lower() or 'ubiquiti' in ubnt_out.lower() or 'board.' in ubnt_out.lower()):
                        info["os_family"] = "UniFi"
                        info["device_type"] = "network"
                        info["category"] = "ap" if 'uap' in uname_all or 'u6' in uname_all or 'u7' in uname_all else "switch"
                        info["manufacturer"] = "Ubiquiti"
                        device_detected = True
                        for line in ubnt_out.split('\n'):
                            if 'board.name' in line.lower() or 'model' in line.lower():
                                info["model"] = line.split('=')[-1].strip() if '=' in line else line.split(':')[-1].strip()
                            elif 'board.sysid' in line.lower() or 'serialno' in line.lower():
                                info["serial_number"] = line.split('=')[-1].strip() if '=' in line else line.split(':')[-1].strip()
                
                # 3. Check for Synology DSM
                if not device_detected:
                    stdin, stdout, stderr = client.exec_command("cat /etc/synoinfo.conf 2>/dev/null", timeout=5)
                    syno_out = stdout.read().decode()
                    if syno_out and 'synology' in syno_out.lower():
                        info["os_family"] = "DSM"
                        info["device_type"] = "nas"
                        info["category"] = "storage"
                        info["manufacturer"] = "Synology"
                        device_detected = True
                        for line in syno_out.split('\n'):
                            if 'upnpmodelname' in line.lower():
                                info["model"] = line.split('=')[-1].strip().strip('"')
                            elif 'unique' in line.lower():
                                info["serial_number"] = line.split('=')[-1].strip().strip('"')
                        # Get DSM version
                        stdin, stdout, stderr = client.exec_command("cat /etc.defaults/VERSION 2>/dev/null", timeout=5)
                        ver_out = stdout.read().decode()
                        for line in ver_out.split('\n'):
                            if 'productversion' in line.lower():
                                info["os_version"] = line.split('=')[-1].strip().strip('"')
                
                # 4. Check for QNAP QTS
                if not device_detected:
                    stdin, stdout, stderr = client.exec_command("getsysinfo model 2>/dev/null || cat /etc/config/qpkg.conf 2>/dev/null", timeout=5)
                    qnap_out = stdout.read().decode()
                    if qnap_out and ('qnap' in qnap_out.lower() or 'qts' in os_info.lower()):
                        info["os_family"] = "QTS"
                        info["device_type"] = "nas"
                        info["category"] = "storage"
                        info["manufacturer"] = "QNAP"
                        device_detected = True
                        info["model"] = qnap_out.strip().split('\n')[0] if qnap_out else None
                
                # 5. Check for VMware ESXi
                if not device_detected and 'vmkernel' in uname_all:
                    info["os_family"] = "ESXi"
                    info["device_type"] = "hypervisor"
                    info["category"] = "hypervisor"
                    info["manufacturer"] = "VMware"
                    device_detected = True
                    stdin, stdout, stderr = client.exec_command("vmware -v 2>/dev/null", timeout=5)
                    ver_out = stdout.read().decode().strip()
                    if ver_out:
                        info["os_version"] = ver_out
                
                # 6. Standard Linux detection
                if not device_detected:
                    if "Ubuntu" in os_info:
                        info["os_family"] = "Ubuntu"
                        info["device_type"] = "linux"
                    elif "Debian" in os_info:
                        info["os_family"] = "Debian"
                        info["device_type"] = "linux"
                    elif "CentOS" in os_info or "Red Hat" in os_info or "Rocky" in os_info or "AlmaLinux" in os_info:
                        info["os_family"] = "RHEL"
                        info["device_type"] = "linux"
                    elif "Alpine" in os_info:
                        info["os_family"] = "Alpine"
                        info["device_type"] = "linux"
                    elif "Proxmox" in os_info:
                        info["os_family"] = "Proxmox"
                        info["device_type"] = "linux"
                        info["category"] = "hypervisor"
                        # Get Proxmox version
                        stdin, stdout, stderr = client.exec_command("pveversion 2>/dev/null", timeout=5)
                        pve_out = stdout.read().decode().strip()
                        if pve_out:
                            info["os_version"] = pve_out
                    elif "SUSE" in os_info or "openSUSE" in os_info:
                        info["os_family"] = "SUSE"
                        info["device_type"] = "linux"
                    elif "Arch" in os_info:
                        info["os_family"] = "Arch"
                        info["device_type"] = "linux"
                    elif "FreeBSD" in os_info or "freebsd" in uname_all:
                        info["os_family"] = "FreeBSD"
                        info["device_type"] = "bsd"
                    else:
                        info["os_family"] = "Linux"
                        info["device_type"] = "linux"
                    
                    # Extract version from os-release
                    for line in os_info.split('\n'):
                        if line.startswith('VERSION_ID='):
                            info["os_version"] = line.split('=')[1].strip().strip('"')
                        elif line.startswith('PRETTY_NAME='):
                            info["os_pretty_name"] = line.split('=')[1].strip().strip('"')
                
                # ==== HARDWARE INFO (for Linux/BSD/NAS - not MikroTik) ====
                if info.get("device_type") not in ["mikrotik"]:
                    # Get kernel version
                    try:
                        stdin, stdout, stderr = client.exec_command("uname -r 2>/dev/null", timeout=5)
                        kernel = stdout.read().decode().strip()
                        if kernel and 'bad command' not in kernel.lower():
                            info["kernel"] = kernel
                    except:
                        pass
                    
                    # Get architecture
                    try:
                        stdin, stdout, stderr = client.exec_command("uname -m 2>/dev/null", timeout=5)
                        arch = stdout.read().decode().strip()
                        if arch and 'bad command' not in arch.lower():
                            info["arch"] = arch
                    except:
                        pass
                
                # ==== DETAILED HARDWARE INFO (for Linux/BSD) ====
                if info.get("device_type") in ["linux", "bsd", "hypervisor"]:
                    # Get Memory
                    try:
                        stdin, stdout, stderr = client.exec_command("free -m | grep Mem | awk '{print $2}'", timeout=5)
                        mem_out = stdout.read().decode().strip()
                        if mem_out.isdigit():
                            info["memory_total_mb"] = int(mem_out)
                    except:
                        pass

                    # Get CPU Info
                    try:
                        stdin, stdout, stderr = client.exec_command("nproc", timeout=5)
                        cpu_out = stdout.read().decode().strip()
                        if cpu_out.isdigit():
                            info["cpu_cores"] = int(cpu_out)
                    except:
                        pass
                    
                    try:
                        stdin, stdout, stderr = client.exec_command("cat /proc/cpuinfo | grep 'model name' | head -1 | cut -d':' -f2", timeout=5)
                        cpu_model = stdout.read().decode().strip()
                        if cpu_model:
                            info["cpu_model"] = cpu_model
                    except:
                        pass
                    
                    # Get Disk
                    try:
                        stdin, stdout, stderr = client.exec_command("df -BG / | awk 'NR==2 {print $2, $4}'", timeout=5)
                        disk_out = stdout.read().decode().strip().split()
                        if len(disk_out) == 2:
                            info["disk_total_gb"] = int(disk_out[0].replace('G', ''))
                            info["disk_free_gb"] = int(disk_out[1].replace('G', ''))
                    except:
                        pass
                    
                    # Get Serial Number (DMI)
                    try:
                        stdin, stdout, stderr = client.exec_command("cat /sys/class/dmi/id/product_serial 2>/dev/null || dmidecode -s system-serial-number 2>/dev/null", timeout=5)
                        serial = stdout.read().decode().strip()
                        if serial and serial != "To Be Filled By O.E.M." and serial != "Not Specified":
                            info["serial_number"] = serial
                    except:
                        pass
                    
                    # Get Manufacturer/Model (DMI)
                    try:
                        stdin, stdout, stderr = client.exec_command("cat /sys/class/dmi/id/sys_vendor 2>/dev/null || dmidecode -s system-manufacturer 2>/dev/null", timeout=5)
                        vendor = stdout.read().decode().strip()
                        if vendor and vendor != "To Be Filled By O.E.M.":
                            info["manufacturer"] = vendor
                    except:
                        pass
                    
                    try:
                        stdin, stdout, stderr = client.exec_command("cat /sys/class/dmi/id/product_name 2>/dev/null || dmidecode -s system-product-name 2>/dev/null", timeout=5)
                        model = stdout.read().decode().strip()
                        if model and model != "To Be Filled By O.E.M.":
                            info["model"] = model
                    except:
                        pass
                    
                    # Get Uptime
                    try:
                        stdin, stdout, stderr = client.exec_command("uptime -s 2>/dev/null || uptime", timeout=5)
                        uptime_out = stdout.read().decode().strip()
                        info["uptime"] = uptime_out
                    except:
                        pass
                    
                    # Check if Docker is installed
                    try:
                        stdin, stdout, stderr = client.exec_command("docker --version 2>/dev/null", timeout=5)
                        docker_out = stdout.read().decode().strip()
                        if docker_out:
                            info["docker_installed"] = True
                            info["docker_version"] = docker_out.split(',')[0].replace('Docker version', '').strip()
                    except:
                        pass

                client.close()
                return info
            
            info = await loop.run_in_executor(self._executor, connect)

            logger.success(f"SSH probe successful for {address}: {info.get('hostname')} ({info.get('os_family')})")
            return ProbeResult(
                success=True,
                protocol="ssh",
                device_type=info.get("device_type", "linux"),
                category=info.get("category", "server"),
                os_family=info.get("os_family"),
                os_version=info.get("kernel"),
                hostname=info.get("hostname"),
                extra_info=info
            )

        except Exception as e:
            logger.error(f"SSH probe failed for {address}:{port} - {type(e).__name__}: {str(e)}")
            return ProbeResult(
                success=False,
                protocol="ssh",
                error=str(e)
            )
    
    async def _probe_snmp(self, address: str, credentials: Dict) -> ProbeResult:
        """Probe via SNMP - identifica dispositivi di rete
        Prova prima con community del cliente, poi fallback a 'public'"""
        try:
            # pysnmp v7 API - usa modulo asyncio
            from pysnmp.hlapi.v1arch.asyncio import (
                get_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity
            )

            port = int(credentials.get("snmp_port", 161))
            version = credentials.get("snmp_version", "2c")
            
            # Lista di communities da provare (prima quella del cliente, poi 'public' come fallback)
            communities_to_try = []
            
            # Prima aggiungi la community del cliente se presente
            client_community = credentials.get("snmp_community")
            if client_community and client_community.strip():
                communities_to_try.append(client_community.strip())
                logger.debug(f"SNMP probe: Will try client community '{client_community}' first for {address}")
            
            # Aggiungi 'public' come fallback solo se non è già nella lista
            if "public" not in communities_to_try:
                communities_to_try.append("public")
                logger.debug(f"SNMP probe: Will use 'public' as fallback for {address}")
            
            # Prova ogni community fino a che una funziona
            for community in communities_to_try:
                try:
                    logger.debug(f"Attempting SNMP probe on {address}:{port} with community '{community}' (v{version})")

                    # OIDs per identificazione dispositivo
                    # Standard MIB-II
                    oids_basic = {
                        "sysDescr": "1.3.6.1.2.1.1.1.0",
                        "sysName": "1.3.6.1.2.1.1.5.0",
                        "sysObjectID": "1.3.6.1.2.1.1.2.0",
                        "sysContact": "1.3.6.1.2.1.1.4.0",
                        "sysLocation": "1.3.6.1.2.1.1.6.0",
                        "sysUpTime": "1.3.6.1.2.1.1.3.0",
                    }
                    
                    # Entity MIB (RFC 4133) - modello, seriale, vendor
                    oids_entity = {
                        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2.1",       # Descrizione hardware
                        "entPhysicalVendorType": "1.3.6.1.2.1.47.1.1.1.1.3.1",  # Tipo vendor
                        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7.1",        # Nome modello
                        "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8.1", # Revisione HW
                        "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9.1", # Revisione FW
                        "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10.1",# Revisione SW
                        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11.1",  # Seriale
                        "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12.1",    # Manufacturer
                        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13.1",  # Modello
                    }
                    
                    # OID specifici per vendor comuni
                    oids_vendor_specific = {
                        # Cisco
                        "ciscoSerial": "1.3.6.1.4.1.9.3.6.3.0",
                        # HP/ProCurve
                        "hpSerial": "1.3.6.1.4.1.11.2.36.1.1.2.9.0",
                        # Ubiquiti
                        "ubntModel": "1.3.6.1.4.1.41112.1.6.3.3.0",
                        "ubntVersion": "1.3.6.1.4.1.41112.1.6.3.6.0",
                        # Synology
                        "synoModel": "1.3.6.1.4.1.6574.1.5.1.0",
                        "synoSerial": "1.3.6.1.4.1.6574.1.5.2.0",
                        # QNAP
                        "qnapModel": "1.3.6.1.4.1.24681.1.2.12.0",
                        "qnapSerial": "1.3.6.1.4.1.24681.1.2.13.0",
                        # APC UPS
                        "apcModel": "1.3.6.1.4.1.318.1.1.1.1.1.1.0",
                        "apcSerial": "1.3.6.1.4.1.318.1.1.1.1.2.3.0",
                        "apcFirmware": "1.3.6.1.4.1.318.1.1.1.1.2.1.0",
                    }

                    info = {}
                    dispatcher = SnmpDispatcher()

                    try:
                        # Crea transport asincrono
                        transport = await UdpTransportTarget.create(
                            (address, port), 
                            timeout=5, 
                            retries=1
                        )
                        
                        # Query OID di base (sempre)
                        for name, oid in oids_basic.items():
                            try:
                                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                                    dispatcher,
                                    CommunityData(community, mpModel=1 if version == "2c" else 0),
                                    transport,
                                    ObjectType(ObjectIdentity(oid))
                                )

                                if errorIndication or errorStatus:
                                    continue

                                for varBind in varBinds:
                                    value = str(varBind[1])
                                    if value and value != "No Such Object" and value != "No Such Instance":
                                        info[name] = value
                            except Exception:
                                continue
                        
                        # Query Entity MIB per modello/seriale/vendor
                        for name, oid in oids_entity.items():
                            try:
                                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                                    dispatcher,
                                    CommunityData(community, mpModel=1 if version == "2c" else 0),
                                    transport,
                                    ObjectType(ObjectIdentity(oid))
                                )

                                if errorIndication or errorStatus:
                                    continue

                                for varBind in varBinds:
                                    value = str(varBind[1])
                                    if value and value != "No Such Object" and value != "No Such Instance":
                                        info[name] = value
                            except Exception:
                                continue
                        
                        # Query OID vendor-specific in base a sysObjectID
                        sys_object_id = info.get("sysObjectID", "")
                        vendor_oids_to_query = {}
                        
                        if sys_object_id.startswith("1.3.6.1.4.1.9"):  # Cisco
                            vendor_oids_to_query["ciscoSerial"] = oids_vendor_specific["ciscoSerial"]
                        elif sys_object_id.startswith("1.3.6.1.4.1.11") or sys_object_id.startswith("1.3.6.1.4.1.25506"):  # HP
                            vendor_oids_to_query["hpSerial"] = oids_vendor_specific["hpSerial"]
                        elif sys_object_id.startswith("1.3.6.1.4.1.41112"):  # Ubiquiti
                            vendor_oids_to_query["ubntModel"] = oids_vendor_specific["ubntModel"]
                            vendor_oids_to_query["ubntVersion"] = oids_vendor_specific["ubntVersion"]
                        elif sys_object_id.startswith("1.3.6.1.4.1.6574"):  # Synology
                            vendor_oids_to_query["synoModel"] = oids_vendor_specific["synoModel"]
                            vendor_oids_to_query["synoSerial"] = oids_vendor_specific["synoSerial"]
                        elif sys_object_id.startswith("1.3.6.1.4.1.24681"):  # QNAP
                            vendor_oids_to_query["qnapModel"] = oids_vendor_specific["qnapModel"]
                            vendor_oids_to_query["qnapSerial"] = oids_vendor_specific["qnapSerial"]
                        elif sys_object_id.startswith("1.3.6.1.4.1.318"):  # APC
                            vendor_oids_to_query["apcModel"] = oids_vendor_specific["apcModel"]
                            vendor_oids_to_query["apcSerial"] = oids_vendor_specific["apcSerial"]
                            vendor_oids_to_query["apcFirmware"] = oids_vendor_specific["apcFirmware"]
                        
                        for name, oid in vendor_oids_to_query.items():
                            try:
                                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                                    dispatcher,
                                    CommunityData(community, mpModel=1 if version == "2c" else 0),
                                    transport,
                                    ObjectType(ObjectIdentity(oid))
                                )

                                if errorIndication or errorStatus:
                                    continue

                                for varBind in varBinds:
                                    value = str(varBind[1])
                                    if value and value != "No Such Object" and value != "No Such Instance":
                                        info[name] = value
                            except Exception as e:
                                logger.debug(f"SNMP OID {name} exception: {e}")
                                continue
                    finally:
                        dispatcher.transport_dispatcher.close_dispatcher()

                    # Se abbiamo ottenuto dati validi, esci dal loop
                    if info and (info.get("sysDescr") or info.get("sysName") or info.get("sysObjectID")):
                        logger.info(f"SNMP probe succeeded with community '{community}' for {address}")
                        break
                    else:
                        logger.debug(f"SNMP probe with community '{community}' returned no usable data for {address}, trying next...")
                        info = {}  # Reset per prossimo tentativo
                        continue
                        
                except Exception as e:
                    logger.debug(f"SNMP probe failed for {address} with community '{community}': {e}")
                    info = {}  # Reset per prossimo tentativo
                    continue
            
            # Se non abbiamo ottenuto dati dopo aver provato tutte le communities
            if not info:
                logger.warning(f"SNMP probe failed for {address}:{port} with all communities tried: {communities_to_try}")
                return ProbeResult(
                    success=False,
                    protocol="snmp",
                    error=f"No SNMP response with communities: {', '.join(communities_to_try)}"
                )
            
            # Analizza sysDescr e sysObjectID per identificare device
            sys_descr = info.get("sysDescr", "").lower()
            sys_name = info.get("sysName", "")
            sys_object_id = info.get("sysObjectID", "")
            
            device_type = "network"
            category = "switch"
            os_family = None
            vendor = None
            model = None
            
            # Estrai modello da sysDescr se possibile
            sys_descr_orig = info.get("sysDescr", "")
            
            # Check sysObjectID per vendor noti (OID enterprise numbers)
            # https://www.iana.org/assignments/enterprise-numbers/
            # Ubiquiti - OID 41112 (standard) o check sysDescr per modelli con OID generico
            if sys_object_id.startswith("1.3.6.1.4.1.41112") or \
               any(ubnt in sys_descr for ubnt in ["u6-", "u7-", "uap-", "usw-", "udm-", "usg-", 
                                                   "edgeswitch", "edgerouter", "nanostation", 
                                                   "nanobeam", "powerbeam", "airmax"]):
                vendor = "Ubiquiti"
                device_type = "network"
                os_family = "UniFi"
                # Estrai modello dal sysDescr (es: "Linux U6-LR 5.60.23" -> "U6-LR")
                model = None
                if sys_descr_orig:
                    parts = sys_descr_orig.split()
                    for part in parts:
                        # Cerca pattern modello Ubiquiti
                        if any(x in part.upper() for x in ["U6", "U7", "UAP", "USW", "UDM", "USG", 
                                                            "EDGE", "NANO", "BEAM", "AIR", "LITE", "PRO", "LR"]):
                            model = part
                            break
                    if not model and len(parts) > 1:
                        model = parts[1] if parts[0].lower() == "linux" else parts[0]
                
                # Identifica tipo device Ubiquiti
                if any(x in sys_descr for x in ["u6", "u7", "uap", "ap", "nanohd", "flexhd", "lite", "lr", "pro", 
                                                 "nanostation", "nanobeam", "powerbeam", "litebeam", "airmax"]):
                    category = "ap"
                elif any(x in sys_descr for x in ["usw", "switch", "us-", "edgeswitch"]):
                    category = "switch"
                elif any(x in sys_descr for x in ["usg", "udm", "dream", "gateway", "edgerouter"]):
                    category = "router"
                else:
                    category = "ap"  # Default Ubiquiti = access point
                
                logger.info(f"SNMP: Identified Ubiquiti device - model={model}, category={category}")
            elif sys_object_id.startswith("1.3.6.1.4.1.14988"):  # MikroTik
                vendor = "MikroTik"
                device_type = "mikrotik"
                category = "router"
                os_family = "RouterOS"
            elif sys_object_id.startswith("1.3.6.1.4.1.9"):  # Cisco
                vendor = "Cisco"
                device_type = "network"
                os_family = "IOS"
                if "catalyst" in sys_descr:
                    category = "switch"
                elif "asa" in sys_descr or "firepower" in sys_descr:
                    category = "firewall"
                else:
                    category = "router"
            elif sys_object_id.startswith("1.3.6.1.4.1.2636"):  # Juniper
                vendor = "Juniper"
                device_type = "network"
                category = "router"
                os_family = "JunOS"
            elif sys_object_id.startswith("1.3.6.1.4.1.12356"):  # Fortinet
                vendor = "Fortinet"
                device_type = "network"
                category = "firewall"
                os_family = "FortiOS"
            elif sys_object_id.startswith("1.3.6.1.4.1.11") or sys_object_id.startswith("1.3.6.1.4.1.25506"):  # HP/HPE/Aruba
                vendor = "HPE/Aruba"
                device_type = "network"
                category = "switch"
                os_family = "ArubaOS"
            elif sys_object_id.startswith("1.3.6.1.4.1.318"):  # APC
                vendor = "APC"
                device_type = "ups"
                category = "ups"
            elif sys_object_id.startswith("1.3.6.1.4.1.3375"):  # F5
                vendor = "F5"
                device_type = "network"
                category = "loadbalancer"
                os_family = "TMOS"
            elif sys_object_id.startswith("1.3.6.1.4.1.6574"):  # Synology
                vendor = "Synology"
                device_type = "nas"
                category = "storage"
                os_family = "DSM"
            elif sys_object_id.startswith("1.3.6.1.4.1.24681"):  # QNAP
                vendor = "QNAP"
                device_type = "nas"
                category = "storage"
                os_family = "QTS"
            # Fallback: analizza sysDescr
            elif "mikrotik" in sys_descr or "routeros" in sys_descr:
                device_type = "mikrotik"
                category = "router"
                os_family = "RouterOS"
                vendor = "MikroTik"
            elif "cisco" in sys_descr:
                device_type = "network"
                vendor = "Cisco"
                if "catalyst" in sys_descr:
                    category = "switch"
                elif "asa" in sys_descr:
                    category = "firewall"
                else:
                    category = "router"
                os_family = "IOS"
            elif "juniper" in sys_descr:
                device_type = "network"
                category = "router"
                os_family = "JunOS"
                vendor = "Juniper"
            elif "fortinet" in sys_descr or "fortigate" in sys_descr:
                device_type = "network"
                category = "firewall"
                os_family = "FortiOS"
                vendor = "Fortinet"
            elif "ubiquiti" in sys_descr or "unifi" in sys_descr or "edgeos" in sys_descr:
                device_type = "network"
                category = "ap"
                os_family = "UniFi"
                vendor = "Ubiquiti"
            # Ubiquiti devices often have sysDescr like "Linux U6-LR 5.60.23" or "Linux EdgeSwitch"
            elif any(ubnt in sys_descr for ubnt in ["u6-", "u7-", "uap-", "usw-", "udm-", "usg-", 
                                                      "edgeswitch", "edgerouter", "edgemax",
                                                      "nanostation", "nanobeam", "powerbeam",
                                                      "litebeam", "airmax", "airfiber"]):
                device_type = "network"
                # Determine category based on device name
                if any(x in sys_descr for x in ["usw-", "edgeswitch", "switch"]):
                    category = "switch"
                elif any(x in sys_descr for x in ["usg-", "udm-", "edgerouter", "gateway"]):
                    category = "router"
                else:
                    category = "ap"
                os_family = "UniFi"
                vendor = "Ubiquiti"
            elif "hp" in sys_descr or "procurve" in sys_descr or "aruba" in sys_descr:
                device_type = "network"
                category = "switch"
                os_family = "ProCurve"
                vendor = "HPE/Aruba"
            elif "linux" in sys_descr:
                device_type = "linux"
                category = "server"
                os_family = "Linux"
            elif "windows" in sys_descr:
                device_type = "windows"
                category = "server"
                os_family = "Windows"
            elif "printer" in sys_descr or "laserjet" in sys_descr or "canon" in sys_descr:
                device_type = "printer"
                category = "printer"
            elif "ups" in sys_descr or "apc" in sys_descr:
                device_type = "ups"
                category = "ups"
            
            # Estrai modello, seriale, firmware dai dati raccolti
            serial_number = None
            firmware_version = None
            hardware_version = None
            
            # Priorità 1: Entity MIB (standard)
            if not model:
                model = info.get("entPhysicalModelName") or info.get("entPhysicalName")
            if not serial_number:
                serial_number = info.get("entPhysicalSerialNum")
            if not vendor:
                vendor = info.get("entPhysicalMfgName")
            if not firmware_version:
                firmware_version = info.get("entPhysicalSoftwareRev") or info.get("entPhysicalFirmwareRev")
            if not hardware_version:
                hardware_version = info.get("entPhysicalHardwareRev")
            
            # Priorità 2: OID vendor-specific
            if not model:
                model = info.get("ubntModel") or info.get("synoModel") or info.get("qnapModel") or info.get("apcModel")
            if not serial_number:
                serial_number = info.get("ciscoSerial") or info.get("hpSerial") or info.get("synoSerial") or info.get("qnapSerial") or info.get("apcSerial")
            if not firmware_version:
                firmware_version = info.get("ubntVersion") or info.get("apcFirmware")
            
            # Priorità 3: Estrai modello da sysDescr se non trovato
            if not model and sys_descr_orig:
                # Prova a estrarre il primo "word" che sembra un modello
                parts = sys_descr_orig.split()
                if parts:
                    # Per molti dispositivi, il modello è la prima parola
                    model = parts[0]
                    # Se c'è anche una versione, potrebbe essere "Model version"
                    if len(parts) > 1 and parts[1][0].isdigit():
                        # Probabilmente "Model X.Y.Z" - model è solo la prima parte
                        pass
            
            # Aggiungi tutti i dati raccolti a extra_info
            if vendor:
                info["vendor"] = vendor
            if model:
                info["model"] = model
            if serial_number:
                info["serial_number"] = serial_number
            if firmware_version:
                info["firmware_version"] = firmware_version
                info["os_version"] = firmware_version  # Alias per compatibilità
            if hardware_version:
                info["hardware_version"] = hardware_version
            
            # Log dettagliato
            details = []
            if model:
                details.append(f"model={model}")
            if serial_number:
                details.append(f"serial={serial_number}")
            if firmware_version:
                details.append(f"fw={firmware_version}")
            details_str = ", ".join(details) if details else "no details"
            
            logger.success(f"SNMP probe successful for {address}: {sys_name} ({vendor or 'unknown'} {device_type}/{category}) [{details_str}]")
            return ProbeResult(
                success=True,
                protocol="snmp",
                device_type=device_type,
                category=category,
                os_family=os_family,
                hostname=sys_name,
                model=model,
                extra_info=info
            )

        except ImportError:
            logger.error(f"SNMP probe failed for {address} - pysnmp not installed")
            return ProbeResult(
                success=False,
                protocol="snmp",
                error="pysnmp not installed"
            )
        except Exception as e:
            logger.error(f"SNMP probe failed for {address}:{port} - {type(e).__name__}: {str(e)}")
            return ProbeResult(
                success=False,
                protocol="snmp",
                error=str(e)
            )
    
    async def _probe_wmi(self, address: str, credentials: Dict) -> ProbeResult:
        """Probe via WMI - identifica Windows"""
        try:
            # WMI richiede impacket
            from impacket.dcerpc.v5 import transport
            from impacket.dcerpc.v5.dcom import wmi as dcom_wmi
            from impacket.dcerpc.v5.dcomrt import DCOMConnection

            username = credentials.get("username", "Administrator")
            password = credentials.get("password", "")
            domain = credentials.get("wmi_domain", credentials.get("domain", ""))

            logger.debug(f"Attempting WMI probe on {address} with user {domain}\\{username if domain else username}")
            
            loop = asyncio.get_event_loop()
            
            def connect():
                # Connessione DCOM
                dcom = DCOMConnection(
                    address,
                    username=username,
                    password=password,
                    domain=domain
                )
                
                # Query WMI
                iInterface = dcom.CoCreateInstanceEx(
                    dcom_wmi.CLSID_WbemLevel1Login,
                    dcom_wmi.IID_IWbemLevel1Login
                )
                iWbemLevel1Login = dcom_wmi.IWbemLevel1Login(iInterface)
                iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', dcom_wmi.NULL, dcom_wmi.NULL)
                
                os_info = {}
                
                # Helper per estrarre valore da proprietà impacket WMI
                def get_prop_value(props, name, default=""):
                    """Estrae valore da OrderedDict restituito da getProperties()"""
                    if name in props:
                        return props[name].get('value', default) or default
                    return default
                
                # Get OS info
                logger.debug(f"WMI: Querying Win32_OperatingSystem...")
                try:
                    result = iWbemServices.ExecQuery("SELECT Caption, Version, BuildNumber, OSArchitecture, SerialNumber FROM Win32_OperatingSystem")
                    item = result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    os_info["name"] = str(get_prop_value(props, "Caption"))
                    os_info["version"] = str(get_prop_value(props, "Version"))
                    os_info["build"] = str(get_prop_value(props, "BuildNumber"))
                    os_info["architecture"] = str(get_prop_value(props, "OSArchitecture"))
                    os_info["serial_number"] = str(get_prop_value(props, "SerialNumber"))
                    logger.debug(f"WMI OS: {os_info.get('name')} v{os_info.get('version')}")
                except Exception as e:
                    logger.warning(f"WMI Win32_OperatingSystem query failed: {type(e).__name__}: {e}")

                # Get computer name
                logger.debug(f"WMI: Querying Win32_ComputerSystem...")
                try:
                    result = iWbemServices.ExecQuery("SELECT Name, Domain, Model, Manufacturer, TotalPhysicalMemory FROM Win32_ComputerSystem")
                    item = result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    os_info["hostname"] = str(get_prop_value(props, "Name"))
                    os_info["domain"] = str(get_prop_value(props, "Domain"))
                    os_info["model"] = str(get_prop_value(props, "Model"))
                    os_info["manufacturer"] = str(get_prop_value(props, "Manufacturer"))
                    mem_val = get_prop_value(props, "TotalPhysicalMemory")
                    if mem_val:
                        try:
                            os_info["memory_total_mb"] = int(mem_val) // (1024*1024)
                        except (ValueError, TypeError):
                            pass
                    logger.debug(f"WMI Computer: {os_info.get('hostname')} ({os_info.get('manufacturer')} {os_info.get('model')})")
                except Exception as e:
                    logger.warning(f"WMI Win32_ComputerSystem query failed: {type(e).__name__}: {e}")
                
                # Get CPU Info
                logger.debug(f"WMI: Querying Win32_Processor...")
                try:
                    result = iWbemServices.ExecQuery("SELECT Name, NumberOfCores FROM Win32_Processor")
                    item = result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    os_info["cpu_model"] = str(get_prop_value(props, "Name"))
                    cores_val = get_prop_value(props, "NumberOfCores")
                    if cores_val:
                        try:
                            os_info["cpu_cores"] = int(cores_val)
                        except (ValueError, TypeError):
                            pass
                    logger.debug(f"WMI CPU: {os_info.get('cpu_model')} ({os_info.get('cpu_cores')} cores)")
                except Exception as e:
                    logger.warning(f"WMI Win32_Processor query failed: {type(e).__name__}: {e}")

                # Get Disk Info (all fixed drives)
                logger.debug(f"WMI: Querying Win32_LogicalDisk...")
                try:
                    result = iWbemServices.ExecQuery("SELECT DeviceID, Size, FreeSpace, FileSystem FROM Win32_LogicalDisk WHERE DriveType=3")
                    disks = []
                    total_size = 0
                    total_free = 0
                    while True:
                        try:
                            item = result.Next(0xffffffff, 1)[0]
                            props = item.getProperties()
                            disk_info = {
                                "device_id": str(get_prop_value(props, "DeviceID")),
                                "filesystem": str(get_prop_value(props, "FileSystem")),
                            }
                            size_val = get_prop_value(props, "Size")
                            free_val = get_prop_value(props, "FreeSpace")
                            if size_val:
                                disk_info["size_gb"] = int(size_val) // (1024**3)
                                total_size += disk_info["size_gb"]
                            if free_val:
                                disk_info["free_gb"] = int(free_val) // (1024**3)
                                total_free += disk_info["free_gb"]
                            disks.append(disk_info)
                        except:
                            break
                    os_info["disks"] = disks
                    os_info["disk_total_gb"] = total_size
                    os_info["disk_free_gb"] = total_free
                    logger.debug(f"WMI Disks: {len(disks)} drives, {total_size}GB total, {total_free}GB free")
                except Exception as e:
                    logger.warning(f"WMI Win32_LogicalDisk query failed: {type(e).__name__}: {e}")
                
                # Get BIOS Serial
                logger.debug(f"WMI: Querying Win32_BIOS...")
                try:
                    result = iWbemServices.ExecQuery("SELECT SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS")
                    item = result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    bios_serial = str(get_prop_value(props, "SerialNumber"))
                    bios_version = str(get_prop_value(props, "SMBIOSBIOSVersion"))
                    if bios_serial and bios_serial != "To Be Filled By O.E.M.":
                        os_info["bios_serial"] = bios_serial
                    if bios_version:
                        os_info["bios_version"] = bios_version
                except Exception as e:
                    logger.debug(f"WMI Win32_BIOS query failed: {e}")
                
                # Get Network Adapters
                logger.debug(f"WMI: Querying Win32_NetworkAdapterConfiguration...")
                try:
                    result = iWbemServices.ExecQuery("SELECT Description, MACAddress, IPAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True")
                    nics = []
                    while True:
                        try:
                            item = result.Next(0xffffffff, 1)[0]
                            props = item.getProperties()
                            nic_info = {
                                "description": str(get_prop_value(props, "Description")),
                                "mac": str(get_prop_value(props, "MACAddress")),
                            }
                            ip_val = get_prop_value(props, "IPAddress")
                            if ip_val:
                                nic_info["ips"] = list(ip_val) if hasattr(ip_val, '__iter__') and not isinstance(ip_val, str) else [str(ip_val)]
                            nics.append(nic_info)
                        except:
                            break
                    os_info["network_adapters"] = nics
                    logger.debug(f"WMI NICs: {len(nics)} adapters found")
                except Exception as e:
                    logger.debug(f"WMI NetworkAdapterConfiguration query failed: {e}")
                
                # Get Last Boot Time
                logger.debug(f"WMI: Querying Win32_OperatingSystem LastBootUpTime...")
                try:
                    result = iWbemServices.ExecQuery("SELECT LastBootUpTime FROM Win32_OperatingSystem")
                    item = result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    boot_time = str(get_prop_value(props, "LastBootUpTime"))
                    if boot_time:
                        os_info["last_boot"] = boot_time
                except Exception as e:
                    logger.debug(f"WMI LastBootUpTime query failed: {e}")
                
                # Get Installed Software (top 20)
                logger.debug(f"WMI: Querying Win32_Product (limited)...")
                try:
                    result = iWbemServices.ExecQuery("SELECT Name, Version, Vendor FROM Win32_Product")
                    software = []
                    count = 0
                    while count < 20:
                        try:
                            item = result.Next(0xffffffff, 1)[0]
                            props = item.getProperties()
                            sw = {
                                "name": str(get_prop_value(props, "Name")),
                                "version": str(get_prop_value(props, "Version")),
                                "vendor": str(get_prop_value(props, "Vendor")),
                            }
                            if sw["name"]:
                                software.append(sw)
                            count += 1
                        except:
                            break
                    os_info["installed_software"] = software
                    logger.debug(f"WMI Software: {len(software)} products found")
                except Exception as e:
                    logger.debug(f"WMI Win32_Product query failed: {e}")
                
                # Detect Server Roles
                if "server" in os_info.get("name", "").lower():
                    logger.debug(f"WMI: Querying Win32_ServerFeature...")
                    try:
                        result = iWbemServices.ExecQuery("SELECT Name FROM Win32_ServerFeature WHERE ParentID=0")
                        roles = []
                        while True:
                            try:
                                item = result.Next(0xffffffff, 1)[0]
                                props = item.getProperties()
                                role = str(get_prop_value(props, "Name"))
                                if role:
                                    roles.append(role)
                            except:
                                break
                        os_info["server_roles"] = roles
                        # Detect if DC
                        if any("Active Directory" in r or "Domain Controller" in r for r in roles):
                            os_info["is_domain_controller"] = True
                        logger.debug(f"WMI Server Roles: {roles}")
                    except Exception as e:
                        logger.debug(f"WMI ServerFeature query failed: {e}")

                logger.info(f"WMI collected data: {list(os_info.keys())}")
                dcom.disconnect()
                return os_info
            
            info = await loop.run_in_executor(self._executor, connect)

            # Determina categoria
            category = "workstation"
            if "server" in info.get("name", "").lower():
                category = "server"

            logger.success(f"WMI probe successful for {address}: {info.get('hostname')} ({info.get('name')})")
            return ProbeResult(
                success=True,
                protocol="wmi",
                device_type="windows",
                category=category,
                os_family="Windows",
                os_version=info.get("version"),
                hostname=info.get("hostname"),
                model=info.get("model"),
                extra_info=info
            )

        except ImportError:
            logger.error(f"WMI probe failed for {address} - impacket not installed")
            return ProbeResult(
                success=False,
                protocol="wmi",
                error="impacket not installed"
            )
        except Exception as e:
            logger.error(f"WMI probe failed for {address} - {type(e).__name__}: {str(e)}")
            return ProbeResult(
                success=False,
                protocol="wmi",
                error=str(e)
            )
    
    async def probe_port(self, address: str, port: int, timeout: float = 2.0) -> bool:
        """Test se una porta TCP è aperta"""
        loop = asyncio.get_event_loop()
        
        def check():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                result = sock.connect_ex((address, port))
                return result == 0
            finally:
                sock.close()
        
        return await loop.run_in_executor(self._executor, check)
    
    async def probe_snmp_udp(self, address: str, community: str = "public", port: int = 161, timeout: float = 3.0) -> bool:
        """
        Test se SNMP è attivo su UDP porta 161.
        Esegue una vera query SNMP (sysDescr) per verificare che il servizio risponda.
        """
        try:
            from pysnmp.hlapi.v1arch.asyncio import (
                get_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget,
                ObjectType, ObjectIdentity
            )
            
            dispatcher = SnmpDispatcher()
            try:
                transport = await UdpTransportTarget.create(
                    (address, port),
                    timeout=timeout,
                    retries=1
                )
                
                # Query sysDescr per verificare risposta SNMP
                errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                    dispatcher,
                    CommunityData(community, mpModel=1),  # SNMPv2c
                    transport,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"))  # sysDescr
                )
                
                if errorIndication or errorStatus:
                    return False
                
                # Se abbiamo una risposta valida, SNMP è attivo
                for varBind in varBinds:
                    value = str(varBind[1])
                    if value and value != "No Such Object" and value != "No Such Instance":
                        logger.debug(f"SNMP probe success on {address}:{port} with community '{community}'")
                        return True
                
                return False
            finally:
                dispatcher.transport_dispatcher.close_dispatcher()
                
        except Exception as e:
            logger.debug(f"SNMP UDP probe failed for {address}:{port}: {e}")
            return False
    
    async def detect_available_protocols(self, address: str, snmp_communities: List[str] = None) -> List[str]:
        """
        Rileva quali protocolli sono disponibili su un host.
        Per SNMP usa probe UDP reale invece di TCP.
        """
        protocols = []
        
        if snmp_communities is None:
            snmp_communities = ["public", "private"]

        # Test porte TCP comuni
        tcp_port_checks = [
            (8728, "mikrotik_api"),  # RouterOS API
            (22, "ssh"),             # SSH
            (135, "wmi"),            # WMI/RPC
            (445, "wmi"),            # SMB (per WMI)
        ]

        # Test TCP in parallelo
        tcp_tasks = []
        for port, protocol in tcp_port_checks:
            tcp_tasks.append(self.probe_port(address, port))

        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)

        seen = set()
        for (port, protocol), result in zip(tcp_port_checks, tcp_results):
            if result is True and protocol not in seen:
                protocols.append(protocol)
                seen.add(protocol)
        
        # Test SNMP UDP separatamente (prova diverse community)
        for community in snmp_communities:
            snmp_available = await self.probe_snmp_udp(address, community=community)
            if snmp_available:
                protocols.append("snmp")
                logger.debug(f"SNMP detected on {address} with community '{community}'")
                break

        return protocols

    async def reverse_dns_lookup(
        self,
        address: str,
        dns_server: Optional[str] = None,
        fallback_dns: Optional[List[str]] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        """
        Esegue reverse DNS lookup con fallback DNS server.
        
        Args:
            address: Indirizzo IP da risolvere
            dns_server: DNS server primario (opzionale)
            fallback_dns: Lista DNS server di fallback (default: [8.8.8.8, 1.1.1.1])
            timeout: Timeout per ogni tentativo in secondi
        
        Returns:
            Dict con hostname e DNS server usato
        """
        import socket
        import dns.resolver
        import dns.reversename
        
        # DNS server di fallback di default
        if fallback_dns is None:
            fallback_dns = ["8.8.8.8", "1.1.1.1"]
        
        # Lista DNS server da provare (prima quello specificato, poi fallback)
        dns_servers = []
        if dns_server:
            dns_servers.append(dns_server)
        dns_servers.extend(fallback_dns)
        
        # Rimuovi duplicati mantenendo l'ordine
        seen = set()
        dns_servers = [s for s in dns_servers if not (s in seen or seen.add(s))]
        
        logger.debug(f"Reverse DNS lookup for {address} using DNS servers: {dns_servers}")
        
        # Prova ogni DNS server fino a trovare una risposta
        for dns_srv in dns_servers:
            try:
                # Crea resolver con DNS server specifico
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_srv]
                resolver.timeout = timeout
                resolver.lifetime = timeout
                
                # Esegui reverse lookup
                reverse_name = dns.reversename.from_address(address)
                answers = resolver.resolve(reverse_name, "PTR")
                
                if answers:
                    hostname = str(answers[0]).rstrip('.')
                    logger.info(f"Reverse DNS lookup for {address}: {hostname} (via {dns_srv})")
                    return {
                        "success": True,
                        "address": address,
                        "hostname": hostname,
                        "dns_server": dns_srv,
                    }
                    
            except dns.resolver.NXDOMAIN:
                # Dominio non esiste - non provare altri DNS server
                logger.debug(f"Reverse DNS NXDOMAIN for {address} (via {dns_srv})")
                return {
                    "success": False,
                    "address": address,
                    "error": "NXDOMAIN - No reverse DNS record",
                    "dns_server": dns_srv,
                }
            except dns.resolver.Timeout:
                logger.warning(f"Reverse DNS timeout for {address} via {dns_srv}, trying next DNS server...")
                continue
            except Exception as e:
                logger.warning(f"Reverse DNS error for {address} via {dns_srv}: {e}, trying next DNS server...")
                continue
        
        # Se tutti i DNS server hanno fallito
        logger.warning(f"Reverse DNS lookup failed for {address} with all DNS servers")
        return {
            "success": False,
            "address": address,
            "error": f"All DNS servers failed (tried: {', '.join(dns_servers)})",
            "dns_servers_tried": dns_servers,
        }
    
    async def reverse_dns_lookup_legacy(
        self, 
        address: str, 
        dns_servers: List[str] = None,
        agent: Optional['MikroTikAgent'] = None,
        use_agent: bool = True
    ) -> str:
        """
        Esegue reverse DNS lookup per ottenere hostname da IP.
        
        Args:
            address: IP address da risolvere
            dns_servers: Lista di DNS server da usare (opzionale).
            agent: Agente MikroTik per query DNS remote (opzionale)
            use_agent: Se True e agent è specificato, usa l'agente
        
        Returns:
            str: hostname se trovato, altrimenti stringa vuota
        """
        loop = asyncio.get_event_loop()
        
        # Se abbiamo un agente, prova prima tramite MikroTik
        if agent and use_agent:
            try:
                from .mikrotik_service import get_mikrotik_service
                mikrotik = get_mikrotik_service()
                
                def lookup_via_mikrotik():
                    return mikrotik.reverse_dns_lookup(
                        address=agent.address,
                        port=agent.api_port,
                        username=agent.username,
                        password=agent.password,
                        target_ip=address,
                        dns_server=agent.dns_server or (dns_servers[0] if dns_servers else None),
                        use_ssl=agent.use_ssl,
                    )
                
                result = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, lookup_via_mikrotik),
                    timeout=5.0
                )
                
                if result.get("success") and result.get("hostname"):
                    hostname = result["hostname"]
                    logger.info(f"Reverse DNS via MikroTik for {address}: {hostname}")
                    return hostname
            except Exception as e:
                logger.debug(f"MikroTik reverse DNS failed for {address}: {e}")
                # Continua con fallback

        def lookup_with_dnspython():
            """Usa dnspython per query PTR con DNS server specifico e fallback"""
            try:
                import dns.resolver
                import dns.reversename
                
                # Crea nome PTR
                rev_name = dns.reversename.from_address(address)
                
                # Lista DNS server da provare (quello specificato + fallback)
                dns_list = dns_servers or []
                fallback_dns = ["8.8.8.8", "1.1.1.1"]
                
                # Aggiungi fallback se non già presenti
                for fb in fallback_dns:
                    if fb not in dns_list:
                        dns_list.append(fb)
                
                # Prova ogni DNS server fino a trovare una risposta
                for dns_srv in dns_list:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dns_srv]
                        resolver.timeout = 2
                        resolver.lifetime = 3
                        
                        answers = resolver.resolve(rev_name, 'PTR')
                        for rdata in answers:
                            hostname = str(rdata).rstrip('.')
                            logger.debug(f"Reverse DNS for {address} via {dns_srv}: {hostname}")
                            return hostname
                    except dns.resolver.NXDOMAIN:
                        # Dominio non esiste - non provare altri DNS server
                        logger.debug(f"Reverse DNS NXDOMAIN for {address} via {dns_srv}")
                        return ""
                    except Exception as e:
                        logger.debug(f"Reverse DNS failed for {address} via {dns_srv}: {type(e).__name__}")
                        continue  # Prova prossimo DNS server
                
                return ""
            except Exception as e:
                logger.debug(f"dnspython PTR lookup failed for {address}: {type(e).__name__}")
                return ""

        def lookup_system():
            """Usa resolver di sistema"""
            try:
                import socket
                socket.setdefaulttimeout(2.0)
                hostname, _, _ = socket.gethostbyaddr(address)
                return hostname
            except (socket.herror, socket.gaierror, OSError, socket.timeout) as e:
                logger.debug(f"System reverse DNS lookup failed for {address}: {e}")
                return ""
            finally:
                socket.setdefaulttimeout(None)

        try:
            hostname = ""
            
            # Se specificati DNS server, usa dnspython
            if dns_servers:
                hostname = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, lookup_with_dnspython),
                    timeout=4.0
                )
            
            # Fallback a resolver di sistema se dnspython fallisce o non specificato
            if not hostname:
                hostname = await asyncio.wait_for(
                    loop.run_in_executor(self._executor, lookup_system),
                    timeout=3.0
                )
            
            if hostname:
                logger.info(f"Reverse DNS for {address}: {hostname}")
            return hostname
        except asyncio.TimeoutError:
            logger.debug(f"Reverse DNS lookup timeout for {address}")
            return ""
        except Exception as e:
            logger.debug(f"Reverse DNS lookup failed for {address}: {e}")
            return ""

    async def suggest_credential_type(self, address: str) -> str:
        """
        Suggerisce il tipo di credenziali in base alle porte aperte.

        Regole:
        - Se risponde a 389 (LDAP), 445 (SMB), o 3389 (RDP) -> wmi (Windows)
        - Se risponde a 161 (SNMP) -> snmp
        - Se risponde a 22 (SSH) ma non SNMP e non WMI -> ssh (Linux)
        - Se risponde a 8728 (RouterOS API) -> mikrotik

        Returns:
            str: "wmi", "snmp", "ssh", "mikrotik", o "unknown"
        """
        # Test porte per identificare il tipo di sistema
        port_checks = [
            (389, "ldap"),      # LDAP (Windows AD)
            (445, "smb"),       # SMB (Windows)
            (3389, "rdp"),      # RDP (Windows)
            (161, "snmp"),      # SNMP
            (22, "ssh"),        # SSH
            (8728, "mikrotik"), # RouterOS API
            (135, "wmi"),       # WMI/RPC (Windows)
        ]

        tasks = []
        for port, _ in port_checks:
            tasks.append(self.probe_port(address, port, timeout=2.0))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Raccogli porte aperte
        open_ports = {}
        for (port, service), result in zip(port_checks, results):
            if result is True:
                open_ports[service] = port

        logger.debug(f"Open ports for {address}: {open_ports}")

        # Determina tipo credenziali in base alle porte aperte
        # IMPORTANTE: La priorità è fondamentale perché Windows può avere SSH installato

        # Priorità 1: Windows (SMB è l'indicatore più affidabile, poi RDP, WMI, LDAP)
        # SMB (445) è quasi esclusivamente Windows
        if "smb" in open_ports:
            logger.info(f"Suggesting WMI credentials for {address} (SMB detected - Windows)")
            return "wmi"

        # RDP (3389) è esclusivamente Windows
        if "rdp" in open_ports:
            logger.info(f"Suggesting WMI credentials for {address} (RDP detected - Windows)")
            return "wmi"

        # WMI/RPC (135) è Windows
        if "wmi" in open_ports:
            logger.info(f"Suggesting WMI credentials for {address} (WMI/RPC detected - Windows)")
            return "wmi"

        # LDAP (389) di solito è Windows AD
        if "ldap" in open_ports:
            logger.info(f"Suggesting WMI credentials for {address} (LDAP detected - likely Windows AD)")
            return "wmi"

        # Priorità 2: MikroTik
        if "mikrotik" in open_ports:
            logger.info(f"Suggesting MikroTik credentials for {address} (RouterOS API detected)")
            return "mikrotik"

        # Priorità 3: SNMP (dispositivi di rete) - solo se non ha SSH
        if "snmp" in open_ports and "ssh" not in open_ports:
            logger.info(f"Suggesting SNMP credentials for {address} (SNMP only - network device)")
            return "snmp"

        # Priorità 4: SSH + SNMP (dispositivi di rete gestibili via SSH)
        if "ssh" in open_ports and "snmp" in open_ports:
            logger.info(f"Suggesting SSH credentials for {address} (SSH + SNMP - managed network device)")
            return "ssh"

        # Priorità 5: SSH solo (Linux/Unix)
        if "ssh" in open_ports:
            logger.info(f"Suggesting SSH credentials for {address} (SSH only - Linux/Unix)")
            return "ssh"

        logger.warning(f"Could not determine credential type for {address}")
        return "unknown"
    
    async def scan_services_quick(
        self, 
        address: str, 
        snmp_communities: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Scansione veloce delle porte critiche per pre-assegnazione OS/device_type.
        Solo le porte necessarie per identificare Windows/Linux/MikroTik/Proxmox/network.
        
        Args:
            address: IP del dispositivo da scansionare
            snmp_communities: Lista di community SNMP da provare per il probe UDP 161

        Returns:
            Lista di servizi rilevati: [{"port": 80, "protocol": "tcp", "service": "http", "open": true}, ...]
        """
        # Porte TCP critiche per pre-assegnazione
        tcp_ports_quick = {
            22: "ssh",          # Linux
            135: "wmi",         # Windows
            139: "netbios",     # Windows
            445: "smb",         # Windows
            3389: "rdp",        # Windows
            80: "http",         # Web
            443: "https",       # Web
            3306: "mysql",      # Database
            5432: "postgresql", # Database
            2049: "nfs",        # NFS
            8006: "proxmox-ve", # Proxmox
            8728: "mikrotik-api", # MikroTik
            8291: "mikrotik-winbox", # MikroTik
        }
        
        logger.info(f"Quick port scan on {address} ({len(tcp_ports_quick)} TCP + SNMP UDP)")
        
        services = []
        
        # Scansione TCP in parallelo
        tcp_tasks = [self._scan_tcp_port(address, port, service) for port, service in tcp_ports_quick.items()]
        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
        for result in tcp_results:
            if isinstance(result, dict) and result.get("open"):
                services.append(result)
        
        # Probe SNMP UDP (critico per network devices) - timeout breve per scansione veloce
        if snmp_communities is None:
            snmp_communities = ["public"]
        # Limita a max 2 community per velocità
        communities_to_try = snmp_communities[:2]
        for community in communities_to_try:
            try:
                # Timeout breve per SNMP probe (1.5 secondi)
                if await asyncio.wait_for(self.probe_snmp_udp(address, community=community, timeout=1.5), timeout=2.0):
                    services.append({"port": 161, "protocol": "udp", "service": "snmp", "open": True})
                    break
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.debug(f"SNMP probe failed for {address} with community '{community}': {e}")
                continue
        
        logger.info(f"Quick scan complete for {address}: {len(services)} ports open")
        return services
    
    async def scan_services(
        self, 
        address: str, 
        agent: Optional['MikroTikAgent'] = None,
        use_agent: bool = True,
        snmp_communities: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Esegue scansione completa delle porte per identificare servizi attivi.
        Include tutte le porte TCP/UDP importanti per identificazione OS/ruolo sistema.

        Args:
            address: IP del dispositivo da scansionare
            agent: Agente MikroTik da usare per la scansione (opzionale)
            use_agent: Se True e agent è specificato, usa l'agente. Se False, usa connessione diretta.
            snmp_communities: Lista di community SNMP da provare per il probe UDP 161

        Returns:
            Lista di servizi rilevati: [{"port": 80, "protocol": "tcp", "service": "http", "open": true}, ...]
        """
        # Se abbiamo un agente e use_agent è True, usa MikroTik
        if agent and use_agent:
            return await self._scan_services_via_mikrotik(address, agent, snmp_communities=snmp_communities)
        # Porte TCP da scansionare (priorità per identificazione OS/ruolo)
        tcp_ports = {
            # Remote Access (identificazione OS)
            22: "ssh",          # *nix/BSD, appliance, Windows hardenato
            23: "telnet",       # Legacy, appliance di rete, vecchi Unix/embedded
            3389: "rdp",        # Windows Desktop/Server (forte indicatore)
            5900: "vnc",        # Linux desktop/appliance
            5901: "vnc",
            5902: "vnc",
            5903: "vnc",
            5904: "vnc",
            5905: "vnc",

            # Windows (forti indicatori)
            135: "wmi",         # MS RPC Endpoint Mapper (Windows)
            139: "netbios",    # NetBIOS (Windows legacy)
            445: "smb",        # SMB (Windows - molto tipico)
            5985: "winrm-http",   # WinRM (Windows server moderno)
            5986: "winrm-https",

            # Directory Services
            389: "ldap",       # LDAP (AD domain controller o directory *nix)
            636: "ldaps",      # LDAPS

            # Web Services (banner e stack TLS aiutano identificazione)
            80: "http",
            443: "https",
            8000: "http-alt",  # Appliance, Java app server, reverse proxy
            8080: "http-proxy",
            8443: "https-alt",

            # Mail (tipico mail server *nix)
            25: "smtp",
            110: "pop3",
            143: "imap",
            465: "smtps",
            587: "smtp-submission",
            993: "imaps",
            995: "pop3s",

            # Databases (quasi sempre *nix)
            3306: "mysql",
            5432: "postgresql",
            1433: "mssql",     # SQL Server (Windows)
            1521: "oracle",
            27017: "mongodb",
            6379: "redis",

            # File Services
            21: "ftp",
            20: "ftp-data",
            69: "tftp",
            111: "rpcbind",    # RPCbind/portmapper (marcato Unix/Linux)
            2049: "nfs",       # NFS (forte indicatore Unix/Linux)

            # Network Management
            161: "snmp",       # SNMP (device di rete, appliance, host server con agent)
            162: "snmp-trap",
            8728: "mikrotik-api",
            8291: "mikrotik-winbox",

            # Virtualization / Hypervisors
            8006: "proxmox-ve",     # Proxmox VE Web UI
            8007: "proxmox-backup", # Proxmox Backup Server
            902: "vmware-soap",     # VMware ESXi SOAP API
            903: "vmware-vnc",      # VMware VNC
            2179: "hyper-v",        # Hyper-V
            2375: "docker",         # Docker daemon (non sicuro)
            2376: "docker-tls",     # Docker daemon TLS
            6443: "kubernetes-api", # Kubernetes API
            10250: "kubelet",        # Kubelet API

            # DNS
            53: "dns",         # DNS (server DNS dedicati, AD, appliance)

            # Remote Desktop / Citrix
            1494: "citrix-ica",     # Citrix ICA
            2598: "citrix-ica-alt", # Citrix ICA alternate
            3390: "rdp-alt",        # RDP alternate
            2222: "ssh-alt",        # SSH alternate

            # Web Services (altri)
            8888: "http-alt",       # HTTP alternate (common)
            9000: "sonarqube",     # SonarQube / other web apps
            9090: "prometheus",     # Prometheus / other web apps

            # Other Services
            123: "ntp",
            514: "syslog",
            1900: "ssdp",
        }

        # Porte UDP da scansionare (infra e appliance)
        udp_ports = {
            53: "dns",         # DNS (pattern di risposta e EDNS aiutano identificazione)
            67: "dhcp-server", # DHCP (tipico server infra, router, appliance)
            68: "dhcp-client",
            69: "tftp",
            123: "ntp",        # NTP (versione e implementation spesso OS-specifica)
            137: "netbios-ns", # NetBIOS (Windows legacy, vecchi domain/lan)
            138: "netbios-dgm",
            161: "snmp",       # SNMP (device di rete, appliance, host server con agent)
            162: "snmp-trap",
            500: "ipsec-ike",  # IKE/IPsec (firewall/VPN appliance, server)
            1900: "ssdp",      # SSDP/UPnP (device consumer, appliance, NAS)
            5353: "mdns",
        }

        logger.info(f"Starting service scan on {address} ({len(tcp_ports)} TCP + {len(udp_ports)} UDP ports)")

        services = []

        # Scansione TCP (più veloce e affidabile)
        tcp_tasks = []
        for port, service_name in tcp_ports.items():
            tcp_tasks.append(self._scan_tcp_port(address, port, service_name))

        tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
        for result in tcp_results:
            if isinstance(result, dict) and result.get("open"):
                services.append(result)

        logger.info(f"TCP scan complete for {address}: {len(services)} open ports found")

        # Scansione UDP (opzionale, più lenta)
        # Limitiamo a porte critiche per identificazione
        udp_critical = {53: "dns", 67: "dhcp-server", 68: "dhcp-client", 123: "ntp", 161: "snmp", 162: "snmp-trap", 500: "ipsec-ike", 1900: "ssdp"}
        udp_tasks = []
        for port, service_name in udp_critical.items():
            udp_tasks.append(self._scan_udp_port(address, port, service_name, snmp_communities=snmp_communities))

        udp_results = await asyncio.gather(*udp_tasks, return_exceptions=True)
        for result in udp_results:
            if isinstance(result, dict) and result.get("open"):
                services.append(result)

        logger.info(f"Service scan complete for {address}: {len(services)} services detected (TCP + UDP)")

        return services

    async def _scan_tcp_port(self, address: str, port: int, service_name: str) -> Dict[str, Any]:
        """Scansiona una singola porta TCP"""
        loop = asyncio.get_event_loop()

        def check():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)  # Timeout breve per velocità
            try:
                result = sock.connect_ex((address, port))
                return result == 0
            except:
                return False
            finally:
                sock.close()

        try:
            is_open = await loop.run_in_executor(self._executor, check)
            return {
                "port": port,
                "protocol": "tcp",
                "service": service_name,
                "open": is_open
            }
        except Exception as e:
            logger.debug(f"Error scanning {address}:{port} - {e}")
            return {
                "port": port,
                "protocol": "tcp",
                "service": service_name,
                "open": False
            }

    async def _scan_udp_port(self, address: str, port: int, service_name: str, snmp_communities: List[str] = None) -> Dict[str, Any]:
        """Scansiona una singola porta UDP"""
        
        # Per SNMP (porta 161), usa il probe SNMP reale con diverse community
        if port == 161:
            communities_to_try = snmp_communities or ["public", "private"]
            for community in communities_to_try:
                is_open = await self.probe_snmp_udp(address, community=community, port=port, timeout=2.0)
                if is_open:
                    logger.debug(f"SNMP detected on {address}:{port} with community '{community}'")
                    return {
                        "port": port,
                        "protocol": "udp",
                        "service": service_name,
                        "open": True,
                        "snmp_community": community
                    }
            return {
                "port": port,
                "protocol": "udp",
                "service": service_name,
                "open": False
            }
        
        # Per altre porte UDP, usa il metodo standard
        loop = asyncio.get_event_loop()

        def check():
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            try:
                # Per UDP, proviamo a inviare un pacchetto e vedere se c'è risposta
                sock.sendto(b'\x00', (address, port))
                sock.recvfrom(1024)
                return True
            except socket.timeout:
                # Per DNS proviamo query specifica
                if port == 53:  # DNS
                    try:
                        query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                        sock.sendto(query, (address, port))
                        sock.recvfrom(1024)
                        return True
                    except:
                        return False
                return False
            except:
                return False
            finally:
                sock.close()

        try:
            is_open = await loop.run_in_executor(self._executor, check)
            return {
                "port": port,
                "protocol": "udp",
                "service": service_name,
                "open": is_open
            }
        except Exception as e:
            logger.debug(f"Error scanning UDP {address}:{port} - {e}")
            return {
                "port": port,
                "protocol": "udp",
                "service": service_name,
                "open": False
            }
    
    async def _scan_services_via_mikrotik(
        self, 
        address: str, 
        agent: 'MikroTikAgent',
        snmp_communities: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Esegue scansione porte tramite router MikroTik.
        Usa SSH per eseguire test di connettività dal router.
        """
        from .mikrotik_service import get_mikrotik_service
        
        logger.info(f"Scanning services on {address} via MikroTik agent {agent.address}")
        
        mikrotik = get_mikrotik_service()
        
        # Esegui scan tramite MikroTik
        loop = asyncio.get_event_loop()
        
        def run_scan():
            return mikrotik.scan_ports(
                address=agent.address,
                port=agent.api_port,
                username=agent.username,
                password=agent.password,
                target_ip=address,
                use_ssl=agent.use_ssl,
            )
        
        try:
            result = await loop.run_in_executor(self._executor, run_scan)
            
            if result.get("success"):
                logger.info(f"MikroTik port scan complete for {address}: {len(result.get('open_ports', []))} ports open")
                return result.get("open_ports", [])
            else:
                logger.warning(f"MikroTik port scan failed for {address}: {result.get('error')}")
                # Fallback a scan diretto
                logger.info(f"Falling back to direct port scan for {address}")
                return await self.scan_services(address, agent=None, use_agent=False)
        except Exception as e:
            logger.error(f"Error in MikroTik port scan: {e}")
            # Fallback a scan diretto
            return await self.scan_services(address, agent=None, use_agent=False)

    async def auto_identify_device(
        self,
        address: str,
        mac_address: str = None,
        credentials_list: List[Dict] = None,
        agent: Optional['MikroTikAgent'] = None,
        use_agent: bool = True
    ) -> Dict[str, Any]:
        """
        Identificazione automatica del dispositivo.

        1. Lookup vendor dal MAC
        2. Rileva protocolli disponibili
        3. Prova le credenziali fornite
        4. Scansiona servizi attivi

        Args:
            address: IP del dispositivo
            mac_address: MAC address (opzionale, per vendor lookup)
            credentials_list: Lista credenziali da provare
            agent: Agente MikroTik per operazioni remote (opzionale)
            use_agent: Se True e agent è specificato, usa l'agente per port scan e DNS

        Returns:
            Dict con device_type, category, os_family, hostname, etc
        """
        
        agent_info = f" via agent {agent.address}" if agent and use_agent else ""
        logger.info(f"Auto-identifying device at {address} (MAC: {mac_address or 'N/A'}){agent_info}")

        result = {
            "address": address,
            "mac_address": mac_address,
            "vendor": None,
            "device_type": "other",
            "category": None,
            "os_family": None,
            "hostname": None,
            "model": None,
            "identified_by": None,
            "available_protocols": [],
            "probe_results": [],
            "open_ports": [],  # Servizi rilevati
        }
        
        # 1. MAC Vendor lookup
        if mac_address:
            mac_service = get_mac_lookup_service()
            vendor_info = mac_service.lookup(mac_address)
            if vendor_info:
                result["vendor"] = vendor_info.get("vendor")
                result["device_type"] = vendor_info.get("device_type", "other")
                result["category"] = vendor_info.get("category")
                result["os_family"] = vendor_info.get("os_family")
                
                if vendor_info.get("vendor"):
                    result["identified_by"] = "mac_vendor"
        
        # Estrai community SNMP dalle credenziali per il probe
        snmp_communities = ["public", "private"]  # Default
        if credentials_list:
            for cred in credentials_list:
                # Supporta sia "type" che "credential_type" per compatibilità
                cred_type = cred.get("type") or cred.get("credential_type")
                snmp_comm = cred.get("snmp_community")
                # Aggiungi community se è di tipo SNMP o se ha una community non-default
                if snmp_comm and snmp_comm not in snmp_communities:
                    snmp_communities.insert(0, snmp_comm)  # Priorità alle credenziali fornite
                    logger.debug(f"Added SNMP community '{snmp_comm}' from credential")
        
        # 2. Rileva protocolli (passa le community SNMP per il probe UDP)
        try:
            result["available_protocols"] = await self.detect_available_protocols(address, snmp_communities=snmp_communities)
        except Exception as e:
            logger.warning(f"Protocol detection failed for {address}: {e}")
        
        # 3. Prova credenziali se fornite
        if credentials_list:
            logger.info(f"Testing {len(credentials_list)} credential(s) for {address}")
            for idx, creds in enumerate(credentials_list, 1):
                cred_type = creds.get("type", "")
                cred_name = creds.get("name", f"credential-{idx}")

                # Scegli protocolli in base al tipo credenziali
                # IMPORTANTE: Se c'è una credenziale specifica, prova sempre quel protocollo anche senza porte aperte
                protocols = []
                if cred_type == "mikrotik" or cred_type == "routeros":
                    protocols = ["mikrotik_api"]
                elif cred_type == "ssh" or cred_type == "linux":
                    protocols = ["ssh"]  # Prova sempre SSH se credenziale SSH, anche senza porte aperte
                elif cred_type == "snmp":
                    protocols = ["snmp"]
                elif cred_type == "wmi" or cred_type == "windows":
                    protocols = ["wmi"]
                else:
                    # Prova tutti i protocolli disponibili, ma se non ci sono porte aperte, prova comunque SSH/SNMP se disponibili nelle credenziali
                    protocols = result["available_protocols"]
                    if not protocols and (creds.get("username") or creds.get("password")):
                        # Se non ci sono protocolli rilevati ma abbiamo username/password, prova SSH
                        protocols = ["ssh"]
                        logger.info(f"No protocols detected, but credential has username/password - trying SSH anyway")

                logger.info(f"Testing credential '{cred_name}' (type: {cred_type}, username: {creds.get('username', 'N/A')}) with protocols: {protocols}")
                probe_results = await self.probe_device(address, creds, protocols)
                
                # Arricchisci i risultati con i dati extra raccolti
                for probe in probe_results:
                     probe_data = {
                        "protocol": probe.protocol,
                        "success": probe.success,
                        "device_type": probe.device_type,
                        "category": probe.category,
                        "os_family": probe.os_family,
                        "hostname": probe.hostname,
                        "error": probe.error,
                        "extra_info": probe.extra_info # Includi extra info
                    }
                     result["probe_results"].append(probe_data)

                # Se trovato un risultato positivo, aggiorna
                for probe in probe_results:
                    if probe.success and probe.device_type:
                        result["device_type"] = probe.device_type
                        result["category"] = probe.category
                        result["os_family"] = probe.os_family
                        result["hostname"] = probe.hostname
                        result["model"] = probe.model
                        result["identified_by"] = f"probe_{probe.protocol}"
                        result["credential_used"] = cred_name
                        
                        # Merge extra info into main result
                        # Questo include: cpu_model, cpu_cores, memory_total_mb, 
                        # disk_total_gb, disk_free_gb, serial_number, manufacturer, domain, etc.
                        if probe.extra_info:
                            logger.debug(f"Merging extra_info from {probe.protocol}: {list(probe.extra_info.keys())}")
                            for key, value in probe.extra_info.items():
                                if value is not None and value != "":
                                    result[key] = value

                        logger.success(f"Device {address} identified via {probe.protocol}: type={probe.device_type}, hostname={probe.hostname}, extra_keys={list(probe.extra_info.keys()) if probe.extra_info else []}")
                        break

                if result["identified_by"] and result["identified_by"].startswith("probe_"):
                    break

        # 4. Scansiona servizi attivi
        try:
            scan_method = "via agent" if agent and use_agent else "direct"
            logger.info(f"Scanning services on {address} ({scan_method})...")
            result["open_ports"] = await self.scan_services(address, agent=agent, use_agent=use_agent)
            logger.info(f"Service scan complete for {address}: {len(result['open_ports'])} services detected")
            
            # Usa le porte aperte per migliorare identificazione OS/ruolo se non già identificato
            if not result.get("identified_by") or result["identified_by"] == "mac_vendor":
                os_hint = self._identify_os_from_ports(result["open_ports"])
                if os_hint:
                    if not result.get("os_family"):
                        result["os_family"] = os_hint.get("os_family")
                    if not result.get("device_type") or result["device_type"] == "other":
                        result["device_type"] = os_hint.get("device_type", "other")
                    if not result.get("category"):
                        result["category"] = os_hint.get("category")
                    result["identified_by"] = "port_scan"
                    logger.info(f"Identified via port scan: {os_hint}")
        except Exception as e:
            logger.warning(f"Service scan failed for {address}: {e}")
            result["open_ports"] = []

        if not result.get("identified_by") or result["identified_by"] == "mac_vendor":
            logger.warning(f"Could not fully identify device {address} - only MAC vendor available")
        else:
            logger.info(f"Device identification complete for {address}: {result['device_type']} ({result['hostname'] or 'no hostname'})")
        
        # 5. Raccogli informazioni avanzate se dispositivo identificato e credenziali disponibili
        # Accetta sia probe_ che agent_ come identificazione valida
        identified = result.get("identified_by")
        is_identified = identified and (identified.startswith("probe_") or identified.startswith("agent_"))
        if is_identified and credentials_list:
            try:
                device_type = result.get("device_type", "").lower()
                # Usa vendor o manufacturer come fallback
                vendor = (result.get("vendor") or result.get("manufacturer") or "").lower()
                
                # Switch/Router: raccogli LLDP/CDP neighbors e dettagli interfacce
                if device_type in ["network", "router", "switch"] or "mikrotik" in vendor or "cisco" in vendor or "hp" in vendor or "aruba" in vendor or "ubiquiti" in vendor:
                    logger.info(f"Collecting advanced network info (LLDP/CDP/interfaces) for {address}...")
                    from .lldp_cdp_collector import get_lldp_cdp_collector
                    lldp_collector = get_lldp_cdp_collector()
                    
                    # Raccogli LLDP neighbors
                    try:
                        lldp_neighbors = await lldp_collector.collect_lldp_neighbors(
                            address, device_type, vendor, credentials_list
                        )
                        if lldp_neighbors:
                            result["lldp_neighbors"] = lldp_neighbors
                            logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors")
                    except Exception as e:
                        logger.debug(f"LLDP collection failed: {e}")
                    
                    # Raccogli CDP neighbors (solo Cisco)
                    if "cisco" in vendor:
                        try:
                            cdp_neighbors = await lldp_collector.collect_cdp_neighbors(
                                address, vendor, credentials_list
                            )
                            if cdp_neighbors:
                                result["cdp_neighbors"] = cdp_neighbors
                                logger.info(f"Found {len(cdp_neighbors)} CDP neighbors")
                        except Exception as e:
                            logger.debug(f"CDP collection failed: {e}")
                    
                    # Raccogli dettagli interfacce
                    try:
                        interfaces = await lldp_collector.collect_interface_details(
                            address, device_type, vendor, credentials_list
                        )
                        if interfaces:
                            result["interface_details"] = interfaces
                            logger.info(f"Found {len(interfaces)} interfaces with details")
                    except Exception as e:
                        logger.debug(f"Interface details collection failed: {e}")
                
                # Proxmox: raccogli info host, VM, storage, backup
                # Controlla anche manufacturer se vendor non è disponibile
                os_family_lower = (result.get("os_family") or "").lower()
                manufacturer_lower = (result.get("manufacturer") or "").lower()
                
                if device_type == "hypervisor" or "proxmox" in vendor or "proxmox" in manufacturer_lower or "proxmox" in os_family_lower:
                    logger.info(f"Collecting advanced Proxmox info for {address}...")
                    from .proxmox_collector import get_proxmox_collector
                    proxmox_collector = get_proxmox_collector()
                    
                    # Raccogli info host
                    try:
                        host_info = await proxmox_collector.collect_proxmox_host_info(
                            address, credentials_list
                        )
                        if host_info:
                            result["proxmox_host_info"] = host_info
                            node_name = host_info.get("node_name")
                            
                            # Raccogli VM se abbiamo il node name
                            if node_name:
                                try:
                                    vms = await proxmox_collector.collect_proxmox_vms(
                                        address, node_name, credentials_list
                                    )
                                    if vms:
                                        result["proxmox_vms"] = vms
                                        logger.info(f"Found {len(vms)} Proxmox VMs")
                                except Exception as e:
                                    logger.debug(f"Proxmox VM collection failed: {e}")
                                
                                # Raccogli storage
                                try:
                                    storage = await proxmox_collector.collect_proxmox_storage(
                                        address, node_name, credentials_list
                                    )
                                    if storage:
                                        result["proxmox_storage"] = storage
                                        logger.info(f"Found {len(storage)} Proxmox storage")
                                except Exception as e:
                                    logger.debug(f"Proxmox storage collection failed: {e}")
                    except Exception as e:
                        logger.debug(f"Proxmox host info collection failed: {e}")
                
            except Exception as e:
                logger.warning(f"Advanced info collection failed for {address}: {e}")

        return result

    def _identify_os_from_ports(self, open_ports: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Identifica OS/ruolo sistema basandosi sulle porte aperte.
        
        Returns:
            Dict con os_family, device_type, category o None
        """
        if not open_ports:
            return None
        
        # Estrai porte aperte
        ports = {p["port"] for p in open_ports if p.get("open")}
        services = {p["service"] for p in open_ports if p.get("open")}
        
        # Windows indicators (priorità alta)
        windows_ports = {135, 139, 445, 3389, 5985, 5986}
        windows_services = {"wmi", "netbios", "smb", "rdp", "winrm-http", "winrm-https"}
        
        if ports & windows_ports or services & windows_services:
            # Determina ruolo
            if 3389 in ports or "rdp" in services:
                category = "workstation" if 3389 in ports and 445 not in ports else "server"
            elif 389 in ports or "ldap" in services:
                category = "server"  # Domain Controller
            elif 1433 in ports or "mssql" in services:
                category = "server"  # SQL Server
            else:
                category = "server"
            
            return {
                "os_family": "Windows",
                "device_type": "windows",
                "category": category
            }
        
        # Linux/Unix indicators
        linux_ports = {22, 111, 2049, 3306, 5432}
        linux_services = {"ssh", "rpcbind", "nfs", "mysql", "postgresql"}
        
        if (ports & linux_ports or services & linux_services) and not (ports & windows_ports):
            # Determina ruolo
            if 3306 in ports or 5432 in ports or "mysql" in services or "postgresql" in services:
                category = "server"  # Database server
            elif 25 in ports or 110 in ports or 143 in ports or "smtp" in services:
                category = "server"  # Mail server
            elif 80 in ports or 443 in ports or "http" in services:
                category = "server"  # Web server
            elif 22 in ports and 161 in ports:
                category = "network"  # Network device gestibile
            else:
                category = "server"
            
            return {
                "os_family": "Linux",
                "device_type": "linux",
                "category": category
            }
        
        # Network device indicators
        network_ports = {161, 162, 8728, 8291}
        network_services = {"snmp", "mikrotik-api", "mikrotik-winbox"}
        
        if ports & network_ports or services & network_services:
            if 8728 in ports or "mikrotik-api" in services:
                return {
                    "os_family": "RouterOS",
                    "device_type": "mikrotik",
                    "category": "router"
                }
            else:
                return {
                    "os_family": "Unknown",
                    "device_type": "network",
                    "category": "switch"
                }
        
        # Appliance indicators
        if 23 in ports or "telnet" in services:
            return {
                "os_family": "Unknown",
                "device_type": "network",
                "category": "appliance"
            }
        
        return None


# Singleton
_device_probe_service: Optional[DeviceProbeService] = None


def get_device_probe_service() -> DeviceProbeService:
    global _device_probe_service
    if _device_probe_service is None:
        _device_probe_service = DeviceProbeService()
    return _device_probe_service