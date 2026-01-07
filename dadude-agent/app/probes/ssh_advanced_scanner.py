"""
DaDude Agent - Advanced SSH Scanner
===================================
Scanner SSH avanzato per sistemi Linux, storage e hypervisor.
Estrae informazioni complete da:
- Linux (Debian, Ubuntu, CentOS, RHEL, Alpine, etc.)
- Synology DSM
- QNAP QTS/QuTS
- Proxmox VE

Supporta comandi con sudo quando necessario.
"""

import asyncio
import re
from typing import Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
from loguru import logger
from io import StringIO
from datetime import datetime
from enum import Enum


class SystemType(Enum):
    """Tipo di sistema identificato"""
    UNKNOWN = "unknown"
    LINUX_GENERIC = "linux"
    LINUX_DEBIAN = "debian"
    LINUX_UBUNTU = "ubuntu"
    LINUX_CENTOS = "centos"
    LINUX_RHEL = "rhel"
    LINUX_ALPINE = "alpine"
    LINUX_PROXMOX = "proxmox"
    SYNOLOGY = "synology"
    QNAP = "qnap"


_executor = ThreadPoolExecutor(max_workers=5)


class SSHAdvancedScanner:
    """Scanner SSH avanzato con supporto sudo"""
    
    def __init__(self, host: str, username: str, password: Optional[str] = None,
                 private_key: Optional[str] = None, port: int = 22, timeout: int = 30):
        self.host = host
        self.username = username
        self.password = password
        self.private_key = private_key
        self.port = port
        self.timeout = timeout
        self.client = None
        self.system_type = SystemType.UNKNOWN
        self.result = {}
    
    def log(self, message: str, level: str = "debug"):
        """Log con prefisso host"""
        if level == "info":
            logger.info(f"[{self.host}] {message}")
        elif level == "warning":
            logger.warning(f"[{self.host}] {message}")
        elif level == "error":
            logger.error(f"[{self.host}] {message}")
        else:
            logger.debug(f"[{self.host}] {message}")
    
    def connect(self) -> bool:
        """Stabilisce connessione SSH"""
        self.log("Connessione SSH...", "info")
        
        try:
            import paramiko
            from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key
            
            self.client = SSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'allow_agent': True,
                'look_for_keys': True,
            }
            
            if self.private_key:
                try:
                    # Prova RSA
                    key = RSAKey.from_private_key(StringIO(self.private_key))
                except:
                    try:
                        # Prova Ed25519
                        key = Ed25519Key.from_private_key(StringIO(self.private_key))
                    except Exception as e:
                        self.log(f"Errore caricamento chiave: {e}", "error")
                        key = None
                
                if key:
                    connect_kwargs['pkey'] = key
            
            if self.password:
                connect_kwargs['password'] = self.password
            
            self.client.connect(**connect_kwargs)
            self.log("Connesso!", "info")
            return True
            
        except Exception as e:
            self.log(f"Errore connessione: {e}", "error")
            self.result["errors"] = self.result.get("errors", [])
            self.result["errors"].append(f"SSH connection failed: {e}")
            return False
    
    def disconnect(self):
        """Chiude connessione SSH"""
        if self.client:
            self.client.close()
            self.log("Disconnesso", "debug")
    
    def run_command(self, command: str, timeout: int = 30, 
                    sudo: bool = False, ignore_errors: bool = True) -> Tuple[str, str, int]:
        """
        Esegue un comando remoto
        
        Args:
            command: Comando da eseguire
            timeout: Timeout comando
            sudo: Esegui con sudo
            ignore_errors: Non fallire su errori
            
        Returns:
            Tuple (stdout, stderr, exit_code)
        """
        if not self.client:
            return "", "Not connected", -1
        
        if sudo and self.password:
            # Usa echo per passare password a sudo
            command = f"echo '{self.password}' | sudo -S {command}"
        elif sudo:
            # Prova senza password (NOPASSWD configurato)
            command = f"sudo {command}"
        
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            stdout_text = stdout.read().decode('utf-8', errors='replace').strip()
            stderr_text = stderr.read().decode('utf-8', errors='replace').strip()
            
            # Rimuovi prompt password sudo dall'output
            if sudo and self.password:
                stdout_text = re.sub(r'\[sudo\].*?:', '', stdout_text).strip()
                stderr_text = re.sub(r'\[sudo\].*?:', '', stderr_text).strip()
            
            return stdout_text, stderr_text, exit_code
            
        except Exception as e:
            if not ignore_errors:
                raise
            return "", str(e), -1
    
    def run_command_output(self, command: str, sudo: bool = False) -> str:
        """Esegue comando e ritorna solo stdout"""
        stdout, _, _ = self.run_command(command, sudo=sudo)
        return stdout
    
    def file_exists(self, path: str) -> bool:
        """Verifica se un file esiste"""
        _, _, code = self.run_command(f"test -e {path}")
        return code == 0
    
    def read_file(self, path: str, sudo: bool = False) -> str:
        """Legge contenuto di un file"""
        return self.run_command_output(f"cat {path}", sudo=sudo)
    
    def detect_system(self) -> SystemType:
        """Identifica il tipo di sistema"""
        self.log("Identificazione sistema...", "debug")
        
        # Check Synology
        if self.file_exists("/etc/synoinfo.conf"):
            self.log("Rilevato: Synology DSM", "info")
            return SystemType.SYNOLOGY
        
        # Check QNAP
        if self.file_exists("/etc/config/uLinux.conf") or self.file_exists("/etc/default_config/BOOT.conf"):
            self.log("Rilevato: QNAP QTS", "info")
            return SystemType.QNAP
        
        # Check Proxmox
        if self.file_exists("/etc/pve"):
            self.log("Rilevato: Proxmox VE", "info")
            return SystemType.LINUX_PROXMOX
        
        # Check Linux distro
        os_release = self.read_file("/etc/os-release")
        
        if "Ubuntu" in os_release:
            self.log("Rilevato: Ubuntu Linux", "info")
            return SystemType.LINUX_UBUNTU
        elif "Debian" in os_release:
            self.log("Rilevato: Debian Linux", "info")
            return SystemType.LINUX_DEBIAN
        elif "CentOS" in os_release:
            self.log("Rilevato: CentOS Linux", "info")
            return SystemType.LINUX_CENTOS
        elif "Red Hat" in os_release or "RHEL" in os_release:
            self.log("Rilevato: RHEL Linux", "info")
            return SystemType.LINUX_RHEL
        elif "Alpine" in os_release:
            self.log("Rilevato: Alpine Linux", "info")
            return SystemType.LINUX_ALPINE
        
        # Generic Linux
        if self.file_exists("/etc/os-release") or self.file_exists("/proc/version"):
            self.log("Rilevato: Linux generico", "info")
            return SystemType.LINUX_GENERIC
        
        self.log("Sistema non identificato", "warning")
        return SystemType.UNKNOWN
    
    def collect_system_info(self):
        """Raccoglie info sistema base"""
        self.log("Raccolta info sistema...", "debug")
        
        si = {}
        
        # Hostname
        si["hostname"] = self.run_command_output("hostname -s")
        si["fqdn"] = self.run_command_output("hostname -f")
        
        # OS Release
        os_release = self.read_file("/etc/os-release")
        for line in os_release.split('\n'):
            if line.startswith('NAME='):
                si["os_name"] = line.split('=')[1].strip('"')
            elif line.startswith('VERSION='):
                si["os_version"] = line.split('=')[1].strip('"')
            elif line.startswith('VERSION_CODENAME='):
                si["os_codename"] = line.split('=')[1].strip('"')
            elif line.startswith('PRETTY_NAME='):
                if not si.get("os_name"):
                    si["os_name"] = line.split('=')[1].strip('"')
        
        # Kernel
        si["kernel_version"] = self.run_command_output("uname -r")
        si["architecture"] = self.run_command_output("uname -m")
        
        # Uptime
        uptime_output = self.run_command_output("cat /proc/uptime")
        if uptime_output:
            try:
                uptime_secs = float(uptime_output.split()[0])
                si["uptime_seconds"] = int(uptime_secs)
                days = int(uptime_secs // 86400)
                hours = int((uptime_secs % 86400) // 3600)
                minutes = int((uptime_secs % 3600) // 60)
                si["uptime"] = f"{days}d {hours}h {minutes}m"
                si["uptime_days"] = round(uptime_secs / 86400, 2)
            except:
                pass
        
        # Boot time
        boot_time = self.run_command_output(
            "date -d \"$(cat /proc/uptime | awk '{print $1}') seconds ago\" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo ''"
        )
        if boot_time:
            try:
                si["boot_time"] = datetime.strptime(boot_time, '%Y-%m-%d %H:%M:%S').isoformat()
            except:
                pass
        
        # Timezone
        si["timezone"] = self.run_command_output("cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null")
        
        si["system_type"] = self.system_type.value
        
        self.result["system_info"] = si
    
    def collect_cpu_info(self):
        """Raccoglie info CPU"""
        self.log("Raccolta info CPU...", "debug")
        
        cpu = {}
        
        # /proc/cpuinfo
        cpuinfo = self.read_file("/proc/cpuinfo")
        
        cores_physical = set()
        cores_logical = 0
        
        for line in cpuinfo.split('\n'):
            if line.startswith('model name'):
                if not cpu.get("model"):
                    cpu["model"] = line.split(':')[1].strip()
            elif line.startswith('cpu MHz'):
                try:
                    cpu["frequency_mhz"] = float(line.split(':')[1].strip())
                except:
                    pass
            elif line.startswith('cache size'):
                cpu["cache_size"] = line.split(':')[1].strip()
            elif line.startswith('physical id'):
                cores_physical.add(line.split(':')[1].strip())
            elif line.startswith('processor'):
                cores_logical += 1
            elif line.startswith('siblings'):
                try:
                    cpu["threads_per_core"] = int(line.split(':')[1].strip())
                except:
                    pass
        
        cpu["cores_physical"] = len(cores_physical) if cores_physical else 1
        cpu["cores_logical"] = cores_logical
        
        if cpu.get("threads_per_core", 0) == 0 and cpu.get("cores_physical", 0) > 0:
            cpu["threads_per_core"] = cores_logical // cpu["cores_physical"]
        
        # Load average
        loadavg = self.read_file("/proc/loadavg")
        if loadavg:
            parts = loadavg.split()
            try:
                cpu["load_1min"] = float(parts[0])
                cpu["load_5min"] = float(parts[1])
                cpu["load_15min"] = float(parts[2])
                cpu["load_average"] = f"{parts[0]}, {parts[1]}, {parts[2]}"
            except:
                pass
        
        # CPU usage (da /proc/stat)
        stat1 = self.read_file("/proc/stat")
        import time
        time.sleep(0.5)
        stat2 = self.read_file("/proc/stat")
        
        try:
            cpu1 = [int(x) for x in stat1.split('\n')[0].split()[1:]]
            cpu2 = [int(x) for x in stat2.split('\n')[0].split()[1:]]
            
            idle1 = cpu1[3] + cpu1[4]
            idle2 = cpu2[3] + cpu2[4]
            total1 = sum(cpu1)
            total2 = sum(cpu2)
            
            idle_delta = idle2 - idle1
            total_delta = total2 - total1
            
            if total_delta > 0:
                cpu["usage_percent"] = round((1 - idle_delta / total_delta) * 100, 1)
        except:
            pass
        
        # Temperatura (vari sensori possibili)
        temp_paths = [
            "/sys/class/thermal/thermal_zone0/temp",
            "/sys/class/hwmon/hwmon0/temp1_input",
            "/sys/class/hwmon/hwmon1/temp1_input",
        ]
        
        for path in temp_paths:
            temp = self.run_command_output(f"cat {path} 2>/dev/null")
            if temp and temp.isdigit():
                try:
                    cpu["temperature_celsius"] = float(temp) / 1000
                    break
                except:
                    pass
        
        self.result["cpu"] = cpu
    
    def collect_memory_info(self):
        """Raccoglie info memoria"""
        self.log("Raccolta info memoria...", "debug")
        
        mem = {}
        
        meminfo = self.read_file("/proc/meminfo")
        
        for line in meminfo.split('\n'):
            parts = line.split()
            if len(parts) < 2:
                continue
            
            key = parts[0].rstrip(':')
            try:
                value = int(parts[1]) * 1024  # KB to bytes
            except:
                continue
            
            if key == 'MemTotal':
                mem["total_bytes"] = value
                mem["total_gb"] = round(value / (1024**3), 2)
            elif key == 'MemFree':
                mem["free_bytes"] = value
            elif key == 'MemAvailable':
                mem["available_bytes"] = value
            elif key == 'Buffers':
                mem["buffers_bytes"] = value
            elif key == 'Cached':
                mem["cached_bytes"] = value
            elif key == 'SwapTotal':
                mem["swap_total_bytes"] = value
            elif key == 'SwapFree':
                mem["swap_free_bytes"] = value
        
        mem["used_bytes"] = mem.get("total_bytes", 0) - mem.get("available_bytes", 0)
        mem["swap_used_bytes"] = mem.get("swap_total_bytes", 0) - mem.get("swap_free_bytes", 0)
        
        if mem.get("total_bytes", 0) > 0:
            mem["usage_percent"] = round((mem["used_bytes"] / mem["total_bytes"]) * 100, 1)
        
        if mem.get("swap_total_bytes", 0) > 0:
            mem["swap_usage_percent"] = round((mem["swap_used_bytes"] / mem["swap_total_bytes"]) * 100, 1)
        
        self.result["memory"] = mem
    
    def collect_disk_info(self):
        """Raccoglie info dischi fisici"""
        self.log("Raccolta info dischi...", "debug")
        
        disks = []
        
        # Lista block devices
        lsblk = self.run_command_output(
            "lsblk -d -b -o NAME,SIZE,TYPE,MODEL,SERIAL,ROTA,TRAN -n 2>/dev/null"
        )
        
        for line in lsblk.split('\n'):
            if not line.strip():
                continue
            
            parts = line.split(None, 6)
            if len(parts) < 3:
                continue
            
            name = parts[0]
            if parts[2] != 'disk':
                continue
            
            disk = {}
            disk["device"] = f"/dev/{name}"
            
            try:
                disk["size_bytes"] = int(parts[1])
                disk["size_gb"] = round(disk["size_bytes"] / (1024**3), 2)
            except:
                pass
            
            if len(parts) > 3:
                disk["model"] = parts[3] if parts[3] != '' else ""
            if len(parts) > 4:
                disk["serial"] = parts[4] if parts[4] != '' else ""
            if len(parts) > 5:
                disk["rotation_rpm"] = 0 if parts[5] == '0' else 7200
                disk["type"] = "SSD" if parts[5] == '0' else "HDD"
            if len(parts) > 6:
                disk["interface"] = parts[6].upper() if parts[6] else ""
            
            # NVMe detection
            if 'nvme' in name:
                disk["type"] = "NVMe"
                disk["interface"] = "NVMe"
            
            # SMART status (richiede sudo)
            smart = self.run_command_output(
                f"smartctl -H {disk['device']} 2>/dev/null | grep -i 'SMART overall-health'",
                sudo=True
            )
            if 'PASSED' in smart:
                disk["smart_status"] = "PASSED"
                disk["health_status"] = "OK"
            elif 'FAILED' in smart:
                disk["smart_status"] = "FAILED"
                disk["health_status"] = "CRITICAL"
            
            # Temperatura disco
            temp = self.run_command_output(
                f"smartctl -A {disk['device']} 2>/dev/null | grep -i temperature | head -1",
                sudo=True
            )
            if temp:
                match = re.search(r'(\d+)\s*(?:Celsius)?$', temp)
                if match:
                    try:
                        disk["temperature_celsius"] = float(match.group(1))
                    except:
                        pass
            
            disks.append(disk)
        
        self.result["disks"] = disks
    
    def collect_volume_info(self):
        """Raccoglie info volumi/filesystem"""
        self.log("Raccolta info volumi...", "debug")
        
        volumes = []
        
        df_output = self.run_command_output(
            "df -B1 -T --output=source,fstype,size,used,avail,pcent,target 2>/dev/null"
        )
        
        for line in df_output.split('\n')[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) < 7:
                continue
            
            device = parts[0]
            
            # Salta filesystem virtuali
            if device in ('tmpfs', 'devtmpfs', 'overlay', 'shm', 'udev', 'none'):
                continue
            if device.startswith('/dev/loop'):
                continue
            
            vol = {}
            vol["device"] = device
            vol["filesystem"] = parts[1]
            vol["mount_point"] = parts[6]
            
            try:
                vol["total_bytes"] = int(parts[2])
                vol["used_bytes"] = int(parts[3])
                vol["available_bytes"] = int(parts[4])
                vol["usage_percent"] = float(parts[5].rstrip('%'))
                vol["total_gb"] = round(vol["total_bytes"] / (1024**3), 2)
                vol["used_gb"] = round(vol["used_bytes"] / (1024**3), 2)
                vol["available_gb"] = round(vol["available_bytes"] / (1024**3), 2)
            except:
                pass
            
            volumes.append(vol)
        
        self.result["volumes"] = volumes
    
    def collect_raid_info(self):
        """Raccoglie info RAID (mdadm)"""
        self.log("Raccolta info RAID...", "debug")
        
        raid_arrays = []
        
        # Check mdstat
        mdstat = self.read_file("/proc/mdstat")
        if not mdstat or 'Personalities' not in mdstat:
            self.result["raid_arrays"] = []
            return
        
        current_raid = None
        
        for line in mdstat.split('\n'):
            # Nuova riga md
            md_match = re.match(r'^(md\d+)\s*:\s*(\w+)\s+(\w+)\s+(.+)', line)
            if md_match:
                if current_raid:
                    raid_arrays.append(current_raid)
                
                current_raid = {}
                current_raid["name"] = f"/dev/{md_match.group(1)}"
                current_raid["status"] = md_match.group(2)  # active, inactive
                current_raid["level"] = md_match.group(3).upper()  # raid1, raid5, etc
                current_raid["devices"] = []
            
            # Parse devices
            elif current_raid and 'blocks' in line:
                # Cerca dimensione
                size_match = re.search(r'(\d+)\s*blocks', line)
                if size_match:
                    current_raid["size_bytes"] = int(size_match.group(1)) * 512
                    current_raid["size_gb"] = round(current_raid["size_bytes"] / (1024**3), 2)
                
                # Chunk size
                chunk_match = re.search(r'(\d+k)\s*chunk', line)
                if chunk_match:
                    current_raid["chunk_size"] = chunk_match.group(1)
                
                # Stato devices [UU] o [U_]
                state_match = re.search(r'\[([U_]+)\]', line)
                if state_match:
                    state = state_match.group(1)
                    current_raid["active_devices"] = state.count('U')
                    current_raid["failed_devices"] = state.count('_')
                    current_raid["total_devices"] = len(state)
                    
                    if '_' in state:
                        current_raid["status"] = "degraded"
                    else:
                        current_raid["status"] = "clean"
            
            # Rebuild progress
            elif current_raid and 'recovery' in line.lower():
                prog_match = re.search(r'(\d+\.\d+%)', line)
                if prog_match:
                    current_raid["rebuild_progress"] = prog_match.group(1)
                    current_raid["status"] = "rebuilding"
        
        if current_raid:
            raid_arrays.append(current_raid)
        
        self.result["raid_arrays"] = raid_arrays
    
    def collect_network_info(self):
        """Raccoglie info rete"""
        self.log("Raccolta info rete...", "debug")
        
        interfaces = {}
        
        # Lista interfacce
        ip_link = self.run_command_output("ip -o link show")
        
        # Parse link info
        for line in ip_link.split('\n'):
            if not line.strip():
                continue
            
            match = re.match(r'\d+:\s+(\S+?)(?:@\S+)?:\s+<(.*)>\s+mtu\s+(\d+)', line)
            if match:
                name = match.group(1)
                flags = match.group(2)
                
                iface = {}
                iface["name"] = name
                iface["mtu"] = int(match.group(3))
                iface["state"] = "up" if "UP" in flags else "down"
                iface["is_virtual"] = name.startswith(('lo', 'veth', 'docker', 'br-', 'virbr'))
                iface["ipv4_addresses"] = []
                iface["ipv6_addresses"] = []
                
                # MAC address
                mac_match = re.search(r'link/\w+\s+([0-9a-f:]{17})', line)
                if mac_match:
                    iface["mac_address"] = mac_match.group(1).upper()
                
                interfaces[name] = iface
        
        # Parse addresses
        ip_addr = self.run_command_output("ip -o addr show")
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
                    iface["ipv4_addresses"].append(ip_match.group(1))
            
            elif 'inet6 ' in line:
                ip6_match = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line)
                if ip6_match:
                    addr = ip6_match.group(1)
                    if not addr.startswith('fe80'):  # Skip link-local
                        iface["ipv6_addresses"].append(addr)
        
        # Default gateway
        route = self.run_command_output("ip route show default")
        gw_match = re.search(r'default via ([0-9.]+)', route)
        if gw_match:
            self.result["default_gateway"] = gw_match.group(1)
        
        # DNS
        resolv = self.read_file("/etc/resolv.conf")
        dns_servers = []
        for line in resolv.split('\n'):
            if line.startswith('nameserver'):
                dns_servers.append(line.split()[1])
        if dns_servers:
            self.result["dns_servers"] = dns_servers
        
        self.result["network_interfaces"] = list(interfaces.values())
    
    def collect_services(self):
        """Raccoglie info servizi (systemd)"""
        self.log("Raccolta info servizi...", "debug")
        
        services = []
        
        # Solo servizi principali
        important_services = [
            'ssh', 'sshd', 'nginx', 'apache2', 'httpd', 'mysql', 'mariadb',
            'postgresql', 'docker', 'containerd', 'nfs-server', 'smbd',
            'postfix', 'dovecot', 'named', 'bind9', 'cron', 'rsyslog',
            'fail2ban', 'ufw', 'firewalld', 'zabbix-agent', 'node_exporter'
        ]
        
        for svc_name in important_services:
            status = self.run_command_output(
                f"systemctl is-active {svc_name} 2>/dev/null"
            )
            
            if status in ('active', 'inactive', 'failed'):
                svc = {}
                svc["name"] = svc_name
                svc["status"] = status
                
                enabled = self.run_command_output(
                    f"systemctl is-enabled {svc_name} 2>/dev/null"
                )
                svc["enabled"] = enabled == 'enabled'
                
                if status == 'active':
                    # PID e memoria
                    show = self.run_command_output(
                        f"systemctl show {svc_name} --property=MainPID,MemoryCurrent 2>/dev/null"
                    )
                    for line in show.split('\n'):
                        if line.startswith('MainPID='):
                            try:
                                svc["pid"] = int(line.split('=')[1])
                            except:
                                pass
                        elif line.startswith('MemoryCurrent='):
                            try:
                                svc["memory_bytes"] = int(line.split('=')[1])
                            except:
                                pass
                
                services.append(svc)
        
        self.result["services"] = services
    
    def collect_docker_info(self):
        """Raccoglie info Docker"""
        self.log("Raccolta info Docker...", "debug")
        
        # Verifica Docker installato
        version = self.run_command_output("docker --version 2>/dev/null")
        if not version:
            return
        
        docker = {}
        
        # Versione
        match = re.search(r'(\d+\.\d+\.\d+)', version)
        if match:
            docker["version"] = match.group(1)
        
        # Stats containers
        containers_running = self.run_command_output("docker ps -q 2>/dev/null | wc -l")
        containers_stopped = self.run_command_output("docker ps -aq --filter 'status=exited' 2>/dev/null | wc -l")
        containers_total = self.run_command_output("docker ps -aq 2>/dev/null | wc -l")
        images_count = self.run_command_output("docker images -q 2>/dev/null | wc -l")
        
        try:
            docker["containers_running"] = int(containers_running.strip()) if containers_running.strip().isdigit() else 0
            docker["containers_stopped"] = int(containers_stopped.strip()) if containers_stopped.strip().isdigit() else 0
            docker["containers_total"] = int(containers_total.strip()) if containers_total.strip().isdigit() else 0
            docker["images_count"] = int(images_count.strip()) if images_count.strip().isdigit() else 0
        except:
            pass
        
        self.result["docker"] = docker
    
    def collect_vms(self):
        """Raccoglie lista VM/container (Proxmox)"""
        if self.system_type != SystemType.LINUX_PROXMOX:
            return
        
        self.log("Raccolta VM/Container...", "debug")
        
        vms = []
        
        # QEMU VMs
        qm_list = self.run_command_output("qm list 2>/dev/null")
        for line in qm_list.split('\n')[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                vm = {}
                vm["vmid"] = parts[0]
                vm["name"] = parts[1]
                vm["status"] = parts[2].lower()
                vm["type"] = "qemu"
                
                if len(parts) >= 4:
                    try:
                        vm["memory_bytes"] = int(parts[3]) * 1024 * 1024
                    except:
                        pass
                
                vms.append(vm)
        
        # LXC containers
        pct_list = self.run_command_output("pct list 2>/dev/null")
        for line in pct_list.split('\n')[1:]:
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 3:
                vm = {}
                vm["vmid"] = parts[0]
                vm["status"] = parts[1].lower()
                vm["name"] = parts[2] if len(parts) > 2 else ""
                vm["type"] = "lxc"
                vms.append(vm)
        
        self.result["vms"] = vms
    
    def collect_all(self):
        """Raccoglie tutti i dati disponibili"""
        if not self.client:
            return
        
        self.system_type = self.detect_system()
        
        # Dati base sempre disponibili
        self.collect_system_info()
        self.collect_cpu_info()
        self.collect_memory_info()
        self.collect_disk_info()
        self.collect_volume_info()
        self.collect_raid_info()
        self.collect_network_info()
        self.collect_services()
        self.collect_docker_info()
        
        # Dati specifici per tipo
        if self.system_type == SystemType.LINUX_PROXMOX:
            self.collect_vms()
        
        # NAS-specific (Synology/QNAP) - da implementare se necessario
        # self.collect_nas_info()
        
        # IMPORTANTE: Estrai anche dati base per compatibilità con sistema esistente
        # Metti i dati base direttamente nel risultato (non solo negli oggetti annidati)
        if self.result.get("system_info"):
            si = self.result["system_info"]
            if isinstance(si, dict):
                if si.get("hostname") and not self.result.get("hostname"):
                    self.result["hostname"] = si.get("hostname")
                if si.get("os_name") and not self.result.get("os_name"):
                    self.result["os_name"] = si.get("os_name")
                if si.get("os_version") and not self.result.get("os_version"):
                    self.result["os_version"] = si.get("os_version")
                if si.get("kernel_version") and not self.result.get("kernel"):
                    self.result["kernel"] = si.get("kernel_version")
                if si.get("architecture") and not self.result.get("architecture"):
                    self.result["architecture"] = si.get("architecture")
                if si.get("system_type"):
                    sys_type = si.get("system_type", "").lower()
                    if sys_type in ["synology", "qnap"]:
                        self.result["device_type"] = "storage"
                    elif sys_type == "proxmox":
                        self.result["device_type"] = "hypervisor"
                    elif not self.result.get("device_type"):
                        self.result["device_type"] = "linux"
        
        if self.result.get("cpu"):
            cpu = self.result["cpu"]
            if isinstance(cpu, dict):
                if cpu.get("model") and not self.result.get("cpu_model"):
                    self.result["cpu_model"] = cpu.get("model")
                if cpu.get("cores_physical") and not self.result.get("cpu_cores"):
                    self.result["cpu_cores"] = cpu.get("cores_physical")
                if cpu.get("cores_logical") and not self.result.get("cpu_threads"):
                    self.result["cpu_threads"] = cpu.get("cores_logical")
        
        if self.result.get("memory"):
            mem = self.result["memory"]
            if isinstance(mem, dict):
                if mem.get("total_gb") and not self.result.get("ram_total_mb"):
                    self.result["ram_total_mb"] = int(mem.get("total_gb") * 1024)
                elif mem.get("total_bytes") and not self.result.get("ram_total_mb"):
                    self.result["ram_total_mb"] = int(mem.get("total_bytes") / (1024 * 1024))
        
        if self.result.get("docker"):
            docker = self.result["docker"]
            if isinstance(docker, dict):
                if docker.get("version") and not self.result.get("docker_version"):
                    self.result["docker_version"] = docker.get("version")
                if docker.get("containers_running") is not None:
                    self.result["docker_installed"] = True
                    if not self.result.get("docker_containers_running"):
                        self.result["docker_containers_running"] = docker.get("containers_running")
    
    def scan(self) -> Dict[str, Any]:
        """Esegue la scansione completa"""
        if not self.connect():
            return self.result
        
        try:
            self.collect_all()
        finally:
            self.disconnect()
        
        return self.result


async def scan_advanced(
    target: str,
    username: str,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    port: int = 22,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Esegue scansione SSH avanzata su un target Linux/Storage/Hypervisor.
    
    Returns:
        Dict con informazioni complete del sistema
    """
    loop = asyncio.get_event_loop()
    
    def _scan():
        scanner = SSHAdvancedScanner(
            host=target,
            username=username,
            password=password,
            private_key=private_key,
            port=port,
            timeout=timeout
        )
        return scanner.scan()
    
    return await loop.run_in_executor(_executor, _scan)

