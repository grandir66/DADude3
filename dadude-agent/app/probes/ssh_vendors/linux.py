"""
DaDude Agent - Linux Generic SSH Probe
Scansione server Linux generici via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class LinuxProbe(SSHVendorProbe):
    """Probe per Linux generico"""
    
    VENDOR_NAME = "Linux"
    DETECTION_PRIORITY = 100  # Bassa priorità - fallback
    
    def detect(self) -> bool:
        """Linux è il fallback, accetta tutto"""
        uname = self.exec_cmd("uname -s 2>/dev/null", timeout=3)
        return bool(uname and 'linux' in uname.lower())
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Linux"""
        self._log_info(f"Probing Linux server at {target}")
        
        info = {
            "device_type": "server",
            "category": "compute",
            "os_family": "Linux",
        }
        
        # Base system info
        info.update(self._get_system_info())
        
        # Hardware info
        hw = self._get_hardware_info()
        if hw:
            info.update(hw)
        
        # Network interfaces
        interfaces = self._get_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
        
        # Disks
        disks = self._get_disks()
        if disks:
            info["disks"] = disks
            info["disks_count"] = len(disks)
        
        # Filesystems
        filesystems = self._get_filesystems()
        if filesystems:
            info["volumes"] = filesystems
            info["volumes_count"] = len(filesystems)
        
        # Services
        services = self._get_services()
        if services:
            info["services"] = services
            info["services_count"] = len(services)
        
        # Listening ports
        ports = self._get_listening_ports()
        if ports:
            info["listening_ports"] = ports
        
        # Users
        users = self._get_users()
        if users:
            info["users"] = users
            info["users_count"] = len(users)
        
        self._log_info(f"Linux probe complete: hostname={info.get('hostname')}, distro={info.get('os_name')}")
        return info
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Ottiene informazioni di sistema base"""
        info = {}
        
        # Hostname
        hostname = self.exec_cmd("hostname", timeout=3)
        if hostname:
            info["hostname"] = hostname.strip()
        
        # OS/Distro
        os_release = self.exec_cmd("cat /etc/os-release 2>/dev/null", timeout=3)
        if os_release:
            for line in os_release.split('\n'):
                if line.startswith('NAME='):
                    info["os_name"] = line.split('=')[1].strip().strip('"')
                elif line.startswith('VERSION='):
                    info["os_version"] = line.split('=')[1].strip().strip('"')
                elif line.startswith('ID='):
                    info["os_id"] = line.split('=')[1].strip().strip('"')
                elif line.startswith('PRETTY_NAME='):
                    info["os_pretty_name"] = line.split('=')[1].strip().strip('"')
        
        # Fallback distro detection
        if not info.get("os_name"):
            lsb = self.exec_cmd("lsb_release -d 2>/dev/null", timeout=3)
            if lsb:
                info["os_name"] = lsb.split(':')[-1].strip()
        
        # Kernel
        kernel = self.exec_cmd("uname -r", timeout=3)
        if kernel:
            info["kernel_version"] = kernel.strip()
        
        # Architecture
        arch = self.exec_cmd("uname -m", timeout=3)
        if arch:
            info["architecture"] = arch.strip()
        
        # Uptime
        uptime = self.exec_cmd("uptime -p 2>/dev/null || uptime", timeout=3)
        if uptime:
            info["uptime"] = uptime.strip()
        
        # Load average
        load = self.exec_cmd("cat /proc/loadavg 2>/dev/null", timeout=3)
        if load:
            parts = load.split()
            if len(parts) >= 3:
                info["load_average"] = f"{parts[0]}, {parts[1]}, {parts[2]}"
        
        return info
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Ottiene informazioni hardware"""
        info = {}
        
        # CPU
        cpu = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1", timeout=3)
        if cpu:
            info["cpu_model"] = cpu.split(':')[-1].strip()
        
        cpu_cores = self.exec_cmd("nproc 2>/dev/null || grep -c processor /proc/cpuinfo", timeout=3)
        if cpu_cores and cpu_cores.strip().isdigit():
            info["cpu_cores"] = int(cpu_cores.strip())
        
        # RAM
        mem = self.exec_cmd("cat /proc/meminfo 2>/dev/null | grep MemTotal", timeout=3)
        if mem:
            try:
                info["ram_total_mb"] = int(mem.split()[1]) // 1024
            except:
                pass
        
        mem_free = self.exec_cmd("cat /proc/meminfo 2>/dev/null | grep MemAvailable", timeout=3)
        if mem_free:
            try:
                info["ram_free_mb"] = int(mem_free.split()[1]) // 1024
            except:
                pass
        
        # DMI info (richiede root)
        manufacturer = self.exec_cmd_sudo("dmidecode -s system-manufacturer 2>/dev/null", timeout=5)
        if manufacturer:
            info["manufacturer"] = manufacturer.strip()
        
        product = self.exec_cmd_sudo("dmidecode -s system-product-name 2>/dev/null", timeout=5)
        if product:
            info["model"] = product.strip()
        
        serial = self.exec_cmd_sudo("dmidecode -s system-serial-number 2>/dev/null", timeout=5)
        if serial:
            info["serial_number"] = serial.strip()
        
        # Virtualization
        virt = self.exec_cmd("systemd-detect-virt 2>/dev/null || cat /sys/class/dmi/id/product_name 2>/dev/null", timeout=3)
        if virt:
            virt = virt.strip().lower()
            if virt != 'none' and virt:
                info["virtualization"] = virt
                if any(v in virt for v in ['vmware', 'virtualbox', 'kvm', 'xen', 'hyperv', 'docker', 'lxc']):
                    info["is_virtual"] = True
        
        return info
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce di rete"""
        interfaces = []
        
        # Usa ip addr (preferito) o ifconfig
        output = self.exec_cmd("ip addr 2>/dev/null || ifconfig -a 2>/dev/null", timeout=5)
        if not output:
            return []
        
        current = {}
        for line in output.split('\n'):
            # Nuova interfaccia (ip addr)
            if line and not line.startswith(' ') and ':' in line:
                if current and current.get("name"):
                    interfaces.append(current)
                parts = line.split(':')
                if len(parts) >= 2:
                    name = parts[1].strip().split()[0]
                    current = {"name": name}
                    # Check state
                    if 'state UP' in line:
                        current["status"] = "up"
                    elif 'state DOWN' in line:
                        current["status"] = "down"
            # IPv4
            elif 'inet ' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        ip_mask = parts[i + 1]
                        current["ipv4"] = ip_mask.split('/')[0]
                        if '/' in ip_mask:
                            current["prefix"] = ip_mask.split('/')[1]
            # IPv6
            elif 'inet6 ' in line and current and 'fe80' not in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet6' and i + 1 < len(parts):
                        current["ipv6"] = parts[i + 1].split('/')[0]
            # MAC
            elif 'link/ether' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'link/ether' and i + 1 < len(parts):
                        current["mac_address"] = parts[i + 1]
        
        if current and current.get("name"):
            interfaces.append(current)
        
        # Filtra loopback e virtual
        return [i for i in interfaces if not i["name"].startswith("lo") and not i["name"].startswith("virbr")]
    
    def _get_disks(self) -> List[Dict[str, Any]]:
        """Ottiene informazioni dischi"""
        disks = []
        
        lsblk = self.exec_cmd("lsblk -d -o NAME,SIZE,TYPE,MODEL 2>/dev/null | tail -n +2", timeout=5)
        if lsblk:
            for line in lsblk.split('\n'):
                if line.strip():
                    parts = line.split()
                    if parts and parts[0] and not parts[0].startswith('loop'):
                        disk = {
                            "name": parts[0],
                            "size": parts[1] if len(parts) > 1 else "",
                            "type": parts[2] if len(parts) > 2 else "",
                            "model": ' '.join(parts[3:]) if len(parts) > 3 else "",
                        }
                        disks.append(disk)
        
        return disks
    
    def _get_filesystems(self) -> List[Dict[str, Any]]:
        """Ottiene informazioni filesystem montati"""
        filesystems = []
        
        df = self.exec_cmd("df -h -T 2>/dev/null | grep -v tmpfs | grep -v devtmpfs | tail -n +2", timeout=5)
        if df:
            for line in df.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 7:
                        fs = {
                            "device": parts[0],
                            "type": parts[1],
                            "size": parts[2],
                            "used": parts[3],
                            "available": parts[4],
                            "use_percent": parts[5],
                            "mount_point": parts[6],
                        }
                        filesystems.append(fs)
        
        return filesystems
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi attivi"""
        services = []
        
        # Systemd
        systemctl = self.exec_cmd("systemctl list-units --type=service --state=running 2>/dev/null | head -30", timeout=5)
        if systemctl and 'LOAD' in systemctl:
            for line in systemctl.split('\n'):
                if '.service' in line and 'loaded' in line.lower():
                    parts = line.split()
                    if parts:
                        name = parts[0].replace('.service', '')
                        services.append({
                            "name": name,
                            "status": "running",
                        })
        else:
            # Fallback: check common services
            common = ['sshd', 'nginx', 'apache2', 'httpd', 'mysql', 'mariadb', 'postgresql', 'docker', 'redis']
            for svc in common:
                status = self.exec_cmd(f"pgrep -x {svc} >/dev/null 2>&1 && echo 'running' || echo 'stopped'", timeout=2)
                if status and status.strip() == 'running':
                    services.append({"name": svc, "status": "running"})
        
        return services
    
    def _get_listening_ports(self) -> List[Dict[str, Any]]:
        """Ottiene porte in ascolto"""
        ports = []
        
        ss = self.exec_cmd("ss -tlnp 2>/dev/null | tail -n +2 | head -30", timeout=5)
        if ss:
            for line in ss.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        listen_addr = parts[3]
                        if ':' in listen_addr:
                            port = listen_addr.rsplit(':', 1)[-1]
                            ports.append({
                                "port": port,
                                "address": listen_addr,
                                "state": parts[0] if parts else "",
                            })
        
        return ports
    
    def _get_users(self) -> List[Dict[str, Any]]:
        """Ottiene utenti con shell"""
        users = []
        
        passwd = self.exec_cmd("cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v /bin/false", timeout=3)
        if passwd:
            for line in passwd.split('\n'):
                if line.strip() and ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 6:
                        uid = int(parts[2]) if parts[2].isdigit() else 0
                        # Solo utenti "reali" (UID >= 1000 o root)
                        if uid >= 1000 or parts[0] == 'root':
                            users.append({
                                "username": parts[0],
                                "uid": uid,
                                "gid": int(parts[3]) if parts[3].isdigit() else 0,
                                "home": parts[5],
                                "shell": parts[6] if len(parts) > 6 else "",
                            })
        
        return users
