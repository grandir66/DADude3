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
        
        # Installed services (all services, not just running)
        installed_services = self._get_installed_services()
        if installed_services:
            info["installed_services"] = installed_services
            info["installed_services_count"] = len(installed_services)
        
        # Detailed storage (partitions, RAID, LVM)
        detailed_storage = self._get_detailed_storage()
        if detailed_storage:
            info.update(detailed_storage)
        
        # Cron jobs
        cron_jobs = self._get_cron_jobs()
        if cron_jobs:
            info["cron_jobs"] = cron_jobs
            info["cron_jobs_count"] = len(cron_jobs)
        
        # Installed software
        software = self._get_installed_software()
        if software:
            info["installed_software"] = software
            info["installed_software_count"] = len(software)
        
        # Running processes (top)
        processes = self._get_running_processes()
        if processes:
            info["running_processes"] = processes
        
        # Network configuration
        network_config = self._get_network_config()
        if network_config:
            info.update(network_config)
        
        # System details (timezone, locale, etc)
        system_details = self._get_system_details()
        if system_details:
            info.update(system_details)
        
        # Firewall info
        firewall_info = self._get_firewall_info()
        if firewall_info:
            info.update(firewall_info)
        
        # Databases
        databases = self._get_databases()
        if databases:
            info["databases"] = databases
        
        # Web servers
        web_servers = self._get_web_servers()
        if web_servers:
            info["web_servers"] = web_servers
        
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
    
    def _get_installed_services(self) -> List[Dict[str, Any]]:
        """Ottiene tutti i servizi installati (non solo attivi)"""
        services = []
        
        # Systemd: tutti i servizi installati
        systemctl_all = self.exec_cmd("systemctl list-unit-files --type=service --no-pager 2>/dev/null | tail -n +2", timeout=10)
        if systemctl_all:
            for line in systemctl_all.split('\n'):
                if line.strip() and '.service' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0].replace('.service', '')
                        state = parts[1] if len(parts) > 1 else "unknown"
                        services.append({
                            "name": name,
                            "status": state,
                            "type": "systemd"
                        })
        
        # SysV init: servizi in /etc/init.d
        initd_services = self.exec_cmd("ls /etc/init.d/ 2>/dev/null", timeout=5)
        if initd_services:
            for svc in initd_services.split('\n'):
                if svc.strip() and not svc.startswith('.'):
                    # Verifica se già presente (potrebbe essere anche systemd)
                    if not any(s["name"] == svc.strip() for s in services):
                        services.append({
                            "name": svc.strip(),
                            "status": "unknown",
                            "type": "sysv"
                        })
        
        return services[:500]  # Limita a 500 per evitare output troppo grande
    
    def _get_detailed_storage(self) -> Dict[str, Any]:
        """Ottiene informazioni storage dettagliate"""
        storage_info = {}
        
        # Partizioni
        partitions = []
        fdisk = self.exec_cmd_sudo("fdisk -l 2>/dev/null | grep -E '^/dev/' | head -50", timeout=10)
        if fdisk:
            for line in fdisk.split('\n'):
                if line.strip() and '/dev/' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        partitions.append({
                            "device": parts[0],
                            "size": parts[1] if len(parts) > 1 else "",
                            "type": parts[2] if len(parts) > 2 else "",
                        })
        
        if partitions:
            storage_info["partitions"] = partitions
        
        # /etc/fstab mount points
        fstab = self.exec_cmd("cat /etc/fstab 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
        fstab_entries = []
        if fstab:
            for line in fstab.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        fstab_entries.append({
                            "device": parts[0],
                            "mount_point": parts[1],
                            "filesystem": parts[2] if len(parts) > 2 else "",
                            "options": parts[3] if len(parts) > 3 else "",
                        })
        
        if fstab_entries:
            storage_info["fstab_entries"] = fstab_entries
        
        # RAID arrays
        mdstat = self.exec_cmd("cat /proc/mdstat 2>/dev/null", timeout=3)
        raid_arrays = []
        if mdstat and 'md' in mdstat:
            current_array = {}
            for line in mdstat.split('\n'):
                if line.startswith('md'):
                    if current_array:
                        raid_arrays.append(current_array)
                    parts = line.split()
                    current_array = {
                        "name": parts[0],
                        "level": parts[3] if len(parts) > 3 else "",
                        "devices": parts[4:] if len(parts) > 4 else [],
                    }
                elif 'blocks' in line and current_array:
                    parts = line.split()
                    if len(parts) >= 2:
                        current_array["size"] = parts[0] + " " + parts[1]
            if current_array:
                raid_arrays.append(current_array)
        
        if raid_arrays:
            storage_info["raid_arrays"] = raid_arrays
        
        # LVM volumes
        lvs = self.exec_cmd_sudo("lvs --noheadings --units g -o lv_name,vg_name,lv_size 2>/dev/null", timeout=5)
        lvm_volumes = []
        if lvs:
            for line in lvs.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        lvm_volumes.append({
                            "name": parts[0],
                            "vg": parts[1],
                            "size": parts[2],
                        })
        
        if lvm_volumes:
            storage_info["lvm_volumes"] = lvm_volumes
        
        # Volume groups
        vgs = self.exec_cmd_sudo("vgs --noheadings --units g -o vg_name,vg_size,vg_free 2>/dev/null", timeout=5)
        volume_groups = []
        if vgs:
            for line in vgs.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        volume_groups.append({
                            "name": parts[0],
                            "size": parts[1],
                            "free": parts[2],
                        })
        
        if volume_groups:
            storage_info["volume_groups"] = volume_groups
        
        # Disk usage per directory principali
        du_root = self.exec_cmd_sudo("du -sh /home /var /usr /opt /tmp 2>/dev/null | head -10", timeout=5)
        disk_usage = {}
        if du_root:
            for line in du_root.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        disk_usage[parts[1]] = parts[0]
        
        if disk_usage:
            storage_info["disk_usage"] = disk_usage
        
        # Inode usage
        df_i = self.exec_cmd("df -i 2>/dev/null | tail -n +2", timeout=5)
        inode_usage = []
        if df_i:
            for line in df_i.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        inode_usage.append({
                            "filesystem": parts[0],
                            "inodes": parts[1],
                            "iused": parts[2],
                            "ifree": parts[3],
                            "iused_percent": parts[4],
                            "mount_point": parts[5],
                        })
        
        if inode_usage:
            storage_info["inode_usage"] = inode_usage
        
        # Swap usage
        swap = self.exec_cmd("swapon --show 2>/dev/null", timeout=3)
        swap_info = []
        if swap and 'NAME' in swap:
            for line in swap.split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        swap_info.append({
                            "name": parts[0],
                            "type": parts[1],
                            "size": parts[2],
                            "used": parts[3] if len(parts) > 3 else "",
                            "priority": parts[4] if len(parts) > 4 else "",
                        })
        
        if swap_info:
            storage_info["swap"] = swap_info
        
        return storage_info
    
    def _get_cron_jobs(self) -> List[Dict[str, Any]]:
        """Ottiene cron jobs (utente e sistema)"""
        cron_jobs = []
        
        # Cron sistema: /etc/crontab
        crontab_system = self.exec_cmd("cat /etc/crontab 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
        if crontab_system:
            for line in crontab_system.split('\n'):
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 6:
                        cron_jobs.append({
                            "user": parts[5] if len(parts) > 5 else "root",
                            "schedule": ' '.join(parts[0:5]),
                            "command": ' '.join(parts[6:]) if len(parts) > 6 else "",
                            "type": "system"
                        })
        
        # Cron.d directory
        cron_d = self.exec_cmd("ls /etc/cron.d/ 2>/dev/null", timeout=3)
        if cron_d:
            for file in cron_d.split('\n'):
                if file.strip():
                    file_content = self.exec_cmd(f"cat /etc/cron.d/{file.strip()} 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
                    if file_content:
                        for line in file_content.split('\n'):
                            if line.strip() and not line.startswith('#'):
                                parts = line.split()
                                if len(parts) >= 6:
                                    cron_jobs.append({
                                        "user": parts[5] if len(parts) > 5 else "root",
                                        "schedule": ' '.join(parts[0:5]),
                                        "command": ' '.join(parts[6:]) if len(parts) > 6 else "",
                                        "type": "cron.d",
                                        "file": file.strip()
                                    })
        
        # Anacron
        anacrontab = self.exec_cmd("cat /etc/anacrontab 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
        if anacrontab:
            for line in anacrontab.split('\n'):
                if line.strip() and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 4:
                        cron_jobs.append({
                            "name": parts[0],
                            "delay": parts[1],
                            "schedule": parts[2],
                            "command": ' '.join(parts[3:]) if len(parts) > 3 else "",
                            "type": "anacron"
                        })
        
        # Cron utenti (solo utenti con shell)
        users_with_shell = self.exec_cmd("cat /etc/passwd 2>/dev/null | grep -v nologin | grep -v /bin/false | cut -d: -f1", timeout=3)
        if users_with_shell:
            for user in users_with_shell.split('\n'):
                user = user.strip()
                if user:
                    user_cron = self.exec_cmd(f"crontab -l -u {user} 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
                    if user_cron:
                        for line in user_cron.split('\n'):
                            if line.strip() and not line.startswith('#'):
                                parts = line.split()
                                if len(parts) >= 6:
                                    cron_jobs.append({
                                        "user": user,
                                        "schedule": ' '.join(parts[0:5]),
                                        "command": ' '.join(parts[5:]),
                                        "type": "user"
                                    })
        
        return cron_jobs
    
    def _get_installed_software(self) -> List[Dict[str, Any]]:
        """Ottiene software installato (dpkg/rpm)"""
        software = []
        
        # Debian/Ubuntu: dpkg
        dpkg_list = self.exec_cmd("dpkg -l 2>/dev/null | tail -n +6 | head -500", timeout=15)
        if dpkg_list:
            for line in dpkg_list.split('\n'):
                if line.strip() and line[0] in 'iihr':
                    parts = line.split()
                    if len(parts) >= 3:
                        software.append({
                            "name": parts[1],
                            "version": parts[2],
                            "status": parts[0],
                            "type": "dpkg"
                        })
        else:
            # RedHat/CentOS: rpm
            rpm_list = self.exec_cmd("rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\n' 2>/dev/null | head -500", timeout=15)
            if rpm_list:
                for line in rpm_list.split('\n'):
                    if line.strip():
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            software.append({
                                "name": parts[0],
                                "version": parts[1] + "-" + parts[2] if len(parts) > 2 else parts[1],
                                "type": "rpm"
                            })
            else:
                # Arch: pacman
                pacman_list = self.exec_cmd("pacman -Q 2>/dev/null | head -500", timeout=15)
                if pacman_list:
                    for line in pacman_list.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                software.append({
                                    "name": parts[0],
                                    "version": parts[1],
                                    "type": "pacman"
                                })
        
        return software
    
    def _get_running_processes(self) -> List[Dict[str, Any]]:
        """Ottiene top processi per CPU/RAM"""
        processes = []
        
        # Top 20 processi per CPU
        ps_cpu = self.exec_cmd("ps aux --sort=-%cpu --no-headers 2>/dev/null | head -20", timeout=5)
        if ps_cpu:
            for line in ps_cpu.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            "user": parts[0],
                            "pid": parts[1],
                            "cpu_percent": parts[2],
                            "mem_percent": parts[3],
                            "command": ' '.join(parts[10:]),
                            "sort_by": "cpu"
                        })
        
        # Top 20 processi per RAM
        ps_mem = self.exec_cmd("ps aux --sort=-%mem --no-headers 2>/dev/null | head -20", timeout=5)
        if ps_mem:
            for line in ps_mem.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        # Evita duplicati
                        pid = parts[1]
                        if not any(p["pid"] == pid and p["sort_by"] == "mem" for p in processes):
                            processes.append({
                                "user": parts[0],
                                "pid": parts[1],
                                "cpu_percent": parts[2],
                                "mem_percent": parts[3],
                                "command": ' '.join(parts[10:]),
                                "sort_by": "mem"
                            })
        
        return processes
    
    def _get_network_config(self) -> Dict[str, Any]:
        """Ottiene configurazione rete"""
        config = {}
        
        # DNS servers
        resolv = self.exec_cmd("cat /etc/resolv.conf 2>/dev/null | grep nameserver", timeout=3)
        dns_servers = []
        if resolv:
            for line in resolv.split('\n'):
                if 'nameserver' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])
        
        if dns_servers:
            config["dns_servers"] = dns_servers
        
        # Default gateway
        gateway = self.exec_cmd("ip route | grep default | head -1", timeout=3)
        if gateway:
            parts = gateway.split()
            for i, p in enumerate(parts):
                if p == 'via' and i + 1 < len(parts):
                    config["default_gateway"] = parts[i + 1]
                    break
        
        # Hostname FQDN
        hostname_fqdn = self.exec_cmd("hostname -f 2>/dev/null || hostname", timeout=3)
        if hostname_fqdn:
            config["hostname_fqdn"] = hostname_fqdn.strip()
        
        # Network manager (se presente)
        nmcli = self.exec_cmd("nmcli -t -f NAME,TYPE,DEVICE connection show 2>/dev/null | head -10", timeout=5)
        network_connections = []
        if nmcli:
            for line in nmcli.split('\n'):
                if line.strip():
                    parts = line.split(':')
                    if len(parts) >= 3:
                        network_connections.append({
                            "name": parts[0],
                            "type": parts[1],
                            "device": parts[2]
                        })
        
        if network_connections:
            config["network_connections"] = network_connections
        
        return config
    
    def _get_system_details(self) -> Dict[str, Any]:
        """Ottiene informazioni sistema avanzate"""
        details = {}
        
        # Timezone
        timezone = self.exec_cmd("timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null", timeout=3)
        if timezone:
            details["timezone"] = timezone.strip()
        
        # Locale
        locale = self.exec_cmd("locale 2>/dev/null | grep LANG=", timeout=3)
        if locale:
            parts = locale.split('=')
            if len(parts) >= 2:
                details["locale"] = parts[1].strip().strip('"')
        
        # NTP servers
        chrony = self.exec_cmd("chronyc sources 2>/dev/null | grep '^\^\*' | head -5", timeout=5)
        ntp_servers = []
        if chrony:
            for line in chrony.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        ntp_servers.append(parts[1])
        else:
            ntpq = self.exec_cmd("ntpq -p 2>/dev/null | tail -n +3 | head -5", timeout=5)
            if ntpq:
                for line in ntpq.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 1:
                            ntp_servers.append(parts[0])
        
        if ntp_servers:
            details["ntp_servers"] = ntp_servers
        
        # SELinux status
        selinux = self.exec_cmd("getenforce 2>/dev/null", timeout=3)
        if selinux:
            details["selinux_status"] = selinux.strip()
        
        # AppArmor status
        apparmor = self.exec_cmd("aa-status 2>/dev/null | head -1", timeout=3)
        if apparmor:
            details["apparmor_status"] = apparmor.strip()
        
        # Boot time
        boot_time = self.exec_cmd("who -b 2>/dev/null | awk '{print $3, $4}'", timeout=3)
        if boot_time:
            details["boot_time"] = boot_time.strip()
        
        # Last reboot
        last_reboot = self.exec_cmd("last reboot 2>/dev/null | head -1", timeout=3)
        if last_reboot:
            details["last_reboot"] = last_reboot.strip()
        
        # Kernel modules loaded
        lsmod = self.exec_cmd("lsmod 2>/dev/null | tail -n +2 | head -30", timeout=3)
        kernel_modules = []
        if lsmod:
            for line in lsmod.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        kernel_modules.append(parts[0])
        
        if kernel_modules:
            details["kernel_modules"] = kernel_modules
        
        return details
    
    def _get_firewall_info(self) -> Dict[str, Any]:
        """Ottiene informazioni firewall"""
        firewall_info = {}
        
        # UFW
        ufw_status = self.exec_cmd("ufw status verbose 2>/dev/null", timeout=5)
        if ufw_status and 'Status:' in ufw_status:
            firewall_info["firewall_type"] = "ufw"
            if 'Status: active' in ufw_status:
                firewall_info["firewall_enabled"] = True
                # Estrai regole
                ufw_rules = self.exec_cmd("ufw status numbered 2>/dev/null | tail -n +4", timeout=5)
                if ufw_rules:
                    rules = []
                    for line in ufw_rules.split('\n'):
                        if line.strip():
                            rules.append(line.strip())
                    firewall_info["firewall_rules"] = rules[:50]  # Limita a 50
            else:
                firewall_info["firewall_enabled"] = False
        
        # iptables (se UFW non presente)
        if "firewall_type" not in firewall_info:
            iptables_rules = self.exec_cmd_sudo("iptables -L -n -v 2>/dev/null | head -50", timeout=5)
            if iptables_rules and 'Chain' in iptables_rules:
                firewall_info["firewall_type"] = "iptables"
                firewall_info["firewall_enabled"] = True
                # Conta regole
                rule_count = len([l for l in iptables_rules.split('\n') if l.strip() and not l.startswith('Chain') and not l.startswith('target')])
                firewall_info["firewall_rules_count"] = rule_count
            else:
                # firewalld
                firewalld = self.exec_cmd("firewall-cmd --list-all 2>/dev/null", timeout=5)
                if firewalld:
                    firewall_info["firewall_type"] = "firewalld"
                    if 'running' in firewalld:
                        firewall_info["firewall_enabled"] = True
                        # Estrai zone e servizi
                        if 'services:' in firewalld:
                            services_line = [l for l in firewalld.split('\n') if 'services:' in l]
                            if services_line:
                                firewall_info["firewall_services"] = services_line[0].split('services:')[1].strip()
        
        return firewall_info
    
    def _get_databases(self) -> List[Dict[str, Any]]:
        """Ottiene database installati"""
        databases = []
        
        # MySQL/MariaDB
        mysql_version = self.exec_cmd("mysql --version 2>/dev/null || mariadb --version 2>/dev/null", timeout=3)
        if mysql_version:
            db_type = "mysql" if "mysql" in mysql_version.lower() else "mariadb"
            databases.append({
                "type": db_type,
                "version": mysql_version.strip()
            })
        
        # PostgreSQL
        postgres_version = self.exec_cmd("psql --version 2>/dev/null", timeout=3)
        if postgres_version:
            databases.append({
                "type": "postgresql",
                "version": postgres_version.strip()
            })
        
        # MongoDB
        mongo_version = self.exec_cmd("mongod --version 2>/dev/null | head -1", timeout=3)
        if mongo_version:
            databases.append({
                "type": "mongodb",
                "version": mongo_version.strip()
            })
        
        # Redis
        redis_version = self.exec_cmd("redis-cli --version 2>/dev/null", timeout=3)
        if redis_version:
            databases.append({
                "type": "redis",
                "version": redis_version.strip()
            })
        
        return databases
    
    def _get_web_servers(self) -> List[Dict[str, Any]]:
        """Ottiene web server installati"""
        web_servers = []
        
        # Apache
        apache_version = self.exec_cmd("apache2 -v 2>/dev/null || httpd -v 2>/dev/null", timeout=3)
        if apache_version:
            apache_info = {"type": "apache", "version": apache_version.strip()}
            # Moduli Apache
            apache_modules = self.exec_cmd("apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null", timeout=5)
            if apache_modules:
                modules = [l.split()[0] for l in apache_modules.split('\n') if l.strip() and 'Loaded' not in l]
                apache_info["modules"] = modules[:30]  # Limita a 30
            web_servers.append(apache_info)
        
        # Nginx
        nginx_version = self.exec_cmd("nginx -v 2>&1", timeout=3)
        if nginx_version:
            web_servers.append({
                "type": "nginx",
                "version": nginx_version.strip()
            })
        
        return web_servers