"""
DaDude Agent - QNAP QTS SSH Probe
Scansione dispositivi QNAP NAS via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class QNAPProbe(SSHVendorProbe):
    """Probe per QNAP QTS NAS"""
    
    VENDOR_NAME = "QNAP"
    DETECTION_PRIORITY = 45
    
    def detect(self) -> bool:
        """Rileva QNAP QTS"""
        # Verifica file specifici QNAP
        qnap = self.exec_cmd("cat /etc/config/qpkg.conf 2>/dev/null || cat /etc/model.conf 2>/dev/null", timeout=3)
        if qnap and ('qnap' in qnap.lower() or 'model' in qnap.lower()):
            return True
        
        # Alternative detection
        uname = self.exec_cmd("uname -a 2>/dev/null", timeout=3)
        if uname and 'qnap' in uname.lower():
            return True
        
        # Verifica getsysinfo
        sysinfo = self.exec_cmd("getsysinfo 2>/dev/null model", timeout=3)
        return bool(sysinfo and sysinfo.strip())
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa QNAP QTS"""
        self._log_info(f"Probing QNAP at {target}")
        
        info = {
            "device_type": "storage",
            "manufacturer": "QNAP",
            "os_name": "QTS",
            "category": "storage",
            "os_family": "Linux",
        }
        
        try:
            # Model via getsysinfo
            model = self.exec_cmd("getsysinfo model 2>/dev/null", timeout=3)
            if model:
                info["model"] = model.strip()
            
            # Hostname
            hostname = self.exec_cmd("hostname", timeout=3)
            if hostname:
                info["hostname"] = hostname.strip()
            
            # Serial number
            serial = self.exec_cmd("getsysinfo serial 2>/dev/null || cat /etc/nas_serial 2>/dev/null", timeout=3)
            if serial:
                info["serial_number"] = serial.strip()
            
            # QTS version
            version = self._get_qts_version()
            if version:
                info.update(version)
                self._log_debug(f"QTS version: {version}")
            
            # Hardware info
            hw = self._get_hardware_info()
            info.update(hw)
            self._log_debug(f"Hardware info: {list(hw.keys())}")
            
            # Storage info
            storage = self._get_storage_info()
            if storage:
                info.update(storage)
                self._log_info(f"Storage info: volumes={storage.get('volumes_count', 0)}, raid={storage.get('raid_count', 0)}, disks={storage.get('disks_count', 0)}")
            else:
                self._log_warning("No storage info collected")
            
            # Network interfaces
            interfaces = self._get_interfaces()
            if interfaces:
                info["interfaces"] = interfaces
                info["interface_count"] = len(interfaces)
            
            # Services
            services = self._get_services()
            if services:
                info["services"] = services
                info["services_count"] = len(services)
            
            # Shares (SMB/NFS)
            shares = self._get_shares()
            if shares:
                info["shares"] = shares
                info["shares_count"] = len(shares)
        
        except Exception as e:
            self._log_error(f"Error during probe: {e}")
        
        self._log_info(f"QNAP probe complete: hostname={info.get('hostname')}, model={info.get('model')}, fields={len(info)}")
        return info
    
    def _get_qts_version(self) -> Dict[str, Any]:
        """Ottiene versione QTS"""
        info = {}
        
        # getsysinfo
        fw_version = self.exec_cmd("getsysinfo firmver 2>/dev/null", timeout=3)
        if fw_version:
            info["firmware_version"] = fw_version.strip()
        
        version = self.exec_cmd("cat /etc/version 2>/dev/null", timeout=3)
        if version:
            info["os_version"] = version.strip()
        
        build = self.exec_cmd("cat /etc/default_config/WEBAPP.build 2>/dev/null || getsysinfo build 2>/dev/null", timeout=3)
        if build:
            info["build_number"] = build.strip()
        
        return info
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Ottiene info hardware"""
        info = {}
        
        # CPU
        cpu = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1", timeout=3)
        if cpu:
            info["cpu_model"] = cpu.split(':')[-1].strip()
        
        cpu_cores = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep processor | wc -l", timeout=3)
        if cpu_cores and cpu_cores.isdigit():
            info["cpu_cores"] = int(cpu_cores)
        
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
        
        # Uptime
        uptime = self.exec_cmd("uptime -p 2>/dev/null || uptime", timeout=3)
        if uptime:
            info["uptime"] = uptime.strip()
        
        return info
    
    def _parse_size(self, size_str: str) -> int:
        """Converte stringa size (es: '8.0T', '500G', '100M') in bytes."""
        if not size_str:
            return 0
        
        try:
            size_str = size_str.strip().upper()
            
            multipliers = {
                'T': 1024**4,
                'G': 1024**3,
                'M': 1024**2,
                'K': 1024,
                'B': 1,
            }
            
            for suffix, mult in multipliers.items():
                if size_str.endswith(suffix):
                    num = float(size_str[:-1].replace(',', '.'))
                    return int(num * mult)
            
            return int(float(size_str))
        except (ValueError, TypeError):
            return 0
    
    def _get_storage_info(self) -> Dict[str, Any]:
        """Ottiene informazioni storage"""
        info = {}
        volumes = []
        
        try:
            # Metodo 1: df -T per ottenere tipo filesystem
            df_out = self.exec_cmd("df -T 2>/dev/null | grep -E '/share|CACHEDEV|/mnt/|DataVol'", timeout=5)
            if df_out:
                for line in df_out.split('\n'):
                    parts = line.split()
                    if len(parts) >= 7:
                        mount_point = parts[6]
                        filesystem = parts[1] if len(parts) > 1 else "ext4"
                        vol_name = mount_point.split('/')[-1] or mount_point
                        
                        # Migliora nome volume per QNAP
                        if '/share/CACHEDEV' in mount_point:
                            # Estrai nome volume da path QNAP
                            vol_parts = mount_point.split('/')
                            if len(vol_parts) >= 3:
                                vol_name = vol_parts[2]  # CACHEDEV1_DATA, MD0_DATA, etc.
                        
                        volumes.append({
                            "name": vol_name,
                            "mount_point": mount_point,
                            "path": mount_point,
                            "device": parts[0],
                            "filesystem": filesystem,
                            "total": parts[3],
                            "used": parts[4],
                            "available": parts[5],
                            "use_percent": parts[5] if len(parts) > 5 else "",
                            "total_bytes": self._parse_size(parts[3]),
                            "used_bytes": self._parse_size(parts[4]),
                            "available_bytes": self._parse_size(parts[5]),
                        })
            
            # Metodo 2: Cerca volumi QNAP esplicitamente
            if not volumes:
                share_list = self.exec_cmd("ls -d /share/CACHEDEV* /share/MD* 2>/dev/null | head -20", timeout=3)
                if share_list:
                    for path in share_list.split('\n'):
                        if path.strip():
                            df_line = self.exec_cmd(f"df -h {path.strip()} 2>/dev/null | tail -1", timeout=3)
                            if df_line:
                                parts = df_line.split()
                                if len(parts) >= 5:
                                    volumes.append({
                                        "name": path.strip().split('/')[-1],
                                        "path": path.strip(),
                                        "device": parts[0],
                                        "total": parts[1],
                                        "used": parts[2],
                                        "available": parts[3],
                                        "use_percent": parts[4] if len(parts) > 4 else "",
                                        "total_bytes": self._parse_size(parts[1]),
                                        "used_bytes": self._parse_size(parts[2]),
                                        "available_bytes": self._parse_size(parts[3]),
                                    })
            
            if volumes:
                info["volumes"] = volumes
                info["volumes_count"] = len(volumes)
                
                # Calcola totali
                total_bytes = sum(v.get("total_bytes", 0) for v in volumes)
                used_bytes = sum(v.get("used_bytes", 0) for v in volumes)
                info["disk_total_gb"] = round(total_bytes / (1024**3), 2) if total_bytes else 0
                info["disk_used_gb"] = round(used_bytes / (1024**3), 2) if used_bytes else 0
                info["disk_free_gb"] = round((total_bytes - used_bytes) / (1024**3), 2) if total_bytes else 0
        
        except Exception as e:
            self._log_warning(f"Error getting volumes: {e}")
        
        # RAID info via mdstat
        raid_info = []
        mdstat = self.exec_cmd("cat /proc/mdstat 2>/dev/null", timeout=3)
        if mdstat and 'md' in mdstat:
            current_md = None
            for line in mdstat.split('\n'):
                if line.startswith('md'):
                    parts = line.split()
                    if parts:
                        current_md = {
                            "name": parts[0].rstrip(':'),
                            "status": parts[1] if len(parts) > 1 else "",
                            "type": "",
                        }
                        for p in parts:
                            if p.startswith('raid'):
                                current_md["type"] = p
                        raid_info.append(current_md)
                elif current_md and '[' in line:
                    if '[' in line and ']' in line:
                        status = line[line.index('['):line.index(']')+1]
                        current_md["disk_status"] = status
        
        if raid_info:
            info["raid_arrays"] = raid_info
            info["raid_count"] = len(raid_info)
        
        # Pool storage (QNAP)
        pool = self.exec_cmd("cat /etc/config/storage_pool.conf 2>/dev/null | head -50", timeout=3)
        if pool:
            info["storage_pool_config"] = "configured"
        
        # Dischi fisici - migliorato con più dettagli hardware
        disks = []
        # Usa lsblk con più colonne per ottenere tipo, modello, seriale
        lsblk = self.exec_cmd("lsblk -d -o NAME,SIZE,MODEL,SERIAL,TYPE,TRAN 2>/dev/null | tail -n +2", timeout=5)
        if lsblk:
            for line in lsblk.split('\n'):
                if line.strip() and not line.startswith('NAME'):
                    parts = line.split()
                    if parts and (parts[0].startswith('sd') or parts[0].startswith('nvme') or parts[0].startswith('hd')):
                        disk = {
                            "name": f"/dev/{parts[0]}",
                            "device": parts[0],
                            "size": parts[1] if len(parts) > 1 else "",
                            "size_bytes": self._parse_size(parts[1]) if len(parts) > 1 else 0,
                            "model": ' '.join(parts[2:-3]) if len(parts) > 5 else (parts[2] if len(parts) > 2 else ""),
                            "serial": parts[-3] if len(parts) > 5 else (parts[-1] if len(parts) > 3 else ""),
                            "type": parts[-2] if len(parts) > 4 else "",
                            "transport": parts[-1] if len(parts) > 5 else "",
                        }
                        
                        # Determina tipo disco (SSD/HDD) da modello o transport
                        model_lower = disk["model"].lower() if disk["model"] else ""
                        transport_lower = disk["transport"].lower() if disk["transport"] else ""
                        if "ssd" in model_lower or "nvme" in transport_lower or disk["name"].startswith("/dev/nvme"):
                            disk["disk_type"] = "SSD"
                        elif "hdd" in model_lower or "sata" in transport_lower:
                            disk["disk_type"] = "HDD"
                        else:
                            disk["disk_type"] = disk["type"] or "Unknown"
                        
                        # Temperatura e salute via smartctl
                        smart = self.exec_cmd_sudo(f"smartctl -a /dev/{parts[0]} 2>/dev/null | grep -E '(Temperature|Health|PASSED|FAILED|SMART)' | head -5", timeout=5)
                        if smart:
                            for sline in smart.split('\n'):
                                sline_lower = sline.lower()
                                if 'temperature' in sline_lower:
                                    try:
                                        for word in sline.split():
                                            if word.isdigit():
                                                disk["temperature"] = int(word)
                                                disk["temperature_celsius"] = int(word)
                                                break
                                    except:
                                        pass
                                elif 'passed' in sline_lower or 'healthy' in sline_lower:
                                    disk["health"] = "healthy"
                                    disk["health_status"] = "healthy"
                                    disk["smart_status"] = "PASSED"
                                elif 'failed' in sline_lower or 'failing' in sline_lower:
                                    disk["health"] = "failing"
                                    disk["health_status"] = "failing"
                                    disk["smart_status"] = "FAILED"
                        
                        # Informazioni aggiuntive da /sys/block
                        if parts[0]:
                            sys_model = self.exec_cmd(f"cat /sys/block/{parts[0]}/device/model 2>/dev/null | tr -d '\\n'", timeout=2)
                            if sys_model:
                                disk["model"] = sys_model.strip()
                            
                            sys_serial = self.exec_cmd(f"cat /sys/block/{parts[0]}/device/serial 2>/dev/null | tr -d '\\n'", timeout=2)
                            if sys_serial:
                                disk["serial"] = sys_serial.strip()
                            
                            sys_vendor = self.exec_cmd(f"cat /sys/block/{parts[0]}/device/vendor 2>/dev/null | tr -d '\\n'", timeout=2)
                            if sys_vendor:
                                disk["vendor"] = sys_vendor.strip()
                        
                        disks.append(disk)
        
        if disks:
            info["disks"] = disks
            info["disks_count"] = len(disks)
        
        return info
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce di rete"""
        interfaces = []
        output = self.exec_cmd("ip addr 2>/dev/null || ifconfig", timeout=5)
        
        if not output:
            return []
        
        current = {}
        for line in output.split('\n'):
            if line and not line.startswith(' ') and ':' in line:
                if current and current.get("name"):
                    interfaces.append(current)
                parts = line.split(':')
                name = parts[1].strip().split()[0] if len(parts) > 1 else parts[0].strip()
                current = {"name": name}
            elif 'inet ' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        current["ipv4"] = parts[i + 1].split('/')[0]
            elif 'link/ether' in line.lower() or 'ether' in line.lower():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.lower() in ('link/ether', 'ether') and i + 1 < len(parts):
                        current["mac_address"] = parts[i + 1]
        
        if current and current.get("name"):
            interfaces.append(current)
        
        return [i for i in interfaces if not i["name"].startswith("lo") and not i["name"].startswith("docker")]
    
    def _get_shares(self) -> List[Dict[str, Any]]:
        """Ottiene share SMB/NFS esposte"""
        shares = []
        
        try:
            # Metodo 1: Leggi configurazione QNAP
            # QNAP usa /etc/config/smb.conf o /etc/config/samba/smb.conf
            smb_conf = self.exec_cmd("cat /etc/config/smb.conf 2>/dev/null || cat /etc/config/samba/smb.conf 2>/dev/null || cat /etc/samba/smb.conf 2>/dev/null", timeout=3)
            if smb_conf:
                for line in smb_conf.split('\n'):
                    if line.strip().startswith('[') and line.strip().endswith(']'):
                        share_name = line.strip()[1:-1]
                        if share_name not in ['global', 'homes', 'printers', 'print$']:
                            shares.append({
                                "name": share_name,
                                "types": ["SMB"],
                                "path": f"/share/{share_name}",
                            })
            
            # Metodo 2: Lista directory /share
            if not shares:
                share_dirs = self.exec_cmd("ls -d /share/* 2>/dev/null | grep -v CACHEDEV | grep -v MD | head -20", timeout=3)
                if share_dirs:
                    for path in share_dirs.split('\n'):
                        if path.strip():
                            share_name = path.strip().split('/')[-1]
                            shares.append({
                                "name": share_name,
                                "types": ["SMB"],  # Default per QNAP
                                "path": path.strip(),
                            })
            
            # Verifica NFS se disponibile
            nfs_exports = self.exec_cmd("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
            if nfs_exports:
                for line in nfs_exports.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if parts:
                            nfs_path = parts[0]
                            if '/share/' in nfs_path:
                                share_name = nfs_path.split('/')[-1]
                                # Trova share esistente e aggiungi NFS
                                for share in shares:
                                    if share["name"] == share_name:
                                        if "NFS" not in share["types"]:
                                            share["types"].append("NFS")
                                        break
                                else:
                                    # Nuova share solo NFS
                                    shares.append({
                                        "name": share_name,
                                        "types": ["NFS"],
                                        "path": nfs_path,
                                    })
        except Exception as e:
            self._log_warning(f"Error getting shares: {e}")
        
        return shares
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi QNAP attivi"""
        services = []
        
        qnap_services = [
            "nginx", "smbd", "nfsd", "sshd", "rsync",
            "mariadb", "mysql", "qvs", "qmailserver"
        ]
        
        for svc in qnap_services:
            # Metodo 1: Prova systemctl
            systemctl_status = self.exec_cmd(f"systemctl is-active {svc} 2>/dev/null", timeout=2)
            if systemctl_status and systemctl_status.strip() == "active":
                status = "running"
            else:
                # Metodo 2: Fallback pgrep
                pgrep_out = self.exec_cmd(f"pgrep -x {svc} >/dev/null 2>&1 && echo 'running' || echo 'stopped'", timeout=2)
                status = pgrep_out.strip() if pgrep_out else "stopped"
            
            services.append({
                "name": svc,
                "status": status,
            })
        
        return services
