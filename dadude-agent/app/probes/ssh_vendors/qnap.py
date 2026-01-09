"""
DaDude Agent - QNAP QTS/QuTS Hero SSH Probe
Scansione dispositivi QNAP NAS via SSH.
Supporta: QTS (ext4/RAID) e QuTS Hero (ZFS)
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe
import re


class QNAPProbe(SSHVendorProbe):
    """Probe per QNAP QTS/QuTS Hero NAS"""
    
    VENDOR_NAME = "QNAP"
    DETECTION_PRIORITY = 45
    
    def __init__(self, exec_cmd, exec_cmd_sudo):
        super().__init__(exec_cmd, exec_cmd_sudo)
        self.is_quts_hero = False  # QuTS Hero usa ZFS
    
    def detect(self) -> bool:
        """Rileva QNAP QTS/QuTS Hero"""
        # Verifica file specifici QNAP
        qnap = self.exec_cmd("cat /etc/config/qpkg.conf 2>/dev/null || cat /etc/model.conf 2>/dev/null", timeout=3)
        if qnap and ('qnap' in qnap.lower() or 'model' in qnap.lower()):
            return True
        
        # Verifica platform.conf
        platform = self.exec_cmd("cat /etc/platform.conf 2>/dev/null | head -10", timeout=3)
        if platform and ('DISPLAY_NAME' in platform or 'Platform' in platform):
            return True
        
        # Alternative detection
        uname = self.exec_cmd("uname -a 2>/dev/null", timeout=3)
        if uname and 'qnap' in uname.lower():
            return True
        
        # Verifica getsysinfo
        sysinfo = self.exec_cmd("getsysinfo model 2>/dev/null", timeout=3)
        return bool(sysinfo and sysinfo.strip())
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa QNAP QTS/QuTS Hero"""
        self._log_info(f"Probing QNAP at {target}")
        
        # Detect if QuTS Hero (ZFS-based) - prova diversi percorsi
        zfs_check = self.exec_cmd("which zpool 2>/dev/null || ls /usr/sbin/zpool 2>/dev/null || ls /sbin/zpool 2>/dev/null", timeout=3)
        self.is_quts_hero = bool(zfs_check and zfs_check.strip() and 'zpool' in zfs_check)
        
        # Alternativa: verifica se ZFS è montato
        if not self.is_quts_hero:
            zfs_mount = self.exec_cmd("mount | grep -i zfs 2>/dev/null | head -1", timeout=3)
            if zfs_mount and 'zfs' in zfs_mount.lower():
                self.is_quts_hero = True
        
        # Alternativa 2: verifica modello (TS-h indica Hero)
        if not self.is_quts_hero:
            model_check = self.exec_cmd("getsysinfo model 2>/dev/null", timeout=3)
            if model_check and 'TS-h' in model_check:
                self.is_quts_hero = True
                self._log_info(f"QuTS Hero detected from model name: {model_check.strip()}")
        
        os_name = "QuTS Hero" if self.is_quts_hero else "QTS"
        self._log_info(f"Detected: {os_name} ({'ZFS' if self.is_quts_hero else 'ext4/RAID'})")
        
        info = {
            "device_type": "storage",
            "manufacturer": "QNAP",
            "os_name": os_name,
            "category": "storage",
            "os_family": "Linux",
        }
        
        try:
            # System info from platform.conf
            platform_info = self._get_platform_info()
            if platform_info:
                info.update(platform_info)
            
            # Model via getsysinfo (fallback)
            if not info.get("model"):
                model = self.exec_cmd("getsysinfo model 2>/dev/null", timeout=3)
                if model:
                    info["model"] = model.strip()
            
            # Hostname
            hostname = self.exec_cmd("hostname", timeout=3)
            if hostname:
                info["hostname"] = hostname.strip()
            
            # Serial number - prova diversi metodi
            serial = None
            
            # Metodo 1: getsysinfo serial
            serial_cmd = self.exec_cmd("getsysinfo serial 2>/dev/null", timeout=3)
            if serial_cmd and serial_cmd.strip():
                serial = serial_cmd.strip()
                self._log_debug(f"Serial from getsysinfo: {serial}")
            
            # Metodo 2: /etc/nas_serial
            if not serial:
                serial_cmd = self.exec_cmd("cat /etc/nas_serial 2>/dev/null", timeout=3)
                if serial_cmd and serial_cmd.strip():
                    serial = serial_cmd.strip()
                    self._log_debug(f"Serial from /etc/nas_serial: {serial}")
            
            # Metodo 3: SUID da platform.conf
            if not serial:
                suid = self.exec_cmd("cat /etc/platform.conf 2>/dev/null | grep -i SUID", timeout=3)
                if suid and '=' in suid:
                    serial = suid.split('=', 1)[1].strip().strip('"')
                    self._log_debug(f"Serial from SUID: {serial}")
            
            # Metodo 4: hal_app per seriale
            if not serial:
                hal_serial = self.exec_cmd("hal_app --get_serial_number 2>/dev/null", timeout=3)
                if hal_serial and hal_serial.strip():
                    serial = hal_serial.strip()
                    self._log_debug(f"Serial from hal_app: {serial}")
            
            # Metodo 5: dmidecode (richiede root)
            if not serial:
                dmi_serial = self.exec_cmd_sudo("dmidecode -s system-serial-number 2>/dev/null", timeout=5)
                if dmi_serial and dmi_serial.strip() and dmi_serial.strip() != "Not Specified":
                    serial = dmi_serial.strip()
                    self._log_debug(f"Serial from dmidecode: {serial}")
            
            if serial:
                info["serial_number"] = serial
                self._log_info(f"Found serial number: {serial}")
            
            # QTS version
            version = self._get_qts_version()
            if version:
                info.update(version)
                self._log_debug(f"QTS version: {version}")
            
            # Hardware info (CPU, RAM, uptime)
            hw = self._get_hardware_info()
            info.update(hw)
            self._log_debug(f"Hardware info: {list(hw.keys())}")
            
            # Storage info (volumes, RAID, disks, ZFS pools)
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
                self._log_info(f"Found {len(shares)} shares")
        
        except Exception as e:
            self._log_error(f"Error during probe: {e}")
        
        self._log_info(f"QNAP probe complete: hostname={info.get('hostname')}, model={info.get('model')}, os={os_name}, fields={len(info)}")
        return info
    
    def _get_platform_info(self) -> Dict[str, Any]:
        """Ottiene informazioni da platform.conf"""
        info = {}
        
        platform_conf = self.exec_cmd("cat /etc/platform.conf 2>/dev/null", timeout=3)
        if not platform_conf:
            return info
        
        for line in platform_conf.split('\n'):
            line = line.strip()
            if 'DISPLAY_NAME' in line and '=' in line:
                info["model"] = line.split('=', 1)[1].strip()
            elif line.startswith('Platform') and '=' in line:
                info["platform"] = line.split('=', 1)[1].strip()
        
        return info
    
    def _get_qts_version(self) -> Dict[str, Any]:
        """Ottiene versione QTS/QuTS Hero"""
        info = {}
        
        # getsysinfo firmware version
        fw_version = self.exec_cmd("getsysinfo firmver 2>/dev/null", timeout=3)
        if fw_version:
            info["firmware_version"] = fw_version.strip()
        
        # /etc/version per versione OS
        version = self.exec_cmd("cat /etc/version 2>/dev/null", timeout=3)
        if version:
            info["os_version"] = version.strip()
        
        # Build number
        build = self.exec_cmd("cat /etc/default_config/WEBAPP.build 2>/dev/null || getsysinfo build 2>/dev/null", timeout=3)
        if build:
            info["build_number"] = build.strip()
        
        return info
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Ottiene info hardware (CPU, RAM, uptime)"""
        info = {}
        
        # RAM info - metodo Linux standard (più affidabile)
        meminfo = self.exec_cmd("cat /proc/meminfo 2>/dev/null", timeout=3)
        if meminfo:
            for line in meminfo.split('\n'):
                try:
                    if 'MemTotal:' in line:
                        # MemTotal in kB
                        mem_kb = int(line.split()[1])
                        info["ram_total_mb"] = mem_kb // 1024
                        info["ram_total_gb"] = round(mem_kb / (1024 * 1024), 2)
                        self._log_debug(f"RAM Total from /proc/meminfo: {info['ram_total_mb']} MB")
                    elif 'MemFree:' in line:
                        info["ram_free_mb"] = int(line.split()[1]) // 1024
                    elif 'MemAvailable:' in line:
                        info["ram_available_mb"] = int(line.split()[1]) // 1024
                    elif 'SwapTotal:' in line:
                        info["swap_total_mb"] = int(line.split()[1]) // 1024
                except (ValueError, IndexError):
                    pass
        
        # CPU info
        cpuinfo = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null", timeout=3)
        if cpuinfo:
            cores = 0
            freq = 0.0
            cache = 0
            for line in cpuinfo.split('\n'):
                if 'model name' in line and not info.get("cpu_model"):
                    info["cpu_model"] = line.split(':', 1)[1].strip()
                elif 'processor' in line.lower() and line.strip().startswith('processor'):
                    cores += 1
                elif 'cpu MHz' in line and freq == 0:
                    try:
                        freq = float(line.split(':')[1].strip())
                    except:
                        pass
                elif 'cache size' in line and cache == 0:
                    try:
                        cache_str = line.split(':')[1].strip().split()[0]
                        cache = int(cache_str)
                    except:
                        pass
            
            if cores > 0:
                info["cpu_cores"] = cores
            if freq > 0:
                info["cpu_frequency_mhz"] = freq
            if cache > 0:
                info["cpu_cache_kb"] = cache
        
        # RAM info
        meminfo = self.exec_cmd("cat /proc/meminfo 2>/dev/null", timeout=3)
        if meminfo:
            for line in meminfo.split('\n'):
                try:
                    if 'MemTotal:' in line:
                        info["ram_total_mb"] = int(line.split()[1]) // 1024
                    elif 'MemFree:' in line:
                        info["ram_free_mb"] = int(line.split()[1]) // 1024
                    elif 'MemAvailable:' in line:
                        info["ram_available_mb"] = int(line.split()[1]) // 1024
                    elif 'SwapTotal:' in line:
                        info["swap_total_mb"] = int(line.split()[1]) // 1024
                except (ValueError, IndexError):
                    pass
        
        # RAM modules from platform.conf
        platform = self.exec_cmd("cat /etc/platform.conf 2>/dev/null | grep -A5 '\\[DIMM'", timeout=3)
        if platform:
            modules = []
            current_dimm = {}
            for line in platform.split('\n'):
                if '[DIMM' in line:
                    if current_dimm.get('size_mb'):
                        modules.append(current_dimm)
                    current_dimm = {}
                elif 'size =' in line:
                    try:
                        size = int(line.split('=')[1].strip())
                        current_dimm['size_mb'] = size
                    except:
                        pass
                elif 'manufaturer =' in line or 'manufacturer =' in line:
                    current_dimm['manufacturer'] = line.split('=')[1].strip()
                elif 'module_part_number =' in line:
                    current_dimm['part_number'] = line.split('=')[1].strip()
            if current_dimm.get('size_mb'):
                modules.append(current_dimm)
            if modules:
                info["ram_modules"] = modules
        
        # Uptime
        uptime = self.exec_cmd("uptime -p 2>/dev/null || uptime", timeout=3)
        if uptime:
            info["uptime"] = uptime.strip()
            # Parse uptime days
            days_match = re.search(r'up\s+(\d+)\s+day', uptime)
            if days_match:
                info["uptime_days"] = int(days_match.group(1))
        
        # Kernel version
        kernel = self.exec_cmd("uname -r 2>/dev/null", timeout=3)
        if kernel:
            info["kernel_version"] = kernel.strip()
        
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
            # === ZFS POOLS (QuTS Hero) ===
            if self.is_quts_hero:
                zfs_info = self._get_zfs_storage()
                if zfs_info:
                    info.update(zfs_info)
                    volumes = zfs_info.get("volumes", [])
            
            # === STANDARD VOLUMES (QTS) ===
            if not volumes:
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
                            if '/share/CACHEDEV' in mount_point or '/share/MD' in mount_point:
                                vol_parts = mount_point.split('/')
                                if len(vol_parts) >= 3:
                                    vol_name = vol_parts[2]
                            
                            # Parse size values - df -T has: Filesystem Type Size Used Avail Use% Mounted
                            try:
                                total_str = parts[2]  # Size
                                used_str = parts[3]   # Used
                                avail_str = parts[4]  # Avail
                                use_pct = parts[5]    # Use%
                            except IndexError:
                                total_str = used_str = avail_str = use_pct = ""
                            
                            volumes.append({
                                "name": vol_name,
                                "mount_point": mount_point,
                                "path": mount_point,
                                "device": parts[0],
                                "filesystem": filesystem,
                                "total": total_str,
                                "used": used_str,
                                "available": avail_str,
                                "use_percent": int(use_pct.rstrip('%')) if use_pct.rstrip('%').isdigit() else 0,
                                "total_bytes": self._parse_size(total_str),
                                "used_bytes": self._parse_size(used_str),
                                "available_bytes": self._parse_size(avail_str),
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
                                            "use_percent": int(parts[4].rstrip('%')) if len(parts) > 4 and parts[4].rstrip('%').isdigit() else 0,
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
        
        # === RAID INFO ===
        raid_info = self._get_raid_info()
        if raid_info:
            info["raid_arrays"] = raid_info
            info["raid_count"] = len(raid_info)
        
        # === PHYSICAL DISKS ===
        disks = self._get_physical_disks()
        if disks:
            info["disks"] = disks
            info["disks_count"] = len(disks)
        
        return info
    
    def _get_zfs_storage(self) -> Dict[str, Any]:
        """Ottiene informazioni ZFS per QuTS Hero"""
        info = {}
        volumes = []
        
        # ZFS Pools
        zpool_output = self.exec_cmd_sudo("zpool list 2>/dev/null", timeout=5)
        if zpool_output:
            zfs_pools = []
            lines = zpool_output.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 7:
                    pool_name = parts[0]
                    size_gb = self._parse_size(parts[1]) / (1024**3)
                    used_gb = self._parse_size(parts[2]) / (1024**3)
                    free_gb = self._parse_size(parts[3]) / (1024**3)
                    capacity = int(parts[4].rstrip('%')) if parts[4].rstrip('%').isdigit() else 0
                    health = parts[6] if len(parts) > 6 else "UNKNOWN"
                    
                    # Get pool status for RAID type and disks
                    status = self.exec_cmd_sudo(f"zpool status {pool_name} 2>/dev/null", timeout=5)
                    raid_type = "unknown"
                    disks = []
                    
                    if status:
                        for sl in status.split('\n'):
                            sl_lower = sl.lower()
                            if 'raidz1' in sl_lower:
                                raid_type = 'raidz1'
                            elif 'raidz2' in sl_lower:
                                raid_type = 'raidz2'
                            elif 'raidz3' in sl_lower:
                                raid_type = 'raidz3'
                            elif 'mirror' in sl_lower and raid_type == 'unknown':
                                raid_type = 'mirror'
                            
                            # Extract disk names
                            if 'sd' in sl or 'nvme' in sl or 'disk_' in sl:
                                disk_match = re.search(r'(sd[a-z]+|nvme\d+n\d+|disk_\S+)', sl)
                                if disk_match:
                                    disks.append(disk_match.group(1))
                    
                    zfs_pools.append({
                        "name": pool_name,
                        "size_gb": round(size_gb, 2),
                        "used_gb": round(used_gb, 2),
                        "free_gb": round(free_gb, 2),
                        "capacity_percent": capacity,
                        "health": health,
                        "raid_type": raid_type,
                        "disks": list(set(disks)),
                    })
                    
                    # Add pool as volume
                    volumes.append({
                        "name": pool_name,
                        "mount_point": f"/{pool_name}",
                        "path": f"/{pool_name}",
                        "filesystem": "zfs",
                        "total_bytes": int(size_gb * 1024**3),
                        "used_bytes": int(used_gb * 1024**3),
                        "available_bytes": int(free_gb * 1024**3),
                        "use_percent": capacity,
                        "pool_health": health,
                        "raid_type": raid_type,
                    })
            
            if zfs_pools:
                info["zfs_pools"] = zfs_pools
                self._log_info(f"Found {len(zfs_pools)} ZFS pools")
        
        # ZFS Datasets
        zfs_output = self.exec_cmd_sudo("zfs list -t filesystem 2>/dev/null", timeout=5)
        if zfs_output:
            zfs_datasets = []
            lines = zfs_output.strip().split('\n')[1:]  # Skip header
            
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    name = parts[0]
                    used = self._parse_size(parts[1])
                    avail = self._parse_size(parts[2])
                    mount = parts[4]
                    
                    # Only include datasets mounted in /share
                    if '/share/' in mount and '@Recently-Snapshot' not in name:
                        pool = name.split('/')[0]
                        
                        zfs_datasets.append({
                            "name": name,
                            "mount_point": mount,
                            "used_gb": round(used / (1024**3), 2),
                            "available_gb": round(avail / (1024**3), 2),
                            "pool": pool,
                        })
                        
                        # Add as volume
                        volumes.append({
                            "name": name.split('/')[-1],
                            "mount_point": mount,
                            "path": mount,
                            "filesystem": "zfs",
                            "total_bytes": used + avail,
                            "used_bytes": used,
                            "available_bytes": avail,
                            "use_percent": int(100 * used / (used + avail)) if (used + avail) > 0 else 0,
                            "zfs_pool": pool,
                        })
            
            if zfs_datasets:
                info["zfs_datasets"] = zfs_datasets
                self._log_info(f"Found {len(zfs_datasets)} ZFS datasets")
        
        if volumes:
            info["volumes"] = volumes
            info["volumes_count"] = len(volumes)
        
        return info
    
    def _get_raid_info(self) -> List[Dict[str, Any]]:
        """Ottiene informazioni RAID da /proc/mdstat"""
        raid_info = []
        
        mdstat = self.exec_cmd("cat /proc/mdstat 2>/dev/null", timeout=3)
        if mdstat and 'md' in mdstat:
            current_md = None
            for line in mdstat.split('\n'):
                if line.startswith('md'):
                    parts = line.split()
                    if parts:
                        md_name = parts[0].rstrip(':')
                        current_md = {
                            "name": f"/dev/{md_name}",
                            "device": md_name,
                            "status": parts[1] if len(parts) > 1 else "",
                            "level": "",
                            "devices": [],
                        }
                        # Extract RAID level
                        for p in parts:
                            if p.startswith('raid'):
                                current_md["level"] = p
                        # Extract disk devices
                        for p in parts:
                            disk_match = re.match(r'(sd[a-z]+|nvme\d+n\d+)\d*\[\d+\]', p)
                            if disk_match:
                                current_md["devices"].append(disk_match.group(1))
                        
                        raid_info.append(current_md)
                elif current_md and '[' in line and ']' in line:
                    # Parse disk status line like "[UUU]"
                    status_match = re.search(r'\[([U_]+)\]', line)
                    if status_match:
                        current_md["disk_status"] = status_match.group(1)
                        # Count degraded disks
                        current_md["degraded"] = '_' in status_match.group(1)
        
        # Also get mdadm details for each array
        for raid in raid_info:
            md_name = raid.get("device", "")
            if md_name:
                mdadm_detail = self.exec_cmd_sudo(f"mdadm --detail /dev/{md_name} 2>/dev/null | head -20", timeout=5)
                if mdadm_detail:
                    for line in mdadm_detail.split('\n'):
                        if 'Raid Level' in line:
                            raid["level"] = line.split(':')[-1].strip()
                        elif 'State :' in line:
                            raid["state"] = line.split(':')[-1].strip()
                        elif 'Array Size' in line:
                            size_match = re.search(r'\(([\d.]+)\s*(TB|GB|MB)', line)
                            if size_match:
                                size = float(size_match.group(1))
                                unit = size_match.group(2)
                                if unit == 'TB':
                                    size *= 1024
                                raid["size_gb"] = round(size, 2)
        
        return raid_info
    
    def _get_physical_disks(self) -> List[Dict[str, Any]]:
        """Ottiene informazioni sui dischi fisici"""
        disks = []
        disk_details = {}
        
        # QNAP disk temperature via get_hd_temp
        for disk_num in range(1, 25):  # Support up to 24 disks
            temp_output = self.exec_cmd(f"/sbin/get_hd_temp {disk_num} 2>/dev/null", timeout=2)
            if temp_output and temp_output.strip().isdigit():
                disk_details[f"disk_{disk_num}"] = {"temperature": int(temp_output.strip())}
        
        # Usa lsblk con più colonne per ottenere tipo, modello, seriale
        lsblk = self.exec_cmd("lsblk -d -o NAME,SIZE,MODEL,SERIAL,TYPE,TRAN 2>/dev/null | tail -n +2", timeout=5)
        if lsblk:
            disk_index = 1
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
                        
                        # Add temperature from get_hd_temp if available
                        if f"disk_{disk_index}" in disk_details:
                            disk["temperature"] = disk_details[f"disk_{disk_index}"]["temperature"]
                            disk["temperature_celsius"] = disk["temperature"]
                        
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
                                if 'temperature' in sline_lower and not disk.get("temperature"):
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
                            if sys_model and sys_model.strip():
                                disk["model"] = sys_model.strip()
                            
                            sys_serial = self.exec_cmd(f"cat /sys/block/{parts[0]}/device/serial 2>/dev/null | tr -d '\\n'", timeout=2)
                            if sys_serial and sys_serial.strip():
                                disk["serial"] = sys_serial.strip()
                            
                            sys_vendor = self.exec_cmd(f"cat /sys/block/{parts[0]}/device/vendor 2>/dev/null | tr -d '\\n'", timeout=2)
                            if sys_vendor and sys_vendor.strip():
                                disk["vendor"] = sys_vendor.strip()
                        
                        disks.append(disk)
                        disk_index += 1
        
        return disks
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce di rete"""
        interfaces = []
        output = self.exec_cmd("ip addr show 2>/dev/null || ifconfig", timeout=5)
        
        if not output:
            return []
        
        current = {}
        for line in output.split('\n'):
            # New interface starts with number: name:
            if line and re.match(r'^\d+:\s+', line):
                if current and current.get("name"):
                    interfaces.append(current)
                
                parts = line.split(':')
                name = parts[1].strip().split()[0] if len(parts) > 1 else ""
                
                # Skip loopback, dummy, docker interfaces
                if name in ('lo', 'docker0') or 'dummy' in name:
                    current = {}
                    continue
                
                state = 'UP' if 'UP' in line else 'DOWN'
                current = {"name": name, "state": state}
                
            elif 'inet ' in line and current and 'inet6' not in line:
                ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current["ipv4"] = ip_match.group(1)
                    
            elif ('link/ether' in line.lower() or 'ether ' in line.lower()) and current:
                mac_match = re.search(r'([0-9a-fA-F:]{17})', line)
                if mac_match:
                    current["mac_address"] = mac_match.group(1)
        
        if current and current.get("name"):
            interfaces.append(current)
        
        # Get interface speed/duplex via ethtool
        for iface in interfaces:
            if iface.get("name"):
                ethtool = self.exec_cmd(f"ethtool {iface['name']} 2>/dev/null | grep -E 'Speed|Duplex'", timeout=2)
                if ethtool:
                    for line in ethtool.split('\n'):
                        if 'Speed:' in line:
                            speed_match = re.search(r'(\d+)Mb/s', line)
                            if speed_match:
                                iface["speed_mbps"] = int(speed_match.group(1))
                        elif 'Duplex:' in line:
                            iface["duplex"] = line.split(':')[1].strip()
        
        return [i for i in interfaces if i.get("name") and not i["name"].startswith("docker")]
    
    def _get_shares(self) -> List[Dict[str, Any]]:
        """Ottiene share SMB/NFS esposte"""
        shares = []
        
        try:
            # Metodo 1: Leggi configurazione QNAP smb.conf
            smb_conf = self.exec_cmd("cat /etc/config/smb.conf 2>/dev/null || cat /etc/config/samba/smb.conf 2>/dev/null || cat /etc/samba/smb.conf 2>/dev/null", timeout=3)
            
            current_share = None
            current_data = {}
            
            if smb_conf:
                for line in smb_conf.split('\n'):
                    line = line.strip()
                    if line.startswith('[') and line.endswith(']'):
                        # Save previous share
                        if current_share and current_share not in ['global', 'home', 'homes', 'printers', 'print$']:
                            shares.append({
                                "name": current_share,
                                "types": ["SMB"],
                                "path": current_data.get('path', f"/share/{current_share}"),
                                "public": current_data.get('public', False),
                                "comment": current_data.get('comment'),
                            })
                        
                        current_share = line[1:-1]
                        current_data = {}
                        
                    elif current_share and '=' in line:
                        key, value = line.split('=', 1)
                        key = key.strip()
                        value = value.strip()
                        
                        if key == 'path':
                            current_data['path'] = value
                        elif key == 'comment':
                            current_data['comment'] = value
                        elif key == 'public':
                            current_data['public'] = value.lower() == 'yes'
                
                # Last share
                if current_share and current_share not in ['global', 'home', 'homes', 'printers', 'print$']:
                    shares.append({
                        "name": current_share,
                        "types": ["SMB"],
                        "path": current_data.get('path', f"/share/{current_share}"),
                        "public": current_data.get('public', False),
                        "comment": current_data.get('comment'),
                    })
                
                self._log_info(f"Found {len(shares)} SMB shares from smb.conf")
            
            # Metodo 2: Lista directory /share se nessuna share trovata
            if not shares:
                share_dirs = self.exec_cmd("ls -d /share/* 2>/dev/null | grep -v CACHEDEV | grep -v MD | head -30", timeout=3)
                if share_dirs:
                    for path in share_dirs.split('\n'):
                        if path.strip():
                            share_name = path.strip().split('/')[-1]
                            shares.append({
                                "name": share_name,
                                "types": ["SMB"],
                                "path": path.strip(),
                            })
            
            # Verifica NFS exports
            nfs_exports = self.exec_cmd("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'", timeout=3)
            if nfs_exports:
                for line in nfs_exports.split('\n'):
                    line = line.strip()
                    if line:
                        # Parse: "/path" host(options) or /path host(options)
                        path_match = re.match(r'"?([^"\s]+)"?\s+', line)
                        if path_match:
                            nfs_path = path_match.group(1)
                            share_name = nfs_path.split('/')[-1]
                            
                            # Trova share esistente e aggiungi NFS
                            found = False
                            for share in shares:
                                if share["path"] == nfs_path or share["name"] == share_name:
                                    if "NFS" not in share["types"]:
                                        share["types"].append("NFS")
                                    found = True
                                    break
                            
                            if not found:
                                shares.append({
                                    "name": f"{share_name}",
                                    "types": ["NFS"],
                                    "path": nfs_path,
                                })
                
                self._log_info(f"Checked NFS exports, total shares: {len(shares)}")
        
        except Exception as e:
            self._log_warning(f"Error getting shares: {e}")
        
        return shares
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi QNAP attivi"""
        services = []
        
        qnap_services = [
            "nginx", "smbd", "nfsd", "sshd", "rsync",
            "mariadb", "mysql", "qvs", "qmailserver",
            "apache2", "httpd", "proftpd", "vsftpd"
        ]
        
        for svc in qnap_services:
            status = "stopped"
            
            # Metodo 1: Prova systemctl
            systemctl_status = self.exec_cmd(f"systemctl is-active {svc} 2>/dev/null", timeout=2)
            if systemctl_status and systemctl_status.strip() == "active":
                status = "running"
            else:
                # Metodo 2: Fallback pgrep
                pgrep_out = self.exec_cmd(f"pgrep -x {svc} >/dev/null 2>&1 && echo 'running' || echo 'stopped'", timeout=2)
                if pgrep_out and pgrep_out.strip() == "running":
                    status = "running"
            
            services.append({
                "name": svc,
                "status": status,
            })
        
        return services
