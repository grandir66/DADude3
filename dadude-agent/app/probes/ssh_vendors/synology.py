"""
DaDude Agent - Synology DSM SSH Probe
Scansione dispositivi Synology NAS via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class SynologyProbe(SSHVendorProbe):
    """Probe per Synology DSM NAS"""
    
    VENDOR_NAME = "Synology"
    DETECTION_PRIORITY = 40
    
    def detect(self) -> bool:
        """Rileva Synology DSM"""
        syno = self.exec_cmd("cat /etc/synoinfo.conf 2>/dev/null", timeout=3)
        return bool(syno and 'synology' in syno.lower())
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Synology DSM"""
        self._log_info(f"Probing Synology at {target}")
        
        info = {
            "device_type": "storage",
            "manufacturer": "Synology",
            "os_name": "DSM",
            "category": "storage",
            "os_family": "Linux",
        }
        
        try:
            # synoinfo.conf
            syno_conf = self.exec_cmd("cat /etc/synoinfo.conf 2>/dev/null", timeout=3)
            if syno_conf:
                parsed = self._parse_synoinfo(syno_conf)
                info.update(parsed)
                self._log_debug(f"synoinfo parsed: {list(parsed.keys())}")
            
            # Hostname
            hostname = self.exec_cmd("hostname", timeout=3)
            if hostname:
                info["hostname"] = hostname.strip()
            
            # DSM version
            version = self.exec_cmd("cat /etc.defaults/VERSION 2>/dev/null || cat /etc/VERSION 2>/dev/null", timeout=3)
            if version:
                parsed = self._parse_version(version)
                info.update(parsed)
                self._log_debug(f"version parsed: {list(parsed.keys())}")
            
            # Hardware info
            hw = self._get_hardware_info()
            info.update(hw)
            self._log_debug(f"hardware info: {list(hw.keys())}")
            
            # Storage info (volumi, RAID, dischi)
            storage = self._get_storage_info()
            if storage:
                info.update(storage)
                self._log_info(f"storage info: volumes={storage.get('volumes_count', 0)}, raid={storage.get('raid_count', 0)}, disks={storage.get('disks_count', 0)}")
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
            
            # Packages installed
            packages = self._get_packages()
            if packages:
                info["packages"] = packages
                info["packages_count"] = len(packages)
            
            # Shares (SMB/NFS/AFP)
            shares = self._get_shares()
            if shares:
                info["shares"] = shares
                info["shares_count"] = len(shares)
                self._log_info(f"shares collected: {len(shares)}")
        except Exception as e:
            self._log_error(f"Error during probe: {e}")
        
        self._log_info(f"Synology probe complete: hostname={info.get('hostname')}, model={info.get('model')}, fields={len(info)}, volumes={len(info.get('volumes', []))}, disks={len(info.get('disks', []))}, shares={len(info.get('shares', []))}")
        return info
    
    def _parse_synoinfo(self, content: str) -> Dict[str, Any]:
        """Parse /etc/synoinfo.conf"""
        info = {}
        for line in content.split('\n'):
            if '=' in line and not line.strip().startswith('#'):
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip().strip('"')
                
                if key == 'upnpmodelname':
                    info["model"] = value
                elif key == 'unique':
                    info["serial_number"] = value
                elif key == 'upnpmodelnumber':
                    info["model_number"] = value
                elif key == 'upnpmodeldescription':
                    info["description"] = value
        return info
    
    def _parse_version(self, content: str) -> Dict[str, Any]:
        """Parse VERSION file"""
        info = {}
        for line in content.split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
                value = value.strip().strip('"')
                
                if key == 'productversion':
                    info["os_version"] = value
                elif key == 'buildnumber':
                    info["build_number"] = value
                elif key == 'smallfixnumber':
                    info["hotfix"] = value
        return info
    
    def _parse_size(self, size_str: str) -> int:
        """
        Converte stringa size (es: '8.0T', '500G', '100M') in bytes.
        """
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
            
            # Prova a parsare come numero puro (bytes)
            return int(float(size_str))
        except (ValueError, TypeError):
            return 0
    
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
    
    def _get_storage_info(self) -> Dict[str, Any]:
        """Ottiene informazioni storage (volumi, RAID, dischi)"""
        info = {}
        volumes = []
        
        try:
            # Metodo 1: Usa synospace --enum volume per informazioni dettagliate volumi
            synospace_enum = self.exec_cmd_sudo("/usr/syno/bin/synospace --enum volume 2>/dev/null", timeout=5)
            if synospace_enum:
                self._log_info(f"synospace --enum volume output length: {len(synospace_enum)}, preview: {synospace_enum[:500]}")
            else:
                self._log_info(f"synospace --enum volume output: None")
            volume_details = {}
            if synospace_enum:
                # Parse synospace --enum volume output
                import re
                volume_blocks = re.split(r'<<<<<<<<<<<<\s+\[([^\]]+)\]\s+>>>>>>>>>>>>', synospace_enum)
                for i in range(1, len(volume_blocks), 2):
                    mount_point = volume_blocks[i].strip()
                    block = volume_blocks[i+1] if i+1 < len(volume_blocks) else ""
                    
                    vol_data = {"mount_point": mount_point}
                    for line in block.split('\n'):
                        if 'Device Type:' in line:
                            match = re.search(r'\[(.*?)\]', line)
                            if match:
                                vol_data['device_type'] = match.group(1)
                        elif 'Status:' in line:
                            match = re.search(r'\[(.*?)\]', line)
                            if match:
                                vol_data['status'] = match.group(1)
                        elif 'Pool Path:' in line:
                            match = re.search(r'\[(.*?)\]', line)
                            if match:
                                vol_data['pool_path'] = match.group(1)
                        elif 'Device Size:' in line:
                            match = re.search(r'\[(\d+)\]', line)
                            if match:
                                vol_data['size_bytes'] = int(match.group(1))
                        elif 'UUID:' in line:
                            match = re.search(r'\[(.*?)\]', line)
                            if match:
                                vol_data['uuid'] = match.group(1)
                        elif 'raid type=' in line:
                            match = re.search(r'raid type=\[(.*?)\]', line)
                            if match:
                                vol_data['raid_type'] = match.group(1)
                        elif 'device path = ' in line:
                            match = re.search(r'device path = \[(.*?)\]', line)
                            if match:
                                vol_data['raid_device'] = match.group(1)
                    
                    if vol_data.get('mount_point', '').startswith('/volume'):
                        volume_details[vol_data['mount_point']] = vol_data
            
            # Metodo 2: Usa synospace --get-volume-list per nomi volumi
            synospace = self.exec_cmd_sudo("/usr/syno/bin/synospace --get-volume-list 2>/dev/null", timeout=5)
            volume_names = {}
            if synospace:
                for line in synospace.split('\n'):
                    if line.strip() and 'volume' in line.lower():
                        # Estrai nome volume (es: "volume1" o "volume_1")
                        parts = line.strip().split()
                        if parts:
                            vol_id = parts[0]
                            vol_name = parts[-1] if len(parts) > 1 else vol_id
                            volume_names[vol_id] = vol_name
            
            # Metodo 2: df -T per ottenere volumi con tipo filesystem
            df_out = self.exec_cmd("df -T 2>/dev/null | grep -E '^/dev/|/volume'", timeout=5)
            if df_out:
                for line in df_out.split('\n'):
                    parts = line.split()
                    if len(parts) >= 7 and '/volume' in line:
                        mount_point = parts[6]
                        filesystem = parts[1] if len(parts) > 1 else "ext4"
                        
                        # Estrai nome volume dal mount_point o da synospace
                        vol_id = mount_point.replace('/', '').replace('volume', 'volume')
                        vol_name = volume_names.get(vol_id, vol_id)
                        if not vol_name or vol_name == vol_id:
                            # Fallback: usa ultima parte del path
                            vol_name = mount_point.split('/')[-1] or mount_point.replace('/', '_').strip('_')
                        
                        # Parse use_percent (rimuovi % se presente) - parts[5] contiene Use%
                        use_percent_str = parts[5].replace('%', '') if len(parts) > 5 else "0"
                        try:
                            use_percent = float(use_percent_str)
                        except (ValueError, TypeError):
                            use_percent = 0
                        
                        # Parse sizes - Synology df -T: parts[2]=1K-blocks, parts[3]=Used, parts[4]=Available
                        # Se i valori sono molto grandi, potrebbero essere già in bytes invece di KB
                        try:
                            total_val = parts[2] if len(parts) > 2 else "0"
                            used_val = parts[3] if len(parts) > 3 else "0"
                            available_val = parts[4] if len(parts) > 4 else "0"
                            
                            # Prova a parsare come interi
                            total_int = int(total_val)
                            used_int = int(used_val)
                            available_int = int(available_val)
                            
                            # Se i valori sono molto grandi (>1TB), probabilmente sono già in bytes
                            # Altrimenti sono in KB (1K-blocks)
                            if total_int > 1000000000:  # > 1TB in bytes
                                total_bytes = total_int
                                used_bytes = used_int
                                available_bytes = available_int
                            else:
                                # Sono in KB, converti in bytes
                                total_bytes = total_int * 1024
                                used_bytes = used_int * 1024
                                available_bytes = available_int * 1024
                        except (ValueError, TypeError):
                            # Fallback: usa _parse_size
                            total_bytes = self._parse_size(total_val)
                            used_bytes = self._parse_size(used_val)
                            available_bytes = self._parse_size(available_val)
                        
                        # Arricchisci con dettagli da synospace --enum volume
                        vol_detail = volume_details.get(mount_point, {})
                        
                        volume_data = {
                            "name": vol_name,
                            "mount_point": mount_point,
                            "path": mount_point,
                            "device": parts[0],
                            "filesystem": filesystem,
                            "total": parts[2] + "K" if len(parts) > 2 else "",  # 1K-blocks
                            "used": parts[3] + "K" if len(parts) > 3 else "",   # Used in KB
                            "available": parts[4] + "K" if len(parts) > 4 else "",  # Available in KB
                            "use_percent": use_percent,
                            "total_bytes": total_bytes,
                            "used_bytes": used_bytes,
                            "available_bytes": available_bytes,
                        }
                        
                        # Aggiungi dettagli da synospace --enum volume
                        if vol_detail:
                            volume_data["pool_path"] = vol_detail.get("pool_path", "")
                            volume_data["device_type"] = vol_detail.get("device_type", "")
                            volume_data["volume_status"] = vol_detail.get("status", "")
                            volume_data["uuid"] = vol_detail.get("uuid", "")
                            volume_data["raid_type"] = vol_detail.get("raid_type", "")
                            volume_data["raid_device"] = vol_detail.get("raid_device", "")
                            if vol_detail.get("size_bytes"):
                                volume_data["size_bytes"] = vol_detail["size_bytes"]
                        
                        volumes.append(volume_data)
            
            # Metodo 2: Cerca volumi esplicitamente
            if not volumes:
                vol_list = self.exec_cmd("ls -d /volume* 2>/dev/null", timeout=3)
                if vol_list:
                    for vol_path in vol_list.split('\n'):
                        if vol_path.strip():
                            df_line = self.exec_cmd(f"df -h {vol_path.strip()} 2>/dev/null | tail -1", timeout=3)
                            if df_line:
                                parts = df_line.split()
                                if len(parts) >= 5:
                                    volumes.append({
                                        "name": vol_path.strip().split('/')[-1],
                                        "path": vol_path.strip(),
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
        
        # RAID info via mdstat + mdadm --detail per informazioni complete
        raid_info = []
        mdstat = self.exec_cmd("cat /proc/mdstat 2>/dev/null", timeout=3)
        if mdstat and 'md' in mdstat:
            import re
            current_md = None
            md_devices = []
            
            for line in mdstat.split('\n'):
                if line.startswith('md'):
                    parts = line.split()
                    if parts:
                        md_name = parts[0].rstrip(':')
                        md_devices.append(md_name)
            
            # Per ogni dispositivo md, ottieni dettagli con mdadm --detail
            for md_name in md_devices:
                md_detail = self.exec_cmd(f"mdadm --detail /dev/{md_name} 2>/dev/null", timeout=5)
                if md_detail:
                    raid_data = {
                        "name": f"/dev/{md_name}",
                        "devices": [],
                    }
                    
                    for detail_line in md_detail.split('\n'):
                        detail_lower = detail_line.lower()
                        if 'raid level' in detail_lower:
                            raid_data["level"] = detail_line.split(':')[1].strip() if ':' in detail_line else ""
                        elif 'state' in detail_lower and 'update time' not in detail_lower:
                            raid_data["status"] = detail_line.split(':')[1].strip() if ':' in detail_line else ""
                        elif 'array size' in detail_lower:
                            size_match = re.search(r'\(([\d.]+)\s+GiB', detail_line)
                            if size_match:
                                raid_data["total_size_gb"] = float(size_match.group(1))
                        elif 'raid devices' in detail_lower:
                            raid_data["disk_count"] = int(detail_line.split(':')[1].strip()) if ':' in detail_line else 0
                        elif 'active devices' in detail_lower:
                            raid_data["active_devices"] = int(detail_line.split(':')[1].strip()) if ':' in detail_line else 0
                        elif 'failed devices' in detail_lower:
                            raid_data["failed_devices"] = int(detail_line.split(':')[1].strip()) if ':' in detail_line else 0
                        # Cerca dispositivi in varie forme: /dev/sdX, /dev/sdX[Y], /dev/nvmeXnY, etc.
                        elif ('/dev/' in detail_line and ('active' in detail_lower or 'sync' in detail_lower or 'spare' in detail_lower)):
                            # Pattern più flessibile per dispositivi
                            disk_patterns = [
                                r'(/dev/sd[a-z]+\d*)',  # /dev/sda, /dev/sda1
                                r'(/dev/nvme\d+n\d+)',  # /dev/nvme0n1
                                r'(/dev/nvme\d+n\d+p\d+)',  # /dev/nvme0n1p1
                                r'(/dev/[a-z]+\d+)',  # Altri dispositivi
                            ]
                            for pattern in disk_patterns:
                                disk_match = re.search(pattern, detail_line)
                                if disk_match:
                                    device_name = disk_match.group(1)
                                    # Estrai status dalla riga
                                    status = "active sync"
                                    if 'spare' in detail_lower:
                                        status = "spare"
                                    elif 'faulty' in detail_lower or 'failed' in detail_lower:
                                        status = "faulty"
                                    raid_data["devices"].append({
                                        "device": device_name,
                                        "status": status
                                    })
                                    break
                    
                    if "level" in raid_data:
                        raid_info.append(raid_data)
                else:
                    # Fallback: parsing semplice da mdstat
                    for line in mdstat.split('\n'):
                        if line.startswith(md_name):
                            parts = line.split()
                            if parts:
                                current_md = {
                                    "name": f"/dev/{md_name}",
                                    "status": parts[1] if len(parts) > 1 else "",
                                    "level": "",
                                    "devices": [],
                                }
                                # Cerca tipo RAID (raid1, raid5, raid6, etc.)
                                for p in parts:
                                    if p.startswith('raid'):
                                        current_md["level"] = p
                                raid_info.append(current_md)
                                break
        
        if raid_info:
            info["raid_arrays"] = raid_info
            info["raid_count"] = len(raid_info)
        
        # Dischi fisici - usa synodisk --enum -t internal per informazioni native Synology
        disks = []
        synodisk_output = self.exec_cmd_sudo("/usr/syno/bin/synodisk --enum -t internal 2>/dev/null", timeout=5)
        self._log_info(f"synodisk --enum -t internal output length: {len(synodisk_output) if synodisk_output else 0}, preview: {synodisk_output[:500] if synodisk_output else 'None'}")
        disk_details = {}
        
        if synodisk_output:
            # Parse synodisk output
            import re
            disk_blocks = synodisk_output.split('************ Disk Info ***************')
            for block in disk_blocks[1:]:  # Skip first empty block
                disk_data = {}
                disk_path = None
                for line in block.strip().split('\n'):
                    if '>> Disk id:' in line:
                        disk_data['disk_id'] = int(line.split(':')[1].strip())
                    elif '>> Disk path:' in line:
                        disk_path = line.split(':')[1].strip()
                        disk_data['disk_path'] = disk_path
                    elif '>> Disk model:' in line:
                        disk_data['model'] = line.split(':', 1)[1].strip()
                    elif '>> Total capacity:' in line:
                        capacity_str = line.split(':')[1].strip().split()[0]
                        try:
                            disk_data['capacity_gb'] = float(capacity_str)
                        except:
                            pass
                    elif '>> Tempeture:' in line or '>> Temperature:' in line:  # Typo nel comando Synology
                        temp_str = line.split(':')[1].strip().split()[0]
                        try:
                            disk_data['temperature'] = int(temp_str)
                        except:
                            pass
                    elif '>> Slot id:' in line or '>> Slot:' in line or 'slot' in line.lower():
                        try:
                            slot_val = line.split(':')[1].strip() if ':' in line else line.split()[-1]
                            disk_data['slot_id'] = int(slot_val)
                        except:
                            # Prova a cercare il numero nella riga
                            slot_match = re.search(r'(\d+)', line)
                            if slot_match:
                                try:
                                    disk_data['slot_id'] = int(slot_match.group(1))
                                except:
                                    pass
                
                if disk_path:
                    disk_details[disk_path] = disk_data
                    # Aggiungi anche senza /dev/ per matching più flessibile
                    if disk_path.startswith('/dev/'):
                        disk_details[disk_path[5:]] = disk_data
                    self._log_debug(f"Parsed disk: path={disk_path}, id={disk_data.get('disk_id')}, model={disk_data.get('model')}, slot={disk_data.get('slot_id', 'N/A')}, temp={disk_data.get('temperature', 'N/A')}")
        
        # Usa lsblk con più colonne per ottenere tipo, modello, seriale
        lsblk = self.exec_cmd("lsblk -d -o NAME,SIZE,MODEL,SERIAL,TYPE,TRAN 2>/dev/null | tail -n +2", timeout=5)
        if lsblk:
            for line in lsblk.split('\n'):
                if line.strip() and not line.startswith('NAME'):
                    parts = line.split()
                    if parts and (parts[0].startswith('sd') or parts[0].startswith('nvme') or parts[0].startswith('hd')):
                        disk_path = f"/dev/{parts[0]}"
                        # Cerca match in disk_details con diversi formati
                        syno_disk = disk_details.get(disk_path, {})
                        if not syno_disk:
                            syno_disk = disk_details.get(parts[0], {})  # Senza /dev/
                        if not syno_disk:
                            # Cerca per device name senza numero (es: sda invece di sda1)
                            base_name = parts[0].rstrip('0123456789')
                            syno_disk = disk_details.get(f"/dev/{base_name}", {})
                            if not syno_disk:
                                syno_disk = disk_details.get(base_name, {})
                        
                        disk = {
                            "name": disk_path,
                            "device": parts[0],
                            "size": parts[1] if len(parts) > 1 else "",
                            "size_bytes": self._parse_size(parts[1]) if len(parts) > 1 else 0,
                            "model": ' '.join(parts[2:-3]) if len(parts) > 5 else (parts[2] if len(parts) > 2 else ""),
                            "serial": parts[-3] if len(parts) > 5 else (parts[-1] if len(parts) > 3 else ""),
                            "type": parts[-2] if len(parts) > 4 else "",
                            "transport": parts[-1] if len(parts) > 5 else "",
                        }
                        
                        # Arricchisci con dati da synodisk
                        if syno_disk:
                            if syno_disk.get('disk_id') is not None:
                                disk["disk_id"] = syno_disk['disk_id']
                            if syno_disk.get('slot_id') is not None:
                                disk["slot_id"] = syno_disk['slot_id']
                            if syno_disk.get('model'):
                                disk["model"] = syno_disk['model']
                            if syno_disk.get('capacity_gb'):
                                disk["capacity_gb"] = syno_disk['capacity_gb']
                                disk["size_bytes"] = int(syno_disk['capacity_gb'] * 1024 * 1024 * 1024)
                            if syno_disk.get('temperature') is not None:
                                disk["temperature"] = syno_disk['temperature']
                                disk["temperature_celsius"] = syno_disk['temperature']
                        
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
                # Nuovo interface
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
        
        # Filtra loopback e virtual
        return [i for i in interfaces if not i["name"].startswith("lo") and not i["name"].startswith("docker")]
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi Synology attivi"""
        services = []
        
        # Metodo 1: Usa synoservicectl se disponibile (metodo Synology nativo)
        synoservicectl = self.exec_cmd("which synoservicectl 2>/dev/null || which /usr/syno/bin/synoservicectl 2>/dev/null", timeout=2)
        if synoservicectl:
            # Lista servizi Synology
            syno_services = [
                "nginx", "smbd", "nfsd", "sshd", "rsync", 
                "synoscgi", "synologyd", "synomount", "synolog"
            ]
            
            for svc in syno_services:
                # Verifica stato con synoservicectl
                status_cmd = f"/usr/syno/bin/synoservicectl --status {svc} 2>/dev/null || synoservicectl --status {svc} 2>/dev/null"
                status_out = self.exec_cmd(status_cmd, timeout=3)
                if status_out:
                    status_lower = status_out.lower()
                    if 'running' in status_lower or 'started' in status_lower or 'active' in status_lower:
                        status = "running"
                    else:
                        status = "stopped"
                else:
                    # Fallback: usa pgrep
                    pgrep_out = self.exec_cmd(f"pgrep -x {svc} >/dev/null 2>&1 && echo 'running' || echo 'stopped'", timeout=2)
                    status = pgrep_out.strip() if pgrep_out else "stopped"
                
                services.append({
                    "name": svc,
                    "status": status,
                })
        else:
            # Metodo 2: Fallback con pgrep e systemctl
            syno_services = [
                "nginx", "smbd", "nfsd", "sshd", "rsync", 
                "synoscgi", "synologyd", "synomount", "synolog"
            ]
            
            for svc in syno_services:
                # Prova systemctl prima
                systemctl_status = self.exec_cmd(f"systemctl is-active {svc} 2>/dev/null", timeout=2)
                if systemctl_status and systemctl_status.strip() == "active":
                    status = "running"
                else:
                    # Fallback pgrep
                    pgrep_out = self.exec_cmd(f"pgrep -x {svc} >/dev/null 2>&1 && echo 'running' || echo 'stopped'", timeout=2)
                    status = pgrep_out.strip() if pgrep_out else "stopped"
                
                services.append({
                    "name": svc,
                    "status": status,
                })
        
        return services
    
    def _get_packages(self) -> List[Dict[str, Any]]:
        """Ottiene packages Synology installati"""
        packages = []
        
        pkg_list = self.exec_cmd("ls /var/packages 2>/dev/null", timeout=3)
        if pkg_list:
            for pkg in pkg_list.split():
                if pkg.strip():
                    packages.append({"name": pkg.strip()})
        
        return packages[:50]  # Limita a 50
    
    def _get_shares(self) -> List[Dict[str, Any]]:
        """Ottiene share SMB/NFS esposte"""
        shares = []
        
        try:
            # Metodo 1: Usa synoshare se disponibile
            synoshare = self.exec_cmd_sudo("/usr/syno/bin/synoshare --enum ALL 2>/dev/null", timeout=5)
            self._log_info(f"synoshare --enum ALL output length: {len(synoshare) if synoshare else 0}, preview: {synoshare[:500] if synoshare else 'None'}")
            
            # Metodo alternativo: Leggi direttamente /etc/samba/smb.conf se synoshare non funziona
            if not synoshare or len(synoshare.strip()) == 0:
                self._log_info("synoshare --enum ALL returned empty, trying alternative methods")
                # Prova a leggere smb.conf direttamente
                smb_conf = self.exec_cmd("cat /etc/samba/smb.conf 2>/dev/null | grep -E '^\\[.*\\]' | grep -v '^\\[global\\]' | grep -v '^\\[homes\\]' | grep -v '^\\[printers\\]'", timeout=3)
                self._log_info(f"smb.conf shares found: {len(smb_conf.split()) if smb_conf else 0}, preview: {smb_conf[:200] if smb_conf else 'None'}")
                if smb_conf:
                    for line in smb_conf.split('\n'):
                        line = line.strip()
                        if line.startswith('[') and line.endswith(']'):
                            share_name = line[1:-1]
                            if share_name:
                                # Verifica se la share esiste e ottieni path
                                share_path_cmd = self.exec_cmd(f"grep -A 5 '^\\[{share_name}\\]' /etc/samba/smb.conf 2>/dev/null | grep 'path\\s*=' | head -1", timeout=2)
                                share_path = f"/volume1/{share_name}"  # Default
                                if share_path_cmd:
                                    path_match = share_path_cmd.split('=')[-1].strip() if '=' in share_path_cmd else None
                                    if path_match:
                                        share_path = path_match
                                
                                # Verifica protocolli abilitati
                                share_types = []
                                # Verifica SMB
                                if self.exec_cmd(f"grep -q '^\\[{share_name}\\]' /etc/samba/smb.conf 2>/dev/null", timeout=1):
                                    share_types.append("SMB")
                                # Verifica NFS
                                nfs_exports = self.exec_cmd(f"grep -E '^[^#].*{share_name}' /etc/exports 2>/dev/null", timeout=2)
                                if nfs_exports:
                                    share_types.append("NFS")
                                
                                shares.append({
                                    "name": share_name,
                                    "types": share_types if share_types else ["SMB"],
                                    "path": share_path,
                                })
                                self._log_info(f"Found share via smb.conf: {share_name}, path={share_path}, types={share_types}")
                
                # Se ancora non abbiamo trovato shares, prova a leggere direttamente il file
                if not shares:
                    self._log_info("No shares found via smb.conf grep, trying direct file read")
                    smb_conf_full = self.exec_cmd("cat /etc/samba/smb.conf 2>/dev/null", timeout=3)
                    if smb_conf_full:
                        self._log_info(f"smb.conf full file length: {len(smb_conf_full)}, preview: {smb_conf_full[:500]}")
                        # Parse manuale del file
                        current_section = None
                        for line in smb_conf_full.split('\n'):
                            line = line.strip()
                            if line.startswith('[') and line.endswith(']'):
                                current_section = line[1:-1]
                                if current_section not in ['global', 'homes', 'printers']:
                                    # Nuova share trovata
                                    share_path = f"/volume1/{current_section}"
                                    shares.append({
                                        "name": current_section,
                                        "types": ["SMB"],
                                        "path": share_path,
                                    })
                                    self._log_info(f"Found share via direct parse: {current_section}")
                            elif current_section and 'path' in line.lower() and '=' in line:
                                # Aggiorna path se trovato
                                path_val = line.split('=')[-1].strip()
                                if path_val and '/' in path_val:
                                    for share in shares:
                                        if share['name'] == current_section:
                                            share['path'] = path_val
                                            break
            
            if synoshare and len(synoshare.strip()) > 0:
                # Il formato di synoshare --enum ALL può essere:
                # - Una lista di share, una per riga
                # - Formato con sezioni [share_name]
                lines = synoshare.split('\n')
                current_share = None
                
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    # Se la riga inizia con [ e finisce con ], è il nome di una share
                    if line.startswith('[') and line.endswith(']'):
                        current_share = line[1:-1].strip()
                        continue
                    
                    # Se abbiamo una share corrente e la riga contiene informazioni
                    if current_share:
                        share_name = current_share
                    else:
                        # Altrimenti, il nome della share è la prima parte della riga
                        share_name = line.split()[0] if line.split() else None
                    
                    if share_name:
                            # Verifica tipo share con synoshare --get
                                share_info = self.exec_cmd_sudo(f"/usr/syno/bin/synoshare --get {share_name} 2>/dev/null", timeout=3)
                            share_type = []
                            share_path = f"/volume1/{share_name}"  # Default path
                            
                            if share_info:
                                # Estrai informazioni dalla risposta
                                for info_line in share_info.split('\n'):
                                    info_lower = info_line.lower()
                                    if 'smb' in info_lower or 'cifs' in info_lower:
                                        if "SMB" not in share_type:
                                            share_type.append("SMB")
                                    if 'nfs' in info_lower:
                                        if "NFS" not in share_type:
                                            share_type.append("NFS")
                                    if 'afp' in info_lower:
                                        if "AFP" not in share_type:
                                            share_type.append("AFP")
                                    # Cerca path nella risposta
                                    if 'path' in info_lower or 'volume' in info_lower:
                                        # Estrai path se presente
                                        if '=' in info_line:
                                            path_val = info_line.split('=')[-1].strip()
                                            if path_val and '/' in path_val:
                                                share_path = path_val
                            
                            shares.append({
                                "name": share_name,
                                "types": share_type if share_type else ["SMB"],  # Default SMB
                                "path": share_path,
                            })
            else:
                # Metodo 2: Leggi /etc/samba/smb.conf
                smb_conf = self.exec_cmd("cat /etc/samba/smb.conf 2>/dev/null | grep -E '^\\[.*\\]' | grep -v '^\\[global\\]' | grep -v '^\\[homes\\]'", timeout=3)
                if smb_conf:
                    for line in smb_conf.split('\n'):
                        if line.strip().startswith('[') and line.strip().endswith(']'):
                            share_name = line.strip()[1:-1]
                            shares.append({
                                "name": share_name,
                                "types": ["SMB"],
                                "path": f"/volume1/{share_name}",
                            })
        except Exception as e:
            self._log_warning(f"Error getting shares: {e}")
        
        return shares