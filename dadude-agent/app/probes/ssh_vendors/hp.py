"""
DaDude Agent - HP SSH Probe
Scansione dispositivi HP Comware e ProCurve via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class HPProbe(SSHVendorProbe):
    """Probe per dispositivi HP (Comware e ProCurve)"""
    
    VENDOR_NAME = "HP"
    DETECTION_PRIORITY = 30
    
    def detect(self) -> bool:
        """Rileva HP Comware o ProCurve"""
        # Comware
        display_ver = self.exec_cmd("display version", timeout=5)
        if display_ver:
            dv = display_ver.lower()
            if "comware" in dv or "hp " in dv or "h3c" in dv or "hpe" in dv:
                return True
        
        # ProCurve
        show_ver = self.exec_cmd("show version", timeout=5)
        if show_ver:
            sv = show_ver.lower()
            if "procurve" in sv or "aruba" in sv or "hp " in sv:
                return True
        
        return False
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa HP"""
        # Determina se Comware o ProCurve
        display_ver = self.exec_cmd("display version", timeout=5)
        if display_ver and ("comware" in display_ver.lower() or "h3c" in display_ver.lower()):
            return self._probe_comware(target, display_ver)
        else:
            return self._probe_procurve(target)
    
    def _probe_comware(self, target: str, version_output: str) -> Dict[str, Any]:
        """Probe HP Comware"""
        self._log_info(f"Probing HP Comware at {target}")
        
        info = {
            "device_type": "switch",
            "manufacturer": "HP",
            "os_name": "Comware",
            "category": "network",
        }
        
        # Parse display version
        info.update(self._parse_comware_version(version_output))
        
        # Hostname
        hostname = self.exec_cmd("display current-configuration | include sysname", timeout=5)
        if hostname:
            for line in hostname.split('\n'):
                if 'sysname' in line.lower():
                    parts = line.split()
                    if len(parts) > 1:
                        info["hostname"] = parts[1].strip()
        
        # Interfaces
        interfaces = self._get_comware_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
        
        # LLDP neighbors
        neighbors = self._get_comware_lldp()
        if neighbors:
            info["neighbors"] = neighbors
            info["neighbors_count"] = len(neighbors)
        
        # VLANs
        vlans = self._get_comware_vlans()
        if vlans:
            info["vlans"] = vlans
            info["vlan_count"] = len(vlans)
        
        self._log_info(f"Comware probe complete: hostname={info.get('hostname')}, model={info.get('model')}")
        return info
    
    def _parse_comware_version(self, output: str) -> Dict[str, Any]:
        """Parse display version per Comware"""
        info = {}
        for line in output.split('\n'):
            ll = line.lower().strip()
            if 'software version' in ll or 'comware software' in ll:
                info["os_version"] = line.split('Version')[-1].strip() if 'Version' in line else line
            elif 'uptime' in ll:
                info["uptime"] = line.split('is')[-1].strip() if 'is' in ll else line
            elif 'cpu' in ll and 'usage' in ll:
                try:
                    # CPU usage is X%
                    for part in line.split():
                        if '%' in part:
                            info["cpu_usage"] = int(part.replace('%', ''))
                            break
                except:
                    pass
            elif 'memory' in ll and 'usage' in ll:
                try:
                    for part in line.split():
                        if '%' in part:
                            info["memory_usage"] = int(part.replace('%', ''))
                            break
                except:
                    pass
        
        # Device info from display device manuinfo
        manu = self.exec_cmd("display device manuinfo", timeout=5)
        if manu:
            for line in manu.split('\n'):
                ll = line.lower().strip()
                if 'device serial number' in ll or 'serial number' in ll:
                    info["serial_number"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'device name' in ll:
                    info["model"] = line.split(':')[-1].strip() if ':' in line else ""
        
        return info
    
    def _get_comware_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce Comware"""
        output = self.exec_cmd("display interface brief", timeout=10)
        if not output:
            return []
        
        interfaces = []
        for line in output.split('\n'):
            if not line.strip() or 'Interface' in line or '--' in line:
                continue
            parts = line.split()
            if parts and ('Eth' in parts[0] or 'GE' in parts[0] or 'XGE' in parts[0] or 'Vlan' in parts[0]):
                iface = {
                    "name": parts[0],
                    "status": parts[1] if len(parts) > 1 else "",
                    "speed": parts[2] if len(parts) > 2 else "",
                }
                interfaces.append(iface)
        
        return interfaces
    
    def _get_comware_lldp(self) -> List[Dict[str, Any]]:
        """Ottiene LLDP neighbors Comware"""
        output = self.exec_cmd("display lldp neighbor-information", timeout=10)
        if not output:
            return []
        
        neighbors = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            ll = line.lower()
            
            if 'lldp neighbor-information' in ll:
                if current:
                    neighbors.append(current)
                current = {"discovered_by": "lldp"}
            elif 'neighbor index' in ll and current:
                pass  # Skip index
            elif 'chassis id' in ll and current:
                current["chassis_id"] = line.split(':')[-1].strip() if ':' in line else ""
            elif 'port id' in ll and current:
                current["remote_interface"] = line.split(':')[-1].strip() if ':' in line else ""
            elif 'system name' in ll and current:
                current["remote_device_name"] = line.split(':')[-1].strip() if ':' in line else ""
            elif 'system description' in ll and current:
                current["platform"] = line.split(':')[-1].strip() if ':' in line else ""
        
        if current:
            neighbors.append(current)
        
        return neighbors
    
    def _get_comware_vlans(self) -> List[Dict[str, Any]]:
        """Ottiene VLANs Comware"""
        output = self.exec_cmd("display vlan brief", timeout=10)
        if not output:
            return []
        
        vlans = []
        for line in output.split('\n'):
            if not line.strip() or 'VLAN' in line or '--' in line:
                continue
            parts = line.split()
            if parts and parts[0].isdigit():
                vlans.append({
                    "id": int(parts[0]),
                    "name": parts[1] if len(parts) > 1 else "",
                    "status": parts[2] if len(parts) > 2 else "",
                })
        
        return vlans
    
    def _probe_procurve(self, target: str) -> Dict[str, Any]:
        """Probe HP ProCurve/Aruba"""
        self._log_info(f"Probing HP ProCurve at {target}")
        
        info = {
            "device_type": "switch",
            "manufacturer": "HP",
            "os_name": "ProCurve",
            "category": "network",
        }
        
        # Show version
        version = self.exec_cmd("show version", timeout=10)
        if version:
            for line in version.split('\n'):
                ll = line.lower().strip()
                if 'image stamp' in ll or 'software revision' in ll:
                    info["os_version"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'rom version' in ll:
                    info["firmware_version"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'serial number' in ll:
                    info["serial_number"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'uptime' in ll:
                    info["uptime"] = line.split(':')[-1].strip() if ':' in line else ""
        
        # Hostname
        config = self.exec_cmd("show running-config | include hostname", timeout=5)
        if config:
            for line in config.split('\n'):
                if 'hostname' in line.lower():
                    parts = line.split()
                    if len(parts) > 1:
                        info["hostname"] = parts[-1].strip().strip('"')
        
        # System info
        system = self.exec_cmd("show system", timeout=5)
        if system:
            for line in system.split('\n'):
                ll = line.lower().strip()
                if 'system name' in ll:
                    info["hostname"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'hardware rev' in ll:
                    info["hardware_version"] = line.split(':')[-1].strip() if ':' in line else ""
        
        # Interfaces
        interfaces = self.exec_cmd("show interfaces brief", timeout=10)
        if interfaces:
            info["interface_count"] = len([l for l in interfaces.split('\n') if l.strip() and not l.startswith(' ') and 'Port' not in l])
        
        # LLDP
        lldp = self.exec_cmd("show lldp info remote-device", timeout=10)
        if lldp:
            neighbors = []
            for line in lldp.split('\n'):
                if line.strip() and not line.startswith('LocalPort') and '|' in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 3:
                        neighbors.append({
                            "local_interface": parts[0],
                            "chassis_id": parts[1],
                            "remote_interface": parts[2],
                            "discovered_by": "lldp"
                        })
            if neighbors:
                info["neighbors"] = neighbors
                info["neighbors_count"] = len(neighbors)
        
        self._log_info(f"ProCurve probe complete: hostname={info.get('hostname')}")
        return info
