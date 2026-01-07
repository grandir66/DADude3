"""
DaDude Agent - Cisco IOS/IOS-XE/NX-OS SSH Probe
Scansione dispositivi Cisco via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class CiscoProbe(SSHVendorProbe):
    """Probe per dispositivi Cisco IOS/IOS-XE/NX-OS"""
    
    VENDOR_NAME = "Cisco"
    DETECTION_PRIORITY = 20
    
    def detect(self) -> bool:
        """Rileva Cisco IOS/IOS-XE"""
        version = self.exec_cmd("show version", timeout=10)
        if not version:
            return False
        vl = version.lower()
        return "cisco" in vl or "ios" in vl or "ios-xe" in vl or "nx-os" in vl
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Cisco"""
        self._log_info(f"Starting probe for {target}")
        
        info = {
            "device_type": "router",
            "manufacturer": "Cisco",
            "os_name": "IOS",
            "category": "network",
        }
        
        # Show version
        version = self.exec_cmd("show version", timeout=10)
        if version:
            info.update(self._parse_show_version(version))
        
        # Hostname from running-config
        hostname_out = self.exec_cmd("show running-config | include hostname", timeout=5)
        if hostname_out:
            for line in hostname_out.split('\n'):
                if 'hostname' in line.lower():
                    parts = line.split()
                    if len(parts) > 1:
                        info["hostname"] = parts[1].strip()
        
        # Interfaces
        interfaces = self._get_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
        
        # CDP Neighbors
        neighbors = self._get_cdp_neighbors()
        if neighbors:
            info["neighbors"] = neighbors
            info["neighbors_count"] = len(neighbors)
        else:
            # Try LLDP
            neighbors = self._get_lldp_neighbors()
            if neighbors:
                info["neighbors"] = neighbors
                info["neighbors_count"] = len(neighbors)
        
        # Routing table
        routes = self._get_routes()
        if routes:
            info["routing_table"] = routes[:100]
            info["routing_count"] = len(routes)
        
        # ARP table
        arp = self._get_arp_table()
        if arp:
            info["arp_table"] = arp[:100]
            info["arp_count"] = len(arp)
        
        # VLANs (per switch)
        vlans = self._get_vlans()
        if vlans:
            info["vlans"] = vlans
            info["vlan_count"] = len(vlans)
            if not info.get("device_type") or info["device_type"] == "router":
                info["device_type"] = "switch"
        
        self._log_info(f"Probe complete for {target}: hostname={info.get('hostname')}, model={info.get('model')}")
        return info
    
    def _parse_show_version(self, output: str) -> Dict[str, Any]:
        """Parse show version output"""
        info = {}
        lines = output.split('\n')
        
        for line in lines:
            ll = line.lower()
            
            # Version
            if 'version' in ll and 'software' in ll:
                # Cisco IOS Software, ... Version X.X.X
                if 'version' in line:
                    try:
                        parts = line.split('Version')
                        if len(parts) > 1:
                            version = parts[1].strip().split()[0].rstrip(',')
                            info["os_version"] = version
                    except:
                        pass
            
            # Model/Platform
            if 'processor' in ll and 'with' in ll:
                try:
                    info["cpu_model"] = line.split('processor')[0].strip()
                except:
                    pass
            
            # Memory
            if 'bytes of memory' in ll or 'k bytes of memory' in ll:
                try:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p.isdigit() and i + 1 < len(parts) and 'bytes' in parts[i+1].lower():
                            mem_bytes = int(p)
                            info["ram_total_mb"] = mem_bytes // (1024 * 1024)
                            break
                except:
                    pass
            
            # Uptime
            if 'uptime is' in ll:
                try:
                    info["uptime"] = line.split('uptime is')[1].strip()
                except:
                    pass
            
            # Serial number
            if 'system serial number' in ll or 'processor board id' in ll:
                try:
                    parts = line.split(':')
                    if len(parts) > 1:
                        info["serial_number"] = parts[1].strip()
                except:
                    pass
            
            # Model
            if 'model number' in ll or 'model:' in ll:
                try:
                    parts = line.split(':')
                    if len(parts) > 1:
                        info["model"] = parts[1].strip().split()[0]
                except:
                    pass
        
        return info
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene lista interfacce"""
        output = self.exec_cmd("show ip interface brief", timeout=10)
        if not output:
            return []
        
        interfaces = []
        for line in output.split('\n'):
            if not line.strip() or line.startswith('Interface') or '--' in line:
                continue
            
            parts = line.split()
            if len(parts) >= 5:
                iface = {
                    "name": parts[0],
                    "ip_address": parts[1] if parts[1] != "unassigned" else "",
                    "status": parts[4] if len(parts) > 4 else "",
                    "protocol": parts[5] if len(parts) > 5 else "",
                }
                interfaces.append(iface)
        
        return interfaces
    
    def _get_cdp_neighbors(self) -> List[Dict[str, Any]]:
        """Ottiene CDP neighbors"""
        output = self.exec_cmd("show cdp neighbors detail", timeout=10)
        if not output:
            return []
        
        neighbors = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            ll = line.lower()
            
            if not line:
                if current:
                    neighbors.append(current)
                    current = {}
                continue
            
            if 'device id:' in ll:
                if current:
                    neighbors.append(current)
                current = {"discovered_by": "cdp"}
                current["remote_device_name"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'platform:' in ll and current:
                current["platform"] = line.split(':')[1].strip().split(',')[0] if ':' in line else ""
            elif 'capabilities:' in ll and current:
                current["capabilities"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'interface:' in ll and current:
                current["local_interface"] = line.split(':')[1].strip().split(',')[0] if ':' in line else ""
            elif 'port id' in ll and 'outgoing' in ll and current:
                current["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'ip address:' in ll and current:
                current["ip_address"] = line.split(':')[1].strip() if ':' in line else ""
        
        if current:
            neighbors.append(current)
        
        return neighbors
    
    def _get_lldp_neighbors(self) -> List[Dict[str, Any]]:
        """Ottiene LLDP neighbors"""
        output = self.exec_cmd("show lldp neighbors detail", timeout=10)
        if not output:
            return []
        
        neighbors = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            ll = line.lower()
            
            if not line:
                if current:
                    neighbors.append(current)
                    current = {}
                continue
            
            if 'chassis id:' in ll:
                if current:
                    neighbors.append(current)
                current = {"discovered_by": "lldp"}
                current["chassis_id"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'system name:' in ll and current:
                current["remote_device_name"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'port id:' in ll and current:
                current["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
            elif 'system description:' in ll and current:
                current["platform"] = line.split(':')[1].strip() if ':' in line else ""
        
        if current:
            neighbors.append(current)
        
        return neighbors
    
    def _get_routes(self) -> List[Dict[str, str]]:
        """Ottiene routing table"""
        output = self.exec_cmd("show ip route", timeout=10)
        if not output:
            return []
        
        routes = []
        for line in output.split('\n'):
            line = line.strip()
            # Lines starting with routing codes (C, S, R, O, D, B, i, L)
            if line and line[0] in 'CSRODBIL' and '/' in line:
                parts = line.split()
                if len(parts) >= 2:
                    route = {
                        "type": parts[0],
                        "dst": parts[1] if '/' in parts[1] else "",
                        "gateway": "",
                        "interface": "",
                    }
                    # Find gateway and interface
                    for i, p in enumerate(parts):
                        if p == 'via' and i + 1 < len(parts):
                            route["gateway"] = parts[i + 1].rstrip(',')
                        if '/' not in p and ('Eth' in p or 'Gi' in p or 'Fa' in p or 'Te' in p or 'Vlan' in p):
                            route["interface"] = p
                    routes.append(route)
        
        return routes
    
    def _get_arp_table(self) -> List[Dict[str, str]]:
        """Ottiene ARP table"""
        output = self.exec_cmd("show ip arp", timeout=10)
        if not output:
            return []
        
        arp_entries = []
        for line in output.split('\n'):
            if not line.strip() or line.startswith('Protocol') or '--' in line:
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                arp_entries.append({
                    "address": parts[1],
                    "mac_address": parts[3],
                    "interface": parts[-1] if len(parts) > 4 else "",
                })
        
        return arp_entries
    
    def _get_vlans(self) -> List[Dict[str, Any]]:
        """Ottiene VLAN list"""
        output = self.exec_cmd("show vlan brief", timeout=10)
        if not output or 'invalid' in output.lower():
            return []
        
        vlans = []
        for line in output.split('\n'):
            if not line.strip() or line.startswith('VLAN') or '--' in line:
                continue
            
            parts = line.split()
            if parts and parts[0].isdigit():
                vlans.append({
                    "id": int(parts[0]),
                    "name": parts[1] if len(parts) > 1 else "",
                    "status": parts[2] if len(parts) > 2 else "",
                })
        
        return vlans
