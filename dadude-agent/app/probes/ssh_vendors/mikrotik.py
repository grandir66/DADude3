"""
DaDude Agent - MikroTik RouterOS SSH Probe
Scansione dispositivi MikroTik via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class MikroTikProbe(SSHVendorProbe):
    """Probe per dispositivi MikroTik RouterOS"""
    
    VENDOR_NAME = "MikroTik"
    DETECTION_PRIORITY = 10  # Alta priorità (RouterOS ha sintassi molto specifica)
    
    def detect(self) -> bool:
        """Rileva MikroTik RouterOS"""
        ros_out = self.exec_cmd("/system resource print", timeout=5)
        return (
            "version:" in ros_out.lower() or 
            "uptime:" in ros_out.lower() or 
            "routeros" in ros_out.lower()
        )
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa MikroTik RouterOS"""
        self._log_info(f"Starting probe for {target}")
        
        info = {
            "device_type": "router",
            "manufacturer": "MikroTik",
            "os_name": "RouterOS",
            "category": "network",
        }
        
        # System Resource
        resource = self.exec_cmd("/system resource print", timeout=5)
        if resource:
            info.update(self._parse_system_resource(resource))
        
        # System Identity (hostname)
        identity = self.exec_cmd("/system identity print", timeout=3)
        if identity:
            for line in identity.split('\n'):
                if 'name:' in line.lower():
                    info["hostname"] = line.split(':', 1)[1].strip()
                    break
        
        # RouterBoard info (hardware)
        rb_info = self.exec_cmd("/system routerboard print", timeout=3)
        if rb_info:
            info.update(self._parse_routerboard(rb_info))
        
        # License
        license_out = self.exec_cmd("/system license print", timeout=3)
        if license_out:
            for line in license_out.split('\n'):
                if 'level:' in line.lower():
                    info["license_level"] = line.split(':', 1)[1].strip()
        
        # Interface count
        iface_count = self.exec_cmd("/interface print count-only", timeout=3)
        if iface_count and iface_count.isdigit():
            info["interface_count"] = int(iface_count)
        
        # Interfaces detail
        interfaces = self._get_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
        
        # Neighbors (LLDP/CDP/MNDP)
        neighbors = self._get_neighbors()
        if neighbors:
            info["neighbors"] = neighbors
            info["neighbors_count"] = len(neighbors)
        
        # Routing table
        routes = self._get_routes()
        if routes:
            info["routing_table"] = routes
            info["routing_count"] = len(routes)
        
        # ARP table
        arp = self._get_arp_table()
        if arp:
            info["arp_table"] = arp
            info["arp_count"] = len(arp)
        
        # DHCP leases (solo se router)
        leases = self._get_dhcp_leases()
        if leases:
            info["dhcp_leases"] = leases
            info["dhcp_leases_count"] = len(leases)
        
        # Firewall rules count
        fw_count = self.exec_cmd("/ip firewall filter print count-only", timeout=3)
        if fw_count and fw_count.isdigit():
            info["firewall_rules_count"] = int(fw_count)
        
        self._log_info(f"Probe complete for {target}: hostname={info.get('hostname')}, model={info.get('model')}")
        return info
    
    def _parse_system_resource(self, output: str) -> Dict[str, Any]:
        """Parse /system resource print"""
        info = {}
        for line in output.split('\n'):
            ll = line.lower().strip()
            if ll.startswith('version:'):
                info["os_version"] = line.split(':', 1)[1].strip()
            elif ll.startswith('board-name:'):
                info["model"] = line.split(':', 1)[1].strip()
            elif ll.startswith('cpu:') and 'cpu-count' not in ll:
                info["cpu_model"] = line.split(':', 1)[1].strip()
            elif ll.startswith('cpu-count:'):
                info["cpu_cores"] = self._safe_int(line.split(':', 1)[1])
            elif ll.startswith('cpu-load:'):
                load_str = line.split(':', 1)[1].strip().replace('%', '')
                info["cpu_usage"] = self._safe_int(load_str)
            elif ll.startswith('total-memory:'):
                mem_str = line.split(':', 1)[1].strip()
                if 'MiB' in mem_str:
                    info["ram_total_mb"] = self._safe_int(mem_str.replace('MiB', ''))
                elif 'GiB' in mem_str:
                    info["ram_total_mb"] = self._safe_int(float(mem_str.replace('GiB', '')) * 1024)
            elif ll.startswith('free-memory:'):
                mem_str = line.split(':', 1)[1].strip()
                if 'MiB' in mem_str:
                    info["ram_free_mb"] = self._safe_int(mem_str.replace('MiB', ''))
            elif ll.startswith('architecture-name:'):
                info["architecture"] = line.split(':', 1)[1].strip()
            elif ll.startswith('uptime:'):
                info["uptime"] = line.split(':', 1)[1].strip()
            elif ll.startswith('bad-blocks:'):
                info["bad_blocks"] = line.split(':', 1)[1].strip()
            elif ll.startswith('total-hdd-space:'):
                info["disk_total"] = line.split(':', 1)[1].strip()
            elif ll.startswith('free-hdd-space:'):
                info["disk_free"] = line.split(':', 1)[1].strip()
        return info
    
    def _parse_routerboard(self, output: str) -> Dict[str, Any]:
        """Parse /system routerboard print"""
        info = {}
        for line in output.split('\n'):
            ll = line.lower().strip()
            if ll.startswith('serial-number:'):
                info["serial_number"] = line.split(':', 1)[1].strip()
            elif ll.startswith('model:') and not info.get("model"):
                info["model"] = line.split(':', 1)[1].strip()
            elif ll.startswith('current-firmware:'):
                info["firmware_version"] = line.split(':', 1)[1].strip()
            elif ll.startswith('upgrade-firmware:'):
                info["firmware_upgrade_available"] = line.split(':', 1)[1].strip()
        return info
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene lista interfacce con tutti i dettagli"""
        # 1. Interfacce base
        output = self.exec_cmd("/interface print terse", timeout=10)
        if not output:
            return []
        
        interfaces = []
        interface_dict = {}  # Key: name, Value: interface dict
        
        # Parse interfacce base
        # MikroTik terse format: flags=flags name="ether1" type=ether mtu=1500 mac-address=...
        # Flags: R=Running, D=Disabled, X=Disabled by other config
        parsed_items = self._parse_terse_output(output)
        self._log_debug(f"Parsed {len(parsed_items)} interface items from terse output")
        
        for idx, item in enumerate(parsed_items):
            # Log primo item per debug
            if idx == 0:
                self._log_debug(f"First parsed item keys: {list(item.keys())}")
                self._log_debug(f"First parsed item: {item}")
            
            name = item.get("name", "")
            if not name:
                self._log_warning(f"Skipping interface item {idx}: no name field")
                continue
            
            # Parse flags per determinare stato
            flags = item.get("flags", "").upper()
            running = "R" in flags or item.get("running", "").lower() == "true"
            disabled = "D" in flags or "X" in flags or item.get("disabled", "").lower() == "true"
            
            # Estrai MAC address - può essere in formato diverso
            mac_address = item.get("mac-address", "") or item.get("mac", "") or ""
            # Se MAC è un numero, probabilmente è sbagliato - salta
            if mac_address and mac_address.isdigit():
                self._log_warning(f"Interface {name}: MAC address looks like a number ({mac_address}), skipping")
                mac_address = ""
            
            iface = {
                "name": name,
                "type": item.get("type", ""),
                "mac_address": mac_address,
                "mtu": self._safe_int(item.get("mtu")),
                "running": running,
                "disabled": disabled,
                "admin_status": "up" if not disabled else "down",
                "oper_status": "up" if running else "down",
                "ip_addresses": [],
                "vlan_id": None,
                "speed": None,
                "duplex": None,
                "description": item.get("comment", ""),
                "rx_bytes": 0,
                "tx_bytes": 0,
            }
            interface_dict[name] = iface
        
        # 2. IP addresses per interfaccia
        ip_output = self.exec_cmd("/ip address print terse", timeout=5)
        if ip_output:
            for item in self._parse_terse_output(ip_output):
                interface_name = item.get("interface", "")
                address = item.get("address", "")
                if interface_name in interface_dict and address:
                    # Address format: "192.168.1.1/24"
                    ip_addr = address.split('/')[0] if '/' in address else address
                    interface_dict[interface_name]["ip_addresses"].append(ip_addr)
        
        # 3. Ethernet interfaces (speed/duplex) - solo per interfacce ethernet
        ethernet_output = self.exec_cmd("/interface ethernet print terse", timeout=5)
        if ethernet_output:
            ethernet_items = self._parse_terse_output(ethernet_output)
            self._log_debug(f"Parsed {len(ethernet_items)} ethernet items")
            for item in ethernet_items:
                name = item.get("name", "")
                if name in interface_dict:
                    # Speed può essere in diversi formati:
                    # - "100Mbps", "1Gbps" (stringa)
                    # - "100000000" (numero in bps)
                    speed_str = item.get("speed", "")
                    if speed_str:
                        # Se è un numero, converti in Mbps
                        if speed_str.isdigit():
                            speed_bps = self._safe_int(speed_str)
                            if speed_bps > 0:
                                speed_mbps = speed_bps // 1000000
                                interface_dict[name]["speed"] = f"{speed_mbps} Mbps"
                        else:
                            # Altrimenti usa il valore originale
                            interface_dict[name]["speed"] = speed_str
                    
                    # Duplex: "full", "half", "auto"
                    duplex_str = item.get("full-duplex", "")
                    if duplex_str == "true":
                        interface_dict[name]["duplex"] = "full"
                    elif duplex_str == "false":
                        interface_dict[name]["duplex"] = "half"
                    else:
                        interface_dict[name]["duplex"] = "auto"
        
        # 4. VLAN info (se interfaccia è VLAN)
        vlan_output = self.exec_cmd("/interface vlan print terse", timeout=5)
        if vlan_output:
            for item in self._parse_terse_output(vlan_output):
                name = item.get("name", "")
                vlan_id = item.get("vlan-id", "")
                if name in interface_dict and vlan_id:
                    interface_dict[name]["vlan_id"] = self._safe_int(vlan_id)
        
        # 5. Monitor/statistics per traffico (solo interfacce attive)
        # Usa /interface monitor per ottenere statistiche in tempo reale
        # Nota: questo può essere lento, quindi lo facciamo solo per interfacce running
        for name, iface in interface_dict.items():
            if iface.get("running"):
                try:
                    # Prova a ottenere statistiche via monitor (solo ultimo valore)
                    monitor_cmd = f'/interface monitor-traffic {name} once'
                    monitor_output = self.exec_cmd(monitor_cmd, timeout=3)
                    if monitor_output:
                        # Parse formato: rx-packets=0 rx-bytes=0 tx-packets=0 tx-bytes=0
                        for item in self._parse_terse_output(monitor_output):
                            rx_bytes = item.get("rx-bytes", "0")
                            tx_bytes = item.get("tx-bytes", "0")
                            iface["rx_bytes"] = self._safe_int(rx_bytes)
                            iface["tx_bytes"] = self._safe_int(tx_bytes)
                            break
                except:
                    pass
        
        # 6. Description da /interface print detail (se disponibile)
        detail_output = self.exec_cmd("/interface print detail", timeout=5)
        if detail_output:
            current_name = None
            for line in detail_output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                if 'name:' in line.lower():
                    current_name = line.split(':', 1)[1].strip()
                elif 'comment:' in line.lower() and current_name and current_name in interface_dict:
                    comment = line.split(':', 1)[1].strip()
                    if comment and not interface_dict[current_name].get("description"):
                        interface_dict[current_name]["description"] = comment
        
        # Converti dict in lista
        interfaces = list(interface_dict.values())
        
        return interfaces
    
    def _get_neighbors(self) -> List[Dict[str, Any]]:
        """Ottiene neighbor discovery (MNDP/LLDP/CDP)"""
        output = self.exec_cmd("/ip neighbor print detail", timeout=10)
        if not output or "interface=" not in output:
            return []
        
        neighbors = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current:
                    neighbors.append(current)
                    current = {}
                continue
            
            # Parse attributes
            for attr in line.split():
                if '=' in attr:
                    key, value = attr.split('=', 1)
                    key = key.strip().lower().replace('-', '_')
                    value = value.strip('"')
                    
                    if key == 'interface':
                        current["local_interface"] = value
                    elif key == 'address':
                        current["ip_address"] = value
                    elif key == 'mac_address':
                        current["mac_address"] = value
                    elif key == 'identity':
                        current["remote_device_name"] = value
                    elif key == 'platform':
                        current["platform"] = value
                    elif key == 'board':
                        current["model"] = value
                    elif key == 'version':
                        current["version"] = value
            
            current["discovered_by"] = "mndp"
        
        if current:
            neighbors.append(current)
        
        return neighbors
    
    def _get_routes(self) -> List[Dict[str, str]]:
        """Ottiene routing table"""
        output = self.exec_cmd("/ip route print terse where active", timeout=10)
        if not output:
            return []
        
        routes = []
        for item in self._parse_terse_output(output):
            if "dst-address" in item:
                routes.append({
                    "dst": item.get("dst-address", ""),
                    "gateway": item.get("gateway", ""),
                    "distance": item.get("distance", ""),
                    "interface": item.get("interface", ""),
                })
        
        return routes[:100]  # Limita a 100
    
    def _get_arp_table(self) -> List[Dict[str, str]]:
        """Ottiene ARP table"""
        output = self.exec_cmd("/ip arp print terse", timeout=10)
        if not output:
            return []
        
        arp_entries = []
        for item in self._parse_terse_output(output):
            if "address" in item:
                arp_entries.append({
                    "address": item.get("address", ""),
                    "mac_address": item.get("mac-address", ""),
                    "interface": item.get("interface", ""),
                    "dynamic": item.get("dynamic") == "true",
                })
        
        return arp_entries[:200]  # Limita a 200
    
    def _get_dhcp_leases(self) -> List[Dict[str, str]]:
        """Ottiene DHCP leases"""
        output = self.exec_cmd("/ip dhcp-server lease print terse", timeout=10)
        if not output:
            return []
        
        leases = []
        for item in self._parse_terse_output(output):
            if "address" in item:
                leases.append({
                    "address": item.get("address", ""),
                    "mac_address": item.get("mac-address", ""),
                    "hostname": item.get("host-name", ""),
                    "server": item.get("server", ""),
                    "status": item.get("status", ""),
                })
        
        return leases[:500]  # Limita a 500
