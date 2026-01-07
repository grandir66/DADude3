"""
DaDude Agent - Ubiquiti SSH Probe
Scansione dispositivi Ubiquiti EdgeOS e UniFi via SSH.
"""
import time
from typing import Dict, Any, List, Optional
from .base import SSHVendorProbe


class UbiquitiProbe(SSHVendorProbe):
    """Probe per dispositivi Ubiquiti (EdgeOS e UniFi)"""
    
    VENDOR_NAME = "Ubiquiti"
    DETECTION_PRIORITY = 25
    
    def __init__(self, exec_cmd, exec_cmd_sudo, client=None):
        """
        Args:
            client: paramiko.SSHClient per sessione interattiva UniFi
        """
        super().__init__(exec_cmd, exec_cmd_sudo)
        self._client = client
    
    def set_client(self, client):
        """Imposta client SSH per sessioni interattive"""
        self._client = client
    
    def detect(self) -> bool:
        """Rileva Ubiquiti EdgeOS o UniFi"""
        # EdgeOS
        version = self.exec_cmd("show version", timeout=5)
        if version and ("edgeos" in version.lower() or "vyatta" in version.lower()):
            return True
        
        # UniFi - prova comando 'info' (AP, Gateway)
        info_out = self.exec_cmd("info", timeout=3)
        if info_out and ("model" in info_out.lower() or "version" in info_out.lower()):
            return True
        
        # UniFi - prova board.info (Switch, AP)
        board = self.exec_cmd("cat /etc/board.info 2>/dev/null", timeout=3)
        if board and ("board.name" in board.lower() or "ubnt" in board.lower() or "usw" in board.lower()):
            return True
        
        # UniFi Switch - cerca indicatori nel motd/uname
        uname = self.exec_cmd("uname -a 2>/dev/null", timeout=3)
        if uname and "ubnt" in uname.lower():
            return True
        
        return False
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Ubiquiti"""
        # Determina se EdgeOS o UniFi
        version = self.exec_cmd("show version", timeout=5)
        if version and ("edgeos" in version.lower() or "vyatta" in version.lower()):
            return self._probe_edgeos(target, version)
        else:
            return self._probe_unifi(target)
    
    def _probe_edgeos(self, target: str, version_output: str) -> Dict[str, Any]:
        """Probe per EdgeOS (EdgeRouter, EdgeSwitch)"""
        self._log_info(f"Probing EdgeOS device at {target}")
        
        info = {
            "device_type": "router",
            "manufacturer": "Ubiquiti",
            "os_name": "EdgeOS",
            "category": "network",
        }
        
        # Parse show version
        info.update(self._parse_edgeos_version(version_output))
        
        # Hostname
        hostname = self.exec_cmd("show host name", timeout=3)
        if hostname:
            info["hostname"] = hostname.strip()
        
        # Interfaces
        interfaces = self._get_edgeos_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
        
        # LLDP neighbors
        neighbors = self._get_edgeos_neighbors()
        if neighbors:
            info["neighbors"] = neighbors
            info["neighbors_count"] = len(neighbors)
        
        # Routing table
        routes = self._get_edgeos_routes()
        if routes:
            info["routing_table"] = routes[:100]
            info["routing_count"] = len(routes)
        
        # ARP table
        arp = self._get_edgeos_arp()
        if arp:
            info["arp_table"] = arp[:100]
            info["arp_count"] = len(arp)
        
        self._log_info(f"EdgeOS probe complete: hostname={info.get('hostname')}, model={info.get('model')}")
        return info
    
    def _parse_edgeos_version(self, output: str) -> Dict[str, Any]:
        """Parse EdgeOS show version"""
        info = {}
        for line in output.split('\n'):
            ll = line.lower().strip()
            if ll.startswith('version:'):
                info["os_version"] = line.split(':', 1)[1].strip()
            elif ll.startswith('build id:'):
                info["build_id"] = line.split(':', 1)[1].strip()
            elif 'hw model:' in ll or 'hardware model:' in ll:
                info["model"] = line.split(':', 1)[1].strip()
            elif ll.startswith('hw s/n:') or ll.startswith('serial number:'):
                info["serial_number"] = line.split(':', 1)[1].strip()
            elif ll.startswith('uptime:'):
                info["uptime"] = line.split(':', 1)[1].strip()
        return info
    
    def _get_edgeos_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce EdgeOS"""
        output = self.exec_cmd("show interfaces", timeout=10)
        if not output:
            return []
        
        interfaces = []
        current = {}
        
        for line in output.split('\n'):
            if not line.strip():
                if current:
                    interfaces.append(current)
                    current = {}
                continue
            
            if not line.startswith(' ') and ':' in line:
                if current:
                    interfaces.append(current)
                parts = line.split()
                current = {"name": parts[0].rstrip(':')}
            elif 'link/ether' in line.lower() and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'link/ether' and i + 1 < len(parts):
                        current["mac_address"] = parts[i + 1]
            elif 'inet ' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        current["ipv4"] = parts[i + 1].split('/')[0]
        
        if current:
            interfaces.append(current)
        
        return interfaces
    
    def _get_edgeos_neighbors(self) -> List[Dict[str, Any]]:
        """Ottiene LLDP neighbors EdgeOS"""
        output = self.exec_cmd("show lldp neighbors detail", timeout=10)
        if not output:
            return []
        
        neighbors = []
        current = {}
        
        # EdgeOS LLDP format:
        # Interface: eth0, via LLDP
        #   Chassis: 
        #     ChassisID: mac 00:11:22:33:44:55
        #     SysName: SW-Example
        #   Port:
        #     PortID: ifname eth1
        #     PortDescr: GigabitEthernet1/1
        #   TTL: 120
        #   SysDescr: Cisco IOS Software...
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                if current and current.get("local_interface"):
                    neighbors.append(current)
                    current = {}
                continue
            
            ll = line.lower()
            
            # Interface line: "Interface: eth0, via LLDP"
            if ll.startswith('interface:'):
                if current and current.get("local_interface"):
                    neighbors.append(current)
                current = {"discovered_by": "lldp"}
                # Extract interface name (before comma)
                interface_part = line.split(':', 1)[1].strip() if ':' in line else ""
                current["local_interface"] = interface_part.split(',')[0].strip()
            
            # ChassisID: mac 00:11:22:33:44:55
            elif 'chassisid:' in ll and current:
                parts = line.split(':', 1)
                if len(parts) > 1:
                    chassis_part = parts[1].strip()
                    # Extract MAC if present
                    if 'mac' in chassis_part.lower():
                        mac = chassis_part.split('mac', 1)[1].strip()
                        current["remote_chassis_id"] = mac
                    else:
                        current["remote_chassis_id"] = chassis_part
            
            # SysName: SW-Example
            elif 'sysname:' in ll and current:
                current["remote_device_name"] = line.split(':', 1)[1].strip() if ':' in line else ""
            
            # PortID: ifname eth1
            elif 'portid:' in ll and current:
                port_part = line.split(':', 1)[1].strip() if ':' in line else ""
                # Extract interface name if "ifname" prefix
                if 'ifname' in port_part.lower():
                    current["remote_interface"] = port_part.split('ifname', 1)[1].strip()
                else:
                    current["remote_interface"] = port_part
            
            # PortDescr: GigabitEthernet1/1
            elif 'portdescr:' in ll and current:
                current["remote_port_description"] = line.split(':', 1)[1].strip() if ':' in line else ""
            
            # SysDescr: Cisco IOS Software...
            elif 'sysdescr:' in ll and current:
                current["remote_system_description"] = line.split(':', 1)[1].strip() if ':' in line else ""
                current["platform"] = current["remote_system_description"]
        
        if current and current.get("local_interface"):
            neighbors.append(current)
        
        return neighbors
    
    def _get_edgeos_routes(self) -> List[Dict[str, str]]:
        """Ottiene routing table EdgeOS"""
        output = self.exec_cmd("show ip route", timeout=10)
        if not output:
            return []
        
        routes = []
        for line in output.split('\n'):
            if '/' in line and ('via' in line or 'dev' in line):
                parts = line.split()
                route = {"dst": "", "gateway": "", "interface": ""}
                for i, p in enumerate(parts):
                    if '/' in p:
                        route["dst"] = p
                    elif p == 'via' and i + 1 < len(parts):
                        route["gateway"] = parts[i + 1]
                    elif p == 'dev' and i + 1 < len(parts):
                        route["interface"] = parts[i + 1]
                if route["dst"]:
                    routes.append(route)
        
        return routes
    
    def _get_edgeos_arp(self) -> List[Dict[str, str]]:
        """Ottiene ARP table EdgeOS"""
        output = self.exec_cmd("show arp", timeout=10)
        if not output:
            return []
        
        entries = []
        for line in output.split('\n'):
            if not line.strip() or line.startswith('IP') or '--' in line:
                continue
            parts = line.split()
            if len(parts) >= 3:
                entries.append({
                    "address": parts[0],
                    "mac_address": parts[2] if len(parts) > 2 else "",
                    "interface": parts[-1] if len(parts) > 3 else "",
                })
        
        return entries
    
    def _probe_unifi(self, target: str) -> Dict[str, Any]:
        """Probe per UniFi (AP, Switch, Gateway)"""
        self._log_info(f"Probing UniFi device at {target}")
        
        info = {
            "device_type": "access_point",
            "manufacturer": "Ubiquiti",
            "os_name": "UniFi",
            "category": "network",
        }
        
        # board.info per hardware (funziona su tutti gli UniFi)
        board = self.exec_cmd("cat /etc/board.info 2>/dev/null", timeout=3)
        is_switch = False
        if board:
            for line in board.split('\n'):
                ll = line.lower()
                if 'board.name=' in ll:
                    model = line.split('=')[-1].strip()
                    info["model"] = model
                    # Determina tipo da modello
                    if 'usw' in model.lower() or 'switch' in model.lower():
                        info["device_type"] = "switch"
                        is_switch = True
                    elif 'uap' in model.lower() or 'u6' in model.lower() or 'u7' in model.lower():
                        info["device_type"] = "access_point"
                    elif 'usg' in model.lower() or 'udm' in model.lower() or 'udr' in model.lower():
                        info["device_type"] = "router"
                elif 'board.hwaddr=' in ll:
                    mac = line.split('=')[-1].strip()
                    # Formatta MAC
                    if len(mac) == 12:
                        info["mac_address"] = ':'.join(mac[i:i+2] for i in range(0, 12, 2)).upper()
                    else:
                        info["mac_address"] = mac
        
        # Firmware version
        fw_version = self.exec_cmd("cat /etc/version 2>/dev/null", timeout=3)
        if fw_version:
            info["firmware_version"] = fw_version.strip()
            info["os_version"] = fw_version.strip()
        
        # Per gli switch UniFi, usa CLI Cisco-like (cli -> enable)
        if is_switch and self._client:
            cli_info = self._probe_unifi_switch_cli()
            if cli_info:
                info.update(cli_info)
        else:
            # Comando 'info' (funziona su AP e Gateway)
            info_out = self.exec_cmd("info", timeout=5)
            if info_out and "model" in info_out.lower():
                info.update(self._parse_unifi_info(info_out))
            
            # Hostname
            if not info.get("hostname"):
                hostname = self.exec_cmd("hostname 2>/dev/null", timeout=3)
                if hostname and "not found" not in hostname.lower():
                    info["hostname"] = hostname.strip()
            
            # Interfaces
            iface_out = self.exec_cmd("ifconfig 2>/dev/null || ip addr 2>/dev/null", timeout=5)
            if iface_out:
                info["interfaces"] = self._parse_ifconfig(iface_out)
                info["interface_count"] = len(info["interfaces"])
            
            # CPU e memoria
            cpu = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1", timeout=3)
            if cpu and ':' in cpu:
                info["cpu_model"] = cpu.split(':')[-1].strip()
            
            mem = self.exec_cmd("cat /proc/meminfo 2>/dev/null | grep MemTotal", timeout=3)
            if mem:
                try:
                    info["ram_total_mb"] = int(mem.split()[1]) // 1024
                except:
                    pass
            
            # Uptime
            uptime = self.exec_cmd("uptime 2>/dev/null", timeout=3)
            if uptime and 'up' in uptime:
                info["uptime"] = uptime.strip()
            
            # Prova CLI avanzata per router/gateway
            if self._client:
                cli_info = self._try_unifi_cli()
                if cli_info:
                    info.update(cli_info)
        
        self._log_info(f"UniFi probe complete: hostname={info.get('hostname')}, model={info.get('model')}, type={info.get('device_type')}")
        return info
    
    def _parse_unifi_info(self, output: str) -> Dict[str, Any]:
        """Parse output del comando 'info' UniFi"""
        info = {}
        for line in output.split('\n'):
            line = line.strip()
            ll = line.lower()
            
            if ll.startswith('model:') or ll.startswith('model='):
                model = line.split(':', 1)[-1].split('=')[-1].strip()
                info["model"] = model
                # Determina tipo device
                ml = model.lower()
                if any(x in ml for x in ['usg', 'udm', 'udr', 'ugw']):
                    info["device_type"] = "router"
                elif any(x in ml for x in ['usw', 'switch']):
                    info["device_type"] = "switch"
                elif any(x in ml for x in ['uap', 'u6', 'u7', 'ac', 'nanostation', 'litebeam']):
                    info["device_type"] = "access_point"
            elif ll.startswith('version:') or ll.startswith('version='):
                info["firmware_version"] = line.split(':', 1)[-1].split('=')[-1].strip()
            elif ll.startswith('mac:') or ll.startswith('mac='):
                info["mac_address"] = line.split(':', 1)[-1].split('=')[-1].strip()
            elif ll.startswith('hostname:') or ll.startswith('hostname='):
                info["hostname"] = line.split(':', 1)[-1].split('=')[-1].strip()
            elif ll.startswith('uptime:') or ll.startswith('uptime='):
                info["uptime"] = line.split(':', 1)[-1].split('=')[-1].strip()
            elif ll.startswith('serial:') or ll.startswith('serial='):
                info["serial_number"] = line.split(':', 1)[-1].split('=')[-1].strip()
            elif ll.startswith('ip:') or ll.startswith('ipaddr='):
                info["ip_address"] = line.split(':', 1)[-1].split('=')[-1].strip()
        
        return info
    
    def _parse_ifconfig(self, output: str) -> List[Dict[str, Any]]:
        """Parse ifconfig output"""
        interfaces = []
        current = {}
        
        for line in output.split('\n'):
            if line and not line.startswith(' ') and not line.startswith('\t'):
                if current and current.get("name"):
                    interfaces.append(current)
                name = line.split(':')[0].split()[0] if ':' in line else line.split()[0]
                current = {"name": name}
            elif 'inet ' in line.lower() and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        current["ipv4"] = parts[i + 1].split('/')[0]
            elif ('hwaddr' in line.lower() or 'ether' in line.lower()) and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.lower() in ('hwaddr', 'ether') and i + 1 < len(parts):
                        current["mac_address"] = parts[i + 1]
        
        if current and current.get("name"):
            interfaces.append(current)
        
        # Filtra loopback
        return [i for i in interfaces if not i["name"].startswith("lo")]
    
    def _probe_unifi_switch_cli(self) -> Optional[Dict[str, Any]]:
        """
        Probe per UniFi Switch con CLI Cisco-like.
        Sequenza: cli -> enable -> comandi show
        """
        if not self._client:
            return None
        
        try:
            channel = self._client.invoke_shell()
            channel.settimeout(15)
            time.sleep(1)
            
            # Svuota buffer iniziale (MOTD)
            if channel.recv_ready():
                channel.recv(8192)
            
            info = {}
            
            # Entra in CLI mode
            channel.send("cli\n")
            time.sleep(1.5)
            if channel.recv_ready():
                channel.recv(4096)
            
            # Enable mode
            channel.send("enable\n")
            time.sleep(1)
            if channel.recv_ready():
                channel.recv(4096)
            
            def cli_cmd(cmd: str, wait: float = 2.0) -> str:
                """Esegue comando CLI e ritorna output"""
                channel.send(f"{cmd}\n")
                time.sleep(wait)
                result = ""
                while channel.recv_ready():
                    result += channel.recv(16384).decode('utf-8', errors='ignore')
                    time.sleep(0.3)
                return result
            
            # Show version
            version_out = cli_cmd("show version", 2)
            if version_out:
                for line in version_out.split('\n'):
                    ll = line.lower().strip()
                    if 'system description' in ll:
                        # USW-Pro-Aggregation, 7.1.26.15869, Linux 4.4.153
                        parts = line.split('...')[-1].strip().split(',')
                        if parts:
                            info["model"] = parts[0].strip()
                            if len(parts) > 1:
                                info["firmware_version"] = parts[1].strip()
                                info["os_version"] = parts[1].strip()
                    elif 'machine type' in ll or 'machine model' in ll:
                        info["model"] = line.split('...')[-1].strip()
                    elif 'serial number' in ll:
                        info["serial_number"] = line.split('...')[-1].strip()
                    elif 'burned in mac' in ll or 'mac address' in ll:
                        mac = line.split('...')[-1].strip()
                        if len(mac) == 12:
                            info["mac_address"] = ':'.join(mac[i:i+2] for i in range(0, 12, 2)).upper()
                        else:
                            info["mac_address"] = mac.upper()
                    elif 'software version' in ll:
                        info["firmware_version"] = line.split('...')[-1].strip()
                        info["os_version"] = line.split('...')[-1].strip()
            
            # Hostname (sysname)
            sysname_out = cli_cmd("show sysname", 1)
            if sysname_out:
                for line in sysname_out.split('\n'):
                    if line.strip() and 'sysname' not in line.lower() and '#' not in line:
                        hostname = line.strip()
                        if hostname and not hostname.startswith('('):
                            info["hostname"] = hostname
                            break
            
            # Uptime
            uptime_out = cli_cmd("show sysinfo", 2)
            if uptime_out:
                for line in uptime_out.split('\n'):
                    ll = line.lower()
                    if 'system up time' in ll or 'uptime' in ll:
                        info["uptime"] = line.split('...')[-1].strip()
                    elif 'system name' in ll and not info.get("hostname"):
                        info["hostname"] = line.split('...')[-1].strip()
            
            # Interfaces / Ports
            ports_out = cli_cmd("show port all", 3)
            if ports_out:
                interfaces = []
                for line in ports_out.split('\n'):
                    # Cerca righe con formato: port_name status ...
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith(('0/', '1/', 'lag', 'eth')):
                        iface = {
                            "name": parts[0],
                            "admin_status": parts[1] if len(parts) > 1 else "unknown",
                            "link_status": parts[2] if len(parts) > 2 else "unknown",
                        }
                        interfaces.append(iface)
                if interfaces:
                    info["interfaces"] = interfaces
                    info["interface_count"] = len(interfaces)
                    # Conta porte attive
                    info["ports_up"] = sum(1 for i in interfaces if i.get("link_status", "").lower() in ("up", "enable"))
            
            # VLAN
            vlan_out = cli_cmd("show vlan", 2)
            if vlan_out:
                vlans = []
                for line in vlan_out.split('\n'):
                    parts = line.split()
                    # Cerca VLAN ID numerico
                    if parts and parts[0].isdigit():
                        vlan_id = int(parts[0])
                        vlan_name = parts[1] if len(parts) > 1 else f"VLAN{vlan_id}"
                        vlans.append({"id": vlan_id, "name": vlan_name})
                if vlans:
                    info["vlan_info"] = vlans
                    info["vlan_count"] = len(vlans)
            
            # LLDP neighbors
            lldp_out = cli_cmd("show lldp remote-device all", 3)
            if lldp_out:
                neighbors = []
                for line in lldp_out.split('\n'):
                    # Formato: Interface RemoteID PortID SysName
                    parts = line.split()
                    if len(parts) >= 3 and parts[0].startswith(('0/', '1/', 'lag')):
                        neighbor = {
                            "local_interface": parts[0],
                            "remote_chassis_id": parts[1] if len(parts) > 1 else "",
                            "remote_interface": parts[2] if len(parts) > 2 else "",
                            "remote_device_name": parts[3] if len(parts) > 3 else "",
                            "discovered_by": "lldp",
                        }
                        neighbors.append(neighbor)
                if neighbors:
                    info["lldp_neighbors"] = neighbors
                    info["neighbors_count"] = len(neighbors)
            
            # MAC address table count
            mac_out = cli_cmd("show mac-address-table count", 2)
            if mac_out:
                for line in mac_out.split('\n'):
                    if 'total' in line.lower() and 'mac' in line.lower():
                        parts = line.split()
                        for p in parts:
                            if p.isdigit():
                                info["mac_table_count"] = int(p)
                                break
            
            # Exit CLI
            channel.send("exit\n")
            time.sleep(0.3)
            channel.send("exit\n")
            time.sleep(0.3)
            channel.close()
            
            self._log_info(f"UniFi Switch CLI probe complete: hostname={info.get('hostname')}, model={info.get('model')}, ports={info.get('interface_count')}")
            return info if info else None
            
        except Exception as e:
            self._log_debug(f"UniFi Switch CLI probe failed: {e}")
            return None
    
    def _try_unifi_cli(self) -> Optional[Dict[str, Any]]:
        """Prova CLI avanzata UniFi (cli -> enable) - per AP e Gateway"""
        if not self._client:
            return None
        
        try:
            channel = self._client.invoke_shell()
            channel.settimeout(10)
            time.sleep(0.5)
            
            # Svuota buffer
            if channel.recv_ready():
                channel.recv(4096)
            
            info = {}
            
            # Prova 'cli'
            channel.send("cli\n")
            time.sleep(1)
            
            output = ""
            if channel.recv_ready():
                output = channel.recv(4096).decode('utf-8', errors='ignore')
            
            if '>' in output or '#' in output:
                self._log_debug("UniFi CLI mode entered")
                
                # Enable
                channel.send("enable\n")
                time.sleep(0.5)
                if channel.recv_ready():
                    channel.recv(4096)
                
                def cli_cmd(cmd: str) -> str:
                    channel.send(f"{cmd}\n")
                    time.sleep(1.5)  # Più tempo per output lunghi
                    result = ""
                    max_reads = 10  # Limita letture per evitare loop infiniti
                    read_count = 0
                    while read_count < max_reads:
                        if channel.recv_ready():
                            result += channel.recv(8192).decode('utf-8', errors='ignore')
                            read_count += 1
                            time.sleep(0.3)  # Aspetta per più dati
                        else:
                            break
                    return result
                
                # Show version
                version = cli_cmd("show version")
                if version:
                    for line in version.split('\n'):
                        ll = line.lower().strip()
                        if 'software version' in ll:
                            info["firmware_version"] = line.split(':')[-1].strip()
                        elif 'hardware version' in ll:
                            info["hardware_version"] = line.split(':')[-1].strip()
                
                # LLDP neighbors - usa detail per dati completi
                lldp = cli_cmd("show lldp neighbors detail")
                if lldp:
                    neighbors = []
                    current = {}
                    
                    for line in lldp.split('\n'):
                        line = line.strip()
                        if not line:
                            if current and current.get("local_interface"):
                                neighbors.append(current)
                                current = {}
                            continue
                        
                        ll = line.lower()
                        
                        # Interface line: "Interface: eth0, via LLDP"
                        if ll.startswith('interface:'):
                            if current and current.get("local_interface"):
                                neighbors.append(current)
                            current = {"discovered_by": "lldp"}
                            interface_part = line.split(':', 1)[1].strip() if ':' in line else ""
                            current["local_interface"] = interface_part.split(',')[0].strip()
                        
                        # SysName: SW-Example
                        elif 'sysname:' in ll and current:
                            current["remote_device_name"] = line.split(':', 1)[1].strip() if ':' in line else ""
                        
                        # PortID: ifname eth1
                        elif 'portid:' in ll and current:
                            port_part = line.split(':', 1)[1].strip() if ':' in line else ""
                            if 'ifname' in port_part.lower():
                                current["remote_interface"] = port_part.split('ifname', 1)[1].strip()
                            else:
                                current["remote_interface"] = port_part
                        
                        # PortDescr: GigabitEthernet1/1
                        elif 'portdescr:' in ll and current:
                            current["remote_port_description"] = line.split(':', 1)[1].strip() if ':' in line else ""
                        
                        # SysDescr: Cisco IOS Software...
                        elif 'sysdescr:' in ll and current:
                            current["remote_system_description"] = line.split(':', 1)[1].strip() if ':' in line else ""
                            current["platform"] = current["remote_system_description"]
                        
                        # ChassisID: mac 00:11:22:33:44:55
                        elif 'chassisid:' in ll and current:
                            chassis_part = line.split(':', 1)[1].strip() if ':' in line else ""
                            if 'mac' in chassis_part.lower():
                                mac = chassis_part.split('mac', 1)[1].strip()
                                current["remote_chassis_id"] = mac
                    
                    if current and current.get("local_interface"):
                        neighbors.append(current)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["lldp_neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                channel.send("exit\n")
                time.sleep(0.3)
            
            channel.close()
            return info if info else None
            
        except Exception as e:
            self._log_debug(f"UniFi CLI failed: {e}")
            return None
