"""
DaDude Agent - SSH Probe
Scansione dispositivi Linux/Unix/MikroTik via SSH
"""
import asyncio
import re
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from loguru import logger
from io import StringIO


_executor = ThreadPoolExecutor(max_workers=5)


async def probe(
    target: str,
    username: str,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Esegue probe SSH su un target Linux/Unix/MikroTik.
    Rileva automaticamente il tipo di device ed esegue comandi appropriati.
    
    Returns:
        Dict con info sistema: hostname, os, kernel, cpu, ram, disco
    """
    loop = asyncio.get_event_loop()
    
    def connect():
        import paramiko
        
        logger.debug(f"SSH probe: connecting to {target}:{port} as {username}")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_args = {
            "hostname": target,
            "port": port,
            "username": username,
            "timeout": 20,
            "banner_timeout": 30,  # Dropbear/UniFi può essere lento a mandare il banner
            "auth_timeout": 20,
            "allow_agent": False,
            "look_for_keys": False,
        }
        
        if private_key:
            key = paramiko.RSAKey.from_private_key(StringIO(private_key))
            connect_args["pkey"] = key
        else:
            connect_args["password"] = password
        
        client.connect(**connect_args)
        
        info = {}
        use_sudo = False  # Flag per usare sudo quando necessario
        
        def exec_cmd(cmd: str, timeout: int = 5, try_sudo: bool = False) -> str:
            """
            Esegue comando SSH con supporto per sudo automatico.
            
            Args:
                cmd: Comando da eseguire
                timeout: Timeout in secondi
                try_sudo: Se True, prova con sudo se il comando fallisce per permessi
            """
            nonlocal use_sudo
            
            try:
                # Prima prova il comando normale
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                # Se fallisce per permessi e abbiamo l'opzione sudo, prova con sudo
                if try_sudo and error and ("permission denied" in error.lower() or 
                                           "operation not permitted" in error.lower() or
                                           "access denied" in error.lower()):
                    # Prova con sudo
                    sudo_cmd = f"sudo {cmd}"
                    logger.debug(f"SSH: Command failed with permission error, retrying with sudo: {sudo_cmd[:60]}...")
                    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout)
                    sudo_output = stdout.read().decode().strip()
                    sudo_error = stderr.read().decode().strip()
                    
                    # Se sudo funziona, ricorda di usarlo
                    if sudo_output and not ("password" in sudo_error.lower() or "sudo:" in sudo_error.lower()):
                        use_sudo = True
                        return sudo_output
                    elif "password" in sudo_error.lower():
                        logger.debug(f"SSH: sudo requires password (not available)")
                
                if error and "Permission denied" not in error.lower() and "command not found" not in error.lower():
                    logger.debug(f"SSH exec_cmd '{cmd[:50]}...' stderr: {error[:200]}")
                return output
            except Exception as e:
                logger.debug(f"SSH exec_cmd '{cmd[:50]}...' failed: {e}")
                return ""
        
        def exec_cmd_sudo(cmd: str, timeout: int = 5) -> str:
            """Esegue comando con sudo se necessario/disponibile"""
            if use_sudo:
                return exec_cmd(f"sudo {cmd}", timeout=timeout)
            return exec_cmd(cmd, timeout=timeout, try_sudo=True)
        
        # ===== PRIMA RILEVA IL TIPO DI DEVICE =====
        # Prova MikroTik RouterOS (non supporta comandi Linux)
        ros_out = exec_cmd("/system resource print")
        
        if "version:" in ros_out.lower() or "uptime:" in ros_out.lower() or "routeros" in ros_out.lower():
            # ===== MIKROTIK ROUTEROS =====
            logger.info(f"SSH probe: Detected MikroTik RouterOS on {target}")
            info["device_type"] = "mikrotik"
            info["os_name"] = "RouterOS"
            info["manufacturer"] = "MikroTik"
            info["category"] = "router"
            
            # Parse /system resource print
            for line in ros_out.split('\n'):
                ll = line.lower().strip()
                if ll.startswith('version:'):
                    info["os_version"] = line.split(':', 1)[1].strip()
                elif ll.startswith('board-name:'):
                    info["model"] = line.split(':', 1)[1].strip()
                elif ll.startswith('cpu:') and 'cpu-count' not in ll:
                    info["cpu_model"] = line.split(':', 1)[1].strip()
                elif ll.startswith('cpu-count:'):
                    try:
                        info["cpu_cores"] = int(line.split(':', 1)[1].strip())
                    except:
                        pass
                elif ll.startswith('total-memory:'):
                    try:
                        mem_str = line.split(':', 1)[1].strip()
                        if 'MiB' in mem_str:
                            info["ram_total_mb"] = int(float(mem_str.replace('MiB', '').strip()))
                        elif 'GiB' in mem_str:
                            info["ram_total_mb"] = int(float(mem_str.replace('GiB', '').strip()) * 1024)
                    except:
                        pass
                elif ll.startswith('free-memory:'):
                    try:
                        mem_str = line.split(':', 1)[1].strip()
                        if 'MiB' in mem_str:
                            info["ram_free_mb"] = int(float(mem_str.replace('MiB', '').strip()))
                    except:
                        pass
                elif ll.startswith('architecture-name:'):
                    info["architecture"] = line.split(':', 1)[1].strip()
                elif ll.startswith('uptime:'):
                    info["uptime"] = line.split(':', 1)[1].strip()
            
            # Get hostname from /system identity
            identity_out = exec_cmd("/system identity print")
            for line in identity_out.split('\n'):
                if 'name:' in line.lower():
                    info["hostname"] = line.split(':', 1)[1].strip()
                    break
            
            # Get serial/model from /system routerboard
            rb_out = exec_cmd("/system routerboard print")
            for line in rb_out.split('\n'):
                ll = line.lower().strip()
                if ll.startswith('serial-number:'):
                    info["serial_number"] = line.split(':', 1)[1].strip()
                elif ll.startswith('model:') and not info.get("model"):
                    info["model"] = line.split(':', 1)[1].strip()
                elif ll.startswith('current-firmware:'):
                    info["firmware"] = line.split(':', 1)[1].strip()
            
            # Get license
            lic_out = exec_cmd("/system license print")
            for line in lic_out.split('\n'):
                if 'level:' in line.lower():
                    info["license_level"] = line.split(':', 1)[1].strip()
            
            # Get interface count
            iface_count = exec_cmd("/interface print count-only")
            if iface_count.isdigit():
                info["interface_count"] = int(iface_count)
            
            # ===== INTERFACES DETAILED =====
            interfaces_out = exec_cmd("/interface print terse", timeout=10)
            if interfaces_out:
                interfaces = []
                for line in interfaces_out.split('\n'):
                    if not line.strip():
                        continue
                    # Parse formato terse: name=ether1 type=ether mac-address=AA:BB:CC:DD:EE:FF mtu=1500 running=true disabled=false
                    iface = {}
                    for attr in line.split():
                        if '=' in attr:
                            key, value = attr.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            if key == 'name':
                                iface["name"] = value
                            elif key == 'type':
                                iface["type"] = value
                            elif key == 'mac-address':
                                iface["mac_address"] = value
                            elif key == 'mtu':
                                try:
                                    iface["mtu"] = int(value)
                                except:
                                    pass
                            elif key == 'running':
                                iface["running"] = value.lower() == "true"
                            elif key == 'disabled':
                                iface["disabled"] = value.lower() == "true"
                    if iface.get("name"):
                        interfaces.append(iface)
                
                if interfaces:
                    info["interfaces"] = interfaces
                    info["network_interfaces"] = interfaces  # Alias per compatibilità unified scanner
                    info["interfaces_count"] = len(interfaces)
                    logger.info(f"SSH probe: Collected {len(interfaces)} MikroTik interfaces")
            
            # ===== NEIGHBOR DISCOVERY (LLDP/CDP/MNDP) =====
            neighbor_out = exec_cmd("/ip neighbor print detail", timeout=10)
            if neighbor_out and "interface=" in neighbor_out:
                neighbors = []
                # Parse output - ogni neighbor inizia con un numero
                current_neighbor = {}
                for line in neighbor_out.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Nuovo neighbor (inizia con numero)
                    if line and line[0].isdigit() and 'interface=' in line:
                        if current_neighbor:
                            neighbors.append(current_neighbor)
                        current_neighbor = {}
                        # Parse la prima riga
                        parts = line.split(' ', 1)
                        if len(parts) > 1:
                            line = parts[1]
                    
                    # Parse attributi
                    for attr in line.split(' '):
                        if '=' in attr:
                            key, value = attr.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            if key == 'interface':
                                current_neighbor['local_interface'] = value.split(',')[0]
                            elif key == 'identity':
                                current_neighbor['remote_device_name'] = value
                            elif key == 'mac-address':
                                current_neighbor['remote_mac'] = value
                            elif key == 'address' or key == 'address4':
                                if not current_neighbor.get('remote_ip'):
                                    current_neighbor['remote_ip'] = value
                            elif key == 'platform':
                                current_neighbor['platform'] = value
                            elif key == 'version':
                                current_neighbor['version'] = value
                            elif key == 'board':
                                current_neighbor['board'] = value
                            elif key == 'interface-name':
                                current_neighbor['remote_interface'] = value
                            elif key == 'discovered-by':
                                current_neighbor['discovered_by'] = value
                            elif key == 'uptime':
                                current_neighbor['uptime'] = value
                
                if current_neighbor:
                    neighbors.append(current_neighbor)
                
                if neighbors:
                    info["neighbors"] = neighbors
                    info["lldp_neighbors"] = neighbors  # Alias per compatibilità unified scanner
                    info["neighbors_count"] = len(neighbors)
                    logger.info(f"SSH probe: Collected {len(neighbors)} MikroTik neighbors")
                else:
                    logger.debug(f"SSH probe: No MikroTik neighbors found (neighbor_out empty or parse failed)")
            else:
                logger.debug(f"SSH probe: MikroTik neighbor command failed or returned empty")
            
            # ===== ROUTING TABLE =====
            routes_out = exec_cmd("/ip route print terse where active", timeout=10)
            if routes_out:
                routes = []
                for line in routes_out.split('\n'):
                    if 'dst-address=' in line:
                        route = {}
                        for attr in line.split(' '):
                            if '=' in attr:
                                key, value = attr.split('=', 1)
                                route[key.strip()] = value.strip()
                        if route:
                            routes.append(route)
                if routes:
                    info["routing_table"] = routes
                    info["routing_count"] = len(routes)
            
            # ===== ARP TABLE =====
            arp_out = exec_cmd("/ip arp print terse", timeout=10)
            if arp_out:
                arp_entries = []
                for line in arp_out.split('\n'):
                    if 'address=' in line:
                        entry = {}
                        for attr in line.split(' '):
                            if '=' in attr:
                                key, value = attr.split('=', 1)
                                entry[key.strip()] = value.strip()
                        if entry:
                            arp_entries.append(entry)
                if arp_entries:
                    info["arp_table"] = arp_entries
                    info["arp_count"] = len(arp_entries)
        
        else:
            # ===== PROVA CISCO IOS/IOS-XE =====
            cisco_version = exec_cmd("show version", timeout=10)
            if cisco_version and ("cisco" in cisco_version.lower() or "ios" in cisco_version.lower() or "ios-xe" in cisco_version.lower()):
                logger.info(f"SSH probe: Detected Cisco IOS/IOS-XE on {target}")
                info["device_type"] = "router"
                info["os_name"] = "IOS"
                info["manufacturer"] = "Cisco"
                info["category"] = "network"
                
                # Parse show version
                for line in cisco_version.split('\n'):
                    line_lower = line.lower()
                    if 'version' in line_lower and 'software' in line_lower:
                        parts = line.split(',')
                        for part in parts:
                            if 'version' in part.lower():
                                info["os_version"] = part.split('Version')[1].strip() if 'Version' in part else part.strip()
                    elif 'processor' in line_lower and 'with' in line_lower:
                        # Extract CPU info
                        if 'processor' in line_lower:
                            info["cpu_model"] = line.split('processor')[1].split('with')[0].strip() if 'with' in line_lower else line.split('processor')[1].strip()
                    elif 'bytes of memory' in line_lower or 'k bytes of memory' in line_lower:
                        # Extract memory
                        try:
                            mem_str = line.split('bytes')[0].strip()
                            mem_str = mem_str.split()[-1]  # Get last number
                            if 'k' in mem_str.lower():
                                info["ram_total_mb"] = int(mem_str.replace('k', '').replace('K', '')) // 1024
                            elif 'm' in mem_str.lower():
                                info["ram_total_mb"] = int(mem_str.replace('m', '').replace('M', ''))
                        except:
                            pass
                    elif 'uptime is' in line_lower:
                        info["uptime"] = line.split('uptime is')[1].strip() if 'uptime is' in line_lower else ""
                    elif 'model number' in line_lower or 'model:' in line_lower:
                        model_part = line.split(':')[-1].strip() if ':' in line else line.split('model')[1].strip()
                        if not info.get("model"):
                            info["model"] = model_part.split()[0] if model_part.split() else model_part
                
                # Get hostname
                hostname_out = exec_cmd("show running-config | include hostname", timeout=5)
                if hostname_out:
                    for line in hostname_out.split('\n'):
                        if 'hostname' in line.lower():
                            info["hostname"] = line.split()[1].strip() if len(line.split()) > 1 else ""
                
                # CDP Neighbors
                cdp_out = exec_cmd("show cdp neighbors detail", timeout=10)
                if cdp_out:
                    neighbors = []
                    current_neighbor = {}
                    for line in cdp_out.split('\n'):
                        line = line.strip()
                        if not line:
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                                current_neighbor = {}
                            continue
                        
                        if 'device id:' in line.lower():
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                            current_neighbor = {"discovered_by": "cdp"}
                            info["remote_device_name"] = line.split(':')[1].strip() if ':' in line else line
                        elif 'platform:' in line.lower():
                            current_neighbor["platform"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'capabilities:' in line.lower():
                            current_neighbor["capabilities"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'interface:' in line.lower():
                            current_neighbor["local_interface"] = line.split(':')[1].strip().split(',')[0] if ':' in line else ""
                        elif 'port id (outgoing port):' in line.lower():
                            current_neighbor["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'software version' in line.lower() or 'version' in line.lower():
                            current_neighbor["version"] = line.split(':')[1].strip() if ':' in line else ""
                    
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                # LLDP Neighbors (if available)
                lldp_out = exec_cmd("show lldp neighbors detail", timeout=10)
                if lldp_out and not info.get("neighbors"):
                    neighbors = []
                    current_neighbor = {}
                    for line in lldp_out.split('\n'):
                        line = line.strip()
                        if not line:
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                                current_neighbor = {}
                            continue
                        
                        if 'chassis id:' in line.lower():
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                            current_neighbor = {"discovered_by": "lldp"}
                        elif 'system name:' in line.lower():
                            current_neighbor["remote_device_name"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'port id:' in line.lower():
                            current_neighbor["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'system description:' in line.lower():
                            current_neighbor["platform"] = line.split(':')[1].strip() if ':' in line else ""
                    
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                # Routing Table
                route_out = exec_cmd("show ip route", timeout=10)
                if route_out:
                    routes = []
                    for line in route_out.split('\n'):
                        if line.strip().startswith(('C', 'S', 'R', 'O', 'D', 'B', 'i', 'L')) and '/' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                route = {
                                    "dst": parts[1] if '/' in parts[1] else parts[1],
                                    "gateway": parts[2] if len(parts) > 2 and not parts[2].startswith('[') else "",
                                    "interface": parts[-1] if len(parts) > 2 else ""
                                }
                                routes.append(route)
                    if routes:
                        info["routing_table"] = routes[:100]  # Limit to 100
                        info["routing_count"] = len(routes)
                
                # ARP Table (solo per router)
                arp_out = exec_cmd("show ip arp", timeout=10)
                if arp_out:
                    arp_entries = []
                    for line in arp_out.split('\n'):
                        if line.strip() and not line.startswith('Protocol') and not line.startswith('-'):
                            parts = line.split()
                            if len(parts) >= 4:
                                arp_entry = {
                                    "address": parts[1],
                                    "mac-address": parts[3],
                                    "interface": parts[-1] if len(parts) > 4 else ""
                                }
                                arp_entries.append(arp_entry)
                    if arp_entries:
                        info["arp_table"] = arp_entries[:100]  # Limit to 100
                        info["arp_count"] = len(arp_entries)
            
            # ===== PROVA HP COMWARE =====
            elif exec_cmd("display version", timeout=5) and ("comware" in exec_cmd("display version", timeout=5).lower() or "hp" in exec_cmd("display version", timeout=5).lower()):
                hp_comware_version = exec_cmd("display version", timeout=10)
                logger.info(f"SSH probe: Detected HP Comware on {target}")
                info["device_type"] = "switch"
                info["os_name"] = "Comware"
                info["manufacturer"] = "HP"
                info["category"] = "network"
                
                # Parse display version
                for line in hp_comware_version.split('\n'):
                    if 'version' in line.lower():
                        info["os_version"] = line.split(':')[1].strip() if ':' in line else line.strip()
                    elif 'hp' in line.lower() and ('switch' in line.lower() or 'router' in line.lower()):
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part.lower() in ['hp', 'hpe'] and i + 1 < len(parts):
                                info["model"] = parts[i+1]
                                break
                
                # LLDP Neighbors
                lldp_out = exec_cmd("display lldp neighbor-information", timeout=10)
                if lldp_out:
                    neighbors = []
                    current_neighbor = {}
                    for line in lldp_out.split('\n'):
                        line = line.strip()
                        if 'neighbor index' in line.lower():
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                            current_neighbor = {"discovered_by": "lldp"}
                        elif 'system name:' in line.lower():
                            current_neighbor["remote_device_name"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'port id:' in line.lower():
                            current_neighbor["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
                    
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                # Routing Table
                route_out = exec_cmd("display ip routing-table", timeout=10)
                if route_out:
                    routes = []
                    for line in route_out.split('\n'):
                        if '/' in line and ('dest' in line.lower() or line.strip().startswith(('0.', '1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.'))):
                            parts = line.split()
                            if len(parts) >= 2:
                                route = {
                                    "dst": parts[0] if '/' in parts[0] else parts[0],
                                    "gateway": parts[1] if len(parts) > 1 else "",
                                    "interface": parts[-1] if len(parts) > 2 else ""
                                }
                                routes.append(route)
                    if routes:
                        info["routing_table"] = routes[:100]
                        info["routing_count"] = len(routes)
                
                # ARP Table (solo se router)
                if info.get("device_type") == "router":
                    arp_out = exec_cmd("display arp", timeout=10)
                    if arp_out:
                        arp_entries = []
                        for line in arp_out.split('\n'):
                            if line.strip() and not line.startswith('IP') and not line.startswith('-'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    arp_entry = {
                                        "address": parts[0],
                                        "mac-address": parts[1],
                                        "interface": parts[-1] if len(parts) > 2 else ""
                                    }
                                    arp_entries.append(arp_entry)
                        if arp_entries:
                            info["arp_table"] = arp_entries[:100]
                            info["arp_count"] = len(arp_entries)
            
            # ===== PROVA HP PROCURVE/ARUBAOS =====
            elif exec_cmd("show version", timeout=5) and ("procurve" in exec_cmd("show version", timeout=5).lower() or "arubaos" in exec_cmd("show version", timeout=5).lower() or "aruba" in exec_cmd("show version", timeout=5).lower()):
                hp_procurve_version = exec_cmd("show version", timeout=10)
                logger.info(f"SSH probe: Detected HP ProCurve/ArubaOS on {target}")
                info["device_type"] = "switch"
                info["os_name"] = "ProCurve" if "procurve" in hp_procurve_version.lower() else "ArubaOS"
                info["manufacturer"] = "HP"
                info["category"] = "network"
                
                # Parse show version
                for line in hp_procurve_version.split('\n'):
                    if 'version' in line.lower():
                        info["os_version"] = line.split(':')[1].strip() if ':' in line else line.strip()
                    elif 'model' in line.lower():
                        info["model"] = line.split(':')[1].strip() if ':' in line else line.strip()
                
                # LLDP Neighbors
                lldp_out = exec_cmd("show lldp info remote-device", timeout=10)
                if lldp_out:
                    neighbors = []
                    current_neighbor = {}
                    for line in lldp_out.split('\n'):
                        line = line.strip()
                        if 'remote chassis id:' in line.lower():
                            if current_neighbor:
                                neighbors.append(current_neighbor)
                            current_neighbor = {"discovered_by": "lldp"}
                        elif 'remote system name:' in line.lower():
                            current_neighbor["remote_device_name"] = line.split(':')[1].strip() if ':' in line else ""
                        elif 'remote port id:' in line.lower():
                            current_neighbor["remote_interface"] = line.split(':')[1].strip() if ':' in line else ""
                    
                    if current_neighbor:
                        neighbors.append(current_neighbor)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                # Routing Table
                route_out = exec_cmd("show ip route", timeout=10)
                if route_out:
                    routes = []
                    for line in route_out.split('\n'):
                        if '/' in line and line.strip().startswith(('0.', '1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.')):
                            parts = line.split()
                            if len(parts) >= 2:
                                route = {
                                    "dst": parts[0],
                                    "gateway": parts[1] if len(parts) > 1 else "",
                                    "interface": parts[-1] if len(parts) > 2 else ""
                                }
                                routes.append(route)
                    if routes:
                        info["routing_table"] = routes[:100]
                        info["routing_count"] = len(routes)
                
                # ARP Table (solo se router)
                if info.get("device_type") == "router":
                    arp_out = exec_cmd("show arp", timeout=10)
                    if arp_out:
                        arp_entries = []
                        for line in arp_out.split('\n'):
                            if line.strip() and not line.startswith('IP') and not line.startswith('-'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    arp_entry = {
                                        "address": parts[0],
                                        "mac-address": parts[1],
                                        "interface": parts[-1] if len(parts) > 2 else ""
                                    }
                                    arp_entries.append(arp_entry)
                        if arp_entries:
                            info["arp_table"] = arp_entries[:100]
                            info["arp_count"] = len(arp_entries)
            
            # ===== PROVA UBIQUITI EDGEOS =====
            elif exec_cmd("show version", timeout=5) and ("edgeos" in exec_cmd("show version", timeout=5).lower() or "vyatta" in exec_cmd("show version", timeout=5).lower()):
                edgeos_version = exec_cmd("show version", timeout=10)
                logger.info(f"SSH probe: Detected Ubiquiti EdgeOS on {target}")
                info["device_type"] = "router"
                info["os_name"] = "EdgeOS"
                info["manufacturer"] = "Ubiquiti"
                info["category"] = "network"
                
                # Parse show version
                for line in edgeos_version.split('\n'):
                    if 'version' in line.lower():
                        info["os_version"] = line.split(':')[1].strip() if ':' in line else line.strip()
                    elif 'model' in line.lower():
                        info["model"] = line.split(':')[1].strip() if ':' in line else line.strip()
                
                # Hostname
                hostname = exec_cmd("show host name", timeout=3)
                if hostname:
                    info["hostname"] = hostname.strip()
                
                # ===== INTERFACES DETAILED =====
                interfaces_out = exec_cmd("show interfaces", timeout=10)
                if interfaces_out:
                    interfaces = []
                    current = {}
                    for line in interfaces_out.split('\n'):
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
                    
                    if interfaces:
                        info["interfaces"] = interfaces
                        info["network_interfaces"] = interfaces  # Alias per compatibilità unified scanner
                        info["interface_count"] = len(interfaces)
                        logger.info(f"SSH probe: Collected {len(interfaces)} EdgeOS interfaces")
                
                # LLDP Neighbors (detail)
                lldp_out = exec_cmd("show lldp neighbors detail", timeout=10)
                if lldp_out:
                    neighbors = []
                    current = {}
                    for line in lldp_out.split('\n'):
                        line = line.strip()
                        ll = line.lower()
                        
                        if ll.startswith('interface:'):
                            if current:
                                neighbors.append(current)
                            current = {"discovered_by": "lldp"}
                            current["local_interface"] = line.split(':', 1)[1].strip() if ':' in line else ""
                        elif ll.startswith('chassis:') and current:
                            # Next line might have chassis id
                            pass
                        elif ll.startswith('sysname:') and current:
                            current["remote_device_name"] = line.split(':', 1)[1].strip() if ':' in line else ""
                        elif ll.startswith('portid:') and current:
                            current["remote_interface"] = line.split(':', 1)[1].strip() if ':' in line else ""
                        elif ll.startswith('sysdescr:') and current:
                            current["platform"] = line.split(':', 1)[1].strip() if ':' in line else ""
                    
                    if current:
                        neighbors.append(current)
                    
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["lldp_neighbors"] = neighbors  # Alias per compatibilità unified scanner
                        info["neighbors_count"] = len(neighbors)
                        logger.info(f"SSH probe: Collected {len(neighbors)} EdgeOS LLDP neighbors")
                else:
                    # Fallback a formato semplice
                    lldp_simple = exec_cmd("show lldp neighbors", timeout=10)
                    if lldp_simple:
                        neighbors = []
                        for line in lldp_simple.split('\n'):
                            if line.strip() and not line.startswith('Interface'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    neighbor = {
                                        "local_interface": parts[0],
                                        "remote_device_name": parts[1],
                                        "remote_interface": parts[2] if len(parts) > 2 else "",
                                        "discovered_by": "lldp"
                                    }
                                    neighbors.append(neighbor)
                        if neighbors:
                            info["neighbors"] = neighbors
                            info["neighbors_count"] = len(neighbors)
                
                # Routing Table
                route_out = exec_cmd("show ip route", timeout=10)
                if route_out:
                    routes = []
                    for line in route_out.split('\n'):
                        if '/' in line and line.strip().startswith(('K', 'C', 'S', 'O', 'B', 'D')):
                            parts = line.split()
                            if len(parts) >= 2:
                                route = {
                                    "dst": parts[1] if '/' in parts[1] else parts[1],
                                    "gateway": parts[2] if len(parts) > 2 else "",
                                    "interface": parts[-1] if len(parts) > 2 else ""
                                }
                                routes.append(route)
                    if routes:
                        info["routing_table"] = routes[:100]
                        info["routing_count"] = len(routes)
                
                # ARP Table (solo se router)
                if info.get("device_type") == "router":
                    arp_out = exec_cmd("show arp", timeout=10)
                    if arp_out:
                        arp_entries = []
                        for line in arp_out.split('\n'):
                            if line.strip() and not line.startswith('IP') and not line.startswith('-'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    arp_entry = {
                                        "address": parts[0],
                                        "mac-address": parts[1],
                                        "interface": parts[-1] if len(parts) > 2 else ""
                                    }
                                    arp_entries.append(arp_entry)
                        if arp_entries:
                            info["arp_table"] = arp_entries[:100]
                            info["arp_count"] = len(arp_entries)
            
            # ===== PROVA OMADA/TP-LINK =====
            elif exec_cmd("show version", timeout=5) and ("omada" in exec_cmd("show version", timeout=5).lower() or "tp-link" in exec_cmd("show version", timeout=5).lower() or "tplink" in exec_cmd("show version", timeout=5).lower()):
                omada_version = exec_cmd("show version", timeout=10)
                logger.info(f"SSH probe: Detected Omada/TP-Link on {target}")
                info["device_type"] = "switch"
                info["os_name"] = "Omada"
                info["manufacturer"] = "TP-Link"
                info["category"] = "network"
                
                # Parse show version
                for line in omada_version.split('\n'):
                    if 'version' in line.lower():
                        info["os_version"] = line.split(':')[1].strip() if ':' in line else line.strip()
                    elif 'model' in line.lower():
                        info["model"] = line.split(':')[1].strip() if ':' in line else line.strip()
                
                # LLDP Neighbors
                lldp_out = exec_cmd("show lldp neighbors", timeout=10)
                if lldp_out:
                    neighbors = []
                    for line in lldp_out.split('\n'):
                        if line.strip() and not line.startswith('Interface'):
                            parts = line.split()
                            if len(parts) >= 3:
                                neighbor = {
                                    "local_interface": parts[0],
                                    "remote_device_name": parts[1],
                                    "remote_interface": parts[2] if len(parts) > 2 else "",
                                    "discovered_by": "lldp"
                                }
                                neighbors.append(neighbor)
                    if neighbors:
                        info["neighbors"] = neighbors
                        info["neighbors_count"] = len(neighbors)
                
                # Routing Table
                route_out = exec_cmd("show ip route", timeout=10)
                if route_out:
                    routes = []
                    for line in route_out.split('\n'):
                        if '/' in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                route = {
                                    "dst": parts[0] if '/' in parts[0] else parts[0],
                                    "gateway": parts[1] if len(parts) > 1 else "",
                                    "interface": parts[-1] if len(parts) > 2 else ""
                                }
                                routes.append(route)
                    if routes:
                        info["routing_table"] = routes[:100]
                        info["routing_count"] = len(routes)
                
                # ARP Table (solo se router)
                if info.get("device_type") == "router":
                    arp_out = exec_cmd("show arp", timeout=10)
                    if arp_out:
                        arp_entries = []
                        for line in arp_out.split('\n'):
                            if line.strip() and not line.startswith('IP') and not line.startswith('-'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    arp_entry = {
                                        "address": parts[0],
                                        "mac-address": parts[1],
                                        "interface": parts[-1] if len(parts) > 2 else ""
                                    }
                                    arp_entries.append(arp_entry)
                        if arp_entries:
                            info["arp_table"] = arp_entries[:100]
                            info["arp_count"] = len(arp_entries)
            
            # ===== PROVA UBIQUITI UNIFI (shell limitata -> cli -> enable) =====
            elif _detect_ubiquiti_unifi(exec_cmd):
                logger.info(f"SSH probe: Detected Ubiquiti UniFi on {target}")
                info = _probe_ubiquiti_unifi(client, target, exec_cmd)
            
            else:
                # ===== LINUX/UNIX/OTHER =====
                logger.debug(f"SSH probe: Detecting Linux/Unix on {target}")
            
            # Hostname
            info["hostname"] = exec_cmd("hostname")
            
            # OS Info
            os_release = exec_cmd("cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null")
            if os_release:
                for line in os_release.split('\n'):
                    if line.startswith('PRETTY_NAME='):
                        info["os_name"] = line.split('=', 1)[1].strip('"')
                    elif line.startswith('ID='):
                        info["os_id"] = line.split('=', 1)[1].strip('"')
                    elif line.startswith('VERSION_ID='):
                        info["os_version"] = line.split('=', 1)[1].strip('"')
            
            # Check for special devices
            # Ubiquiti
            ubnt_out = exec_cmd("cat /etc/board.info 2>/dev/null")
            if ubnt_out and 'board.' in ubnt_out.lower():
                info["device_type"] = "network"
                info["manufacturer"] = "Ubiquiti"
                info["os_name"] = "UniFi"
                for line in ubnt_out.split('\n'):
                    if 'board.name' in line.lower():
                        info["model"] = line.split('=')[-1].strip()
                    elif 'board.sysid' in line.lower():
                        info["serial_number"] = line.split('=')[-1].strip()
            
            # Synology
            syno_out = exec_cmd("cat /etc/synoinfo.conf 2>/dev/null")
            is_synology = False
            if syno_out and 'synology' in syno_out.lower():
                is_synology = True
                info["device_type"] = "storage"
                info["category"] = "storage"
                info["manufacturer"] = "Synology"
                info["os_name"] = "DSM"
                info["os_family"] = "Linux"
                for line in syno_out.split('\n'):
                    if 'upnpmodelname' in line.lower():
                        info["model"] = line.split('=')[-1].strip().strip('"')
                    elif 'productversion' in line.lower():
                        info["os_version"] = line.split('=')[-1].strip().strip('"')
                    elif 'unique' in line.lower() and 'serial' in line.lower():
                        serial_val = line.split('=')[-1].strip().strip('"')
                        if serial_val and not info.get("serial_number"):
                            info["serial_number"] = serial_val
                
                # ===== RACCOLTA INFORMAZIONI STORAGE SYNOLOGY =====
                storage_info = {}
                
                # Volumi - df -h per tutti i volumi
                df_out = exec_cmd("df -h 2>/dev/null | grep -E '^/dev|volume'")
                volumes = []
                if df_out:
                    for line in df_out.split('\n'):
                        parts = line.split()
                        if len(parts) >= 6:
                            try:
                                mount_point = parts[5]
                                # Filtra solo volumi Synology (volume1, volume2, etc.)
                                if '/volume' in mount_point or mount_point == '/':
                                    size_str = parts[1]
                                    used_str = parts[2]
                                    avail_str = parts[3]
                                    usage_str = parts[4].replace('%', '')
                                    
                                    # Converti dimensioni in GB
                                    def to_gb(size_str):
                                        if 'T' in size_str:
                                            return float(size_str.replace('T', '')) * 1024
                                        elif 'G' in size_str:
                                            return float(size_str.replace('G', ''))
                                        elif 'M' in size_str:
                                            return float(size_str.replace('M', '')) / 1024
                                        return 0.0
                                    
                                    total_gb = to_gb(size_str)
                                    used_gb = to_gb(used_str)
                                    free_gb = to_gb(avail_str)
                                    usage_percent = float(usage_str) if usage_str.replace('.', '').isdigit() else 0.0
                                    
                                    volumes.append({
                                        "name": mount_point.split('/')[-1] or "root",
                                        "mount_point": mount_point,
                                        "total_gb": round(total_gb, 2),
                                        "used_gb": round(used_gb, 2),
                                        "free_gb": round(free_gb, 2),
                                        "filesystem": parts[0],
                                        "usage_percent": round(usage_percent, 1)
                                    })
                            except Exception as e:
                                logger.debug(f"Error parsing df output: {e}")
                                pass
                
                if volumes:
                    storage_info["volumes"] = volumes
                
                # RAID - /proc/mdstat
                mdstat_out = exec_cmd("cat /proc/mdstat 2>/dev/null")
                if mdstat_out and 'md' in mdstat_out:
                    raid_info = {}
                    lines = mdstat_out.split('\n')
                    raid_devices = []
                    raid_level = None
                    raid_status = "unknown"
                    degraded = False
                    
                    for line in lines:
                        if line.startswith('md'):
                            parts = line.split()
                            if len(parts) >= 4:
                                raid_devices.append(parts[0])
                                if 'raid' in line.lower():
                                    for part in parts:
                                        if part.startswith('raid'):
                                            raid_level = part.upper()
                                        elif part in ['active', 'inactive', 'degraded']:
                                            raid_status = part
                                            if part == 'degraded':
                                                degraded = True
                    
                    if raid_devices:
                        raid_info = {
                            "level": raid_level or "unknown",
                            "status": raid_status,
                            "devices": raid_devices,
                            "degraded": degraded
                        }
                        storage_info["raid"] = raid_info
                
                # Dischi - lsblk e informazioni SMART
                lsblk_out = exec_cmd("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL 2>/dev/null")
                disks = []
                if lsblk_out:
                    current_disk = {}
                    for line in lsblk_out.split('\n')[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[0]
                            size_str = parts[1]
                            disk_type = parts[2]
                            
                            # Solo dischi fisici (disk) o partizioni principali
                            if disk_type == 'disk' or (disk_type == 'part' and not current_disk):
                                # Converti dimensione in GB
                                size_gb = 0.0
                                if 'T' in size_str:
                                    size_gb = float(size_str.replace('T', '')) * 1024
                                elif 'G' in size_str:
                                    size_gb = float(size_str.replace('G', ''))
                                elif 'M' in size_str:
                                    size_gb = float(size_str.replace('M', '')) / 1024
                                
                                model = parts[4] if len(parts) > 4 else ""
                                serial = parts[5] if len(parts) > 5 else ""
                                
                                # Prova a ottenere temperatura e salute via smartctl
                                temp = None
                                health = "unknown"
                                if name.startswith('sd'):
                                    # smartctl richiede privilegi root
                                    smart_out = exec_cmd_sudo(f"smartctl -a /dev/{name} 2>/dev/null | head -50", timeout=5)
                                    if smart_out:
                                        for smart_line in smart_out.split('\n'):
                                            if 'Temperature' in smart_line or 'Temperature_Celsius' in smart_line:
                                                temp_match = re.search(r'(\d+)\s*C', smart_line)
                                                if temp_match:
                                                    temp = int(temp_match.group(1))
                                            if 'SMART overall-health' in smart_line:
                                                if 'PASSED' in smart_line:
                                                    health = "good"
                                                elif 'FAILED' in smart_line:
                                                    health = "bad"
                                
                                disks.append({
                                    "name": name,
                                    "size_gb": round(size_gb, 2),
                                    "model": model,
                                    "serial": serial,
                                    "health": health,
                                    "temperature": temp
                                })
                                
                                # Limita a 20 dischi per performance
                                if len(disks) >= 20:
                                    break
                
                if disks:
                    storage_info["disks"] = disks
                
                # Temperatura sistema
                temp_info = {}
                # CPU temperature
                cpu_temp_out = exec_cmd("cat /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null | head -1")
                if cpu_temp_out and cpu_temp_out.strip().isdigit():
                    temp_info["cpu"] = int(int(cpu_temp_out.strip()) / 1000)  # Converti da millidegrees
                
                # System temperature (se disponibile)
                sys_temp_out = exec_cmd("cat /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null | head -2 | tail -1")
                if sys_temp_out and sys_temp_out.strip().isdigit():
                    temp_info["system"] = int(int(sys_temp_out.strip()) / 1000)
                
                # Temperature dischi (se non già raccolte)
                if disks and not any(d.get("temperature") for d in disks):
                    disk_temps = []
                    for disk in disks[:10]:  # Limita a 10 per performance
                        if disk["name"].startswith('sd'):
                            # smartctl richiede privilegi root
                            temp_out = exec_cmd_sudo(f"smartctl -a /dev/{disk['name']} 2>/dev/null | grep -i temperature | head -1", timeout=3)
                            if temp_out:
                                temp_match = re.search(r'(\d+)\s*C', temp_out)
                                if temp_match:
                                    disk_temps.append(int(temp_match.group(1)))
                    if disk_temps:
                        temp_info["disks"] = disk_temps
                
                if temp_info:
                    storage_info["temperature"] = temp_info
                
                # Salva storage_info se raccolto
                if storage_info:
                    info["storage_info"] = storage_info
                    logger.info(f"SSH probe: Collected storage info for Synology: {len(volumes)} volumes, {len(disks)} disks")
            
            # QNAP Detection
            qnap_conf = exec_cmd("cat /etc/config/uLinux.conf 2>/dev/null")
            uname_out = exec_cmd("uname -a 2>/dev/null")
            is_qnap = False
            if (qnap_conf and ('qnap' in qnap_conf.lower() or 'qts' in qnap_conf.lower())) or \
               (uname_out and 'qnap' in uname_out.lower()):
                is_qnap = True
                info["device_type"] = "storage"
                info["category"] = "storage"
                info["manufacturer"] = "QNAP"
                info["os_name"] = "QTS"
                info["os_family"] = "Linux"
                
                # Modello QNAP
                model_out = exec_cmd("/sbin/getcfg System 'Model Name' 2>/dev/null")
                if model_out:
                    info["model"] = model_out.strip()
                
                # Versione QTS
                version_out = exec_cmd("/sbin/getcfg System 'Version' 2>/dev/null")
                if version_out:
                    info["os_version"] = version_out.strip()
                
                # ===== RACCOLTA INFORMAZIONI STORAGE QNAP =====
                storage_info = {}
                
                # Volumi - df -h per tutti i volumi
                df_out = exec_cmd("df -h 2>/dev/null | grep -E '^/dev|share'")
                volumes = []
                if df_out:
                    for line in df_out.split('\n'):
                        parts = line.split()
                        if len(parts) >= 6:
                            try:
                                mount_point = parts[5]
                                # Filtra volumi QNAP (share, volume, etc.)
                                if '/share' in mount_point or '/mnt' in mount_point or mount_point == '/':
                                    size_str = parts[1]
                                    used_str = parts[2]
                                    avail_str = parts[3]
                                    usage_str = parts[4].replace('%', '')
                                    
                                    # Converti dimensioni in GB
                                    def to_gb(size_str):
                                        if 'T' in size_str:
                                            return float(size_str.replace('T', '')) * 1024
                                        elif 'G' in size_str:
                                            return float(size_str.replace('G', ''))
                                        elif 'M' in size_str:
                                            return float(size_str.replace('M', '')) / 1024
                                        return 0.0
                                    
                                    total_gb = to_gb(size_str)
                                    used_gb = to_gb(used_str)
                                    free_gb = to_gb(avail_str)
                                    usage_percent = float(usage_str) if usage_str.replace('.', '').isdigit() else 0.0
                                    
                                    volumes.append({
                                        "name": mount_point.split('/')[-1] or "root",
                                        "mount_point": mount_point,
                                        "total_gb": round(total_gb, 2),
                                        "used_gb": round(used_gb, 2),
                                        "free_gb": round(free_gb, 2),
                                        "filesystem": parts[0],
                                        "usage_percent": round(usage_percent, 1)
                                    })
                            except Exception as e:
                                logger.debug(f"Error parsing df output: {e}")
                                pass
                
                if volumes:
                    storage_info["volumes"] = volumes
                
                # RAID - /proc/mdstat
                mdstat_out = exec_cmd("cat /proc/mdstat 2>/dev/null")
                if mdstat_out and 'md' in mdstat_out:
                    raid_info = {}
                    lines = mdstat_out.split('\n')
                    raid_devices = []
                    raid_level = None
                    raid_status = "unknown"
                    degraded = False
                    
                    for line in lines:
                        if line.startswith('md'):
                            parts = line.split()
                            if len(parts) >= 4:
                                raid_devices.append(parts[0])
                                if 'raid' in line.lower():
                                    for part in parts:
                                        if part.startswith('raid'):
                                            raid_level = part.upper()
                                        elif part in ['active', 'inactive', 'degraded']:
                                            raid_status = part
                                            if part == 'degraded':
                                                degraded = True
                    
                    if raid_devices:
                        raid_info = {
                            "level": raid_level or "unknown",
                            "status": raid_status,
                            "devices": raid_devices,
                            "degraded": degraded
                        }
                        storage_info["raid"] = raid_info
                
                # Dischi - lsblk e informazioni SMART
                lsblk_out = exec_cmd("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL 2>/dev/null")
                disks = []
                if lsblk_out:
                    for line in lsblk_out.split('\n')[1:]:  # Skip header
                        parts = line.split()
                        if len(parts) >= 3:
                            name = parts[0]
                            size_str = parts[1]
                            disk_type = parts[2]
                            
                            # Solo dischi fisici (disk) o partizioni principali
                            if disk_type == 'disk' or (disk_type == 'part' and len(disks) == 0):
                                # Converti dimensione in GB
                                size_gb = 0.0
                                if 'T' in size_str:
                                    size_gb = float(size_str.replace('T', '')) * 1024
                                elif 'G' in size_str:
                                    size_gb = float(size_str.replace('G', ''))
                                elif 'M' in size_str:
                                    size_gb = float(size_str.replace('M', '')) / 1024
                                
                                model = parts[4] if len(parts) > 4 else ""
                                serial = parts[5] if len(parts) > 5 else ""
                                
                                # Prova a ottenere temperatura e salute via smartctl
                                temp = None
                                health = "unknown"
                                if name.startswith('sd'):
                                    # smartctl richiede privilegi root
                                    smart_out = exec_cmd_sudo(f"smartctl -a /dev/{name} 2>/dev/null | head -50", timeout=5)
                                    if smart_out:
                                        for smart_line in smart_out.split('\n'):
                                            if 'Temperature' in smart_line or 'Temperature_Celsius' in smart_line:
                                                temp_match = re.search(r'(\d+)\s*C', smart_line)
                                                if temp_match:
                                                    temp = int(temp_match.group(1))
                                            if 'SMART overall-health' in smart_line:
                                                if 'PASSED' in smart_line:
                                                    health = "good"
                                                elif 'FAILED' in smart_line:
                                                    health = "bad"
                                
                                disks.append({
                                    "name": name,
                                    "size_gb": round(size_gb, 2),
                                    "model": model,
                                    "serial": serial,
                                    "health": health,
                                    "temperature": temp
                                })
                                
                                # Limita a 20 dischi per performance
                                if len(disks) >= 20:
                                    break
                
                if disks:
                    storage_info["disks"] = disks
                
                # Temperatura sistema
                temp_info = {}
                # CPU temperature
                cpu_temp_out = exec_cmd("cat /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null | head -1")
                if cpu_temp_out and cpu_temp_out.strip().isdigit():
                    temp_info["cpu"] = int(int(cpu_temp_out.strip()) / 1000)  # Converti da millidegrees
                
                # System temperature (se disponibile)
                sys_temp_out = exec_cmd("cat /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null | head -2 | tail -1")
                if sys_temp_out and sys_temp_out.strip().isdigit():
                    temp_info["system"] = int(int(sys_temp_out.strip()) / 1000)
                
                # Temperature dischi (se non già raccolte)
                if disks and not any(d.get("temperature") for d in disks):
                    disk_temps = []
                    for disk in disks[:10]:  # Limita a 10 per performance
                        if disk["name"].startswith('sd'):
                            # smartctl richiede privilegi root
                            temp_out = exec_cmd_sudo(f"smartctl -a /dev/{disk['name']} 2>/dev/null | grep -i temperature | head -1", timeout=3)
                            if temp_out:
                                temp_match = re.search(r'(\d+)\s*C', temp_out)
                                if temp_match:
                                    disk_temps.append(int(temp_match.group(1)))
                    if disk_temps:
                        temp_info["disks"] = disk_temps
                
                if temp_info:
                    storage_info["temperature"] = temp_info
                
                # Salva storage_info se raccolto
                if storage_info:
                    info["storage_info"] = storage_info
                    logger.info(f"SSH probe: Collected storage info for QNAP: {len(volumes)} volumes, {len(disks)} disks")
            
            # Proxmox VE Detection (più robusta - Proxmox è basato su Debian)
            pve_ver = exec_cmd("pveversion 2>/dev/null")
            if pve_ver and 'pve-manager' in pve_ver.lower():
                info["device_type"] = "hypervisor"
                info["category"] = "hypervisor"
                info["os_name"] = "Proxmox VE"
                info["os_family"] = "Proxmox VE"
                info["manufacturer"] = "Proxmox Server Solutions GmbH"
                info["os_version"] = pve_ver
                # Conta container e VM
                lxc = exec_cmd("pct list 2>/dev/null | tail -n +2 | wc -l")
                if lxc.isdigit():
                    info["lxc_containers"] = int(lxc)
                vms = exec_cmd("qm list 2>/dev/null | tail -n +2 | wc -l")
                if vms.isdigit():
                    info["vms"] = int(vms)
                # Cluster info
                cluster = exec_cmd("pvecm status 2>/dev/null | grep 'Cluster Name' | cut -d: -f2")
                if cluster:
                    info["cluster_name"] = cluster.strip()
                # Storage
                storage = exec_cmd("pvesm status 2>/dev/null | tail -n +2 | wc -l")
                if storage.isdigit():
                    info["storage_count"] = int(storage)
            elif 'proxmox' in os_release.lower():
                info["device_type"] = "hypervisor"
                info["category"] = "hypervisor"
                info["os_name"] = "Proxmox VE"
                info["manufacturer"] = "Proxmox Server Solutions GmbH"
            
            # Default device type
            if not info.get("device_type"):
                info["device_type"] = "linux"
            
            # Kernel
            kernel = exec_cmd("uname -r")
            if kernel:
                info["kernel"] = kernel
            
            # Architecture
            arch = exec_cmd("uname -m")
            if arch:
                info["architecture"] = arch
            
            # CPU Info
            cpu_info = exec_cmd("cat /proc/cpuinfo | grep 'model name' | head -1")
            if cpu_info and ':' in cpu_info:
                info["cpu_model"] = cpu_info.split(':')[1].strip()
            
            # CPU Cores
            cores = exec_cmd("nproc 2>/dev/null || grep -c processor /proc/cpuinfo")
            if cores.isdigit():
                info["cpu_cores"] = int(cores)
            
            # RAM
            mem = exec_cmd("free -m | grep Mem | awk '{print $2}'")
            if mem.isdigit():
                info["ram_total_mb"] = int(mem)
            
            # Disk
            disk = exec_cmd("df -BG / | awk 'NR==2 {print $2, $4}'")
            if disk:
                parts = disk.split()
                if len(parts) >= 2:
                    try:
                        info["disk_total_gb"] = int(parts[0].replace('G', ''))
                        info["disk_free_gb"] = int(parts[1].replace('G', ''))
                    except:
                        pass
            
            # Uptime
            uptime = exec_cmd("uptime -p 2>/dev/null || uptime")
            if uptime:
                info["uptime"] = uptime
            
            # Serial (DMI)
            serial = exec_cmd("cat /sys/class/dmi/id/product_serial 2>/dev/null")
            if serial and serial != "To Be Filled By O.E.M." and "Permission" not in serial:
                info["serial_number"] = serial
            
            # Manufacturer/Model (DMI)
            vendor = exec_cmd("cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
            if vendor and vendor != "To Be Filled By O.E.M.":
                info["manufacturer"] = vendor
            
            model = exec_cmd("cat /sys/class/dmi/id/product_name 2>/dev/null")
            if model and model != "To Be Filled By O.E.M.":
                info["model"] = model
            
            # ===== INFORMAZIONI DETTAGLIATE LINUX =====
            
            # RAM dettagli
            mem_free = exec_cmd("free -m | grep Mem | awk '{print $4}'")
            if mem_free.isdigit():
                info["ram_free_mb"] = int(mem_free)
            
            # CPU speed
            cpu_speed = exec_cmd("lscpu 2>/dev/null | grep 'CPU MHz' | awk '{print $3}'")
            if cpu_speed:
                try:
                    info["cpu_speed_mhz"] = int(float(cpu_speed))
                except:
                    pass
            
            # All disks
            disks_out = exec_cmd("df -BG -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2")
            if disks_out:
                disks = []
                for line in disks_out.split('\n'):
                    parts = line.split()
                    if len(parts) >= 6:
                        try:
                            disks.append({
                                "device": parts[0],
                                "mount": parts[5],
                                "size_gb": int(parts[1].replace('G', '')),
                                "free_gb": int(parts[3].replace('G', '')),
                            })
                        except:
                            pass
                if disks:
                    info["disks"] = disks
            
            # Network interfaces
            ifaces_out = exec_cmd("ip -o addr show 2>/dev/null | grep -v '127.0.0.1' | awk '{print $2, $4}'")
            if ifaces_out:
                interfaces = []
                for line in ifaces_out.split('\n'):
                    parts = line.split()
                    if len(parts) >= 2:
                        interfaces.append({
                            "name": parts[0],
                            "address": parts[1].split('/')[0],
                        })
                if interfaces:
                    info["network_interfaces"] = interfaces
            
            # MAC addresses
            macs_out = exec_cmd("ip link show 2>/dev/null | grep 'link/ether' | awk '{print $2}'")
            if macs_out:
                macs = [m for m in macs_out.split('\n') if m]
                if macs:
                    info["mac_addresses"] = macs
            
            # Docker installed?
            docker_ver = exec_cmd("docker --version 2>/dev/null")
            if docker_ver:
                info["docker_version"] = docker_ver.replace('Docker version ', '').split(',')[0]
                # Docker containers count
                containers = exec_cmd("docker ps -q 2>/dev/null | wc -l")
                if containers.isdigit():
                    info["docker_containers_running"] = int(containers)
            
            # LXC/LXD containers (Proxmox)
            lxc_count = exec_cmd("pct list 2>/dev/null | tail -n +2 | wc -l")
            if lxc_count.isdigit() and int(lxc_count) > 0:
                info["lxc_containers"] = int(lxc_count)
            
            # VMs (Proxmox)
            vm_count = exec_cmd("qm list 2>/dev/null | tail -n +2 | wc -l")
            if vm_count.isdigit() and int(vm_count) > 0:
                info["vms"] = int(vm_count)
            
            # ===== SERVIZI ATTIVI (tutti) =====
            services_out = exec_cmd("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null | awk '{print $1}'", timeout=10)
            if services_out:
                all_services = [s.replace('.service', '') for s in services_out.split('\n') if s]
                if all_services:
                    info["running_services"] = all_services[:100]  # Limita a 100 servizi
                    info["running_services_count"] = len(all_services)
                    logger.debug(f"SSH probe: Collected {len(all_services)} running services")
                    
                    # Filtra servizi importanti/critici separatamente
                    important = ["nginx", "apache", "httpd", "mysql", "mariadb", "postgresql", "redis", 
                               "mongodb", "docker", "sshd", "postfix", "dovecot", "named", "bind", 
                               "haproxy", "squid", "samba", "nfs", "pve", "ceph", "grafana", "prometheus",
                               "zabbix", "nagios", "elasticsearch", "kibana", "logstash", "influxdb"]
                    filtered = [s for s in all_services if any(imp in s.lower() for imp in important)]
                    if filtered:
                        info["important_services"] = filtered
                        logger.debug(f"SSH probe: Found {len(filtered)} important services")
            else:
                logger.debug(f"SSH probe: No services output (services_out empty or failed)")
            
            # ===== CRON JOBS =====
            cron_jobs = []
            
            # User crontab
            user_cron = exec_cmd("crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$'")
            if user_cron and "no crontab" not in user_cron.lower():
                for line in user_cron.split('\n'):
                    if line.strip():
                        cron_jobs.append({"source": "user_crontab", "job": line.strip()})
            
            # Root crontab
            root_cron = exec_cmd("sudo crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' || true")
            if root_cron and "no crontab" not in root_cron.lower():
                for line in root_cron.split('\n'):
                    if line.strip():
                        cron_jobs.append({"source": "root_crontab", "job": line.strip()})
            
            # System cron.d
            cron_d = exec_cmd("ls /etc/cron.d/ 2>/dev/null")
            if cron_d:
                for f in cron_d.split('\n'):
                    if f and not f.startswith('.'):
                        cron_jobs.append({"source": f"/etc/cron.d/{f}", "job": "file"})
            
            if cron_jobs:
                info["cron_jobs"] = cron_jobs[:50]  # Limita a 50
                info["cron_jobs_count"] = len(cron_jobs)
                logger.debug(f"SSH probe: Collected {len(cron_jobs)} cron jobs")
            else:
                logger.debug(f"SSH probe: No cron jobs found")
            
            # ===== HARDWARE DETTAGLIATO (lshw/dmidecode) =====
            # Prova lshw (più completo) - richiede sudo
            lshw_out = exec_cmd_sudo("lshw -short -quiet 2>/dev/null | head -50", timeout=15)
            if lshw_out and "WARNING" not in lshw_out:
                info["hardware_inventory"] = lshw_out
            else:
                # Fallback a dmidecode - richiede sudo
                dmi_out = exec_cmd_sudo("dmidecode -t system 2>/dev/null | grep -E '(Manufacturer|Product|Serial|UUID)' | head -10")
                if dmi_out:
                    info["hardware_inventory"] = dmi_out
            
            # BIOS info
            bios_vendor = exec_cmd("cat /sys/class/dmi/id/bios_vendor 2>/dev/null")
            bios_version = exec_cmd("cat /sys/class/dmi/id/bios_version 2>/dev/null")
            bios_date = exec_cmd("cat /sys/class/dmi/id/bios_date 2>/dev/null")
            if bios_vendor:
                info["bios_vendor"] = bios_vendor
            if bios_version:
                info["bios_version"] = bios_version
            if bios_date:
                info["bios_date"] = bios_date
            
            # ===== DISCHI DETTAGLIATI (lsblk) =====
            lsblk_out = exec_cmd("lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL -J 2>/dev/null", timeout=10)
            if lsblk_out and lsblk_out.startswith('{'):
                try:
                    import json
                    lsblk_data = json.loads(lsblk_out)
                    if "blockdevices" in lsblk_data:
                        info["block_devices"] = lsblk_data["blockdevices"]
                except:
                    pass
            
            # Fallback a lsblk semplice
            if not info.get("block_devices"):
                lsblk_simple = exec_cmd("lsblk -d -o NAME,SIZE,TYPE,MODEL 2>/dev/null | tail -n +2")
                if lsblk_simple:
                    block_devs = []
                    for line in lsblk_simple.split('\n'):
                        parts = line.split()
                        if len(parts) >= 3:
                            block_devs.append({
                                "name": parts[0],
                                "size": parts[1],
                                "type": parts[2],
                                "model": ' '.join(parts[3:]) if len(parts) > 3 else None
                            })
                    if block_devs:
                        info["block_devices"] = block_devs
            
            # ===== NETWORK COMPLETO =====
            # IP addresses dettagliati
            ip_addr_out = exec_cmd("ip -o addr show 2>/dev/null", timeout=5)
            if ip_addr_out:
                ip_addresses = []
                for line in ip_addr_out.split('\n'):
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] == 'inet':
                        ip_addresses.append({
                            "interface": parts[1],
                            "address": parts[3].split('/')[0],
                            "prefix": parts[3].split('/')[1] if '/' in parts[3] else None,
                            "scope": parts[-1] if 'scope' in line else None
                        })
                    elif len(parts) >= 4 and parts[2] == 'inet6':
                        ip_addresses.append({
                            "interface": parts[1],
                            "address": parts[3].split('/')[0],
                            "prefix": parts[3].split('/')[1] if '/' in parts[3] else None,
                            "type": "ipv6"
                        })
                if ip_addresses:
                    info["ip_addresses"] = ip_addresses
                    logger.debug(f"SSH probe: Collected {len(ip_addresses)} IP addresses")
            else:
                logger.debug(f"SSH probe: No IP addresses output")
            
            # Routing table
            routes_out = exec_cmd("ip route show 2>/dev/null | head -20")
            if routes_out:
                routes = []
                for line in routes_out.split('\n'):
                    if line.strip():
                        routes.append(line.strip())
                if routes:
                    info["routes"] = routes
            
            # Default gateway
            gateway = exec_cmd("ip route | grep default | awk '{print $3}'")
            if gateway:
                info["default_gateway"] = gateway.split('\n')[0]
            
            # DNS servers
            dns_out = exec_cmd("cat /etc/resolv.conf 2>/dev/null | grep nameserver | awk '{print $2}'")
            if dns_out:
                dns_servers = [d for d in dns_out.split('\n') if d]
                if dns_servers:
                    info["dns_servers"] = dns_servers
            
            # Listening ports
            listening_out = exec_cmd("ss -tlnp 2>/dev/null | tail -n +2 | awk '{print $4}' | rev | cut -d: -f1 | rev | sort -u")
            if listening_out:
                ports = [p for p in listening_out.split('\n') if p and p.isdigit()]
                if ports:
                    info["listening_ports"] = [int(p) for p in ports][:50]
            
            # Timezone
            tz = exec_cmd("timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null")
            if tz:
                info["timezone"] = tz
            
            # Users with shell access
            users_out = exec_cmd("grep -E '/bin/(ba)?sh$' /etc/passwd | cut -d: -f1")
            if users_out:
                users = [u for u in users_out.split('\n') if u and u not in ['root']]
                if users:
                    info["shell_users"] = users
            
            # Last login
            last_login = exec_cmd("last -1 -w 2>/dev/null | head -1")
            if last_login and 'wtmp' not in last_login:
                info["last_login"] = last_login
            
            # Virtualization type
            virt = exec_cmd("systemd-detect-virt 2>/dev/null")
            if virt and virt != "none":
                info["virtualization"] = virt
            
            # ===== LOAD AVERAGE =====
            load_avg = exec_cmd("cat /proc/loadavg | awk '{print $1, $2, $3}'")
            if load_avg:
                info["load_average"] = load_avg
            
            # ===== INSTALLED PACKAGES COUNT =====
            pkg_count = exec_cmd("dpkg -l 2>/dev/null | wc -l || rpm -qa 2>/dev/null | wc -l")
            if pkg_count and pkg_count.isdigit():
                info["packages_installed"] = int(pkg_count)
        
        client.close()
        
        # Log summary dei dati raccolti
        collected_keys = [k for k in info.keys() if k not in ['address', 'mac_address', 'device_type', 'category', 'identified_by']]
        logger.info(f"SSH probe successful: {info.get('hostname')} ({info.get('os_name', 'Unknown')}), collected {len(collected_keys)} fields: {sorted(collected_keys)[:20]}")
        if info.get("running_services_count"):
            logger.info(f"SSH probe: running_services_count={info.get('running_services_count')}, cron_jobs_count={info.get('cron_jobs_count')}, neighbors_count={info.get('neighbors_count')}")
        
        return info
    
    return await loop.run_in_executor(_executor, connect)


def _detect_ubiquiti_unifi(exec_cmd) -> bool:
    """
    Rileva se il dispositivo è un Ubiquiti UniFi con shell limitata.
    Gli UniFi entrano in una shell limitata BusyBox, ma supportano il comando 'info'.
    """
    # Prova il comando 'info' tipico degli UniFi
    info_out = exec_cmd("info", timeout=3)
    if info_out and ("model" in info_out.lower() or "version" in info_out.lower() or "mac" in info_out.lower()):
        return True
    
    # Prova a vedere se siamo in una shell BusyBox di un UniFi
    busybox = exec_cmd("busybox", timeout=3)
    if busybox and "busybox" in busybox.lower():
        # Controlla se esiste /etc/board.info (tipico UniFi)
        board = exec_cmd("cat /etc/board.info 2>/dev/null", timeout=3)
        if board and "board" in board.lower():
            return True
    
    return False


def _probe_ubiquiti_unifi(client, target: str, exec_cmd) -> Dict[str, Any]:
    """
    Probe per dispositivi Ubiquiti UniFi.
    
    Gli UniFi hanno una shell limitata. Per alcuni modelli:
    - 'info' mostra informazioni base
    - 'mca-cli' o 'cli' entrano in una shell Cisco-like
    - Poi 'enable' e 'configure' per accedere a più comandi
    
    Per altri (come AP e switch):
    - Usano direttamente comandi BusyBox/Linux
    """
    import time
    
    info = {
        "device_type": "access_point",
        "manufacturer": "Ubiquiti",
        "os_name": "UniFi",
        "category": "network",
    }
    
    logger.debug(f"SSH probe: Probing Ubiquiti UniFi on {target}")
    
    # 1. Prova comando 'info' (funziona su molti UniFi)
    info_out = exec_cmd("info", timeout=5)
    if info_out:
        for line in info_out.split('\n'):
            line = line.strip()
            ll = line.lower()
            if ll.startswith('model:') or ll.startswith('model='):
                info["model"] = line.split(':', 1)[-1].split('=')[-1].strip()
                # Determina tipo device dal modello
                model_lower = info["model"].lower()
                if 'usg' in model_lower or 'udm' in model_lower or 'udr' in model_lower:
                    info["device_type"] = "router"
                elif 'usw' in model_lower or 'switch' in model_lower:
                    info["device_type"] = "switch"
                elif 'uap' in model_lower or 'ap' in model_lower or 'u6' in model_lower or 'u7' in model_lower:
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
                ip = line.split(':', 1)[-1].split('=')[-1].strip()
                if ip:
                    info["ip_address"] = ip
    
    # 2. Prova board.info per info hardware
    board_out = exec_cmd("cat /etc/board.info 2>/dev/null", timeout=3)
    if board_out:
        for line in board_out.split('\n'):
            if 'board.name' in line.lower():
                info["model"] = line.split('=')[-1].strip()
            elif 'board.sysid' in line.lower():
                info["serial_number"] = line.split('=')[-1].strip()
            elif 'board.shortname' in line.lower():
                info["short_name"] = line.split('=')[-1].strip()
    
    # 3. Hostname se non ancora ottenuto
    if not info.get("hostname"):
        hostname = exec_cmd("hostname 2>/dev/null", timeout=3)
        if hostname:
            info["hostname"] = hostname
    
    # 4. Prova ad accedere alla CLI avanzata per router/switch
    # Molti UniFi supportano: cli -> enable -> configure
    cli_info = _try_unifi_cli(client, target)
    if cli_info:
        info.update(cli_info)
    
    # 5. Informazioni di rete
    # Interface info
    iface_out = exec_cmd("ifconfig 2>/dev/null || ip addr 2>/dev/null", timeout=5)
    if iface_out:
        interfaces = []
        current_iface = {}
        for line in iface_out.split('\n'):
            if line and not line.startswith(' ') and not line.startswith('\t'):
                if current_iface:
                    interfaces.append(current_iface)
                iface_name = line.split(':')[0].split()[0] if ':' in line else line.split()[0]
                current_iface = {"name": iface_name}
            elif 'inet ' in line.lower():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        current_iface["ipv4"] = parts[i + 1].split('/')[0]
            elif 'hwaddr' in line.lower() or 'ether' in line.lower():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.lower() in ('hwaddr', 'ether') and i + 1 < len(parts):
                        current_iface["mac"] = parts[i + 1]
        if current_iface:
            interfaces.append(current_iface)
        if interfaces:
            info["interfaces"] = [i for i in interfaces if i.get("name") and not i["name"].startswith("lo")]
            info["network_interfaces"] = info["interfaces"]  # Alias per compatibilità unified scanner
            info["interface_count"] = len(info["interfaces"])
    
    # 6. Uptime se non ancora
    if not info.get("uptime"):
        uptime_out = exec_cmd("uptime 2>/dev/null", timeout=3)
        if uptime_out and 'up' in uptime_out:
            info["uptime"] = uptime_out
    
    # 7. CPU e memoria (se disponibili)
    cpu_info = exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep -i 'model name' | head -1", timeout=3)
    if cpu_info:
        info["cpu_model"] = cpu_info.split(':')[-1].strip()
    
    mem_out = exec_cmd("cat /proc/meminfo 2>/dev/null | grep MemTotal", timeout=3)
    if mem_out:
        try:
            mem_kb = int(mem_out.split()[1])
            info["ram_total_mb"] = mem_kb // 1024
        except:
            pass
    
    return info


def _try_unifi_cli(client, target: str) -> Optional[Dict[str, Any]]:
    """
    Prova ad accedere alla CLI avanzata UniFi.
    
    Sequenza per molti device UniFi:
    1. 'cli' o 'mca-cli' - entra in shell Cisco-like
    2. 'enable' - modo privilegiato
    3. Poi puoi eseguire comandi come 'show running-config', 'show interfaces', etc.
    """
    import time
    
    try:
        # Apri una sessione interattiva
        channel = client.invoke_shell()
        channel.settimeout(10)
        time.sleep(0.5)
        
        # Svuota buffer iniziale
        if channel.recv_ready():
            channel.recv(4096)
        
        info = {}
        
        # Prova 'cli' per entrare nella shell avanzata
        channel.send("cli\n")
        time.sleep(1)
        
        output = ""
        if channel.recv_ready():
            output = channel.recv(4096).decode('utf-8', errors='ignore')
        
        # Se siamo entrati in CLI (prompt cambia)
        if '>' in output or '#' in output or 'cli' in output.lower():
            logger.debug(f"SSH probe: UniFi CLI mode entered on {target}")
            
            # Prova 'enable' per modo privilegiato
            channel.send("enable\n")
            time.sleep(0.5)
            enable_output = ""
            if channel.recv_ready():
                enable_output = channel.recv(4096).decode('utf-8', errors='ignore')
            
            # Se necessario, entra in modalità config (simile a Cisco)
            # Alcuni UniFi richiedono 'configure' dopo 'enable' per alcuni comandi
            in_config_mode = False
            if '#' in enable_output or 'config' in enable_output.lower():
                # Prova 'configure' per entrare in modalità configurazione
                channel.send("configure\n")
                time.sleep(0.5)
                config_output = ""
                if channel.recv_ready():
                    config_output = channel.recv(4096).decode('utf-8', errors='ignore')
                if 'config' in config_output.lower() or '(config)' in config_output.lower():
                    in_config_mode = True
                    logger.debug(f"SSH probe: UniFi config mode entered on {target}")
            
            # Funzione per eseguire comandi CLI
            def cli_cmd(cmd: str, wait_time: float = 1.0) -> str:
                channel.send(f"{cmd}\n")
                time.sleep(wait_time)
                result = ""
                # Leggi tutto l'output disponibile
                max_iterations = 10
                iteration = 0
                while iteration < max_iterations:
                    if channel.recv_ready():
                        chunk = channel.recv(4096).decode('utf-8', errors='ignore')
                        result += chunk
                        time.sleep(0.2)  # Piccola pausa per permettere più dati
                    else:
                        break
                    iteration += 1
                return result
            
            # Show version (funziona sia in enable che in config)
            version_out = cli_cmd("show version", wait_time=1.5)
            if version_out:
                for line in version_out.split('\n'):
                    ll = line.lower().strip()
                    if 'software version' in ll or 'version:' in ll or 'firmware version' in ll:
                        version_val = line.split(':')[-1].strip()
                        if version_val:
                            info["firmware_version"] = version_val
                            info["os_version"] = version_val  # Alias
                    elif 'hardware version' in ll or 'hw version' in ll:
                        hw_val = line.split(':')[-1].strip()
                        if hw_val:
                            info["hardware_version"] = hw_val
                    elif 'serial' in ll and 'number' in ll:
                        serial_val = line.split(':')[-1].strip()
                        if serial_val:
                            info["serial_number"] = serial_val
                    elif 'model' in ll and ':' in line:
                        model_val = line.split(':')[-1].strip()
                        if model_val and not info.get("model"):
                            info["model"] = model_val
            
            # Show interfaces (per switch/router) - comando Cisco-like
            iface_out = cli_cmd("show interfaces status", wait_time=2.0)
            if iface_out:
                interfaces = []
                for line in iface_out.split('\n'):
                    line = line.strip()
                    if not line or line.startswith('Port') or line.startswith('-') or 'Name' in line:
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        iface = {
                            "name": parts[0],
                            "status": parts[1] if len(parts) > 1 else "unknown"
                        }
                        # Cerca VLAN, speed, duplex
                        for i, p in enumerate(parts):
                            if p.lower() in ['up', 'down']:
                                iface["running"] = p.lower() == 'up'
                            elif 'g' in p.lower() and ('speed' in line.lower() or 'mbps' in p.lower()):
                                iface["speed"] = p
                        interfaces.append(iface)
                if interfaces:
                    info["interfaces"] = interfaces
                    info["network_interfaces"] = interfaces  # Alias per compatibilità
                    info["interface_count"] = len(interfaces)
                    logger.info(f"SSH probe: Collected {len(interfaces)} UniFi interfaces via CLI")
            
            # Show interfaces brief (alternativa)
            if not info.get("interfaces"):
                iface_brief = cli_cmd("show interfaces brief", wait_time=2.0)
                if iface_brief and ('interface' in iface_brief.lower() or 'port' in iface_brief.lower()):
                    interfaces = []
                    for line in iface_brief.split('\n'):
                        line = line.strip()
                        if not line or line.startswith('Interface') or line.startswith('-'):
                            continue
                        parts = line.split()
                        if len(parts) >= 1:
                            interfaces.append({"name": parts[0]})
                    if interfaces:
                        info["interfaces"] = interfaces
                        info["network_interfaces"] = interfaces
                        info["interface_count"] = len(interfaces)
            
            # Esci da config mode se necessario prima di eseguire show commands
            if in_config_mode:
                channel.send("exit\n")
                time.sleep(0.5)
                if channel.recv_ready():
                    channel.recv(4096)
            
            # Show LLDP neighbors (detail) - comando Cisco-like
            lldp_out = cli_cmd("show lldp neighbors detail", wait_time=2.0)
            if lldp_out and ('device' in lldp_out.lower() or 'neighbor' in lldp_out.lower() or 'interface' in lldp_out.lower()):
                neighbors = []
                current = {}
                for line in lldp_out.split('\n'):
                    line = line.strip()
                    ll = line.lower()
                    
                    if ll.startswith('interface:') or ll.startswith('local port:'):
                        if current:
                            neighbors.append(current)
                        current = {"discovered_by": "lldp"}
                        current["local_port"] = line.split(':', 1)[1].strip() if ':' in line else ""
                    elif ll.startswith('chassis id:') or ll.startswith('chassis:') and current:
                        # Next line might have chassis id
                        pass
                    elif ll.startswith('system name:') or ll.startswith('sysname:') and current:
                        current["remote_device"] = line.split(':', 1)[1].strip() if ':' in line else ""
                    elif ll.startswith('port id:') or ll.startswith('portid:') and current:
                        current["remote_port"] = line.split(':', 1)[1].strip() if ':' in line else ""
                    elif ll.startswith('system description:') or ll.startswith('sysdescr:') and current:
                        current["platform"] = line.split(':', 1)[1].strip() if ':' in line else ""
                
                if current:
                    neighbors.append(current)
                
                if neighbors:
                    info["neighbors"] = neighbors
                    info["lldp_neighbors"] = neighbors  # Alias per compatibilità unified scanner
                    info["neighbors_count"] = len(neighbors)
                    logger.info(f"SSH probe: Collected {len(neighbors)} UniFi LLDP neighbors via CLI")
                else:
                    # Fallback a formato semplice
                    lldp_simple = cli_cmd("show lldp neighbors")
                    if lldp_simple and ('device' in lldp_simple.lower() or 'neighbor' in lldp_simple.lower()):
                        neighbors = []
                        for line in lldp_simple.split('\n'):
                            if line.strip() and not line.startswith('Port') and not line.startswith('-'):
                                parts = line.split()
                                if len(parts) >= 3:
                                    neighbors.append({
                                        "local_port": parts[0],
                                        "remote_device": parts[1] if len(parts) > 1 else "",
                                        "remote_port": parts[2] if len(parts) > 2 else "",
                                        "discovered_by": "lldp"
                                    })
                        if neighbors:
                            info["neighbors"] = neighbors
                            info["lldp_neighbors"] = neighbors  # Alias per compatibilità unified scanner
                            info["neighbors_count"] = len(neighbors)
            
            # Show running-config per info aggiuntive (se disponibile)
            if not info.get("model") or not info.get("firmware_version"):
                config_out = cli_cmd("show running-config | include version", wait_time=1.5)
                if config_out:
                    for line in config_out.split('\n'):
                        ll = line.lower().strip()
                        if 'version' in ll and ':' in line:
                            if not info.get("firmware_version"):
                                info["firmware_version"] = line.split(':')[-1].strip()
            
            # Esci dalla CLI
            if in_config_mode:
                channel.send("exit\n")
                time.sleep(0.3)
            channel.send("exit\n")
            time.sleep(0.3)
            channel.send("exit\n")
        
        channel.close()
        return info if info else None
        
    except Exception as e:
        logger.debug(f"SSH probe: UniFi CLI access failed for {target}: {e}")
        return None
