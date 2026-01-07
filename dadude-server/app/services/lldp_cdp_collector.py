"""
DaDude - LLDP/CDP Collector Service
Raccoglie informazioni LLDP/CDP neighbors e dettagli interfacce per switch/router
Supporta: MikroTik, Cisco, HP/Aruba, Ubiquiti
"""
from typing import Optional, Dict, Any, List
from loguru import logger
import asyncio
from concurrent.futures import ThreadPoolExecutor
import re


class LLDPCDPCollector:
    """Servizio per raccogliere informazioni LLDP/CDP e dettagli interfacce"""
    
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=5)
    
    async def collect_lldp_neighbors(
        self,
        device_address: str,
        device_type: str,
        manufacturer: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie neighbor LLDP da un dispositivo di rete
        
        Args:
            device_address: IP del dispositivo
            device_type: Tipo dispositivo (mikrotik, network, router)
            manufacturer: Marca dispositivo
            credentials: Lista credenziali da provare
            
        Returns:
            Lista di neighbor LLDP trovati
        """
        neighbors = []
        
        try:
            manufacturer_lower = (manufacturer or "").lower()
            device_type_lower = (device_type or "").lower()
            
            # MikroTik - usa RouterOS API
            if device_type_lower == "mikrotik" or "mikrotik" in manufacturer_lower:
                neighbors = await self._collect_lldp_mikrotik(device_address, credentials)
            
            # HP/Aruba - usa SSH
            elif "hp" in manufacturer_lower or "aruba" in manufacturer_lower or "hpe" in manufacturer_lower:
                neighbors = await self._collect_lldp_hp_aruba(device_address, credentials)
            
            # Ubiquiti - usa SSH
            elif "ubiquiti" in manufacturer_lower or "unifi" in manufacturer_lower:
                neighbors = await self._collect_lldp_ubiquiti(device_address, credentials)
            
            # Cisco - può avere LLDP o CDP
            elif "cisco" in manufacturer_lower:
                neighbors = await self._collect_lldp_cisco(device_address, credentials)
            
            # Generico via SNMP
            else:
                neighbors = await self._collect_lldp_snmp(device_address, credentials)
            
            logger.info(f"LLDP neighbors collected for {device_address}: {len(neighbors)} found")
            return neighbors
            
        except Exception as e:
            logger.error(f"Error collecting LLDP neighbors for {device_address}: {e}")
            return []
    
    async def collect_cdp_neighbors(
        self,
        device_address: str,
        manufacturer: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie neighbor CDP da un dispositivo Cisco
        
        Args:
            device_address: IP del dispositivo
            manufacturer: Marca dispositivo
            credentials: Lista credenziali da provare
            
        Returns:
            Lista di neighbor CDP trovati
        """
        neighbors = []
        
        try:
            manufacturer_lower = (manufacturer or "").lower()
            
            # Solo Cisco supporta CDP
            if "cisco" in manufacturer_lower:
                neighbors = await self._collect_cdp_cisco(device_address, credentials)
            
            logger.info(f"CDP neighbors collected for {device_address}: {len(neighbors)} found")
            return neighbors
            
        except Exception as e:
            logger.error(f"Error collecting CDP neighbors for {device_address}: {e}")
            return []
    
    async def collect_interface_details(
        self,
        device_address: str,
        device_type: str,
        manufacturer: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie dettagli completi interfacce di rete
        
        Args:
            device_address: IP del dispositivo
            device_type: Tipo dispositivo
            manufacturer: Marca dispositivo
            credentials: Lista credenziali da provare
            
        Returns:
            Lista di interfacce con dettagli completi
        """
        interfaces = []
        
        try:
            manufacturer_lower = (manufacturer or "").lower()
            device_type_lower = (device_type or "").lower()
            
            # MikroTik - usa RouterOS API
            if device_type_lower == "mikrotik" or "mikrotik" in manufacturer_lower:
                interfaces = await self._collect_interfaces_mikrotik(device_address, credentials)
            
            # HP/Aruba - usa SSH
            elif "hp" in manufacturer_lower or "aruba" in manufacturer_lower or "hpe" in manufacturer_lower:
                interfaces = await self._collect_interfaces_hp_aruba(device_address, credentials)
            
            # Cisco - usa SNMP o SSH
            elif "cisco" in manufacturer_lower:
                interfaces = await self._collect_interfaces_cisco(device_address, credentials)
            
            # Ubiquiti - usa SSH
            elif "ubiquiti" in manufacturer_lower or "unifi" in manufacturer_lower:
                interfaces = await self._collect_interfaces_ubiquiti(device_address, credentials)
            
            # Generico via SNMP
            else:
                interfaces = await self._collect_interfaces_snmp(device_address, credentials)
            
            logger.info(f"Interface details collected for {device_address}: {len(interfaces)} interfaces")
            return interfaces
            
        except Exception as e:
            logger.error(f"Error collecting interface details for {device_address}: {e}")
            return []
    
    # ==========================================
    # MIKROTIK IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_lldp_mikrotik(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP da MikroTik via RouterOS API"""
        neighbors = []
        
        for cred in credentials:
            # Accetta credenziali mikrotik, ssh o api (tutte possono avere username/password per MikroTik)
            cred_type = str(cred.get("type", "")).lower()
            if cred_type not in ["mikrotik", "ssh", "api", ""] and not cred.get("mikrotik_api_port"):
                continue
            
            try:
                import routeros_api
                
                api_port = cred.get("mikrotik_api_port", 8728)
                use_ssl = cred.get("use_ssl", False)
                
                connection = routeros_api.RouterOsApi(
                    address,
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    port=api_port,
                    use_ssl=use_ssl,
                    plaintext_login=True
                )
                
                # MikroTik usa /ip neighbor per neighbor discovery (MNDP/CDP/LLDP)
                neighbor_resource = connection.get_resource('/ip/neighbor')
                neighbor_list = neighbor_resource.get()
                
                for n in neighbor_list:
                    neighbor = {
                        "local_interface": n.get("interface", ""),
                        "remote_device_name": n.get("identity", ""),
                        "remote_mac": n.get("mac-address", ""),
                        "remote_ip": n.get("address", ""),
                        "chassis_id": n.get("mac-address", ""),
                        "chassis_id_type": "mac",
                        "capabilities": {}
                    }
                    neighbors.append(neighbor)
                
                connection.disconnect()
                break  # Se funziona, non provare altre credenziali
                
            except Exception as e:
                logger.debug(f"MikroTik API failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_interfaces_mikrotik(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce da MikroTik via RouterOS API"""
        interfaces = []
        
        for cred in credentials:
            # Accetta credenziali mikrotik, ssh o api (tutte possono avere username/password per MikroTik)
            cred_type = str(cred.get("type", "")).lower()
            if cred_type not in ["mikrotik", "ssh", "api", ""] and not cred.get("mikrotik_api_port"):
                continue
            
            try:
                import routeros_api
                
                api_port = cred.get("mikrotik_api_port", 8728)
                use_ssl = cred.get("use_ssl", False)
                
                connection = routeros_api.RouterOsApi(
                    address,
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    port=api_port,
                    use_ssl=use_ssl,
                    plaintext_login=True
                )
                
                # Ottieni interfacce
                interface_resource = connection.get_resource('/interface')
                interface_list = interface_resource.get()
                
                for iface in interface_list:
                    iface_name = iface.get("name", "")
                    if not iface_name or iface_name.startswith("lo"):
                        continue
                    
                    interface_info = {
                        "name": iface_name,
                        "description": iface.get("comment", ""),
                        "interface_type": iface.get("type", ""),
                        "mac_address": iface.get("mac-address", ""),
                        "admin_status": "enabled" if iface.get("disabled") == "false" else "disabled",
                        "oper_status": iface.get("running", ""),
                        "mtu": int(iface.get("mtu", 1500)) if iface.get("mtu") else None,
                        "speed_mbps": None,  # MikroTik non espone direttamente
                        "lldp_enabled": None,  # Verificare se LLDP è abilitato globalmente
                    }
                    
                    # Prova a ottenere velocità da ethernet
                    if iface.get("type") == "ether":
                        try:
                            ether_resource = connection.get_resource('/interface/ethernet')
                            ether_list = ether_resource.get(name=iface_name)
                            if ether_list:
                                speed = ether_list[0].get("speed", "")
                                if speed and speed != "auto":
                                    # MikroTik speed può essere "10Mbps", "100Mbps", "1Gbps"
                                    speed_map = {
                                        "10Mbps": 10,
                                        "100Mbps": 100,
                                        "1Gbps": 1000,
                                        "10Gbps": 10000
                                    }
                                    interface_info["speed_mbps"] = speed_map.get(speed, None)
                        except:
                            pass
                    
                    interfaces.append(interface_info)
                
                connection.disconnect()
                break
                
            except Exception as e:
                logger.debug(f"MikroTik API failed for {address}: {e}")
                continue
        
        return interfaces
    
    # ==========================================
    # CISCO IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_lldp_cisco(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP da Cisco via SNMP o SSH"""
        neighbors = []
        
        # Prova prima SNMP
        neighbors = await self._collect_lldp_snmp(address, credentials)
        
        # Se SNMP fallisce, prova SSH
        if not neighbors:
            neighbors = await self._collect_lldp_cisco_ssh(address, credentials)
        
        return neighbors
    
    async def _collect_lldp_cisco_ssh(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP da Cisco via SSH"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") not in ["ssh", "cisco"]:
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: show lldp neighbors detail
                stdin, stdout, stderr = ssh.exec_command("show lldp neighbors detail", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output Cisco LLDP
                current_neighbor = {}
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        if current_neighbor:
                            neighbors.append(current_neighbor.copy())
                            current_neighbor = {}
                        continue
                    
                    if 'Local Intf:' in line:
                        current_neighbor["local_interface"] = line.split(':', 1)[1].strip()
                    elif 'Chassis id:' in line:
                        current_neighbor["chassis_id"] = line.split(':', 1)[1].strip()
                    elif 'Port id:' in line:
                        current_neighbor["remote_port"] = line.split(':', 1)[1].strip()
                    elif 'System Name:' in line:
                        current_neighbor["remote_device_name"] = line.split(':', 1)[1].strip()
                    elif 'System Description:' in line:
                        current_neighbor["remote_device_description"] = line.split(':', 1)[1].strip()
                    elif 'Management address:' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            current_neighbor["remote_ip"] = ip_match.group(1)
                
                if current_neighbor:
                    neighbors.append(current_neighbor)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"Cisco SSH failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_cdp_cisco(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor CDP da Cisco via SNMP o SSH"""
        neighbors = []
        
        # Prova prima SNMP
        neighbors = await self._collect_cdp_snmp(address, credentials)
        
        # Se SNMP fallisce, prova SSH
        if not neighbors:
            neighbors = await self._collect_cdp_cisco_ssh(address, credentials)
        
        return neighbors
    
    async def _collect_cdp_cisco_ssh(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor CDP da Cisco via SSH"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") not in ["ssh", "cisco"]:
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: show cdp neighbors detail
                stdin, stdout, stderr = ssh.exec_command("show cdp neighbors detail", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output Cisco CDP
                current_neighbor = {}
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        if current_neighbor:
                            neighbors.append(current_neighbor.copy())
                            current_neighbor = {}
                        continue
                    
                    if 'Device ID:' in line:
                        current_neighbor["remote_device_id"] = line.split(':', 1)[1].strip()
                        current_neighbor["remote_device_name"] = current_neighbor["remote_device_id"]
                    elif 'Entry address(es):' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            current_neighbor["remote_ip"] = ip_match.group(1)
                    elif 'Platform:' in line:
                        current_neighbor["platform"] = line.split(':', 1)[1].strip()
                    elif 'Interface:' in line:
                        parts = line.split(',')
                        if len(parts) >= 2:
                            current_neighbor["local_interface"] = parts[0].split(':', 1)[1].strip()
                            current_neighbor["remote_port"] = parts[1].split(':', 1)[1].strip() if ':' in parts[1] else parts[1].strip()
                    elif 'Version' in line and ':' in line:
                        current_neighbor["remote_version"] = line.split(':', 1)[1].strip()
                
                if current_neighbor:
                    neighbors.append(current_neighbor)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"Cisco SSH CDP failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_interfaces_cisco(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce da Cisco via SNMP o SSH"""
        interfaces = []
        
        # Prova prima SNMP
        interfaces = await self._collect_interfaces_snmp(address, credentials)
        
        # Se SNMP fallisce o non completo, prova SSH
        if not interfaces:
            interfaces = await self._collect_interfaces_cisco_ssh(address, credentials)
        
        return interfaces
    
    async def _collect_interfaces_cisco_ssh(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce da Cisco via SSH"""
        interfaces = []
        
        for cred in credentials:
            if cred.get("type") not in ["ssh", "cisco"]:
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: show interfaces status
                stdin, stdout, stderr = ssh.exec_command("show interfaces status", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output
                for line in output.split('\n')[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = parts[0]
                        if iface_name.startswith('--') or not iface_name:
                            continue
                        
                        interface_info = {
                            "name": iface_name,
                            "admin_status": parts[1] if len(parts) > 1 else None,
                            "oper_status": parts[2] if len(parts) > 2 else None,
                            "speed_mbps": None,
                            "duplex": None,
                        }
                        
                        # Prova a ottenere dettagli completi
                        try:
                            stdin2, stdout2, stderr2 = ssh.exec_command(f"show interfaces {iface_name}", timeout=10)
                            detail_output = stdout2.read().decode('utf-8')
                            
                            # Parse dettagli
                            for detail_line in detail_output.split('\n'):
                                if 'Hardware is' in detail_line:
                                    interface_info["interface_type"] = detail_line.split('is', 1)[1].strip()
                                elif 'MTU' in detail_line:
                                    mtu_match = re.search(r'MTU\s+(\d+)', detail_line)
                                    if mtu_match:
                                        interface_info["mtu"] = int(mtu_match.group(1))
                                elif 'BW' in detail_line or 'Bandwidth' in detail_line:
                                    bw_match = re.search(r'(\d+)\s*[KMGT]?bps', detail_line, re.I)
                                    if bw_match:
                                        bw = int(bw_match.group(1))
                                        if 'Gbps' in detail_line.upper():
                                            interface_info["speed_mbps"] = bw * 1000
                                        elif 'Mbps' in detail_line.upper():
                                            interface_info["speed_mbps"] = bw
                                        else:
                                            interface_info["speed_mbps"] = bw / 1000
                        except:
                            pass
                        
                        interfaces.append(interface_info)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"Cisco SSH interfaces failed for {address}: {e}")
                continue
        
        return interfaces
    
    # ==========================================
    # HP/ARUBA IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_lldp_hp_aruba(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP da HP/Aruba via SSH"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") != "ssh":
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "admin"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: show lldp info remote-device detail
                stdin, stdout, stderr = ssh.exec_command("show lldp info remote-device detail", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output HP/Aruba LLDP
                current_neighbor = {}
                current_port = None
                
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Port identifier
                    if 'LLDP Remote Device Information of port' in line:
                        port_match = re.search(r'port\s+(\S+)', line, re.I)
                        if port_match:
                            current_port = port_match.group(1)
                            if current_neighbor:
                                neighbors.append(current_neighbor.copy())
                            current_neighbor = {"local_interface": current_port}
                    elif current_port:
                        if 'Remote Chassis ID:' in line:
                            current_neighbor["chassis_id"] = line.split(':', 1)[1].strip()
                        elif 'Remote Port ID:' in line:
                            current_neighbor["remote_port"] = line.split(':', 1)[1].strip()
                        elif 'Remote System Name:' in line:
                            current_neighbor["remote_device_name"] = line.split(':', 1)[1].strip()
                        elif 'Remote System Description:' in line:
                            current_neighbor["remote_device_description"] = line.split(':', 1)[1].strip()
                        elif 'Remote Management Address:' in line:
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                current_neighbor["remote_ip"] = ip_match.group(1)
                
                if current_neighbor:
                    neighbors.append(current_neighbor)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"HP/Aruba SSH failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_interfaces_hp_aruba(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce da HP/Aruba via SSH"""
        # Usa il servizio esistente hp_aruba_collector se disponibile
        try:
            from .hp_aruba_collector import HPArubaCollector
            collector = HPArubaCollector()
            result = await asyncio.to_thread(collector.collect_full_info, address, credentials[0] if credentials else {})
            return result.get("interfaces", [])
        except Exception as e:
            logger.debug(f"HP/Aruba collector failed, using generic SSH: {e}")
            return await self._collect_interfaces_snmp(address, credentials)
    
    # ==========================================
    # UBIQUITI IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_lldp_ubiquiti(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP da Ubiquiti via SSH"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") != "ssh":
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "ubnt"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: lldpctl show neighbors details
                stdin, stdout, stderr = ssh.exec_command("lldpctl show neighbors details", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output Ubiquiti LLDP
                current_neighbor = {}
                current_port = None
                
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if 'Interface:' in line:
                        if current_neighbor:
                            neighbors.append(current_neighbor.copy())
                        current_port = line.split(':', 1)[1].strip()
                        current_neighbor = {"local_interface": current_port}
                    elif current_port:
                        if 'Chassis ID:' in line:
                            current_neighbor["chassis_id"] = line.split(':', 1)[1].strip()
                        elif 'Port ID:' in line:
                            current_neighbor["remote_port"] = line.split(':', 1)[1].strip()
                        elif 'SysName:' in line:
                            current_neighbor["remote_device_name"] = line.split(':', 1)[1].strip()
                        elif 'SysDescr:' in line:
                            current_neighbor["remote_device_description"] = line.split(':', 1)[1].strip()
                        elif 'MgmtIP:' in line:
                            current_neighbor["remote_ip"] = line.split(':', 1)[1].strip()
                
                if current_neighbor:
                    neighbors.append(current_neighbor)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"Ubiquiti SSH failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_interfaces_ubiquiti(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce da Ubiquiti via SSH"""
        interfaces = []
        
        for cred in credentials:
            if cred.get("type") != "ssh":
                continue
            
            try:
                import paramiko
                
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                ssh.connect(
                    address,
                    port=cred.get("ssh_port", 22),
                    username=cred.get("username", "ubnt"),
                    password=cred.get("password", ""),
                    timeout=10
                )
                
                # Comando: ifconfig
                stdin, stdout, stderr = ssh.exec_command("ifconfig", timeout=30)
                output = stdout.read().decode('utf-8')
                
                # Parse output
                current_iface = None
                for line in output.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    
                    if ':' in line and not line.startswith(' '):
                        # Nuova interfaccia
                        iface_name = line.split(':')[0]
                        if iface_name != 'lo':
                            if current_iface:
                                interfaces.append(current_iface)
                            current_iface = {"name": iface_name}
                    elif current_iface:
                        if 'inet ' in line:
                            ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', line)
                            if ip_match:
                                if not current_iface.get("ip_addresses"):
                                    current_iface["ip_addresses"] = []
                                current_iface["ip_addresses"].append(ip_match.group(1))
                        elif 'ether' in line or 'HWaddr' in line:
                            mac_match = re.search(r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line)
                            if mac_match:
                                current_iface["mac_address"] = mac_match.group(1)
                
                if current_iface:
                    interfaces.append(current_iface)
                
                ssh.close()
                break
                
            except Exception as e:
                logger.debug(f"Ubiquiti SSH interfaces failed for {address}: {e}")
                continue
        
        return interfaces
    
    # ==========================================
    # GENERIC SNMP IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_lldp_snmp(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor LLDP via SNMP (OID standard)"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") != "snmp":
                continue
            
            try:
                from pysnmp.hlapi.v1arch.asyncio import (
                    get_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget,
                    ObjectType, ObjectIdentity
                )
                
                community = cred.get("snmp_community", "public")
                port = int(cred.get("snmp_port", 161))
                
                # LLDP MIB OIDs
                # lldpRemLocalPortNum - porta locale
                # lldpRemChassisIdSubtype - tipo chassis ID
                # lldpRemChassisId - chassis ID
                # lldpRemPortIdSubtype - tipo port ID
                # lldpRemPortId - port ID remoto
                # lldpRemSysName - nome sistema remoto
                # lldpRemSysDesc - descrizione sistema remoto
                
                # Implementazione semplificata - richiede parsing complesso
                # Per ora restituiamo lista vuota, implementazione completa richiede
                # iterazione su tutte le entry nella tabella LLDP
                logger.debug(f"SNMP LLDP collection not fully implemented for {address}")
                return []
                
            except Exception as e:
                logger.debug(f"SNMP LLDP failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_cdp_snmp(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie neighbor CDP via SNMP (Cisco specific)"""
        neighbors = []
        
        for cred in credentials:
            if cred.get("type") != "snmp":
                continue
            
            try:
                # CDP MIB OID: 1.3.6.1.4.1.9.9.23
                # Implementazione semplificata
                logger.debug(f"SNMP CDP collection not fully implemented for {address}")
                return []
                
            except Exception as e:
                logger.debug(f"SNMP CDP failed for {address}: {e}")
                continue
        
        return neighbors
    
    async def _collect_interfaces_snmp(
        self,
        address: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Raccoglie dettagli interfacce via SNMP (IF-MIB standard)"""
        interfaces = []
        
        for cred in credentials:
            if cred.get("type") != "snmp":
                continue
            
            try:
                from pysnmp.hlapi.v1arch.asyncio import (
                    next_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget,
                    ObjectType, ObjectIdentity
                )
                
                community = cred.get("snmp_community", "public")
                port = int(cred.get("snmp_port", 161))
                
                # IF-MIB OIDs standard
                # ifDescr, ifType, ifSpeed, ifAdminStatus, ifOperStatus, ifPhysAddress
                # Implementazione semplificata
                logger.debug(f"SNMP interface collection not fully implemented for {address}")
                return []
                
            except Exception as e:
                logger.debug(f"SNMP interfaces failed for {address}: {e}")
                continue
        
        return interfaces


# Singleton instance
_lldp_cdp_collector: Optional[LLDPCDPCollector] = None


def get_lldp_cdp_collector() -> LLDPCDPCollector:
    """Ottiene istanza singleton del collector LLDP/CDP"""
    global _lldp_cdp_collector
    if _lldp_cdp_collector is None:
        _lldp_cdp_collector = LLDPCDPCollector()
    return _lldp_cdp_collector

