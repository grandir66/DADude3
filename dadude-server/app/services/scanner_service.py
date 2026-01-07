"""
DaDude - Scanner Service
Scansione reti tramite connessione diretta a router MikroTik
"""
from typing import Optional, List, Dict, Any
from loguru import logger
import routeros_api


class ScannerService:
    """Servizio per scansioni di rete tramite router MikroTik"""
    
    @staticmethod
    def scan_network_via_router(
        router_address: str,
        router_port: int,
        router_username: str,
        router_password: str,
        network: str,
        scan_type: str = "ping",
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Esegue una scansione di rete usando un router MikroTik.
        
        Usa il comando /tool/ip-scan del router per scansionare la rete.
        
        Args:
            router_address: IP del router
            router_port: Porta API
            router_username: Username
            router_password: Password
            network: Rete da scansionare (CIDR)
            scan_type: Tipo scan (ping, arp, all)
            use_ssl: Usa SSL
            
        Returns:
            Dict con risultati della scansione
        """
        try:
            # Connetti al router
            connection = routeros_api.RouterOsApiPool(
                host=router_address,
                username=router_username,
                password=router_password,
                port=router_port,
                use_ssl=use_ssl,
                ssl_verify=False,
                plaintext_login=True,
            )
            
            api = connection.get_api()
            
            # Usa ip-scan per scansionare
            # Il comando è /tool ip-scan address-range=X.X.X.X/XX
            scan_resource = api.get_resource('/tool')
            
            results = []
            
            # Esegui ping scan
            if scan_type in ["ping", "all"]:
                try:
                    # Usa il comando ping con count=1 per ogni IP nella rete
                    # Oppure usa ip neighbor per ARP
                    pass
                except:
                    pass
            
            # Ottieni neighbor ARP
            if scan_type in ["arp", "all"]:
                try:
                    neighbor_resource = api.get_resource('/ip/neighbor')
                    neighbors = neighbor_resource.get()
                    
                    for n in neighbors:
                        results.append({
                            "address": n.get("address", ""),
                            "mac_address": n.get("mac-address", ""),
                            "interface": n.get("interface", ""),
                            "identity": n.get("identity", ""),
                            "platform": n.get("platform", ""),
                            "board": n.get("board", ""),
                            "source": "neighbor"
                        })
                except Exception as e:
                    logger.warning(f"Error getting neighbors: {e}")
            
            # Ottieni ARP table
            try:
                arp_resource = api.get_resource('/ip/arp')
                arps = arp_resource.get()
                
                existing_ips = {r.get("address") for r in results}
                
                for a in arps:
                    ip = a.get("address", "")
                    if ip and ip not in existing_ips:
                        results.append({
                            "address": ip,
                            "mac_address": a.get("mac-address", ""),
                            "interface": a.get("interface", ""),
                            "source": "arp"
                        })
            except Exception as e:
                logger.warning(f"Error getting ARP: {e}")
            
            connection.disconnect()
            
            # Arricchisci risultati con scan porte se disponibile
            enriched_results = []
            for device in results:
                device_ip = device.get("address", "")
                if device_ip:
                    # Prova a scansionare porte (opzionale, può essere lento)
                    try:
                        from .device_probe_service import get_device_probe_service
                        import asyncio
                        probe_service = get_device_probe_service()
                        ports = asyncio.run(probe_service.scan_services(device_ip))
                        device["open_ports"] = ports
                    except Exception as e:
                        logger.debug(f"Port scan skipped for {device_ip}: {e}")
                        device["open_ports"] = []
                enriched_results.append(device)
            
            return {
                "success": True,
                "network": network,
                "scan_type": scan_type,
                "devices_found": len(enriched_results),
                "results": enriched_results,
                "message": f"Trovati {len(enriched_results)} dispositivi"
            }
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore scansione: {e}"
            }

    @staticmethod
    def scan_network_via_ssh(
        router_address: str,
        ssh_port: int,
        username: str,
        password: str,
        network: str,
        ssh_key: str = None,
    ) -> Dict[str, Any]:
        """
        Esegue una scansione di rete usando SSH su router MikroTik.
        """
        import paramiko
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_params = {
                "hostname": router_address,
                "port": ssh_port,
                "username": username,
                "timeout": 30,
                "allow_agent": False,
                "look_for_keys": False,
            }
            
            if ssh_key:
                from io import StringIO
                key = paramiko.RSAKey.from_private_key(StringIO(ssh_key))
                connect_params["pkey"] = key
            else:
                connect_params["password"] = password
            
            ssh.connect(**connect_params)
            
            results = []
            
            # Ottieni neighbor discovery
            stdin, stdout, stderr = ssh.exec_command("/ip neighbor print detail")
            neighbor_output = stdout.read().decode()
            
            # Parse neighbor output
            current = {}
            for line in neighbor_output.split('\n'):
                line = line.strip()
                if line.startswith('Flags:'):
                    continue
                if not line:
                    if current:
                        results.append(current)
                        current = {}
                    continue
                    
                for field in ['address', 'mac-address', 'identity', 'platform', 'board', 'interface']:
                    if f'{field}=' in line.lower() or f'{field}:' in line.lower():
                        parts = line.split('=') if '=' in line else line.split(':')
                        if len(parts) >= 2:
                            key = parts[0].strip().lower().replace('-', '_')
                            value = '='.join(parts[1:]).strip() if '=' in line else ':'.join(parts[1:]).strip()
                            current[key] = value
            
            if current:
                results.append(current)
            
            # Ottieni ARP table
            stdin, stdout, stderr = ssh.exec_command("/ip arp print")
            arp_output = stdout.read().decode()
            
            existing_ips = {r.get("address") for r in results}
            
            for line in arp_output.split('\n'):
                if 'ADDRESS' in line or '---' in line or not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    ip = parts[1] if parts[0].isdigit() else parts[0]
                    mac = parts[2] if parts[0].isdigit() else parts[1]
                    if ip and ip not in existing_ips and '.' in ip:
                        results.append({
                            "address": ip,
                            "mac_address": mac,
                            "source": "arp"
                        })
            
            ssh.close()
            
            return {
                "success": True,
                "network": network,
                "scan_type": "ssh",
                "devices_found": len(results),
                "results": results,
                "message": f"Trovati {len(results)} dispositivi"
            }
            
        except Exception as e:
            logger.error(f"SSH scan error: {e}")
            return {
                "success": False,
                "error": str(e),
                "message": f"Errore scansione SSH: {e}"
            }


# Singleton
_scanner_service: Optional[ScannerService] = None


def get_scanner_service() -> ScannerService:
    global _scanner_service
    if _scanner_service is None:
        _scanner_service = ScannerService()
    return _scanner_service
