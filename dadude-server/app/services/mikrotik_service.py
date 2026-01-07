"""
DaDude - MikroTik Remote Service
Gestione funzionalità avanzate su router MikroTik remoti
"""
from typing import Optional, List, Dict, Any
from loguru import logger
import routeros_api
from datetime import datetime


class MikroTikRemoteService:
    """
    Servizio per operazioni avanzate su router MikroTik remoti.
    Supporta: ip-scan, netwatch, snmp, neighbor discovery
    """
    
    def __init__(self):
        self._connections: Dict[str, Any] = {}
    
    def _get_connection(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Any:
        """Ottiene connessione API al router"""
        try:
            connection = routeros_api.RouterOsApiPool(
                host=address,
                username=username,
                password=password,
                port=port,
                use_ssl=use_ssl,
                ssl_verify=False,
                plaintext_login=True,
            )
            return connection.get_api()
        except Exception as e:
            logger.error(f"Connection error to {address}: {e}")
            raise
    
    # ==========================================
    # SYSTEM INFO
    # ==========================================
    
    def get_system_info(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene informazioni complete del sistema RouterOS"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            # Identity
            identity = api.get_resource('/system/identity').get()
            
            # Resource (CPU, RAM, etc)
            resource = api.get_resource('/system/resource').get()
            
            # RouterBoard info
            try:
                routerboard = api.get_resource('/system/routerboard').get()
            except:
                routerboard = [{}]
            
            # License
            try:
                license_info = api.get_resource('/system/license').get()
            except:
                license_info = [{}]
            
            res = resource[0] if resource else {}
            rb = routerboard[0] if routerboard else {}
            lic = license_info[0] if license_info else {}
            
            return {
                "success": True,
                "identity": identity[0].get("name") if identity else "",
                "version": res.get("version", ""),
                "board_name": res.get("board-name", ""),
                "platform": res.get("platform", ""),
                "architecture": res.get("architecture-name", ""),
                "cpu_model": res.get("cpu", ""),
                "cpu_count": int(res.get("cpu-count", 1)),
                "cpu_frequency": int(res.get("cpu-frequency", 0)),
                "cpu_load": int(res.get("cpu-load", 0)),
                "memory_total_mb": int(res.get("total-memory", 0)) // (1024*1024),
                "memory_free_mb": int(res.get("free-memory", 0)) // (1024*1024),
                "hdd_total_mb": int(res.get("total-hdd-space", 0)) // (1024*1024),
                "hdd_free_mb": int(res.get("free-hdd-space", 0)) // (1024*1024),
                "uptime": res.get("uptime", ""),
                "routerboard": rb.get("model", ""),
                "serial_number": rb.get("serial-number", ""),
                "firmware": rb.get("current-firmware", ""),
                "license_level": lic.get("level", ""),
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # ARP TABLE - Per reti remote
    # ==========================================
    
    def get_arp_for_network(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        network_cidr: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Ottiene la tabella ARP del router filtrata per una rete specifica.
        Utile per ottenere MAC address di host su reti remote (dietro il router).
        
        Args:
            address: IP del router MikroTik
            port: Porta API
            username: Username
            password: Password
            network_cidr: Rete da filtrare (es: 192.168.40.0/24)
            use_ssl: Usa SSL
            
        Returns:
            Dict con lista di {ip, mac, interface} per la rete specificata
        """
        try:
            import ipaddress
            
            api = self._get_connection(address, port, username, password, use_ssl)
            
            # Leggi tabella ARP completa
            arp_resource = api.get_resource('/ip/arp')
            arps = arp_resource.get()
            
            # Filtra per network
            try:
                net = ipaddress.ip_network(network_cidr, strict=False)
            except ValueError as e:
                return {"success": False, "error": f"Invalid network: {e}"}
            
            results = []
            for a in arps:
                ip_str = a.get("address", "")
                if not ip_str:
                    continue
                    
                try:
                    ip = ipaddress.ip_address(ip_str)
                    if ip in net:
                        mac = a.get("mac-address", "")
                        if mac and mac != "00:00:00:00:00:00":
                            results.append({
                                "ip": ip_str,
                                "mac": mac.upper(),
                                "interface": a.get("interface", ""),
                                "complete": a.get("complete", "") == "true",
                            })
                except ValueError:
                    continue
            
            logger.info(f"MikroTik ARP for {network_cidr}: found {len(results)} entries")
            
            return {
                "success": True,
                "network": network_cidr,
                "entries": results,
                "count": len(results),
            }
            
        except Exception as e:
            logger.error(f"Error getting ARP for network {network_cidr}: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # IP SCAN - Discovery attiva
    # ==========================================
    
    def run_ip_scan(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        network: str,
        interface: str = None,
        duration: int = 30,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Esegue /tool ip-scan sul router remoto.
        Questo fa una scansione attiva della rete.
        
        Args:
            network: Rete da scansionare (es: 192.168.1.0/24)
            interface: Interfaccia da usare (opzionale)
            duration: Durata scansione in secondi
        """
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            # Prepara parametri
            params = {
                "address-range": network,
                "duration": f"{duration}s",
            }
            
            if interface:
                params["interface"] = interface
            
            # Avvia ip-scan
            # Nota: ip-scan è interattivo, dobbiamo usare un approccio diverso
            # Usiamo il comando "run" per eseguire e raccogliere risultati
            
            scan_resource = api.get_resource('/tool')
            
            # RouterOS API non supporta direttamente ip-scan come resource
            # Dobbiamo usare un workaround: leggere ARP + neighbor dopo un ping sweep
            
            # Alternativa: usa /ip arp + /ip neighbor che sono già popolati
            logger.info(f"IP-scan not directly available via API, using ARP + Neighbor")
            
            results = []
            
            # ARP table
            arp_resource = api.get_resource('/ip/arp')
            arps = arp_resource.get()
            
            for a in arps:
                ip = a.get("address", "")
                # Filtra per rete se specificato
                if network and "/" in network:
                    import ipaddress
                    try:
                        net = ipaddress.ip_network(network, strict=False)
                        if ipaddress.ip_address(ip) not in net:
                            continue
                    except:
                        pass
                
                results.append({
                    "address": ip,
                    "mac_address": a.get("mac-address", ""),
                    "interface": a.get("interface", ""),
                    "source": "arp",
                    "complete": a.get("complete", "") == "true",
                })
            
            # Neighbor discovery (MNDP/CDP/LLDP)
            neighbor_resource = api.get_resource('/ip/neighbor')
            neighbors = neighbor_resource.get()
            
            existing_ips = {r["address"] for r in results if r["address"]}
            
            for n in neighbors:
                ip = n.get("address", "")
                if ip and ip not in existing_ips:
                    results.append({
                        "address": ip,
                        "mac_address": n.get("mac-address", ""),
                        "interface": n.get("interface", ""),
                        "identity": n.get("identity", ""),
                        "platform": n.get("platform", ""),
                        "board": n.get("board", ""),
                        "version": n.get("version", ""),
                        "source": "neighbor",
                    })
            
            return {
                "success": True,
                "network": network,
                "devices_found": len(results),
                "results": results,
            }
            
        except Exception as e:
            logger.error(f"Error running ip-scan: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # NETWATCH Management
    # ==========================================
    
    def get_netwatch_list(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene lista netwatch configurati sul router"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            netwatch_resource = api.get_resource('/tool/netwatch')
            netwatches = netwatch_resource.get()
            
            results = []
            for nw in netwatches:
                results.append({
                    "id": nw.get(".id", ""),
                    "host": nw.get("host", ""),
                    "port": nw.get("port", ""),
                    "type": nw.get("type", "icmp"),
                    "interval": nw.get("interval", ""),
                    "timeout": nw.get("timeout", ""),
                    "status": nw.get("status", "unknown"),
                    "since": nw.get("since", ""),
                    "disabled": nw.get("disabled", "false") == "true",
                    "comment": nw.get("comment", ""),
                })
            
            return {
                "success": True,
                "count": len(results),
                "netwatches": results,
            }
            
        except Exception as e:
            logger.error(f"Error getting netwatch list: {e}")
            return {"success": False, "error": str(e)}
    
    def add_netwatch(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        host: str,
        target_port: int = None,
        interval: str = "30s",
        timeout: str = "3s",
        up_script: str = None,
        down_script: str = None,
        comment: str = None,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Aggiunge un netwatch sul router remoto"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            params = {
                "host": host,
                "interval": interval,
                "timeout": timeout,
            }
            
            if target_port:
                params["port"] = str(target_port)
                params["type"] = "tcp-conn"
            else:
                params["type"] = "icmp"
            
            if up_script:
                params["up-script"] = up_script
            if down_script:
                params["down-script"] = down_script
            if comment:
                params["comment"] = comment
            
            netwatch_resource = api.get_resource('/tool/netwatch')
            result = netwatch_resource.add(**params)
            
            return {
                "success": True,
                "message": f"Netwatch per {host} creato",
                "netwatch_id": result if isinstance(result, str) else None,
            }
            
        except Exception as e:
            logger.error(f"Error adding netwatch: {e}")
            return {"success": False, "error": str(e)}
    
    def remove_netwatch(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        netwatch_id: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Rimuove un netwatch dal router"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            netwatch_resource = api.get_resource('/tool/netwatch')
            netwatch_resource.remove(id=netwatch_id)
            
            return {
                "success": True,
                "message": f"Netwatch {netwatch_id} rimosso",
            }
            
        except Exception as e:
            logger.error(f"Error removing netwatch: {e}")
            return {"success": False, "error": str(e)}
    
    def update_netwatch(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        netwatch_id: str,
        use_ssl: bool = False,
        **kwargs,
    ) -> Dict[str, Any]:
        """Aggiorna un netwatch esistente"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            netwatch_resource = api.get_resource('/tool/netwatch')
            netwatch_resource.set(id=netwatch_id, **kwargs)
            
            return {
                "success": True,
                "message": f"Netwatch {netwatch_id} aggiornato",
            }
            
        except Exception as e:
            logger.error(f"Error updating netwatch: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # INTERFACES
    # ==========================================
    
    def get_interfaces(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene lista interfacce del router"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            interface_resource = api.get_resource('/interface')
            interfaces = interface_resource.get()
            
            results = []
            for iface in interfaces:
                results.append({
                    "id": iface.get(".id", ""),
                    "name": iface.get("name", ""),
                    "type": iface.get("type", ""),
                    "mac_address": iface.get("mac-address", ""),
                    "mtu": iface.get("mtu", ""),
                    "running": iface.get("running", "false") == "true",
                    "disabled": iface.get("disabled", "false") == "true",
                    "rx_bytes": int(iface.get("rx-byte", 0)),
                    "tx_bytes": int(iface.get("tx-byte", 0)),
                    "comment": iface.get("comment", ""),
                })
            
            return {
                "success": True,
                "count": len(results),
                "interfaces": results,
            }
            
        except Exception as e:
            logger.error(f"Error getting interfaces: {e}")
            return {"success": False, "error": str(e)}
    
    def get_ip_addresses(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene indirizzi IP configurati"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            ip_resource = api.get_resource('/ip/address')
            addresses = ip_resource.get()
            
            results = []
            for addr in addresses:
                results.append({
                    "id": addr.get(".id", ""),
                    "address": addr.get("address", ""),
                    "network": addr.get("network", ""),
                    "interface": addr.get("interface", ""),
                    "disabled": addr.get("disabled", "false") == "true",
                    "dynamic": addr.get("dynamic", "false") == "true",
                    "comment": addr.get("comment", ""),
                })
            
            return {
                "success": True,
                "count": len(results),
                "addresses": results,
            }
            
        except Exception as e:
            logger.error(f"Error getting IP addresses: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # ROUTING
    # ==========================================
    
    def get_routes(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene tabella routing"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            route_resource = api.get_resource('/ip/route')
            routes = route_resource.get()
            
            results = []
            for r in routes:
                results.append({
                    "id": r.get(".id", ""),
                    "dst_address": r.get("dst-address", ""),
                    "gateway": r.get("gateway", ""),
                    "distance": r.get("distance", ""),
                    "scope": r.get("scope", ""),
                    "routing_table": r.get("routing-table", "main"),
                    "active": r.get("active", "false") == "true",
                    "dynamic": r.get("dynamic", "false") == "true",
                    "static": r.get("static", "false") == "true",
                    "disabled": r.get("disabled", "false") == "true",
                    "comment": r.get("comment", ""),
                })
            
            return {
                "success": True,
                "count": len(results),
                "routes": results,
            }
            
        except Exception as e:
            logger.error(f"Error getting routes: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # FIREWALL STATS
    # ==========================================
    
    def get_firewall_stats(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Ottiene statistiche firewall"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            # Filter rules count
            filter_resource = api.get_resource('/ip/firewall/filter')
            filter_rules = filter_resource.get()
            
            # NAT rules count
            nat_resource = api.get_resource('/ip/firewall/nat')
            nat_rules = nat_resource.get()
            
            # Mangle rules count
            mangle_resource = api.get_resource('/ip/firewall/mangle')
            mangle_rules = mangle_resource.get()
            
            # Connections count
            conn_resource = api.get_resource('/ip/firewall/connection')
            connections = conn_resource.get()
            
            return {
                "success": True,
                "filter_rules": len(filter_rules),
                "nat_rules": len(nat_rules),
                "mangle_rules": len(mangle_rules),
                "active_connections": len(connections),
            }
            
        except Exception as e:
            logger.error(f"Error getting firewall stats: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # DUDE AGENT STATUS
    # ==========================================
    
    def get_dude_agent_status(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Verifica stato Dude Agent sul router"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            # Verifica se il pacchetto dude è installato
            packages = api.get_resource('/system/package')
            pkg_list = packages.get()
            
            dude_installed = False
            dude_version = None
            
            for pkg in pkg_list:
                if pkg.get("name") == "dude":
                    dude_installed = True
                    dude_version = pkg.get("version", "")
                    break
            
            if not dude_installed:
                return {
                    "success": True,
                    "dude_installed": False,
                    "message": "Dude agent package non installato",
                }
            
            # Ottieni configurazione dude agent
            try:
                dude_resource = api.get_resource('/dude')
                dude_config = dude_resource.get()
                
                config = dude_config[0] if dude_config else {}
                
                return {
                    "success": True,
                    "dude_installed": True,
                    "dude_version": dude_version,
                    "enabled": config.get("enabled", "false") == "true",
                    "server": config.get("server", ""),
                    "status": config.get("status", "unknown"),
                }
            except:
                return {
                    "success": True,
                    "dude_installed": True,
                    "dude_version": dude_version,
                    "enabled": None,
                    "message": "Impossibile leggere configurazione dude",
                }
            
        except Exception as e:
            logger.error(f"Error getting dude agent status: {e}")
            return {"success": False, "error": str(e)}
    
    def configure_dude_agent(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        dude_server: str,
        enabled: bool = True,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """Configura Dude Agent sul router remoto"""
        try:
            api = self._get_connection(address, port, username, password, use_ssl)
            
            dude_resource = api.get_resource('/dude')
            
            dude_resource.set(
                server=dude_server,
                enabled="yes" if enabled else "no",
            )
            
            return {
                "success": True,
                "message": f"Dude agent configurato per connettersi a {dude_server}",
            }
            
        except Exception as e:
            logger.error(f"Error configuring dude agent: {e}")
            return {"success": False, "error": str(e)}
    
    # ==========================================
    # DNS LOOKUP VIA ROUTER
    # ==========================================
    
    def reverse_dns_lookup(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ip: str,
        dns_server: str = None,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Esegue reverse DNS lookup tramite il router MikroTik.
        Usa il comando /resolve del router che può accedere ai DNS interni.
        
        Args:
            address: IP del router MikroTik
            port: Porta API
            username: Username
            password: Password
            target_ip: IP da risolvere
            dns_server: DNS server da usare (opzionale)
            use_ssl: Usa SSL
            
        Returns:
            Dict con hostname risolto o errore
        """
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # SSH usa porta 22 di default
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            
            # Costruisci comando resolve
            # /resolve address=192.168.4.4 server=192.168.4.1
            cmd = f":put [/resolve {target_ip}]"
            if dns_server:
                cmd = f":put [/resolve {target_ip} server={dns_server}]"
            
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
            result = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            
            ssh.close()
            
            if result and not error:
                # Il risultato potrebbe essere un hostname
                logger.debug(f"MikroTik DNS resolve {target_ip} -> {result}")
                return {
                    "success": True,
                    "hostname": result,
                    "target_ip": target_ip,
                }
            else:
                logger.debug(f"MikroTik DNS resolve failed for {target_ip}: {error or 'no result'}")
                return {
                    "success": False,
                    "error": error or "No result",
                    "target_ip": target_ip,
                }
                
        except Exception as e:
            logger.warning(f"MikroTik DNS lookup failed for {target_ip}: {e}")
            return {"success": False, "error": str(e), "target_ip": target_ip}
    
    def batch_reverse_dns_lookup(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ips: List[str],
        dns_server: str = None,
        use_ssl: bool = False,
    ) -> Dict[str, str]:
        """
        Esegue reverse DNS lookup per più IP tramite MikroTik.
        Più efficiente di singole chiamate.
        
        Returns:
            Dict[ip -> hostname] (solo IP risolti con successo)
        """
        results = {}
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            
            for target_ip in target_ips:
                try:
                    # Costruisci comando resolve
                    cmd = f":put [/resolve {target_ip}]"
                    if dns_server:
                        cmd = f":put [/resolve {target_ip} server={dns_server}]"
                    
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=3)
                    result = stdout.read().decode().strip()
                    error = stderr.read().decode().strip()
                    
                    if result and not error:
                        results[target_ip] = result
                        logger.debug(f"Resolved {target_ip} -> {result}")
                except Exception as e:
                    logger.debug(f"Failed to resolve {target_ip}: {e}")
                    continue
            
            ssh.close()
            
        except Exception as e:
            logger.error(f"Batch DNS lookup failed: {e}")
        
        return results
    
    # ==========================================
    # PORT SCAN VIA ROUTER
    # ==========================================
    
    def check_port(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ip: str,
        target_port: int,
        protocol: str = "tcp",
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Verifica se una porta è aperta tramite il router MikroTik.
        Usa /tool/fetch o semplice connessione TCP.
        
        Returns:
            Dict con risultato del check
        """
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            
            # Usa /tool fetch per verificare la porta (solo TCP)
            if protocol.lower() == "tcp":
                # Prova con tool/fetch che tenta una connessione
                cmd = f"/tool/fetch mode=http url=\"http://{target_ip}:{target_port}/\" keep-result=no duration=2s"
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=5)
                result = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                # Se non c'è errore di connessione, la porta è aperta
                # Nota: questo metodo non è perfetto ma funziona per molte porte
                is_open = "connection refused" not in error.lower() and "timeout" not in error.lower()
            else:
                # Per UDP non possiamo verificare facilmente
                is_open = None
            
            ssh.close()
            
            return {
                "success": True,
                "target_ip": target_ip,
                "target_port": target_port,
                "protocol": protocol,
                "open": is_open,
            }
            
        except Exception as e:
            logger.debug(f"Port check failed for {target_ip}:{target_port}: {e}")
            return {"success": False, "error": str(e)}
    
    def scan_ports(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ip: str,
        ports: List[int] = None,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Scansiona porte TCP su un target tramite il router MikroTik.
        Usa ping TCP per verificare le porte.
        
        Args:
            target_ip: IP da scansionare
            ports: Lista porte da controllare (default: porte comuni)
            
        Returns:
            Dict con lista porte aperte
        """
        if ports is None:
            # Porte comuni da controllare
            ports = [22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445, 
                     636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 8080, 8443]
        
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
            )
            
            open_ports = []
            
            for target_port in ports:
                try:
                    # Usa tool/fetch con timeout breve per testare la porta
                    # Se la porta risponde (anche con errore HTTP), è aperta
                    cmd = f":do {{ /tool/fetch mode=http url=\"http://{target_ip}:{target_port}/\" keep-result=no duration=1s }} on-error={{ }}"
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=3)
                    
                    # Alternativa: prova con ping TCP (più affidabile)
                    # RouterOS non ha un comando diretto, ma possiamo usare telnet test
                    # Metodo alternativo: esegui un script che tenta la connessione
                    
                except Exception:
                    continue
            
            # Metodo alternativo più affidabile: usa script RouterOS
            # Questo script tenta di connettersi a ogni porta e riporta il risultato
            script = f"""
:local targetIP "{target_ip}"
:local ports "{','.join(map(str, ports))}"
:local openPorts ""
:foreach p in=[:toarray $ports] do={{
    :do {{
        /tool/fetch mode=http url="http://$targetIP:$p/" keep-result=no duration=1s
        :set openPorts ($openPorts . $p . ",")
    }} on-error={{
        # Controlla se l'errore è "connection refused" (porta chiusa) o altro (porta aperta ma no HTTP)
    }}
}}
:put $openPorts
"""
            # Per semplicità, usiamo un approccio più diretto con ping
            # MikroTik non ha port scanner integrato semplice, quindi usiamo test individuali
            
            for target_port in ports:
                try:
                    # Prova connessione TCP diretta tramite script
                    cmd = f":put [:tostr [/tool/fetch mode=http url=\"http://{target_ip}:{target_port}/\" keep-result=no duration=1s as-value ]]"
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=3)
                    stdout.read()
                    error = stderr.read().decode().strip().lower()
                    
                    # Se non è "connection refused" o "no route", la porta è probabilmente aperta
                    if error:
                        if "refused" in error or "no route" in error or "timeout" in error:
                            continue  # Porta chiusa
                    
                    # Porta aperta
                    open_ports.append({
                        "port": target_port,
                        "protocol": "tcp",
                        "open": True,
                        "service": self._get_service_name(target_port),
                    })
                except Exception:
                    continue
            
            ssh.close()
            
            logger.info(f"MikroTik port scan for {target_ip}: {len(open_ports)} ports open")
            
            return {
                "success": True,
                "target_ip": target_ip,
                "open_ports": open_ports,
                "scanned_count": len(ports),
            }
            
        except Exception as e:
            logger.error(f"MikroTik port scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _get_service_name(self, port: int) -> str:
        """Restituisce nome servizio per porta comune"""
        services = {
            22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
            110: "pop3", 135: "wmi", 139: "netbios", 143: "imap", 161: "snmp",
            389: "ldap", 443: "https", 445: "smb", 636: "ldaps", 993: "imaps",
            995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
            5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
            8080: "http-alt", 8443: "https-alt", 8728: "mikrotik-api",
            8729: "mikrotik-api-ssl", 8291: "winbox",
        }
        return services.get(port, f"port-{port}")
    
    def snmp_get(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ip: str,
        oid: str,
        community: str = "public",
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Esegue SNMP GET tramite il router MikroTik.
        MikroTik può fare SNMP tramite /tool/snmpget
        
        Returns:
            Dict con risultato SNMP
        """
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            
            # MikroTik usa /tool/snmp-get (se disponibile, dipende dalla versione)
            # In alternativa, alcuni router hanno /tool/snmpget
            cmd = f"/tool/fetch url=\"snmp://{target_ip}/{oid}\" mode=http"
            
            # Metodo alternativo: esegui snmpget se il router ha il pacchetto
            # Purtroppo MikroTik standard non ha un client SNMP built-in
            # Dobbiamo usare un approccio diverso
            
            ssh.close()
            
            return {
                "success": False,
                "error": "SNMP via MikroTik not supported - use direct connection",
            }
            
        except Exception as e:
            logger.error(f"SNMP get via MikroTik failed: {e}")
            return {"success": False, "error": str(e)}
    
    def ping_check(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target_ip: str,
        count: int = 3,
        use_ssl: bool = False,
    ) -> Dict[str, Any]:
        """
        Esegue ping a un target tramite il router MikroTik.
        
        Returns:
            Dict con risultato ping
        """
        try:
            import paramiko
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                hostname=address,
                port=22,
                username=username,
                password=password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False,
            )
            
            cmd = f"/ping {target_ip} count={count}"
            stdin, stdout, stderr = ssh.exec_command(cmd, timeout=count + 5)
            result = stdout.read().decode().strip()
            
            ssh.close()
            
            # Parse risultato ping
            lines = result.split('\n')
            received = 0
            avg_time = None
            
            for line in lines:
                if 'received' in line.lower() or 'packet-loss' in line.lower():
                    # Formato: "3 packets transmitted, 3 received, 0% packet loss"
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == 'received,' or part == 'received':
                            if i > 0 and parts[i-1].isdigit():
                                received = int(parts[i-1])
                elif 'avg' in line.lower() or 'min/avg/max' in line.lower():
                    # Estrai tempo medio
                    pass
            
            is_alive = received > 0
            
            return {
                "success": True,
                "target_ip": target_ip,
                "alive": is_alive,
                "packets_sent": count,
                "packets_received": received,
                "raw_output": result,
            }
            
        except Exception as e:
            logger.error(f"Ping check via MikroTik failed: {e}")
            return {"success": False, "error": str(e)}


    async def ping_via_router(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target: str,
        use_ssl: bool = False,
    ) -> bool:
        """
        Async wrapper per ping tramite router MikroTik.
        Ritorna True se il target risponde, False altrimenti.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.ping_check(address, port, username, password, target, count=3, use_ssl=use_ssl)
        )
        return result.get("alive", False) if result.get("success") else False
    
    async def check_port_via_router(
        self,
        address: str,
        port: int,
        username: str,
        password: str,
        target: str,
        target_port: int,
        use_ssl: bool = False,
    ) -> bool:
        """
        Async wrapper per check porta tramite router MikroTik.
        Ritorna True se la porta è aperta, False altrimenti.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.check_port(address, port, username, password, target, target_port, use_ssl=use_ssl)
        )
        return result.get("is_open", False) if result.get("success") else False


# Singleton
_mikrotik_service: Optional[MikroTikRemoteService] = None


def get_mikrotik_service() -> MikroTikRemoteService:
    global _mikrotik_service
    if _mikrotik_service is None:
        _mikrotik_service = MikroTikRemoteService()
    return _mikrotik_service
