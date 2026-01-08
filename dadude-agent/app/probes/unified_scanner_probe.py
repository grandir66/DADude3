"""
DaDude Agent - Unified Scanner Probe
v3.0.0: Scanner multi-protocollo per acquisizione dati completa

Esegue scansione combinando:
- SNMP per device di rete
- SSH per Linux/NAS/Proxmox
- WinRM per Windows
"""
import asyncio
from datetime import datetime
from typing import Dict, Any, Optional, List
from loguru import logger

# Import moduli vendor-specific per SSH
from .ssh_vendors import (
    MikroTikProbe, UbiquitiProbe, CiscoProbe, HPProbe,
    LinuxProbe, ProxmoxProbe, SynologyProbe, QNAPProbe
)


async def probe(
    target: str,
    protocols: List[str] = None,
    credentials: Dict[str, Any] = None,
    timeout: int = 180,  # Aumentato default timeout a 180 secondi
    include_software: bool = True,
    include_services: bool = True,
    include_users: bool = False,
) -> Dict[str, Any]:
    """
    Esegue probe unificato multi-protocollo.
    
    Args:
        target: IP o hostname del target
        protocols: Lista protocolli da usare (auto, snmp, ssh, winrm)
        credentials: Dict con credenziali per ogni protocollo
        timeout: Timeout totale in secondi (default 180s per dispositivi lenti)
        include_software: Includi lista software
        include_services: Includi lista servizi
        include_users: Includi lista utenti
    
    Returns:
        Dict con dati unificati da tutti i protocolli
    """
    if protocols is None:
        protocols = ["auto"]
    if credentials is None:
        credentials = {}
    
    # Assicura timeout minimo ragionevole
    timeout = max(timeout, 120)
    
    start_time = datetime.utcnow()
    
    result = {
        "target": target,
        "protocol_used": "",
        "scan_timestamp": start_time.isoformat(),
        "system_info": {},
        "cpu": {},
        "memory": {},
        "disks": [],
        "volumes": [],
        "raid_arrays": [],
        "shares": [],
        "network_interfaces": [],
        "lldp_neighbors": [],
        "services": [],
        "software": [],
        "users": [],
        "logged_in_users": [],
        "vms": [],
        "hypervisor_type": "",
        "antivirus_status": "",
        "firewall_status": "",
        "open_ports": [],
        "errors": [],
        "warnings": [],
        # Dati vendor-specific
        "routing_table": [],
        "arp_table": [],
        "dhcp_leases": [],
        "cdp_neighbors": [],
        "vlan_info": [],
        "firewall_rules_count": 0,
    }
    
    protocols_used = []
    
    try:
        # 1. Port scan SEMPRE per verificare porte aperte
        # Passa le community SNMP del cliente per il test UDP
        snmp_communities = []
        snmp_creds = credentials.get("snmp", {})
        if snmp_creds.get("community"):
            snmp_communities.append(snmp_creds["community"])
        # Aggiungi sempre public come fallback
        if "public" not in snmp_communities:
            snmp_communities.append("public")
        
        logger.info(f"[UNIFIED] Starting port scan for {target} (SNMP communities: {snmp_communities})")
        open_ports = await _scan_ports(target, snmp_communities=snmp_communities)
        result["open_ports"] = open_ports
        
        # Determina porte aperte
        ports_set = {p["port"] for p in open_ports if p.get("open")}
        logger.info(f"[UNIFIED] Open ports for {target}: {sorted(ports_set)}")
        
        # Mappa protocollo -> porte richieste
        # NOTA: SNMP usa UDP quindi il port scan TCP potrebbe non rilevarlo
        # SSH e WinRM usano TCP
        proto_ports = {
            "snmp": [],  # SNMP UDP - prova sempre, il port scan TCP non lo rileva
            "ssh": [22],
            "winrm": [5985, 5986, 135],
            "wmi": [5985, 5986, 135],
        }
        
        # Se "auto", determina protocolli automaticamente
        if "auto" in protocols:
            protocols = []  # Reset
            # SNMP: prova sempre (UDP, non rilevabile con port scan TCP)
            protocols.append("snmp")
            if 22 in ports_set:
                protocols.append("ssh")
            if 5985 in ports_set or 5986 in ports_set or 135 in ports_set:
                protocols.append("winrm")
            logger.info(f"[UNIFIED] Auto-detected protocols: {protocols}")
        else:
            # Per protocolli espliciti, filtra solo SSH/WinRM in base alle porte
            # SNMP viene sempre provato perché usa UDP
            available_protocols = []
            for proto in protocols:
                if proto == "auto":
                    continue
                if proto == "snmp":
                    # SNMP usa UDP, prova sempre
                    available_protocols.append(proto)
                elif proto == "ssh":
                    # SSH: prova sempre se richiesto esplicitamente, anche se port scan non trova porta 22
                    # Alcuni dispositivi (es. UniFi) possono avere firewall o porte non standard
                    # Il probe SSH stesso gestirà l'errore di connessione
                    if 22 in ports_set:
                        available_protocols.append(proto)
                        logger.info(f"[UNIFIED] SSH port 22 detected, adding SSH probe")
                    else:
                        # Port scan non ha trovato porta 22, ma proviamo comunque SSH
                        # perché alcuni dispositivi possono avere firewall che blocca il port scan
                        # ma permette connessioni SSH dirette
                        logger.warning(f"[UNIFIED] Port scan didn't find port 22, but trying SSH anyway (device may have firewall)")
                        available_protocols.append(proto)
                        result["warnings"].append("Port scan didn't detect SSH port 22, but trying SSH probe anyway")
                else:
                    required_ports = proto_ports.get(proto, [])
                    if not required_ports or any(p in ports_set for p in required_ports):
                        available_protocols.append(proto)
                    else:
                        logger.warning(f"[UNIFIED] Skipping {proto} - required ports {required_ports} not open")
                        result["warnings"].append(f"{proto}: porte richieste non aperte ({required_ports})")
            protocols = available_protocols
            logger.info(f"[UNIFIED] Filtered protocols based on open ports: {protocols}")
        
        if not protocols:
            logger.warning(f"[UNIFIED] No protocols available for {target}")
            result["errors"].append("Nessun protocollo disponibile - porte chiuse o non raggiungibili")
            return result
        
        # 2. Prova ogni protocollo con timeout appropriati
        # SNMP è veloce, SSH/WinRM richiedono più tempo
        snmp_result = None
        ssh_tried = False
        
        for proto in protocols:
            if proto == "auto":
                continue
            
            try:
                if proto == "snmp":
                    # SNMP timeout: 40% del totale (veloce ma deve fare molte query)
                    snmp_timeout = max(timeout * 2 // 5, 60)
                    logger.debug(f"SNMP probe for {target} with timeout {snmp_timeout}s")
                    snmp_result = await _probe_snmp(
                        target,
                        credentials.get("snmp", {}),
                        snmp_timeout
                    )
                    if snmp_result:
                        _merge_results(result, snmp_result)
                        protocols_used.append("snmp")
                
                elif proto == "ssh":
                    # SSH timeout: 70% del totale (può richiedere molti comandi)
                    ssh_timeout = max(timeout * 7 // 10, 90)
                    logger.debug(f"SSH probe for {target} with timeout {ssh_timeout}s")
                    ssh_result = await _probe_ssh(
                        target,
                        credentials.get("ssh", {}),
                        ssh_timeout,
                        include_software,
                        include_services
                    )
                    if ssh_result:
                        _merge_results(result, ssh_result)
                        protocols_used.append("ssh")
                    ssh_tried = True
                
                elif proto in ("winrm", "wmi"):
                    # WinRM/WMI timeout: 80% del totale (query WMI lente, specialmente software)
                    winrm_timeout = max(timeout * 4 // 5, 120)
                    logger.debug(f"WinRM probe for {target} with timeout {winrm_timeout}s")
                    winrm_result = await _probe_winrm(
                        target,
                        credentials.get("wmi", {}),
                        winrm_timeout,
                        include_software,
                        include_services
                    )
                    if winrm_result:
                        _merge_results(result, winrm_result)
                        protocols_used.append("winrm")
                        
            except Exception as e:
                logger.warning(f"Protocol {proto} failed for {target}: {e}")
                result["warnings"].append(f"{proto}: {str(e)}")
        
        # 3. Fallback: Se SNMP ha restituito pochi dati e SSH non è stato provato, prova SSH
        # Questo è importante per UniFi che spesso ha SNMP limitato ma SSH completo
        # Non controlliamo ports_set perché il port scan potrebbe non rilevare la porta 22
        # a causa di firewall o timeout, ma SSH potrebbe comunque funzionare
        if snmp_result and not ssh_tried:
            # Controlla se SNMP ha restituito pochi dati utili
            has_minimal_data = (
                not result.get("interfaces") or len(result.get("interfaces", [])) == 0
            ) and (
                not result.get("lldp_neighbors") or len(result.get("lldp_neighbors", [])) == 0
            ) and (
                not result.get("os_version") or result.get("os_version") == ""
            ) and (
                not result.get("firmware_version") or result.get("firmware_version") == ""
            )
            
            # Rileva UniFi/MikroTik dal modello o manufacturer
            model = result.get("model", "").lower()
            manufacturer = result.get("manufacturer", "").lower()
            is_unifi = (
                "usw" in model or "uap" in model or "usg" in model or 
                "unifi" in model or "ubiquiti" in manufacturer or
                "edge" in model or "edgerouter" in model or "edgeswitch" in model
            )
            is_mikrotik = "mikrotik" in manufacturer.lower() or "routeros" in result.get("os_name", "").lower()
            
            # Se SNMP ha restituito pochi dati E (è UniFi/MikroTik O ha dati minimi), prova SSH
            if has_minimal_data or is_unifi or is_mikrotik:
                logger.info(f"[UNIFIED] SNMP returned minimal data for {target}, trying SSH fallback (UniFi={is_unifi}, MikroTik={is_mikrotik})")
                try:
                    ssh_timeout = max(timeout * 7 // 10, 90)
                    logger.debug(f"SSH fallback probe for {target} with timeout {ssh_timeout}s")
                    ssh_result = await _probe_ssh(
                        target,
                        credentials.get("ssh", {}),
                        ssh_timeout,
                        include_software,
                        include_services
                    )
                    if ssh_result:
                        _merge_results(result, ssh_result)
                        if "ssh" not in protocols_used:
                            protocols_used.append("ssh")
                        logger.info(f"[UNIFIED] SSH fallback succeeded for {target}")
                except Exception as e:
                    logger.warning(f"SSH fallback failed for {target}: {e}")
                    result["warnings"].append(f"ssh_fallback: {str(e)}")
        
        result["protocol_used"] = ",".join(protocols_used)
        
    except Exception as e:
        logger.error(f"Unified probe error for {target}: {e}")
        result["errors"].append(str(e))
    
    # Calcola durata
    end_time = datetime.utcnow()
    result["scan_duration_seconds"] = (end_time - start_time).total_seconds()
    
    # Alias per compatibilità - preferisci "interfaces" dal probe vendor se presente e più completo
    vendor_interfaces = result.get("interfaces", [])
    network_interfaces = result.get("network_interfaces", [])
    
    # Usa interfaces dal vendor se è più completo (ha più dati come mac_address, ipv4)
    if vendor_interfaces and len(vendor_interfaces) > 0:
        # Verifica se vendor_interfaces ha dati più completi (es. mac_address)
        has_details = any(iface.get("mac_address") or iface.get("ipv4") for iface in vendor_interfaces)
        if has_details or not network_interfaces:
            result["network_interfaces"] = vendor_interfaces
            result["interfaces"] = vendor_interfaces
    elif network_interfaces:
        result["interfaces"] = network_interfaces
    
    # Flatten system_info nel risultato principale per compatibilità
    for key, value in result.get("system_info", {}).items():
        if key not in result or not result[key]:
            result[key] = value
    
    return result


async def _scan_ports(target: str, snmp_communities: List[str] = None) -> List[Dict]:
    """Scansione porte veloce per determinare protocolli
    
    Args:
        target: IP o hostname da scansionare
        snmp_communities: Lista di community SNMP da provare per il test UDP (default: ["public"])
    """
    # Porte rilevanti per unified scan
    ports = [22, 135, 161, 443, 5985, 5986, 8728]
    
    if snmp_communities is None:
        snmp_communities = ["public"]
    
    try:
        # Prova prima con port_scanner interno
        try:
            from ..scanners.port_scanner import scan
            results = await asyncio.wait_for(
                scan(target, ports=ports, timeout=2.0, include_udp=True, snmp_communities=snmp_communities),
                timeout=30
            )
            logger.debug(f"[PORTSCAN] Full scan with port_scanner: {len(results)} ports open for {target}")
            return results
        except ImportError as e:
            logger.warning(f"[PORTSCAN] Could not import port_scanner: {e}, using fallback")
        except TypeError as e:
            # Port scanner potrebbe non supportare snmp_communities (vecchia versione)
            logger.warning(f"[PORTSCAN] Port scanner doesn't support snmp_communities: {e}")
            from ..scanners.port_scanner import scan
            results = await asyncio.wait_for(
                scan(target, ports=ports, timeout=2.0, include_udp=True),
                timeout=30
            )
            return results
        
        # Fallback: scan manuale TCP con timeout aumentato
        results = []
        for port in ports:
            try:
                conn = asyncio.open_connection(target, port)
                _, writer = await asyncio.wait_for(conn, timeout=5.0)
                writer.close()
                await writer.wait_closed()
                results.append({"port": port, "protocol": "tcp", "open": True, "service": _get_service_name(port)})
                logger.debug(f"[PORTSCAN] {target}:{port} TCP open")
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as e:
                results.append({"port": port, "protocol": "tcp", "open": False})
                logger.debug(f"[PORTSCAN] {target}:{port} TCP closed/filtered: {type(e).__name__}")
        
        # Per SNMP (UDP 161) prova con tutte le community del cliente
        snmp_found = False
        for community in snmp_communities:
            if snmp_found:
                break
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0)
                # Costruisci pacchetto SNMP con la community specificata
                snmp_get = _build_snmp_packet(community)
                sock.sendto(snmp_get, (target, 161))
                try:
                    data, _ = sock.recvfrom(1024)
                    if data:
                        results.append({"port": 161, "protocol": "udp", "open": True, "service": "snmp"})
                        logger.debug(f"[PORTSCAN] {target}:161 UDP (SNMP) open with community '{community}'")
                        snmp_found = True
                except socket.timeout:
                    pass
                sock.close()
            except Exception as e:
                logger.debug(f"[PORTSCAN] SNMP UDP check with '{community}' failed: {e}")
        
        return results
        
    except asyncio.TimeoutError:
        logger.warning(f"[PORTSCAN] Timeout for {target}")
        return []
    except Exception as e:
        logger.warning(f"[PORTSCAN] Failed for {target}: {e}")
        return []


def _build_snmp_packet(community: str) -> bytes:
    """Costruisce un pacchetto SNMP GET per sysDescr.0 con la community specificata"""
    community_bytes = community.encode('ascii')
    community_len = len(community_bytes)
    
    # PDU content (request-id, error-status, error-index, varbind)
    pdu_content = bytes([
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id: 1
        0x02, 0x01, 0x00,  # error-status: 0
        0x02, 0x01, 0x00,  # error-index: 0
        0x30, 0x0b,  # varbind list
        0x30, 0x09,  # varbind
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID: 1.3.6.1.2.1 (sysDescr)
        0x05, 0x00,  # NULL value
    ])
    pdu_len = len(pdu_content)
    
    # Costruisci pacchetto completo
    packet = bytes([0x30])  # SEQUENCE
    inner_len = 3 + 2 + community_len + 2 + pdu_len
    packet += bytes([inner_len])
    packet += bytes([0x02, 0x01, 0x00])  # version: 0 (SNMPv1)
    packet += bytes([0x04, community_len]) + community_bytes
    packet += bytes([0xa0, pdu_len]) + pdu_content  # GET-REQUEST
    
    return packet


def _get_service_name(port: int) -> str:
    """Restituisce il nome del servizio per una porta nota"""
    services = {
        22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
        110: "pop3", 135: "wmi", 139: "netbios", 143: "imap", 161: "snmp",
        389: "ldap", 443: "https", 445: "smb", 636: "ldaps",
        5985: "winrm", 5986: "winrm-ssl", 8728: "mikrotik-api",
        8729: "mikrotik-api-ssl", 8291: "winbox",
    }
    return services.get(port, f"port-{port}")


async def _probe_snmp(
    target: str,
    credentials: Dict,
    timeout: int
) -> Optional[Dict]:
    """Probe SNMP - prova prima con community del cliente, poi fallback a 'public'"""
    try:
        from .snmp_probe import probe as snmp_probe
        
        version = credentials.get("version", "2c")
        port = credentials.get("port", 161)
        
        # Lista di communities da provare (prima quella del cliente, poi 'public' come fallback)
        communities_to_try = []
        
        # Prima aggiungi la community del cliente se presente
        client_community = credentials.get("community")
        if client_community and client_community.strip():
            communities_to_try.append(client_community.strip())
            logger.debug(f"[UNIFIED] SNMP probe: Will try client community '{client_community}' first for {target}")
        
        # Aggiungi 'public' come fallback solo se non è già nella lista
        if "public" not in communities_to_try:
            communities_to_try.append("public")
            logger.debug(f"[UNIFIED] SNMP probe: Will use 'public' as fallback for {target}")
        
        # Prova ogni community fino a che una funziona
        for community in communities_to_try:
            try:
                logger.debug(f"[UNIFIED] SNMP probe: Trying community '{community}' for {target}")
                result = await asyncio.wait_for(
                    snmp_probe(target, community=community, version=version, port=port),
                    timeout=timeout
                )
                
                # Verifica se abbiamo ottenuto dati validi (hostname, identity, o device_type)
                if result and (result.get("identity") or result.get("hostname") or result.get("device_type")):
                    logger.info(f"[UNIFIED] SNMP probe succeeded with community '{community}' for {target}: hostname={result.get('hostname')}, identity={result.get('identity')}, device_type={result.get('device_type')}")
                    return _normalize_snmp_result(result)
                else:
                    logger.debug(f"[UNIFIED] SNMP probe with community '{community}' returned no usable data for {target}, trying next...")
                    # Continua con la prossima community
                    continue
                    
            except asyncio.TimeoutError:
                logger.debug(f"[UNIFIED] SNMP probe timeout with community '{community}' for {target}, trying next...")
                # Continua con la prossima community
                continue
            except Exception as e:
                logger.debug(f"[UNIFIED] SNMP probe error with community '{community}' for {target}: {e}, trying next...")
                # Continua con la prossima community
                continue
        
        # Se arriviamo qui, nessuna community ha funzionato
        logger.warning(f"[UNIFIED] SNMP probe failed for {target} with all communities tried: {communities_to_try}")
        
    except Exception as e:
        logger.warning(f"[UNIFIED] SNMP probe unexpected error for {target}: {e}")
    
    return None


async def _probe_ssh(
    target: str,
    credentials: Dict,
    timeout: int,
    include_software: bool,
    include_services: bool
) -> Optional[Dict]:
    """Probe SSH con integrazione moduli vendor-specific"""
    try:
        from .ssh_probe import probe as ssh_probe
        
        username = credentials.get("username")
        password = credentials.get("password")
        private_key = credentials.get("private_key")
        port = credentials.get("port", 22)
        
        logger.info(f"[UNIFIED] SSH probe for {target}: username={username}, "
                   f"password={'***' if password else 'None'}, port={port}")
        
        if not username:
            logger.warning(f"[UNIFIED] SSH probe skipped for {target}: no username provided")
            return None
        
        if not password and not private_key:
            logger.warning(f"[UNIFIED] SSH probe skipped for {target}: no password or private_key provided")
            return None
        
        # 1. Esegui probe SSH base
        result = await asyncio.wait_for(
            ssh_probe(
                target,
                username=username,
                password=password,
                private_key=private_key,
                port=port
            ),
            timeout=timeout
        )
        
        if not result or not result.get("hostname"):
            logger.warning(f"[UNIFIED] SSH probe returned no usable data for {target}")
            return None
        
        logger.info(f"[UNIFIED] SSH probe got data for {target}: hostname={result.get('hostname')}, manufacturer={result.get('manufacturer')}")
        
        # 2. Rileva vendor e chiama modulo vendor-specific se disponibile
        manufacturer = (result.get("manufacturer") or "").lower()
        os_name = (result.get("os_name") or result.get("os") or "").lower()
        device_type = (result.get("device_type") or "").lower()
        
        # Determina quale probe vendor-specific usare
        vendor_probe_class = None
        if "mikrotik" in manufacturer or "routeros" in os_name or device_type == "mikrotik":
            vendor_probe_class = MikroTikProbe
        elif "ubiquiti" in manufacturer or "unifi" in os_name or "edgeos" in os_name:
            vendor_probe_class = UbiquitiProbe
        elif "cisco" in manufacturer or "ios" in os_name or "nx-os" in os_name:
            vendor_probe_class = CiscoProbe
        elif "hp" in manufacturer or "hewlett" in manufacturer or "comware" in os_name or "procurve" in os_name:
            vendor_probe_class = HPProbe
        elif "proxmox" in os_name or device_type == "proxmox":
            vendor_probe_class = ProxmoxProbe
        elif "synology" in manufacturer or "dsm" in os_name:
            vendor_probe_class = SynologyProbe
        elif "qnap" in manufacturer or "qts" in os_name:
            vendor_probe_class = QNAPProbe
        
        # 3. Se vendor rilevato, chiama probe vendor-specific per dati avanzati
        if vendor_probe_class:
            logger.info(f"[UNIFIED] Detected vendor {vendor_probe_class.VENDOR_NAME}, calling vendor-specific probe for {target}")
            try:
                # Crea connessione SSH per il probe vendor-specific
                import paramiko
                from io import StringIO
                
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                connect_args = {
                    "hostname": target,
                    "port": port,
                    "username": username,
                    "timeout": min(timeout // 2, 30),  # Timeout più breve per connessione
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
                
                # Crea funzioni exec_cmd per il probe vendor-specific
                def exec_cmd(cmd: str, timeout: int = 5) -> str:
                    """Esegue comando SSH"""
                    try:
                        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                        output = stdout.read().decode().strip()
                        error = stderr.read().decode().strip()
                        if error and "Permission denied" not in error.lower() and "command not found" not in error.lower():
                            logger.debug(f"SSH exec_cmd '{cmd[:50]}...' stderr: {error[:200]}")
                        return output
                    except Exception as e:
                        logger.debug(f"SSH exec_cmd '{cmd[:50]}...' failed: {e}")
                        return ""
                
                def exec_cmd_sudo(cmd: str, timeout: int = 5) -> str:
                    """Esegue comando con sudo se necessario"""
                    # Prova prima senza sudo (molti comandi Synology funzionano anche senza root)
                    output = exec_cmd(cmd, timeout=timeout)
                    if output and len(output.strip()) > 0:
                        return output
                    
                    # Se senza sudo non funziona, prova con sudo
                    # Se abbiamo la password SSH, usala per sudo
                    ssh_password = credentials.get("password")
                    if ssh_password:
                        import shlex
                        
                        # Metodo 1: Echo semplice con password literal
                        # Escapa caratteri speciali per shell
                        escaped_password = ssh_password.replace("\\", "\\\\").replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
                        # Rimuovi redirect dal comando per sudo
                        cmd_clean = cmd.replace(' 2>/dev/null', '').replace(' 2>&1', '')
                        # Usa sudo con PATH preservato per trovare comandi Synology/QNAP
                        # Include /usr/syno/sbin dove si trovano molti tool Synology
                        sudo_cmd = f'echo "{escaped_password}" | sudo -S env "PATH=$PATH:/usr/syno/bin:/usr/syno/sbin:/usr/local/bin:/usr/sbin:/sbin" {cmd_clean}'
                        logger.debug(f"SSH: trying sudo with echo, cmd_clean: {cmd_clean[:80]}...")
                        try:
                            stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout)
                            sudo_output = stdout.read().decode().strip()
                            sudo_error = stderr.read().decode().strip()
                            logger.debug(f"SSH: sudo echo raw output length={len(sudo_output)}, stderr length={len(sudo_error)}, stderr={sudo_error[:150] if sudo_error else 'none'}")
                            
                            # Rimuovi eventuali prompt password dall'output
                            lines = []
                            for line in sudo_output.split('\n'):
                                line_lower = line.lower()
                                if '[sudo]' not in line_lower and 'password' not in line_lower and 'password:' not in line_lower:
                                    lines.append(line)
                            sudo_output = '\n'.join(lines)
                            
                            # Rimuovi prompt password anche da stderr
                            stderr_clean = '\n'.join([l for l in sudo_error.split('\n') if 'password' not in l.lower()])
                            
                            # Se sudo funziona (output presente), usalo
                            if sudo_output and len(sudo_output.strip()) > 0:
                                logger.debug(f"SSH: sudo command succeeded with echo: {cmd_clean[:50]}...")
                                return sudo_output
                            elif not stderr_clean or ('incorrect password' not in stderr_clean.lower() and 'authentication failure' not in stderr_clean.lower()):
                                # Potrebbe essere che l'output sia vuoto ma il comando sia riuscito
                                logger.debug(f"SSH: sudo command executed (empty output): {cmd_clean[:50]}...")
                                return sudo_output
                            else:
                                logger.debug(f"SSH: sudo with echo failed, error: {sudo_error[:100]}")
                        except Exception as e:
                            logger.debug(f"SSH: sudo command with echo failed: {cmd_clean[:50]}... error: {e}")
                        
                        # Metodo 2: Usa stdin diretto per password con PTY
                        try:
                            cmd_clean = cmd.replace(' 2>/dev/null', '').replace(' 2>&1', '')
                            # Usa sudo con PATH preservato per trovare comandi Synology/QNAP
                            sudo_cmd = f'sudo -S env "PATH=$PATH:/usr/syno/bin:/usr/syno/sbin:/usr/local/bin:/usr/sbin:/sbin" {cmd_clean}'
                            logger.debug(f"SSH: trying sudo with stdin/pty, cmd_clean: {cmd_clean[:80]}...")
                            stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout, get_pty=True)
                            # Invia password direttamente via stdin
                            stdin.write(ssh_password + '\n')
                            stdin.flush()
                            
                            sudo_output = stdout.read().decode().strip()
                            sudo_error = stderr.read().decode().strip()
                            logger.debug(f"SSH: sudo stdin raw output length={len(sudo_output)}, stderr length={len(sudo_error)}, preview={sudo_output[:200] if sudo_output else 'empty'}")
                            
                            # Rimuovi eventuali prompt password dall'output
                            lines = []
                            for line in sudo_output.split('\n'):
                                line_lower = line.lower()
                                if '[sudo]' not in line_lower and 'password' not in line_lower and 'password:' not in line_lower:
                                    lines.append(line)
                            sudo_output = '\n'.join(lines)
                            
                            if sudo_output and len(sudo_output.strip()) > 0:
                                logger.debug(f"SSH: sudo command succeeded with stdin: {cmd_clean[:50]}...")
                                return sudo_output
                        except Exception as e:
                            logger.debug(f"SSH: sudo command with stdin failed: {cmd_clean[:50]}... error: {e}")
                    
                    # Fallback: prova sudo senza password (se configurato NOPASSWD)
                    sudo_cmd = f"sudo {cmd}"
                    try:
                        stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout)
                        sudo_output = stdout.read().decode().strip()
                        sudo_error = stderr.read().decode().strip()
                        
                        # Se sudo funziona (output presente e nessun errore di password), usalo
                        if sudo_output and len(sudo_output.strip()) > 0:
                            # Verifica che non ci siano errori di password
                            if "password" not in sudo_error.lower() and "sudo:" not in sudo_error.lower():
                                logger.debug(f"SSH: sudo command succeeded without password: {cmd[:50]}...")
                                return sudo_output
                            else:
                                logger.debug(f"SSH: sudo requires password (not available): {cmd[:50]}...")
                    except Exception as e:
                        logger.debug(f"SSH: sudo command failed: {cmd[:50]}... error: {e}")
                    
                    # Se entrambi falliscono, ritorna output originale (potrebbe essere vuoto ma corretto)
                    return output
                
                # Istanzia e chiama probe vendor-specific
                vendor_probe = vendor_probe_class(exec_cmd, exec_cmd_sudo)
                
                # Verifica detection prima di chiamare probe completo
                if vendor_probe.detect():
                    logger.info(f"[UNIFIED] Vendor {vendor_probe_class.VENDOR_NAME} confirmed, collecting advanced data")
                    vendor_result = vendor_probe.probe(target)
                    logger.info(f"[UNIFIED] Vendor probe returned: type={type(vendor_result)}, fields={len(vendor_result) if vendor_result else 0}, keys={sorted(list(vendor_result.keys()))[:10] if vendor_result else []}")
                    
                    # Log chiavi importanti per storage
                    if vendor_result:
                        logger.info(f"[UNIFIED] Vendor storage data: volumes={len(vendor_result.get('volumes', []))}, disks={len(vendor_result.get('disks', []))}, disk_total_gb={vendor_result.get('disk_total_gb')}, disk_used_gb={vendor_result.get('disk_used_gb')}")
                    
                    # Merge dati vendor-specific con risultato base
                    if vendor_result:
                        # Estrai storage_info se presente (Synology/QNAP)
                        storage_info = vendor_result.get("storage_info", {})
                        if storage_info:
                            # Estrai volumes, disks, raid_arrays da storage_info
                            if storage_info.get("volumes"):
                                result["volumes"] = storage_info["volumes"]
                            if storage_info.get("disks"):
                                result["disks"] = storage_info["disks"]
                            if storage_info.get("raid_arrays"):
                                result["raid_arrays"] = storage_info["raid_arrays"]
                        
                        # Estrai anche direttamente dal dizionario principale (Synology restituisce così)
                        if vendor_result.get("volumes"):
                            result["volumes"] = vendor_result["volumes"]
                        if vendor_result.get("disks"):
                            result["disks"] = vendor_result["disks"]
                        if vendor_result.get("raid_arrays"):
                            result["raid_arrays"] = vendor_result["raid_arrays"]
                        if vendor_result.get("shares"):
                            result["shares"] = vendor_result["shares"]
                        
                        # I dati vendor-specific hanno priorità
                        for key, value in vendor_result.items():
                            if value and key not in ["storage_info", "volumes", "disks", "raid_arrays", "shares"]:  # già processati sopra
                                result[key] = value
                        
                        logger.info(f"[UNIFIED] Vendor-specific probe collected: device_type={vendor_result.get('device_type')}, volumes={len(result.get('volumes', []))}, disks={len(result.get('disks', []))}, raid_arrays={len(result.get('raid_arrays', []))}, shares={len(result.get('shares', []))}")
                        logger.info(f"[UNIFIED] After merge: result.device_type={result.get('device_type')}, volumes={len(result.get('volumes', []))}, disks={len(result.get('disks', []))}, raid_arrays={len(result.get('raid_arrays', []))}, shares={len(result.get('shares', []))}")
                else:
                    logger.debug(f"[UNIFIED] Vendor {vendor_probe_class.VENDOR_NAME} detection failed, skipping vendor-specific probe")
                
                client.close()
                
            except Exception as e:
                logger.warning(f"[UNIFIED] Vendor-specific probe failed for {target}: {e}")
                # Continua con risultato base anche se probe vendor-specific fallisce
                try:
                    client.close()
                except:
                    pass
        
        logger.debug(f"[UNIFIED] Before normalization: os_name={result.get('os_name')}, manufacturer={result.get('manufacturer')}, device_type={result.get('device_type')}")
        normalized = _normalize_ssh_result(result)
        logger.info(f"[UNIFIED] After normalization: os_name={normalized.get('system_info', {}).get('os_name')}, volumes={len(normalized.get('volumes', []))}, disks={len(normalized.get('disks', []))}, raid_arrays={len(normalized.get('raid_arrays', []))}, shares={len(normalized.get('shares', []))}")
        return normalized
        
    except asyncio.TimeoutError:
        logger.warning(f"SSH probe timeout for {target}")
    except Exception as e:
        logger.warning(f"SSH probe error for {target}: {e}")
    
    return None


async def _probe_winrm(
    target: str,
    credentials: Dict,
    timeout: int,
    include_software: bool,
    include_services: bool
) -> Optional[Dict]:
    """Probe WinRM/WMI"""
    try:
        from .wmi_probe import probe as wmi_probe
        
        username = credentials.get("username")
        password = credentials.get("password")
        domain = credentials.get("domain", "")
        
        if not username:
            return None
        
        result = await asyncio.wait_for(
            wmi_probe(
                target,
                username=username,
                password=password,
                domain=domain
            ),
            timeout=timeout
        )
        
        if result and result.get("hostname"):
            return _normalize_winrm_result(result)
        
    except asyncio.TimeoutError:
        logger.warning(f"WinRM probe timeout for {target}")
    except Exception as e:
        logger.warning(f"WinRM probe error for {target}: {e}")
    
    return None


def _normalize_snmp_result(data: Dict) -> Dict:
    """Normalizza risultato SNMP nel formato unificato"""
    result = {
        "system_info": {
            "hostname": data.get("identity") or data.get("hostname") or data.get("sysName", ""),
            "device_type": data.get("device_type", "unknown"),
            "os_name": data.get("platform") or data.get("os", ""),
            "os_version": data.get("version") or data.get("software_version", ""),
            "manufacturer": data.get("vendor") or data.get("manufacturer", ""),
            "model": data.get("model") or data.get("board", ""),
            "serial_number": data.get("serial_number", ""),
            "firmware_version": data.get("firmware") or data.get("firmware_version", ""),
            "uptime": data.get("uptime", ""),
        },
        "network_interfaces": _safe_list(data.get("interfaces")),
        "lldp_neighbors": _safe_list(data.get("lldp_neighbors")),
        # Dati vendor-specific raccolti da SNMP
        "routing_table": _safe_list(data.get("routing_table")),
        "arp_table": _safe_list(data.get("arp_table")),
    }
    
    # CPU/Memory se disponibili
    if data.get("cpu_usage"):
        result["cpu"] = {"load_percent": data.get("cpu_usage", 0)}
    if data.get("memory_usage"):
        result["memory"] = {"usage_percent": data.get("memory_usage", 0)}
    
    return result


def _safe_list(value, default=None):
    """Converte un valore in lista in modo sicuro"""
    if default is None:
        default = []
    if value is None:
        return default
    if isinstance(value, list):
        return value
    if isinstance(value, (int, float, str)):
        return default  # Non iterabile
    try:
        return list(value)
    except (TypeError, ValueError):
        return default


def _normalize_ssh_result(data: Dict) -> Dict:
    """Normalizza risultato SSH nel formato unificato"""
    # Preserva os_name se già impostato dal vendor probe (es. DSM per Synology)
    os_name = data.get("os_name") or data.get("os") or data.get("distro", "")
    result = {
        "system_info": {
            "hostname": data.get("hostname", ""),
            "device_type": _detect_device_type_from_ssh(data),
            "os_name": os_name,
            "os_version": data.get("version") or data.get("os_version", ""),
            "kernel_version": data.get("kernel", ""),
            "manufacturer": data.get("manufacturer", ""),
            "model": data.get("model", ""),
            "serial_number": data.get("serial", ""),
            "uptime": data.get("uptime", ""),
        },
        "cpu": {
            "model": data.get("cpu_model", ""),
            "cores_physical": data.get("cpu_cores", 0),
            "cores_logical": data.get("cpu_threads", 0),
            "load_1min": data.get("load_1", 0),
            "load_5min": data.get("load_5", 0),
            "load_15min": data.get("load_15", 0),
        },
        "memory": {
            "total_bytes": int(data.get("memory_total_mb", 0) or 0) * 1024 * 1024,
            "used_bytes": int(data.get("memory_used_mb", 0) or 0) * 1024 * 1024,
            "free_bytes": int(data.get("memory_free_mb", 0) or 0) * 1024 * 1024,
        },
        "disks": _safe_list(data.get("disks") or (data.get("storage_info", {}).get("disks") if isinstance(data.get("storage_info"), dict) else [])),
        "volumes": _safe_list(data.get("volumes") or data.get("filesystems") or (data.get("storage_info", {}).get("volumes") if isinstance(data.get("storage_info"), dict) else [])),
        "raid_arrays": _safe_list(data.get("raid_arrays") or (data.get("storage_info", {}).get("raid_arrays") if isinstance(data.get("storage_info"), dict) else [])),
        "shares": _safe_list(data.get("shares") or []),
        # Mantieni anche i campi originali se presenti
        "volumes_count": data.get("volumes_count", 0),
        "disks_count": data.get("disks_count", 0),
        "raid_count": data.get("raid_count", 0),
        "shares_count": data.get("shares_count", 0),
        "disk_total_gb": data.get("disk_total_gb", 0),
        "disk_used_gb": data.get("disk_used_gb", 0),
        "disk_free_gb": data.get("disk_free_gb", 0),
        "network_interfaces": _safe_list(data.get("network_interfaces") or data.get("interfaces")),
        "lldp_neighbors": _safe_list(data.get("lldp_neighbors") or data.get("neighbors")),
        "services": _safe_list(data.get("services")),
        "vms": _safe_list(data.get("vms")),
        # Dati vendor-specific
        "routing_table": _safe_list(data.get("routing_table")),
        "arp_table": _safe_list(data.get("arp_table")),
        "dhcp_leases": _safe_list(data.get("dhcp_leases")),
        "cdp_neighbors": _safe_list(data.get("cdp_neighbors")),
        "vlan_info": _safe_list(data.get("vlan_info")),
        "firewall_rules_count": data.get("firewall_rules_count", 0),
    }
    
    # Calcola usage percent
    if result["memory"]["total_bytes"]:
        result["memory"]["usage_percent"] = (
            result["memory"]["used_bytes"] / result["memory"]["total_bytes"]
        ) * 100
    
    # Proxmox
    if data.get("proxmox"):
        result["hypervisor_type"] = "pve"
        result["system_info"]["device_type"] = "proxmox"
    
    # MikroTik/Ubiquiti: aggiungi neighbors se presenti
    if data.get("neighbors") and not result["lldp_neighbors"]:
        result["lldp_neighbors"] = _safe_list(data.get("neighbors"))
    
    # MikroTik/Ubiquiti: aggiungi interfaces se presenti
    if data.get("interfaces") and not result["network_interfaces"]:
        result["network_interfaces"] = _safe_list(data.get("interfaces"))
    
    return result


def _normalize_winrm_result(data: Dict) -> Dict:
    """Normalizza risultato WinRM nel formato unificato"""
    result = {
        "system_info": {
            "hostname": data.get("hostname", ""),
            "device_type": "windows_server" if "server" in (data.get("os") or "").lower() else "windows_workstation",
            "os_name": data.get("os", ""),
            "os_version": data.get("version", ""),
            "os_build": data.get("build", ""),
            "manufacturer": data.get("manufacturer", ""),
            "model": data.get("model", ""),
            "serial_number": data.get("serial", ""),
            "bios_version": data.get("bios_version", ""),
            "uptime": data.get("uptime", ""),
        },
        "cpu": {
            "model": data.get("cpu_name", ""),
            "cores_physical": data.get("cpu_cores", 0),
            "cores_logical": data.get("cpu_threads", 0),
            "load_percent": data.get("cpu_usage", 0),
        },
        "memory": {
            "total_bytes": int(data.get("memory_total_mb", 0) or 0) * 1024 * 1024,
            "used_bytes": int(data.get("memory_used_mb", 0) or 0) * 1024 * 1024,
            "free_bytes": int(data.get("memory_free_mb", 0) or 0) * 1024 * 1024,
        },
        "disks": _safe_list(data.get("disks")),
        "volumes": _safe_list(data.get("volumes")),
        "network_interfaces": _safe_list(data.get("network_adapters")),
        "services": _safe_list(data.get("services")),
        "software": _safe_list(data.get("software")),
        "users": _safe_list(data.get("local_users")),
        "logged_in_users": _safe_list(data.get("logged_users")),
        "antivirus_status": data.get("antivirus", ""),
        "firewall_status": data.get("firewall_status", ""),
    }
    
    # Calcola usage percent
    if result["memory"]["total_bytes"]:
        result["memory"]["usage_percent"] = (
            result["memory"]["used_bytes"] / result["memory"]["total_bytes"]
        ) * 100
    
    return result


def _detect_device_type_from_ssh(data: Dict) -> str:
    """Rileva tipo device da dati SSH"""
    # Log per debug
    import logging
    logger = logging.getLogger(__name__)
    
    # Se il probe ha già determinato il device_type, usalo
    existing_type = data.get("device_type")
    if existing_type:
        logger.debug(f"[DETECT_TYPE] Using existing device_type: {existing_type}")
        return existing_type
    
    os_lower = (data.get("os") or "").lower()
    distro = (data.get("distro") or "").lower()
    hostname = (data.get("hostname") or "").lower()
    manufacturer = (data.get("manufacturer") or "").lower()
    
    # MikroTik - router
    if manufacturer == "mikrotik" or "routeros" in os_lower:
        return "router"
    
    # Proxmox
    if "proxmox" in os_lower or "pve" in distro:
        return "proxmox"
    if data.get("vms"):
        return "proxmox"  # Ha VMs, probabilmente hypervisor
    
    # NAS devices
    if "synology" in os_lower or "dsm" in distro or manufacturer == "synology":
        return "nas"
    if "qnap" in os_lower or "qts" in distro or manufacturer == "qnap":
        return "nas"
    
    return "linux_server"


def _merge_interfaces(target_list: List[Dict], source_list: List[Dict]):
    """Merge network interfaces by name, combining data from multiple sources"""
    # Build index by normalized interface name
    by_name = {}
    for iface in target_list:
        name = (iface.get("name") or "").lower().strip()
        if name:
            by_name[name] = iface
    
    for src_iface in source_list:
        name = (src_iface.get("name") or "").lower().strip()
        if not name:
            continue
        
        if name in by_name:
            # Merge: update empty fields with source data
            existing = by_name[name]
            for key, value in src_iface.items():
                if value and value not in ["-", "N/A", "", 0, "0", "unknown"]:
                    existing_val = existing.get(key)
                    # Update if existing is empty or less informative
                    if not existing_val or existing_val in ["-", "N/A", "", 0, "0", "unknown"]:
                        existing[key] = value
                    # Special case: prefer "up" status over "down" if both present
                    elif key in ("admin_status", "oper_status", "state"):
                        if str(value).lower() == "up" and str(existing_val).lower() == "down":
                            existing[key] = value
        else:
            # New interface, add it
            target_list.append(src_iface)
            by_name[name] = src_iface


def _merge_lldp_neighbors(target_list: List[Dict], source_list: List[Dict]):
    """Merge LLDP neighbors, avoiding duplicates based on local_interface + remote_device"""
    # Build index by (local_interface, remote_device_name or remote_chassis_id)
    existing_keys = set()
    for neighbor in target_list:
        local_if = (neighbor.get("local_interface") or "").lower().strip()
        remote_id = (
            neighbor.get("remote_device_name") or 
            neighbor.get("remote_chassis_id") or ""
        ).lower().strip()
        if local_if and remote_id:
            existing_keys.add((local_if, remote_id))
    
    for src_neighbor in source_list:
        local_if = (src_neighbor.get("local_interface") or "").lower().strip()
        remote_id = (
            src_neighbor.get("remote_device_name") or 
            src_neighbor.get("remote_chassis_id") or ""
        ).lower().strip()
        
        key = (local_if, remote_id)
        if key not in existing_keys and local_if and remote_id:
            target_list.append(src_neighbor)
            existing_keys.add(key)


def _merge_results(target: Dict, source: Dict):
    """Merge risultati da diversi protocolli"""
    if not source:
        return
    
    # System info - priorità ai dati più completi
    for key, value in source.get("system_info", {}).items():
        if value and not target["system_info"].get(key):
            target["system_info"][key] = value
    
    # CPU/Memory - aggiorna se presente
    if source.get("cpu"):
        target["cpu"].update(source["cpu"])
    if source.get("memory"):
        target["memory"].update(source["memory"])
    
    # Liste - estendi con deduplicazione
    if source.get("disks"):
        existing_disks = {d.get("name") or d.get("device") for d in target["disks"]}
        for disk in source["disks"]:
            disk_id = disk.get("name") or disk.get("device")
            if disk_id not in existing_disks:
                target["disks"].append(disk)
                existing_disks.add(disk_id)
    if source.get("volumes"):
        existing_volumes = {v.get("mount_point") or v.get("path") for v in target["volumes"]}
        for vol in source["volumes"]:
            vol_id = vol.get("mount_point") or vol.get("path")
            if vol_id not in existing_volumes:
                target["volumes"].append(vol)
                existing_volumes.add(vol_id)
    if source.get("raid_arrays"):
        existing_raids = {r.get("name") or r.get("device") for r in target["raid_arrays"]}
        for raid in source["raid_arrays"]:
            raid_id = raid.get("name") or raid.get("device")
            if raid_id not in existing_raids:
                target["raid_arrays"].append(raid)
                existing_raids.add(raid_id)
    if source.get("shares"):
        existing_shares = {s.get("name") for s in target["shares"]}
        for share in source["shares"]:
            share_id = share.get("name")
            if share_id not in existing_shares:
                target["shares"].append(share)
                existing_shares.add(share_id)
    
    # Network interfaces - merge per nome interfaccia
    if source.get("network_interfaces"):
        _merge_interfaces(target["network_interfaces"], source["network_interfaces"])
    
    # LLDP neighbors - merge per local_interface + remote_device
    if source.get("lldp_neighbors"):
        _merge_lldp_neighbors(target["lldp_neighbors"], source["lldp_neighbors"])
    if source.get("services"):
        target["services"].extend(source["services"])
    if source.get("software"):
        target["software"].extend(source["software"])
    if source.get("users"):
        target["users"].extend(source["users"])
    if source.get("logged_in_users"):
        target["logged_in_users"].extend(source["logged_in_users"])
    if source.get("vms"):
        target["vms"].extend(source["vms"])
    
    # Dati vendor-specific - merge con priorità ai dati più completi
    # Routing table: mergeare da tutte le fonti
    if source.get("routing_table"):
        if not target.get("routing_table"):
            target["routing_table"] = []
        target["routing_table"].extend(source["routing_table"])
    
    # ARP table: mergeare da tutte le fonti
    if source.get("arp_table"):
        if not target.get("arp_table"):
            target["arp_table"] = []
        target["arp_table"].extend(source["arp_table"])
    
    # DHCP leases: solo da MikroTik (sostituisce se presente)
    if source.get("dhcp_leases"):
        target["dhcp_leases"] = source["dhcp_leases"]
    
    # CDP neighbors: solo da Cisco (sostituisce se presente)
    if source.get("cdp_neighbors"):
        target["cdp_neighbors"] = source["cdp_neighbors"]
    
    # VLAN info: mergeare da tutte le fonti
    if source.get("vlan_info"):
        if not target.get("vlan_info"):
            target["vlan_info"] = []
        target["vlan_info"].extend(source["vlan_info"])
    
    # Firewall rules count: aggiorna se maggiore
    if source.get("firewall_rules_count"):
        current_count = target.get("firewall_rules_count", 0)
        if source["firewall_rules_count"] > current_count:
            target["firewall_rules_count"] = source["firewall_rules_count"]
    
    # Stringhe singole
    for key in ["hypervisor_type", "antivirus_status", "firewall_status"]:
        if source.get(key) and not target.get(key):
            target[key] = source[key]


# Import opzionale per port_scanner
try:
    from ..scanners import port_scanner
except ImportError:
    port_scanner = None
