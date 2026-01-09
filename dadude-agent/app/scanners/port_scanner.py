"""
DaDude Agent - Port Scanner
Scansione porte TCP/UDP
v3.0.0: Aggiunto supporto UDP per SNMP e DNS
v3.2.0: Configurazione porte da file JSON
"""
import asyncio
import socket
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from loguru import logger


# Porte di default hardcoded (fallback se config non disponibile)
_DEFAULT_PORTS_HARDCODED = [
    22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445,
    636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986,
    8080, 8443, 8728, 8729, 8291,
]

_DEFAULT_UDP_PORTS_HARDCODED = [
    53,    # DNS
    161,   # SNMP
    162,   # SNMP Trap
    123,   # NTP
    500,   # IKE (VPN)
]

# Mappa porte -> servizi (fallback)
_PORT_SERVICES_HARDCODED = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "wmi", 139: "netbios", 143: "imap", 161: "snmp",
    162: "snmp-trap", 123: "ntp", 500: "ike",
    389: "ldap", 443: "https", 445: "smb", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
    8080: "http-alt", 8443: "https-alt", 8728: "mikrotik-api",
    8729: "mikrotik-api-ssl", 8291: "winbox",
}

# Cache per configurazione porte
_port_config_cache: Optional[Dict[str, Any]] = None


def load_port_config() -> Dict[str, Any]:
    """
    Carica configurazione porte da file JSON.
    Ritorna configurazione con fallback ai valori hardcoded.
    
    Returns:
        Dict con "tcp_ports" (dict porta->servizio) e "udp_ports" (dict porta->servizio)
    """
    global _port_config_cache
    
    # Usa cache se disponibile
    if _port_config_cache is not None:
        return _port_config_cache
    
    config_path = Path(__file__).parent.parent.parent / "config" / "scan_ports.json"
    
    try:
        if config_path.exists():
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Converti chiavi stringhe in int
            tcp_ports = {int(port): service for port, service in config.get("tcp_ports", {}).items()}
            udp_ports = {int(port): service for port, service in config.get("udp_ports", {}).items()}
            
            _port_config_cache = {
                "tcp_ports": tcp_ports,
                "udp_ports": udp_ports,
                "port_services": {**tcp_ports, **udp_ports}
            }
            
            logger.debug(f"Loaded port config: {len(tcp_ports)} TCP, {len(udp_ports)} UDP ports")
            return _port_config_cache
    except Exception as e:
        logger.warning(f"Error loading port config from {config_path}: {e}, using defaults")
    
    # Fallback ai valori hardcoded
    _port_config_cache = {
        "tcp_ports": {port: _PORT_SERVICES_HARDCODED.get(port, f"port-{port}") for port in _DEFAULT_PORTS_HARDCODED},
        "udp_ports": {port: _PORT_SERVICES_HARDCODED.get(port, f"port-{port}") for port in _DEFAULT_UDP_PORTS_HARDCODED},
        "port_services": _PORT_SERVICES_HARDCODED.copy()
    }
    
    return _port_config_cache


def invalidate_port_config_cache():
    """Invalida cache configurazione porte (chiamata dopo SYNC_CONFIG)"""
    global _port_config_cache
    _port_config_cache = None


def get_default_tcp_ports() -> List[int]:
    """Ottiene lista porte TCP di default dalla configurazione"""
    config = load_port_config()
    return list(config["tcp_ports"].keys())


def get_default_udp_ports() -> List[int]:
    """Ottiene lista porte UDP di default dalla configurazione"""
    config = load_port_config()
    return list(config["udp_ports"].keys())


def get_port_service(port: int) -> str:
    """Ottiene nome servizio per una porta dalla configurazione"""
    config = load_port_config()
    return config["port_services"].get(port, f"port-{port}")


# Alias per compatibilità
DEFAULT_PORTS = get_default_tcp_ports()
DEFAULT_UDP_PORTS = get_default_udp_ports()
PORT_SERVICES = load_port_config()["port_services"]


async def scan_port(target: str, port: int, timeout: float = 1.0) -> Dict[str, Any]:
    """Scansiona una singola porta TCP"""
    loop = asyncio.get_event_loop()
    
    def check():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((target, port))
            return result == 0
        except:
            return False
        finally:
            sock.close()
    
    try:
        is_open = await loop.run_in_executor(None, check)
        return {
            "port": port,
            "protocol": "tcp",
            "service": get_port_service(port),
            "open": is_open,
        }
    except:
        return {
            "port": port,
            "protocol": "tcp",
            "service": get_port_service(port),
            "open": False,
        }


async def scan_udp_port(target: str, port: int, timeout: float = 2.0, snmp_communities: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Scansiona una singola porta UDP.
    
    Per SNMP (161), invia richieste SNMP GET con diverse community.
    Per DNS (53), invia una query DNS valida.
    Per altre porte, invia un pacchetto generico.
    
    v3.0.0: Nuova funzione per supporto UDP
    v3.1.0: Supporto community SNMP multiple
    """
    loop = asyncio.get_event_loop()
    
    # Community SNMP da provare (in ordine)
    if snmp_communities is None:
        snmp_communities = ["public", "private", "Domarc", "domarc", "DOMARC"]
    
    def build_snmp_packet(community: str) -> bytes:
        """Costruisce pacchetto SNMP GET con community specificata"""
        community_bytes = community.encode('ascii')
        community_len = len(community_bytes)
        
        # Calcola lunghezza totale del pacchetto
        # Header: version(3) + community(2+len) + PDU header + varbind
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
        inner_len = 3 + 2 + community_len + 2 + pdu_len  # version + community + PDU
        packet += bytes([inner_len])
        packet += bytes([0x02, 0x01, 0x00])  # version: 0 (SNMPv1)
        packet += bytes([0x04, community_len]) + community_bytes  # community
        packet += bytes([0xa0, pdu_len]) + pdu_content  # GET-REQUEST
        
        return packet
    
    def check_udp():
        try:
            # Payload specifico per ogni porta
            if port == 161:  # SNMP
                # Prova diverse community
                for community in snmp_communities:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(timeout)
                        payload = build_snmp_packet(community)
                        sock.sendto(payload, (target, port))
                        try:
                            data, addr = sock.recvfrom(1024)
                            if len(data) > 0:
                                logger.debug(f"SNMP port open on {target} with community '{community}'")
                                return True
                        except socket.timeout:
                            pass
                        finally:
                            sock.close()
                    except Exception as e:
                        logger.debug(f"SNMP check with '{community}' failed: {e}")
                return False
            
            # Per altre porte UDP (DNS, NTP, etc.)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            try:
                if port == 53:  # DNS
                    # DNS query per "." (root)
                    payload = bytes([
                        0x00, 0x01,  # Transaction ID
                        0x01, 0x00,  # Flags: Standard query
                        0x00, 0x01,  # Questions: 1
                        0x00, 0x00,  # Answer RRs: 0
                        0x00, 0x00,  # Authority RRs: 0
                        0x00, 0x00,  # Additional RRs: 0
                        0x00,        # Root label (empty)
                        0x00, 0x01,  # Type: A
                        0x00, 0x01,  # Class: IN
                    ])
                elif port == 123:  # NTP
                    # NTP request (mode 3 = client)
                    payload = bytes([
                        0x1b, 0x00, 0x00, 0x00,  # LI, VN, Mode
                        0x00, 0x00, 0x00, 0x00,  # Stratum, Poll, Precision
                        0x00, 0x00, 0x00, 0x00,  # Root Delay
                        0x00, 0x00, 0x00, 0x00,  # Root Dispersion
                        0x00, 0x00, 0x00, 0x00,  # Reference ID
                    ] + [0x00] * 32)  # Reference Timestamp, etc.
                else:
                    # Generic probe
                    payload = b"\x00"
                
                sock.sendto(payload, (target, port))
                
                try:
                    data, addr = sock.recvfrom(1024)
                    return len(data) > 0  # Risposta ricevuta = porta aperta
                except socket.timeout:
                    # Timeout può significare porta filtrata o chiusa
                    return False
                except socket.error:
                    return False
            finally:
                sock.close()
                
        except Exception as e:
            logger.debug(f"UDP scan error on {target}:{port}: {e}")
            return False
    
    try:
        is_open = await loop.run_in_executor(None, check_udp)
        return {
            "port": port,
            "protocol": "udp",
            "service": get_port_service(port),
            "open": is_open,
        }
    except Exception as e:
        logger.debug(f"UDP scan exception on {target}:{port}: {e}")
        return {
            "port": port,
            "protocol": "udp",
            "service": get_port_service(port),
            "open": False,
        }


async def scan(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    include_udp: bool = True,
    snmp_communities: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Scansiona multiple porte TCP e opzionalmente UDP.
    
    Args:
        target: IP o hostname
        ports: Lista porte TCP (default: porte comuni)
        timeout: Timeout per porta in secondi
        include_udp: Se True, scansiona anche porte UDP comuni (v3.0.0)
        snmp_communities: Lista community SNMP da provare (v3.1.0)
    
    Returns:
        Lista di risultati per ogni porta (TCP + UDP)
    """
    if ports is None:
        ports = get_default_tcp_ports()
    
    logger.debug(f"Scanning {len(ports)} TCP ports on {target}")
    
    # Scansiona porte TCP in parallelo
    tcp_tasks = [scan_port(target, port, timeout) for port in ports]
    tcp_results = await asyncio.gather(*tcp_tasks, return_exceptions=True)
    
    # Filtra solo porte aperte TCP
    open_ports = []
    for result in tcp_results:
        if isinstance(result, dict) and result.get("open"):
            open_ports.append(result)
    
    # v3.0.0: Scansiona anche porte UDP
    # v3.1.0: Passa community SNMP del cliente
    # v3.2.0: Porte UDP da configurazione
    if include_udp:
        udp_ports = get_default_udp_ports()
        logger.debug(f"Scanning {len(udp_ports)} UDP ports on {target}")
        udp_tasks = [scan_udp_port(target, port, timeout + 1.0, snmp_communities) for port in udp_ports]
        udp_results = await asyncio.gather(*udp_tasks, return_exceptions=True)
        
        for result in udp_results:
            if isinstance(result, dict) and result.get("open"):
                open_ports.append(result)
    
    tcp_count = len([p for p in open_ports if p.get("protocol") == "tcp"])
    udp_count = len([p for p in open_ports if p.get("protocol") == "udp"])
    logger.info(f"Port scan complete on {target}: {tcp_count} TCP, {udp_count} UDP ports open")
    
    return open_ports


# Alias per compatibilità con handler
def scan_ports(target: str, ports: Optional[List[int]] = None, timeout: float = 1.0, include_udp: bool = True) -> Dict[str, Any]:
    """
    Wrapper sincrono per scan().
    Ritorna dict con open_ports e metadata.
    
    v3.0.0: Aggiunto supporto UDP (include_udp=True di default)
    """
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Siamo già in un loop asincrono, usa thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, scan(target, ports, timeout, include_udp))
                open_ports = future.result()
        else:
            open_ports = loop.run_until_complete(scan(target, ports, timeout, include_udp))
    except RuntimeError:
        open_ports = asyncio.run(scan(target, ports, timeout, include_udp))
    
    tcp_count = len([p for p in open_ports if p.get("protocol") == "tcp"])
    udp_count = len([p for p in open_ports if p.get("protocol") == "udp"])
    
    return {
        "target": target,
        "open_ports": open_ports,
        "total_scanned": len(ports or get_default_tcp_ports()) + (len(get_default_udp_ports()) if include_udp else 0),
        "open_count": len(open_ports),
        "tcp_open": tcp_count,
        "udp_open": udp_count,
    }

