"""
DaDude Agent - Port Scanner
Scansione porte TCP/UDP
v3.0.0: Aggiunto supporto UDP per SNMP e DNS
"""
import asyncio
import socket
from typing import List, Dict, Any, Optional
from loguru import logger


# Porte di default da scansionare (TCP)
DEFAULT_PORTS = [
    22, 23, 25, 53, 80, 110, 135, 139, 143, 161, 389, 443, 445,
    636, 993, 995, 1433, 3306, 3389, 5432, 5900, 5985, 5986,
    8080, 8443, 8728, 8729, 8291,
]

# Porte UDP da scansionare sempre
DEFAULT_UDP_PORTS = [
    53,    # DNS
    161,   # SNMP
    162,   # SNMP Trap
    123,   # NTP
    500,   # IKE (VPN)
]

# Mappa porte -> servizi
PORT_SERVICES = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "wmi", 139: "netbios", 143: "imap", 161: "snmp",
    162: "snmp-trap", 123: "ntp", 500: "ike",
    389: "ldap", 443: "https", 445: "smb", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp",
    5432: "postgresql", 5900: "vnc", 5985: "winrm", 5986: "winrm-ssl",
    8080: "http-alt", 8443: "https-alt", 8728: "mikrotik-api",
    8729: "mikrotik-api-ssl", 8291: "winbox",
}


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
            "service": PORT_SERVICES.get(port, f"port-{port}"),
            "open": is_open,
        }
    except:
        return {
            "port": port,
            "protocol": "tcp",
            "service": PORT_SERVICES.get(port, f"port-{port}"),
            "open": False,
        }


async def scan_udp_port(target: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """
    Scansiona una singola porta UDP.
    
    Per SNMP (161), invia una richiesta SNMP GET valida.
    Per DNS (53), invia una query DNS valida.
    Per altre porte, invia un pacchetto generico.
    
    v3.0.0: Nuova funzione per supporto UDP
    """
    loop = asyncio.get_event_loop()
    
    def check_udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        try:
            # Payload specifico per ogni porta
            if port == 161:  # SNMP
                # SNMP GET request per sysDescr.0 (community: public)
                # Struttura ASN.1/BER semplificata per SNMPv1 GET
                payload = bytes([
                    0x30, 0x26,  # SEQUENCE
                    0x02, 0x01, 0x00,  # version: 0 (v1)
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: "public"
                    0xa0, 0x19,  # GET-REQUEST
                    0x02, 0x04, 0x00, 0x00, 0x00, 0x01,  # request-id: 1
                    0x02, 0x01, 0x00,  # error-status: 0
                    0x02, 0x01, 0x00,  # error-index: 0
                    0x30, 0x0b,  # varbind list
                    0x30, 0x09,  # varbind
                    0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID: 1.3.6.1.2.1 (sysDescr.0)
                    0x05, 0x00,  # NULL value
                ])
            elif port == 53:  # DNS
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
                # Per UDP non c'è modo certo di sapere se chiusa
                return False
            except socket.error:
                return False
                
        except Exception as e:
            logger.debug(f"UDP scan error on {target}:{port}: {e}")
            return False
        finally:
            sock.close()
    
    try:
        is_open = await loop.run_in_executor(None, check_udp)
        return {
            "port": port,
            "protocol": "udp",
            "service": PORT_SERVICES.get(port, f"port-{port}"),
            "open": is_open,
        }
    except Exception as e:
        logger.debug(f"UDP scan exception on {target}:{port}: {e}")
        return {
            "port": port,
            "protocol": "udp",
            "service": PORT_SERVICES.get(port, f"port-{port}"),
            "open": False,
        }


async def scan(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 1.0,
    include_udp: bool = True,
) -> List[Dict[str, Any]]:
    """
    Scansiona multiple porte TCP e opzionalmente UDP.
    
    Args:
        target: IP o hostname
        ports: Lista porte TCP (default: porte comuni)
        timeout: Timeout per porta in secondi
        include_udp: Se True, scansiona anche porte UDP comuni (v3.0.0)
    
    Returns:
        Lista di risultati per ogni porta (TCP + UDP)
    """
    if ports is None:
        ports = DEFAULT_PORTS
    
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
    if include_udp:
        logger.debug(f"Scanning {len(DEFAULT_UDP_PORTS)} UDP ports on {target}")
        udp_tasks = [scan_udp_port(target, port, timeout + 1.0) for port in DEFAULT_UDP_PORTS]
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
        "total_scanned": len(ports or DEFAULT_PORTS) + (len(DEFAULT_UDP_PORTS) if include_udp else 0),
        "open_count": len(open_ports),
        "tcp_open": tcp_count,
        "udp_open": udp_count,
    }

