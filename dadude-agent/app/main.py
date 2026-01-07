"""
DaDude Agent - Network Scanning Agent
Esegue scansioni WMI, SSH, SNMP dalla rete locale del cliente
"""
import os
import sys
import json
import asyncio
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger
import uvicorn

from .probes import wmi_probe, ssh_probe, snmp_probe
from .scanners import port_scanner, dns_resolver
from .config import get_settings, Settings


# ==========================================
# VERSION
# ==========================================
AGENT_VERSION = "2.7.4"  # Supporto pysnmp v7.x con API asincrona


# ==========================================
# SCHEMAS
# ==========================================

class WMIProbeRequest(BaseModel):
    target: str
    username: str
    password: str
    domain: Optional[str] = ""


class SSHProbeRequest(BaseModel):
    target: str
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    port: int = 22


class SNMPProbeRequest(BaseModel):
    target: str
    community: str = "public"
    version: str = "2c"
    port: int = 161


class UnifiedProbeRequest(BaseModel):
    """Richiesta scan multi-protocollo unificato"""
    target: str
    protocols: Optional[List[str]] = None  # None o ["auto"] per auto-detection
    # SSH
    ssh_user: Optional[str] = None
    ssh_password: Optional[str] = None
    ssh_key: Optional[str] = None
    ssh_port: int = 22
    # WinRM
    winrm_user: Optional[str] = None
    winrm_password: Optional[str] = None
    winrm_domain: str = ""
    winrm_port: int = 5985
    winrm_ssl: bool = False
    # SNMP
    snmp_community: str = "public"
    snmp_port: int = 161
    snmp_version: int = 2
    # Common
    timeout: int = 30


class PortScanRequest(BaseModel):
    target: str
    ports: Optional[List[int]] = None  # None = default ports
    timeout: float = 1.0


class DNSReverseRequest(BaseModel):
    targets: List[str]
    dns_server: Optional[str] = None


class NetworkScanRequest(BaseModel):
    """Richiesta scansione rete"""
    network: str  # CIDR notation, es: 192.168.1.0/24
    scan_type: str = "ping"  # ping, arp, all
    timeout: float = 1.0


class BatchProbeRequest(BaseModel):
    """Richiesta batch dal server centrale"""
    task_id: str
    targets: List[Dict[str, Any]]
    credentials: Dict[str, Any]
    options: Optional[Dict[str, Any]] = None


class ProbeResult(BaseModel):
    success: bool
    target: str
    protocol: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    duration_ms: Optional[int] = None


# ==========================================
# APP SETUP
# ==========================================

app = FastAPI(
    title="DaDude Agent",
    description="Network scanning agent for DaDude inventory system",
    version=AGENT_VERSION,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# AUTHENTICATION
# ==========================================

async def verify_token(authorization: str = Header(None)) -> bool:
    """Verifica token di autenticazione"""
    settings = get_settings()
    
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    # Formato: "Bearer <token>"
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    
    token = authorization[7:]
    
    if token != settings.agent_token:
        raise HTTPException(status_code=403, detail="Invalid token")
    
    return True


# ==========================================
# HEALTH ENDPOINTS
# ==========================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    settings = get_settings()
    return {
        "status": "healthy",
        "agent_id": settings.agent_id,
        "agent_name": settings.agent_name,
        "version": AGENT_VERSION,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/info")
async def agent_info(authorized: bool = Depends(verify_token)):
    """Informazioni dettagliate sull'agent"""
    settings = get_settings()
    return {
        "agent_id": settings.agent_id,
        "agent_name": settings.agent_name,
        "server_url": settings.server_url,
        "dns_servers": settings.dns_servers,
        "capabilities": ["wmi", "ssh", "snmp", "port_scan", "dns_reverse"],
    }


# ==========================================
# PROBE ENDPOINTS
# ==========================================

@app.post("/probe/wmi", response_model=ProbeResult)
async def probe_wmi(
    request: WMIProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue probe WMI su un target Windows.
    Raccoglie: OS, hostname, CPU, RAM, disco, seriale.
    """
    start_time = datetime.now()
    
    try:
        result = await wmi_probe.probe(
            target=request.target,
            username=request.username,
            password=request.password,
            domain=request.domain or "",
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return ProbeResult(
            success=True,
            target=request.target,
            protocol="wmi",
            data=result,
            duration_ms=duration,
        )
        
    except Exception as e:
        logger.error(f"WMI probe failed for {request.target}: {e}")
        return ProbeResult(
            success=False,
            target=request.target,
            protocol="wmi",
            error=str(e),
        )


@app.post("/probe/ssh", response_model=ProbeResult)
async def probe_ssh(
    request: SSHProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue probe SSH su un target Linux/Unix.
    Raccoglie: hostname, OS, kernel, CPU, RAM, disco.
    """
    start_time = datetime.now()
    
    try:
        result = await ssh_probe.probe(
            target=request.target,
            username=request.username,
            password=request.password,
            private_key=request.private_key,
            port=request.port,
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return ProbeResult(
            success=True,
            target=request.target,
            protocol="ssh",
            data=result,
            duration_ms=duration,
        )
        
    except Exception as e:
        logger.error(f"SSH probe failed for {request.target}: {e}")
        return ProbeResult(
            success=False,
            target=request.target,
            protocol="ssh",
            error=str(e),
        )


@app.post("/probe/ssh-advanced", response_model=ProbeResult)
async def probe_ssh_advanced(
    request: SSHProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue scansione SSH avanzata su un target Linux/Storage/Hypervisor.
    Raccoglie informazioni complete: sistema, CPU, memoria, storage, RAID, rete, servizi, Docker, VM.
    Supporta comandi con sudo quando necessario.
    """
    start_time = datetime.now()
    
    try:
        from app.probes.ssh_advanced_scanner import scan_advanced
        
        result = await scan_advanced(
            target=request.target,
            username=request.username,
            password=request.password,
            private_key=request.private_key,
            port=request.port,
            timeout=30,
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return ProbeResult(
            success=True,
            target=request.target,
            protocol="ssh-advanced",
            data=result,
            duration_ms=duration,
        )
        
    except Exception as e:
        logger.error(f"SSH advanced scan failed for {request.target}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return ProbeResult(
            success=False,
            target=request.target,
            protocol="ssh-advanced",
            error=str(e),
        )


@app.post("/probe/unified", response_model=ProbeResult)
async def probe_unified(
    request: UnifiedProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue scan multi-protocollo unificato su un target.
    Supporta SSH, SNMP, WinRM e altri protocolli.
    Combina risultati da tutti i protocolli disponibili.
    """
    from datetime import datetime
    from .probes.unified_scanner_service import UnifiedScannerService
    
    start_time = datetime.now()
    
    try:
        service = UnifiedScannerService(verbose=True)  # Abilita verbose per debug SNMP/SSH
        
        result = await service.scan_multi_protocol(
            target=request.target,
            protocols=request.protocols,
            ssh_user=request.ssh_user,
            ssh_password=request.ssh_password,
            ssh_key=request.ssh_key,
            ssh_port=request.ssh_port,
            winrm_user=request.winrm_user,
            winrm_password=request.winrm_password,
            winrm_domain=request.winrm_domain,
            winrm_port=request.winrm_port,
            winrm_ssl=request.winrm_ssl,
            snmp_community=request.snmp_community,
            snmp_port=request.snmp_port,
            snmp_version=request.snmp_version,
            timeout=request.timeout,
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        if result.get("success"):
            return ProbeResult(
                success=True,
                target=request.target,
                protocol="unified",
                data=result.get("data", {}),
                duration_ms=duration,
            )
        else:
            return ProbeResult(
                success=False,
                target=request.target,
                protocol="unified",
                error=result.get("error", "Unified probe failed"),
                duration_ms=duration,
            )
            
    except Exception as e:
        logger.error(f"Unified probe failed for {request.target}: {e}", exc_info=True)
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        return ProbeResult(
            success=False,
            target=request.target,
            protocol="unified",
            error=str(e),
            duration_ms=duration,
        )


@app.post("/probe/snmp", response_model=ProbeResult)
async def probe_snmp(
    request: SNMPProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue probe SNMP su un target.
    Raccoglie: sysDescr, sysName, vendor, model, seriale.
    """
    start_time = datetime.now()
    
    try:
        result = await snmp_probe.probe(
            target=request.target,
            community=request.community,
            version=request.version,
            port=request.port,
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return ProbeResult(
            success=True,
            target=request.target,
            protocol="snmp",
            data=result,
            duration_ms=duration,
        )
        
    except Exception as e:
        logger.error(f"SNMP probe failed for {request.target}: {e}")
        return ProbeResult(
            success=False,
            target=request.target,
            protocol="snmp",
            error=str(e),
        )


# ==========================================
# SCANNER ENDPOINTS
# ==========================================

@app.post("/scan/ports")
async def scan_ports(
    request: PortScanRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Scansiona porte TCP su un target.
    """
    start_time = datetime.now()
    
    try:
        result = await port_scanner.scan(
            target=request.target,
            ports=request.ports,
            timeout=request.timeout,
        )
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return {
            "success": True,
            "target": request.target,
            "open_ports": result,
            "duration_ms": duration,
        }
        
    except Exception as e:
        logger.error(f"Port scan failed for {request.target}: {e}")
        return {
            "success": False,
            "target": request.target,
            "error": str(e),
        }


@app.post("/scan/network")
async def scan_network(
    request: NetworkScanRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Scansiona una rete per trovare host attivi usando nmap.
    Nmap è molto più veloce e affidabile, ottiene anche MAC address via ARP.
    """
    import asyncio
    import re
    import xml.etree.ElementTree as ET
    
    start_time = datetime.now()
    
    try:
        logger.info(f"[NMAP] Scanning network {request.network}")
        
        # Usa nmap con:
        # -sn: Ping scan (no port scan per velocità)
        # -PR: ARP ping (ottiene MAC address)
        # -oX -: Output XML a stdout
        # --min-rate 500: Velocità minima pacchetti
        # -T4: Timing aggressivo
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sn", "-PR", "-oX", "-", 
            "--min-rate", "300", "-T4",
            request.network,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        
        if proc.returncode != 0:
            error_msg = stderr.decode().strip() if stderr else "Unknown nmap error"
            logger.error(f"[NMAP] Failed: {error_msg}")
            return {
                "success": False,
                "network": request.network,
                "error": f"nmap failed: {error_msg}",
            }
        
        # Parse XML output
        results = []
        try:
            root = ET.fromstring(stdout.decode())
            
            for host in root.findall('.//host'):
                status = host.find('status')
                if status is not None and status.get('state') == 'up':
                    device = {"alive": True, "open_ports": []}
                    
                    # IP address
                    for addr in host.findall('address'):
                        if addr.get('addrtype') == 'ipv4':
                            device['address'] = addr.get('addr')
                        elif addr.get('addrtype') == 'mac':
                            device['mac_address'] = addr.get('addr', '').upper()
                            # Vendor from nmap
                            vendor = addr.get('vendor')
                            if vendor:
                                device['vendor'] = vendor
                    
                    # Hostname
                    hostnames = host.find('hostnames')
                    if hostnames is not None:
                        hostname_elem = hostnames.find('hostname')
                        if hostname_elem is not None:
                            device['hostname'] = hostname_elem.get('name')
                    
                    if device.get('address'):
                        results.append(device)
                        
        except ET.ParseError as e:
            logger.error(f"[NMAP] XML parse error: {e}")
            # Fallback: parse text output
            output = stdout.decode()
            for line in output.split('\n'):
                if 'Nmap scan report for' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        results.append({
                            "address": ip_match.group(1),
                            "alive": True,
                            "mac_address": None,
                            "open_ports": []
                        })
        
        duration = int((datetime.now() - start_time).total_seconds() * 1000)
        
        logger.info(f"[NMAP] Scan completed: {len(results)} hosts found in {duration}ms")
        
        return {
            "success": True,
            "network": request.network,
            "scan_type": "nmap",
            "devices_found": len(results),
            "results": results,
            "duration_ms": duration,
        }
        
    except asyncio.TimeoutError:
        logger.error(f"[NMAP] Timeout scanning {request.network}")
        return {
            "success": False,
            "network": request.network,
            "error": "Scan timeout (120s)",
        }
    except Exception as e:
        logger.error(f"[NMAP] Network scan failed: {e}")
        return {
            "success": False,
            "network": request.network,
            "error": str(e),
        }


@app.post("/dns/reverse")
async def dns_reverse(
    request: DNSReverseRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue reverse DNS lookup per una lista di IP.
    """
    settings = get_settings()
    dns_server = request.dns_server or (settings.dns_servers[0] if settings.dns_servers else None)
    
    try:
        results = await dns_resolver.batch_reverse_lookup(
            targets=request.targets,
            dns_server=dns_server,
        )
        
        return {
            "success": True,
            "results": results,
            "dns_server": dns_server,
        }
        
    except Exception as e:
        logger.error(f"DNS reverse lookup failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


# ==========================================
# BATCH OPERATIONS
# ==========================================

@app.post("/batch/probe")
async def batch_probe(
    request: BatchProbeRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Esegue probe batch su più target.
    Usato dal server centrale per scansioni massive.
    """
    results = []
    
    for target_info in request.targets:
        target = target_info.get("address")
        probe_type = target_info.get("probe_type", "auto")
        
        if probe_type == "wmi":
            result = await probe_wmi(WMIProbeRequest(
                target=target,
                username=request.credentials.get("username", ""),
                password=request.credentials.get("password", ""),
                domain=request.credentials.get("domain", ""),
            ), authorized=True)
        elif probe_type == "ssh":
            result = await probe_ssh(SSHProbeRequest(
                target=target,
                username=request.credentials.get("username", ""),
                password=request.credentials.get("password"),
                port=request.credentials.get("port", 22),
            ), authorized=True)
        elif probe_type == "snmp":
            result = await probe_snmp(SNMPProbeRequest(
                target=target,
                community=request.credentials.get("community", "public"),
                version=request.credentials.get("version", "2c"),
            ), authorized=True)
        else:
            # Auto-detect: prova in base alle porte
            result = ProbeResult(
                success=False,
                target=target,
                protocol="unknown",
                error="Probe type not specified",
            )
        
        results.append(result.dict())
    
    return {
        "task_id": request.task_id,
        "total": len(request.targets),
        "success": sum(1 for r in results if r.get("success")),
        "results": results,
    }


# ==========================================
# AUTO-REGISTRATION & HEARTBEAT
# ==========================================

import socket
import platform
import httpx

async def get_local_ip() -> str:
    """Rileva l'IP locale dell'agent"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


async def register_with_server():
    """Registra l'agent con il server centrale"""
    settings = get_settings()
    
    if not settings.server_url:
        logger.warning("No server URL configured, skipping registration")
        return
    
    try:
        local_ip = await get_local_ip()
        hostname = socket.gethostname()
        
        registration_data = {
            "agent_id": settings.agent_id,
            "agent_name": settings.agent_name,
            "agent_type": "docker",
            "version": AGENT_VERSION,
            "detected_ip": local_ip,
            "detected_hostname": hostname,
            "capabilities": ["wmi", "ssh", "snmp", "port_scan", "dns_reverse", "nmap"],
            "os_info": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
        }
        
        async with httpx.AsyncClient(timeout=30, verify=False) as client:
            response = await client.post(
                f"{settings.server_url}/api/v1/agents/register",
                json=registration_data,
                headers={"Authorization": f"Bearer {settings.agent_token}"}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("registered"):
                    logger.success(f"Agent registered successfully! Token: {result.get('agent_token', 'N/A')}")
                    # Salva il nuovo token se fornito
                    if result.get("agent_token"):
                        logger.info("Save this token in your agent configuration!")
                elif result.get("updated"):
                    logger.info("Agent info updated on server")
            else:
                logger.warning(f"Registration failed: {response.status_code} - {response.text}")
                
    except Exception as e:
        logger.warning(f"Could not register with server: {e}")


async def send_heartbeat():
    """Invia heartbeat periodico al server"""
    settings = get_settings()
    
    if not settings.server_url:
        return
    
    try:
        local_ip = await get_local_ip()
        
        heartbeat_data = {
            "agent_id": settings.agent_id,
            "status": "online",
            "version": AGENT_VERSION,
            "detected_ip": local_ip,
        }
        
        async with httpx.AsyncClient(timeout=10, verify=False) as client:
            response = await client.post(
                f"{settings.server_url}/api/v1/agents/heartbeat",
                json=heartbeat_data,
                headers={"Authorization": f"Bearer {settings.agent_token}"}
            )
            
            if response.status_code == 200:
                result = response.json()
                if result.get("action") == "register":
                    logger.info("Server requested re-registration")
                    await register_with_server()
                    
    except Exception as e:
        logger.debug(f"Heartbeat failed: {e}")


async def heartbeat_loop():
    """Loop di heartbeat"""
    settings = get_settings()
    
    # Prima registrazione
    await register_with_server()
    
    # Heartbeat ogni 60 secondi
    while True:
        await asyncio.sleep(settings.poll_interval)
        await send_heartbeat()


@app.on_event("startup")
async def startup_event():
    """Avvio dell'agent"""
    settings = get_settings()
    logger.info(f"Agent {settings.agent_id} starting...")
    
    # Avvia heartbeat in background
    asyncio.create_task(heartbeat_loop())


# ==========================================
# ADMIN ENDPOINTS (UPDATE/RESTART)
# ==========================================

class UpdateRequest(BaseModel):
    version: str
    download_url: Optional[str] = None
    force: bool = False


@app.post("/admin/update")
async def trigger_update(
    request: UpdateRequest,
    authorized: bool = Depends(verify_token)
):
    """
    Riceve comando di aggiornamento dal server.
    Esegue l'update scaricando il codice da GitHub e ricostruendo il container.
    Richiede che il socket Docker sia montato nel container.
    """
    import subprocess
    
    current_version = AGENT_VERSION
    
    logger.info(f"Update requested: {current_version} -> {request.version}")
    
    if not request.force and request.version == current_version:
        return {
            "success": False,
            "message": "Already at the latest version",
            "current_version": current_version,
        }
    
    try:
        # Verifica se possiamo accedere a Docker
        docker_available = os.path.exists("/var/run/docker.sock")
        agent_dir = "/opt/dadude-agent"
        agent_dir_available = os.path.exists(agent_dir)
        
        logger.info(f"Docker socket available: {docker_available}, Agent dir available: {agent_dir_available}")
        
        if not docker_available or not agent_dir_available:
            # Fallback: segnala che l'update deve essere fatto manualmente
            return {
                "success": False,
                "message": "Auto-update not available. Docker socket or agent directory not mounted.",
                "current_version": current_version,
                "manual_update_required": True,
                "update_command": f"cd {agent_dir} && git pull && docker compose build --no-cache && docker compose up -d"
            }
        
        # Esegue l'update in background
        async def do_update():
            await asyncio.sleep(2)  # Attendi che la risposta sia inviata
            
            try:
                logger.info("Starting auto-update process...")
                
                # 1. Scarica nuova versione
                temp_dir = "/tmp/dadude-update"
                subprocess.run(["rm", "-rf", temp_dir], check=False)
                
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", "https://github.com/grandir66/dadude.git", temp_dir],
                    capture_output=True, text=True, timeout=60
                )
                
                if result.returncode != 0:
                    logger.error(f"Git clone failed: {result.stderr}")
                    return
                
                logger.info("Git clone successful")
                
                # 2. Copia nuovi file
                src_dir = f"{temp_dir}/dadude-agent"
                for item in ["app", "Dockerfile", "requirements.txt", "docker-compose.yml", "update.sh"]:
                    src = f"{src_dir}/{item}"
                    dst = f"{agent_dir}/{item}"
                    if os.path.exists(src):
                        if os.path.isdir(src):
                            subprocess.run(["rm", "-rf", dst], check=False)
                            subprocess.run(["cp", "-r", src, dst], check=True)
                        else:
                            subprocess.run(["cp", src, dst], check=True)
                
                logger.info("Files copied successfully")
                
                # 3. Cleanup
                subprocess.run(["rm", "-rf", temp_dir], check=False)
                
                # 4. Rebuild e restart container
                logger.info("Rebuilding container...")
                os.chdir(agent_dir)
                
                # Usa docker-compose per rebuild
                result = subprocess.run(
                    ["docker-compose", "build", "--no-cache"],
                    capture_output=True, text=True, timeout=300, cwd=agent_dir
                )
                
                if result.returncode != 0:
                    logger.error(f"Docker build failed: {result.stderr}")
                    # Prova con docker compose (senza trattino)
                    result = subprocess.run(
                        ["docker", "compose", "build", "--no-cache"],
                        capture_output=True, text=True, timeout=300, cwd=agent_dir
                    )
                
                logger.info("Build completed, restarting...")
                
                # 5. Restart (questo terminerà il container corrente)
                subprocess.Popen(
                    ["docker", "compose", "up", "-d", "--force-recreate"],
                    cwd=agent_dir, start_new_session=True
                )
                
            except Exception as e:
                logger.error(f"Auto-update failed: {e}")
        
        # Avvia update in background
        asyncio.create_task(do_update())
        
        return {
            "success": True,
            "message": f"Update to {request.version} started. Agent will restart automatically.",
            "current_version": current_version,
            "target_version": request.version,
        }
        
    except Exception as e:
        logger.error(f"Update trigger failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@app.post("/admin/restart")
async def trigger_restart(authorized: bool = Depends(verify_token)):
    """
    Riavvia l'agent.
    """
    logger.info("Restart requested")
    
    # Programma riavvio dopo 2 secondi
    asyncio.create_task(_delayed_restart(2))
    
    return {
        "success": True,
        "message": "Agent will restart in 2 seconds",
    }


@app.get("/admin/status")
async def admin_status(authorized: bool = Depends(verify_token)):
    """
    Stato dettagliato dell'agent per amministrazione.
    """
    settings = get_settings()
    local_ip = await get_local_ip()
    
    # Controlla se c'è un aggiornamento pendente
    update_pending = False
    update_info = None
    try:
        if os.path.exists("/tmp/dadude-agent-update.json"):
            with open("/tmp/dadude-agent-update.json") as f:
                update_info = json.load(f)
                update_pending = True
    except:
        pass
    
    return {
        "agent_id": settings.agent_id,
        "agent_name": settings.agent_name,
        "version": AGENT_VERSION,
        "detected_ip": local_ip,
        "hostname": socket.gethostname(),
        "server_url": settings.server_url,
        "uptime": _get_uptime(),
        "update_pending": update_pending,
        "update_info": update_info,
        "python_version": platform.python_version(),
        "os_info": f"{platform.system()} {platform.release()}",
    }


async def _delayed_restart(delay_seconds: int):
    """Riavvia l'agent dopo un delay"""
    await asyncio.sleep(delay_seconds)
    logger.warning(f"Restarting agent...")
    
    # Chiudi tutte le connessioni e task in corso prima di riavviare
    try:
        # Annulla tutti i task in corso
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        
        # Attendi che i task vengano cancellati (con timeout)
        if tasks:
            await asyncio.wait(tasks, timeout=5.0)
        
        logger.info("All tasks cancelled, restarting...")
    except Exception as e:
        logger.warning(f"Error during graceful shutdown: {e}")
    
    # In Docker, usciamo con codice 0 per trigger restart policy
    # Il container Docker si riavvierà automaticamente
    # Usa os._exit invece di sys.exit per evitare problemi con cleanup
    os._exit(0)


def _get_uptime() -> str:
    """Calcola uptime del processo"""
    try:
        import time
        # Questo è approssimativo, in produzione useresti psutil
        return "running"
    except:
        return "unknown"


# ==========================================
# MAIN
# ==========================================

def main():
    """Entry point"""
    settings = get_settings()
    
    # Setup logging
    logger.remove()
    logger.add(
        sys.stderr,
        level=settings.log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    )
    
    logger.info(f"Starting DaDude Agent {settings.agent_id}")
    logger.info(f"Server URL: {settings.server_url}")
    logger.info(f"API Port: {settings.api_port}")
    
    # Run server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=settings.api_port,
        log_level="warning",
    )


if __name__ == "__main__":
    main()

