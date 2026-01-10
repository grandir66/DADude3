"""
DaDude - Agents Router
API endpoints per registrazione e gestione dinamica degli agent
"""
import asyncio
import os
import re
import subprocess
from fastapi import APIRouter, HTTPException, Query, Header, Request
from typing import Optional, List
from pydantic import BaseModel
from datetime import datetime
from loguru import logger

from ..services.customer_service import get_customer_service
from ..services.encryption_service import get_encryption_service
from ..config import VERSION

router = APIRouter(prefix="/agents", tags=["Agents"])


# ==========================================
# SCHEMAS
# ==========================================

class AgentRegistration(BaseModel):
    """Schema per auto-registrazione agent"""
    agent_id: str  # ID univoco dell'agent
    agent_name: str
    agent_type: str = "docker"  # docker, mikrotik
    version: str = "1.0.0"
    
    # Token generato dall'agent durante l'installazione
    agent_token: Optional[str] = None
    
    # Info rete rilevate dall'agent
    detected_ip: Optional[str] = None
    detected_hostname: Optional[str] = None
    
    # Capacità
    capabilities: Optional[List[str]] = None  # ["ssh", "snmp", "wmi", "nmap", "dns"]
    
    # Info sistema
    os_info: Optional[str] = None
    python_version: Optional[str] = None


class AgentHeartbeat(BaseModel):
    """Schema per heartbeat agent"""
    agent_id: str
    status: str = "online"
    version: Optional[str] = None
    detected_ip: Optional[str] = None
    uptime_seconds: Optional[int] = None
    last_scan_count: Optional[int] = None  # Numero scan eseguiti dall'ultimo heartbeat


class AgentConfigResponse(BaseModel):
    """Configurazione inviata dal server all'agent"""
    agent_id: str
    agent_name: str
    
    # Configurazione polling
    poll_interval: int = 60  # Secondi tra un poll e l'altro
    
    # DNS da usare per scansioni
    dns_servers: List[str] = ["8.8.8.8", "1.1.1.1"]
    
    # Range di porte da scansionare
    default_ports: List[int] = [22, 23, 80, 443, 161, 445, 3389, 8728]
    
    # Credenziali (opzionale, per scan automatici)
    # Non inviamo password in chiaro, solo riferimento
    credential_ids: List[str] = []
    
    # Reti assegnate all'agent
    assigned_networks: List[dict] = []
    
    # Ultimo aggiornamento config
    config_version: int = 1
    updated_at: Optional[str] = None


class AgentUpdateRequest(BaseModel):
    """Richiesta di aggiornamento configurazione agent dal server"""
    name: Optional[str] = None
    address: Optional[str] = None
    dns_servers: Optional[List[str]] = None
    poll_interval: Optional[int] = None
    assigned_networks: Optional[List[str]] = None
    active: Optional[bool] = None


# ==========================================
# AGENT SELF-SERVICE ENDPOINTS
# ==========================================

@router.post("/register")
async def register_agent(
    data: AgentRegistration,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Auto-registrazione di un nuovo agent.
    
    L'agent chiama questo endpoint al primo avvio per registrarsi.
    Il server crea un record temporaneo che deve essere approvato
    da un amministratore e associato a un cliente.
    """
    service = get_customer_service()
    encryption = get_encryption_service()
    
    # Estrai IP reale dalla request se non fornito
    client_ip = data.detected_ip
    if not client_ip:
        client_ip = request.client.host if request.client else None
    
    logger.info(f"Agent registration request: {data.agent_id} from {client_ip}")
    
    # Verifica se agent già esiste (per ID, nome o indirizzo)
    try:
        logger.debug(f"Looking up existing agent: agent_id={data.agent_id}, address={client_ip}")
        existing = service.get_agent_by_unique_id(data.agent_id, address=client_ip)
        if existing:
            # Aggiorna info esistente
            logger.info(f"Agent {data.agent_id} already registered (DB ID: {existing.id}), updating info")
            
            # Aggiorna IP e status
            service.update_agent_status(
                existing.id, 
                status="online",
                version=data.version
            )
            
            # Se IP cambiato, aggiornalo
            if client_ip and client_ip != existing.address:
                logger.info(f"Agent {data.agent_id} IP changed: {existing.address} -> {client_ip}")
                service.update_agent_address(existing.id, client_ip)
            
            return {
                "success": True,
                "registered": False,
                "updated": True,
                "agent_db_id": existing.id,
                "message": "Agent info updated"
            }
        else:
            logger.info(f"Agent {data.agent_id} not found in database, will create new record")
            
            # Fix: cerca anche per nome e aggiorna dude_agent_id se mancante
            try:
                from ..models.database import AgentAssignmentDB, init_db, get_session
                from ..config import get_settings
                settings = get_settings()
                db_url = settings.database_url
                engine = init_db(db_url)
                fix_session = get_session(engine)
                
                # Cerca agent con stesso nome ma senza dude_agent_id
                fix_agent = fix_session.query(AgentAssignmentDB).filter(
                    AgentAssignmentDB.name == data.agent_name,
                    (AgentAssignmentDB.dude_agent_id == None) | (AgentAssignmentDB.dude_agent_id == "")
                ).first()
                
                if fix_agent:
                    logger.info(f"Found existing agent {fix_agent.id} with name '{data.agent_name}' but missing dude_agent_id, updating...")
                    fix_agent.dude_agent_id = data.agent_id
                    fix_session.commit()
                    fix_session.close()
                    
                    # Ricarica usando il servizio
                    existing = service.get_agent_by_unique_id(data.agent_id, address=client_ip)
                    if existing:
                        logger.info(f"Agent {data.agent_id} found after fix, updating info")
                        service.update_agent_status(existing.id, status="online", version=data.version)
                        if client_ip and client_ip != existing.address:
                            service.update_agent_address(existing.id, client_ip)
                        return {
                            "success": True,
                            "registered": False,
                            "updated": True,
                            "agent_db_id": existing.id,
                            "message": "Agent info updated (fixed missing dude_agent_id)"
                        }
                else:
                    fix_session.close()
            except Exception as fix_error:
                logger.debug(f"Fix attempt failed: {fix_error}")
                
    except Exception as e:
        logger.warning(f"Error looking up agent {data.agent_id}: {e}, will create new record")
    
    # Crea nuovo agent
    try:
        from ..models.database import AgentAssignment, generate_uuid, init_db, get_session
        from ..config import get_settings
        import os
        
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        # Usa token dall'agent se fornito, altrimenti genera uno nuovo
        import secrets
        if data.agent_token:
            agent_token = data.agent_token
            logger.info(f"Using token provided by agent {data.agent_id}")
        else:
            agent_token = secrets.token_urlsafe(32)
            logger.info(f"Generated new token for agent {data.agent_id}")
        
        # Auto-approvazione: se DADUDE_DEFAULT_CUSTOMER_ID è impostato, approva automaticamente
        default_customer_id = os.getenv("DADUDE_DEFAULT_CUSTOMER_ID", None)
        # Assicurati che customer_id sia None se vuoto o non valido
        if default_customer_id == '' or default_customer_id is None:
            default_customer_id = None
        auto_approve = default_customer_id is not None
        
        agent = AgentAssignment(
            id=generate_uuid(),
            customer_id=default_customer_id,  # Auto-assegna se configurato, None altrimenti
            dude_agent_id=data.agent_id,  # Salva agent_id per lookup successivi
            name=data.agent_name,
            address=client_ip or "pending",
            port=8080,
            agent_type=data.agent_type,
            agent_api_port=8080,
            agent_token=encryption.encrypt(agent_token),
            agent_url=f"http://{client_ip}:8080" if client_ip else None,
            status="online" if auto_approve else "pending_approval",
            version=data.version,
            active=auto_approve,  # Attivo se auto-approvato
        )
        
        # Salva capabilities come JSON
        if data.capabilities:
            import json
            agent.notes = json.dumps({"capabilities": data.capabilities, "os_info": data.os_info})
        
        session.add(agent)
        session.commit()
        
        if auto_approve:
            logger.success(f"New agent auto-approved: {data.agent_id} ({data.agent_name}) -> customer {default_customer_id}")
            return {
                "success": True,
                "registered": True,
                "approved": True,
                "agent_db_id": agent.id,
                "agent_token": agent_token,
                "customer_id": default_customer_id,
                "message": "Agent registered and auto-approved.",
            }
        else:
            logger.success(f"New agent registered: {data.agent_id} ({data.agent_name}) from {client_ip}")
            return {
                "success": True,
                "registered": True,
                "approved": False,
                "agent_db_id": agent.id,
                "agent_token": agent_token,
                "message": "Agent registered successfully. Awaiting admin approval.",
                "next_steps": [
                    "Save the agent_token securely",
                    "An admin will approve and assign this agent to a customer",
                    "Once approved, the agent will receive its configuration"
                ]
            }
        
    except Exception as e:
        logger.error(f"Failed to register agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/heartbeat")
async def agent_heartbeat(
    data: AgentHeartbeat,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Heartbeat periodico dall'agent.
    Aggiorna lo stato e restituisce eventuali comandi pendenti.
    """
    service = get_customer_service()
    
    # Estrai IP dalla request
    client_ip = data.detected_ip or (request.client.host if request.client else None)
    
    try:
        # Trova agent
        agent = service.get_agent_by_unique_id(data.agent_id)
        if not agent:
            return {
                "success": False,
                "error": "Agent not registered",
                "action": "register"  # Dice all'agent di registrarsi
            }
        
        # Aggiorna status
        service.update_agent_status(agent.id, status=data.status, version=data.version)
        
        # Se IP cambiato, aggiornalo
        if client_ip and client_ip != agent.address:
            service.update_agent_address(agent.id, client_ip)
        
        # AUTO-REATTIVAZIONE: Se l'agent era già approvato ma non attivo (dopo restart),
        # riattivalo automaticamente quando invia heartbeat
        if data.status == "online" and not agent.active:
            # Verifica che l'agent sia stato approvato (non pending)
            if agent.status != "pending_approval":
                try:
                    from ..models.database import AgentAssignment as AgentAssignmentDB, init_db, get_session
                    from ..config import get_settings
                    
                    settings = get_settings()
                    db_url = settings.database_url
                    engine = init_db(db_url)
                    session = get_session(engine)
                    
                    try:
                        db_agent = session.query(AgentAssignmentDB).filter(
                            AgentAssignmentDB.id == agent.id
                        ).first()
                        
                        if db_agent:
                            db_agent.active = True
                            db_agent.status = "online"
                            session.commit()
                            logger.info(f"Auto-reactivated agent {agent.id} ({data.agent_id}) after restart")
                    finally:
                        session.close()
                except Exception as e:
                    logger.warning(f"Failed to auto-reactivate agent {agent.id}: {e}")
        
        # Controlla se ci sono comandi pendenti
        # (future: scan requests, config updates, etc.)
        
        return {
            "success": True,
            "agent_db_id": agent.id,
            "active": agent.active,
            "config_changed": False,  # Future: True se config è cambiata
            "commands": []  # Future: comandi da eseguire
        }
        
    except Exception as e:
        logger.error(f"Heartbeat failed for {data.agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config/{agent_id}")
async def get_agent_config(
    agent_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Ottiene la configurazione corrente per un agent.
    L'agent chiama questo endpoint per ottenere/aggiornare la sua config.
    """
    service = get_customer_service()
    
    try:
        agent = service.get_agent_by_unique_id(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        if not agent.active:
            return {
                "success": False,
                "error": "Agent not approved yet",
                "status": "pending_approval"
            }
        
        # Costruisci configurazione
        config = AgentConfigResponse(
            agent_id=agent_id,
            agent_name=agent.name,
            poll_interval=60,  # Default, potrebbe essere configurabile
            dns_servers=agent.dns_server.split(",") if agent.dns_server else ["8.8.8.8"],
            default_ports=[22, 23, 80, 443, 161, 445, 3389, 8728],
            config_version=1,
            updated_at=agent.updated_at.isoformat() if agent.updated_at else None,
        )
        
        # Aggiungi reti assegnate se customer_id presente
        if agent.customer_id:
            networks = service.list_networks(customer_id=agent.customer_id)
            config.assigned_networks = [
                {"id": n.id, "name": n.name, "cidr": n.cidr}
                for n in networks
            ]
        
        return {
            "success": True,
            "config": config.model_dump()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get config for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# ADMIN ENDPOINTS
# ==========================================

@router.get("/pending")
async def list_pending_agents():
    """
    Lista agent in attesa di approvazione.
    Include tutti gli agent non assegnati a un customer O non attivi.
    """
    from ..models.database import AgentAssignment, init_db, get_session
    from sqlalchemy import or_
    from ..config import get_settings
    
    settings = get_settings()
    # PostgreSQL è l'unico database supportato
    engine = init_db(settings.database_url)
    session = get_session(engine)
    
    try:
        # Mostra agent che:
        # - Non hanno customer_id (mai assegnati) - include NULL e stringa vuota
        # - O hanno status pending_approval
        # - O non sono attivi (active=False)
        agents = session.query(AgentAssignment).filter(
            or_(
                AgentAssignment.customer_id == None,
                AgentAssignment.customer_id == "",
                AgentAssignment.status == "pending_approval",
                AgentAssignment.active == False
            )
        ).all()
        
        return {
            "total": len(agents),
            "agents": [
                {
                    "id": a.id,
                    "name": a.name,
                    "address": a.address,
                    "agent_type": a.agent_type,
                    "version": a.version,
                    "status": a.status,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                }
                for a in agents
            ]
        }
    finally:
        session.close()


# ==========================================
# SERVER UPDATE SYSTEM
# (MUST be before routes with path parameters)
# ==========================================

# Versione corrente del server (importata da config.py)
SERVER_VERSION = VERSION
GITHUB_REPO = "grandir66/dadude"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"


@router.get("/server/version")
async def get_server_version():
    """
    Restituisce la versione corrente del server.
    """
    return {
        "version": SERVER_VERSION,
        "agent_version": AGENT_VERSION,
        "repository": f"https://github.com/{GITHUB_REPO}",
    }


@router.get("/server/check-update")
async def check_server_update():
    """
    Controlla se è disponibile una nuova versione del server su GitHub.
    Legge la versione corrente dal file su disco (non dalla memoria) per rilevare aggiornamenti dopo git pull.
    """
    import re
    
    try:
        import httpx
        
        # Leggi versione corrente dal file su disco (non dalla variabile in memoria)
        # Questo permette di rilevare aggiornamenti anche dopo git pull senza riavvio
        current_version_disk = SERVER_VERSION
        version_file_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "app", "routers", "agents.py"
        )
        
        # Se siamo in Docker con repository montato, usa il percorso montato
        if os.path.exists("/app/repo"):
            if os.path.exists("/app/repo/dadude/app/routers/agents.py"):
                version_file_path = "/app/repo/dadude/app/routers/agents.py"
            elif os.path.exists("/app/repo/app/routers/agents.py"):
                version_file_path = "/app/repo/app/routers/agents.py"
        
        try:
            with open(version_file_path, 'r') as f:
                file_content = f.read()
                match = re.search(r'SERVER_VERSION\s*=\s*["\']([^"\']+)["\']', file_content)
                if match:
                    current_version_disk = match.group(1)
        except Exception as e:
            logger.warning(f"Could not read version from disk, using in-memory version: {e}")
        
        async with httpx.AsyncClient(timeout=15) as client:
            # Leggi versione dal file raw su GitHub
            raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dadude/app/routers/agents.py"
            response = await client.get(raw_url)
            
            if response.status_code == 200:
                content = response.text
                
                # Estrai SERVER_VERSION dal file
                match = re.search(r'SERVER_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    latest_version = match.group(1)
                    # Confronta con la versione su disco (non quella in memoria)
                    # needs_update = True se GitHub ha una versione più nuova di quella su disco
                    needs_update = _compare_versions(current_version_disk, latest_version) < 0
                    
                    # Verifica anche se la versione su disco è diversa da quella in memoria
                    # (indica che serve un riavvio dopo git pull)
                    needs_restart = current_version_disk != SERVER_VERSION
                    
                    # Se serve riavvio ma non ci sono aggiornamenti su GitHub, 
                    # mostra comunque che c'è qualcosa da fare (riavvio)
                    if needs_restart and not needs_update:
                        # La versione su disco è più nuova di quella in memoria
                        # ma GitHub è aggiornato, quindi serve solo riavvio
                        pass
                    
                    # Ottieni info ultimo commit
                    commits_resp = await client.get(
                        f"{GITHUB_API}/commits?per_page=1",
                        headers={"Accept": "application/vnd.github.v3+json"}
                    )
                    
                    changelog = ""
                    release_date = None
                    commit_sha = None
                    
                    if commits_resp.status_code == 200:
                        commits = commits_resp.json()
                        if commits:
                            latest_commit = commits[0]
                            changelog = latest_commit.get("commit", {}).get("message", "")[:500]
                            release_date = latest_commit.get("commit", {}).get("author", {}).get("date")
                            commit_sha = latest_commit.get("sha", "")[:8]
                    
                    return {
                        "success": True,
                        "current_version": SERVER_VERSION,  # Versione in memoria (runtime)
                        "current_version_disk": current_version_disk,  # Versione su disco
                        "latest_version": latest_version,
                        "needs_update": needs_update,
                        "needs_restart": needs_restart,  # Indica se serve riavvio dopo git pull
                        "release_name": f"v{latest_version}" if needs_update else "Current",
                        "release_date": release_date,
                        "release_url": f"https://github.com/{GITHUB_REPO}/commits/main",
                        "changelog": changelog,
                        "commit_sha": commit_sha,
                    }
                else:
                    return {
                        "success": False,
                        "current_version": SERVER_VERSION,
                        "current_version_disk": current_version_disk,
                        "error": "Could not parse version from GitHub",
                    }
            else:
                return {
                    "success": False,
                    "current_version": SERVER_VERSION,
                    "current_version_disk": current_version_disk,
                    "error": f"GitHub raw file error: {response.status_code}",
                }
                
    except Exception as e:
        logger.error(f"Failed to check server update: {e}")
        return {
            "success": False,
            "current_version": SERVER_VERSION,
            "error": str(e),
        }


@router.get("/server/commits")
async def get_recent_commits():
    """
    Ottiene gli ultimi commit dal repository GitHub.
    """
    try:
        import httpx
        
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                f"{GITHUB_API}/commits?per_page=10",
                headers={"Accept": "application/vnd.github.v3+json"}
            )
            
            if response.status_code == 200:
                commits = response.json()
                return {
                    "success": True,
                    "commits": [
                        {
                            "sha": c.get("sha", "")[:8],
                            "message": c.get("commit", {}).get("message", "").split("\n")[0],
                            "author": c.get("commit", {}).get("author", {}).get("name"),
                            "date": c.get("commit", {}).get("author", {}).get("date"),
                            "url": c.get("html_url"),
                        }
                        for c in commits
                    ]
                }
            else:
                return {
                    "success": False,
                    "error": f"GitHub API error: {response.status_code}",
                }
                
    except Exception as e:
        logger.error(f"Failed to get commits: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@router.post("/server/update")
async def trigger_server_update():
    """
    Avvia l'aggiornamento del server (git pull).
    Se la versione è cambiata, crea tag Git e release su GitHub.
    NOTA: Richiede riavvio manuale del server dopo l'update.
    """
    import subprocess
    import os
    import re
    import httpx
    from ..config import get_settings
    
    # Determina la directory del progetto
    # Se siamo in Docker e il repo è montato, usa quello, altrimenti cerca nella struttura normale
    if os.path.exists("/app/repo"):
        # Verifica se è montato /app/repo o /app/repo/dadude
        if os.path.exists("/app/repo/dadude"):
            project_dir = "/app/repo/dadude"
        elif os.path.exists("/app/repo/.git"):
            project_dir = "/app/repo"
        else:
            project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    else:
        project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Leggi versione corrente prima del pull
    version_file = os.path.join(project_dir, "app", "routers", "agents.py")
    old_version = None
    try:
        with open(version_file, 'r') as f:
            content = f.read()
            match = re.search(r'SERVER_VERSION\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                old_version = match.group(1)
    except Exception as e:
        logger.warning(f"Could not read current version: {e}")
    
    try:
        # Configura git safe.directory se necessario (per Docker con repository montato)
        if os.path.exists("/app/repo"):
            try:
                subprocess.run(
                    ["git", "config", "--global", "--add", "safe.directory", "/app/repo"],
                    capture_output=True,
                    timeout=5
                )
            except:
                pass
        
        # 1. Git pull
        # In Docker con repository montato, i permessi dovrebbero essere già configurati
        result = subprocess.run(
            ["git", "pull", "--rebase"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        # Se fallisce per permessi, fornisci istruzioni chiare
        if result.returncode != 0 and "Permission denied" in result.stderr:
            if os.path.exists("/.dockerenv"):
                return {
                    "success": False,
                    "error": "Permessi insufficienti sul repository montato",
                    "output": result.stdout,
                    "stderr": result.stderr,
                    "suggestion": "Esegui dall'host: docker exec -u root dadude bash -c 'cd /app/repo/dadude && git pull origin main'"
                }
        
        if result.returncode != 0:
            return {
                "success": False,
                "error": result.stderr or "Git pull failed",
                "output": result.stdout,
            }
        
        output = result.stdout
        already_up_to_date = "Already up to date" in output or "Già aggiornato" in output
        
        # 2. Leggi sempre la versione dal file su disco dopo il pull (anche se già aggiornato)
        # Questo permette di rilevare se il file è stato aggiornato manualmente
        new_version = None
        tag_created = False
        release_created = False
        
        try:
            # Leggi versione dal file su disco dopo il pull
            with open(version_file, 'r') as f:
                content = f.read()
                match = re.search(r'SERVER_VERSION\s*=\s*["\']([^"\']+)["\']', content)
                if match:
                    new_version = match.group(1)
        except Exception as e:
            logger.warning(f"Could not read new version after pull: {e}")
        
        # Se la versione su disco è diversa da quella in memoria, serve riavvio
        needs_restart_after_update = new_version and new_version != SERVER_VERSION
        
        # 3. Se aggiornato e la versione è cambiata, crea tag e release
        if not already_up_to_date and new_version and new_version != old_version:
            try:
                    tag_name = f"v{new_version}"
                    
                    # Verifica se il tag esiste già
                    tag_check = subprocess.run(
                        ["git", "tag", "-l", tag_name],
                        cwd=project_dir,
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if tag_name not in tag_check.stdout:
                        # Crea tag Git locale
                        tag_result = subprocess.run(
                            ["git", "tag", "-a", tag_name, "-m", f"Release {tag_name}"],
                            cwd=project_dir,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if tag_result.returncode == 0:
                            tag_created = True
                            
                            # Push tag su GitHub
                            push_tag_result = subprocess.run(
                                ["git", "push", "origin", tag_name],
                                cwd=project_dir,
                                capture_output=True,
                                text=True,
                                timeout=30
                            )
                            
                            if push_tag_result.returncode == 0:
                                logger.info(f"Tag {tag_name} pushed to GitHub")
                                
                                # Crea release su GitHub (se token disponibile)
                                settings = get_settings()
                                github_token = getattr(settings, 'github_token', None) or os.getenv('GITHUB_TOKEN')
                                
                                if github_token:
                                    try:
                                        async with httpx.AsyncClient() as client:
                                            release_data = {
                                                "tag_name": tag_name,
                                                "name": f"Release {tag_name}",
                                                "body": f"Automatic release for version {new_version}",
                                                "draft": False,
                                                "prerelease": False
                                            }
                                            
                                            response = await client.post(
                                                f"{GITHUB_API}/releases",
                                                headers={
                                                    "Authorization": f"Bearer {github_token}",
                                                    "Accept": "application/vnd.github.v3+json"
                                                },
                                                json=release_data,
                                                timeout=30.0
                                            )
                                            
                                            if response.status_code == 201:
                                                release_created = True
                                                logger.info(f"Release {tag_name} created on GitHub")
                                            else:
                                                logger.warning(f"Failed to create GitHub release: {response.status_code} - {response.text}")
                                    except Exception as e:
                                        logger.warning(f"Failed to create GitHub release: {e}")
                                else:
                                    logger.info("GITHUB_TOKEN not configured, skipping GitHub release creation")
                            else:
                                logger.warning(f"Failed to push tag: {push_tag_result.stderr}")
                    else:
                        logger.info(f"Tag {tag_name} already exists")
            except Exception as e:
                logger.warning(f"Error creating tag/release: {e}")
        
        # Costruisci messaggio di risposta
        messages = []
        if already_up_to_date:
            messages.append("Server già aggiornato")
        else:
            messages.append("Server aggiornato")
            if tag_created:
                messages.append(f"Tag v{new_version} creato")
            if release_created:
                messages.append(f"Release v{new_version} creata su GitHub")
        
        # Determina se serve riavvio
        # Serve riavvio se: 
        # 1. Ci sono stati aggiornamenti (non already_up_to_date), OPPURE
        # 2. La versione su disco è diversa da quella in memoria (serve riavvio per applicare)
        needs_restart = not already_up_to_date or needs_restart_after_update
        
        # Se serve riavvio per versione diversa, aggiungi al messaggio
        if needs_restart_after_update and already_up_to_date:
            messages.append(f"Versione su disco: v{new_version} (serve riavvio per applicare)")
        
        # 4. Se siamo in Docker, verifica se il codice è montato come volume
        # Se il codice è montato (non copiato), git pull è sufficiente e serve solo riavvio
        # Se il codice è copiato nel Dockerfile, serve rebuild (ma non lo facciamo più automaticamente)
        code_is_mounted = False
        restart_success = False
        restart_output = ""
        
        if os.path.exists("/.dockerenv"):
            # Verifica se /app/app è un mount point (volume montato)
            try:
                mount_check = subprocess.run(
                    ["mountpoint", "-q", "/app/app"],
                    capture_output=True,
                    timeout=2
                )
                code_is_mounted = mount_check.returncode == 0
            except:
                # Se mountpoint non disponibile, verifica in altro modo
                # Controlla se /app/app è un symlink o se esiste /app/repo/dadude/app
                if os.path.exists("/app/repo/dadude/app"):
                    code_is_mounted = True
            
            # Se il codice è montato e serve riavvio, riavvia automaticamente il container
            if code_is_mounted and needs_restart:
                try:
                    # Riavvia il container usando Docker CLI
                    docker_sock = "/var/run/docker.sock"
                    if os.path.exists(docker_sock):
                        # Ottieni il nome del container (di solito "dadude")
                        container_name = os.getenv("HOSTNAME", "dadude")
                        
                        restart_result = subprocess.run(
                            ["docker", "restart", container_name],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        restart_output = restart_result.stdout + "\n" + restart_result.stderr
                        
                        if restart_result.returncode == 0:
                            restart_success = True
                            messages.append("✅ Container riavviato automaticamente")
                            logger.info(f"Container {container_name} restarted successfully")
                        else:
                            logger.warning(f"Container restart failed: {restart_output}")
                            messages.append("⚠️ Riavvio automatico fallito - esegui manualmente:")
                            messages.append(f"   docker restart {container_name}")
                    else:
                        messages.append("⚠️ Socket Docker non accessibile - esegui manualmente:")
                        messages.append("   docker restart dadude")
                        logger.warning("Docker socket not accessible, cannot restart container")
                except subprocess.TimeoutExpired:
                    messages.append("⚠️ Timeout durante riavvio - esegui manualmente: docker restart dadude")
                    logger.error("Container restart timed out")
                except Exception as e:
                    logger.error(f"Failed to restart container: {e}")
                    messages.append(f"⚠️ Errore riavvio: {str(e)[:50]} - esegui manualmente: docker restart dadude")
            elif code_is_mounted:
                messages.append("✅ Codice montato come volume - git pull applicato")
                logger.info("Code is mounted as volume, git pull is sufficient")
            elif rebuild_needed:
                messages.append("⚠️ Codice copiato nel Dockerfile - serve rebuild manuale:")
                messages.append(f"   cd {compose_dir or project_dir} && docker compose up -d --build")
        
        return {
            "success": True,
            "already_up_to_date": already_up_to_date,
            "message": " | ".join(messages),
            "output": output,
            "code_is_mounted": code_is_mounted if os.path.exists("/.dockerenv") else None,
            "restart_success": restart_success if code_is_mounted and needs_restart else None,
            "restart_output": restart_output if code_is_mounted and needs_restart else None,
            "needs_restart": needs_restart and not restart_success,  # Serve riavvio solo se non già fatto automaticamente
            "version_changed": new_version != old_version if new_version and old_version else False,
            "version_disk_different": needs_restart_after_update,
            "current_version_memory": SERVER_VERSION,
            "current_version_disk": new_version,
            "new_version": new_version,
            "tag_created": tag_created,
            "release_created": release_created,
        }
            
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Update timed out",
        }
    except Exception as e:
        logger.error(f"Failed to update server: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@router.post("/server/restart")
async def trigger_server_restart():
    """
    Riavvia il server.
    Per Docker: restarta il container.
    Per processo diretto: esegue reload.
    """
    import os
    
    try:
        in_docker = os.path.exists("/.dockerenv")
        
        if in_docker:
            return {
                "success": True,
                "message": "Server is running in Docker. Please restart the container manually.",
                "command": "docker restart dadude-server",
            }
        else:
            import signal
            os.kill(os.getpid(), signal.SIGHUP)
            
            return {
                "success": True,
                "message": "Restart signal sent",
            }
            
    except Exception as e:
        logger.error(f"Failed to restart server: {e}")
        return {
            "success": False,
            "error": str(e),
        }


# ==========================================
# AGENT-SPECIFIC ROUTES (with path parameters)
# ==========================================

@router.post("/{agent_db_id}/approve")
async def approve_agent(
    agent_db_id: str,
    customer_id: str = Query(..., description="ID cliente a cui assegnare l'agent"),
):
    """
    Approva un agent e lo assegna a un cliente.
    """
    service = get_customer_service()
    
    try:
        agent = service.get_agent(agent_db_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Verifica che il cliente esista
        customer = service.get_customer(customer_id)
        if not customer:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        # Aggiorna agent
        from ..models.database import AgentAssignment, init_db, get_session
        from ..config import get_settings
        
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        db_agent = session.query(AgentAssignment).filter(
            AgentAssignment.id == agent_db_id
        ).first()
        
        if db_agent:
            db_agent.customer_id = customer_id
            db_agent.active = True
            db_agent.status = "online"
            session.commit()
        
        session.close()
        
        logger.success(f"Agent {agent.name} approved and assigned to {customer.name}")
        
        return {
            "success": True,
            "message": f"Agent assigned to {customer.name}",
            "agent_id": agent_db_id,
            "customer_id": customer_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to approve agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{agent_db_id}/update-address")
async def update_agent_address(
    agent_db_id: str,
    new_address: str = Query(..., description="Nuovo indirizzo IP"),
):
    """
    Aggiorna l'indirizzo IP di un agent dal pannello admin.
    """
    service = get_customer_service()
    
    try:
        success = service.update_agent_address(agent_db_id, new_address)
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        return {
            "success": True,
            "message": f"Agent address updated to {new_address}"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent address: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{agent_db_id}/config")
async def update_agent_config(
    agent_db_id: str,
    data: AgentUpdateRequest,
):
    """
    Aggiorna la configurazione di un agent dal pannello admin.
    La nuova config sarà inviata all'agent al prossimo poll.
    """
    service = get_customer_service()
    
    try:
        agent = service.get_agent(agent_db_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Aggiorna campi
        from ..models.database import AgentAssignment, init_db, get_session
        from ..config import get_settings
        
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        db_agent = session.query(AgentAssignment).filter(
            AgentAssignment.id == agent_db_id
        ).first()
        
        if db_agent:
            if data.name:
                db_agent.name = data.name
            if data.address:
                db_agent.address = data.address
                db_agent.agent_url = f"http://{data.address}:{db_agent.agent_api_port}"
            if data.dns_servers:
                db_agent.dns_server = ",".join(data.dns_servers)
            if data.active is not None:
                db_agent.active = data.active
            
            session.commit()
        
        session.close()
        
        return {
            "success": True,
            "message": "Agent configuration updated"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update agent config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# AGENT UPDATE/UPGRADE SYSTEM
# ==========================================

# Versione corrente dell'agent (stessa del server)
AGENT_VERSION = VERSION

@router.get("/version")
async def get_current_agent_version():
    """Restituisce la versione corrente dell'agent disponibile sul server"""
    return {
        "version": AGENT_VERSION,
        "download_url": "/api/v1/agents/download/agent-package.tar.gz",
        "changelog": "https://github.com/grandir66/dadude/releases",
    }


@router.get("/{agent_db_id}/check-update")
async def check_agent_update(agent_db_id: str):
    """
    Controlla se un agent ha bisogno di aggiornamento.
    Legge la versione dal database.
    """
    service = get_customer_service()
    
    agent = service.get_agent(agent_db_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    agent_version = agent.version or "0.0.0"
    needs_update = _compare_versions(agent_version, AGENT_VERSION) < 0
    
    return {
        "agent_id": agent_db_id,
        "current_version": agent_version,
        "latest_version": AGENT_VERSION,
        "needs_update": needs_update,
    }


@router.get("/{agent_db_id}/verify-version")
async def verify_agent_version(agent_db_id: str):
    """
    Verifica la versione REALE dell'agent contattandolo direttamente.
    Aggiorna il database con la versione rilevata.
    """
    service = get_customer_service()
    encryption = get_encryption_service()
    
    agent = service.get_agent(agent_db_id, include_password=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Prima verifica se l'agent è connesso via WebSocket
    from ..services.websocket_hub import get_websocket_hub
    hub = get_websocket_hub()
    
    # Cerca connessione WebSocket attiva per questo agent usando dude_agent_id
    ws_agent_id = None
    agent_dude_id = agent.dude_agent_id if agent.dude_agent_id else None
    
    if agent_dude_id:
        for conn_id in hub._connections.keys():
            if conn_id == agent_dude_id:
                ws_agent_id = conn_id
                break
    
    if ws_agent_id and ws_agent_id in hub._connections:
        # Agent connesso via WebSocket - è online
        real_version = agent.version or "2.0.0"
        
        # Aggiorna status nel database
        service.update_agent_status(agent_db_id, status="online", version=real_version)
        
        needs_update = _compare_versions(real_version, AGENT_VERSION) < 0
        
        return {
            "success": True,
            "agent_id": agent_db_id,
            "agent_name": agent.name,
            "db_version": agent.version or "N/A",
            "real_version": real_version,
            "latest_version": AGENT_VERSION,
            "needs_update": needs_update,
            "version_match": (agent.version or "") == real_version,
            "agent_online": True,
            "connection_type": "websocket",
            "ws_agent_id": ws_agent_id,
        }
    
    # Fallback a HTTP per agent non WebSocket
    if not agent.agent_url:
        # Agent WebSocket senza connessione attiva
        return {
            "success": False,
            "agent_id": agent_db_id,
            "agent_name": agent.name,
            "agent_online": False,
            "error": "Agent not connected (WebSocket mode)",
        }
    
    # Decripta token
    agent_token = None
    if hasattr(agent, 'agent_token') and agent.agent_token:
        try:
            agent_token = encryption.decrypt(agent.agent_token)
        except:
            agent_token = agent.agent_token
    
    try:
        import httpx
        
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{agent.agent_url}/health",
                headers={"Authorization": f"Bearer {agent_token}"} if agent_token else {}
            )
            
            if response.status_code == 200:
                data = response.json()
                real_version = data.get("version", "unknown")
                
                # Aggiorna versione nel database
                if real_version != "unknown":
                    service.update_agent_status(agent_db_id, status="online", version=real_version)
                
                needs_update = _compare_versions(real_version, AGENT_VERSION) < 0
                
                return {
                    "success": True,
                    "agent_id": agent_db_id,
                    "agent_name": agent.name,
                    "db_version": agent.version or "N/A",
                    "real_version": real_version,
                    "latest_version": AGENT_VERSION,
                    "needs_update": needs_update,
                    "version_match": (agent.version or "") == real_version,
                    "agent_online": True,
                    "connection_type": "http",
                    "agent_info": {
                        "agent_id": data.get("agent_id"),
                        "agent_name": data.get("agent_name"),
                        "uptime": data.get("uptime_seconds"),
                    }
                }
            else:
                return {
                    "success": False,
                    "agent_id": agent_db_id,
                    "agent_online": False,
                    "error": f"Agent returned {response.status_code}",
                }
                
    except Exception as e:
        logger.error(f"Failed to verify version for agent {agent_db_id}: {e}")
        return {
            "success": False,
            "agent_id": agent_db_id,
            "agent_online": False,
            "error": str(e),
        }


@router.post("/{agent_db_id}/trigger-update")
async def trigger_agent_update(agent_db_id: str):
    """
    Invia comando di aggiornamento all'agent.
    L'agent scaricherà la nuova versione e si riavvierà.
    Supporta sia agent WebSocket che HTTP.
    """
    service = get_customer_service()
    encryption = get_encryption_service()
    
    agent = service.get_agent(agent_db_id, include_password=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Prima prova via WebSocket
    from ..services.websocket_hub import get_websocket_hub, CommandType
    hub = get_websocket_hub()
    
    # Trova connessione WebSocket per questo agent usando dude_agent_id
    ws_agent_id = None
    agent_dude_id = agent.dude_agent_id if agent.dude_agent_id else None
    
    if agent_dude_id:
        for conn_id in hub._connections.keys():
            if conn_id == agent_dude_id:
                ws_agent_id = conn_id
                break
    
    if ws_agent_id and ws_agent_id in hub._connections:
        # Agent connesso via WebSocket
        # Prova prima a eseguire lo script esterno se possibile (più affidabile)
        # Altrimenti invia comando UPDATE_AGENT via WebSocket
        
        # Identifica l'host Proxmox dall'indirizzo IP dell'agent
        agent_ip = agent.address
        proxmox_host = None
        container_id = None
        
        # Mappa IP a host Proxmox (configurabile)
        # Per ora, prova a identificare l'host dall'IP
        if agent_ip:
            # Se l'IP è nella rete 192.168.99.x, probabilmente è su 192.168.99.10
            if agent_ip.startswith("192.168.99."):
                proxmox_host = "192.168.99.10"
            # Se l'IP è nella rete 192.168.40.x, probabilmente è su 192.168.40.3
            elif agent_ip.startswith("192.168.40."):
                proxmox_host = "192.168.40.3"
            # Altrimenti, prova a trovare il container ID dall'IP o dal nome
            else:
                # Prova a identificare l'host dall'IP
                proxmox_host = None
        
        # Se abbiamo identificato l'host Proxmox, prova a eseguire lo script esterno
        if proxmox_host:
            # Prova a trovare il container ID cercando container con agent Docker
            # IMPORTANTE: Trova il container corretto per questo agent specifico
            # basandosi sull'IP dell'agent o sul nome.
            # 
            # FIX v2.2.4: Rimosso il problema del "break" che trovava sempre lo stesso container.
            # Ora cerca il container corretto per ogni agent specifico verificando l'IP.
            # Mantiene compatibilità con la configurazione precedente - lo script update-agent.sh
            # riceve ancora il CTID come parametro, solo la ricerca è migliorata.
            try:
                import subprocess
                # Strategia 1: Cerca il container che ha l'IP dell'agent come IP del container LXC
                # Verifica l'IP effettivo del container invece della configurazione
                find_ctid_by_ip_cmd = f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'pct list | grep running | awk \"{{print \\$1}}\" | while read ctid; do pct exec $ctid -- ip addr show 2>/dev/null | grep -q \"{agent_ip}\" && echo $ctid && break; done'"
                
                find_result = subprocess.run(
                    find_ctid_by_ip_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                
                if find_result.returncode == 0 and find_result.stdout.strip():
                    container_id = find_result.stdout.strip()
                    logger.info(f"Found container ID {container_id} for agent {agent.name} (matched by IP {agent_ip}) on {proxmox_host}")
                else:
                    # Strategia 2: Se non trovato per IP, cerca tutti i container con agent Docker
                    # e verifica quale corrisponde all'agent tramite il nome o altre caratteristiche
                    logger.info(f"Container not found by IP for {agent.name}, trying alternative method...")
                    
                    # Lista tutti i container con agent Docker e verifica quale corrisponde
                    find_all_ctids_cmd = f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'pct list | grep running | awk \"{{print \\$1}}\" | while read ctid; do pct exec $ctid -- docker ps --filter name=dadude-agent --format \"{{{{.Names}}}}\" 2>/dev/null | grep -q dadude-agent && echo $ctid; done'"
                    
                    find_all_result = subprocess.run(
                        find_all_ctids_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )
                    
                    if find_all_result.returncode == 0 and find_all_result.stdout.strip():
                        # Se c'è solo un container, usalo
                        container_ids = [ctid.strip() for ctid in find_all_result.stdout.strip().split('\n') if ctid.strip()]
                        if len(container_ids) == 1:
                            container_id = container_ids[0]
                            logger.info(f"Found single container ID {container_id} for agent {agent.name} on {proxmox_host}")
                        else:
                            # Se ci sono più container, cerca quello che corrisponde meglio
                            # Verifica quale container ha un agent che corrisponde al nome o all'IP
                            logger.warning(f"Multiple containers found ({len(container_ids)}), trying to match by agent name/IP...")
                            
                            # Per ogni container, verifica se l'agent corrisponde
                            for ctid in container_ids:
                                # Verifica se questo container ha l'IP corretto verificando l'IP effettivo
                                check_ip_cmd = f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'pct exec {ctid} -- ip addr show 2>/dev/null | grep -q \"{agent_ip}\"'"
                                check_result = subprocess.run(
                                    check_ip_cmd,
                                    shell=True,
                                    capture_output=True,
                                    text=True,
                                    timeout=10,
                                )
                                
                                if check_result.returncode == 0:
                                    container_id = ctid
                                    logger.info(f"Matched container ID {container_id} for agent {agent.name} by IP verification ({agent_ip})")
                                    break
                            
                            # Se ancora non trovato, usa il primo (fallback)
                            if not container_id and container_ids:
                                container_id = container_ids[0]
                                logger.warning(f"Using first container ID {container_id} as fallback for agent {agent.name}")
                
                if container_id:
                    
                    # Esegui lo script di update esterno (usa update-agent-remote.sh che è più robusto)
                    # Lo script viene scaricato direttamente da GitHub per assicurarsi di avere l'ultima versione
                    update_cmd = f"ssh -o StrictHostKeyChecking=no root@{proxmox_host} 'curl -fsSL https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/deploy/proxmox/update-agent-remote.sh | bash -s -- {proxmox_host} {container_id}'"
                    
                    logger.info(f"Executing external update script for agent {agent.name}")
                    update_result = subprocess.run(
                        update_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=600,
                    )
                    
                    if update_result.returncode == 0:
                        return {
                            "success": True,
                            "message": "Update completed successfully via external script",
                            "connection_type": "external_script",
                            "output": update_result.stdout,
                        }
                    else:
                        logger.warning(f"External script failed: {update_result.stderr}")
                        # Fallback a WebSocket command
            except Exception as e:
                logger.warning(f"Could not execute external script: {e}")
                # Fallback a WebSocket command
        
        # Fallback: invia comando UPDATE_AGENT via WebSocket
        logger.info(f"Triggering update for agent {agent.name} via WebSocket")
        try:
            result = await hub.send_command(
                ws_agent_id,
                CommandType.UPDATE_AGENT,
                params={
                    "version": AGENT_VERSION,
                    "download_url": f"https://github.com/grandir66/DADude3.git",
                },
                timeout=60.0
            )
            
            if result.status == "success":
                return {
                    "success": True,
                    "message": "Update triggered successfully via WebSocket",
                    "connection_type": "websocket",
                    "agent_response": result.data,
                }
            else:
                return {
                    "success": False,
                    "error": f"WebSocket command failed: {result.error}",
                    "connection_type": "websocket",
                }
        except Exception as e:
            logger.error(f"WebSocket update failed for agent {agent_db_id}: {e}")
            return {
                "success": False,
                "error": str(e),
                "connection_type": "websocket",
            }
    
    # Fallback a HTTP per agent legacy
    if not agent.agent_url:
        raise HTTPException(status_code=400, detail="Agent not connected (WebSocket) and no URL configured (HTTP)")
    
    # Decripta token
    agent_token = None
    if hasattr(agent, 'agent_token') and agent.agent_token:
        try:
            agent_token = encryption.decrypt(agent.agent_token)
        except:
            agent_token = agent.agent_token
    
    try:
        import httpx
        
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{agent.agent_url}/admin/update",
                json={
                    "version": AGENT_VERSION,
                    "download_url": f"https://raw.githubusercontent.com/grandir66/DADude3/main/dadude-agent/",
                },
                headers={"Authorization": f"Bearer {agent_token}"} if agent_token else {}
            )
            
            if response.status_code == 200:
                result = response.json()
                return {
                    "success": True,
                    "message": "Update triggered successfully via HTTP",
                    "connection_type": "http",
                    "agent_response": result,
                }
            else:
                return {
                    "success": False,
                    "error": f"Agent returned {response.status_code}: {response.text}",
                    "connection_type": "http",
                }
                
    except Exception as e:
        logger.error(f"Failed to trigger update for agent {agent_db_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_db_id}/exec")
async def exec_command_on_agent(
    agent_db_id: str,
    command: str = Query(..., description="Comando da eseguire"),
    target_host: Optional[str] = Query(None, description="Host remoto (se vuoto, esegue sull'agent)"),
    username: Optional[str] = Query("root", description="Username SSH per host remoto"),
    password: Optional[str] = Query(None, description="Password SSH (opzionale)"),
    port: int = Query(22, description="Porta SSH"),
    timeout: int = Query(60, description="Timeout in secondi"),
):
    """
    Esegue un comando sull'agent o su un host remoto via SSH.
    
    Se target_host è specificato, l'agent si connette via SSH all'host ed esegue il comando.
    Altrimenti il comando viene eseguito localmente sull'agent.
    """
    service = get_customer_service()
    
    agent = service.get_agent(agent_db_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    from ..services.websocket_hub import get_websocket_hub, CommandType
    hub = get_websocket_hub()
    
    # Trova connessione WebSocket usando dude_agent_id
    ws_agent_id = None
    agent_dude_id = agent.dude_agent_id if agent.dude_agent_id else None
    
    if agent_dude_id:
        for conn_id in hub._connections.keys():
            if conn_id == agent_dude_id:
                ws_agent_id = conn_id
                break
    
    if not ws_agent_id:
        raise HTTPException(
            status_code=400, 
            detail="Agent not connected via WebSocket. Cannot execute remote commands."
        )
    
    try:
        if target_host:
            # Esegui su host remoto via SSH
            result = await hub.send_command(
                ws_agent_id,
                CommandType.EXEC_SSH,
                {
                    "host": target_host,
                    "command": command,
                    "username": username,
                    "password": password,
                    "port": port,
                    "timeout": timeout,
                },
                timeout=float(timeout + 10),
            )
        else:
            # Esegui localmente sull'agent
            result = await hub.send_command(
                ws_agent_id,
                CommandType.EXEC_COMMAND,
                {
                    "command": command,
                    "timeout": timeout,
                },
                timeout=float(timeout + 10),
            )
        
        if result.status == "success":
            return {
                "success": True,
                "agent_id": agent_db_id,
                "target": target_host or "agent-local",
                "command": command,
                "stdout": result.data.get("stdout", ""),
                "stderr": result.data.get("stderr", ""),
                "exit_code": result.data.get("exit_code", -1),
            }
        else:
            return {
                "success": False,
                "error": result.error,
                "agent_id": agent_db_id,
                "target": target_host or "agent-local",
            }
            
    except Exception as e:
        logger.error(f"Exec command failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_db_id}/restart")
async def restart_agent(agent_db_id: str):
    """
    Invia comando di riavvio all'agent.
    """
    service = get_customer_service()
    encryption = get_encryption_service()
    
    agent = service.get_agent(agent_db_id, include_password=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if not agent.agent_url:
        raise HTTPException(status_code=400, detail="Agent URL not configured")
    
    agent_token = None
    if hasattr(agent, 'agent_token') and agent.agent_token:
        try:
            agent_token = encryption.decrypt(agent.agent_token)
        except:
            agent_token = agent.agent_token
    
    try:
        import httpx
        
        # Timeout breve per evitare blocchi se l'agent non risponde
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(
                f"{agent.agent_url}/admin/restart",
                headers={"Authorization": f"Bearer {agent_token}"} if agent_token else {},
                follow_redirects=False
            )
            
            return {
                "success": response.status_code == 200,
                "message": "Restart command sent" if response.status_code == 200 else response.text,
            }
                
    except httpx.TimeoutException:
        # Timeout: l'agent potrebbe essere già in riavvio o non raggiungibile
        logger.warning(f"Timeout restarting agent {agent_db_id}")
        return {
            "success": True,
            "message": "Restart command sent (agent may be restarting or unreachable)",
        }
    except Exception as e:
        # L'agent potrebbe disconnettersi durante il riavvio
        logger.warning(f"Error restarting agent {agent_db_id}: {e}")
        return {
            "success": True,
            "message": "Restart command sent (agent may be restarting)",
        }


@router.get("/outdated")
async def list_outdated_agents():
    """
    Lista tutti gli agent che hanno bisogno di aggiornamento.
    Legge la versione latest da GitHub per confronto accurato.
    """
    import re
    import httpx
    from ..models.database import AgentAssignment, init_db, get_session
    from ..config import get_settings
    
    # Leggi versione agent da GitHub
    latest_agent_version = AGENT_VERSION
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            raw_url = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/dadude-agent/app/agent.py"
            response = await client.get(raw_url)
            if response.status_code == 200:
                match = re.search(r'AGENT_VERSION\s*=\s*["\']([^"\']+)["\']', response.text)
                if match:
                    latest_agent_version = match.group(1)
    except Exception as e:
        logger.warning(f"Could not fetch agent version from GitHub: {e}")
    
    settings = get_settings()
    # PostgreSQL è l'unico database supportato
    engine = init_db(settings.database_url)
    session = get_session(engine)
    
    try:
        # Solo agent Docker possono essere aggiornati (non MikroTik)
        agents = session.query(AgentAssignment).filter(
            AgentAssignment.active == True,
            AgentAssignment.agent_type == "docker"
        ).all()
        
        outdated = []
        for agent in agents:
            agent_version = agent.version or "0.0.0"
            if _compare_versions(agent_version, latest_agent_version) < 0:
                outdated.append({
                    "id": agent.id,
                    "name": agent.name,
                    "address": agent.address,
                    "agent_type": agent.agent_type,
                    "current_version": agent_version,
                    "latest_version": latest_agent_version,
                    "customer_id": agent.customer_id,
                })
        
        return {
            "total_agents": len(agents),
            "outdated_count": len(outdated),
            "latest_version": latest_agent_version,
            "outdated_agents": outdated,
        }
    finally:
        session.close()


@router.post("/update-all")
async def update_all_agents():
    """
    Invia comando di aggiornamento a tutti gli agent outdated.
    Aggiorna gli agent in sequenza per evitare conflitti.
    """
    outdated_result = await list_outdated_agents()
    outdated_agents = outdated_result.get("outdated_agents", [])
    
    if not outdated_agents:
        return {
            "total_updated": 0,
            "total_failed": 0,
            "message": "No outdated agents found",
            "results": [],
        }
    
    logger.info(f"Starting update for {len(outdated_agents)} outdated agents")
    
    results = []
    
    for idx, agent in enumerate(outdated_agents, 1):
        agent_id = agent["id"]
        agent_name = agent.get("name", "Unknown")
        logger.info(f"[{idx}/{len(outdated_agents)}] Updating agent {agent_name} (ID: {agent_id})")
        
        try:
            result = await trigger_agent_update(agent_id)
            success = result.get("success", False)
            message = result.get("message") or result.get("error", "Unknown error")
            
            results.append({
                "agent_id": agent_id,
                "agent_name": agent_name,
                "success": success,
                "message": message,
            })
            
            if success:
                logger.info(f"✓ Successfully updated agent {agent_name}")
            else:
                logger.warning(f"✗ Failed to update agent {agent_name}: {message}")
                
        except Exception as e:
            error_msg = str(e)
            logger.error(f"✗ Exception updating agent {agent_name}: {error_msg}")
            results.append({
                "agent_id": agent_id,
                "agent_name": agent_name,
                "success": False,
                "message": error_msg,
            })
        
        # Piccolo delay tra gli update per evitare sovraccarichi
        if idx < len(outdated_agents):
            await asyncio.sleep(2)
    
    total_updated = sum(1 for r in results if r["success"])
    total_failed = sum(1 for r in results if not r["success"])
    
    logger.info(f"Update completed: {total_updated} succeeded, {total_failed} failed")
    
    return {
        "total_updated": total_updated,
        "total_failed": total_failed,
        "results": results,
    }


def _compare_versions(v1: str, v2: str) -> int:
    """
    Confronta due versioni semver.
    Ritorna: -1 se v1 < v2, 0 se v1 == v2, 1 se v1 > v2
    """
    def parse(v):
        parts = v.replace("-", ".").split(".")
        return [int(p) if p.isdigit() else 0 for p in parts[:3]]
    
    p1, p2 = parse(v1), parse(v2)
    
    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


# ==========================================
# PKI / CERTIFICATE ENROLLMENT (mTLS)
# ==========================================

class CertificateEnrollRequest(BaseModel):
    """Richiesta enrollment certificato"""
    agent_id: str
    agent_name: str


class CertificateRenewRequest(BaseModel):
    """Richiesta rinnovo certificato"""
    validity_days: int = 365


@router.post("/enroll")
async def enroll_agent_certificate(
    data: CertificateEnrollRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """
    Enrollment certificato per mTLS.
    
    L'agent chiama questo endpoint per ottenere un certificato client
    che userà per connettersi via WebSocket sicuro.
    
    Richiede che l'agent sia già registrato e approvato.
    """
    from ..services.pki_service import get_pki_service
    from ..services.customer_service import get_customer_service
    
    service = get_customer_service()
    pki = get_pki_service()
    
    # Verifica token
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization")
    
    token = authorization[7:]
    
    # Trova agent e verifica token
    try:
        # Usa il servizio per cercare l'agent (supporta dude_agent_id, id, name)
        agent = service.get_agent_by_unique_id(data.agent_id)
        
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Accedi direttamente al database per ottenere agent_token e active status
        from ..models.database import AgentAssignment as AgentAssignmentDB
        session = service._get_session()
        agent_db = session.query(AgentAssignmentDB).filter(
            AgentAssignmentDB.id == agent.id
        ).first()
        
        if not agent_db:
            raise HTTPException(status_code=404, detail="Agent not found in database")

        # Verifica che agent sia approvato
        if not agent_db.active:
            raise HTTPException(status_code=403, detail="Agent not approved yet")

        # Verifica token
        encryption = get_encryption_service()
        stored_token = encryption.decrypt(agent_db.agent_token) if agent_db.agent_token else None

        if stored_token != token:
            raise HTTPException(status_code=401, detail="Invalid token")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error verifying agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    
    # Genera certificato
    try:
        cert_data = pki.generate_agent_certificate(
            agent_id=data.agent_id,
            agent_name=data.agent_name,
            validity_days=365
        )
        
        logger.success(f"Certificate issued for agent: {data.agent_id}")
        
        return {
            "success": True,
            "agent_id": data.agent_id,
            "certificate": cert_data["certificate"].decode("utf-8"),
            "private_key": cert_data["private_key"].decode("utf-8"),
            "ca_certificate": cert_data["ca_certificate"].decode("utf-8"),
            "expires_in_days": 365,
        }
        
    except Exception as e:
        logger.error(f"Certificate enrollment failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{agent_db_id}/certificate")
async def get_agent_certificate(
    agent_db_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Recupera certificato esistente per un agent.
    """
    from ..services.pki_service import get_pki_service
    from ..services.customer_service import get_customer_service
    
    service = get_customer_service()
    pki = get_pki_service()
    
    # Verifica autorizzazione
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    token = authorization[7:]
    
    # Trova agent
    agent = service.get_agent(agent_db_id, include_password=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Verifica token
    encryption = get_encryption_service()
    stored_token = encryption.decrypt(agent.agent_token) if agent.agent_token else None
    if stored_token != token:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    # Recupera certificato
    cert_data = pki.get_agent_certificate(agent.name)  # Usa name come agent_id nel PKI
    
    if not cert_data:
        raise HTTPException(status_code=404, detail="Certificate not found. Call /enroll first.")
    
    # Info certificato
    cert_info = pki.get_certificate_info(agent.name)
    
    return {
        "success": True,
        "certificate": cert_data["certificate"].decode("utf-8"),
        "ca_certificate": cert_data["ca_certificate"].decode("utf-8"),
        "info": cert_info,
        # Non restituiamo la chiave privata - già fornita all'enrollment
    }


@router.post("/{agent_db_id}/renew")
async def renew_agent_certificate(
    agent_db_id: str,
    data: CertificateRenewRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Rinnova certificato agent.
    """
    from ..services.pki_service import get_pki_service
    from ..services.customer_service import get_customer_service
    
    service = get_customer_service()
    pki = get_pki_service()
    
    # Verifica autorizzazione
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    
    # Trova agent
    agent = service.get_agent(agent_db_id, include_password=True)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Revoca vecchio certificato
    pki.revoke_certificate(agent.name)
    
    # Genera nuovo certificato
    cert_data = pki.generate_agent_certificate(
        agent_id=agent.name,
        agent_name=agent.name,
        validity_days=data.validity_days
    )
    
    logger.info(f"Certificate renewed for agent: {agent.name}")
    
    return {
        "success": True,
        "certificate": cert_data["certificate"].decode("utf-8"),
        "private_key": cert_data["private_key"].decode("utf-8"),
        "ca_certificate": cert_data["ca_certificate"].decode("utf-8"),
        "expires_in_days": data.validity_days,
    }


@router.delete("/{agent_db_id}/certificate")
async def revoke_agent_certificate(
    agent_db_id: str,
    authorization: Optional[str] = Header(None),
):
    """
    Revoca certificato agent (admin only).
    """
    from ..services.pki_service import get_pki_service
    from ..services.customer_service import get_customer_service
    
    # TODO: Verificare che sia admin
    
    service = get_customer_service()
    pki = get_pki_service()
    
    agent = service.get_agent(agent_db_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    success = pki.revoke_certificate(agent.name)
    
    if success:
        logger.warning(f"Certificate revoked for agent: {agent.name}")
        return {"success": True, "message": f"Certificate revoked for {agent.name}"}
    else:
        return {"success": False, "message": "Certificate not found or already revoked"}


@router.get("/pki/ca")
async def get_ca_certificate():
    """
    Ottiene il certificato CA pubblico.
    Utile per gli agent per verificare il server.
    """
    from ..services.pki_service import get_pki_service
    
    pki = get_pki_service()
    ca_cert = pki.get_ca_certificate()
    
    return {
        "success": True,
        "ca_certificate": ca_cert.decode("utf-8"),
    }


@router.get("/pki/expiring")
async def get_expiring_certificates(
    days: int = Query(default=30, description="Giorni prima della scadenza"),
):
    """
    Lista certificati in scadenza entro N giorni.
    """
    from ..services.pki_service import get_pki_service
    
    pki = get_pki_service()
    expiring = pki.check_expiring_soon(days=days)
    
    return {
        "days_threshold": days,
        "count": len(expiring),
        "certificates": expiring,
    }


# ==========================================
# WEBSOCKET ENDPOINT
# ==========================================

from fastapi import WebSocket, WebSocketDisconnect


@router.websocket("/ws/{agent_id}")
async def websocket_agent_connection(
    websocket: WebSocket,
    agent_id: str,
):
    """
    WebSocket endpoint per connessione agent bidirezionale.
    
    L'agent si connette qui dopo l'enrollment e mantiene la connessione
    aperta per ricevere comandi e inviare risultati.
    
    Autenticazione via mTLS (certificato client) o token header.
    """
    from ..services.websocket_hub import get_websocket_hub
    from ..services.customer_service import get_customer_service
    
    hub = get_websocket_hub()
    service = get_customer_service()
    
    # Estrai token dall'header (fallback se mTLS non disponibile)
    # In produzione, verificherebbe il certificato client
    auth_header = websocket.headers.get("authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    
    # Verifica che agent esista
    try:
        logger.info(f"WebSocket: Looking up agent {agent_id}")
        agent = service.get_agent_by_unique_id(agent_id)
        
        if not agent:
            logger.warning(f"WebSocket: Agent {agent_id} not found")
            await websocket.close(code=4004, reason="Agent not found")
            return
        
        logger.info(f"WebSocket: Found agent {agent.name} (id={agent.id}, active={agent.active})")
        
        if not agent.active:
            logger.warning(f"WebSocket: Agent {agent_id} not approved")
            await websocket.close(code=4003, reason="Agent not approved")
            return
        
        # Verifica token (se presente nell'header)
        if token:
            logger.info(f"WebSocket: Verifying token for {agent_id}")
            encryption = get_encryption_service()
            stored_token_encrypted = service.get_agent_token(agent_id)
            if stored_token_encrypted:
                try:
                    stored_token = encryption.decrypt(stored_token_encrypted)
                    if stored_token != token:
                        logger.warning(f"WebSocket: Token mismatch for {agent_id}")
                        await websocket.close(code=4001, reason="Invalid token")
                        return
                    logger.info(f"WebSocket: Token verified for {agent_id}")
                except Exception as e:
                    logger.warning(f"Token decryption failed for {agent_id}: {e}")
                    # Se la decriptazione fallisce, accetta comunque se l'agent è approvato
            else:
                logger.warning(f"WebSocket: No stored token for {agent_id}, skipping verification")
        else:
            logger.info(f"WebSocket: No token in header for {agent_id}, skipping verification")
        
    except Exception as e:
        logger.error(f"WebSocket auth error for {agent_id}: {e}")
        await websocket.close(code=4000, reason="Authentication failed")
        return
    
    # Gestisci connessione
    logger.info(f"WebSocket connection from agent: {agent_id}")
    
    try:
        await hub.handle_connection(websocket, agent_id)
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected: {agent_id}")
    except Exception as e:
        logger.error(f"WebSocket error for {agent_id}: {e}")


@router.get("/ws/connected")
async def list_connected_agents():
    """
    Lista agent attualmente connessi via WebSocket.
    """
    from ..services.websocket_hub import get_websocket_hub
    
    hub = get_websocket_hub()
    
    return {
        "count": await hub.connected_count(),
        "agents": await hub.get_connected_agents(),
    }


@router.post("/ws/{agent_id}/command")
async def send_command_to_agent(
    agent_id: str,
    action: str = Query(..., description="Azione: scan_network, probe_wmi, probe_ssh, etc."),
    params: Optional[str] = Query(None, description="Parametri JSON"),
    timeout: float = Query(default=300.0, description="Timeout in secondi"),
):
    """
    Invia comando a un agent connesso via WebSocket.
    """
    from ..services.websocket_hub import get_websocket_hub, CommandType
    import json
    
    hub = get_websocket_hub()
    
    if not await hub.is_connected(agent_id):
        raise HTTPException(status_code=404, detail="Agent not connected")
    
    # Parse parametri
    try:
        command_params = json.loads(params) if params else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in params")
    
    # Mappa azione a CommandType
    try:
        action_type = CommandType(action)
    except ValueError:
        # Accetta anche azioni custom
        action_type = action
    
    # Invia comando
    result = await hub.send_command(
        agent_id=agent_id,
        action=action_type,
        params=command_params,
        timeout=timeout
    )
    
    return {
        "command_id": result.command_id,
        "status": result.status,
        "data": result.data,
        "error": result.error,
    }

