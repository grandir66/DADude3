"""
DaDude - Dashboard Router
Pagine web per dashboard e configurazione
"""
from fastapi import APIRouter, Request, HTTPException, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from typing import Optional
from datetime import datetime, timedelta
from loguru import logger
import os

from ..config import get_settings
from ..services import get_dude_service, get_sync_service, get_alert_service
from ..services.customer_service import get_customer_service
from ..services.settings_service import get_settings_service
from ..auth import (
    is_auth_enabled, verify_password, get_admin_username,
    create_session, destroy_session
)

router = APIRouter(tags=["Dashboard"])

# Setup templates
templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
templates = Jinja2Templates(directory=templates_dir)


def get_dashboard_data():
    """Raccoglie dati per la dashboard"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    
    settings = get_settings()
    settings_service = get_settings_service()
    dude = get_dude_service()
    sync = get_sync_service()
    alert_service = get_alert_service()
    customer_service = get_customer_service()
    
    # Configurazione Dude
    dude_config = settings_service.get_dude_config()
    
    # Dati clienti
    customers_raw = customer_service.list_customers(active_only=True, limit=1000)
    customers = []
    for c in customers_raw:
        if hasattr(c, 'model_dump'):
            customers.append(c.model_dump(mode='json'))
        else:
            c_dict = dict(c)
            for key, value in c_dict.items():
                if hasattr(value, 'isoformat'):
                    c_dict[key] = value.isoformat()
            customers.append(c_dict)
    
    # Dati inventario locale
    try:
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        
        # Conta dispositivi in inventario
        inventory_total = session.query(InventoryDevice).filter(InventoryDevice.active == True).count()
        inventory_monitored = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.monitored == True
        ).count()
        inventory_online = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.status == 'online'
        ).count()
        inventory_offline = session.query(InventoryDevice).filter(
            InventoryDevice.active == True,
            InventoryDevice.status == 'offline'
        ).count()
        
        # Conta sonde attive
        agents = customer_service.list_agents(active_only=True)
        agents_mikrotik = len([a for a in agents if a.agent_type == 'mikrotik'])
        agents_docker = len([a for a in agents if a.agent_type == 'docker'])
        
        session.close()
    except Exception as e:
        logger.warning(f"Errore lettura inventario: {e}")
        inventory_total = 0
        inventory_monitored = 0
        inventory_online = 0
        inventory_offline = 0
        agents = []
        agents_mikrotik = 0
        agents_docker = 0
    
    # Dati The Dude (opzionali)
    dude_devices = []
    dude_up = 0
    dude_down = 0
    dude_probes_ok = 0
    dude_probes_warning = 0
    dude_probes_critical = 0
    alerts_unack = 0
    
    if dude.is_connected:
        devices = sync.devices
        dude_up = len([d for d in devices if d.status.value == "up"])
        dude_down = len([d for d in devices if d.status.value == "down"])
        dude_devices = devices[:10]
        
        probes = sync.probes
        dude_probes_ok = len([p for p in probes if p.status.value == "ok"])
        dude_probes_warning = len([p for p in probes if p.status.value == "warning"])
        dude_probes_critical = len([p for p in probes if p.status.value == "critical"])
        
        alerts = alert_service.get_alerts(since=datetime.utcnow() - timedelta(hours=24), limit=100)
        alerts_unack = len([a for a in alerts if not a.acknowledged])
    
    return {
        "dude_connected": dude.is_connected,
        "dude_host": settings.dude_host,
        "dude_config": dude_config,
        "last_sync": sync.last_sync,
        # Inventario locale (principale)
        "inventory": {
            "total": inventory_total,
            "monitored": inventory_monitored,
            "online": inventory_online,
            "offline": inventory_offline,
        },
        "agents": {
            "total": len(agents) if agents else 0,
            "mikrotik": agents_mikrotik,
            "docker": agents_docker,
        },
        # The Dude (opzionale)
        "devices": {
            "total": len(dude_devices),
            "up": dude_up,
            "down": dude_down,
            "list": dude_devices,
        },
        "probes": {
            "ok": dude_probes_ok,
            "warning": dude_probes_warning,
            "critical": dude_probes_critical,
        },
        "alerts": {
            "unacknowledged": alerts_unack,
        },
        "customers": {
            "total": len(customers),
            "list": customers[:10],
        },
        "settings": settings,
    }


# ==========================================
# DASHBOARD PAGES
# ==========================================

# ==========================================
# LOGIN ROUTES
# ==========================================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, error: Optional[str] = None):
    """Pagina di login"""
    return templates.TemplateResponse("login.html", {
        "request": request,
        "error": error,
        "username": get_admin_username(),
    })


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """Processa il login"""
    admin_username = get_admin_username()
    
    if username != admin_username:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Username non valido",
            "username": username,
        })
    
    if not verify_password(password):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Password non valida",
            "username": username,
        })
    
    # Login riuscito, crea sessione
    session_token = create_session(username)
    response = RedirectResponse(url="/", status_code=302)
    response.set_cookie(
        key="dadude_session",
        value=session_token,
        httponly=True,
        max_age=86400 * 7,  # 7 giorni
        samesite="lax"
    )
    return response


@router.get("/logout")
async def logout(request: Request):
    """Logout e distrugge la sessione"""
    session_token = request.cookies.get("dadude_session")
    if session_token:
        destroy_session(session_token)
    
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie("dadude_session")
    return response


# ==========================================
# DASHBOARD ROUTES
# ==========================================

@router.get("/", response_class=HTMLResponse)
@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Dashboard principale"""
    data = get_dashboard_data()
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "page": "dashboard",
        "title": "Dashboard",
        **data
    })


@router.get("/monitoring", response_class=HTMLResponse)
async def monitoring_page(
    request: Request, 
    customer_id: Optional[str] = None, 
    status: Optional[str] = None, 
    show_all: bool = False
):
    """Pagina unificata per monitoraggio dispositivi - mostra sia device da Dude che da inventory"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from fastapi import Query
    
    # Estrai parametri dalla query string se non passati come parametri funzione
    query_params = request.query_params
    monitoring_type_filter = query_params.get("monitoring_type")
    
    # Estrai customer_id dalla query string (priorità ai parametri query string)
    if "customer_id" in query_params:
        customer_id_from_query = query_params.get("customer_id")
        if customer_id_from_query and customer_id_from_query.strip():
            customer_id = customer_id_from_query.strip()
        elif customer_id_from_query == "":
            customer_id = None  # Stringa vuota significa "tutti i clienti"
    
    if not status and "status" in query_params:
        status = query_params.get("status")
    if "show_all" in query_params:
        show_all = query_params.get("show_all", "false").lower() == "true"
    
    logger.info(f"Monitoring page request: customer_id={customer_id} (type: {type(customer_id).__name__}), status={status}, monitoring_type={monitoring_type_filter}, show_all={show_all}")
    
    customer_service = get_customer_service()
    customers = customer_service.list_customers(active_only=True, limit=500)
    customers_dicts = []
    for c in customers:
        if hasattr(c, 'model_dump'):
            c_dict = c.model_dump(mode='json')
            # Assicurati che l'id sia una stringa per il confronto nel template
            if 'id' in c_dict:
                c_dict['id'] = str(c_dict['id'])
            customers_dicts.append(c_dict)
        else:
            c_dict = dict(c)
            if 'id' in c_dict:
                c_dict['id'] = str(c_dict['id'])
            customers_dicts.append(c_dict)
    
    logger.debug(f"Loaded {len(customers_dicts)} customers for filter dropdown")
    
    # Carica device dall'inventory database
    devices = []
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice).filter(
            InventoryDevice.active == True
        )
        
        # Conta totale device prima dei filtri (per debug)
        total_before_filters = query.count()
        logger.info(f"Total devices before filters: {total_before_filters}")
        
        # Filtra per cliente se specificato - DEVE essere il primo filtro applicato
        if customer_id and customer_id.strip():
            customer_id = customer_id.strip()
            
            # Verifica quanti device hanno questo customer_id esatto
            exact_match_count = session.query(InventoryDevice).filter(
                InventoryDevice.active == True,
                InventoryDevice.customer_id == customer_id
            ).count()
            logger.info(f"Devices with customer_id={customer_id}: {exact_match_count}")
            
            # Applica filtro customer
            query = query.filter(InventoryDevice.customer_id == customer_id)
            logger.info(f"Applied customer filter: {customer_id}")
            
            count_after = query.count()
            logger.info(f"Devices after customer filter: {count_after}")
        else:
            logger.debug("No customer_id filter - showing all devices")
        
        # Se show_all=False, mostra solo device monitorati o con monitoraggio configurato
        # MA: se un cliente è selezionato, mostra TUTTI i device di quel cliente (monitorati e non)
        if not show_all and not customer_id:
            # Solo se NON c'è un filtro cliente, applica il filtro monitoraggio
            from sqlalchemy import or_, and_
            query = query.filter(
                or_(
                    InventoryDevice.monitored == True,
                    and_(
                        InventoryDevice.monitoring_type.isnot(None),
                        InventoryDevice.monitoring_type != "none"
                    )
                )
            )
            logger.debug(f"Applied monitoring filter (show_all=False, no customer filter)")
        elif customer_id:
            # Se c'è un filtro cliente, mostra TUTTI i device di quel cliente (non applicare filtro monitoraggio)
            logger.info(f"Customer filter active - showing ALL devices for customer {customer_id} (ignoring show_all filter)")
        
        # Filtra per status se specificato
        if status:
            query = query.filter(InventoryDevice.status == status)
            logger.debug(f"Applied status filter: {status}")
        
        # Filtra per monitoring_type se specificato
        if monitoring_type_filter:
            if monitoring_type_filter == "none":
                # Nessuno: mostra solo device senza monitoraggio configurato
                query = query.filter(
                    (InventoryDevice.monitoring_type.is_(None)) | 
                    (InventoryDevice.monitoring_type == "none")
                )
            else:
                query = query.filter(InventoryDevice.monitoring_type == monitoring_type_filter)
            logger.debug(f"Applied monitoring_type filter: {monitoring_type_filter}")
        
        devices_raw = query.order_by(InventoryDevice.name).all()
        
        logger.info(f"Monitoring page: Found {len(devices_raw)} devices (total before filters: {total_before_filters}, customer_id: {customer_id}, show_all: {show_all}, status: {status}, monitoring_type: {monitoring_type_filter})")
        
        # Debug: mostra alcuni esempi di customer_id presenti nei device trovati
        if devices_raw:
            sample_customer_ids = set([d.customer_id for d in devices_raw[:10] if d.customer_id])
            logger.info(f"Sample customer_ids in results: {sample_customer_ids}")
            # Debug: mostra anche alcuni esempi di dispositivi trovati
            logger.debug(f"Sample devices: {[(d.name, d.primary_ip, d.customer_id) for d in devices_raw[:5]]}")
        else:
            logger.warning(f"No devices found with filters (customer_id={customer_id}, show_all={show_all}, status={status}, monitoring_type={monitoring_type_filter})")
            # Se customer_id è specificato ma non ci sono risultati, verifica se ci sono device con customer_id NULL o diverso
            if customer_id:
                null_customer_count = session.query(InventoryDevice).filter(
                    InventoryDevice.active == True,
                    InventoryDevice.customer_id.is_(None)
                ).count()
                logger.warning(f"Found {null_customer_count} devices with NULL customer_id")
                
                # Verifica tutti i customer_id presenti nel database
                all_customer_ids = session.query(InventoryDevice.customer_id).filter(
                    InventoryDevice.active == True
                ).distinct().all()
                logger.warning(f"All customer_ids in database: {[c[0] for c in all_customer_ids if c[0]]}")
        
        # Crea mappa customer_id -> customer per lookup veloce
        # Normalizza gli ID come stringhe per il confronto
        customers_map = {}
        for c in customers_dicts:
            c_id = str(c.get('id', ''))
            customers_map[c_id] = c
        
        logger.debug(f"Customers map keys: {list(customers_map.keys())[:5]}")
        
        for dev in devices_raw:
            # Normalizza anche il customer_id del device come stringa
            dev_customer_id = str(dev.customer_id) if dev.customer_id else None
            customer_info = customers_map.get(dev_customer_id, {})
            
            logger.debug(f"Device {dev.name} ({dev.primary_ip}): customer_id={dev_customer_id}, customer_name={customer_info.get('name', 'N/A')}")
            
            devices.append({
                "id": dev.id,
                "name": dev.name or dev.primary_ip or "Unknown",
                "hostname": dev.hostname,
                "primary_ip": dev.primary_ip,
                "primary_mac": dev.primary_mac or dev.mac_address,
                "device_type": dev.device_type,
                "category": dev.category,
                "customer_id": dev_customer_id,
                "customer_name": customer_info.get('name', 'Unknown'),
                "customer_code": customer_info.get('code', ''),
                "status": dev.status or "unknown",
                "monitored": dev.monitored or False,
                "monitoring_type": dev.monitoring_type or "none",
                "monitoring_port": dev.monitoring_port,
                "monitoring_agent_id": dev.monitoring_agent_id,
                "netwatch_id": dev.netwatch_id,
                "last_check": dev.last_check.isoformat() if dev.last_check else None,
                "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
            })
    finally:
        session.close()
    
    # Debug: log anche il numero di device trovati
    logger.info(f"Monitoring page rendered: {len(devices)} devices, customer_id={customer_id}, show_all={show_all}, status={status}, monitoring_type={monitoring_type_filter}")
    
    # Assicurati che selected_customer_id sia una stringa o None per il confronto nel template
    selected_customer_id_str = str(customer_id) if customer_id else None
    
    logger.debug(f"Template context: selected_customer_id={selected_customer_id_str}, devices_count={len(devices)}")
    
    return templates.TemplateResponse("monitoring.html", {
        "request": request,
        "page": "monitoring",
        "title": "Monitoraggio Dispositivi",
        "customers": customers_dicts,
        "selected_customer_id": selected_customer_id_str,  # Usa stringa per confronto nel template
        "status_filter": status,
        "monitoring_type_filter": monitoring_type_filter,
        "show_all": show_all,
        "devices": devices,
        "devices_count": len(devices),  # Aggiunto per debug nel template
    })


@router.get("/devices", response_class=HTMLResponse)
async def devices_page(request: Request, status: Optional[str] = None):
    """Pagina dispositivi"""
    sync = get_sync_service()
    devices_raw = sync.devices
    
    if status:
        devices_raw = [d for d in devices_raw if d.status.value == status]
    
    # Converti devices in dizionari per JSON serialization
    # Aggiungi anche dispositivi dall'inventario se disponibili
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    devices = []
    inventory_devices_map = {}
    
    # Carica dispositivi dall'inventario per avere dati di monitoraggio
    try:
        settings = get_settings()
        db_url = settings.database_url
        engine = init_db(db_url)
        session = get_session(engine)
        try:
            inventory_devices = session.query(InventoryDevice).filter(
                InventoryDevice.active == True
            ).all()
            # Crea mappa IP -> device inventario per matching
            for inv_dev in inventory_devices:
                ip = inv_dev.primary_ip or inv_dev.mac_address
                if ip:
                    inventory_devices_map[ip] = {
                        'id': inv_dev.id,
                        'monitoring_type': inv_dev.monitoring_type or 'none',
                        'monitoring_port': inv_dev.monitoring_port,
                        'monitoring_agent_id': inv_dev.monitoring_agent_id,
                        'monitored': inv_dev.monitored
                    }
        finally:
            session.close()
    except Exception as e:
        logger.warning(f"Errore caricamento dispositivi inventario: {e}")
    
    for d in devices_raw:
        # Cerca corrispondente nell'inventario per IP o MAC
        inv_data = None
        if d.address and d.address in inventory_devices_map:
            inv_data = inventory_devices_map[d.address]
        elif getattr(d, 'mac_address', None) and d.mac_address in inventory_devices_map:
            inv_data = inventory_devices_map[d.mac_address]
        
        device_dict = {
            'id': inv_data['id'] if inv_data else None,  # ID inventario se disponibile
            'name': d.name,
            'address': d.address,
            'mac_address': getattr(d, 'mac_address', None),
            'device_type': getattr(d, 'device_type', None),
            'group': getattr(d, 'group', None),
            'status': {'value': d.status.value},
            'last_seen': d.last_seen.isoformat() if hasattr(d, 'last_seen') and d.last_seen else None,
            # Campi monitoraggio (da inventario se disponibile, altrimenti default)
            'monitoring_type': inv_data['monitoring_type'] if inv_data else 'none',
            'monitoring_port': inv_data['monitoring_port'] if inv_data else None,
            'monitoring_agent_id': inv_data['monitoring_agent_id'] if inv_data else None,
            'monitored': inv_data['monitored'] if inv_data else False
        }
        devices.append(device_dict)
    
    return templates.TemplateResponse("devices.html", {
        "request": request,
        "page": "devices",
        "title": "Dispositivi",
        "devices": devices,
        "status_filter": status,
    })


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Pagina alert"""
    alert_service = get_alert_service()
    alerts = alert_service.get_alerts(since=datetime.utcnow() - timedelta(hours=48), limit=200)
    
    return templates.TemplateResponse("alerts.html", {
        "request": request,
        "page": "alerts",
        "title": "Alert",
        "alerts": alerts,
    })


@router.get("/customers", response_class=HTMLResponse)
async def customers_page(request: Request):
    """Pagina clienti"""
    customer_service = get_customer_service()
    customers = customer_service.list_customers(active_only=True, limit=500)
    
    # Converti customers in dizionari per JSON serialization
    import json
    customers_dict = []
    for c in customers:
        if hasattr(c, 'model_dump'):
            # Usa mode='json' per gestire datetime automaticamente
            customers_dict.append(c.model_dump(mode='json'))
        else:
            # Fallback: converti manualmente
            c_dict = dict(c)
            # Converti datetime in stringhe
            for key, value in c_dict.items():
                if hasattr(value, 'isoformat'):
                    c_dict[key] = value.isoformat()
            customers_dict.append(c_dict)
    
    return templates.TemplateResponse("customers.html", {
        "request": request,
        "page": "customers",
        "title": "Clienti",
        "customers": customers_dict,
    })


@router.get("/customers/{customer_id}", response_class=HTMLResponse)
async def customer_detail_page(request: Request, customer_id: str):
    """Dettaglio cliente"""
    import re
    import httpx
    
    customer_service = get_customer_service()
    
    customer = customer_service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    networks = customer_service.list_networks(customer_id=customer_id, active_only=False)
    credentials_raw = customer_service.list_credentials(customer_id=customer_id, active_only=False)
    global_credentials_raw = customer_service.list_global_credentials(active_only=True)
    devices = customer_service.list_device_assignments(customer_id=customer_id, active_only=False)
    agents_raw = customer_service.list_agents(customer_id=customer_id, active_only=False)
    
    # Converti credenziali in dizionari per il template
    credentials = []
    for cred in credentials_raw:
        if hasattr(cred, 'model_dump'):
            credentials.append(cred.model_dump(mode='json'))
        elif hasattr(cred, 'dict'):
            credentials.append(cred.dict())
        else:
            credentials.append(dict(cred))
    
    global_credentials = []
    for cred in global_credentials_raw:
        if hasattr(cred, 'model_dump'):
            global_credentials.append(cred.model_dump(mode='json'))
        elif hasattr(cred, 'dict'):
            global_credentials.append(cred.dict())
        else:
            global_credentials.append(dict(cred))
    
    # Ottieni stato WebSocket via HTTP dall'Agent API (porta 8000)
    ws_connected_names = set()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get("http://localhost:8000/api/v1/agents/ws/connected")
            if resp.status_code == 200:
                ws_data = resp.json()
                for ws_agent in ws_data.get("agents", []):
                    agent_id = ws_agent.get("agent_id", "")
                    match = re.match(r'^agent-(.+?)(?:-\d+)?$', agent_id)
                    if match:
                        ws_connected_names.add(match.group(1))
                logger.debug(f"WebSocket connected names: {ws_connected_names}")
    except Exception as e:
        logger.warning(f"Could not fetch WebSocket status: {e}")
    
    # Converti e arricchisci
    agents = []
    connected_docker_agents = []
    
    for agent in agents_raw:
        agent_dict = agent.model_dump() if hasattr(agent, 'model_dump') else dict(agent)
        agent_type = agent_dict.get('agent_type', 'mikrotik')
        agent_name = agent_dict.get('name', '')
        
        if agent_type == 'docker':
            if agent_name in ws_connected_names:
                agent_dict['status'] = 'online'
                agent_dict['ws_connected'] = True
                connected_docker_agents.append(agent_dict)
            else:
                agent_dict['ws_connected'] = False
        
        agents.append(agent_dict)
    
    # Per MikroTik, mostra se raggiungibili via Docker agent
    for agent_dict in agents:
        if agent_dict.get('agent_type', 'mikrotik') == 'mikrotik':
            if connected_docker_agents:
                bridge = connected_docker_agents[0]
                agent_dict['status'] = 'reachable'
                agent_dict['reachable_via'] = bridge.get('name', 'Docker Agent')
            else:
                agent_dict['status'] = 'unreachable'
    
    return templates.TemplateResponse("customer_detail.html", {
        "request": request,
        "page": "customers",
        "title": f"Cliente: {customer.name}",
        "customer": customer,
        "networks": networks,
        "credentials": credentials,
        "global_credentials": global_credentials,
        "devices": devices,
        "agents": agents,
    })


# ==========================================
# CREDENTIALS PAGE
# ==========================================

@router.get("/credentials", response_class=HTMLResponse)
async def credentials_page(request: Request):
    """Pagina credenziali globali"""
    customer_service = get_customer_service()
    
    # Ottieni credenziali globali (senza customer_id)
    credentials = customer_service.list_global_credentials()
    
    return templates.TemplateResponse("credentials.html", {
        "request": request,
        "page": "credentials",
        "title": "Credenziali Globali",
        "credentials": credentials,
    })


# ==========================================
# AGENTS PAGE
# ==========================================

@router.get("/agents", response_class=HTMLResponse)
async def agents_page(request: Request):
    """Pagina gestione agent"""
    return templates.TemplateResponse("agents.html", {
        "request": request,
        "page": "agents",
        "title": "Gestione Agent",
    })


@router.get("/backups", response_class=HTMLResponse)
async def backups_page(request: Request):
    """Pagina file browser backup"""
    return templates.TemplateResponse("backups.html", {
        "request": request,
        "page": "backups",
        "title": "File Backup",
    })


@router.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Pagina visualizzazione log server"""
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "page": "logs",
        "title": "Log Server",
    })


# ==========================================
# CONFIGURATION PAGES
# ==========================================

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Pagina configurazione"""
    import os
    settings = get_settings()
    dude = get_dude_service()
    
    # Leggi impostazioni extra da .env
    env_vars = {}
    env_path = ".env"
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip().strip('"').strip("'")
    
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "page": "settings",
        "title": "Configurazione",
        "settings": settings,
        "dude_connected": dude.is_connected,
        "ssl_enabled": env_vars.get("SSL_ENABLED", "false").lower() == "true",
        "ssl_cert_path": env_vars.get("SSL_CERT_PATH", "/app/data/certs/server.crt"),
        "ssl_key_path": env_vars.get("SSL_KEY_PATH", "/app/data/certs/server.key"),
        "auth_enabled": env_vars.get("AUTH_ENABLED", "false").lower() == "true",
        "admin_username": env_vars.get("ADMIN_USERNAME", "admin"),
    })


@router.get("/settings/webhooks", response_class=HTMLResponse)
async def webhooks_settings_page(request: Request):
    """Pagina configurazione webhook"""
    from ..services.webhook_service import get_webhook_service
    webhook_service = get_webhook_service()
    
    return templates.TemplateResponse("settings_webhooks.html", {
        "request": request,
        "page": "settings",
        "title": "Configurazione Webhook",
        "destinations": webhook_service.get_destinations(),
    })


@router.get("/settings/import-export", response_class=HTMLResponse)
async def import_export_page(request: Request):
    """Pagina import/export"""
    customer_service = get_customer_service()
    customers = customer_service.list_customers(active_only=True, limit=500)
    
    return templates.TemplateResponse("settings_import_export.html", {
        "request": request,
        "page": "settings",
        "title": "Import/Export",
        "customers": customers,
    })


# ==========================================
# DISCOVERY PAGES
# ==========================================

@router.get("/discovery", response_class=HTMLResponse)
async def discovery_page(request: Request):
    """Pagina discovery generale"""
    dude = get_dude_service()
    customer_service = get_customer_service()
    
    # Ottieni agenti disponibili
    agents = []
    if dude.is_connected:
        try:
            agents = dude.get_agents()
        except Exception as e:
            logger.warning(f"Error getting agents: {e}")
    
    # Ottieni clienti con le loro reti
    customers = customer_service.list_customers(active_only=True, limit=500)
    
    # Per ogni cliente, ottieni le reti (convertite in dict per JSON)
    customers_with_networks = []
    for customer in customers:
        networks = customer_service.list_networks(customer_id=customer.id, active_only=True)
        # Converti networks in lista di dict per serializzazione JSON
        networks_dict = [
            {"id": n.id, "name": n.name, "ip_network": n.ip_network, "network_type": n.network_type.value if hasattr(n.network_type, 'value') else n.network_type}
            for n in networks
        ]
        customers_with_networks.append({
            "customer": customer,
            "networks": networks_dict,
        })
    
    return templates.TemplateResponse("discovery.html", {
        "request": request,
        "page": "discovery",
        "title": "Network Discovery",
        "dude_connected": dude.is_connected,
        "agents": agents,
        "customers_with_networks": customers_with_networks,
    })


@router.get("/customers/{customer_id}/scans/{scan_id}", response_class=HTMLResponse)
async def scan_results_page(request: Request, customer_id: str, scan_id: str):
    """Pagina HTML per visualizzare i risultati di una scansione"""
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..config import get_settings
    
    customer_service = get_customer_service()
    customer = customer_service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    # Carica dettagli scansione
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id
        ).order_by(DiscoveredDevice.identity, DiscoveredDevice.address).all()
        
        scan_data = {
            "scan": {
                "id": scan.id,
                "network_cidr": scan.network_cidr,
                "scan_type": scan.scan_type,
                "devices_found": scan.devices_found,
                "status": scan.status,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            },
            "devices": [
                {
                    "id": d.id,
                    "address": d.address,
                    "mac_address": d.mac_address,
                    "identity": d.identity,
                    "hostname": d.hostname,
                    "reverse_dns": d.reverse_dns,
                    "platform": d.platform,
                    "board": d.board,
                    "interface": d.interface,
                    "source": d.source,
                    "imported": d.imported,
                    "open_ports": d.open_ports,
                    "os_family": d.os_family,
                    "os_version": d.os_version,
                    "vendor": d.vendor,
                    "model": d.model,
                    "category": d.category,
                    "device_type": d.device_type,
                    "identified_by": d.identified_by,
                    "cpu_cores": d.cpu_cores,
                    "ram_total_mb": d.ram_total_mb,
                    "disk_total_gb": d.disk_total_gb,
                    "serial_number": d.serial_number,
                }
                for d in devices
            ]
        }
    finally:
        session.close()
    
    return templates.TemplateResponse("scan_results.html", {
        "request": request,
        "page": "scans",
        "title": f"Risultati Scansione - {customer.name}",
        "customer": customer,
        "scan": scan_data["scan"],
        "devices": scan_data["devices"],
    })


@router.get("/customers/{customer_id}/discovery", response_class=HTMLResponse)
async def customer_discovery_page(request: Request, customer_id: str):
    """Pagina discovery per cliente specifico"""
    dude = get_dude_service()
    customer_service = get_customer_service()
    
    # Ottieni cliente
    customer = customer_service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    # Ottieni reti del cliente (convertite in dict per JSON)
    networks_db = customer_service.list_networks(customer_id=customer_id, active_only=True)
    networks = [
        {"id": n.id, "name": n.name, "ip_network": n.ip_network, "network_type": n.network_type.value if hasattr(n.network_type, 'value') else n.network_type}
        for n in networks_db
    ]
    
    # Ottieni agenti disponibili
    agents = []
    if dude.is_connected:
        try:
            agents = dude.get_agents()
        except Exception as e:
            logger.warning(f"Error getting agents: {e}")
    
    return templates.TemplateResponse("customer_discovery.html", {
        "request": request,
        "page": "customers",
        "title": f"Discovery - {customer.name}",
        "customer": customer,
        "networks": networks,
        "agents": agents,
        "dude_connected": dude.is_connected,
    })



@router.get("/customers/{customer_id}/agents/{agent_id}/mikrotik", response_class=HTMLResponse)
async def mikrotik_management(request: Request, customer_id: str, agent_id: str):
    """Pagina gestione MikroTik per una sonda"""
    from ..services.customer_service import get_customer_service
    
    customer_service = get_customer_service()
    
    # Ottieni cliente
    customer = customer_service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    # Ottieni sonda
    agent = customer_service.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    if agent.customer_id != customer_id:
        raise HTTPException(status_code=403, detail="Sonda non appartiene a questo cliente")
    
    return templates.TemplateResponse("router_detail.html", {
        "request": request,
        "page": "customers",
        "title": f"{agent.name} - MikroTik",
        "customer": customer,
        "agent": agent,
    })
