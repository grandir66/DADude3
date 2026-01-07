"""
DaDude - System Router
API endpoints per gestione sistema e configurazione
"""
from fastapi import APIRouter, HTTPException, Depends, Header
from typing import Optional
from datetime import datetime
from loguru import logger

from ..config import get_settings, Settings
from ..models import DudeServerInfo, StatusResponse
from ..services import get_dude_service, get_sync_service
from ..services.settings_service import get_settings_service
from pydantic import BaseModel


class DudeConfigUpdate(BaseModel):
    """Schema per aggiornamento configurazione Dude"""
    host: str
    port: int = 8728
    username: str
    password: str
    use_ssl: bool = False

router = APIRouter(prefix="/system", tags=["System"])


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Verifica API key se configurata"""
    settings = get_settings()
    if not settings.dadude_api_key:
        return True  # Nessuna API key configurata = accesso libero
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API key required")
    if x_api_key != settings.dadude_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


def optional_api_key(x_api_key: Optional[str] = Header(None)) -> bool:
    """Verifica API key solo se fornita (per endpoint accessibili anche da UI)"""
    settings = get_settings()
    if not settings.dadude_api_key:
        return True  # Nessuna API key configurata
    if x_api_key and x_api_key != settings.dadude_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return True


@router.get("/health")
async def health_check():
    """
    Controllo stato salute del sistema.
    """
    dude = get_dude_service()
    sync = get_sync_service()
    
    return {
        "status": "healthy" if dude.is_connected else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {
            "dude_connection": {
                "status": "up" if dude.is_connected else "down",
                "host": get_settings().dude_host,
            },
            "sync_service": {
                "status": "running",
                "last_sync": sync.last_sync.isoformat() if sync.last_sync else None,
                "devices_cached": len(sync.devices),
                "probes_cached": len(sync.probes),
            },
        },
    }


@router.get("/info", response_model=DudeServerInfo)
async def get_server_info():
    """
    Ottiene informazioni dettagliate sul server Dude.
    """
    try:
        dude = get_dude_service()
        return dude.get_server_info()
    except Exception as e:
        logger.error(f"Error getting server info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
async def get_config(authorized: bool = Depends(verify_api_key)):
    """
    Ottiene configurazione corrente (richiede API key).
    """
    settings = get_settings()
    
    return {
        "dude_host": settings.dude_host,
        "dude_port": settings.dude_api_port,
        "dude_ssl": settings.dude_use_ssl,
        "poll_interval": settings.poll_interval,
        "full_sync_interval": settings.full_sync_interval,
        "log_level": settings.log_level,
        "webhook_configured": bool(settings.webhook_url),
    }


@router.post("/sync", response_model=StatusResponse)
async def force_sync(authorized: bool = Depends(optional_api_key)):
    """
    Forza sincronizzazione immediata con Dude Server.
    """
    try:
        sync = get_sync_service()
        await sync.full_sync()
        
        return StatusResponse(
            status="success",
            message="Sync completed",
            data={
                "devices": len(sync.devices),
                "probes": len(sync.probes),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )
    except Exception as e:
        logger.error(f"Error during forced sync: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reconnect", response_model=StatusResponse)
async def reconnect_dude(authorized: bool = Depends(optional_api_key)):
    """
    Riconnette al server Dude.
    """
    try:
        dude = get_dude_service()
        dude.disconnect()
        
        if dude.connect():
            return StatusResponse(status="success", message="Reconnected to Dude Server")
        else:
            raise HTTPException(status_code=503, detail="Failed to reconnect")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error reconnecting: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_stats():
    """
    Statistiche di utilizzo del sistema.
    """
    sync = get_sync_service()
    devices = sync.devices
    probes = sync.probes
    
    # Calcola uptime stats
    devices_up = len([d for d in devices if d.status.value == "up"])
    devices_down = len([d for d in devices if d.status.value == "down"])
    
    return {
        "devices": {
            "total": len(devices),
            "up": devices_up,
            "down": devices_down,
            "uptime_percentage": round(devices_up / len(devices) * 100, 2) if devices else 0,
        },
        "probes": {
            "total": len(probes),
            "ok": len([p for p in probes if p.status.value == "ok"]),
            "warning": len([p for p in probes if p.status.value == "warning"]),
            "critical": len([p for p in probes if p.status.value == "critical"]),
        },
        "system": {
            "uptime": "N/A",  # TODO: track uptime
            "last_sync": sync.last_sync.isoformat() if sync.last_sync else None,
        },
    }


@router.post("/test-connection")
async def test_dude_connection(config: DudeConfigUpdate):
    """
    Testa la connessione al server Dude con le credenziali fornite.
    Non salva la configurazione.
    """
    import routeros_api
    
    try:
        # Prova connessione
        port = 8729 if config.use_ssl else config.port
        
        connection = routeros_api.RouterOsApiPool(
            host=config.host,
            username=config.username,
            password=config.password,
            port=port,
            use_ssl=config.use_ssl,
            ssl_verify=False,
            plaintext_login=True,
        )
        
        api = connection.get_api()
        
        # Test: ottieni info sistema
        identity = api.get_resource('/system/identity')
        identity_data = identity.get()
        server_name = identity_data[0].get('name', 'Unknown') if identity_data else 'Unknown'
        
        # Chiudi connessione
        connection.disconnect()
        
        return {
            "success": True,
            "server_info": f"Connesso a: {server_name}",
        }
        
    except Exception as e:
        logger.error(f"Test connection failed: {e}")
        return {
            "success": False,
            "error": str(e),
        }


@router.post("/dude-config")
async def save_dude_config(config: DudeConfigUpdate):
    """
    Salva la configurazione Dude e tenta la riconnessione.
    """
    settings_service = get_settings_service()
    
    # Test connessione prima di salvare
    test_result = await test_dude_connection(config)
    
    if not test_result["success"]:
        raise HTTPException(
            status_code=400,
            detail=f"Connessione fallita: {test_result.get('error', 'Errore sconosciuto')}"
        )
    
    # Salva configurazione
    success = settings_service.set_dude_config(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
        use_ssl=config.use_ssl,
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Errore salvataggio configurazione")
    
    # Riconnetti con nuove credenziali
    try:
        dude = get_dude_service()
        dude.disconnect()
        
        # Aggiorna impostazioni runtime
        dude.host = config.host
        dude.port = config.port
        dude.username = config.username
        dude.password = config.password
        dude.use_ssl = config.use_ssl
        
        connected = dude.connect()
        
        if connected:
            # Esegui sync iniziale
            sync = get_sync_service()
            await sync.full_sync()
        
        return {
            "success": True,
            "connected": connected,
            "message": "Configurazione salvata" + (" e connesso" if connected else ", riavvia per applicare"),
        }
        
    except Exception as e:
        logger.error(f"Error reconnecting after config save: {e}")
        return {
            "success": True,
            "connected": False,
            "message": f"Configurazione salvata, riavvia l'applicazione: {e}",
        }


@router.get("/dude-config")
async def get_dude_config(authorized: bool = Depends(verify_api_key)):
    """
    Ottiene la configurazione corrente del Dude (senza password).
    """
    settings_service = get_settings_service()
    config = settings_service.get_dude_config()
    
    # Non esporre la password
    config["password"] = "********" if config.get("password") else ""
    
    return config


# ==========================================
# LOG VIEWER ENDPOINTS
# ==========================================

@router.get("/logs")
async def get_logs(
    lines: int = 500,
    level: Optional[str] = None,
    search: Optional[str] = None,
    tail: bool = True,
    authorized: bool = Depends(optional_api_key)
):
    """
    Legge i log del server.
    
    Args:
        lines: Numero di righe da leggere (default: 500)
        level: Filtra per livello di log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        search: Cerca testo nei log
        tail: Se True, legge dalla fine del file (ultime righe)
    """
    from pathlib import Path
    import gzip
    
    settings = get_settings()
    log_file = Path(settings.log_file)
    
    # Cerca anche file compressi (loguru crea file .gz per rotazione)
    log_files = []
    if log_file.exists():
        log_files.append(log_file)
    
    # Cerca file compressi recenti
    log_dir = log_file.parent
    if log_dir.exists():
        for gz_file in sorted(log_dir.glob(f"{log_file.name}.*.gz"), reverse=True)[:2]:
            log_files.append(gz_file)
    
    if not log_files:
        return {
            "logs": [],
            "total_lines": 0,
            "file": str(log_file),
            "error": "File di log non trovato"
        }
    
    all_logs = []
    
    # Leggi tutti i file di log (dal più recente al più vecchio)
    for log_path in log_files:
        try:
            if log_path.suffix == '.gz':
                # File compresso
                with gzip.open(log_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    file_logs = f.readlines()
            else:
                # File normale
                with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_logs = f.readlines()
            
            all_logs.extend(file_logs)
            
            # Se abbiamo abbastanza righe, fermati
            if len(all_logs) >= lines * 2:  # Leggi un po' di più per avere margine
                break
        except Exception as e:
            logger.warning(f"Errore lettura log file {log_path}: {e}")
            continue
    
    # Se tail=True, prendi le ultime righe
    if tail and len(all_logs) > lines:
        all_logs = all_logs[-lines:]
    
    # Applica filtri
    filtered_logs = []
    for log_line in all_logs:
        log_line = log_line.strip()
        if not log_line:
            continue
        
        # Filtro per livello
        if level:
            level_upper = level.upper()
            if level_upper not in log_line.upper():
                continue
        
        # Filtro per ricerca testo
        if search:
            if search.lower() not in log_line.lower():
                continue
        
        filtered_logs.append(log_line)
    
    # Limita il numero di righe restituite
    if len(filtered_logs) > lines:
        filtered_logs = filtered_logs[-lines:]
    
    return {
        "logs": filtered_logs,
        "total_lines": len(filtered_logs),
        "file": str(log_file),
        "level_filter": level,
        "search_filter": search,
    }


@router.get("/logs/levels")
async def get_log_levels(authorized: bool = Depends(optional_api_key)):
    """
    Restituisce i livelli di log disponibili e il conteggio per livello.
    """
    from pathlib import Path
    import gzip
    import re
    
    settings = get_settings()
    log_file = Path(settings.log_file)
    
    log_files = []
    if log_file.exists():
        log_files.append(log_file)
    
    log_dir = log_file.parent
    if log_dir.exists():
        for gz_file in sorted(log_dir.glob(f"{log_file.name}.*.gz"), reverse=True)[:1]:
            log_files.append(gz_file)
    
    levels_count = {
        "DEBUG": 0,
        "INFO": 0,
        "WARNING": 0,
        "ERROR": 0,
        "CRITICAL": 0,
    }
    
    # Pattern per riconoscere i livelli nei log di loguru
    level_pattern = re.compile(r'\|\s*(DEBUG|INFO|WARNING|ERROR|CRITICAL)\s*\|', re.IGNORECASE)
    
    for log_path in log_files:
        try:
            if log_path.suffix == '.gz':
                with gzip.open(log_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        match = level_pattern.search(line)
                        if match:
                            level = match.group(1).upper()
                            if level in levels_count:
                                levels_count[level] += 1
        except Exception as e:
            logger.warning(f"Errore conteggio livelli log {log_path}: {e}")
            continue
    
    return {
        "levels": levels_count,
        "total": sum(levels_count.values())
    }
