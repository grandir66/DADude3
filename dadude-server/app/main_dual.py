"""
DaDude - Dual Port Application
Main FastAPI Application with separated Agent API (8000) and Admin UI (8001)

Separazione per sicurezza:
- Porta 8000: Agent API (esposta su Internet, solo endpoint agent)
- Porta 8001: Admin UI + Management API (solo rete interna)
"""
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from .auth import AuthMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
import sys
import os
from pathlib import Path

from .config import get_settings
from .services import get_dude_service, get_sync_service
from .services.websocket_hub import get_websocket_hub
from .routers import (
    devices, probes, alerts, webhook, system, customers,
    import_export, dashboard, discovery, mikrotik, inventory, agents,
    settings as settings_router, device_backup, hp_aruba, cleanup, backup,
    unified_scanner
)


# Configura logging
def setup_logging():
    settings = get_settings()

    # Rimuovi handler default
    logger.remove()

    # Console output
    logger.add(
        sys.stderr,
        level=settings.log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
    )

    # File output
    log_path = Path(settings.log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        settings.log_file,
        level=settings.log_level,
        rotation="10 MB",
        retention="7 days",
        compression="gz",
    )


# Shared services state - use asyncio.Lock per thread safety
_services_lock = None
_services_started = False

async def _init_shared_services():
    """Initialize shared services ONCE for both apps"""
    global _services_started, _services_lock

    if _services_lock is None:
        _services_lock = asyncio.Lock()

    async with _services_lock:
        if _services_started:
            logger.info("Services already initialized - skipping")
            return

        setup_logging()
        settings = get_settings()

        # Crea directory necessarie
        Path("./data").mkdir(exist_ok=True)
        Path("./logs").mkdir(exist_ok=True)

        logger.info("=" * 60)
        logger.info("DaDude - Initializing shared services")
        logger.info("=" * 60)

        # Avvia WebSocket Hub (singleton)
        ws_hub = get_websocket_hub()
        await ws_hub.start()
        logger.info("✓ WebSocket Hub started (shared)")

        # Connetti a Dude Server (opzionale)
        dude = get_dude_service()
        if dude.connect():
            logger.success(f"✓ Connected to Dude Server at {settings.dude_host}")

            # Avvia sync service
            sync = get_sync_service()
            await sync.full_sync()
            sync.start()
            logger.info("✓ Sync service started")
        else:
            logger.warning("Running in offline mode - Dude Server not available")

        _services_started = True
        logger.info("=" * 60)


@asynccontextmanager
async def agent_lifespan(app: FastAPI):
    """Gestione lifecycle per Agent API"""
    # Initialize shared services
    await _init_shared_services()
    
    # Avvia Device Monitoring Service (su Agent API perché condivide il WebSocket Hub con gli agent)
    from .services.device_monitoring_service import get_monitoring_service
    monitoring_service = get_monitoring_service()
    await monitoring_service.start_async()
    logger.info("✓ Device Monitoring Service started")

    logger.info("DaDude Agent API - Ready on port 8000")

    yield

    # Shutdown
    logger.info("Shutting down Agent API...")
    
    # Ferma monitoring service
    try:
        monitoring_service.stop()
        logger.info("Device Monitoring Service stopped")
    except Exception as e:
        logger.warning(f"Error stopping monitoring service: {e}")


@asynccontextmanager
async def admin_lifespan(app: FastAPI):
    """Gestione lifecycle per Admin UI"""
    # Initialize shared services
    await _init_shared_services()

    logger.info("DaDude Admin UI - Ready on port 8001")

    yield

    # Shutdown
    logger.info("Shutting down Admin UI...")

    # Ferma servizi solo se questa è l'ultima app a chiudere
    ws_hub = get_websocket_hub()
    await ws_hub.stop()
    logger.info("WebSocket Hub stopped")

    sync = get_sync_service()
    sync.stop()

    dude = get_dude_service()
    dude.disconnect()

    logger.info("DaDude shutdown complete")


# ==========================================
# AGENT API APPLICATION (Porta 8000)
# ==========================================

agent_app = FastAPI(
    title="DaDude Agent API",
    description="""
## Agent API - Network Inventory Agent Communication

**SOLO PER AGENT - Esposto su Internet**

Endpoint per comunicazione con agent distribuiti:
- Registrazione e enrollment agent
- WebSocket connessioni bidirezionali
- Heartbeat e health check
- Comandi remoti

**Autenticazione**: Token + mTLS certificati
    """,
    version="3.0.0",
    lifespan=agent_lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS per Agent API
agent_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Gli agent possono venire da qualsiasi IP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Exception handler
@agent_app.exception_handler(Exception)
async def agent_exception_handler(request: Request, exc: Exception):
    logger.error(f"Agent API unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )

# Registra router agents (WebSocket connections, registration, commands)
agent_app.include_router(agents.router, prefix="/api/v1")

# Registra anche customers router per endpoint che usano WebSocket Hub
# (scan-customer-networks, test, etc.)
agent_app.include_router(customers.router, prefix="/api/v1")

# Registra inventory router per auto-detect che usa WebSocket Hub
agent_app.include_router(inventory.router, prefix="/api/v1")

# Registra unified_scanner router - richiede WebSocket Hub per comunicare con agent
agent_app.include_router(unified_scanner.router, prefix="/api/v1")

# Health check per agent
@agent_app.get("/health", tags=["Health"])
async def agent_health_check():
    """Health check per Agent API"""
    ws_hub = get_websocket_hub()
    return {
        "status": "healthy",
        "service": "agent-api",
        "port": 8000,
        "websocket_hub": {
            "active": True,
            "connected_agents": await ws_hub.connected_count() if ws_hub else 0,
        }
    }

@agent_app.get("/", tags=["Root"])
async def agent_root():
    """Root endpoint Agent API"""
    return {
        "service": "DaDude Agent API",
        "version": "3.0.0",
        "port": 8000,
        "description": "Agent communication endpoint",
        "docs": "/docs",
        "health": "/health",
    }


# ==========================================
# ADMIN UI APPLICATION (Porta 8001)
# ==========================================

admin_app = FastAPI(
    title="DaDude Admin UI",
    description="""
## DaDude Admin - Management Interface

**SOLO RETE INTERNA - NON esporre su Internet**

Dashboard e API per gestione sistema:
- Dashboard web UI
- Gestione clienti multi-tenant
- Inventario dispositivi
- Configurazione reti e credenziali
- Import/Export dati
- Monitoraggio alert

**Autenticazione**: Da implementare (Basic Auth / API Key)
    """,
    version="3.0.0",
    lifespan=admin_lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS per Admin UI
admin_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth Middleware per Admin UI (dopo CORS, prima delle route)
admin_app.add_middleware(AuthMiddleware)

# No middleware needed - we'll override the route directly below

# Exception handler
@admin_app.exception_handler(Exception)
async def admin_exception_handler(request: Request, exc: Exception):
    logger.error(f"Admin UI unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error", "detail": str(exc)},
    )

# Add Admin-specific proxy endpoints BEFORE including agents router
# These endpoints proxy requests to the Agent API's WebSocket Hub
import httpx

def _get_agent_api_base_url() -> str:
    """Get the base URL for Agent API, supporting both HTTP and HTTPS"""
    # Read SSL settings from data/.env
    ssl_enabled = False
    env_path = Path("./data/.env")
    if env_path.exists():
        with open(env_path) as f:
            for line in f:
                if line.startswith("SSL_ENABLED="):
                    ssl_enabled = line.strip().split("=")[1].lower() == "true"
                    break
    
    protocol = "https" if ssl_enabled else "http"
    return f"{protocol}://localhost:8000"

def _get_httpx_client(**kwargs) -> httpx.AsyncClient:
    """Get httpx client with SSL verification disabled for self-signed certs"""
    return httpx.AsyncClient(verify=False, **kwargs)

@admin_app.get("/api/v1/admin/agents/ws/connected", tags=["Admin"])
async def admin_ws_connected():
    """
    Query connected agents via WebSocket Hub (Admin UI version).

    This endpoint proxies the request to the Agent API's WebSocket Hub
    since Admin UI runs in a separate process.
    """
    logger.info("Admin UI querying ws/connected via proxy")
    try:
        base_url = _get_agent_api_base_url()
        async with _get_httpx_client(timeout=5.0) as client:
            response = await client.get(f"{base_url}/api/v1/agents/ws/connected")

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Proxy successful: {data.get('count', 0)} agents")
                return data
            else:
                logger.error(f"Proxy failed: {response.status_code}")
                return {"count": 0, "agents": [], "error": f"Agent API returned {response.status_code}"}
    except Exception as e:
        logger.error(f"Proxy error: {e}")
        return {"count": 0, "agents": [], "error": str(e)}


@admin_app.post("/api/v1/admin/agents/ws/{agent_id}/command", tags=["Admin"])
async def admin_ws_command(agent_id: str, request: Request):
    """
    Send command to agent via WebSocket (Admin UI proxy version).

    This endpoint proxies the request to the Agent API's WebSocket Hub
    since Admin UI runs in a separate process.
    """
    logger.info(f"Admin UI sending command to {agent_id} via proxy")
    try:
        base_url = _get_agent_api_base_url()
        body = await request.json()
        async with _get_httpx_client(timeout=30.0) as client:
            response = await client.post(
                f"{base_url}/api/v1/agents/ws/{agent_id}/command",
                json=body
            )

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Command proxy successful for {agent_id}")
                return data
            else:
                logger.error(f"Command proxy failed: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.content else {"error": "Proxy failed"}
                )
    except Exception as e:
        logger.error(f"Command proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.post("/api/v1/admin/agents/{agent_db_id}/exec", tags=["Admin"])
async def admin_exec_command(agent_db_id: str, request: Request):
    """
    Execute command on agent (Admin UI proxy version).

    This endpoint proxies the request to the Agent API's WebSocket Hub
    since Admin UI runs in a separate process.
    """
    logger.info(f"Admin UI executing command on agent {agent_db_id} via proxy")
    try:
        base_url = _get_agent_api_base_url()
        # Forward query parameters from original request
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/agents/{agent_db_id}/exec?{query_string}"

        async with _get_httpx_client(timeout=90.0) as client:  # Longer timeout for command execution
            response = await client.post(url)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Exec proxy successful for agent {agent_db_id}")
                return data
            else:
                logger.error(f"Exec proxy failed: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.content else {"error": "Proxy failed"}
                )
    except Exception as e:
        logger.error(f"Exec proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.get("/api/v1/admin/agents/{agent_db_id}/verify-version", tags=["Admin"])
async def admin_verify_version(agent_db_id: str):
    """
    Verify agent version (Admin UI proxy version).

    This endpoint proxies the request to the Agent API's WebSocket Hub
    since Admin UI runs in a separate process.
    """
    logger.info(f"Admin UI verifying version for agent {agent_db_id} via proxy")
    try:
        base_url = _get_agent_api_base_url()
        async with _get_httpx_client(timeout=10.0) as client:
            response = await client.get(f"{base_url}/api/v1/agents/{agent_db_id}/verify-version")

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Verify-version proxy successful for agent {agent_db_id}")
                return data
            else:
                logger.error(f"Verify-version proxy failed: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.content else {"error": "Proxy failed"}
                )
    except Exception as e:
        logger.error(f"Verify-version proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: Network Scan (uses WebSocket Hub)
# ==========================================

@admin_app.post("/api/v1/customers/agents/{agent_id}/scan-customer-networks", tags=["Admin"])
async def admin_scan_customer_networks(agent_id: str, request: Request):
    """
    Proxy network scan to Agent API (port 8000).
    
    This endpoint requires WebSocket Hub access, which is only available
    in the Agent API process.
    """
    logger.info(f"Admin UI proxying network scan for agent {agent_id}")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/customers/agents/{agent_id}/scan-customer-networks"
        if query_string:
            url += f"?{query_string}"
        
        # Longer timeout for network scans (can take minutes)
        async with _get_httpx_client(timeout=300.0) as client:
            response = await client.post(url)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Network scan proxy successful for agent {agent_id}")
                return data
            else:
                logger.error(f"Network scan proxy failed: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.content else {"error": "Proxy failed"}
                )
    except httpx.ReadTimeout:
        logger.error(f"Network scan proxy timeout for agent {agent_id}")
        return JSONResponse(
            status_code=504,
            content={"error": "Scan timeout - the network scan took too long"}
        )
    except Exception as e:
        logger.error(f"Network scan proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.post("/api/v1/customers/agents/{agent_id}/test", tags=["Admin"])
async def admin_test_agent(agent_id: str, request: Request):
    """
    Proxy agent test to Agent API (port 8000).
    """
    logger.info(f"Admin UI proxying agent test for {agent_id}")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/customers/agents/{agent_id}/test"
        if query_string:
            url += f"?{query_string}"
        
        async with _get_httpx_client(timeout=60.0) as client:
            response = await client.post(url)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"Agent test proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: Agent trigger-update (uses WebSocket)  
# ==========================================

@admin_app.post("/api/v1/agents/{agent_db_id}/trigger-update", tags=["Admin"])
async def admin_trigger_agent_update(agent_db_id: str):
    """
    Proxy trigger-update to Agent API (port 8000).
    """
    logger.info(f"Admin UI proxying trigger-update for agent {agent_db_id}")
    try:
        base_url = _get_agent_api_base_url()
        async with _get_httpx_client(timeout=120.0) as client:
            response = await client.post(f"{base_url}/api/v1/agents/{agent_db_id}/trigger-update")
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"Trigger-update proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: Inventory Auto-Detect (uses WebSocket Hub via agent_service)
# ==========================================

@admin_app.post("/api/v1/inventory/auto-detect", tags=["Admin"])
async def admin_auto_detect(request: Request):
    """
    Proxy auto-detect to Agent API (port 8000).
    
    Auto-detect uses agent_service which requires WebSocket Hub access.
    """
    logger.info("Admin UI proxying auto-detect request")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/inventory/auto-detect"
        if query_string:
            url += f"?{query_string}"
        
        body = await request.json()
        
        async with _get_httpx_client(timeout=180.0) as client:
            response = await client.post(url, json=body)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Auto-detect proxy successful")
                return data
            else:
                logger.error(f"Auto-detect proxy failed: {response.status_code}")
                return JSONResponse(
                    status_code=response.status_code,
                    content=response.json() if response.content else {"error": "Proxy failed"}
                )
    except Exception as e:
        logger.error(f"Auto-detect proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.post("/api/v1/inventory/auto-detect-batch", tags=["Admin"])
async def admin_auto_detect_batch(request: Request):
    """
    Proxy batch auto-detect to Agent API (port 8000).
    """
    logger.info("Admin UI proxying batch auto-detect request")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/inventory/auto-detect-batch"
        if query_string:
            url += f"?{query_string}"
        
        body = await request.json()
        
        async with _get_httpx_client(timeout=600.0) as client:  # Longer for batch
            response = await client.post(url, json=body)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"Auto-detect batch proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.post("/api/v1/inventory/probe", tags=["Admin"])
async def admin_probe_device(request: Request):
    """
    Proxy device probe to Agent API (port 8000).
    """
    logger.info("Admin UI proxying probe request")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/inventory/probe"
        if query_string:
            url += f"?{query_string}"
        
        body = await request.json()
        
        async with _get_httpx_client(timeout=120.0) as client:
            response = await client.post(url, json=body)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"Probe proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: SSH Advanced Scan (needs WebSocket Hub)
# ==========================================

@admin_app.post("/api/v1/inventory/ssh-advanced-scan", tags=["Admin"])
async def admin_ssh_advanced_scan(request: Request):
    """
    Proxy SSH advanced scan to Agent API (port 8000).
    
    SSH advanced scan requires WebSocket Hub access to communicate with agents.
    """
    logger.info("Admin UI proxying SSH advanced scan request")
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/inventory/ssh-advanced-scan"
        if query_string:
            url += f"?{query_string}"
        
        body = await request.json()
        
        async with _get_httpx_client(timeout=180.0) as client:
            response = await client.post(url, json=body)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"SSH advanced scan proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: Unified Scanner (needs WebSocket Hub)
# ==========================================

@admin_app.post("/api/v1/unified-scanner/scan", tags=["Admin"])
async def admin_unified_scanner_scan(request: Request):
    """
    Proxy unified scanner to Agent API (port 8000).
    
    Unified scanner requires WebSocket Hub access to communicate with agents.
    """
    logger.info("Admin UI proxying unified scanner request")
    try:
        base_url = _get_agent_api_base_url()
        body = await request.json()
        
        async with _get_httpx_client(timeout=180.0) as client:
            response = await client.post(f"{base_url}/api/v1/unified-scanner/scan", json=body)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except httpx.ReadTimeout:
        logger.error("Unified scanner proxy timeout")
        return JSONResponse(
            status_code=504,
            content={"error": "Scan timeout - the scan took too long"}
        )
    except Exception as e:
        logger.error(f"Unified scanner proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@admin_app.get("/api/v1/unified-scanner/results/{device_id}", tags=["Admin"])
async def admin_unified_scanner_results(device_id: str):
    """
    Proxy unified scanner results to Agent API (port 8000).
    """
    try:
        base_url = _get_agent_api_base_url()
        async with _get_httpx_client(timeout=30.0) as client:
            response = await client.get(f"{base_url}/api/v1/unified-scanner/results/{device_id}")
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else {}
            )
    except Exception as e:
        logger.error(f"Unified scanner results proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# PROXY: Customer Agents List (needs WebSocket Hub for real-time status)
# ==========================================

@admin_app.get("/api/v1/customers/{customer_id}/agents", tags=["Admin"])
async def admin_list_customer_agents(customer_id: str, request: Request):
    """
    Proxy customer agents list to Agent API (port 8000).
    
    This endpoint needs WebSocket Hub access to show real-time connection status.
    """
    try:
        base_url = _get_agent_api_base_url()
        query_string = str(request.url.query)
        url = f"{base_url}/api/v1/customers/{customer_id}/agents"
        if query_string:
            url += f"?{query_string}"
        
        async with _get_httpx_client(timeout=30.0) as client:
            response = await client.get(url)
            return JSONResponse(
                status_code=response.status_code,
                content=response.json() if response.content else []
            )
    except Exception as e:
        logger.error(f"Customer agents proxy error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Registra tutti gli altri router AFTER proxy endpoints
admin_app.include_router(devices.router, prefix="/api/v1")
admin_app.include_router(probes.router, prefix="/api/v1")
admin_app.include_router(alerts.router, prefix="/api/v1")
admin_app.include_router(webhook.router, prefix="/api/v1")
admin_app.include_router(system.router, prefix="/api/v1")
admin_app.include_router(customers.router, prefix="/api/v1")
admin_app.include_router(mikrotik.router, prefix="/api/v1")
admin_app.include_router(hp_aruba.router, prefix="/api/v1")
admin_app.include_router(inventory.router, prefix="/api/v1")
admin_app.include_router(import_export.router, prefix="/api/v1")
admin_app.include_router(discovery.router, prefix="/api/v1")

# IMPORTANTE: Include anche agents router per endpoints di management
# (pending, outdated, approve, etc.)
# This is registered AFTER proxy endpoints so proxies take precedence
admin_app.include_router(agents.router, prefix="/api/v1")

# Dashboard (senza prefisso API)
admin_app.include_router(dashboard.router)
admin_app.include_router(settings_router.router, prefix="/api/v1")
admin_app.include_router(device_backup.router, prefix="/api/v1")
admin_app.include_router(cleanup.router, prefix="/api/v1")  # Device cleanup endpoints
admin_app.include_router(backup.router, prefix="/api/v1")  # Backup and versioning endpoints
admin_app.include_router(unified_scanner.router, prefix="/api/v1")  # v3.0.0: Unified multi-protocol scanner

# Monta directory static se esiste
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    admin_app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Health check per admin
@admin_app.get("/health", tags=["Health"])
async def admin_health_check():
    """Health check per Admin UI"""
    dude = get_dude_service()
    sync = get_sync_service()

    return {
        "status": "healthy" if dude.is_connected else "degraded",
        "service": "admin-ui",
        "port": 8001,
        "dude_connected": dude.is_connected,
        "devices_cached": len(sync.devices),
        "probes_cached": len(sync.probes),
        "last_sync": sync.last_sync.isoformat() if sync.last_sync else None,
    }

@admin_app.get("/api", tags=["Root"])
async def admin_api_info():
    """Endpoint info API"""
    return {
        "name": "DaDude Admin API",
        "version": "1.1.0",
        "description": "Management and Administration Interface",
        "docs": "/docs",
        "dashboard": "/dashboard",
        "health": "/health",
    }
