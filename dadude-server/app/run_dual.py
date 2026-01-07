#!/usr/bin/env python3
"""
DaDude - Dual Server Runner
Avvia entrambe le applicazioni FastAPI su porte separate

Porta 8000: Agent API (pubblico)
Porta 8001: Admin UI (privato)
"""
import asyncio
import signal
import sys
import os
from multiprocessing import Process
import uvicorn
from loguru import logger


def _read_env_file(env_path: str = "./data/.env") -> dict:
    """Legge il file .env e ritorna un dizionario"""
    env_vars = {}
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip().strip('"').strip("'")
    return env_vars


def get_ssl_config():
    """Legge configurazione SSL dal .env"""
    env_vars = _read_env_file()
    ssl_enabled = env_vars.get("SSL_ENABLED", "false").lower() == "true"
    ssl_cert = env_vars.get("SSL_CERT_PATH", "/app/data/certs/server.crt")
    ssl_key = env_vars.get("SSL_KEY_PATH", "/app/data/certs/server.key")
    
    if ssl_enabled and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        return {"ssl_certfile": ssl_cert, "ssl_keyfile": ssl_key}
    return {}


def run_agent_api():
    """Avvia Agent API su porta 8000"""
    ssl_config = get_ssl_config()
    uvicorn.run(
        "app.main_dual:agent_app",
        host="0.0.0.0",
        port=8000,
        log_level="info",
        access_log=True,
        reload=False,
        **ssl_config,
    )


def run_admin_ui():
    """Avvia Admin UI su porta 8001"""
    ssl_config = get_ssl_config()
    uvicorn.run(
        "app.main_dual:admin_app",
        host="0.0.0.0",
        port=8001,
        log_level="info",
        access_log=True,
        reload=False,
        **ssl_config,
    )


def main():
    """Avvia entrambi i server in processi separati"""
    ssl_config = get_ssl_config()
    protocol = "https" if ssl_config else "http"
    
    logger.info("=" * 70)
    logger.info("DaDude - Starting Dual Port Configuration")
    logger.info("=" * 70)
    logger.info(f"Agent API (public):  {protocol}://0.0.0.0:8000")
    logger.info(f"Admin UI (private):  {protocol}://0.0.0.0:8001")
    if ssl_config:
        logger.info(f"SSL Certificate: {ssl_config.get('ssl_certfile')}")
    logger.info("=" * 70)

    # Crea processi per entrambi i server
    agent_process = Process(target=run_agent_api, name="agent-api-8000")
    admin_process = Process(target=run_admin_ui, name="admin-ui-8001")

    # Avvia processi
    agent_process.start()
    admin_process.start()

    # Handler per shutdown graceful
    def shutdown_handler(signum, frame):
        logger.info("Shutdown signal received, stopping servers...")
        agent_process.terminate()
        admin_process.terminate()
        agent_process.join(timeout=10)
        admin_process.join(timeout=10)
        logger.info("All servers stopped")
        sys.exit(0)

    # Registra handler per SIGINT e SIGTERM
    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    logger.info("Both servers started successfully")
    logger.info("Press Ctrl+C to stop")

    # Mantieni processo principale attivo
    try:
        agent_process.join()
        admin_process.join()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
        shutdown_handler(None, None)


if __name__ == "__main__":
    main()
