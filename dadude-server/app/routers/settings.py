"""
DaDude - Settings API Router
Gestione configurazione sistema via web
"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional
from loguru import logger
import os
import subprocess

router = APIRouter(prefix="/settings", tags=["Settings"])


class DudeSettings(BaseModel):
    """Impostazioni connessione Dude Server"""
    dude_host: Optional[str] = None
    dude_api_port: Optional[int] = None
    dude_use_ssl: Optional[bool] = None
    dude_username: Optional[str] = None
    dude_password: Optional[str] = None


class DaDudeSettings(BaseModel):
    """Impostazioni server DaDude"""
    dadude_host: Optional[str] = None
    dadude_port: Optional[int] = None
    dadude_api_key: Optional[str] = None
    poll_interval: Optional[int] = None
    full_sync_interval: Optional[int] = None
    connection_timeout: Optional[int] = None
    log_level: Optional[str] = None


class SSLSettings(BaseModel):
    """Impostazioni SSL/HTTPS"""
    ssl_enabled: Optional[bool] = None
    ssl_cert_path: Optional[str] = None
    ssl_key_path: Optional[str] = None


class AuthSettings(BaseModel):
    """Impostazioni autenticazione"""
    auth_enabled: Optional[bool] = None
    admin_username: Optional[str] = None
    admin_password: Optional[str] = None  # Solo per creazione/modifica


def _read_env_file(env_path: str = ".env") -> dict:
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


def _write_env_file(env_vars: dict, env_path: str = ".env"):
    """Scrive il dizionario nel file .env"""
    with open(env_path, "w") as f:
        for key, value in sorted(env_vars.items()):
            if value is not None:
                # Non aggiungere virgolette ai valori
                f.write(f'{key}={value}\n')


@router.get("/current")
async def get_current_settings():
    """
    Ottiene le impostazioni correnti dal file .env
    """
    from ..config import get_settings
    settings = get_settings()
    
    # Leggi anche le impostazioni extra non in pydantic
    env_vars = _read_env_file()
    
    return {
        "dude": {
            "host": settings.dude_host,
            "api_port": settings.dude_api_port,
            "use_ssl": settings.dude_use_ssl,
            "username": settings.dude_username,
            "password": "***" if settings.dude_password else "",
        },
        "dadude": {
            "host": settings.dadude_host,
            "port": settings.dadude_port,
            "api_key": "***" if settings.dadude_api_key else "",
        },
        "polling": {
            "poll_interval": settings.poll_interval,
            "full_sync_interval": settings.full_sync_interval,
            "connection_timeout": settings.connection_timeout,
        },
        "logging": {
            "log_level": settings.log_level,
            "log_file": settings.log_file,
        },
        "ssl": {
            "enabled": env_vars.get("SSL_ENABLED", "false").lower() == "true",
            "cert_path": env_vars.get("SSL_CERT_PATH", "/app/data/certs/server.crt"),
            "key_path": env_vars.get("SSL_KEY_PATH", "/app/data/certs/server.key"),
        },
        "auth": {
            "enabled": env_vars.get("AUTH_ENABLED", "false").lower() == "true",
            "admin_username": env_vars.get("ADMIN_USERNAME", "admin"),
        },
    }


@router.post("/dude")
async def update_dude_settings(settings: DudeSettings):
    """
    Aggiorna le impostazioni di connessione al Dude Server
    """
    env_vars = _read_env_file()
    
    if settings.dude_host is not None:
        env_vars["DUDE_HOST"] = settings.dude_host
    if settings.dude_api_port is not None:
        env_vars["DUDE_API_PORT"] = str(settings.dude_api_port)
    if settings.dude_use_ssl is not None:
        env_vars["DUDE_USE_SSL"] = "true" if settings.dude_use_ssl else "false"
    if settings.dude_username is not None:
        env_vars["DUDE_USERNAME"] = settings.dude_username
    if settings.dude_password is not None:
        env_vars["DUDE_PASSWORD"] = settings.dude_password
    
    _write_env_file(env_vars)
    logger.info("Dude settings updated")
    
    return {"success": True, "message": "Impostazioni Dude aggiornate. Riavvia il servizio per applicare."}


@router.post("/dadude")
async def update_dadude_settings(settings: DaDudeSettings):
    """
    Aggiorna le impostazioni del server DaDude
    """
    env_vars = _read_env_file()
    
    if settings.dadude_host is not None:
        env_vars["DADUDE_HOST"] = settings.dadude_host
    if settings.dadude_port is not None:
        env_vars["DADUDE_PORT"] = str(settings.dadude_port)
    if settings.dadude_api_key is not None:
        env_vars["DADUDE_API_KEY"] = settings.dadude_api_key
    if settings.poll_interval is not None:
        env_vars["POLL_INTERVAL"] = str(settings.poll_interval)
    if settings.full_sync_interval is not None:
        env_vars["FULL_SYNC_INTERVAL"] = str(settings.full_sync_interval)
    if settings.connection_timeout is not None:
        env_vars["CONNECTION_TIMEOUT"] = str(settings.connection_timeout)
    if settings.log_level is not None:
        env_vars["LOG_LEVEL"] = settings.log_level
    
    _write_env_file(env_vars)
    logger.info("DaDude settings updated")
    
    return {"success": True, "message": "Impostazioni DaDude aggiornate. Riavvia il servizio per applicare."}


@router.post("/ssl/generate")
async def generate_ssl_certificate(
    common_name: str = Query("dadude.local", description="Common Name per il certificato"),
    days: int = Query(365, description="Validità in giorni"),
):
    """
    Genera un certificato SSL autofirmato
    """
    cert_dir = "/app/data/certs"
    os.makedirs(cert_dir, exist_ok=True)
    
    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")
    
    try:
        # Genera chiave privata e certificato autofirmato con openssl
        cmd = [
            "openssl", "req", "-x509", "-nodes",
            "-days", str(days),
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out", cert_path,
            "-subj", f"/CN={common_name}/O=DaDude/C=IT"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Errore generazione certificato: {result.stderr}")
        
        # Aggiorna .env
        env_vars = _read_env_file()
        env_vars["SSL_ENABLED"] = "true"
        env_vars["SSL_CERT_PATH"] = cert_path
        env_vars["SSL_KEY_PATH"] = key_path
        _write_env_file(env_vars)
        
        logger.info(f"SSL certificate generated: {cert_path}")
        
        return {
            "success": True,
            "message": "Certificato SSL generato con successo",
            "cert_path": cert_path,
            "key_path": key_path,
            "common_name": common_name,
            "valid_days": days,
        }
        
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Timeout durante la generazione del certificato")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/ssl")
async def update_ssl_settings(settings: SSLSettings):
    """
    Aggiorna le impostazioni SSL
    """
    env_vars = _read_env_file()
    
    if settings.ssl_enabled is not None:
        env_vars["SSL_ENABLED"] = "true" if settings.ssl_enabled else "false"
    if settings.ssl_cert_path is not None:
        env_vars["SSL_CERT_PATH"] = settings.ssl_cert_path
    if settings.ssl_key_path is not None:
        env_vars["SSL_KEY_PATH"] = settings.ssl_key_path
    
    _write_env_file(env_vars)
    logger.info("SSL settings updated")
    
    return {"success": True, "message": "Impostazioni SSL aggiornate. Riavvia il servizio per applicare."}


@router.post("/auth")
async def update_auth_settings(settings: AuthSettings):
    """
    Aggiorna le impostazioni di autenticazione
    """
    import hashlib
    import secrets
    
    env_vars = _read_env_file()
    
    if settings.auth_enabled is not None:
        env_vars["AUTH_ENABLED"] = "true" if settings.auth_enabled else "false"
    if settings.admin_username is not None:
        env_vars["ADMIN_USERNAME"] = settings.admin_username
    if settings.admin_password is not None:
        # Hash della password con salt
        salt = secrets.token_hex(16)
        password_hash = hashlib.sha256((settings.admin_password + salt).encode()).hexdigest()
        env_vars["ADMIN_PASSWORD_HASH"] = password_hash
        env_vars["ADMIN_PASSWORD_SALT"] = salt
    
    _write_env_file(env_vars)
    logger.info("Auth settings updated")
    
    return {"success": True, "message": "Impostazioni autenticazione aggiornate. Riavvia il servizio per applicare."}


@router.post("/restart")
async def restart_service():
    """
    Riavvia il servizio DaDude via Docker socket
    """
    try:
        # Verifica se il socket Docker è disponibile
        if os.path.exists("/var/run/docker.sock"):
            # Ottieni il nome del container corrente
            hostname = os.environ.get("HOSTNAME", "dadude")
            
            # Usa docker per riavviare il container
            # Il restart viene eseguito in background perché interromperà questo processo
            result = subprocess.Popen(
                ["docker", "restart", hostname],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            
            return {
                "success": True,
                "message": f"Riavvio container {hostname} in corso... La pagina si ricaricherà automaticamente."
            }
        elif os.path.exists("/.dockerenv"):
            # Siamo in Docker ma senza socket
            return {
                "success": False,
                "message": "Socket Docker non disponibile. Esegui: docker compose restart dadude"
            }
        else:
            # Non in Docker, prova systemctl
            result = subprocess.run(
                ["systemctl", "restart", "dadude"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return {"success": True, "message": "Servizio riavviato"}
            else:
                return {"success": False, "message": result.stderr}
    except Exception as e:
        logger.error(f"Restart failed: {e}")
        return {"success": False, "message": str(e)}

