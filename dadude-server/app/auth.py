"""
DaDude - Authentication Module
Sistema di autenticazione basato su sessioni
"""
from fastapi import Request, HTTPException, Depends
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Optional
import hashlib
import secrets
import os
from loguru import logger


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


def is_auth_enabled() -> bool:
    """Verifica se l'autenticazione è abilitata"""
    env_vars = _read_env_file()
    return env_vars.get("AUTH_ENABLED", "false").lower() == "true"


def verify_password(password: str) -> bool:
    """Verifica la password dell'admin"""
    env_vars = _read_env_file()
    stored_hash = env_vars.get("ADMIN_PASSWORD_HASH", "")
    salt = env_vars.get("ADMIN_PASSWORD_SALT", "")
    
    if not stored_hash or not salt:
        # Password non configurata, usa default
        return password == "admin"
    
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return password_hash == stored_hash


def get_admin_username() -> str:
    """Ottiene lo username dell'admin"""
    env_vars = _read_env_file()
    return env_vars.get("ADMIN_USERNAME", "admin")


# Store delle sessioni attive (in memoria, si resetta al riavvio)
_active_sessions: dict = {}


def create_session(username: str) -> str:
    """Crea una nuova sessione e ritorna il token"""
    token = secrets.token_urlsafe(32)
    _active_sessions[token] = {
        "username": username,
        "created_at": __import__("datetime").datetime.utcnow().isoformat()
    }
    logger.info(f"Session created for user: {username}")
    return token


def verify_session(token: str) -> Optional[dict]:
    """Verifica se una sessione è valida"""
    return _active_sessions.get(token)


def destroy_session(token: str):
    """Distrugge una sessione"""
    if token in _active_sessions:
        del _active_sessions[token]
        logger.info("Session destroyed")


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Middleware per proteggere le route admin con autenticazione.
    Le route API per gli agent non sono protette.
    """
    
    # Route che non richiedono autenticazione
    PUBLIC_PATHS = [
        "/api/v1/agents/",  # API per gli agent
        "/api/v1/agents/ws/",  # WebSocket per gli agent
        "/login",
        "/static/",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
        "/favicon.ico",
    ]
    
    async def dispatch(self, request: Request, call_next):
        # Verifica se l'autenticazione è abilitata
        if not is_auth_enabled():
            return await call_next(request)
        
        path = request.url.path
        
        # Permetti route pubbliche
        for public_path in self.PUBLIC_PATHS:
            if path.startswith(public_path):
                return await call_next(request)
        
        # Verifica sessione
        session_token = request.cookies.get("dadude_session")
        
        if session_token and verify_session(session_token):
            # Sessione valida, procedi
            return await call_next(request)
        
        # Sessione non valida, redirect a login per pagine HTML
        if not path.startswith("/api/"):
            return RedirectResponse(url="/login", status_code=302)
        
        # Per API, ritorna 401
        raise HTTPException(status_code=401, detail="Non autenticato")


def get_current_user(request: Request) -> Optional[dict]:
    """
    Dependency per ottenere l'utente corrente dalla sessione.
    Ritorna None se non autenticato.
    """
    if not is_auth_enabled():
        return {"username": "admin", "authenticated": False}
    
    session_token = request.cookies.get("dadude_session")
    if session_token:
        session = verify_session(session_token)
        if session:
            return {"username": session["username"], "authenticated": True}
    
    return None

