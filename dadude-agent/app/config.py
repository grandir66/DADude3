"""
DaDude Agent - Configuration
"""
import os
import json
from typing import Optional, List
from functools import lru_cache
from pydantic_settings import BaseSettings


def parse_dns_servers_env() -> List[str]:
    """Legge e parsa DADUDE_DNS_SERVERS dall'ambiente"""
    raw = os.environ.get("DADUDE_DNS_SERVERS", "")
    if not raw:
        return ["8.8.8.8", "1.1.1.1"]
    
    raw = raw.strip()
    
    # Prova come JSON array
    if raw.startswith('['):
        try:
            return json.loads(raw)
        except:
            pass
    
    # Splitta per virgola
    return [s.strip() for s in raw.split(',') if s.strip()]


class Settings(BaseSettings):
    """Configurazione agent"""
    
    # Server
    server_url: str = "http://localhost:8000"
    
    # Agent Identity
    agent_id: str = "agent-001"
    agent_name: str = "DaDude Agent"
    agent_token: str = "change-me-in-production"
    
    # Polling / Connection
    poll_interval: int = 60  # seconds
    heartbeat_interval: int = 30  # seconds
    
    # API (legacy HTTP mode)
    api_port: int = 8080
    
    # Connection mode: "websocket" (new) or "http" (legacy)
    connection_mode: str = "websocket"
    
    # mTLS / Certificates
    certs_dir: Optional[str] = None  # Directory certificati
    
    # Local storage
    data_dir: Optional[str] = "/var/lib/dadude-agent"
    
    # SFTP Fallback
    sftp_enabled: bool = False
    sftp_host: str = ""
    sftp_port: int = 22
    sftp_username: str = ""
    sftp_password: Optional[str] = None
    sftp_private_key_path: Optional[str] = None
    sftp_remote_path: str = "/incoming"
    sftp_fallback_timeout_minutes: int = 30
    
    # Logging
    log_level: str = "INFO"
    
    model_config = {
        "env_prefix": "DADUDE_",
        "env_file": ".env",
        "extra": "ignore",
    }
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Parsa dns_servers manualmente
        self._dns_servers = None
        
        # Salva i valori dalle env vars (hanno priorità)
        env_server_url = os.environ.get("DADUDE_SERVER_URL")
        env_agent_id = os.environ.get("DADUDE_AGENT_ID")
        env_agent_token = os.environ.get("DADUDE_AGENT_TOKEN")
        env_agent_name = os.environ.get("DADUDE_AGENT_NAME")
        
        # Try to load from config file
        config_paths = [
            "/app/config/config.json",
            "./config/config.json",
            os.path.expanduser("~/.dadude-agent/config.json"),
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path) as f:
                        config_data = json.load(f)
                    
                    # Override with config file values
                    for key, value in config_data.items():
                        if key == 'dns_servers':
                            self._dns_servers = value
                        elif hasattr(self, key):
                            object.__setattr__(self, key, value)
                    
                    break
                except Exception:
                    pass
        
        # Environment variables hanno SEMPRE priorità sul file config
        if env_server_url:
            object.__setattr__(self, 'server_url', env_server_url)
        if env_agent_id:
            object.__setattr__(self, 'agent_id', env_agent_id)
        if env_agent_token:
            object.__setattr__(self, 'agent_token', env_agent_token)
        if env_agent_name:
            object.__setattr__(self, 'agent_name', env_agent_name)
    
    @property
    def dns_servers(self) -> List[str]:
        if self._dns_servers is None:
            self._dns_servers = parse_dns_servers_env()
        return self._dns_servers


# Singleton cached
_settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """Ottieni settings (singleton)"""
    global _settings_instance
    if _settings_instance is None:
        _settings_instance = Settings()
    return _settings_instance
