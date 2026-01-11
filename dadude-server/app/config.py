"""
DaDude - Configuration Settings
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
from functools import lru_cache

# DaDude Version
VERSION = "3.2.1"


class Settings(BaseSettings):
    """Configurazione applicazione DaDude"""
    
    # Dude Server
    dude_host: str = Field(default="192.168.1.1", description="Dude Server IP/hostname")
    dude_api_port: int = Field(default=8728, description="RouterOS API port")
    dude_use_ssl: bool = Field(default=False, description="Use SSL for API connection")
    dude_username: str = Field(default="admin", description="RouterOS username")
    dude_password: str = Field(default="", description="RouterOS password")
    
    # DaDude Server
    dadude_host: str = Field(default="0.0.0.0", description="DaDude bind host")
    dadude_port: int = Field(default=8000, description="DaDude port")
    dadude_api_key: str = Field(default="", description="API key for authentication")
    
    # Database
    database_url: str = Field(
        default="postgresql+psycopg2://dadude:dadude@localhost:5432/dadude",
        description="Database connection URL (PostgreSQL)"
    )
    
    # Polling
    poll_interval: int = Field(default=60, description="Device poll interval (seconds)")
    full_sync_interval: int = Field(default=300, description="Full sync interval (seconds)")
    connection_timeout: int = Field(default=30, description="Connection timeout (seconds)")
    
    # Logging
    log_level: str = Field(default="INFO", description="Log level")
    log_file: str = Field(default="./logs/dadude.log", description="Log file path")
    
    # Webhook
    webhook_url: Optional[str] = Field(default=None, description="External webhook URL")
    webhook_secret: Optional[str] = Field(default=None, description="Webhook secret")
    
    # Encryption
    encryption_key: Optional[str] = Field(default=None, description="Master encryption key for credentials")
    
    # GitHub (per creazione release automatiche)
    github_token: Optional[str] = Field(default=None, description="GitHub token for creating releases")
    
    # Device Management - Intelligent Data Management
    device_cleanup_threshold_days: int = Field(default=90, description="Giorni senza verifica prima di pulizia")
    device_cleanup_grace_period_days: int = Field(default=30, description="Periodo di grazia dopo marcatura")
    device_merge_auto_enabled: bool = Field(default=False, description="Auto-merge se dati più completi")
    device_cleanup_schedule_enabled: bool = Field(default=True, description="Abilita pulizia automatica schedulata")
    device_cleanup_schedule_cron: str = Field(default="0 2 * * 0", description="Cron expression per pulizia (ogni domenica alle 2)")
    
    class Config:
        # Usa .env nella directory data (persistente)
        env_file = "./data/.env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        # Permetti override da variabili ambiente per compatibilità docker-compose
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
