"""
DaDude - Settings Service
Gestione configurazione dinamica
"""
import os
from typing import Optional, Dict, Any
from pathlib import Path
from loguru import logger


class SettingsService:
    """Servizio per gestione configurazione .env"""
    
    def __init__(self, env_file: str = "./data/.env"):
        self.env_file = Path(env_file)
        self._ensure_env_file()
    
    def _ensure_env_file(self):
        """Crea .env se non esiste, migra da posizione precedente"""
        # Crea directory se non esiste
        self.env_file.parent.mkdir(parents=True, exist_ok=True)
        
        if not self.env_file.exists():
            import shutil
            
            # Prova a migrare da vecchia posizione (.env nella root)
            old_env = Path(".env")
            if old_env.exists():
                shutil.copy(old_env, self.env_file)
                logger.info(f"Migrated .env from {old_env} to {self.env_file}")
                return
            
            # Oppure copia da .env.example
            example_file = Path(".env.example")
            if example_file.exists():
                shutil.copy(example_file, self.env_file)
                logger.info("Created .env from .env.example")
            else:
                self.env_file.touch()
                logger.info(f"Created empty .env at {self.env_file}")
    
    def read_env(self) -> Dict[str, str]:
        """Legge tutte le variabili dal file .env"""
        env_vars = {}
        
        if not self.env_file.exists():
            return env_vars
        
        with open(self.env_file, 'r') as f:
            for line in f:
                line = line.strip()
                # Salta commenti e righe vuote
                if not line or line.startswith('#'):
                    continue
                
                if '=' in line:
                    key, value = line.split('=', 1)
                    # Rimuovi virgolette dal valore
                    value = value.strip().strip('"').strip("'")
                    env_vars[key.strip()] = value
        
        return env_vars
    
    def get(self, key: str, default: str = "") -> str:
        """Ottiene singola variabile"""
        env_vars = self.read_env()
        return env_vars.get(key, os.environ.get(key, default))
    
    def set(self, key: str, value: str) -> bool:
        """Imposta singola variabile nel .env"""
        return self.update({key: value})
    
    def update(self, updates: Dict[str, str]) -> bool:
        """Aggiorna multiple variabili nel .env"""
        try:
            # Leggi file esistente
            lines = []
            if self.env_file.exists():
                with open(self.env_file, 'r') as f:
                    lines = f.readlines()
            
            # Aggiorna o aggiungi variabili
            updated_keys = set()
            new_lines = []
            
            for line in lines:
                stripped = line.strip()
                
                # Preserva commenti e righe vuote
                if not stripped or stripped.startswith('#'):
                    new_lines.append(line)
                    continue
                
                if '=' in stripped:
                    key = stripped.split('=', 1)[0].strip()
                    if key in updates:
                        new_lines.append(f"{key}={updates[key]}\n")
                        updated_keys.add(key)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)
            
            # Aggiungi nuove variabili non esistenti
            for key, value in updates.items():
                if key not in updated_keys:
                    new_lines.append(f"{key}={value}\n")
            
            # Scrivi file
            with open(self.env_file, 'w') as f:
                f.writelines(new_lines)
            
            # Aggiorna anche environment corrente
            for key, value in updates.items():
                os.environ[key] = value
            
            logger.info(f"Updated .env: {list(updates.keys())}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating .env: {e}")
            return False
    
    def get_dude_config(self) -> Dict[str, Any]:
        """Ottiene configurazione Dude Server"""
        return {
            "host": self.get("DUDE_HOST", "192.168.1.1"),
            "port": int(self.get("DUDE_API_PORT", "8728")),
            "use_ssl": self.get("DUDE_USE_SSL", "false").lower() == "true",
            "username": self.get("DUDE_USERNAME", "admin"),
            "password": self.get("DUDE_PASSWORD", ""),
        }
    
    def set_dude_config(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        use_ssl: Optional[bool] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        """Aggiorna configurazione Dude Server"""
        updates = {}
        
        if host is not None:
            updates["DUDE_HOST"] = host
        if port is not None:
            updates["DUDE_API_PORT"] = str(port)
        if use_ssl is not None:
            updates["DUDE_USE_SSL"] = "true" if use_ssl else "false"
        if username is not None:
            updates["DUDE_USERNAME"] = username
        if password is not None:
            updates["DUDE_PASSWORD"] = password
        
        return self.update(updates) if updates else True


# Singleton
_settings_service: Optional[SettingsService] = None


def get_settings_service() -> SettingsService:
    """Get singleton SettingsService instance"""
    global _settings_service
    if _settings_service is None:
        _settings_service = SettingsService()
    return _settings_service
