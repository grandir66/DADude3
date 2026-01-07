"""
DaDude - Version Manager Service
Gestisce il versioning automatico del sistema
v3.0.0: Nuovo servizio
"""
import os
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, Any
from loguru import logger


class VersionManager:
    """
    Gestisce versioni applicazione con supporto per:
    - Auto-incremento basato su tipo modifica (patch, minor, major)
    - Salvataggio versione in file VERSION e config
    - Tracking storia versioni
    """
    
    # Percorsi file
    VERSION_FILE = "./VERSION"
    VERSION_HISTORY_FILE = "./data/version_history.json"
    
    def __init__(self, version_file: str = None, history_file: str = None):
        self.version_file = version_file or self.VERSION_FILE
        self.history_file = history_file or self.VERSION_HISTORY_FILE
        
        # Assicura che directory data esista
        Path("./data").mkdir(exist_ok=True)
    
    def get_current_version(self) -> str:
        """Ottiene versione corrente"""
        # Prima prova da file VERSION
        if os.path.exists(self.version_file):
            with open(self.version_file, "r") as f:
                version = f.read().strip()
                if version:
                    return version
        
        # Fallback: leggi da config.py
        try:
            from ..config import VERSION
            return VERSION
        except ImportError:
            pass
        
        # Default
        return "3.0.0"
    
    def parse_version(self, version: str) -> Tuple[int, int, int]:
        """Parse versione in (major, minor, patch)"""
        # Rimuovi prefissi come 'v'
        version = version.lstrip("v")
        
        # Gestisci suffissi come '-stable', '-beta'
        version = version.split("-")[0]
        
        parts = version.split(".")
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return (major, minor, patch)
        except ValueError:
            return (3, 0, 0)  # Default
    
    def format_version(self, major: int, minor: int, patch: int) -> str:
        """Formatta versione in stringa"""
        return f"{major}.{minor}.{patch}"
    
    def increment_version(
        self,
        change_type: str = "patch",
        reason: str = None,
        save: bool = True
    ) -> str:
        """
        Incrementa versione in base al tipo di modifica.
        
        Args:
            change_type: 'patch' (0.0.1), 'minor' (0.1.0), 'major' (1.0.0)
            reason: Descrizione della modifica
            save: Se True, salva la nuova versione
        
        Returns:
            Nuova versione
        """
        current = self.get_current_version()
        major, minor, patch = self.parse_version(current)
        
        if change_type == "major":
            major += 1
            minor = 0
            patch = 0
        elif change_type == "minor":
            minor += 1
            patch = 0
        else:  # patch
            patch += 1
        
        new_version = self.format_version(major, minor, patch)
        
        if save:
            self.save_version(new_version, change_type, reason)
        
        logger.info(f"Version incremented: {current} -> {new_version} ({change_type})")
        return new_version
    
    def save_version(
        self,
        version: str,
        change_type: str = "patch",
        reason: str = None
    ):
        """Salva nuova versione in file e storico"""
        # Salva in file VERSION
        with open(self.version_file, "w") as f:
            f.write(version)
        
        # Aggiorna storico
        self._add_to_history(version, change_type, reason)
        
        logger.info(f"Version saved: {version}")
    
    def _add_to_history(
        self,
        version: str,
        change_type: str,
        reason: str = None
    ):
        """Aggiunge entry allo storico versioni"""
        history = self.get_version_history()
        
        entry = {
            "version": version,
            "change_type": change_type,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        history.append(entry)
        
        # Mantieni solo ultime 100 versioni
        if len(history) > 100:
            history = history[-100:]
        
        with open(self.history_file, "w") as f:
            json.dump(history, f, indent=2)
    
    def get_version_history(self) -> list:
        """Ottiene storico versioni"""
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return []
    
    def get_version_info(self) -> Dict[str, Any]:
        """Ottiene info complete sulla versione"""
        version = self.get_current_version()
        history = self.get_version_history()
        
        last_change = history[-1] if history else None
        
        return {
            "version": version,
            "major": self.parse_version(version)[0],
            "minor": self.parse_version(version)[1],
            "patch": self.parse_version(version)[2],
            "last_change": last_change,
            "total_releases": len(history),
        }
    
    def compare_versions(self, v1: str, v2: str) -> int:
        """
        Confronta due versioni.
        
        Returns:
            -1 se v1 < v2
            0 se v1 == v2
            1 se v1 > v2
        """
        v1_parts = self.parse_version(v1)
        v2_parts = self.parse_version(v2)
        
        if v1_parts < v2_parts:
            return -1
        elif v1_parts > v2_parts:
            return 1
        else:
            return 0


# Singleton
_version_manager: Optional[VersionManager] = None


def get_version_manager() -> VersionManager:
    """Ottiene istanza singleton del VersionManager"""
    global _version_manager
    if _version_manager is None:
        _version_manager = VersionManager()
    return _version_manager
