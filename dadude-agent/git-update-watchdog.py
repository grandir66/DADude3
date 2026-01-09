#!/usr/bin/env python3
"""
DaDude Git Update Watchdog
===========================
Servizio indipendente per aggiornamento automatico dell'agent via Git.

Caratteristiche:
- Completamente indipendente dall'agent
- Auto-riparante (può aggiornare anche se stesso)
- Controllo periodico del repository Git
- Rollback automatico se l'update fallisce
- Health check dell'agent dopo l'update
- Logging persistente

Uso:
  python3 git-update-watchdog.py [--once] [--force]

Opzioni:
  --once   Esegue un solo controllo ed esce
  --force  Forza l'aggiornamento anche se già alla versione corrente
"""

import os
import sys
import time
import json
import shutil
import signal
import logging
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import argparse

# Configurazione
AGENT_DIR = Path(os.getenv("AGENT_DIR", "/opt/dadude-agent"))
DADUDE_AGENT_SUBDIR = AGENT_DIR / "dadude-agent"
CHECK_INTERVAL_SECONDS = int(os.getenv("UPDATE_CHECK_INTERVAL", "3600"))  # Default: 1 ora
GIT_REMOTE = os.getenv("GIT_REMOTE", "origin")
GIT_BRANCH = os.getenv("GIT_BRANCH", "main")
AGENT_HEALTH_TIMEOUT = int(os.getenv("AGENT_HEALTH_TIMEOUT", "120"))  # 2 minuti
MAX_RETRY_ATTEMPTS = 3
LOG_FILE = AGENT_DIR / "logs" / "git-update-watchdog.log"
STATE_FILE = AGENT_DIR / ".watchdog_state.json"

# Setup logging
def setup_logging():
    """Configura logging sia su file che su stdout."""
    log_dir = LOG_FILE.parent
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Ruota log se troppo grande (>10MB)
    if LOG_FILE.exists() and LOG_FILE.stat().st_size > 10 * 1024 * 1024:
        backup = LOG_FILE.with_suffix('.log.1')
        if backup.exists():
            backup.unlink()
        LOG_FILE.rename(backup)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(LOG_FILE),
            logging.StreamHandler(sys.stdout)
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()


class WatchdogState:
    """Gestisce lo stato persistente del watchdog."""
    
    def __init__(self, state_file: Path = STATE_FILE):
        self.state_file = state_file
        self.state = self._load()
    
    def _load(self) -> Dict[str, Any]:
        """Carica lo stato dal file."""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Impossibile caricare stato: {e}")
        return {
            "last_check": None,
            "last_update": None,
            "last_commit": None,
            "consecutive_failures": 0,
            "bad_commits": [],
            "last_healthy_commit": None
        }
    
    def save(self):
        """Salva lo stato su file."""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.state, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Impossibile salvare stato: {e}")
    
    def mark_check(self):
        """Segna che è stato fatto un controllo."""
        self.state["last_check"] = datetime.now().isoformat()
        self.save()
    
    def mark_update(self, commit: str, success: bool):
        """Segna il risultato di un aggiornamento."""
        self.state["last_update"] = datetime.now().isoformat()
        self.state["last_commit"] = commit
        
        if success:
            self.state["consecutive_failures"] = 0
            self.state["last_healthy_commit"] = commit
        else:
            self.state["consecutive_failures"] += 1
            if commit not in self.state["bad_commits"]:
                self.state["bad_commits"].append(commit)
                # Mantieni solo gli ultimi 10 bad commits
                self.state["bad_commits"] = self.state["bad_commits"][-10:]
        
        self.save()
    
    def is_bad_commit(self, commit: str) -> bool:
        """Verifica se un commit è marcato come bad."""
        return commit in self.state.get("bad_commits", [])


class GitUpdateWatchdog:
    """Watchdog per aggiornamenti automatici via Git."""
    
    def __init__(self, agent_dir: Path = AGENT_DIR, force: bool = False):
        self.agent_dir = agent_dir
        self.dadude_agent_dir = DADUDE_AGENT_SUBDIR
        self.force = force
        self.state = WatchdogState()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        
        logger.info(f"Git Update Watchdog avviato")
        logger.info(f"Agent directory: {self.agent_dir}")
        logger.info(f"Check interval: {CHECK_INTERVAL_SECONDS}s")
    
    def _signal_handler(self, signum, frame):
        """Gestisce segnali di terminazione."""
        logger.info(f"Ricevuto segnale {signum}, terminazione in corso...")
        self.running = False
    
    def _run_command(self, cmd: list, cwd: Path = None, timeout: int = 60) -> tuple:
        """
        Esegue un comando shell.
        Ritorna (success, stdout, stderr).
        """
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd or self.agent_dir,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return (
                result.returncode == 0,
                result.stdout.strip(),
                result.stderr.strip()
            )
        except subprocess.TimeoutExpired:
            return (False, "", f"Timeout dopo {timeout}s")
        except Exception as e:
            return (False, "", str(e))
    
    def _get_current_commit(self) -> Optional[str]:
        """Ottiene il commit hash corrente."""
        success, stdout, _ = self._run_command(["git", "rev-parse", "HEAD"])
        return stdout if success else None
    
    def _get_remote_commit(self) -> Optional[str]:
        """Ottiene l'ultimo commit dal remote."""
        success, stdout, _ = self._run_command(
            ["git", "rev-parse", f"{GIT_REMOTE}/{GIT_BRANCH}"]
        )
        return stdout if success else None
    
    def _fetch_updates(self) -> bool:
        """Fetch degli aggiornamenti dal remote."""
        success, _, stderr = self._run_command(
            ["git", "fetch", GIT_REMOTE, GIT_BRANCH],
            timeout=120
        )
        if not success:
            logger.error(f"Git fetch fallito: {stderr}")
        return success
    
    def _get_version_from_file(self) -> Optional[str]:
        """Legge la versione dal file VERSION."""
        version_file = self.agent_dir / "VERSION"
        if version_file.exists():
            try:
                return version_file.read_text().strip()
            except Exception:
                pass
        
        # Prova nella subdirectory
        version_file = self.dadude_agent_dir / "VERSION"
        if version_file.exists():
            try:
                return version_file.read_text().strip()
            except Exception:
                pass
        
        return None
    
    def _backup_env_files(self) -> Dict[str, str]:
        """
        Backup dei file .env.
        Ritorna un dict con i contenuti salvati.
        """
        backups = {}
        
        env_files = [
            self.agent_dir / ".env",
            self.dadude_agent_dir / ".env"
        ]
        
        for env_file in env_files:
            if env_file.exists():
                try:
                    backups[str(env_file)] = env_file.read_text()
                    logger.info(f"Backup .env: {env_file}")
                except Exception as e:
                    logger.warning(f"Impossibile fare backup di {env_file}: {e}")
        
        return backups
    
    def _restore_env_files(self, backups: Dict[str, str]):
        """Ripristina i file .env dal backup."""
        for path, content in backups.items():
            try:
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                Path(path).write_text(content)
                logger.info(f"Ripristinato .env: {path}")
            except Exception as e:
                logger.error(f"Impossibile ripristinare {path}: {e}")
    
    def _git_reset_hard(self, commit: str = None) -> bool:
        """
        Esegue git reset --hard.
        Se commit è None, resetta a origin/main.
        """
        target = commit or f"{GIT_REMOTE}/{GIT_BRANCH}"
        success, _, stderr = self._run_command(
            ["git", "reset", "--hard", target],
            timeout=60
        )
        if not success:
            logger.error(f"Git reset fallito: {stderr}")
        return success
    
    def _check_agent_is_native(self) -> bool:
        """
        Verifica se l'agent gira come servizio nativo o Docker.
        Ritorna True se nativo (systemd), False se Docker.
        """
        # Verifica se c'è un servizio systemd attivo
        success, stdout, _ = self._run_command(
            ["systemctl", "is-active", "dadude-agent"],
            timeout=10
        )
        if success and "active" in stdout.lower():
            return True
        
        # Verifica se c'è un container Docker
        success, stdout, _ = self._run_command(
            ["docker", "ps", "--filter", "name=dadude-agent", "--format", "{{.Names}}"],
            timeout=10
        )
        if success and "dadude-agent" in stdout:
            return False
        
        # Default: assume nativo
        return True
    
    def _restart_agent(self) -> bool:
        """
        Riavvia l'agent (systemd o Docker).
        Ritorna True se il riavvio ha avuto successo.
        """
        is_native = self._check_agent_is_native()
        
        if is_native:
            logger.info("Riavvio agent via systemd...")
            
            # Stop
            self._run_command(["systemctl", "stop", "dadude-agent"], timeout=30)
            time.sleep(2)
            
            # Clear cache Python
            for pycache in self.agent_dir.rglob("__pycache__"):
                try:
                    shutil.rmtree(pycache)
                except Exception:
                    pass
            
            # Start
            success, _, stderr = self._run_command(
                ["systemctl", "start", "dadude-agent"],
                timeout=30
            )
            
            if not success:
                logger.error(f"Riavvio systemd fallito: {stderr}")
                return False
        else:
            logger.info("Riavvio agent via Docker...")
            
            compose_dir = self.dadude_agent_dir
            if not (compose_dir / "docker-compose.yml").exists():
                compose_dir = self.agent_dir
            
            # Build e restart
            success, _, stderr = self._run_command(
                ["docker", "compose", "build", "--quiet"],
                cwd=compose_dir,
                timeout=300
            )
            
            if not success:
                logger.warning(f"Docker build warning: {stderr}")
            
            success, _, stderr = self._run_command(
                ["docker", "compose", "up", "-d", "--force-recreate"],
                cwd=compose_dir,
                timeout=120
            )
            
            if not success:
                logger.error(f"Docker compose up fallito: {stderr}")
                return False
        
        logger.info("Agent riavviato, attendo stabilizzazione...")
        time.sleep(10)
        return True
    
    def _check_agent_health(self, timeout: int = AGENT_HEALTH_TIMEOUT) -> bool:
        """
        Verifica che l'agent sia healthy dopo il riavvio.
        Controlla i log per "Connected to DaDude server" o messaggi simili.
        """
        is_native = self._check_agent_is_native()
        
        start_time = time.time()
        check_interval = 5
        
        while time.time() - start_time < timeout:
            if is_native:
                # Controlla log systemd
                success, stdout, _ = self._run_command(
                    ["journalctl", "-u", "dadude-agent", "-n", "50", "--no-pager"],
                    timeout=10
                )
                logs = stdout
            else:
                # Controlla log Docker
                success, stdout, _ = self._run_command(
                    ["docker", "logs", "dadude-agent", "--tail", "50"],
                    timeout=10
                )
                logs = stdout
            
            if not success:
                time.sleep(check_interval)
                continue
            
            # Cerca indicatori di salute
            health_indicators = [
                "Connected to DaDude server",
                "WebSocket connected",
                "Agent ready",
                "Heartbeat sent",
                "Connection established"
            ]
            
            for indicator in health_indicators:
                if indicator.lower() in logs.lower():
                    logger.info(f"Agent healthy: trovato '{indicator}'")
                    return True
            
            # Cerca errori critici
            error_indicators = [
                "Connection refused",
                "Failed to connect",
                "ImportError",
                "ModuleNotFoundError",
                "SyntaxError"
            ]
            
            for error in error_indicators:
                if error.lower() in logs.lower():
                    logger.warning(f"Errore critico rilevato: {error}")
                    # Non ritornare subito False, potrebbe essere un errore temporaneo
            
            logger.debug(f"In attesa di salute agent... ({int(time.time() - start_time)}s)")
            time.sleep(check_interval)
        
        logger.warning(f"Timeout raggiunto ({timeout}s) senza conferma di salute")
        return False
    
    def check_for_updates(self) -> Optional[str]:
        """
        Verifica se ci sono aggiornamenti disponibili.
        Ritorna il nuovo commit hash se disponibile, altrimenti None.
        """
        logger.info("Controllo aggiornamenti...")
        
        # Verifica che sia un repository git
        if not (self.agent_dir / ".git").exists():
            logger.error(f"{self.agent_dir} non è un repository git")
            return None
        
        # Fetch updates
        if not self._fetch_updates():
            return None
        
        current_commit = self._get_current_commit()
        remote_commit = self._get_remote_commit()
        
        if not current_commit or not remote_commit:
            logger.error("Impossibile ottenere commit hash")
            return None
        
        logger.info(f"Commit corrente: {current_commit[:8]}")
        logger.info(f"Commit remoto:   {remote_commit[:8]}")
        
        if current_commit == remote_commit and not self.force:
            logger.info("Nessun aggiornamento disponibile")
            return None
        
        # Verifica se il nuovo commit è marcato come bad
        if self.state.is_bad_commit(remote_commit):
            logger.warning(f"Commit {remote_commit[:8]} è marcato come bad, skip")
            return None
        
        logger.info(f"Aggiornamento disponibile: {current_commit[:8]} -> {remote_commit[:8]}")
        return remote_commit
    
    def perform_update(self, new_commit: str) -> bool:
        """
        Esegue l'aggiornamento alla nuova versione.
        Ritorna True se l'aggiornamento ha avuto successo.
        """
        logger.info(f"Inizio aggiornamento a {new_commit[:8]}...")
        
        old_commit = self._get_current_commit()
        old_version = self._get_version_from_file()
        
        # Backup .env files
        env_backups = self._backup_env_files()
        
        try:
            # Git reset --hard
            logger.info("Esecuzione git reset --hard...")
            if not self._git_reset_hard():
                raise Exception("Git reset fallito")
            
            # Ripristina .env files
            self._restore_env_files(env_backups)
            
            # Verifica versione
            new_version = self._get_version_from_file()
            logger.info(f"Versione: {old_version} -> {new_version}")
            
            # Riavvia agent
            logger.info("Riavvio agent...")
            if not self._restart_agent():
                raise Exception("Riavvio agent fallito")
            
            # Verifica salute
            logger.info("Verifica salute agent...")
            if not self._check_agent_health():
                raise Exception("Agent non healthy dopo l'aggiornamento")
            
            # Successo!
            logger.info(f"✓ Aggiornamento completato con successo a {new_commit[:8]}")
            self.state.mark_update(new_commit, success=True)
            return True
            
        except Exception as e:
            logger.error(f"Aggiornamento fallito: {e}")
            
            # Rollback
            if old_commit:
                logger.info(f"Rollback a {old_commit[:8]}...")
                if self._git_reset_hard(old_commit):
                    self._restore_env_files(env_backups)
                    self._restart_agent()
                    logger.info("Rollback completato")
                else:
                    logger.error("Rollback fallito!")
            
            self.state.mark_update(new_commit, success=False)
            return False
    
    def run_once(self) -> bool:
        """
        Esegue un singolo controllo e aggiornamento se necessario.
        Ritorna True se è stato eseguito un aggiornamento con successo.
        """
        self.state.mark_check()
        
        new_commit = self.check_for_updates()
        if new_commit:
            return self.perform_update(new_commit)
        
        return False
    
    def run_loop(self):
        """Esegue il loop principale del watchdog."""
        logger.info(f"Avvio loop principale (intervallo: {CHECK_INTERVAL_SECONDS}s)")
        
        # Prima esecuzione immediata
        self.run_once()
        
        while self.running:
            try:
                # Attendi prossimo check
                for _ in range(CHECK_INTERVAL_SECONDS):
                    if not self.running:
                        break
                    time.sleep(1)
                
                if self.running:
                    self.run_once()
                    
            except Exception as e:
                logger.error(f"Errore nel loop principale: {e}")
                time.sleep(60)  # Attendi 1 minuto prima di riprovare
        
        logger.info("Watchdog terminato")


def main():
    parser = argparse.ArgumentParser(
        description="DaDude Git Update Watchdog",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Esegue un solo controllo ed esce"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Forza l'aggiornamento anche se alla versione corrente"
    )
    parser.add_argument(
        "--agent-dir",
        type=str,
        default=str(AGENT_DIR),
        help=f"Directory dell'agent (default: {AGENT_DIR})"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=CHECK_INTERVAL_SECONDS,
        help=f"Intervallo di controllo in secondi (default: {CHECK_INTERVAL_SECONDS})"
    )
    
    args = parser.parse_args()
    
    # Aggiorna configurazione globale
    global CHECK_INTERVAL_SECONDS
    CHECK_INTERVAL_SECONDS = args.interval
    
    # Crea e avvia watchdog
    watchdog = GitUpdateWatchdog(
        agent_dir=Path(args.agent_dir),
        force=args.force
    )
    
    if args.once:
        success = watchdog.run_once()
        sys.exit(0 if success else 1)
    else:
        watchdog.run_loop()


if __name__ == "__main__":
    main()
