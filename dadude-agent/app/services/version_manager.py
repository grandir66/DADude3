"""
Version Manager per DaDude Agent
Gestisce versioni multiple con backup e rollback automatico
"""
import os
import shutil
import subprocess
import json
import logging
import hashlib
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime
import glob

logger = logging.getLogger(__name__)


class VersionManager:
    """
    Gestisce versioni multiple dell'agent con backup e rollback automatico.
    """
    
    def __init__(self, agent_dir: str = "/opt/dadude-agent"):
        self.agent_dir = Path(agent_dir)
        self.versions_dir = self.agent_dir / "versions"
        self.backups_dir = self.agent_dir / "backups"
        self.current_version_file = self.agent_dir / ".current_version"
        self.bad_versions_file = self.agent_dir / ".bad_versions"
        self.health_check_timeout = 300  # 5 minuti per verificare connessione
        
        # Configurazione pulizia disco
        self.max_backups = int(os.getenv("MAX_BACKUPS", "1"))  # Mantieni solo l'ultimo backup funzionante
        self.max_backup_age_days = int(os.getenv("MAX_BACKUP_AGE_DAYS", "7"))  # Elimina backup più vecchi di 7 giorni
        self.min_free_space_mb = int(os.getenv("MIN_FREE_SPACE_MB", "500"))  # Mantieni almeno 500MB liberi
        
        # Crea directory se non esistono
        self.versions_dir.mkdir(parents=True, exist_ok=True)
        self.backups_dir.mkdir(parents=True, exist_ok=True)
    
    def get_current_version(self) -> Optional[str]:
        """Ottiene la versione corrente."""
        if self.current_version_file.exists():
            try:
                with open(self.current_version_file, 'r') as f:
                    data = json.load(f)
                    return data.get("version")
            except Exception as e:
                logger.warning(f"Could not read current version: {e}")
        return None
    
    def get_current_commit(self) -> Optional[str]:
        """Ottiene il commit hash corrente."""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.agent_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception as e:
            logger.warning(f"Could not get current commit: {e}")
        return None
    
    def is_bad_version(self, version: str) -> bool:
        """Verifica se una versione è marcata come bad."""
        if not self.bad_versions_file.exists():
            return False
        
        try:
            with open(self.bad_versions_file, 'r') as f:
                bad_versions = json.load(f)
                return version in bad_versions.get("versions", [])
        except Exception as e:
            logger.warning(f"Could not read bad versions: {e}")
        return False
    
    def mark_version_bad(self, version: str):
        """Marca una versione come bad."""
        bad_versions = []
        if self.bad_versions_file.exists():
            try:
                with open(self.bad_versions_file, 'r') as f:
                    data = json.load(f)
                    bad_versions = data.get("versions", [])
            except Exception:
                pass
        
        if version not in bad_versions:
            bad_versions.append(version)
            with open(self.bad_versions_file, 'w') as f:
                json.dump({"versions": bad_versions}, f, indent=2)
            logger.warning(f"Marked version {version} as bad")
    
    def backup_current_version(self) -> Optional[str]:
        """
        Crea un backup della versione corrente.
        Ritorna il path del backup o None se fallisce.
        """
        try:
            current_commit = self.get_current_commit()
            if not current_commit:
                logger.warning("Could not get current commit for backup")
                return None
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{current_commit[:8]}_{timestamp}"
            backup_path = self.backups_dir / backup_name
            
            # Se la directory esiste già, rimuovila prima
            if backup_path.exists():
                logger.warning(f"Backup directory already exists: {backup_path}, removing...")
                shutil.rmtree(backup_path)
            
            logger.info(f"Creating backup: {backup_name}")
            
            # Crea la directory backup
            backup_path.mkdir(parents=True, exist_ok=True)
            
            # Copia la directory app (escludendo versioni e backup)
            if (self.agent_dir / "app").exists():
                shutil.copytree(
                    self.agent_dir / "app",
                    backup_path / "app",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
                )
            
            # Copia docker-compose.yml se esiste
            compose_file = self.agent_dir / "dadude-agent" / "docker-compose.yml"
            if compose_file.exists():
                backup_path.mkdir(parents=True, exist_ok=True)
                shutil.copy2(compose_file, backup_path / "docker-compose.yml")
            
            # Salva metadata del backup
            metadata = {
                "commit": current_commit,
                "timestamp": timestamp,
                "backup_path": str(backup_path),
            }
            with open(backup_path / "metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"Backup created: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            logger.error(f"Failed to create backup: {e}", exc_info=True)
            return None
    
    def restore_backup(self, backup_path: str) -> bool:
        """
        Ripristina un backup.
        """
        try:
            backup_dir = Path(backup_path)
            if not backup_dir.exists():
                logger.error(f"Backup path does not exist: {backup_path}")
                return False
            
            logger.info(f"Restoring backup: {backup_path}")
            
            # Ripristina app directory
            app_backup = backup_dir / "app"
            if app_backup.exists():
                app_target = self.agent_dir / "app"
                if app_target.exists():
                    shutil.rmtree(app_target)
                shutil.copytree(app_backup, app_target)
            
            # Ripristina docker-compose.yml se presente
            compose_backup = backup_dir / "docker-compose.yml"
            if compose_backup.exists():
                compose_target = self.agent_dir / "dadude-agent" / "docker-compose.yml"
                compose_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(compose_backup, compose_target)
            
            logger.info("Backup restored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore backup: {e}", exc_info=True)
            return False
    
    def check_for_updates(self) -> Optional[str]:
        """
        Verifica se ci sono aggiornamenti disponibili.
        Ritorna il commit hash della nuova versione o None.
        """
        try:
            # Verifica che siamo in un repository git
            git_dir = self.agent_dir / ".git"
            logger.debug(f"Checking for updates in {self.agent_dir}, git exists: {git_dir.exists()}")
            
            if not git_dir.exists():
                logger.warning(f"Not a git repository at {self.agent_dir}, cannot check for updates")
                # Verifica se esiste in una posizione alternativa
                alt_git_dir = self.agent_dir.parent / ".git"
                if alt_git_dir.exists():
                    logger.info(f"Found git repository at {alt_git_dir.parent}, trying alternative path")
                    self.agent_dir = alt_git_dir.parent
                else:
                    return None
            
            # Verifica accesso alla rete
            logger.debug("Fetching latest changes from origin/main...")
            
            # Fetch latest
            fetch_result = subprocess.run(
                ["git", "fetch", "origin", "main"],
                cwd=self.agent_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if fetch_result.returncode != 0:
                logger.warning(f"Git fetch failed (returncode={fetch_result.returncode}): {fetch_result.stderr}")
                if fetch_result.stdout:
                    logger.debug(f"Git fetch stdout: {fetch_result.stdout}")
                return None
            
            logger.debug("Git fetch successful")
            
            # Verifica se ci sono commit nuovi
            current_commit = self.get_current_commit()
            logger.debug(f"Current commit: {current_commit[:8] if current_commit else 'unknown'}")
            
            result = subprocess.run(
                ["git", "rev-parse", "origin/main"],
                cwd=self.agent_dir,
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode != 0:
                logger.warning(f"Failed to get origin/main commit: {result.stderr}")
                return None
            
            latest_commit = result.stdout.strip()
            logger.debug(f"Latest commit on origin/main: {latest_commit[:8]}")
            
            if current_commit != latest_commit:
                logger.info(f"Update available: {current_commit[:8] if current_commit else 'unknown'} -> {latest_commit[:8]}")
                return latest_commit
            else:
                logger.debug("No updates available, already at latest version")
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to check for updates: {e}", exc_info=True)
            return None
    
    def update_to_version(self, commit_hash: str) -> bool:
        """
        Aggiorna alla versione specificata.
        """
        try:
            logger.info(f"Updating to commit {commit_hash[:8]}")
            
            # Backup versione corrente
            backup_path = self.backup_current_version()
            if not backup_path:
                logger.error("Failed to create backup, aborting update")
                return False
            
            # Reset a origin/main
            reset_result = subprocess.run(
                ["git", "reset", "--hard", "origin/main"],
                cwd=self.agent_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if reset_result.returncode != 0:
                logger.error(f"Git reset failed: {reset_result.stderr}")
                # Ripristina backup
                self.restore_backup(backup_path)
                return False
            
            # Verifica che il commit sia corretto
            new_commit = self.get_current_commit()
            if new_commit != commit_hash:
                logger.warning(f"Commit mismatch: expected {commit_hash[:8]}, got {new_commit[:8] if new_commit else 'None'}")
            
            # Salva nuova versione
            with open(self.current_version_file, 'w') as f:
                json.dump({
                    "version": commit_hash,
                    "updated_at": datetime.now().isoformat(),
                    "backup_path": backup_path,
                }, f, indent=2)
            
            logger.info(f"Updated to commit {commit_hash[:8]}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update: {e}", exc_info=True)
            return False
    
    def rollback_to_backup(self, backup_path: Optional[str] = None) -> bool:
        """
        Ripristina l'ultimo backup.
        """
        try:
            if backup_path:
                return self.restore_backup(backup_path)
            
            # Trova l'ultimo backup dal metadata corrente
            if self.current_version_file.exists():
                try:
                    with open(self.current_version_file, 'r') as f:
                        data = json.load(f)
                        backup_path = data.get("backup_path")
                        if backup_path and Path(backup_path).exists():
                            return self.restore_backup(backup_path)
                except Exception as e:
                    logger.warning(f"Could not read backup path from metadata: {e}")
            
            # Cerca l'ultimo backup nella directory
            backups = sorted(self.backups_dir.glob("backup_*"), key=os.path.getmtime, reverse=True)
            if backups:
                return self.restore_backup(str(backups[0]))
            
            logger.error("No backup found to restore")
            return False
            
        except Exception as e:
            logger.error(f"Failed to rollback: {e}", exc_info=True)
            return False
    
    def get_disk_usage(self) -> Dict[str, int]:
        """
        Ottiene informazioni sull'uso del disco.
        Ritorna dict con: total_bytes, used_bytes, free_bytes
        """
        try:
            stat = shutil.disk_usage(self.agent_dir)
            return {
                "total_bytes": stat.total,
                "used_bytes": stat.used,
                "free_bytes": stat.free,
                "free_mb": stat.free // (1024 * 1024),
            }
        except Exception as e:
            logger.warning(f"Could not get disk usage: {e}")
            return {"total_bytes": 0, "used_bytes": 0, "free_bytes": 0, "free_mb": 0}
    
    def get_backup_size(self, backup_path: str) -> int:
        """Calcola dimensione totale di un backup in bytes."""
        try:
            backup_dir = Path(backup_path)
            if not backup_dir.exists():
                return 0
            
            total_size = 0
            for file_path in backup_dir.rglob("*"):
                if file_path.is_file():
                    total_size += file_path.stat().st_size
            return total_size
        except Exception as e:
            logger.warning(f"Could not calculate backup size: {e}")
            return 0
    
    def cleanup_old_backups(self, force: bool = False) -> Dict[str, any]:
        """
        Pulisce backup vecchi secondo le policy configurate.
        
        Policy:
        1. Mantieni solo gli ultimi N backup (max_backups)
        2. Elimina backup più vecchi di max_backup_age_days giorni
        3. Se spazio libero < min_free_space_mb, elimina backup più vecchi
        
        Ritorna dict con statistiche della pulizia.
        """
        stats = {
            "backups_before": 0,
            "backups_after": 0,
            "deleted_backups": [],
            "freed_space_mb": 0,
            "reason": [],
        }
        
        try:
            # Trova tutti i backup
            backups = []
            for backup_dir in self.backups_dir.glob("backup_*"):
                if backup_dir.is_dir():
                    try:
                        mtime = backup_dir.stat().st_mtime
                        size = self.get_backup_size(str(backup_dir))
                        backups.append({
                            "path": backup_dir,
                            "mtime": mtime,
                            "age_days": (datetime.now().timestamp() - mtime) / (24 * 3600),
                            "size_bytes": size,
                            "size_mb": size // (1024 * 1024),
                        })
                    except Exception as e:
                        logger.warning(f"Error processing backup {backup_dir}: {e}")
                        continue
            
            stats["backups_before"] = len(backups)
            
            if not backups:
                return stats
            
            # Ordina per età (più vecchi prima)
            backups.sort(key=lambda x: x["mtime"])
            
            # Verifica spazio disco disponibile
            disk_usage = self.get_disk_usage()
            free_space_mb = disk_usage.get("free_mb", 0)
            low_space = free_space_mb < self.min_free_space_mb
            
            if low_space:
                stats["reason"].append(f"Low disk space: {free_space_mb}MB < {self.min_free_space_mb}MB")
            
            # Identifica backup da eliminare
            to_delete = []
            
            # 1. Elimina backup più vecchi di max_backup_age_days
            for backup in backups:
                if backup["age_days"] > self.max_backup_age_days:
                    to_delete.append(backup)
                    stats["reason"].append(f"Backup older than {self.max_backup_age_days} days")
            
            # 2. Mantieni solo gli ultimi max_backups
            if len(backups) > self.max_backups:
                # Mantieni gli ultimi max_backups, elimina gli altri
                keep_count = self.max_backups
                old_backups = backups[:-keep_count]  # Prendi tutti tranne gli ultimi N
                for backup in old_backups:
                    if backup not in to_delete:
                        to_delete.append(backup)
                        stats["reason"].append(f"Keeping only last {self.max_backups} backups")
            
            # 3. Se spazio basso, elimina backup più vecchi fino a raggiungere spazio minimo
            if low_space:
                freed_mb = sum(b["size_mb"] for b in to_delete)
                for backup in backups:
                    if backup not in to_delete and freed_mb < (self.min_free_space_mb - free_space_mb):
                        to_delete.append(backup)
                        freed_mb += backup["size_mb"]
                        stats["reason"].append("Freeing space due to low disk")
            
            # Elimina backup identificati
            for backup in to_delete:
                try:
                    backup_path = backup["path"]
                    size_mb = backup["size_mb"]
                    
                    logger.info(f"Deleting old backup: {backup_path.name} ({size_mb}MB, {backup['age_days']:.1f} days old)")
                    shutil.rmtree(backup_path)
                    
                    stats["deleted_backups"].append({
                        "name": backup_path.name,
                        "size_mb": size_mb,
                        "age_days": backup["age_days"],
                    })
                    stats["freed_space_mb"] += size_mb
                    
                except Exception as e:
                    logger.error(f"Failed to delete backup {backup['path']}: {e}")
            
            stats["backups_after"] = stats["backups_before"] - len(stats["deleted_backups"])
            
            if stats["deleted_backups"]:
                logger.info(f"Cleanup completed: deleted {len(stats['deleted_backups'])} backups, freed {stats['freed_space_mb']}MB")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error during backup cleanup: {e}", exc_info=True)
            return stats
    
    def cleanup_logs(self) -> Dict[str, any]:
        """
        Pulisce log vecchi.
        Mantiene solo gli ultimi N giorni di log.
        """
        stats = {
            "deleted_files": [],
            "freed_space_mb": 0,
        }
        
        try:
            log_dir = self.agent_dir / "logs"
            if not log_dir.exists():
                return stats
            
            max_log_age_days = int(os.getenv("MAX_LOG_AGE_DAYS", "7"))  # Mantieni 7 giorni di log
            cutoff_time = datetime.now().timestamp() - (max_log_age_days * 24 * 3600)
            
            for log_file in log_dir.glob("*"):
                if log_file.is_file():
                    try:
                        mtime = log_file.stat().st_mtime
                        if mtime < cutoff_time:
                            size_mb = log_file.stat().st_size // (1024 * 1024)
                            logger.info(f"Deleting old log: {log_file.name} ({size_mb}MB)")
                            log_file.unlink()
                            
                            stats["deleted_files"].append({
                                "name": log_file.name,
                                "size_mb": size_mb,
                            })
                            stats["freed_space_mb"] += size_mb
                    except Exception as e:
                        logger.warning(f"Error deleting log {log_file}: {e}")
            
            if stats["deleted_files"]:
                logger.info(f"Log cleanup completed: deleted {len(stats['deleted_files'])} files, freed {stats['freed_space_mb']}MB")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error during log cleanup: {e}", exc_info=True)
            return stats
    
    def cleanup_temp_files(self) -> Dict[str, any]:
        """
        Pulisce file temporanei e cache.
        """
        stats = {
            "deleted_files": [],
            "freed_space_mb": 0,
        }
        
        try:
            # Pulisci __pycache__
            for pycache_dir in self.agent_dir.rglob("__pycache__"):
                try:
                    size_mb = sum(f.stat().st_size for f in pycache_dir.rglob("*") if f.is_file()) // (1024 * 1024)
                    shutil.rmtree(pycache_dir)
                    stats["deleted_files"].append({"name": str(pycache_dir.relative_to(self.agent_dir)), "size_mb": size_mb})
                    stats["freed_space_mb"] += size_mb
                except Exception as e:
                    logger.warning(f"Error deleting __pycache__ {pycache_dir}: {e}")
            
            # Pulisci file .pyc
            for pyc_file in self.agent_dir.rglob("*.pyc"):
                try:
                    size_mb = pyc_file.stat().st_size // (1024 * 1024)
                    pyc_file.unlink()
                    stats["deleted_files"].append({"name": str(pyc_file.relative_to(self.agent_dir)), "size_mb": size_mb})
                    stats["freed_space_mb"] += size_mb
                except Exception as e:
                    logger.warning(f"Error deleting .pyc {pyc_file}: {e}")
            
            # Pulisci file temporanei (.tmp, .temp, .swp)
            temp_patterns = ["*.tmp", "*.temp", "*.swp", "*.bak"]
            for pattern in temp_patterns:
                for temp_file in self.agent_dir.rglob(pattern):
                    try:
                        size_mb = temp_file.stat().st_size // (1024 * 1024)
                        temp_file.unlink()
                        stats["deleted_files"].append({"name": str(temp_file.relative_to(self.agent_dir)), "size_mb": size_mb})
                        stats["freed_space_mb"] += size_mb
                    except Exception as e:
                        logger.warning(f"Error deleting temp file {temp_file}: {e}")
            
            if stats["deleted_files"]:
                logger.info(f"Temp files cleanup completed: deleted {len(stats['deleted_files'])} files, freed {stats['freed_space_mb']}MB")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error during temp files cleanup: {e}", exc_info=True)
            return stats
    
    def cleanup_all(self, force: bool = False) -> Dict[str, any]:
        """
        Esegue pulizia completa dello spazio disco.
        
        Ritorna dict con statistiche totali.
        """
        logger.info("Starting disk cleanup...")
        
        total_stats = {
            "backups": {},
            "logs": {},
            "temp_files": {},
            "total_freed_mb": 0,
        }
        
        # 1. Pulisci backup vecchi
        total_stats["backups"] = self.cleanup_old_backups(force=force)
        total_stats["total_freed_mb"] += total_stats["backups"].get("freed_space_mb", 0)
        
        # 2. Pulisci log vecchi
        total_stats["logs"] = self.cleanup_logs()
        total_stats["total_freed_mb"] += total_stats["logs"].get("freed_space_mb", 0)
        
        # 3. Pulisci file temporanei
        total_stats["temp_files"] = self.cleanup_temp_files()
        total_stats["total_freed_mb"] += total_stats["temp_files"].get("freed_space_mb", 0)
        
        # Mostra statistiche finali
        disk_usage = self.get_disk_usage()
        logger.info(f"Cleanup completed: freed {total_stats['total_freed_mb']}MB total")
        logger.info(f"Disk usage: {disk_usage.get('free_mb', 0)}MB free / {disk_usage.get('total_bytes', 0) // (1024*1024)}MB total")
        
        return total_stats

