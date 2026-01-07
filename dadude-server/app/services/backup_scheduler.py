"""
DaDude - Backup Scheduler Service
Sistema di backup automatico
v3.0.0: Nuovo servizio
"""
import os
import gzip
import shutil
import asyncio
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from loguru import logger

from ..config import get_settings


class BackupScheduler:
    """
    Gestisce backup automatici del sistema:
    - Database PostgreSQL (dump)
    - File di configurazione
    - Certificati PKI
    
    Supporta:
    - Backup schedulati (cron-like)
    - Retention configurabile
    - Compressione automatica
    """
    
    BACKUP_DIR = "./backups"
    
    def __init__(
        self,
        backup_dir: str = None,
        retention_days: int = 30,
        enabled: bool = True
    ):
        self.backup_dir = Path(backup_dir or self.BACKUP_DIR)
        self.retention_days = retention_days
        self.enabled = enabled
        
        self._scheduler_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Assicura che directory backup esista
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    async def start(self, schedule_hours: int = 24):
        """
        Avvia scheduler backup.
        
        Args:
            schedule_hours: Intervallo tra backup in ore (default: 24 = giornaliero)
        """
        if not self.enabled:
            logger.info("Backup scheduler disabled")
            return
        
        self._running = True
        self._scheduler_task = asyncio.create_task(
            self._scheduler_loop(schedule_hours)
        )
        logger.info(f"Backup scheduler started (every {schedule_hours}h)")
    
    async def stop(self):
        """Ferma scheduler backup"""
        self._running = False
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        logger.info("Backup scheduler stopped")
    
    async def _scheduler_loop(self, schedule_hours: int):
        """Loop scheduler"""
        while self._running:
            try:
                # Attendi prossimo backup
                await asyncio.sleep(schedule_hours * 3600)
                
                if not self._running:
                    break
                
                # Esegui backup
                await self.create_backup()
                
                # Cleanup vecchi backup
                await self.cleanup_old_backups()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Backup scheduler error: {e}")
    
    async def create_backup(self, reason: str = "scheduled") -> Dict[str, Any]:
        """
        Crea backup completo del sistema.
        
        Returns:
            Dict con info sul backup creato
        """
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_name = f"dadude-backup-{timestamp}"
        backup_path = self.backup_dir / backup_name
        
        logger.info(f"Starting backup: {backup_name}")
        
        try:
            backup_path.mkdir(parents=True, exist_ok=True)
            
            files_backed_up = []
            
            # 1. Backup database PostgreSQL
            db_backup = await self._backup_database(backup_path)
            if db_backup:
                files_backed_up.append(db_backup)
            
            # 2. Backup configurazione (.env)
            env_backup = self._backup_config_files(backup_path)
            files_backed_up.extend(env_backup)
            
            # 3. Backup certificati PKI
            pki_backup = self._backup_pki(backup_path)
            files_backed_up.extend(pki_backup)
            
            # 4. Backup file VERSION
            version_backup = self._backup_version_file(backup_path)
            if version_backup:
                files_backed_up.append(version_backup)
            
            # 5. Crea archivio compresso
            archive_path = f"{backup_path}.tar.gz"
            shutil.make_archive(
                str(backup_path),
                'gztar',
                root_dir=str(backup_path.parent),
                base_dir=backup_name
            )
            
            # Rimuovi directory temporanea
            shutil.rmtree(backup_path)
            
            # Calcola dimensione
            archive_size = os.path.getsize(archive_path)
            
            result = {
                "success": True,
                "backup_name": backup_name,
                "archive_path": archive_path,
                "size_bytes": archive_size,
                "size_human": self._format_size(archive_size),
                "files_count": len(files_backed_up),
                "timestamp": timestamp,
                "reason": reason,
            }
            
            logger.info(f"Backup completed: {archive_path} ({result['size_human']})")
            return result
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            # Cleanup in caso di errore
            if backup_path.exists():
                shutil.rmtree(backup_path, ignore_errors=True)
            return {
                "success": False,
                "error": str(e),
                "backup_name": backup_name,
            }
    
    async def _backup_database(self, backup_path: Path) -> Optional[str]:
        """Backup database PostgreSQL"""
        settings = get_settings()
        db_url = settings.database_url
        
        # Estrai parametri da URL PostgreSQL
        # postgresql+psycopg2://user:pass@host:port/dbname
        if "postgresql" not in db_url:
            logger.warning("Database is not PostgreSQL, skipping DB backup")
            return None
        
        try:
            # Parse URL semplificato
            import re
            match = re.match(
                r'postgresql.*://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)',
                db_url
            )
            
            if not match:
                logger.warning(f"Could not parse database URL for backup")
                return None
            
            user, password, host, port, dbname = match.groups()
            
            dump_file = backup_path / "database.sql"
            
            # Esegui pg_dump
            env = os.environ.copy()
            env['PGPASSWORD'] = password
            
            result = subprocess.run(
                [
                    'pg_dump',
                    '-h', host,
                    '-p', port,
                    '-U', user,
                    '-d', dbname,
                    '-F', 'p',  # Plain text format
                    '-f', str(dump_file)
                ],
                env=env,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                logger.debug(f"Database backup created: {dump_file}")
                return str(dump_file)
            else:
                logger.warning(f"pg_dump failed: {result.stderr}")
                return None
                
        except FileNotFoundError:
            logger.warning("pg_dump not found, skipping database backup")
            return None
        except Exception as e:
            logger.error(f"Database backup error: {e}")
            return None
    
    def _backup_config_files(self, backup_path: Path) -> List[str]:
        """Backup file di configurazione"""
        files_backed_up = []
        
        config_files = [
            "./data/.env",
            "./docker-compose-dual.yml",
            "./docker-compose-postgres.yml",
        ]
        
        config_dir = backup_path / "config"
        config_dir.mkdir(exist_ok=True)
        
        for config_file in config_files:
            if os.path.exists(config_file):
                dest = config_dir / Path(config_file).name
                shutil.copy2(config_file, dest)
                files_backed_up.append(str(dest))
                logger.debug(f"Backed up: {config_file}")
        
        return files_backed_up
    
    def _backup_pki(self, backup_path: Path) -> List[str]:
        """Backup certificati PKI"""
        files_backed_up = []
        
        pki_dir = Path("./data/pki")
        if not pki_dir.exists():
            return files_backed_up
        
        dest_pki = backup_path / "pki"
        try:
            shutil.copytree(pki_dir, dest_pki)
            for f in dest_pki.rglob("*"):
                if f.is_file():
                    files_backed_up.append(str(f))
            logger.debug(f"Backed up PKI directory: {len(files_backed_up)} files")
        except Exception as e:
            logger.warning(f"PKI backup error: {e}")
        
        return files_backed_up
    
    def _backup_version_file(self, backup_path: Path) -> Optional[str]:
        """Backup file VERSION"""
        version_file = Path("./VERSION")
        if version_file.exists():
            dest = backup_path / "VERSION"
            shutil.copy2(version_file, dest)
            return str(dest)
        return None
    
    async def cleanup_old_backups(self) -> int:
        """
        Rimuove backup più vecchi di retention_days.
        
        Returns:
            Numero backup rimossi
        """
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        removed = 0
        
        for backup_file in self.backup_dir.glob("dadude-backup-*.tar.gz"):
            try:
                # Estrai timestamp dal nome file
                name = backup_file.stem.replace(".tar", "")
                timestamp_str = name.replace("dadude-backup-", "")
                backup_time = datetime.strptime(timestamp_str, "%Y%m%d_%H%M%S")
                
                if backup_time < cutoff:
                    backup_file.unlink()
                    removed += 1
                    logger.info(f"Removed old backup: {backup_file.name}")
            except (ValueError, OSError) as e:
                logger.warning(f"Could not process backup file {backup_file}: {e}")
        
        if removed > 0:
            logger.info(f"Cleaned up {removed} old backups")
        
        return removed
    
    def list_backups(self) -> List[Dict[str, Any]]:
        """Lista tutti i backup disponibili"""
        backups = []
        
        for backup_file in sorted(
            self.backup_dir.glob("dadude-backup-*.tar.gz"),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        ):
            try:
                stat = backup_file.stat()
                name = backup_file.stem.replace(".tar", "")
                timestamp_str = name.replace("dadude-backup-", "")
                
                backups.append({
                    "name": backup_file.name,
                    "path": str(backup_file),
                    "size_bytes": stat.st_size,
                    "size_human": self._format_size(stat.st_size),
                    "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    "timestamp": timestamp_str,
                })
            except Exception as e:
                logger.warning(f"Could not read backup {backup_file}: {e}")
        
        return backups
    
    async def restore_backup(self, backup_name: str) -> Dict[str, Any]:
        """
        Ripristina da backup.
        
        ⚠️ ATTENZIONE: Questa operazione sovrascrive i dati correnti!
        
        Args:
            backup_name: Nome file backup (es: dadude-backup-20250106_120000.tar.gz)
        
        Returns:
            Dict con risultato operazione
        """
        backup_path = self.backup_dir / backup_name
        
        if not backup_path.exists():
            return {"success": False, "error": f"Backup not found: {backup_name}"}
        
        # TODO: Implementare restore completo
        # Per ora solo placeholder
        return {
            "success": False,
            "error": "Restore not yet implemented. Manual restore required.",
            "backup_path": str(backup_path),
        }
    
    def _format_size(self, size: int) -> str:
        """Formatta dimensione in formato leggibile"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# Singleton
_backup_scheduler: Optional[BackupScheduler] = None


def get_backup_scheduler() -> BackupScheduler:
    """Ottiene istanza singleton del BackupScheduler"""
    global _backup_scheduler
    if _backup_scheduler is None:
        settings = get_settings()
        _backup_scheduler = BackupScheduler(
            retention_days=30,
            enabled=True
        )
    return _backup_scheduler
