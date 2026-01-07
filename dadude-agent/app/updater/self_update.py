"""
DaDude Agent - Self Updater
Aggiornamento automatico dell'agent
"""
import asyncio
import hashlib
import os
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum
from loguru import logger

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class UpdateStatus(str, Enum):
    """Stati update"""
    IDLE = "idle"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    COMPLETE = "complete"
    FAILED = "failed"
    RESTART_REQUIRED = "restart_required"


@dataclass
class UpdateResult:
    """Risultato operazione update"""
    success: bool
    status: UpdateStatus
    message: str
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    error: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "status": self.status.value,
            "message": self.message,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "error": self.error,
        }


@dataclass
class UpdateInfo:
    """Info su update disponibile"""
    available: bool
    current_version: str
    latest_version: Optional[str] = None
    download_url: Optional[str] = None
    checksum: Optional[str] = None
    release_notes: Optional[str] = None
    release_date: Optional[str] = None


class SelfUpdater:
    """
    Self-updater per agent.
    
    Supporta due modalità:
    1. Docker: git pull + docker compose rebuild
    2. Binary: download nuovo eseguibile + replace + restart
    
    Procedura sicura:
    1. Scarica nuovo binario/codice in temp
    2. Verifica checksum SHA256
    3. Backup corrente
    4. Sostituisci
    5. Riavvia servizio/container
    """
    
    def __init__(
        self,
        current_version: str,
        agent_dir: str = "/opt/dadude-agent",
        backup_dir: str = "/opt/dadude-agent/backups",
        is_docker: bool = True,
        github_repo: str = "grandir66/dadude",
    ):
        self.current_version = current_version
        self.agent_dir = Path(agent_dir)
        self.backup_dir = Path(backup_dir)
        self.is_docker = is_docker
        self.github_repo = github_repo
        
        self._status = UpdateStatus.IDLE
        self._update_lock = asyncio.Lock()
        
        # Crea directory backup
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    @property
    def status(self) -> UpdateStatus:
        return self._status
    
    async def check_for_updates(self) -> UpdateInfo:
        """
        Controlla se ci sono aggiornamenti disponibili.
        
        Checks:
        1. GitHub releases API per nuove versioni
        2. Confronta con versione corrente
        """
        self._status = UpdateStatus.CHECKING
        
        try:
            if not HAS_HTTPX:
                return UpdateInfo(
                    available=False,
                    current_version=self.current_version,
                    error="httpx not available",
                )
            
            # Ottieni ultimo release da GitHub
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"https://api.github.com/repos/{self.github_repo}/releases/latest",
                    timeout=10.0,
                )
                
                if response.status_code == 404:
                    # Nessun release, check commits
                    return await self._check_git_updates()
                
                if response.status_code != 200:
                    return UpdateInfo(
                        available=False,
                        current_version=self.current_version,
                        error=f"GitHub API error: {response.status_code}",
                    )
                
                data = response.json()
                latest_version = data.get("tag_name", "").lstrip("v")
                
                # Confronta versioni
                available = self._compare_versions(self.current_version, latest_version) < 0
                
                return UpdateInfo(
                    available=available,
                    current_version=self.current_version,
                    latest_version=latest_version,
                    download_url=data.get("tarball_url"),
                    release_notes=data.get("body"),
                    release_date=data.get("published_at"),
                )
                
        except Exception as e:
            logger.error(f"Update check failed: {e}")
            return UpdateInfo(
                available=False,
                current_version=self.current_version,
                error=str(e),
            )
        finally:
            self._status = UpdateStatus.IDLE
    
    async def _check_git_updates(self) -> UpdateInfo:
        """Check updates via git (se no releases)"""
        try:
            # Fetch updates
            result = subprocess.run(
                ["git", "fetch", "origin"],
                cwd=str(self.agent_dir),
                capture_output=True,
                text=True,
                timeout=30,
            )
            
            # Check se ci sono nuovi commit
            result = subprocess.run(
                ["git", "log", "HEAD..origin/main", "--oneline"],
                cwd=str(self.agent_dir),
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            new_commits = result.stdout.strip().split("\n") if result.stdout.strip() else []
            
            return UpdateInfo(
                available=len(new_commits) > 0,
                current_version=self.current_version,
                latest_version=f"{self.current_version}+{len(new_commits)}" if new_commits else None,
                release_notes=f"{len(new_commits)} new commit(s)" if new_commits else None,
            )
            
        except Exception as e:
            return UpdateInfo(
                available=False,
                current_version=self.current_version,
                error=str(e),
            )
    
    async def update(
        self,
        download_url: Optional[str] = None,
        expected_checksum: Optional[str] = None,
    ) -> UpdateResult:
        """
        Esegue update dell'agent.
        
        Args:
            download_url: URL da cui scaricare (opzionale, usa git se None)
            expected_checksum: SHA256 checksum atteso (opzionale)
            
        Returns:
            UpdateResult con esito
        """
        async with self._update_lock:
            try:
                if self.is_docker:
                    return await self._update_docker()
                else:
                    return await self._update_binary(download_url, expected_checksum)
                    
            except Exception as e:
                logger.error(f"Update failed: {e}")
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Update failed",
                    error=str(e),
                )
    
    async def _update_docker(self) -> UpdateResult:
        """Update in ambiente Docker (git pull + rebuild)"""
        logger.info("Starting Docker update...")
        self._status = UpdateStatus.DOWNLOADING
        
        try:
            # Crea backup
            await self._create_backup()
            
            # Git pull
            self._status = UpdateStatus.DOWNLOADING
            result = subprocess.run(
                ["git", "pull", "--rebase", "origin", "main"],
                cwd=str(self.agent_dir),
                capture_output=True,
                text=True,
                timeout=120,
            )
            
            if result.returncode != 0:
                logger.error(f"Git pull failed: {result.stderr}")
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Git pull failed",
                    error=result.stderr,
                )
            
            logger.info("Git pull successful")
            
            # Rebuild container
            self._status = UpdateStatus.INSTALLING
            result = subprocess.run(
                ["docker", "compose", "build", "--no-cache"],
                cwd=str(self.agent_dir),
                capture_output=True,
                text=True,
                timeout=600,  # 10 minuti per build
            )
            
            if result.returncode != 0:
                logger.error(f"Docker build failed: {result.stderr}")
                await self._restore_backup()
                return UpdateResult(
                    success=False,
                    status=UpdateStatus.FAILED,
                    message="Docker build failed",
                    error=result.stderr,
                )
            
            logger.info("Docker build successful")
            
            # Restart container
            self._status = UpdateStatus.RESTART_REQUIRED
            
            # Avvia in background e termina
            subprocess.Popen(
                ["docker", "compose", "up", "-d", "--force-recreate"],
                cwd=str(self.agent_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            
            return UpdateResult(
                success=True,
                status=UpdateStatus.RESTART_REQUIRED,
                message="Update complete, restarting...",
                old_version=self.current_version,
            )
            
        except Exception as e:
            logger.error(f"Docker update error: {e}")
            await self._restore_backup()
            raise
    
    async def _update_binary(
        self,
        download_url: Optional[str],
        expected_checksum: Optional[str],
    ) -> UpdateResult:
        """Update binario standalone"""
        if not download_url:
            return UpdateResult(
                success=False,
                status=UpdateStatus.FAILED,
                message="Download URL required for binary update",
            )
        
        logger.info(f"Starting binary update from {download_url}")
        
        try:
            # Crea backup
            await self._create_backup()
            
            # Download
            self._status = UpdateStatus.DOWNLOADING
            temp_file = await self._download_file(download_url)
            
            # Verifica checksum
            if expected_checksum:
                self._status = UpdateStatus.VERIFYING
                actual_checksum = await self._calculate_checksum(temp_file)
                
                if actual_checksum.lower() != expected_checksum.lower():
                    os.unlink(temp_file)
                    return UpdateResult(
                        success=False,
                        status=UpdateStatus.FAILED,
                        message="Checksum verification failed",
                        error=f"Expected: {expected_checksum}, Got: {actual_checksum}",
                    )
                
                logger.info("Checksum verified")
            
            # Installa
            self._status = UpdateStatus.INSTALLING
            await self._install_binary(temp_file)
            
            # Restart
            self._status = UpdateStatus.RESTART_REQUIRED
            await self._restart_service()
            
            return UpdateResult(
                success=True,
                status=UpdateStatus.COMPLETE,
                message="Update installed successfully",
                old_version=self.current_version,
            )
            
        except Exception as e:
            logger.error(f"Binary update error: {e}")
            await self._restore_backup()
            raise
    
    async def _download_file(self, url: str) -> str:
        """Scarica file in temp"""
        if not HAS_HTTPX:
            raise RuntimeError("httpx not available")
        
        temp_path = tempfile.mktemp(suffix=".tar.gz")
        
        async with httpx.AsyncClient() as client:
            async with client.stream("GET", url, timeout=300.0) as response:
                response.raise_for_status()
                
                with open(temp_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=8192):
                        f.write(chunk)
        
        logger.info(f"Downloaded to {temp_path}")
        return temp_path
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calcola SHA256 checksum"""
        sha256 = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    async def _create_backup(self):
        """Crea backup corrente"""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = self.backup_dir / f"backup_{timestamp}"
        
        if self.agent_dir.exists():
            shutil.copytree(
                self.agent_dir,
                backup_path,
                ignore=shutil.ignore_patterns("*.pyc", "__pycache__", "*.db", "logs", "backups"),
            )
            logger.info(f"Backup created: {backup_path}")
        
        # Mantieni solo ultimi 3 backup
        backups = sorted(self.backup_dir.glob("backup_*"))
        while len(backups) > 3:
            oldest = backups.pop(0)
            shutil.rmtree(oldest)
            logger.info(f"Removed old backup: {oldest}")
    
    async def _restore_backup(self):
        """Ripristina da ultimo backup"""
        backups = sorted(self.backup_dir.glob("backup_*"))
        if not backups:
            logger.warning("No backup available to restore")
            return
        
        latest = backups[-1]
        logger.warning(f"Restoring from backup: {latest}")
        
        # Rimuovi corrente
        if self.agent_dir.exists():
            shutil.rmtree(self.agent_dir)
        
        # Ripristina
        shutil.copytree(latest, self.agent_dir)
        logger.info("Backup restored")
    
    async def _install_binary(self, temp_file: str):
        """Installa nuovo binario"""
        # Estrai tarball
        import tarfile
        
        extract_dir = tempfile.mkdtemp()
        
        with tarfile.open(temp_file, "r:gz") as tar:
            tar.extractall(extract_dir)
        
        # Trova directory agent
        subdirs = list(Path(extract_dir).iterdir())
        if len(subdirs) == 1 and subdirs[0].is_dir():
            source = subdirs[0] / "dadude-agent"
        else:
            source = Path(extract_dir)
        
        # Copia file
        for item in source.iterdir():
            dest = self.agent_dir / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)
        
        # Cleanup
        os.unlink(temp_file)
        shutil.rmtree(extract_dir)
        
        logger.info("Binary installed")
    
    async def _restart_service(self):
        """Riavvia servizio"""
        if self.is_docker:
            subprocess.Popen(
                ["docker", "compose", "restart"],
                cwd=str(self.agent_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(
                ["systemctl", "restart", "dadude-agent"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        
        logger.info("Service restart initiated")
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Confronta versioni semver.
        Ritorna: -1 se v1 < v2, 0 se ==, 1 se v1 > v2
        """
        def parse(v):
            parts = v.replace("-", ".").split(".")
            return [int(p) if p.isdigit() else 0 for p in parts[:3]]
        
        p1, p2 = parse(v1), parse(v2)
        
        for a, b in zip(p1, p2):
            if a < b:
                return -1
            if a > b:
                return 1
        return 0

