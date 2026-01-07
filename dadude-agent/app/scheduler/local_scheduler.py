"""
DaDude Agent - Local Scheduler
Scheduler cron-like per task periodici, funziona anche offline
"""
import asyncio
import uuid
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

try:
    from croniter import croniter
    HAS_CRONITER = True
except ImportError:
    HAS_CRONITER = False


class JobStatus(str, Enum):
    """Stati job"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    DISABLED = "disabled"


@dataclass
class JobResult:
    """Risultato esecuzione job"""
    job_id: str
    started_at: datetime
    completed_at: datetime
    success: bool
    data: Optional[Dict] = None
    error: Optional[str] = None


@dataclass
class ScheduledJob:
    """Job schedulato"""
    id: str
    name: str
    cron: str  # Cron expression (es: "0 */4 * * *")
    action: str  # Azione da eseguire
    params: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    fail_count: int = 0
    last_error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "cron": self.cron,
            "action": self.action,
            "params": self.params,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "run_count": self.run_count,
            "fail_count": self.fail_count,
            "last_error": self.last_error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "ScheduledJob":
        return cls(
            id=data.get("id", str(uuid.uuid4())[:8]),
            name=data["name"],
            cron=data["cron"],
            action=data["action"],
            params=data.get("params", {}),
            enabled=data.get("enabled", True),
            last_run=datetime.fromisoformat(data["last_run"]) if data.get("last_run") else None,
            next_run=datetime.fromisoformat(data["next_run"]) if data.get("next_run") else None,
            run_count=data.get("run_count", 0),
            fail_count=data.get("fail_count", 0),
            last_error=data.get("last_error"),
        )


class LocalScheduler:
    """
    Scheduler locale per esecuzione task periodici.
    
    Funziona anche quando l'agent è offline (non connesso al server).
    I risultati vengono accodati nella LocalQueue per invio successivo.
    
    Supporta:
    - Cron expressions standard
    - Task one-shot con delay
    - Persistenza stato su disco
    - Retry automatico su fallimento
    """
    
    # Job predefiniti
    DEFAULT_JOBS = [
        ScheduledJob(
            id="scan-network",
            name="Network Scan",
            cron="0 */4 * * *",  # Ogni 4 ore
            action="scan_network",
            params={"scan_type": "ping"},
        ),
        ScheduledJob(
            id="cleanup-queue",
            name="Queue Cleanup",
            cron="0 3 * * *",  # Ogni notte alle 3
            action="cleanup_queue",
        ),
        ScheduledJob(
            id="check-updates",
            name="Check Updates",
            cron="0 5 * * 0",  # Domenica alle 5
            action="check_updates",
        ),
        ScheduledJob(
            id="daily-restart",
            name="Daily Restart",
            cron="0 4 * * *",  # Ogni giorno alle 4 di mattina
            action="daily_restart",
            params={"force": True},
        ),
        ScheduledJob(
            id="connection-watchdog",
            name="Connection Watchdog",
            cron="0 * * * *",  # Ogni ora
            action="connection_watchdog",
            params={"max_disconnected_hours": 24},
        ),
    ]
    
    def __init__(
        self,
        command_handler,  # CommandHandler
        local_queue,  # LocalQueue
        state_file: str = "/var/lib/dadude-agent/scheduler_state.json",
    ):
        self.command_handler = command_handler
        self.local_queue = local_queue
        self.state_file = state_file
        
        self._jobs: Dict[str, ScheduledJob] = {}
        self._running = False
        self._scheduler_task: Optional[asyncio.Task] = None
        
        # Carica stato salvato
        self._load_state()
    
    def _load_state(self):
        """Carica stato da file"""
        import json
        from pathlib import Path
        
        state_path = Path(self.state_file)
        if state_path.exists():
            try:
                with open(state_path) as f:
                    data = json.load(f)
                    for job_data in data.get("jobs", []):
                        job = ScheduledJob.from_dict(job_data)
                        self._jobs[job.id] = job
                logger.info(f"Loaded {len(self._jobs)} scheduled jobs")
            except Exception as e:
                logger.error(f"Failed to load scheduler state: {e}")
        
        # Aggiungi job di default se mancanti
        for default_job in self.DEFAULT_JOBS:
            if default_job.id not in self._jobs:
                self._jobs[default_job.id] = default_job
                logger.info(f"Added default job: {default_job.name}")
    
    def _save_state(self):
        """Salva stato su file"""
        import json
        from pathlib import Path
        
        state_path = Path(self.state_file)
        state_path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "jobs": [job.to_dict() for job in self._jobs.values()],
            "updated_at": datetime.utcnow().isoformat(),
        }
        
        with open(state_path, "w") as f:
            json.dump(data, f, indent=2)
    
    async def start(self):
        """Avvia scheduler"""
        if self._running:
            return
        
        self._running = True
        
        # Calcola prossime esecuzioni
        for job in self._jobs.values():
            if job.enabled and not job.next_run:
                job.next_run = self._calculate_next_run(job.cron)
        
        self._save_state()
        
        # Avvia loop
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        
        logger.info(f"Scheduler started with {len(self._jobs)} jobs")
    
    async def stop(self):
        """Ferma scheduler"""
        self._running = False
        
        if self._scheduler_task and not self._scheduler_task.done():
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        self._save_state()
        logger.info("Scheduler stopped")
    
    async def _scheduler_loop(self):
        """Loop principale scheduler"""
        while self._running:
            try:
                now = datetime.utcnow()
                
                # Trova job da eseguire
                jobs_to_run = [
                    job for job in self._jobs.values()
                    if job.enabled and job.next_run and job.next_run <= now
                ]
                
                # Esegui job
                for job in jobs_to_run:
                    await self._execute_job(job)
                
                # Attendi 1 minuto
                await asyncio.sleep(60)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(60)
    
    async def _execute_job(self, job: ScheduledJob):
        """Esegue singolo job"""
        logger.info(f"Executing scheduled job: {job.name} ({job.action})")
        
        started_at = datetime.utcnow()
        
        try:
            # Costruisci comando
            command = {
                "id": f"scheduled-{job.id}-{started_at.timestamp()}",
                "action": job.action,
                "params": job.params,
            }
            
            # Esegui tramite command handler
            result = await self.command_handler.handle(command)
            
            # Aggiorna job
            job.last_run = started_at
            job.run_count += 1
            job.next_run = self._calculate_next_run(job.cron)
            
            if result.get("success", False):
                job.last_error = None
                logger.success(f"Job completed: {job.name}")
            else:
                job.fail_count += 1
                job.last_error = result.get("error")
                logger.warning(f"Job failed: {job.name} - {job.last_error}")
            
            # Accoda risultato per invio al server
            await self.local_queue.enqueue(
                task_id=command["id"],
                message_type="result",
                data={
                    "job_id": job.id,
                    "job_name": job.name,
                    "scheduled": True,
                    **result,
                },
            )
            
        except Exception as e:
            logger.error(f"Job execution error: {job.name} - {e}")
            job.fail_count += 1
            job.last_error = str(e)
            job.last_run = started_at
            job.next_run = self._calculate_next_run(job.cron)
        
        self._save_state()
    
    def _calculate_next_run(self, cron: str) -> Optional[datetime]:
        """Calcola prossima esecuzione da cron expression"""
        if not HAS_CRONITER:
            # Fallback senza croniter: esegui ogni 4 ore
            return datetime.utcnow() + timedelta(hours=4)
        
        try:
            cron_iter = croniter(cron, datetime.utcnow())
            return cron_iter.get_next(datetime)
        except Exception as e:
            logger.error(f"Invalid cron expression '{cron}': {e}")
            return None
    
    # ==========================================
    # JOB MANAGEMENT
    # ==========================================
    
    def add_job(self, job: ScheduledJob) -> ScheduledJob:
        """Aggiunge nuovo job"""
        if not job.id:
            job.id = str(uuid.uuid4())[:8]
        
        job.next_run = self._calculate_next_run(job.cron)
        self._jobs[job.id] = job
        self._save_state()
        
        logger.info(f"Added job: {job.name} (cron: {job.cron})")
        return job
    
    def remove_job(self, job_id: str) -> bool:
        """Rimuove job"""
        if job_id in self._jobs:
            job = self._jobs.pop(job_id)
            self._save_state()
            logger.info(f"Removed job: {job.name}")
            return True
        return False
    
    def enable_job(self, job_id: str) -> bool:
        """Abilita job"""
        if job_id in self._jobs:
            job = self._jobs[job_id]
            job.enabled = True
            job.next_run = self._calculate_next_run(job.cron)
            self._save_state()
            return True
        return False
    
    def disable_job(self, job_id: str) -> bool:
        """Disabilita job"""
        if job_id in self._jobs:
            self._jobs[job_id].enabled = False
            self._save_state()
            return True
        return False
    
    def update_job(self, job_id: str, updates: Dict) -> Optional[ScheduledJob]:
        """Aggiorna job"""
        if job_id not in self._jobs:
            return None
        
        job = self._jobs[job_id]
        
        if "name" in updates:
            job.name = updates["name"]
        if "cron" in updates:
            job.cron = updates["cron"]
            job.next_run = self._calculate_next_run(job.cron)
        if "action" in updates:
            job.action = updates["action"]
        if "params" in updates:
            job.params = updates["params"]
        if "enabled" in updates:
            job.enabled = updates["enabled"]
        
        self._save_state()
        return job
    
    def get_job(self, job_id: str) -> Optional[ScheduledJob]:
        """Ottiene job per ID"""
        return self._jobs.get(job_id)
    
    def list_jobs(self) -> List[ScheduledJob]:
        """Lista tutti i job"""
        return list(self._jobs.values())
    
    async def run_now(self, job_id: str) -> Optional[Dict]:
        """Esegue job immediatamente"""
        job = self._jobs.get(job_id)
        if not job:
            return None
        
        await self._execute_job(job)
        return job.to_dict()
    
    def get_stats(self) -> Dict[str, Any]:
        """Ottiene statistiche scheduler"""
        jobs = list(self._jobs.values())
        
        return {
            "running": self._running,
            "total_jobs": len(jobs),
            "enabled_jobs": sum(1 for j in jobs if j.enabled),
            "total_runs": sum(j.run_count for j in jobs),
            "total_failures": sum(j.fail_count for j in jobs),
            "next_job": min(
                (j for j in jobs if j.enabled and j.next_run),
                key=lambda j: j.next_run,
                default=None,
            ),
        }

