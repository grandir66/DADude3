"""
DaDude Agent - Queue Worker
Worker asincrono per svuotamento coda locale (Store & Forward)
"""
import asyncio
import random
from datetime import datetime, timedelta
from typing import Optional, Callable, Awaitable
from dataclasses import dataclass
from loguru import logger

from ..storage.local_queue import LocalQueue, QueueItem, QueueStatus
from ..connection.ws_client import AgentWebSocketClient, ConnectionState


@dataclass
class WorkerConfig:
    """Configurazione worker"""
    # Intervallo polling coda (secondi)
    poll_interval: float = 5.0
    
    # Batch size per dequeue
    batch_size: int = 10
    
    # Delay tra invii in un batch (evita flooding)
    send_delay: float = 0.1
    
    # Intervallo pulizia coda (ore)
    cleanup_interval_hours: int = 1
    
    # Giorni prima di eliminare item vecchi
    cleanup_days: int = 30
    
    # Exponential backoff per errori
    backoff_initial: float = 1.0
    backoff_max: float = 60.0
    backoff_multiplier: float = 2.0


class QueueWorker:
    """
    Worker per svuotamento coda locale.
    
    Funzionamento:
    1. Monitora la coda locale
    2. Quando connesso, preleva batch di item pendenti
    3. Invia ogni item al server via WebSocket
    4. Marca come sent o failed
    5. Esegue pulizia periodica di item vecchi
    
    Gestisce:
    - Retry con exponential backoff su errori
    - Pulizia automatica item scaduti
    - Rate limiting per evitare flooding
    """
    
    def __init__(
        self,
        queue: LocalQueue,
        ws_client: AgentWebSocketClient,
        config: Optional[WorkerConfig] = None,
    ):
        self.queue = queue
        self.ws_client = ws_client
        self.config = config or WorkerConfig()
        
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Stato backoff
        self._consecutive_failures = 0
        self._last_send_time: Optional[datetime] = None
        
        # Stats
        self._items_sent = 0
        self._items_failed = 0
        self._last_cleanup: Optional[datetime] = None
    
    async def start(self):
        """Avvia worker"""
        if self._running:
            return
        
        self._running = True
        self._worker_task = asyncio.create_task(self._worker_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Queue worker started")
    
    async def stop(self):
        """Ferma worker"""
        self._running = False
        
        for task in [self._worker_task, self._cleanup_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        logger.info(f"Queue worker stopped. Sent: {self._items_sent}, Failed: {self._items_failed}")
    
    async def _worker_loop(self):
        """Loop principale worker"""
        while self._running:
            try:
                # Attendi se non connesso
                if not self.ws_client.is_connected:
                    await asyncio.sleep(self.config.poll_interval)
                    continue
                
                # Ottieni item pendenti
                items = await self.queue.dequeue(batch_size=self.config.batch_size)
                
                if not items:
                    # Nessun item, attendi
                    await asyncio.sleep(self.config.poll_interval)
                    continue
                
                logger.debug(f"Processing {len(items)} queue items")
                
                # Processa batch
                for item in items:
                    if not self._running or not self.ws_client.is_connected:
                        # Rimetti in coda
                        await self.queue.mark_failed(item.id, "Worker stopped or disconnected")
                        break
                    
                    success = await self._send_item(item)
                    
                    if success:
                        await self.queue.mark_sent(item.id)
                        self._items_sent += 1
                        self._consecutive_failures = 0
                    else:
                        await self.queue.mark_failed(item.id, "Send failed")
                        self._items_failed += 1
                        self._consecutive_failures += 1
                    
                    # Delay tra invii
                    if self.config.send_delay > 0:
                        await asyncio.sleep(self.config.send_delay)
                
                # Backoff se troppi fallimenti consecutivi
                if self._consecutive_failures > 0:
                    delay = self._calculate_backoff()
                    logger.warning(f"Backoff: waiting {delay:.1f}s after {self._consecutive_failures} failures")
                    await asyncio.sleep(delay)
                else:
                    await asyncio.sleep(self.config.poll_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue worker error: {e}")
                await asyncio.sleep(self.config.poll_interval)
    
    async def _send_item(self, item: QueueItem) -> bool:
        """Invia singolo item al server"""
        try:
            # Costruisci messaggio appropriato
            if item.message_type == "result":
                await self.ws_client.send_result(item.task_id, item.data)
            elif item.message_type == "log":
                level = item.data.get("level", "INFO")
                message = item.data.get("message", "")
                await self.ws_client.send_log(level, message)
            elif item.message_type == "metrics":
                await self.ws_client.send_metrics(item.data)
            else:
                # Tipo generico
                await self.ws_client.send_result(item.task_id, item.data)
            
            self._last_send_time = datetime.utcnow()
            return True
            
        except Exception as e:
            logger.error(f"Failed to send queue item {item.id}: {e}")
            return False
    
    def _calculate_backoff(self) -> float:
        """Calcola delay backoff"""
        delay = min(
            self.config.backoff_initial * (self.config.backoff_multiplier ** self._consecutive_failures),
            self.config.backoff_max
        )
        # Aggiungi jitter
        jitter = random.uniform(0, delay * 0.1)
        return delay + jitter
    
    async def _cleanup_loop(self):
        """Loop pulizia periodica"""
        interval = timedelta(hours=self.config.cleanup_interval_hours)
        
        while self._running:
            try:
                await asyncio.sleep(interval.total_seconds())
                
                # Cleanup item scaduti
                await self.queue.cleanup_expired()
                
                # Cleanup item vecchi già processati
                await self.queue.cleanup_old(days=self.config.cleanup_days)
                
                self._last_cleanup = datetime.utcnow()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    async def flush_all(self) -> int:
        """Forza invio di tutti gli item pendenti"""
        if not self.ws_client.is_connected:
            logger.warning("Cannot flush: not connected")
            return 0
        
        sent = 0
        
        while True:
            items = await self.queue.dequeue(batch_size=100)
            if not items:
                break
            
            for item in items:
                if not self.ws_client.is_connected:
                    await self.queue.mark_failed(item.id, "Disconnected during flush")
                    break
                
                success = await self._send_item(item)
                if success:
                    await self.queue.mark_sent(item.id)
                    sent += 1
                else:
                    await self.queue.mark_failed(item.id, "Send failed during flush")
        
        logger.info(f"Flush complete: {sent} items sent")
        return sent
    
    async def get_stats(self) -> dict:
        """Ottiene statistiche worker"""
        queue_stats = await self.queue.get_stats()
        
        return {
            "running": self._running,
            "connected": self.ws_client.is_connected,
            "items_sent_total": self._items_sent,
            "items_failed_total": self._items_failed,
            "consecutive_failures": self._consecutive_failures,
            "last_send": self._last_send_time.isoformat() if self._last_send_time else None,
            "last_cleanup": self._last_cleanup.isoformat() if self._last_cleanup else None,
            "queue": queue_stats,
        }


class StoreForwardManager:
    """
    Manager ad alto livello per Store & Forward.
    Combina LocalQueue e QueueWorker con logica aggiuntiva.
    """
    
    def __init__(
        self,
        ws_client: AgentWebSocketClient,
        db_path: str = "/var/lib/dadude-agent/queue.db",
        worker_config: Optional[WorkerConfig] = None,
    ):
        self.queue = LocalQueue(db_path=db_path)
        self.worker = QueueWorker(
            queue=self.queue,
            ws_client=ws_client,
            config=worker_config,
        )
        self.ws_client = ws_client
    
    async def start(self):
        """Avvia store & forward"""
        await self.worker.start()
        logger.info("Store & Forward manager started")
    
    async def stop(self):
        """Ferma store & forward"""
        await self.worker.stop()
    
    async def store_result(self, task_id: str, result: dict):
        """
        Memorizza risultato per invio.
        Se connesso, invia subito. Altrimenti accoda.
        """
        if self.ws_client.is_connected:
            try:
                await self.ws_client.send_result(task_id, result)
                return
            except Exception as e:
                logger.warning(f"Direct send failed, queueing: {e}")
        
        # Accoda per invio successivo
        await self.queue.enqueue(
            task_id=task_id,
            message_type="result",
            data=result,
        )
    
    async def store_log(self, level: str, message: str):
        """Memorizza log per invio"""
        if self.ws_client.is_connected:
            try:
                await self.ws_client.send_log(level, message)
                return
            except Exception:
                pass
        
        await self.queue.enqueue(
            task_id=f"log-{datetime.utcnow().timestamp()}",
            message_type="log",
            data={"level": level, "message": message},
            ttl_hours=24,  # Log scadono dopo 24h
        )
    
    async def store_metrics(self, metrics: dict):
        """Memorizza metriche per invio"""
        if self.ws_client.is_connected:
            try:
                await self.ws_client.send_metrics(metrics)
                return
            except Exception:
                pass
        
        await self.queue.enqueue(
            task_id=f"metrics-{datetime.utcnow().timestamp()}",
            message_type="metrics",
            data=metrics,
            ttl_hours=1,  # Metriche scadono dopo 1h (sono time-sensitive)
        )
    
    async def get_pending_count(self) -> int:
        """Conta item pendenti"""
        return await self.queue.get_pending_count()
    
    async def get_stats(self) -> dict:
        """Ottiene statistiche complete"""
        return await self.worker.get_stats()

