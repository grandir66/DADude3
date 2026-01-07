"""
DaDude Agent - Local Queue
Coda di persistenza locale SQLite per offline mode (Store & Forward)
"""
import asyncio
import json
import sqlite3
from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from loguru import logger

try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False


class QueueStatus(str, Enum):
    """Stati degli item in coda"""
    PENDING = "pending"
    SENDING = "sending"
    SENT = "sent"
    FAILED = "failed"
    EXPIRED = "expired"


@dataclass
class QueueItem:
    """Item nella coda"""
    id: int
    task_id: str
    message_type: str
    data: Dict[str, Any]
    status: QueueStatus
    attempts: int
    created_at: datetime
    updated_at: datetime
    last_error: Optional[str] = None
    expires_at: Optional[datetime] = None
    
    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "QueueItem":
        """Crea QueueItem da row SQLite"""
        return cls(
            id=row["id"],
            task_id=row["task_id"],
            message_type=row["message_type"],
            data=json.loads(row["data"]),
            status=QueueStatus(row["status"]),
            attempts=row["attempts"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_error=row["last_error"],
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dict serializzabile"""
        return {
            "id": self.id,
            "task_id": self.task_id,
            "message_type": self.message_type,
            "data": self.data,
            "status": self.status.value,
            "attempts": self.attempts,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_error": self.last_error,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


class LocalQueue:
    """
    Coda di persistenza locale con SQLite.
    
    Caratteristiche:
    - Persistente su disco (sopravvive ai riavvii)
    - Thread-safe
    - Supporta retry con conteggio tentativi
    - TTL/scadenza opzionale per item
    - Async con aiosqlite (se disponibile) o sync
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS queue (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        task_id TEXT NOT NULL,
        message_type TEXT NOT NULL,
        data TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER DEFAULT 10,
        last_error TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        expires_at TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_queue_status ON queue(status);
    CREATE INDEX IF NOT EXISTS idx_queue_created ON queue(created_at);
    CREATE INDEX IF NOT EXISTS idx_queue_task_id ON queue(task_id);
    """
    
    def __init__(
        self,
        db_path: str = "/var/lib/dadude-agent/queue.db",
        max_attempts: int = 10,
        default_ttl_hours: Optional[int] = 168,  # 7 giorni default
    ):
        self.db_path = Path(db_path)
        self.max_attempts = max_attempts
        self.default_ttl_hours = default_ttl_hours
        
        # Crea directory se non esiste
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Lock per operazioni sync
        self._lock = asyncio.Lock()
        
        # Inizializza database
        self._init_db()
    
    def _init_db(self):
        """Inizializza schema database"""
        conn = sqlite3.connect(str(self.db_path))
        conn.executescript(self.SCHEMA)
        conn.commit()
        conn.close()
        logger.info(f"Local queue initialized: {self.db_path}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """Ottiene connessione SQLite"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    async def enqueue(
        self,
        task_id: str,
        message_type: str,
        data: Dict[str, Any],
        ttl_hours: Optional[int] = None,
    ) -> int:
        """
        Aggiunge item alla coda.
        
        Args:
            task_id: ID del task/comando
            message_type: Tipo messaggio (result, log, metrics)
            data: Dati da inviare
            ttl_hours: Ore prima della scadenza (None = default)
            
        Returns:
            ID dell'item creato
        """
        async with self._lock:
            now = datetime.utcnow()
            
            ttl = ttl_hours if ttl_hours is not None else self.default_ttl_hours
            expires_at = None
            if ttl:
                from datetime import timedelta
                expires_at = now + timedelta(hours=ttl)
            
            conn = self._get_connection()
            try:
                cursor = conn.execute("""
                    INSERT INTO queue (task_id, message_type, data, status, created_at, updated_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    task_id,
                    message_type,
                    json.dumps(data),
                    QueueStatus.PENDING.value,
                    now.isoformat(),
                    now.isoformat(),
                    expires_at.isoformat() if expires_at else None,
                ))
                conn.commit()
                item_id = cursor.lastrowid
                
                logger.debug(f"Enqueued: {message_type} task={task_id} id={item_id}")
                return item_id
                
            finally:
                conn.close()
    
    async def dequeue(self, batch_size: int = 10) -> List[QueueItem]:
        """
        Preleva batch di item pendenti.
        Gli item prelevati vengono marcati come 'sending'.
        
        Args:
            batch_size: Numero massimo di item da prelevare
            
        Returns:
            Lista di QueueItem
        """
        async with self._lock:
            now = datetime.utcnow()
            
            conn = self._get_connection()
            try:
                # Seleziona item pendenti non scaduti
                cursor = conn.execute("""
                    SELECT * FROM queue
                    WHERE status = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                    AND attempts < ?
                    ORDER BY created_at ASC
                    LIMIT ?
                """, (
                    QueueStatus.PENDING.value,
                    now.isoformat(),
                    self.max_attempts,
                    batch_size,
                ))
                
                rows = cursor.fetchall()
                items = [QueueItem.from_row(row) for row in rows]
                
                # Marca come sending
                if items:
                    ids = [item.id for item in items]
                    placeholders = ",".join("?" * len(ids))
                    conn.execute(f"""
                        UPDATE queue
                        SET status = ?, updated_at = ?
                        WHERE id IN ({placeholders})
                    """, [QueueStatus.SENDING.value, now.isoformat()] + ids)
                    conn.commit()
                
                return items
                
            finally:
                conn.close()
    
    async def mark_sent(self, item_id: int):
        """Marca item come inviato con successo"""
        async with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    UPDATE queue
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    QueueStatus.SENT.value,
                    datetime.utcnow().isoformat(),
                    item_id,
                ))
                conn.commit()
                logger.debug(f"Queue item sent: {item_id}")
            finally:
                conn.close()
    
    async def mark_failed(self, item_id: int, error: str):
        """Marca item come fallito (verrà riprovato)"""
        async with self._lock:
            conn = self._get_connection()
            try:
                # Incrementa attempts e torna a pending
                conn.execute("""
                    UPDATE queue
                    SET status = ?,
                        attempts = attempts + 1,
                        last_error = ?,
                        updated_at = ?
                    WHERE id = ?
                """, (
                    QueueStatus.PENDING.value,
                    error,
                    datetime.utcnow().isoformat(),
                    item_id,
                ))
                conn.commit()
                logger.debug(f"Queue item failed, will retry: {item_id}")
            finally:
                conn.close()
    
    async def mark_expired(self, item_id: int):
        """Marca item come scaduto (non verrà riprovato)"""
        async with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("""
                    UPDATE queue
                    SET status = ?, updated_at = ?
                    WHERE id = ?
                """, (
                    QueueStatus.EXPIRED.value,
                    datetime.utcnow().isoformat(),
                    item_id,
                ))
                conn.commit()
            finally:
                conn.close()
    
    async def get_pending_count(self) -> int:
        """Conta item pendenti"""
        conn = self._get_connection()
        try:
            cursor = conn.execute("""
                SELECT COUNT(*) FROM queue
                WHERE status = ?
            """, (QueueStatus.PENDING.value,))
            return cursor.fetchone()[0]
        finally:
            conn.close()
    
    async def get_all_pending(self) -> List[Dict[str, Any]]:
        """Ottiene tutti gli item pendenti come dict"""
        conn = self._get_connection()
        try:
            cursor = conn.execute("""
                SELECT * FROM queue
                WHERE status IN (?, ?)
                ORDER BY created_at ASC
            """, (QueueStatus.PENDING.value, QueueStatus.SENDING.value))
            
            rows = cursor.fetchall()
            return [QueueItem.from_row(row).to_dict() for row in rows]
        finally:
            conn.close()
    
    async def cleanup_old(self, days: int = 30):
        """Rimuove item vecchi (sent/expired) più vecchi di N giorni"""
        async with self._lock:
            from datetime import timedelta
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            conn = self._get_connection()
            try:
                cursor = conn.execute("""
                    DELETE FROM queue
                    WHERE status IN (?, ?)
                    AND updated_at < ?
                """, (
                    QueueStatus.SENT.value,
                    QueueStatus.EXPIRED.value,
                    cutoff.isoformat(),
                ))
                conn.commit()
                deleted = cursor.rowcount
                if deleted > 0:
                    logger.info(f"Cleaned up {deleted} old queue items")
                return deleted
            finally:
                conn.close()
    
    async def cleanup_expired(self):
        """Marca come expired gli item scaduti"""
        async with self._lock:
            now = datetime.utcnow()
            
            conn = self._get_connection()
            try:
                # Item con TTL scaduto
                cursor = conn.execute("""
                    UPDATE queue
                    SET status = ?, updated_at = ?
                    WHERE status = ?
                    AND expires_at IS NOT NULL
                    AND expires_at < ?
                """, (
                    QueueStatus.EXPIRED.value,
                    now.isoformat(),
                    QueueStatus.PENDING.value,
                    now.isoformat(),
                ))
                
                # Item con troppi tentativi
                cursor2 = conn.execute("""
                    UPDATE queue
                    SET status = ?, updated_at = ?, last_error = 'Max attempts exceeded'
                    WHERE status = ?
                    AND attempts >= ?
                """, (
                    QueueStatus.FAILED.value,
                    now.isoformat(),
                    QueueStatus.PENDING.value,
                    self.max_attempts,
                ))
                
                conn.commit()
                
                expired = cursor.rowcount
                failed = cursor2.rowcount
                
                if expired > 0 or failed > 0:
                    logger.info(f"Queue cleanup: {expired} expired, {failed} max attempts exceeded")
                
            finally:
                conn.close()
    
    async def get_stats(self) -> Dict[str, Any]:
        """Ottiene statistiche coda"""
        conn = self._get_connection()
        try:
            stats = {}
            
            for status in QueueStatus:
                cursor = conn.execute("""
                    SELECT COUNT(*) FROM queue WHERE status = ?
                """, (status.value,))
                stats[status.value] = cursor.fetchone()[0]
            
            # Totale
            cursor = conn.execute("SELECT COUNT(*) FROM queue")
            stats["total"] = cursor.fetchone()[0]
            
            # Item più vecchio pendente
            cursor = conn.execute("""
                SELECT MIN(created_at) FROM queue WHERE status = ?
            """, (QueueStatus.PENDING.value,))
            oldest = cursor.fetchone()[0]
            stats["oldest_pending"] = oldest
            
            return stats
            
        finally:
            conn.close()
    
    async def get_by_task_id(self, task_id: str) -> Optional[QueueItem]:
        """Trova item per task_id"""
        conn = self._get_connection()
        try:
            cursor = conn.execute("""
                SELECT * FROM queue WHERE task_id = ?
            """, (task_id,))
            row = cursor.fetchone()
            if row:
                return QueueItem.from_row(row)
            return None
        finally:
            conn.close()
    
    async def delete(self, item_id: int):
        """Elimina item dalla coda"""
        async with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM queue WHERE id = ?", (item_id,))
                conn.commit()
            finally:
                conn.close()
    
    async def clear(self):
        """Svuota tutta la coda"""
        async with self._lock:
            conn = self._get_connection()
            try:
                conn.execute("DELETE FROM queue")
                conn.commit()
                logger.warning("Queue cleared")
            finally:
                conn.close()

