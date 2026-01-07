"""
DaDude Agent - WebSocket Client
Client WebSocket per connessione mTLS al server DaDude
"""
import asyncio
import json
import ssl
import random
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Callable, Awaitable
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path

import websockets
from websockets.client import WebSocketClientProtocol
from loguru import logger


class ConnectionState(str, Enum):
    """Stati della connessione"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    SFTP_FALLBACK = "sftp_fallback"
    ERROR = "error"


class MessageType(str, Enum):
    """Tipi di messaggio"""
    # Agent -> Server
    HEARTBEAT = "heartbeat"
    RESULT = "result"
    LOG = "log"
    METRICS = "metrics"
    
    # Server -> Agent
    COMMAND = "command"
    CONFIG_UPDATE = "config_update"
    ACK = "ack"


@dataclass
class ReconnectionPolicy:
    """Policy per riconnessione con exponential backoff"""
    initial_delay: float = 1.0
    max_delay: float = 300.0  # 5 minuti max
    multiplier: float = 2.0
    max_attempts: int = -1  # -1 = infinito
    jitter_factor: float = 0.1
    
    _attempt: int = field(default=0, init=False, repr=False)
    
    def next_delay(self) -> float:
        """Calcola prossimo delay con jitter"""
        delay = min(
            self.initial_delay * (self.multiplier ** self._attempt),
            self.max_delay
        )
        # Aggiungi jitter
        jitter = random.uniform(0, delay * self.jitter_factor)
        self._attempt += 1
        return delay + jitter
    
    def reset(self):
        """Reset contatore tentativi"""
        self._attempt = 0
    
    @property
    def attempts(self) -> int:
        return self._attempt
    
    def should_retry(self) -> bool:
        """Verifica se deve riprovare"""
        if self.max_attempts < 0:
            return True
        return self._attempt < self.max_attempts


@dataclass
class Message:
    """Messaggio WebSocket"""
    type: MessageType
    data: Dict[str, Any] = field(default_factory=dict)
    id: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_json(self) -> str:
        return json.dumps({
            "type": self.type.value if isinstance(self.type, MessageType) else self.type,
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            **self.data
        })
    
    @classmethod
    def from_json(cls, data: str) -> "Message":
        parsed = json.loads(data)
        return cls(
            type=parsed.get("type", "unknown"),
            data={k: v for k, v in parsed.items() if k not in ("type", "id", "timestamp")},
            id=parsed.get("id"),
        )


@dataclass
class RetryMessage:
    """Messaggio in attesa di retry con exponential backoff"""
    message: Message
    attempts: int = 0
    next_retry_at: datetime = field(default_factory=datetime.utcnow)
    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    multiplier: float = 2.0
    
    def should_retry(self) -> bool:
        """Verifica se deve riprovare"""
        return self.attempts < self.max_attempts
    
    def get_delay(self) -> float:
        """Calcola delay per prossimo tentativo con exponential backoff"""
        delay = min(
            self.base_delay * (self.multiplier ** self.attempts),
            self.max_delay
        )
        # Aggiungi jitter
        jitter = random.uniform(0, delay * 0.1)
        return delay + jitter
    
    def schedule_next_retry(self):
        """Programma prossimo tentativo"""
        self.attempts += 1
        delay = self.get_delay()
        self.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)


class AgentWebSocketClient:
    """
    Client WebSocket per connessione al server DaDude.
    Supporta mTLS, auto-reconnect con exponential backoff,
    e gestione messaggi bidirezionali.
    """
    
    def __init__(
        self,
        server_url: str,
        agent_id: str,
        agent_token: str,
        agent_version: str = "3.0.0",
        client_cert_path: Optional[str] = None,
        client_key_path: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        reconnect_policy: Optional[ReconnectionPolicy] = None,
    ):
        self.server_url = server_url
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.agent_version = agent_version
        
        # Certificati mTLS
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path
        self.ca_cert_path = ca_cert_path
        
        # Stato
        self._state = ConnectionState.DISCONNECTED
        self._websocket: Optional[WebSocketClientProtocol] = None
        self._reconnect_policy = reconnect_policy or ReconnectionPolicy()
        self._running = False
        
        # Task
        self._receive_task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._reconnect_task: Optional[asyncio.Task] = None
        self._retry_task: Optional[asyncio.Task] = None
        
        # Handlers
        self._command_handler: Optional[Callable[[Dict], Awaitable[Dict]]] = None
        self._state_change_handler: Optional[Callable[[ConnectionState], Awaitable[None]]] = None
        
        # Metriche
        self._last_heartbeat: Optional[datetime] = None
        self._messages_sent = 0
        self._messages_received = 0
        self._reconnect_count = 0
        
        # Coda messaggi pendenti (per offline mode)
        self._pending_queue: asyncio.Queue = asyncio.Queue()
        
        # Coda messaggi in retry con exponential backoff
        self._retry_queue: list[RetryMessage] = []
        self._retry_queue_lock = asyncio.Lock()
        
        # Heartbeat config - aumentato a 60s per evitare disconnessioni premature
        self._heartbeat_interval = 60  # secondi
    
    @property
    def state(self) -> ConnectionState:
        return self._state
    
    @property
    def is_connected(self) -> bool:
        return self._state == ConnectionState.CONNECTED
    
    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Crea SSL context per mTLS o connessione HTTPS semplice"""
        # Controlla se il server usa HTTPS/WSS
        is_secure = self.server_url.startswith("https://") or self.server_url.startswith("wss://")
        
        if not is_secure:
            # Connessione non sicura (ws://) - NO SSL
            logger.info("HTTP mode - SSL disabled")
            return None
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # IMPORTANTE: Per certificati self-signed del server, disabilita sempre la verifica
        # anche se abbiamo un CA cert (il CA cert è per mTLS client, non per verificare il server)
        # Il server usa certificati self-signed, quindi dobbiamo accettarli senza verifica
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        logger.info("SSL enabled without certificate verification (self-signed server cert)")
        
        # Carica certificato client per mTLS (opzionale)
        # Questo è per autenticare il client, non per verificare il server
        if self.client_cert_path and self.client_key_path:
            if Path(self.client_cert_path).exists() and Path(self.client_key_path).exists():
                context.load_cert_chain(
                    self.client_cert_path,
                    self.client_key_path
                )
                logger.info("mTLS enabled with client certificate")
        
        return context
    
    async def _set_state(self, new_state: ConnectionState):
        """Cambia stato e notifica handler"""
        if self._state != new_state:
            old_state = self._state
            self._state = new_state
            logger.info(f"Connection state: {old_state.value} -> {new_state.value}")
            
            # Salva stato connessione per watchdog
            await self._save_connection_state(new_state == ConnectionState.CONNECTED)
            
            if self._state_change_handler:
                try:
                    await self._state_change_handler(new_state)
                except Exception as e:
                    logger.error(f"State change handler error: {e}")
    
    async def _save_connection_state(self, connected: bool):
        """Salva stato connessione su file per il watchdog"""
        import json
        from pathlib import Path
        
        state_file = Path("/var/lib/dadude-agent/connection_state.json")
        
        try:
            state_file.parent.mkdir(parents=True, exist_ok=True)
            
            state = {}
            if state_file.exists():
                with open(state_file, "r") as f:
                    state = json.load(f)
            
            if connected:
                state["last_connected"] = datetime.utcnow().isoformat()
            
            state["last_state_change"] = datetime.utcnow().isoformat()
            state["is_connected"] = connected
            
            with open(state_file, "w") as f:
                json.dump(state, f, indent=2)
                
        except Exception as e:
            logger.debug(f"Error saving connection state: {e}")
    
    async def connect(self) -> bool:
        """
        Connetti al server.
        Ritorna True se connesso con successo.
        """
        if self._state == ConnectionState.CONNECTED:
            return True
        
        await self._set_state(ConnectionState.CONNECTING)
        
        try:
            # Costruisci URL WebSocket (converti http->ws, https->wss)
            base_url = self.server_url.strip() if self.server_url else ""
            
            # Se URL vuoto, errore
            if not base_url:
                raise ValueError("server_url is empty")
            
            # Converti protocollo
            if base_url.startswith("http://"):
                base_url = "ws://" + base_url[7:]
            elif base_url.startswith("https://"):
                base_url = "wss://" + base_url[8:]
            elif not base_url.startswith("ws://") and not base_url.startswith("wss://"):
                # Default: usa ws:// (http) - per wss usare https:// nell'URL
                base_url = "ws://" + base_url
            
            ws_url = f"{base_url}/api/v1/agents/ws/{self.agent_id}"
            
            # SSL context
            ssl_context = self._create_ssl_context()
            
            # Headers
            headers = {
                "Authorization": f"Bearer {self.agent_token}",
                "X-Agent-Version": self.agent_version,
            }
            
            logger.info(f"Connecting to {ws_url}")
            
            self._websocket = await websockets.connect(
                ws_url,
                ssl=ssl_context,
                additional_headers=headers,
                ping_interval=None,  # Disabilita ping client-side per evitare timeout aggressivi
                ping_timeout=None,
                close_timeout=10,
            )
            
            await self._set_state(ConnectionState.CONNECTED)
            self._reconnect_policy.reset()
            
            logger.success(f"Connected to DaDude server")
            
            return True
            
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            await self._set_state(ConnectionState.DISCONNECTED)
            return False
    
    async def disconnect(self):
        """Disconnetti dal server"""
        self._running = False
        
        # Cancella task
        for task in [self._receive_task, self._heartbeat_task, self._reconnect_task, self._retry_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Chiudi websocket
        if self._websocket:
            try:
                await self._websocket.close()
            except Exception:
                pass
            self._websocket = None
        
        await self._set_state(ConnectionState.DISCONNECTED)
        logger.info("Disconnected from server")
    
    async def run(self):
        """
        Loop principale - mantiene connessione e gestisce messaggi.
        Questa funzione blocca finché non viene chiamato disconnect().
        """
        self._running = True
        
        while self._running:
            # Connetti se non connesso
            if not self.is_connected:
                success = await self.connect()
                
                if not success:
                    if self._reconnect_policy.should_retry():
                        delay = self._reconnect_policy.next_delay()
                        logger.info(f"Reconnecting in {delay:.1f}s (attempt {self._reconnect_policy.attempts})")
                        await self._set_state(ConnectionState.RECONNECTING)
                        await asyncio.sleep(delay)
                        continue
                    else:
                        logger.error("Max reconnection attempts reached")
                        await self._set_state(ConnectionState.ERROR)
                        break
            
            # Avvia task di background
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            logger.info("Heartbeat loop started")
            self._receive_task = asyncio.create_task(self._receive_loop())
            self._retry_task = asyncio.create_task(self._retry_failed_messages())
            
            # Flush pending queue quando ci riconnettiamo
            await self.flush_pending_queue()
            
            # Attendi che uno dei task termini
            try:
                done, pending = await asyncio.wait(
                    [self._heartbeat_task, self._receive_task],
                    return_when=asyncio.FIRST_COMPLETED
                )
                
                # Cancella task pendenti (eccetto retry che continua sempre)
                for task in pending:
                    if task != self._retry_task:
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                
                # Verifica errori
                for task in done:
                    if task.exception():
                        logger.error(f"Task error: {task.exception()}")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Run loop error: {e}")
            
            # Disconnesso - riprova con delay
            await self._set_state(ConnectionState.DISCONNECTED)
            self._reconnect_count += 1
            
            # Delay prima di riconnettere per evitare loop rapidi
            if self._running:
                delay = self._reconnect_policy.next_delay()
                logger.info(f"Connection lost. Reconnecting in {delay:.1f}s...")
                await asyncio.sleep(delay)
        
        await self.disconnect()
    
    async def _receive_loop(self):
        """Loop ricezione messaggi dal server"""
        if not self._websocket:
            return
        
        try:
            async for raw_message in self._websocket:
                try:
                    message = Message.from_json(raw_message)
                    self._messages_received += 1
                    await self._handle_message(message)
                except json.JSONDecodeError as e:
                    logger.warning(f"Invalid message: {e}")
                except Exception as e:
                    logger.error(f"Message handling error: {e}")
                    
        except websockets.ConnectionClosed as e:
            logger.warning(f"Connection closed: {e.code} {e.reason}")
        except Exception as e:
            logger.error(f"Receive error: {e}")
    
    async def _handle_message(self, message: Message):
        """Gestisce messaggio ricevuto"""
        msg_type = message.type
        
        if msg_type == MessageType.COMMAND.value or msg_type == "command":
            await self._handle_command(message)
        
        elif msg_type == MessageType.ACK.value or msg_type == "ack":
            logger.debug(f"ACK received: {message.id}")
        
        elif msg_type == MessageType.CONFIG_UPDATE.value or msg_type == "config_update":
            await self._handle_config_update(message)
        
        else:
            logger.debug(f"Unhandled message type: {msg_type}")
    
    async def _handle_command(self, message: Message):
        """Gestisce comando dal server"""
        command_id = message.id or message.data.get("id")
        action = message.data.get("action")
        params = message.data.get("params", {})
        
        logger.info(f"[WS] Command received: {action} (id={command_id}, params keys: {list(params.keys())})")
        
        if self._command_handler:
            try:
                result = await self._command_handler({
                    "id": command_id,
                    "action": action,
                    "params": params,
                })
                
                # Invia risultato
                await self.send_result(command_id, result)
                
            except Exception as e:
                logger.error(f"Command handler error: {e}")
                await self.send_result(command_id, {
                    "status": "error",
                    "error": str(e),
                })
        else:
            logger.warning("No command handler registered")
            await self.send_result(command_id, {
                "status": "error",
                "error": "No command handler",
            })
    
    async def _handle_config_update(self, message: Message):
        """Gestisce aggiornamento configurazione"""
        logger.info(f"Config update received")
        # TODO: Applicare configurazione
    
    async def _heartbeat_loop(self):
        """Loop invio heartbeat periodico"""
        logger.info(f"Starting heartbeat loop (interval: {self._heartbeat_interval}s)")
        while self._running and self.is_connected:
            try:
                logger.debug("Sending heartbeat...")
                await self.send_heartbeat()
                await asyncio.sleep(self._heartbeat_interval)
            except asyncio.CancelledError:
                logger.info("Heartbeat loop cancelled")
                break
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                break
        logger.info("Heartbeat loop ended")
    
    async def send_heartbeat(self, metrics: Optional[Dict] = None):
        """Invia heartbeat al server"""
        message = Message(
            type=MessageType.HEARTBEAT,
            data={
                "agent_id": self.agent_id,
                "version": self.agent_version,
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": metrics or self._get_metrics(),
            }
        )
        await self._send(message)
        self._last_heartbeat = datetime.utcnow()
    
    async def send_result(self, task_id: str, result: Dict):
        """Invia risultato comando al server"""
        message = Message(
            type=MessageType.RESULT,
            data={
                "task_id": task_id,
                "status": result.get("status", "success"),
                "data": result.get("data"),
                "error": result.get("error"),
            },
            id=task_id,
        )
        await self._send(message)
    
    async def send_log(self, level: str, log_message: str):
        """Invia log al server"""
        message = Message(
            type=MessageType.LOG,
            data={
                "level": level,
                "message": log_message,
            }
        )
        await self._send(message)
    
    async def send_metrics(self, metrics: Dict):
        """Invia metriche al server"""
        message = Message(
            type=MessageType.METRICS,
            data={"metrics": metrics}
        )
        await self._send(message)
    
    async def _send(self, message: Message):
        """Invia messaggio al server"""
        if not self.is_connected or not self._websocket:
            # Accoda per invio successivo
            await self._pending_queue.put(message)
            logger.debug(f"Message queued (offline): {message.type}")
            return
        
        try:
            await self._websocket.send(message.to_json())
            self._messages_sent += 1
        except Exception as e:
            logger.error(f"Send error: {e}")
            # Accoda per retry con exponential backoff
            await self._add_to_retry_queue(message)
            raise
    
    async def _add_to_retry_queue(self, message: Message):
        """Aggiunge messaggio alla coda di retry"""
        async with self._retry_queue_lock:
            retry_msg = RetryMessage(message=message)
            retry_msg.schedule_next_retry()
            self._retry_queue.append(retry_msg)
            logger.debug(f"Message added to retry queue: {message.type} (attempt {retry_msg.attempts})")
    
    async def _retry_failed_messages(self):
        """Task background per riprovare messaggi falliti con exponential backoff"""
        while self._running:
            try:
                await asyncio.sleep(5)  # Check ogni 5 secondi
                
                if not self.is_connected:
                    continue
                
                now = datetime.utcnow()
                messages_to_retry = []
                
                async with self._retry_queue_lock:
                    remaining = []
                    for retry_msg in self._retry_queue:
                        if now >= retry_msg.next_retry_at:
                            if retry_msg.should_retry():
                                messages_to_retry.append(retry_msg)
                            else:
                                logger.warning(f"Message {retry_msg.message.type} exceeded max retry attempts ({retry_msg.max_attempts})")
                        else:
                            remaining.append(retry_msg)
                    self._retry_queue = remaining
                
                # Riprova messaggi pronti
                for retry_msg in messages_to_retry:
                    try:
                        await self._websocket.send(retry_msg.message.to_json())
                        self._messages_sent += 1
                        logger.debug(f"Retry successful for message {retry_msg.message.type} (attempt {retry_msg.attempts + 1})")
                        # Rimuovi dalla coda - successo
                    except Exception as e:
                        logger.debug(f"Retry failed for message {retry_msg.message.type}: {e}")
                        # Riprogramma per prossimo tentativo
                        retry_msg.schedule_next_retry()
                        async with self._retry_queue_lock:
                            if retry_msg not in self._retry_queue:
                                self._retry_queue.append(retry_msg)
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Retry task error: {e}")
    
    def _get_metrics(self) -> Dict[str, Any]:
        """Ottiene metriche agente"""
        import psutil
        
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            
            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used_mb": memory.used // (1024 * 1024),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free // (1024 * 1024 * 1024),
                "messages_sent": self._messages_sent,
                "messages_received": self._messages_received,
                "reconnect_count": self._reconnect_count,
                "pending_queue_size": self._pending_queue.qsize(),
                "retry_queue_size": len(self._retry_queue),
            }
        except Exception:
            return {}
    
    def set_command_handler(self, handler: Callable[[Dict], Awaitable[Dict]]):
        """Registra handler per comandi dal server"""
        self._command_handler = handler
    
    def set_state_change_handler(self, handler: Callable[[ConnectionState], Awaitable[None]]):
        """Registra handler per cambi di stato"""
        self._state_change_handler = handler
    
    async def flush_pending_queue(self):
        """Invia messaggi pendenti"""
        while not self._pending_queue.empty() and self.is_connected:
            try:
                message = await asyncio.wait_for(
                    self._pending_queue.get(), 
                    timeout=1.0
                )
                await self._send(message)
            except asyncio.TimeoutError:
                break
            except Exception as e:
                logger.error(f"Flush queue error: {e}")
                break

