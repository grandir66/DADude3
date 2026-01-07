"""
DaDude Agent - Connection State Machine
Gestisce transizioni di stato della connessione con fallback SFTP
"""
import asyncio
from datetime import datetime, timedelta
from typing import Optional, Callable, Awaitable
from enum import Enum
from dataclasses import dataclass
from loguru import logger


class ConnectionState(str, Enum):
    """Stati della connessione"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    SFTP_FALLBACK = "sftp_fallback"
    ERROR = "error"


class ConnectionEvent(str, Enum):
    """Eventi che causano transizioni"""
    CONNECT = "connect"
    CONNECTED = "connected"
    DISCONNECT = "disconnect"
    CONNECTION_LOST = "connection_lost"
    CONNECTION_ERROR = "connection_error"
    RECONNECT_SUCCESS = "reconnect_success"
    RECONNECT_TIMEOUT = "reconnect_timeout"
    SFTP_COMPLETE = "sftp_complete"
    SFTP_FAILED = "sftp_failed"


@dataclass
class StateTransition:
    """Transizione di stato"""
    from_state: ConnectionState
    event: ConnectionEvent
    to_state: ConnectionState


class ConnectionStateMachine:
    """
    State machine per gestione connessione con fallback.
    
    Stati:
    - DISCONNECTED: Non connesso
    - CONNECTING: Tentativo connessione in corso
    - CONNECTED: Connesso e operativo
    - RECONNECTING: Riconnessione in corso dopo perdita connessione
    - SFTP_FALLBACK: Fallback a upload SFTP (server irraggiungibile per troppo tempo)
    - ERROR: Errore critico, richiede intervento
    
    Transizioni:
    - DISCONNECTED + connect -> CONNECTING
    - CONNECTING + connected -> CONNECTED
    - CONNECTING + error -> RECONNECTING
    - CONNECTED + connection_lost -> RECONNECTING
    - RECONNECTING + success -> CONNECTED
    - RECONNECTING + timeout -> SFTP_FALLBACK
    - SFTP_FALLBACK + complete -> RECONNECTING
    """
    
    # Definizione transizioni valide
    TRANSITIONS = [
        StateTransition(ConnectionState.DISCONNECTED, ConnectionEvent.CONNECT, ConnectionState.CONNECTING),
        StateTransition(ConnectionState.CONNECTING, ConnectionEvent.CONNECTED, ConnectionState.CONNECTED),
        StateTransition(ConnectionState.CONNECTING, ConnectionEvent.CONNECTION_ERROR, ConnectionState.RECONNECTING),
        StateTransition(ConnectionState.CONNECTED, ConnectionEvent.DISCONNECT, ConnectionState.DISCONNECTED),
        StateTransition(ConnectionState.CONNECTED, ConnectionEvent.CONNECTION_LOST, ConnectionState.RECONNECTING),
        StateTransition(ConnectionState.RECONNECTING, ConnectionEvent.RECONNECT_SUCCESS, ConnectionState.CONNECTED),
        StateTransition(ConnectionState.RECONNECTING, ConnectionEvent.RECONNECT_TIMEOUT, ConnectionState.SFTP_FALLBACK),
        StateTransition(ConnectionState.SFTP_FALLBACK, ConnectionEvent.SFTP_COMPLETE, ConnectionState.RECONNECTING),
        StateTransition(ConnectionState.SFTP_FALLBACK, ConnectionEvent.SFTP_FAILED, ConnectionState.ERROR),
        StateTransition(ConnectionState.ERROR, ConnectionEvent.CONNECT, ConnectionState.CONNECTING),
    ]
    
    def __init__(
        self,
        sftp_fallback_timeout_minutes: int = 30,
        on_state_change: Optional[Callable[[ConnectionState, ConnectionState], Awaitable[None]]] = None,
        on_sftp_required: Optional[Callable[[], Awaitable[bool]]] = None,
    ):
        self._state = ConnectionState.DISCONNECTED
        self._sftp_timeout = timedelta(minutes=sftp_fallback_timeout_minutes)
        
        # Handlers
        self._on_state_change = on_state_change
        self._on_sftp_required = on_sftp_required
        
        # Timing
        self._last_connected: Optional[datetime] = None
        self._disconnected_since: Optional[datetime] = None
        self._state_history: list = []
        
        # Build transition map
        self._transition_map = {}
        for t in self.TRANSITIONS:
            key = (t.from_state, t.event)
            self._transition_map[key] = t.to_state
    
    @property
    def state(self) -> ConnectionState:
        return self._state
    
    @property
    def is_connected(self) -> bool:
        return self._state == ConnectionState.CONNECTED
    
    @property
    def disconnected_duration(self) -> Optional[timedelta]:
        """Durata disconnessione corrente"""
        if self._disconnected_since:
            return datetime.utcnow() - self._disconnected_since
        return None
    
    @property
    def should_fallback_to_sftp(self) -> bool:
        """Verifica se deve passare a SFTP fallback"""
        if self._state != ConnectionState.RECONNECTING:
            return False
        
        duration = self.disconnected_duration
        if duration and duration > self._sftp_timeout:
            return True
        return False
    
    async def handle_event(self, event: ConnectionEvent) -> bool:
        """
        Gestisce evento e transizione stato.
        
        Returns:
            True se transizione avvenuta, False se non valida
        """
        key = (self._state, event)
        
        if key not in self._transition_map:
            logger.warning(f"Invalid transition: {self._state.value} + {event.value}")
            return False
        
        new_state = self._transition_map[key]
        old_state = self._state
        
        # Aggiorna timing
        if new_state == ConnectionState.CONNECTED:
            self._last_connected = datetime.utcnow()
            self._disconnected_since = None
        elif new_state in (ConnectionState.DISCONNECTED, ConnectionState.RECONNECTING):
            if self._disconnected_since is None:
                self._disconnected_since = datetime.utcnow()
        
        # Esegui transizione
        self._state = new_state
        self._state_history.append({
            "from": old_state.value,
            "to": new_state.value,
            "event": event.value,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        logger.info(f"State transition: {old_state.value} --[{event.value}]--> {new_state.value}")
        
        # Notifica handler
        if self._on_state_change:
            try:
                await self._on_state_change(old_state, new_state)
            except Exception as e:
                logger.error(f"State change handler error: {e}")
        
        # Trigger SFTP se necessario
        if new_state == ConnectionState.SFTP_FALLBACK:
            if self._on_sftp_required:
                try:
                    success = await self._on_sftp_required()
                    if success:
                        await self.handle_event(ConnectionEvent.SFTP_COMPLETE)
                    else:
                        await self.handle_event(ConnectionEvent.SFTP_FAILED)
                except Exception as e:
                    logger.error(f"SFTP handler error: {e}")
                    await self.handle_event(ConnectionEvent.SFTP_FAILED)
        
        return True
    
    async def check_sftp_timeout(self) -> bool:
        """
        Verifica timeout e trigger SFTP fallback se necessario.
        Da chiamare periodicamente.
        
        Returns:
            True se passato a SFTP fallback
        """
        if self.should_fallback_to_sftp:
            await self.handle_event(ConnectionEvent.RECONNECT_TIMEOUT)
            return True
        return False
    
    def get_history(self, limit: int = 10) -> list:
        """Ottiene ultimi N eventi"""
        return self._state_history[-limit:]
    
    def reset(self):
        """Reset state machine"""
        self._state = ConnectionState.DISCONNECTED
        self._last_connected = None
        self._disconnected_since = None
        self._state_history = []


class ConnectionManager:
    """
    Manager che combina WebSocket client e state machine.
    Gestisce automaticamente riconnessione e fallback SFTP.
    """
    
    def __init__(
        self,
        ws_client,  # AgentWebSocketClient
        sftp_uploader,  # SFTPFallbackUploader
        local_queue,  # LocalQueue
        sftp_timeout_minutes: int = 30,
    ):
        self.ws_client = ws_client
        self.sftp_uploader = sftp_uploader
        self.local_queue = local_queue
        
        # State machine
        self.state_machine = ConnectionStateMachine(
            sftp_fallback_timeout_minutes=sftp_timeout_minutes,
            on_state_change=self._on_state_change,
            on_sftp_required=self._on_sftp_required,
        )
        
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Avvia connection manager"""
        self._running = True
        
        # Avvia monitoring
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        
        # Connetti
        await self.state_machine.handle_event(ConnectionEvent.CONNECT)
        
        # Avvia WS client
        await self.ws_client.run()
    
    async def stop(self):
        """Ferma connection manager"""
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        await self.ws_client.disconnect()
    
    async def _monitor_loop(self):
        """Loop monitoraggio stato connessione"""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check ogni minuto
                
                # Aggiorna stato basandosi su WS client
                if self.ws_client.is_connected:
                    if not self.state_machine.is_connected:
                        await self.state_machine.handle_event(ConnectionEvent.CONNECTED)
                else:
                    if self.state_machine.is_connected:
                        await self.state_machine.handle_event(ConnectionEvent.CONNECTION_LOST)
                
                # Check SFTP timeout
                await self.state_machine.check_sftp_timeout()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor error: {e}")
    
    async def _on_state_change(self, old_state: ConnectionState, new_state: ConnectionState):
        """Handler cambio stato"""
        logger.info(f"Connection state: {old_state.value} -> {new_state.value}")
    
    async def _on_sftp_required(self) -> bool:
        """Handler per upload SFTP"""
        logger.warning("SFTP fallback triggered - uploading pending data")
        
        try:
            # Ottieni dati pendenti dalla coda
            pending_items = await self.local_queue.get_all_pending()
            
            if not pending_items:
                logger.info("No pending data to upload via SFTP")
                return True
            
            # Crea dump crittografato e upload
            success = await self.sftp_uploader.upload_pending_data(pending_items)
            
            if success:
                # Marca come inviati
                for item in pending_items:
                    await self.local_queue.mark_sent(item["id"])
                logger.success(f"SFTP upload complete: {len(pending_items)} items")
            
            return success
            
        except Exception as e:
            logger.error(f"SFTP fallback failed: {e}")
            return False

