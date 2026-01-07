"""
DaDude Agent - Connection Module
Gestisce connessione WebSocket al server con mTLS
"""
from .ws_client import AgentWebSocketClient, ConnectionState
from .state_machine import ConnectionStateMachine

__all__ = ["AgentWebSocketClient", "ConnectionState", "ConnectionStateMachine"]

