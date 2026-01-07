"""
WebSocket Hub Proxy Utility

This module provides a helper to access the WebSocket Hub across dual-port architecture.
When running with dual ports (Agent API on 8000, Admin UI on 8001), the WebSocket Hub
lives only in the Agent API process. Admin UI needs to proxy requests to access it.
"""

import os
from typing import Optional
from ..services.websocket_hub import AgentWebSocketHub, get_websocket_hub


def get_websocket_hub_for_request() -> AgentWebSocketHub:
    """
    Get the WebSocket Hub instance, handling dual-port architecture.

    In dual-port mode:
    - Agent API (port 8000): Returns local WebSocket Hub with active connections
    - Admin UI (port 8001): Returns local WebSocket Hub (which may be empty)

    Note: This function returns the local hub. For cross-process access from Admin UI,
    use HTTP proxy endpoints instead (e.g., /api/v1/admin/agents/ws/connected).

    Returns:
        AgentWebSocketHub: The local WebSocket Hub instance
    """
    # Always return local hub - this is intentional
    # Endpoints that need cross-process access should use HTTP proxy
    return get_websocket_hub()


def is_admin_ui_process() -> bool:
    """
    Detect if running in Admin UI process (port 8001) vs Agent API (port 8000).

    Returns:
        bool: True if running on Admin UI, False if on Agent API
    """
    # Check if we're running on port 8001 (Admin UI)
    # This can be detected from environment variable or server config
    port = os.getenv("SERVER_PORT", "8000")
    return port == "8001"
