"""
DaDude - Webhook Service
Gestisce l'inoltro delle notifiche a sistemi esterni
"""
from typing import Optional, List, Dict, Any
from datetime import datetime
from loguru import logger
import httpx
import asyncio
import uuid
import json

from ..config import get_settings
from ..models import WebhookPayload


class WebhookDestination:
    """Destinazione webhook"""
    def __init__(
        self,
        url: str,
        name: str,
        events: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.id = str(uuid.uuid4())[:8]
        self.url = url
        self.name = name
        self.events = events  # None = tutti gli eventi
        self.headers = headers or {}
        self.created_at = datetime.utcnow()
        self.last_success: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.success_count = 0
        self.error_count = 0
    
    def should_forward(self, event_type: str) -> bool:
        """Verifica se questo evento deve essere inoltrato"""
        if self.events is None:
            return True
        return event_type in self.events
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "name": self.name,
            "events": self.events,
            "created_at": self.created_at.isoformat(),
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "last_error": self.last_error,
            "success_count": self.success_count,
            "error_count": self.error_count,
        }


class WebhookService:
    """Servizio per inoltro webhook a sistemi esterni"""
    
    def __init__(self):
        self._destinations: List[WebhookDestination] = []
        self._client: Optional[httpx.AsyncClient] = None
        self._setup_default_destination()
    
    def _setup_default_destination(self):
        """Configura destinazione webhook da settings"""
        settings = get_settings()
        if settings.webhook_url:
            headers = {}
            if settings.webhook_secret:
                headers["X-Webhook-Secret"] = settings.webhook_secret
            
            self.add_destination(
                url=settings.webhook_url,
                name="Default (from config)",
                headers=headers,
            )
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Ottiene client HTTP"""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client
    
    def has_destinations(self) -> bool:
        """Verifica se ci sono destinazioni configurate"""
        return len(self._destinations) > 0
    
    def get_destinations(self) -> List[Dict[str, Any]]:
        """Lista destinazioni"""
        return [d.to_dict() for d in self._destinations]
    
    def add_destination(
        self,
        url: str,
        name: str,
        events: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Aggiunge destinazione"""
        dest = WebhookDestination(url=url, name=name, events=events, headers=headers)
        self._destinations.append(dest)
        logger.info(f"Added webhook destination: {name} -> {url}")
        return dest.to_dict()
    
    def remove_destination(self, destination_id: str) -> bool:
        """Rimuove destinazione"""
        for i, dest in enumerate(self._destinations):
            if dest.id == destination_id:
                self._destinations.pop(i)
                logger.info(f"Removed webhook destination: {dest.name}")
                return True
        return False
    
    async def forward_webhook(self, payload: WebhookPayload):
        """Inoltra webhook a tutte le destinazioni appropriate"""
        if not self._destinations:
            return
        
        client = await self._get_client()
        
        # Prepara payload JSON
        json_payload = {
            "event_type": payload.event_type,
            "device_id": payload.device_id,
            "device_name": payload.device_name,
            "probe_id": payload.probe_id,
            "probe_name": payload.probe_name,
            "old_status": payload.old_status,
            "new_status": payload.new_status,
            "message": payload.message,
            "timestamp": payload.timestamp.isoformat(),
            "extra_data": payload.extra_data,
            "source": "DaDude",
        }
        
        # Inoltra a ogni destinazione
        tasks = []
        for dest in self._destinations:
            if dest.should_forward(payload.event_type):
                tasks.append(self._send_to_destination(client, dest, json_payload))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_to_destination(
        self,
        client: httpx.AsyncClient,
        dest: WebhookDestination,
        payload: Dict[str, Any],
    ):
        """Invia a singola destinazione"""
        try:
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "DaDude/1.0",
                **dest.headers,
            }
            
            response = await client.post(
                dest.url,
                json=payload,
                headers=headers,
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                dest.last_success = datetime.utcnow()
                dest.success_count += 1
                logger.debug(f"Webhook sent to {dest.name}: {response.status_code}")
            else:
                dest.last_error = f"HTTP {response.status_code}"
                dest.error_count += 1
                logger.warning(f"Webhook to {dest.name} failed: {response.status_code}")
                
        except Exception as e:
            dest.last_error = str(e)
            dest.error_count += 1
            logger.error(f"Error sending webhook to {dest.name}: {e}")
    
    async def close(self):
        """Chiude client HTTP"""
        if self._client:
            await self._client.aclose()
            self._client = None


# Singleton
_webhook_service: Optional[WebhookService] = None


def get_webhook_service() -> WebhookService:
    """Get singleton WebhookService instance"""
    global _webhook_service
    if _webhook_service is None:
        _webhook_service = WebhookService()
    return _webhook_service
