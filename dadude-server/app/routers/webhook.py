"""
DaDude - Webhook Router
Endpoint per ricevere notifiche da The Dude e integrarsi con sistemi esterni
"""
from fastapi import APIRouter, HTTPException, Request, Header, BackgroundTasks
from typing import Optional, List
from datetime import datetime
from loguru import logger
import hmac
import hashlib

from ..config import get_settings
from ..models import WebhookPayload, StatusResponse
from ..services import get_alert_service, get_webhook_service

router = APIRouter(prefix="/webhook", tags=["Webhook"])


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verifica firma HMAC del webhook"""
    if not secret:
        return True
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


@router.post("/receive", response_model=StatusResponse)
async def receive_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_webhook_signature: Optional[str] = Header(None),
):
    """
    Riceve notifiche webhook da The Dude.
    
    Questo endpoint deve essere configurato in The Dude come destinazione
    per le notifiche di cambio stato dispositivi/probe.
    
    Esempio configurazione in RouterOS:
    ```
    /tool fetch url="http://dadude:8000/api/v1/webhook/receive" \\
        http-method=post \\
        http-data="event_type=device_down&device_name=Router1&device_id=*1"
    ```
    """
    settings = get_settings()
    
    # Leggi body
    body = await request.body()
    
    # Verifica firma se configurata
    if settings.webhook_secret and x_webhook_signature:
        if not verify_signature(body, x_webhook_signature, settings.webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")
    
    # Parse payload
    try:
        # Supporta sia JSON che form-urlencoded
        content_type = request.headers.get("content-type", "")
        
        if "application/json" in content_type:
            data = await request.json()
        else:
            # Form data (da script RouterOS)
            form_data = await request.form()
            data = dict(form_data)
        
        payload = WebhookPayload(
            event_type=data.get("event_type", "unknown"),
            device_id=data.get("device_id"),
            device_name=data.get("device_name"),
            probe_id=data.get("probe_id"),
            probe_name=data.get("probe_name"),
            old_status=data.get("old_status"),
            new_status=data.get("new_status"),
            message=data.get("message"),
            extra_data={k: v for k, v in data.items() if k not in [
                "event_type", "device_id", "device_name", "probe_id",
                "probe_name", "old_status", "new_status", "message"
            ]},
        )
        
    except Exception as e:
        logger.error(f"Error parsing webhook payload: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")
    
    logger.info(f"Received webhook: {payload.event_type} - {payload.device_name or payload.probe_name}")
    
    # Processa in background
    alert_service = get_alert_service()
    background_tasks.add_task(alert_service.process_webhook, payload)
    
    # Inoltra a webhook esterni se configurato
    webhook_service = get_webhook_service()
    if webhook_service.has_destinations():
        background_tasks.add_task(webhook_service.forward_webhook, payload)
    
    return StatusResponse(status="accepted", message="Webhook received and queued for processing")


@router.get("/destinations")
async def list_webhook_destinations():
    """
    Lista destinazioni webhook configurate per l'inoltro.
    """
    webhook_service = get_webhook_service()
    return {
        "destinations": webhook_service.get_destinations(),
        "enabled": webhook_service.has_destinations(),
    }


@router.post("/destinations")
async def add_webhook_destination(
    url: str,
    name: Optional[str] = None,
    events: Optional[List[str]] = None,
    headers: Optional[dict] = None,
):
    """
    Aggiunge una nuova destinazione webhook.
    
    - **url**: URL destinazione
    - **name**: Nome identificativo
    - **events**: Lista eventi da inoltrare (default: tutti)
    - **headers**: Header custom da inviare
    """
    webhook_service = get_webhook_service()
    
    destination = webhook_service.add_destination(
        url=url,
        name=name or url,
        events=events,
        headers=headers,
    )
    
    return {"status": "success", "destination": destination}


@router.delete("/destinations/{destination_id}")
async def remove_webhook_destination(destination_id: str):
    """
    Rimuove una destinazione webhook.
    """
    webhook_service = get_webhook_service()
    
    if webhook_service.remove_destination(destination_id):
        return {"status": "success", "message": f"Destination {destination_id} removed"}
    else:
        raise HTTPException(status_code=404, detail=f"Destination {destination_id} not found")


@router.post("/test")
async def test_webhook(background_tasks: BackgroundTasks):
    """
    Invia un webhook di test a tutte le destinazioni configurate.
    """
    webhook_service = get_webhook_service()
    
    test_payload = WebhookPayload(
        event_type="test",
        device_name="DaDude Test",
        message="This is a test webhook from DaDude",
        timestamp=datetime.utcnow(),
    )
    
    background_tasks.add_task(webhook_service.forward_webhook, test_payload)
    
    return {
        "status": "success",
        "message": "Test webhook queued",
        "destinations": len(webhook_service.get_destinations()),
    }
