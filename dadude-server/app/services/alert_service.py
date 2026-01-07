"""
DaDude - Alert Service
Gestisce gli alert e le notifiche
"""
from typing import Optional, List
from datetime import datetime
from loguru import logger
import uuid

from ..models import Alert, WebhookPayload


class AlertService:
    """Servizio per gestione alert"""
    
    def __init__(self):
        self._alerts: List[Alert] = []
        self._max_alerts = 10000
    
    def create_alert(
        self,
        device_id: str,
        device_name: str,
        alert_type: str,
        severity: str,
        message: str,
        probe_id: Optional[str] = None,
        probe_name: Optional[str] = None,
    ) -> Alert:
        """Crea un nuovo alert"""
        alert = Alert(
            id=str(uuid.uuid4()),
            device_id=device_id,
            device_name=device_name,
            probe_id=probe_id,
            probe_name=probe_name,
            alert_type=alert_type,
            severity=severity,
            message=message,
            timestamp=datetime.utcnow(),
        )
        
        self._alerts.insert(0, alert)
        
        # Limita dimensione lista
        if len(self._alerts) > self._max_alerts:
            self._alerts = self._alerts[:self._max_alerts]
        
        logger.info(f"Alert created: {alert_type} - {device_name} - {message}")
        return alert
    
    def get_alerts(
        self,
        device_id: Optional[str] = None,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        resolved: Optional[bool] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Alert]:
        """Ottiene lista alert filtrata"""
        alerts = self._alerts
        
        if device_id:
            alerts = [a for a in alerts if a.device_id == device_id]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        if resolved is not None:
            alerts = [a for a in alerts if a.resolved == resolved]
        if since:
            alerts = [a for a in alerts if a.timestamp >= since]
        
        return alerts[:limit]
    
    def acknowledge_alert(self, alert_id: str) -> Optional[Alert]:
        """Segna alert come acknowledged"""
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                logger.info(f"Alert {alert_id} acknowledged")
                return alert
        return None
    
    def resolve_alert(self, alert_id: str) -> Optional[Alert]:
        """Segna alert come risolto"""
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.resolved = True
                alert.resolved_at = datetime.utcnow()
                logger.info(f"Alert {alert_id} resolved")
                return alert
        return None
    
    def process_webhook(self, payload: WebhookPayload):
        """Processa webhook e crea alert appropriato"""
        # Mappa event_type a severity
        severity_map = {
            "device_down": "critical",
            "device_up": "info",
            "probe_critical": "critical",
            "probe_warning": "warning",
            "probe_ok": "info",
            "test": "info",
        }
        
        severity = severity_map.get(payload.event_type, "warning")
        
        # Determina tipo alert
        if payload.event_type.startswith("device_"):
            alert_type = "device_status"
        elif payload.event_type.startswith("probe_"):
            alert_type = "probe_status"
        else:
            alert_type = payload.event_type
        
        # Costruisci messaggio
        message = payload.message
        if not message:
            if payload.old_status and payload.new_status:
                message = f"Status changed from {payload.old_status} to {payload.new_status}"
            else:
                message = f"Event: {payload.event_type}"
        
        self.create_alert(
            device_id=payload.device_id or "unknown",
            device_name=payload.device_name or "Unknown Device",
            probe_id=payload.probe_id,
            probe_name=payload.probe_name,
            alert_type=alert_type,
            severity=severity,
            message=message,
        )


# Singleton
_alert_service: Optional[AlertService] = None


def get_alert_service() -> AlertService:
    """Get singleton AlertService instance"""
    global _alert_service
    if _alert_service is None:
        _alert_service = AlertService()
    return _alert_service
