"""
DaDude - Alerts Router
API endpoints per gestione alert/notifiche
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List
from datetime import datetime, timedelta
from loguru import logger

from ..models import Alert, AlertListResponse
from ..services import get_alert_service

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    acknowledged: Optional[bool] = Query(None, description="Filter by acknowledged"),
    resolved: Optional[bool] = Query(None, description="Filter by resolved"),
    hours: int = Query(24, description="Get alerts from last N hours"),
    limit: int = Query(100, description="Max alerts to return"),
):
    """
    Ottiene lista degli alert recenti.
    """
    try:
        alert_service = get_alert_service()
        alerts = alert_service.get_alerts(
            device_id=device_id,
            severity=severity,
            acknowledged=acknowledged,
            resolved=resolved,
            since=datetime.utcnow() - timedelta(hours=hours),
            limit=limit,
        )
        
        return AlertListResponse(total=len(alerts), alerts=alerts)
        
    except Exception as e:
        logger.error(f"Error listing alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary")
async def alerts_summary():
    """
    Ottiene riepilogo alert.
    """
    alert_service = get_alert_service()
    alerts = alert_service.get_alerts(
        since=datetime.utcnow() - timedelta(hours=24),
        limit=1000,
    )
    
    return {
        "total_24h": len(alerts),
        "unacknowledged": len([a for a in alerts if not a.acknowledged]),
        "unresolved": len([a for a in alerts if not a.resolved]),
        "by_severity": {
            "critical": len([a for a in alerts if a.severity == "critical"]),
            "warning": len([a for a in alerts if a.severity == "warning"]),
            "info": len([a for a in alerts if a.severity == "info"]),
        },
    }


@router.get("/active")
async def get_active_alerts():
    """
    Ottiene solo gli alert attivi (non risolti).
    """
    alert_service = get_alert_service()
    alerts = alert_service.get_alerts(resolved=False, limit=500)
    
    return {"total": len(alerts), "alerts": alerts}


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    """
    Segna un alert come acknowledged.
    """
    try:
        alert_service = get_alert_service()
        alert = alert_service.acknowledge_alert(alert_id)
        
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        return {"status": "success", "alert": alert}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: str):
    """
    Segna un alert come risolto.
    """
    try:
        alert_service = get_alert_service()
        alert = alert_service.resolve_alert(alert_id)
        
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        return {"status": "success", "alert": alert}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
