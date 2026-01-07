"""
DaDude - Data Models
"""
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class DeviceStatus(str, Enum):
    """Stati possibili dei dispositivi"""
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"
    DISABLED = "disabled"
    PARTIAL = "partial"


class ProbeStatus(str, Enum):
    """Stati possibili delle probe"""
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class Device(BaseModel):
    """Modello dispositivo Dude"""
    id: str
    name: str
    address: Optional[str] = None
    mac_address: Optional[str] = None
    status: DeviceStatus = DeviceStatus.UNKNOWN
    device_type: Optional[str] = None
    group: Optional[str] = None
    location: Optional[str] = None
    note: Optional[str] = None
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
    last_seen: Optional[datetime] = None
    uptime: Optional[str] = None
    
    class Config:
        from_attributes = True


class Probe(BaseModel):
    """Modello probe/sonda Dude"""
    id: str
    name: str
    device_id: str
    probe_type: str
    status: ProbeStatus = ProbeStatus.UNKNOWN
    value: Optional[str] = None
    unit: Optional[str] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    last_check: Optional[datetime] = None
    error_message: Optional[str] = None
    
    class Config:
        from_attributes = True


class Alert(BaseModel):
    """Modello alert/notifica"""
    id: str
    device_id: str
    device_name: str
    probe_id: Optional[str] = None
    probe_name: Optional[str] = None
    alert_type: str
    severity: str
    message: str
    timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class DeviceGroup(BaseModel):
    """Modello gruppo dispositivi"""
    id: str
    name: str
    parent_id: Optional[str] = None
    device_count: int = 0


class NetworkMap(BaseModel):
    """Modello mappa di rete"""
    id: str
    name: str
    devices: List[str] = Field(default_factory=list)


class DudeServerInfo(BaseModel):
    """Informazioni sul server Dude"""
    version: Optional[str] = None
    uptime: Optional[str] = None
    device_count: int = 0
    probe_count: int = 0
    alert_count: int = 0
    connected: bool = False
    last_sync: Optional[datetime] = None


# ============================================
# API Request/Response Models
# ============================================

class DeviceListResponse(BaseModel):
    """Response lista dispositivi"""
    total: int
    devices: List[Device]


class ProbeListResponse(BaseModel):
    """Response lista probe"""
    total: int
    probes: List[Probe]


class AlertListResponse(BaseModel):
    """Response lista alert"""
    total: int
    alerts: List[Alert]


class WebhookPayload(BaseModel):
    """Payload webhook da Dude"""
    event_type: str
    device_id: Optional[str] = None
    device_name: Optional[str] = None
    probe_id: Optional[str] = None
    probe_name: Optional[str] = None
    old_status: Optional[str] = None
    new_status: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    extra_data: Dict[str, Any] = Field(default_factory=dict)


class StatusResponse(BaseModel):
    """Response stato generale"""
    status: str
    message: str
    data: Optional[Dict[str, Any]] = None
