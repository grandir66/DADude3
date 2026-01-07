"""
DaDude - Discovery Router
API endpoints per network discovery via The Dude
"""
from fastapi import APIRouter, HTTPException
from typing import Optional, List
from pydantic import BaseModel, Field
from loguru import logger

from ..services import get_dude_service

router = APIRouter(prefix="/discovery", tags=["Discovery"])


# ============================================
# Schemas
# ============================================

class AgentResponse(BaseModel):
    """Schema risposta agente"""
    id: str
    name: str
    address: str
    status: str
    version: str
    enabled: bool


class DiscoveryRequest(BaseModel):
    """Schema richiesta discovery"""
    network: str = Field(..., description="Rete CIDR, es: 192.168.1.0/24")
    agent_id: Optional[str] = Field(None, description="ID agente (None = locale)")
    scan_type: str = Field("ping", description="Tipo scan: ping, arp, snmp, all")
    add_devices: bool = Field(False, description="Aggiungi dispositivi automaticamente")


class DiscoveryResponse(BaseModel):
    """Schema risposta discovery"""
    id: str
    address_range: str
    status: str
    found: str
    added: str
    progress: str
    agent: str
    type: str


class DiscoveryResultResponse(BaseModel):
    """Schema risultato discovery"""
    id: str
    name: str
    address: str
    mac_address: str
    type: str
    status: str


class AddDeviceRequest(BaseModel):
    """Schema richiesta aggiunta dispositivo"""
    name: str
    address: str
    device_type: str = "generic"
    agent_id: Optional[str] = None
    note: Optional[str] = None
    group: Optional[str] = None


# ============================================
# Agents (Sonde)
# ============================================

@router.get("/agents", response_model=List[AgentResponse])
async def list_agents():
    """
    Lista tutti gli agenti/sonde configurati in The Dude.
    """
    try:
        dude = get_dude_service()
        agents = dude.get_agents()
        return agents
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str):
    """
    Ottiene dettagli di un agente specifico.
    """
    try:
        dude = get_dude_service()
        agent = dude.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agente non trovato")
        return agent
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Discovery
# ============================================

@router.post("/start")
async def start_discovery(request: DiscoveryRequest):
    """
    Avvia una network discovery.
    
    Parametri:
    - network: Rete da scansionare in notazione CIDR
    - agent_id: ID dell'agente da usare (opzionale, default: server locale)
    - scan_type: Tipo di scansione (ping, arp, snmp, all)
    - add_devices: Se aggiungere automaticamente i dispositivi trovati
    """
    try:
        dude = get_dude_service()
        result = dude.start_discovery(
            network=request.network,
            agent_id=request.agent_id,
            scan_type=request.scan_type,
            add_devices=request.add_devices,
        )
        
        if not result.get("success"):
            raise HTTPException(status_code=500, detail=result.get("error", "Errore sconosciuto"))
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error starting discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/list", response_model=List[DiscoveryResponse])
async def list_discoveries():
    """
    Lista tutte le discovery attive e completate.
    """
    try:
        dude = get_dude_service()
        return dude.get_discoveries()
    except Exception as e:
        logger.error(f"Error listing discoveries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{discovery_id}/results", response_model=List[DiscoveryResultResponse])
async def get_discovery_results(discovery_id: str):
    """
    Ottiene i risultati di una discovery specifica.
    """
    try:
        dude = get_dude_service()
        return dude.get_discovery_results(discovery_id)
    except Exception as e:
        logger.error(f"Error getting discovery results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{discovery_id}")
async def stop_discovery(discovery_id: str):
    """
    Ferma una discovery in corso.
    """
    try:
        dude = get_dude_service()
        success = dude.stop_discovery(discovery_id)
        
        if not success:
            raise HTTPException(status_code=500, detail="Errore stop discovery")
        
        return {"status": "stopped", "discovery_id": discovery_id}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error stopping discovery: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================
# Device Management
# ============================================

@router.post("/devices/add")
async def add_device(request: AddDeviceRequest):
    """
    Aggiunge manualmente un dispositivo a The Dude.
    """
    try:
        dude = get_dude_service()
        
        extra_params = {}
        if request.note:
            extra_params["note"] = request.note
        if request.group:
            extra_params["group"] = request.group
        
        device_id = dude.add_device(
            name=request.name,
            address=request.address,
            device_type=request.device_type,
            agent_id=request.agent_id,
            **extra_params
        )
        
        if not device_id:
            raise HTTPException(status_code=500, detail="Errore aggiunta dispositivo")
        
        return {
            "status": "created",
            "device_id": device_id,
            "name": request.name,
            "address": request.address,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error adding device: {e}")
        raise HTTPException(status_code=500, detail=str(e))
