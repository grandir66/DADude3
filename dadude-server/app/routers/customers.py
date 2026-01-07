"""
DaDude - Customers Router
API endpoints per gestione clienti/tenant
"""
from datetime import datetime
from fastapi import APIRouter, HTTPException, Query, Depends, Request, Body
from fastapi.responses import HTMLResponse
from typing import Optional, List, Any
from loguru import logger

from ..models.customer_schemas import (
    Customer, CustomerCreate, CustomerUpdate, CustomerListResponse,
    Network, NetworkCreate, NetworkUpdate, NetworkListResponse,
    CredentialSafe, CredentialCreate, CredentialUpdate, CredentialListResponse,
    DeviceAssignment, DeviceAssignmentCreate, DeviceAssignmentUpdate,
    DeviceAssignmentListResponse,
    AgentAssignment, AgentAssignmentCreate, AgentAssignmentUpdate, AgentAssignmentSafe,
)
from ..services.customer_service import get_customer_service

router = APIRouter(prefix="/customers", tags=["Customers"])


# ==========================================
# CUSTOMERS ENDPOINTS
# ==========================================

@router.get("", response_model=CustomerListResponse)
async def list_customers(
    active_only: bool = Query(True, description="Solo clienti attivi"),
    search: Optional[str] = Query(None, description="Cerca per codice o nome"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Lista tutti i clienti.
    
    - **active_only**: Filtra solo clienti attivi
    - **search**: Cerca per codice o nome (case-insensitive)
    """
    try:
        service = get_customer_service()
        customers = service.list_customers(
            active_only=active_only,
            search=search,
            limit=limit,
            offset=offset,
        )
        return CustomerListResponse(total=len(customers), customers=customers)
    except Exception as e:
        logger.error(f"Error listing customers: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("", response_model=Customer, status_code=201)
async def create_customer(data: CustomerCreate):
    """
    Crea un nuovo cliente.
    
    Il codice cliente deve essere univoco e verrà convertito in maiuscolo.
    """
    try:
        service = get_customer_service()
        return service.create_customer(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating customer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{customer_id}", response_model=Customer)
async def get_customer(customer_id: str):
    """
    Ottiene dettagli di un cliente specifico.
    """
    service = get_customer_service()
    customer = service.get_customer(customer_id)
    
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    return customer


@router.get("/code/{code}", response_model=Customer)
async def get_customer_by_code(code: str):
    """
    Ottiene cliente per codice.
    """
    service = get_customer_service()
    customer = service.get_customer_by_code(code)
    
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente con codice {code} non trovato")
    
    return customer


@router.put("/{customer_id}", response_model=Customer)
async def update_customer(customer_id: str, data: CustomerUpdate):
    """
    Aggiorna dati di un cliente.
    """
    try:
        service = get_customer_service()
        customer = service.update_customer(customer_id, data)
        
        if not customer:
            raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
        
        return customer
    except Exception as e:
        logger.error(f"Error updating customer: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{customer_id}")
async def delete_customer(customer_id: str):
    """
    Disattiva un cliente (soft delete).
    """
    service = get_customer_service()
    
    if not service.delete_customer(customer_id):
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    return {"status": "success", "message": f"Cliente {customer_id} disattivato"}


# ==========================================
# NETWORKS ENDPOINTS
# ==========================================

@router.get("/{customer_id}/networks", response_model=NetworkListResponse)
async def list_customer_networks(
    customer_id: str,
    network_type: Optional[str] = Query(None, description="Filtra per tipo"),
    vlan_id: Optional[int] = Query(None, description="Filtra per VLAN ID"),
):
    """
    Lista reti di un cliente.
    """
    service = get_customer_service()
    networks = service.list_networks(
        customer_id=customer_id,
        network_type=network_type,
        vlan_id=vlan_id,
    )
    return NetworkListResponse(total=len(networks), networks=networks)


@router.post("/{customer_id}/networks", response_model=Network, status_code=201)
async def create_network(customer_id: str, data: NetworkCreate):
    """
    Crea una nuova rete per il cliente.
    
    Le reti possono sovrapporsi tra clienti diversi.
    """
    # Override customer_id dal path
    data.customer_id = customer_id
    
    try:
        service = get_customer_service()
        return service.create_network(data)
    except Exception as e:
        logger.error(f"Error creating network: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/networks/{network_id}", response_model=Network)
async def update_network(network_id: str, data: NetworkUpdate):
    """
    Aggiorna una rete.
    """
    service = get_customer_service()
    network = service.update_network(network_id, data)
    
    if not network:
        raise HTTPException(status_code=404, detail=f"Rete {network_id} non trovata")
    
    return network


@router.delete("/networks/{network_id}")
async def delete_network(network_id: str):
    """
    Elimina una rete.
    """
    service = get_customer_service()
    
    if not service.delete_network(network_id):
        raise HTTPException(status_code=404, detail=f"Rete {network_id} non trovata")
    
    return {"status": "success", "message": "Rete eliminata"}


# ==========================================
# CREDENTIALS ENDPOINTS
# ==========================================

@router.get("/{customer_id}/credentials")
async def list_customer_credentials(
    customer_id: str,
    credential_type: Optional[str] = Query(None, description="Filtra per tipo"),
):
    """
    Lista credenziali disponibili per un cliente.
    Include:
    - Credenziali linkate dall'archivio centrale
    - Credenziali legacy con customer_id (retrocompatibilità)
    """
    service = get_customer_service()
    
    # 1. Credenziali linkate (nuovo sistema)
    linked_creds = service.get_customer_credentials(customer_id=customer_id)
    
    # 2. Credenziali legacy (vecchio sistema con customer_id)
    legacy_creds = service.list_credentials(
        customer_id=customer_id,
        credential_type=credential_type,
    )
    
    # Combina evitando duplicati (per ID)
    seen_ids = set()
    all_creds = []
    
    for cred in linked_creds:
        if credential_type and cred.get("credential_type") != credential_type:
            continue
        if cred["id"] not in seen_ids:
            seen_ids.add(cred["id"])
            all_creds.append(cred)
    
    for cred in legacy_creds:
        if cred.id not in seen_ids:
            seen_ids.add(cred.id)
            # Converti CredentialSafe in dict
            all_creds.append({
                "id": cred.id,
                "name": cred.name,
                "credential_type": cred.credential_type,
                "username": cred.username,
                "is_default": cred.is_default,
                "description": cred.description,
                "active": cred.active,
                "ssh_port": cred.ssh_port,
                "snmp_community": cred.snmp_community,
                "snmp_version": cred.snmp_version,
                "snmp_port": cred.snmp_port,
                "wmi_domain": cred.wmi_domain,
                "mikrotik_api_port": cred.mikrotik_api_port,
            })
    
    return {"total": len(all_creds), "credentials": all_creds}


@router.post("/{customer_id}/credentials", response_model=CredentialSafe, status_code=201)
async def create_credential(customer_id: str, data: CredentialCreate):
    """
    Crea nuove credenziali per il cliente.
    
    - **is_default**: Se True, sarà usata come fallback per device senza credenziali specifiche
    - **device_filter**: Pattern glob per matching device (es: "router-*", "*-fw")
    """
    data.customer_id = customer_id
    
    try:
        service = get_customer_service()
        return service.create_credential(data)
    except Exception as e:
        logger.error(f"Error creating credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==========================================
# GLOBAL CREDENTIALS ENDPOINTS (DEVE ESSERE PRIMA DI {credential_id})
# ==========================================

@router.get("/credentials/all")
async def list_all_credentials(include_usage: bool = True):
    """
    Lista tutte le credenziali dall'archivio centrale.
    Include conteggio di utilizzo (clienti e device).
    """
    service = get_customer_service()
    credentials = service.get_all_credentials(include_usage=include_usage)
    return {"total": len(credentials), "credentials": credentials}


@router.get("/credentials", response_model=CredentialListResponse)
async def list_global_credentials(
    credential_type: Optional[str] = Query(None, description="Filtra per tipo"),
):
    """
    Lista credenziali globali (disponibili a tutti i clienti).
    """
    service = get_customer_service()
    credentials = service.list_global_credentials(credential_type=credential_type)
    return CredentialListResponse(total=len(credentials), credentials=credentials)


@router.post("/credentials", response_model=CredentialSafe, status_code=201)
async def create_global_credential(data: CredentialCreate):
    """
    Crea nuove credenziali globali (archivio centrale).
    """
    service = get_customer_service()
    
    # Crea una copia con is_global=True e customer_id=None
    global_data = data.model_copy(update={"is_global": True, "customer_id": None})
    
    try:
        credential = service.create_credential(global_data)
        return credential
    except Exception as e:
        logger.error(f"Error creating global credential: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint con path parameter DOPO quelli statici
@router.get("/credentials/{credential_id}")
async def get_credential(credential_id: str, include_secrets: bool = False):
    """
    Ottiene credenziali (include_secrets richiede autenticazione).
    """
    service = get_customer_service()
    credential = service.get_credential(credential_id, include_secrets=include_secrets)
    
    if not credential:
        raise HTTPException(status_code=404, detail=f"Credenziali {credential_id} non trovate")
    
    return credential


@router.put("/credentials/{credential_id}", response_model=CredentialSafe)
async def update_credential(credential_id: str, data: CredentialUpdate):
    """
    Aggiorna credenziali esistenti.
    """
    service = get_customer_service()
    
    # Verifica esistenza
    existing = service.get_credential(credential_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Credenziali {credential_id} non trovate")
    
    updated = service.update_credential(credential_id, data)
    if not updated:
        raise HTTPException(status_code=500, detail="Errore aggiornamento credenziali")
    
    return updated


@router.delete("/credentials/{credential_id}")
async def delete_credential(credential_id: str):
    """
    Elimina credenziali.
    """
    service = get_customer_service()
    
    # Verifica esistenza
    existing = service.get_credential(credential_id)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Credenziali {credential_id} non trovate")
    
    credential_name = existing.name if hasattr(existing, 'name') else credential_id
    success = service.delete_credential(credential_id)
    if not success:
        raise HTTPException(status_code=500, detail="Errore eliminazione credenziali")
    
    return {"success": True, "message": f"Credenziali '{credential_name}' eliminate"}


# ==========================================
# CREDENTIAL LINKS (Associazione Cliente-Credenziale)
# ==========================================

@router.post("/{customer_id}/credential-links")
async def link_credential(
    customer_id: str,
    credential_id: str = Query(..., description="ID credenziale da associare"),
    is_default: bool = Query(False, description="Imposta come default per questo tipo"),
    notes: str = Query(None, description="Note per questa associazione"),
):
    """
    Associa una credenziale dall'archivio centrale a un cliente.
    """
    service = get_customer_service()
    try:
        result = service.link_credential_to_customer(
            customer_id=customer_id,
            credential_id=credential_id,
            is_default=is_default,
            notes=notes
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error linking credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{customer_id}/credential-links/{credential_id}")
async def unlink_credential(customer_id: str, credential_id: str):
    """
    Rimuove l'associazione tra credenziale e cliente.
    """
    service = get_customer_service()
    if service.unlink_credential_from_customer(customer_id, credential_id):
        return {"success": True, "message": "Credenziale rimossa dal cliente"}
    raise HTTPException(status_code=404, detail="Link non trovato")


@router.get("/{customer_id}/credential-links")
async def get_customer_credential_links(
    customer_id: str,
    include_password: bool = False,
):
    """
    Ottiene tutte le credenziali associate a un cliente.
    """
    service = get_customer_service()
    credentials = service.get_customer_credentials(
        customer_id=customer_id,
        include_password=include_password
    )
    return {"total": len(credentials), "credentials": credentials}


@router.put("/{customer_id}/credential-links/{credential_id}/set-default")
async def set_default_credential(customer_id: str, credential_id: str):
    """
    Imposta una credenziale come default per il suo tipo per questo cliente.
    """
    service = get_customer_service()
    if service.set_customer_default_credential(customer_id, credential_id):
        return {"success": True, "message": "Credenziale impostata come default"}
    raise HTTPException(status_code=404, detail="Credenziale o link non trovato")


# ==========================================
# DEVICE ASSIGNMENTS ENDPOINTS
# ==========================================

@router.get("/{customer_id}/devices", response_model=DeviceAssignmentListResponse)
async def list_customer_devices(
    customer_id: str,
    role: Optional[str] = Query(None, description="Filtra per ruolo"),
):
    """
    Lista device assegnati a un cliente.
    """
    service = get_customer_service()
    assignments = service.list_device_assignments(
        customer_id=customer_id,
        role=role,
    )
    return DeviceAssignmentListResponse(total=len(assignments), assignments=assignments)


@router.post("/{customer_id}/devices", response_model=DeviceAssignment, status_code=201)
async def assign_device_to_customer(customer_id: str, data: DeviceAssignmentCreate):
    """
    Assegna un device dal Dude a questo cliente.
    
    - **dude_device_id**: ID del device nel Dude (obbligatorio)
    - **role**: Ruolo del device (router, switch, firewall, etc.)
    - **primary_network_id**: Rete principale del device
    - **credential_id**: Credenziali specifiche per questo device
    """
    data.customer_id = customer_id
    
    try:
        service = get_customer_service()
        return service.assign_device(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error assigning device: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/devices/{dude_device_id}", response_model=DeviceAssignment)
async def get_device_assignment(dude_device_id: str):
    """
    Ottiene assegnazione di un device specifico.
    """
    service = get_customer_service()
    assignment = service.get_device_assignment(dude_device_id)
    
    if not assignment:
        raise HTTPException(status_code=404, detail=f"Device {dude_device_id} non assegnato")
    
    return assignment


@router.put("/devices/{dude_device_id}", response_model=DeviceAssignment)
async def update_device_assignment(dude_device_id: str, data: DeviceAssignmentUpdate):
    """
    Aggiorna assegnazione device.
    """
    service = get_customer_service()
    assignment = service.update_device_assignment(dude_device_id, data)
    
    if not assignment:
        raise HTTPException(status_code=404, detail=f"Device {dude_device_id} non assegnato")
    
    return assignment


@router.delete("/devices/{dude_device_id}")
async def unassign_device(dude_device_id: str):
    """
    Rimuove assegnazione device.
    """
    service = get_customer_service()
    
    if not service.unassign_device(dude_device_id):
        raise HTTPException(status_code=404, detail=f"Device {dude_device_id} non assegnato")
    
    return {"status": "success", "message": f"Device {dude_device_id} rimosso"}


# ==========================================
# UTILITY ENDPOINTS
# ==========================================

@router.get("/{customer_id}/summary")
async def get_customer_summary(customer_id: str):
    """
    Ottiene riepilogo completo di un cliente.
    """
    service = get_customer_service()
    
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    networks = service.list_networks(customer_id=customer_id)
    credentials = service.list_credentials(customer_id=customer_id)
    devices = service.list_device_assignments(customer_id=customer_id)
    
    return {
        "customer": customer,
        "summary": {
            "networks": len(networks),
            "credentials": len(credentials),
            "devices": len(devices),
            "devices_by_role": _count_by_field(devices, "role"),
        },
        "networks": networks,
        "credentials": credentials,
        "devices": devices,
    }


def _count_by_field(items: List, field: str) -> dict:
    """Conta elementi per valore di un campo"""
    counts = {}
    for item in items:
        value = getattr(item, field, None) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return counts


# ==========================================
# AGENT ASSIGNMENTS (SONDE)
# ==========================================

@router.get("/{customer_id}/agents")
async def list_customer_agents(
    customer_id: str,
    active_only: bool = Query(True),
):
    """
    Lista le sonde assegnate a un cliente.
    Aggiunge informazioni real-time sullo stato WebSocket per agent Docker.
    Per agent MikroTik, mostra se sono raggiungibili via un agent Docker connesso.
    """
    from ..services.websocket_hub import get_websocket_hub
    import re
    
    service = get_customer_service()
    
    # Verifica cliente esiste
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    agents = service.list_agents(customer_id=customer_id, active_only=active_only)
    
    # Arricchisci con stato WebSocket real-time
    hub = get_websocket_hub()
    ws_connected_names = set()
    connected_docker_agents = []  # Lista agent Docker connessi
    
    if hub and hub._connections:
        for conn_id in hub._connections.keys():
            # Estrai nome base (es: "agent-PX-OVH-51-1234" -> "PX-OVH-51")
            match = re.match(r'^agent-(.+?)(?:-\d+)?$', conn_id)
            if match:
                ws_connected_names.add(match.group(1))
    
    # Prima passata: identifica agent Docker connessi
    result = []
    for agent in agents:
        agent_dict = agent.model_dump() if hasattr(agent, 'model_dump') else dict(agent)
        agent_type = agent_dict.get('agent_type', 'mikrotik')
        agent_name = agent_dict.get('name', '')
        
        if agent_type == 'docker':
            if agent_name in ws_connected_names:
                agent_dict['status'] = 'online'
                agent_dict['ws_connected'] = True
                connected_docker_agents.append(agent_dict)
            else:
                agent_dict['ws_connected'] = False
        
        result.append(agent_dict)
    
    # Seconda passata: per agent MikroTik, verifica se raggiungibili via Docker agent
    for agent_dict in result:
        agent_type = agent_dict.get('agent_type', 'mikrotik')
        
        if agent_type == 'mikrotik':
            # Gli agent MikroTik sono raggiungibili se c'è almeno un agent Docker connesso
            # nello stesso cliente (possono fare query API/SSH al router)
            if connected_docker_agents:
                # Usa il primo agent Docker connesso come "ponte"
                bridge_agent = connected_docker_agents[0]
                agent_dict['status'] = 'reachable'
                agent_dict['reachable_via'] = bridge_agent.get('name', 'Docker Agent')
                agent_dict['reachable_via_id'] = bridge_agent.get('id')
            else:
                agent_dict['status'] = 'unreachable'
                agent_dict['reachable_via'] = None
    
    return result


@router.post("/{customer_id}/agents", response_model=AgentAssignment, status_code=201)
async def create_customer_agent(customer_id: str, data: AgentAssignmentCreate):
    """
    Crea una nuova sonda per il cliente.
    """
    data.customer_id = customer_id
    
    # Log dei dati ricevuti per debug
    logger.info(f"Creating agent for customer {customer_id}: name={data.name}, address={data.address}, "
                f"agent_type={data.agent_type}, agent_api_port={data.agent_api_port}, "
                f"agent_token={'***' if data.agent_token else None}")
    
    try:
        service = get_customer_service()
        return service.create_agent(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating agent: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents/{agent_id}", response_model=AgentAssignment)
async def get_agent(agent_id: str, include_password: bool = Query(False)):
    """
    Ottiene dettagli di una sonda.
    """
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=include_password)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    return agent


@router.put("/agents/{agent_id}", response_model=AgentAssignment)
async def update_agent(agent_id: str, data: AgentAssignmentUpdate):
    """
    Aggiorna una sonda.
    """
    service = get_customer_service()
    agent = service.update_agent(agent_id, data)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    return agent


@router.delete("/agents/{agent_id}")
async def delete_agent(agent_id: str):
    """
    Elimina una sonda.
    Chiude connessioni WebSocket attive prima di eliminare.
    """
    service = get_customer_service()
    
    try:
        # Recupera info agent prima di eliminare per includere nome nel messaggio
        agent_name = f"ID {agent_id}"
        try:
            agent = service.get_agent(agent_id)
            if agent:
                agent_name = agent.name
        except Exception:
            # Se non riesce a recuperare, usa ID come fallback
            pass
        
        success = await service.delete_agent(agent_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Sonda non trovata")
        
        return {
            "success": True,
            "status": "deleted",
            "agent_id": agent_id,
            "message": f"Sonda '{agent_name}' eliminata con successo"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting agent {agent_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante eliminazione sonda: {str(e)}"
        )


@router.post("/agents/{agent_id}/reassign")
async def reassign_agent(
    agent_id: str,
    new_customer_id: str = Query(..., description="ID del nuovo cliente"),
):
    """
    Riassegna un agent a un nuovo cliente.
    """
    service = get_customer_service()
    
    # Verifica che l'agent esista
    agent = service.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent non trovato")
    
    # Verifica che il nuovo cliente esista
    new_customer = service.get_customer(new_customer_id)
    if not new_customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    # Aggiorna customer_id
    from ..models.database import AgentAssignment, init_db, get_session
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        db_agent = session.query(AgentAssignment).filter(AgentAssignment.id == agent_id).first()
        if db_agent:
            old_customer_id = db_agent.customer_id
            db_agent.customer_id = new_customer_id
            db_agent.status = "approved"
            db_agent.active = True
            session.commit()
            
            return {
                "success": True,
                "message": f"Agent riassegnato a {new_customer.name}",
                "agent_id": agent_id,
                "old_customer_id": old_customer_id,
                "new_customer_id": new_customer_id,
            }
        else:
            raise HTTPException(status_code=404, detail="Agent non trovato nel database")
    finally:
        session.close()


@router.post("/agents/{agent_id}/unassign")
async def unassign_agent(agent_id: str):
    """
    Dissocia un agent dal cliente (torna in pending).
    """
    service = get_customer_service()
    
    # Verifica che l'agent esista
    agent = service.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent non trovato")
    
    from ..models.database import AgentAssignment, init_db, get_session
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        db_agent = session.query(AgentAssignment).filter(AgentAssignment.id == agent_id).first()
        if db_agent:
            old_customer_id = db_agent.customer_id
            db_agent.customer_id = None
            db_agent.status = "pending_approval"
            db_agent.active = False
            session.commit()
            
            return {
                "success": True,
                "message": "Agent dissociato dal cliente",
                "agent_id": agent_id,
                "old_customer_id": old_customer_id,
            }
        else:
            raise HTTPException(status_code=404, detail="Agent non trovato nel database")
    finally:
        session.close()


@router.post("/agents/{agent_id}/update")
async def update_agent_remote(
    agent_id: str,
):
    """
    Aggiorna un agent Docker remoto inviando comando UPDATE_AGENT via WebSocket.
    Solo per agent Docker connessi via WebSocket.
    """
    from ..services.customer_service import get_customer_service
    from ..services.websocket_hub import get_websocket_hub, CommandType
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent non trovato")
    
    agent_type = getattr(agent, 'agent_type', 'mikrotik')
    if agent_type != "docker":
        raise HTTPException(status_code=400, detail="Update remoto supportato solo per agent Docker")
    
    # Trova agent connesso via WebSocket
    hub = get_websocket_hub()
    if not hub or not hub._connections:
        raise HTTPException(status_code=503, detail="Nessun agent connesso via WebSocket")
    
    agent_name = getattr(agent, 'name', '')
    agent_address = getattr(agent, 'address', '')
    
    # Cerca agent per nome o IP
    ws_agent_id = None
    import re
    for conn_id, conn in hub._connections.items():
        match = re.match(r'^agent-(.+?)(?:-\d+)?$', conn_id)
        if match and (match.group(1) == agent_name or conn.ip_address == agent_address):
            ws_agent_id = conn_id
            break
    
    if not ws_agent_id:
        raise HTTPException(
            status_code=404, 
            detail=f"Agent '{agent_name}' ({agent_address}) non trovato tra le connessioni WebSocket attive"
        )
    
    # Invia comando UPDATE_AGENT
    try:
        logger.info(f"Inviando comando UPDATE_AGENT a agent {ws_agent_id} ({agent_name})")
        result = await hub.send_command(
            agent_id=ws_agent_id,
            action=CommandType.UPDATE_AGENT,
            params={},
            timeout=600.0  # 10 minuti per update
        )
        
        if result.status == "success":
            return {
                "success": True,
                "message": "Comando di update inviato con successo",
                "agent_id": ws_agent_id,
                "agent_name": agent_name,
                "data": result.data,
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Update fallito: {result.error}"
            )
            
    except Exception as e:
        logger.error(f"Errore durante update agent {agent_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante update: {str(e)}"
        )


@router.post("/agents/update-domarc")
async def update_domarc_agent():
    """
    Trova e aggiorna automaticamente l'agent Domarc.
    Cerca per nome "Domarc" o IP 192.168.40.114/192.168.40.4 nelle connessioni WebSocket attive.
    """
    from ..services.customer_service import get_customer_service
    from ..services.websocket_hub import get_websocket_hub, CommandType
    
    service = get_customer_service()
    hub = get_websocket_hub()
    
    if not hub or not hub._connections:
        raise HTTPException(status_code=503, detail="Nessun agent connesso via WebSocket")
    
    # Prima cerca direttamente tra le connessioni WebSocket attive
    ws_agent_id = None
    agent_info = None
    import re
    
    logger.info(f"Connessioni WebSocket attive: {list(hub._connections.keys())}")
    
    # Cerca per nome "domarc" (case insensitive) o IP 192.168.40.114/192.168.40.4
    for conn_id, conn in hub._connections.items():
        match = re.match(r'^agent-(.+?)(?:-\d+)?$', conn_id)
        if match:
            agent_name_match = match.group(1).lower()
            # Cerca per nome "domarc" o IP
            if 'domarc' in agent_name_match or conn.ip_address in ['192.168.40.114', '192.168.40.4']:
                ws_agent_id = conn_id
                agent_info = {
                    "name": match.group(1),
                    "ip": conn.ip_address,
                    "version": conn.version,
                }
                logger.info(f"Trovato agent Domarc via WebSocket: {ws_agent_id} ({conn.ip_address})")
                break
    
    if not ws_agent_id:
        # Se non trovato, cerca nel database
        session = service._get_session()
        try:
            from ..models.database import AgentAssignment
            
            agents = session.query(AgentAssignment).filter(
                (AgentAssignment.name.ilike('%domarc%')) |
                (AgentAssignment.address.like('%192.168.40.114%')) |
                (AgentAssignment.address.like('%192.168.40.4%'))
            ).all()
            
            if agents:
                agent = agents[0]
                logger.info(f"Trovato agent nel database: {agent.name} (ID: {agent.id}, Address: {agent.address})")
                
                # Cerca corrispondenza WebSocket
                for conn_id, conn in hub._connections.items():
                    match = re.match(r'^agent-(.+?)(?:-\d+)?$', conn_id)
                    if match:
                        agent_name_match = match.group(1).lower()
                        if agent_name_match == agent.name.lower() or conn.ip_address == agent.address:
                            ws_agent_id = conn_id
                            agent_info = {
                                "name": agent.name,
                                "ip": conn.ip_address,
                                "version": conn.version,
                            }
                            logger.info(f"Trovato corrispondenza WebSocket: {ws_agent_id}")
                            break
        finally:
            session.close()
    
    if not ws_agent_id:
        available = list(hub._connections.keys())
        raise HTTPException(
            status_code=404,
            detail=f"Agent Domarc non trovato tra le connessioni WebSocket attive. Connessioni disponibili: {available}"
        )
    
    # Invia comando UPDATE_AGENT
    logger.info(f"Inviando comando UPDATE_AGENT a {ws_agent_id} (IP: {agent_info.get('ip') if agent_info else 'unknown'})")
    try:
        result = await hub.send_command(
            agent_id=ws_agent_id,
            action=CommandType.UPDATE_AGENT,
            params={},
            timeout=600.0  # 10 minuti per update
        )
        
        if result.status == "success":
            return {
                "success": True,
                "message": "Agent Domarc aggiornato con successo",
                "ws_agent_id": ws_agent_id,
                "agent_name": agent_info.get("name") if agent_info else ws_agent_id,
                "agent_ip": agent_info.get("ip") if agent_info else "unknown",
                "current_version": agent_info.get("version") if agent_info else "unknown",
                "data": result.data,
            }
        else:
            raise HTTPException(
                status_code=500,
                detail=f"Update fallito: {result.error}"
            )
    except Exception as e:
        logger.error(f"Errore durante invio comando UPDATE_AGENT: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante update: {str(e)}"
        )


@router.post("/agents/{agent_id}/test")
async def test_agent_connection(
    agent_id: str,
    test_type: Optional[str] = Query(None, description="Forza tipo test: api, ssh, docker, o auto (default)")
):
    """
    Testa la connessione a una sonda (API RouterOS, SSH, o Docker Agent).
    """
    import routeros_api
    import paramiko
    import socket
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    agent_type = getattr(agent, 'agent_type', 'mikrotik')
    
    # Se è un agent Docker, verifica prima WebSocket poi HTTP
    if agent_type == "docker" or test_type == "docker":
        from ..services.websocket_hub import get_websocket_hub
        import re
        
        # Prima verifica connessione WebSocket
        hub = get_websocket_hub()
        ws_connected = False
        ws_info = None
        
        if hub and hub._connections:
            agent_name = getattr(agent, 'name', '')
            for conn_id, conn in hub._connections.items():
                match = re.match(r'^agent-(.+?)(?:-\d+)?$', conn_id)
                if match and match.group(1) == agent_name:
                    ws_connected = True
                    ws_info = {
                        "agent_id": conn_id,
                        "connected_at": conn.connected_at.isoformat() if conn.connected_at else None,
                        "last_heartbeat": conn.last_heartbeat.isoformat() if conn.last_heartbeat else None,
                        "version": conn.version,
                        "ip_address": conn.ip_address,
                    }
                    break
        
        if ws_connected:
            service.update_agent_status(agent_id, "online", ws_info.get("version", ""))
            return {
                "success": True,
                "connection_type": "websocket",
                "status": "online",
                "results": {"websocket": ws_info},
                "message": f"Docker Agent OK via WebSocket - {agent.name}"
            }
        
        # Fallback: testa via HTTP (legacy)
        from ..services.agent_service import get_agent_service
        
        agent_svc = get_agent_service()
        agent_info = agent_svc._agent_to_dict(agent)
        
        try:
            health = await agent_svc.check_agent_health(agent_info)
            
            if health.get("status") == "healthy":
                service.update_agent_status(agent_id, "online", health.get("version", ""))
                return {
                    "success": True,
                    "connection_type": "docker",
                    "status": "online",
                    "results": {"docker": health},
                    "message": f"Docker Agent OK - {health.get('agent_name', agent.name)}"
                }
            else:
                service.update_agent_status(agent_id, "offline", "")
                return {
                    "success": False,
                    "connection_type": "docker",
                    "status": "offline",
                    "results": {"docker": health},
                    "message": f"Docker Agent fallito: {health.get('error', 'Unknown error')}"
                }
        except Exception as e:
            service.update_agent_status(agent_id, "offline", "")
            return {
                "success": False,
                "connection_type": "docker",
                "status": "offline",
                "results": {"docker": {"error": str(e)}},
                "message": f"Docker Agent non raggiungibile via HTTP: {e}"
            }
    
    # MikroTik nativo
    conn_type = test_type or agent.connection_type
    results = {"api": None, "ssh": None}
    
    # Test API RouterOS
    if conn_type in ["api", "both"]:
        try:
            connection = routeros_api.RouterOsApiPool(
                host=agent.address,
                username=agent.username or "admin",
                password=agent.password or "",
                port=agent.port,
                use_ssl=agent.use_ssl,
                ssl_verify=False,
                plaintext_login=True,
            )
            
            api = connection.get_api()
            
            identity = api.get_resource('/system/identity')
            identity_data = identity.get()
            name = identity_data[0].get('name', 'Unknown') if identity_data else 'Unknown'
            
            resource = api.get_resource('/system/resource')
            resource_data = resource.get()
            version = resource_data[0].get('version', '') if resource_data else ''
            
            connection.disconnect()
            
            results["api"] = {
                "success": True,
                "name": name,
                "version": version,
                "message": f"API OK - {name}"
            }
        except Exception as e:
            results["api"] = {
                "success": False,
                "error": str(e),
                "message": f"API fallita: {e}"
            }
    
    # Test SSH
    if conn_type in ["ssh", "both"]:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_params = {
                "hostname": agent.address,
                "port": agent.ssh_port,
                "username": agent.username or "admin",
                "timeout": 10,
                "allow_agent": False,
                "look_for_keys": False,
            }
            
            # Usa chiave SSH se disponibile, altrimenti password
            if agent.ssh_key:
                from io import StringIO
                key = paramiko.RSAKey.from_private_key(StringIO(agent.ssh_key))
                connect_params["pkey"] = key
            else:
                connect_params["password"] = agent.password or ""
            
            ssh.connect(**connect_params)
            
            # Esegui comando per verificare
            stdin, stdout, stderr = ssh.exec_command("/system identity print")
            output = stdout.read().decode().strip()
            
            # Ottieni versione
            stdin, stdout, stderr = ssh.exec_command("/system resource print")
            resource_output = stdout.read().decode()
            
            ssh.close()
            
            # Parse output
            name = "Unknown"
            version = ""
            for line in output.split('\n'):
                if 'name:' in line.lower():
                    name = line.split(':')[-1].strip()
            for line in resource_output.split('\n'):
                if 'version:' in line.lower():
                    version = line.split(':')[-1].strip()
            
            results["ssh"] = {
                "success": True,
                "name": name,
                "version": version,
                "message": f"SSH OK - {name}"
            }
        except Exception as e:
            results["ssh"] = {
                "success": False,
                "error": str(e),
                "message": f"SSH fallita: {e}"
            }
    
    # Determina stato finale
    api_ok = results["api"] and results["api"]["success"] if results["api"] else None
    ssh_ok = results["ssh"] and results["ssh"]["success"] if results["ssh"] else None
    
    if conn_type == "both":
        success = api_ok and ssh_ok
        status = "online" if success else ("partial" if (api_ok or ssh_ok) else "offline")
    elif conn_type == "api":
        success = api_ok
        status = "online" if success else "offline"
    else:  # ssh
        success = ssh_ok
        status = "online" if success else "offline"
    
    # Aggiorna stato
    version = (results["api"] or results["ssh"] or {}).get("version", "")
    service.update_agent_status(agent_id, status, version)
    
    return {
        "success": success,
        "connection_type": conn_type,
        "status": status,
        "results": results,
        "message": f"Test {conn_type}: {'OK' if success else 'Fallito'}"
    }


@router.post("/agents/{agent_id}/ssh-command")
async def execute_ssh_command(
    agent_id: str,
    command: str = Query(..., description="Comando da eseguire"),
):
    """
    Esegue un comando SSH sulla sonda.
    """
    import paramiko
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    if agent.connection_type not in ["ssh", "both"]:
        raise HTTPException(status_code=400, detail="Sonda non configurata per SSH")
    
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_params = {
            "hostname": agent.address,
            "port": agent.ssh_port,
            "username": agent.username or "admin",
            "timeout": 30,
            "allow_agent": False,
            "look_for_keys": False,
        }
        
        if agent.ssh_key:
            from io import StringIO
            key = paramiko.RSAKey.from_private_key(StringIO(agent.ssh_key))
            connect_params["pkey"] = key
        else:
            connect_params["password"] = agent.password or ""
        
        ssh.connect(**connect_params)
        
        stdin, stdout, stderr = ssh.exec_command(command, timeout=30)
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        
        ssh.close()
        
        return {
            "success": exit_code == 0,
            "command": command,
            "output": output,
            "error": error,
            "exit_code": exit_code
        }
        
    except Exception as e:
        return {
            "success": False,
            "command": command,
            "error": str(e),
            "message": f"Errore SSH: {e}"
        }


@router.post("/agents/{agent_id}/scan")
async def start_agent_scan(
    agent_id: str,
    network_id: Optional[str] = Query(None, description="ID rete da scansionare"),
    scan_type: str = Query("ping", description="Tipo scan: ping, arp, snmp, all"),
    add_devices: bool = Query(False, description="Aggiungi device a Dude"),
):
    """
    Avvia una scansione tramite la sonda.
    """
    from ..services import get_dude_service
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    # Determina rete da scansionare
    network_cidr = None
    if network_id:
        networks = service.list_networks(customer_id=agent.customer_id)
        network = next((n for n in networks if n.id == network_id), None)
        if network:
            network_cidr = network.ip_network
    elif agent.assigned_networks:
        # Usa prima rete assegnata
        networks = service.list_networks(customer_id=agent.customer_id)
        for net in networks:
            if net.id in agent.assigned_networks:
                network_cidr = net.ip_network
                break
    
    if not network_cidr:
        raise HTTPException(status_code=400, detail="Nessuna rete specificata o assegnata")
    
    # Avvia discovery via Dude con l'agent specificato
    dude = get_dude_service()
    result = dude.start_discovery(
        network=network_cidr,
        agent_id=agent.dude_agent_id,  # ID agent in Dude
        scan_type=scan_type or agent.default_scan_type,
        add_devices=add_devices or agent.auto_add_devices,
    )
    
    return {
        "agent_id": agent_id,
        "agent_name": agent.name,
        "network": network_cidr,
        "scan_type": scan_type,
        **result
    }



@router.post("/agents/{agent_id}/register-in-dude")
async def register_agent_in_dude(agent_id: str):
    """
    Registra una sonda locale come agent in The Dude.
    Questo permette a The Dude di usare il router per eseguire discovery.
    """
    from ..services import get_dude_service
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    # Registra in The Dude
    dude = get_dude_service()
    result = dude.add_agent_to_dude(
        name=agent.name,
        address=agent.address,
        port=agent.port,
        username=agent.username or "admin",
        password=agent.password or "",
        use_ssl=agent.use_ssl,
    )
    
    if result.get("success"):
        # Aggiorna la sonda locale con l'ID di The Dude
        dude_agent_id = result.get("agent_id")
        if dude_agent_id:
            service.update_agent(agent_id, AgentAssignmentUpdate(
                dude_agent_id=dude_agent_id
            ))
        
        return {
            "success": True,
            "agent_id": agent_id,
            "dude_agent_id": dude_agent_id,
            "message": result.get("message"),
            "existing": result.get("existing", False)
        }
    else:
        return {
            "success": False,
            "error": result.get("error"),
            "message": result.get("message")
        }


@router.delete("/agents/{agent_id}/unregister-from-dude")
async def unregister_agent_from_dude(agent_id: str):
    """
    Rimuove una sonda da The Dude (ma la mantiene in DaDude).
    """
    from ..services import get_dude_service
    
    service = get_customer_service()
    agent = service.get_agent(agent_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    if not agent.dude_agent_id:
        return {
            "success": False,
            "message": "Sonda non registrata in The Dude"
        }
    
    # Rimuovi da The Dude
    dude = get_dude_service()
    result = dude.remove_agent_from_dude(agent.dude_agent_id)
    
    if result.get("success"):
        # Rimuovi l'ID Dude dalla sonda locale
        service.update_agent(agent_id, AgentAssignmentUpdate(
            dude_agent_id=None
        ))
        
        return {
            "success": True,
            "message": "Sonda rimossa da The Dude"
        }
    else:
        return result


async def _execute_scan_background(
    scan_id: str,
    agent_id: str,
    networks: list,
    scan_type: str,
    agent: Any
):
    """
    Esegue la scansione in background e aggiorna il record ScanResult esistente.
    Usa asyncio con timeout per evitare blocchi del sistema.
    """
    from ..models.database import ScanResult, init_db, get_session
    from ..config import get_settings
    import asyncio
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    
    try:
        logger.info(f"Starting background scan {scan_id} for agent {agent_id}, network {networks[0].ip_network if networks else 'unknown'}")
        
        # Esegui scansione con timeout di 10 minuti per evitare blocchi
        try:
            result = await asyncio.wait_for(
                scan_customer_networks(
                    agent_id=agent_id,
                    scan_type=scan_type,
                    network_ids=[n.id for n in networks],
                    background=False,
                    existing_scan_id=scan_id  # Passa scan_id per aggiornare record esistente
                ),
                timeout=600.0  # 10 minuti timeout
            )
            logger.info(f"Background scan {scan_id} completed: {result.get('scan_id')}")
        except asyncio.TimeoutError:
            logger.error(f"Background scan {scan_id} timed out after 10 minutes")
            session = get_session(engine)
            try:
                scan_record = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
                if scan_record:
                    scan_record.status = "failed"
                    scan_record.error_message = "Scansione timeout dopo 10 minuti"
                    session.commit()
            finally:
                session.close()
        except Exception as e:
            logger.error(f"Error in background scan {scan_id}: {e}", exc_info=True)
            # Aggiorna status a "failed"
            session = get_session(engine)
            try:
                scan_record = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
                if scan_record:
                    scan_record.status = "failed"
                    # Limita lunghezza messaggio errore
                    error_msg = str(e)[:500] if len(str(e)) > 500 else str(e)
                    scan_record.error_message = error_msg
                    session.commit()
            except Exception as db_error:
                logger.error(f"Error updating scan record status: {db_error}")
            finally:
                session.close()
    except Exception as e:
        logger.error(f"Critical error in background scan {scan_id}: {e}", exc_info=True)
        # Ultimo tentativo di aggiornare lo status
        try:
            session = get_session(engine)
            scan_record = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
            if scan_record:
                scan_record.status = "failed"
                scan_record.error_message = f"Errore critico: {str(e)[:500]}"
                session.commit()
            session.close()
        except:
            pass


@router.post("/agents/{agent_id}/scan-customer-networks")
async def scan_customer_networks(
    agent_id: str,
    scan_type: str = Query("arp", description="Tipo scan: arp, ping, all"),
    network_ids: Optional[List[str]] = Query(None, description="IDs reti da scansionare (tutte se vuoto)"),
    background: bool = Query(True, description="Esegui scansione in background"),
    existing_scan_id: Optional[str] = None,  # Se fornito, aggiorna record esistente invece di crearne uno nuovo
):
    """
    Scansiona le reti del cliente usando la sonda con connessione diretta.
    Se background=True, avvia la scansione in background e ritorna immediatamente.
    Salva i risultati nel database per visualizzazione successiva.
    """
    from ..services.scanner_service import get_scanner_service
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..config import get_settings
    
    service = get_customer_service()
    agent = service.get_agent(agent_id, include_password=True)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Sonda non trovata")
    
    # Ottieni reti del cliente
    all_networks = service.list_networks(customer_id=agent.customer_id, active_only=True)
    logger.info(f"[SCAN DEBUG] All networks for customer: {[(n.id, n.name, n.ip_network) for n in all_networks]}")
    logger.info(f"[SCAN DEBUG] Requested network_ids: {network_ids}")
    
    if not all_networks:
        raise HTTPException(status_code=400, detail="Nessuna rete configurata per il cliente")
    
    # Filtra reti se specificato
    if network_ids:
        networks = [n for n in all_networks if n.id in network_ids]
        logger.info(f"[SCAN DEBUG] Filtered networks: {[(n.id, n.name, n.ip_network) for n in networks]}")
    else:
        networks = all_networks
        logger.info(f"[SCAN DEBUG] No filter, using all networks")
    
    if not networks:
        raise HTTPException(status_code=400, detail="Nessuna rete valida selezionata")
    
    # Crea o aggiorna record scansione
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Usa la prima rete per il record (o tutte se multiple)
        network = networks[0]
        
        if existing_scan_id:
            # Aggiorna record esistente
            scan_record = session.query(ScanResult).filter(ScanResult.id == existing_scan_id).first()
            if not scan_record:
                raise HTTPException(status_code=404, detail=f"Scan record {existing_scan_id} not found")
            scan_record.status = "running" if background else "pending"
            scan_record.network_id = network.id
            scan_record.network_cidr = network.ip_network
            scan_record.scan_type = scan_type
            scan_record.devices_found = 0
            scan_record.error_message = None
            scan_id = existing_scan_id
        else:
            # Crea nuovo record
            scan_record = ScanResult(
                customer_id=agent.customer_id,
                agent_id=agent_id,
                network_id=network.id,
                network_cidr=network.ip_network,
                scan_type=scan_type,
                devices_found=0,
                status="running" if background else "pending",
                error_message=None,
            )
            session.add(scan_record)
            session.flush()  # Per ottenere l'ID
            scan_id = scan_record.id
        
        session.commit()
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error creating/updating scan record: {e}")
        raise HTTPException(status_code=500, detail=f"Errore creazione/aggiornamento record scansione: {e}")
    finally:
        session.close()
    
    # Se background=True, avvia scansione in background e ritorna immediatamente
    if background:
        import asyncio
        asyncio.create_task(_execute_scan_background(scan_id, agent_id, networks, scan_type, agent))
        
        return {
            "scan_id": scan_id,
            "agent_id": agent_id,
            "agent_name": agent.name,
            "customer_id": agent.customer_id,
            "scan_type": scan_type,
            "status": "running",
            "message": "Scansione avviata in background",
            "view_url": f"/customers/{agent.customer_id}/scans/{scan_id}",
        }
    
    # Altrimenti esegui scansione sincrona (comportamento legacy)
    # Esegui scansione diretta tramite il router o Docker agent
    scanner = get_scanner_service()
    logger.info(f"[SCAN DEBUG] Selected network: {network.id} = {network.name} ({network.ip_network})")
    
    # Verifica tipo agent
    agent_type = getattr(agent, 'agent_type', 'mikrotik') or 'mikrotik'
    
    logger.info(f"Scan request: agent_type={agent_type}, agent_id={agent.id}, address={agent.address}")
    
    if agent_type == "docker":
        # =====================================================
        # STRATEGIA IBRIDA per Docker Agent:
        # 1. Se la rete ha gateway configurato (MikroTik o SNMP), DELEGA ALL'AGENT la query ARP
        # 2. Esegui nmap scan via WebSocket
        # 3. Merge: IP da nmap + MAC da ARP (se disponibile)
        # =====================================================
        from ..services.agent_client import AgentClient, AgentConfig
        from ..services.websocket_hub import get_websocket_hub, CommandType
        
        hub = get_websocket_hub()
        
        # Trova connessione WebSocket dell'agent
        def normalize(s: str) -> str:
            return s.lower().replace(" ", "").replace("-", "").replace("_", "")
        
        ws_agent_id = None
        agent_name_norm = normalize(agent.name) if agent.name else ""
        
        for conn_id in hub._connections.keys():
            conn_id_norm = normalize(conn_id)
            if agent_name_norm and (agent_name_norm in conn_id_norm or conn_id_norm in agent_name_norm):
                ws_agent_id = conn_id
                break
        
        # Step 1: Ottieni cache ARP da gateway (delegando all'agent remoto)
        arp_cache = {}  # {ip: mac}
        gateway_agent_id = getattr(network, 'gateway_agent_id', None)
        gateway_snmp_address = getattr(network, 'gateway_snmp_address', None)
        gateway_snmp_community = getattr(network, 'gateway_snmp_community', None)
        
        if ws_agent_id and gateway_agent_id:
            # Opzione 1: Usa gateway MikroTik specificato - DELEGA ALL'AGENT
            gateway_agent = service.get_agent(gateway_agent_id, include_password=True)
            if gateway_agent:
                # Verifica che le credenziali siano presenti
                if not gateway_agent.password or not gateway_agent.password.strip():
                    logger.warning(f"[ARP CACHE] Agent {gateway_agent.name} ({gateway_agent.address}) has no password configured. Cannot query ARP table.")
                else:
                    logger.info(f"[ARP CACHE] Delegating MikroTik ARP query to agent {ws_agent_id} -> {gateway_agent.name} ({gateway_agent.address})")
                    try:
                        arp_result = await hub.send_command(
                            ws_agent_id,
                            CommandType.GET_ARP_TABLE,
                            params={
                                "method": "mikrotik",
                                "address": gateway_agent.address,
                                "port": gateway_agent.port or 8728,
                                "username": gateway_agent.username or "admin",
                                "password": gateway_agent.password,
                                "use_ssl": gateway_agent.use_ssl or False,
                                "network_cidr": network.ip_network,
                            },
                            timeout=60.0
                        )
                        if arp_result.status == "success" and arp_result.data:
                            for entry in arp_result.data.get("entries", []):
                                arp_cache[entry["ip"]] = entry["mac"]
                            logger.info(f"[ARP CACHE] Got {len(arp_cache)} MAC addresses from MikroTik via agent")
                    except Exception as e:
                        logger.warning(f"[ARP CACHE] MikroTik via agent failed: {e}")
        
        elif ws_agent_id and gateway_snmp_address and gateway_snmp_community:
            # Opzione 2: Usa gateway generico via SNMP - DELEGA ALL'AGENT
            logger.info(f"[ARP CACHE] Delegating SNMP ARP query to agent {ws_agent_id} -> {gateway_snmp_address}")
            try:
                snmp_version = getattr(network, 'gateway_snmp_version', '2c') or '2c'
                arp_result = await hub.send_command(
                    ws_agent_id,
                    CommandType.GET_ARP_TABLE,
                    params={
                        "method": "snmp",
                        "address": gateway_snmp_address,
                        "community": gateway_snmp_community,
                        "version": snmp_version,
                        "network_cidr": network.ip_network,
                    },
                    timeout=120.0  # SNMP può essere lento con molti device
                )
                if arp_result.status == "success" and arp_result.data:
                    for entry in arp_result.data.get("entries", []):
                        arp_cache[entry["ip"]] = entry["mac"]
                    logger.info(f"[ARP CACHE] Got {len(arp_cache)} MAC addresses from SNMP via agent")
            except Exception as e:
                logger.warning(f"[ARP CACHE] SNMP via agent failed: {e}")
        
        elif ws_agent_id:
            # Prima controlla se l'agent Docker ha un ARP gateway configurato
            if agent.agent_type == "docker":
                # Usa ARP gateway configurato nell'agent Docker
                if agent.arp_gateway_agent_id:
                    gateway_agent = service.get_agent(agent.arp_gateway_agent_id, include_password=True)
                    if gateway_agent and gateway_agent.agent_type == "mikrotik":
                        if gateway_agent.password and gateway_agent.password.strip():
                            logger.info(f"[ARP CACHE] Using configured MikroTik gateway {gateway_agent.name} via agent {ws_agent_id}")
                            try:
                                arp_result = await hub.send_command(
                                    ws_agent_id,
                                    CommandType.GET_ARP_TABLE,
                                    params={
                                        "method": "mikrotik",
                                        "address": gateway_agent.address,
                                        "port": gateway_agent.port or 8728,
                                        "username": gateway_agent.username or "admin",
                                        "password": gateway_agent.password,
                                        "use_ssl": gateway_agent.use_ssl or False,
                                        "network_cidr": network.ip_network,
                                    },
                                    timeout=60.0
                                )
                                if arp_result.status == "success" and arp_result.data:
                                    for entry in arp_result.data.get("entries", []):
                                        arp_cache[entry["ip"]] = entry["mac"]
                                    logger.info(f"[ARP CACHE] Got {len(arp_cache)} MAC addresses from configured gateway {gateway_agent.name}")
                            except Exception as e:
                                logger.warning(f"[ARP CACHE] Configured gateway failed: {e}")
                
                # Oppure usa SNMP gateway configurato
                if not arp_cache and agent.arp_gateway_snmp_address and agent.arp_gateway_snmp_community:
                    logger.info(f"[ARP CACHE] Using configured SNMP gateway {agent.arp_gateway_snmp_address} via agent {ws_agent_id}")
                    try:
                        snmp_version = agent.arp_gateway_snmp_version or '2c'
                        arp_result = await hub.send_command(
                            ws_agent_id,
                            CommandType.GET_ARP_TABLE,
                            params={
                                "method": "snmp",
                                "address": agent.arp_gateway_snmp_address,
                                "community": agent.arp_gateway_snmp_community,
                                "version": snmp_version,
                                "network_cidr": network.ip_network,
                            },
                            timeout=120.0
                        )
                        if arp_result.status == "success" and arp_result.data:
                            for entry in arp_result.data.get("entries", []):
                                arp_cache[entry["ip"]] = entry["mac"]
                            logger.info(f"[ARP CACHE] Got {len(arp_cache)} MAC addresses from configured SNMP gateway")
                    except Exception as e:
                        logger.warning(f"[ARP CACHE] Configured SNMP gateway failed: {e}")
            
            # Fallback: cerca un MikroTik qualsiasi del cliente e delega all'agent
            if not arp_cache:
                all_agents = service.list_agents(customer_id=agent.customer_id, active_only=True)
                for ag in all_agents:
                    ag_type = getattr(ag, 'agent_type', 'mikrotik') or 'mikrotik'
                    if ag_type == 'mikrotik':
                        mikrotik_agent = service.get_agent(ag.id, include_password=True)
                        if mikrotik_agent:
                            # Verifica che le credenziali siano presenti
                            if not mikrotik_agent.password or not mikrotik_agent.password.strip():
                                logger.debug(f"[ARP CACHE] Skipping MikroTik {mikrotik_agent.name} - no password configured")
                                continue
                            
                            logger.info(f"[ARP CACHE] Trying MikroTik {mikrotik_agent.name} via agent {ws_agent_id}")
                            try:
                                arp_result = await hub.send_command(
                                    ws_agent_id,
                                    CommandType.GET_ARP_TABLE,
                                    params={
                                        "method": "mikrotik",
                                        "address": mikrotik_agent.address,
                                        "port": mikrotik_agent.port or 8728,
                                        "username": mikrotik_agent.username or "admin",
                                        "password": mikrotik_agent.password,
                                        "use_ssl": mikrotik_agent.use_ssl or False,
                                        "network_cidr": network.ip_network,
                                    },
                                    timeout=60.0
                                )
                                if arp_result.status == "success" and arp_result.data and arp_result.data.get("count", 0) > 0:
                                    for entry in arp_result.data.get("entries", []):
                                        arp_cache[entry["ip"]] = entry["mac"]
                                    logger.info(f"[ARP CACHE] Got {len(arp_cache)} MAC addresses from {mikrotik_agent.name} via agent")
                                    break  # Trovato, esci dal loop
                            except Exception as e:
                                logger.debug(f"[ARP CACHE] MikroTik {mikrotik_agent.name} via agent failed: {e}")
        
        # Step 2: Esegui nmap scan via WebSocket
        scan_result = None
        
        if ws_agent_id and ws_agent_id in hub._connections:
            # Agent connesso via WebSocket - invia scan
            logger.info(f"[SCAN VIA WEBSOCKET] Scanning {network.ip_network} via {ws_agent_id}")
            try:
                result = await hub.send_command(
                    ws_agent_id,
                    CommandType.SCAN_NETWORK,
                    params={"network": network.ip_network, "scan_type": scan_type},
                    timeout=300.0  # Timeout più lungo per reti grandi
                )
                
                if result.status == "success":
                    scan_result = result.data or {}
                    scan_result["success"] = True
                    
                    # Normalizza e arricchisci con MAC da cache ARP
                    hosts = scan_result.get("hosts", scan_result.get("devices", []))
                    normalized_devices = []
                    mac_found_count = 0
                    
                    for h in hosts:
                        ip = h.get("ip", h.get("address", ""))
                        # Prima prova MAC da scan nmap, poi da cache ARP
                        mac = h.get("mac", h.get("mac_address", ""))
                        if not mac and ip in arp_cache:
                            mac = arp_cache[ip]
                            mac_found_count += 1
                        
                        device = {
                            "address": ip,
                            "mac_address": mac,
                            "vendor": h.get("vendor", ""),
                            "hostname": h.get("hostname", ""),
                            "status": h.get("status", "up"),
                        }
                        normalized_devices.append(device)
                    
                    scan_result["devices"] = normalized_devices
                    scan_result["devices_found"] = len(normalized_devices)
                    logger.info(f"[SCAN COMPLETED] {len(normalized_devices)} devices, {mac_found_count} MAC from ARP cache")
                else:
                    logger.error(f"WebSocket scan failed: {result.error}")
                    raise HTTPException(status_code=500, detail=f"Errore scansione: {result.error}")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"WebSocket scan failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Errore scansione WebSocket: {e}")
        else:
            # Fallback: agent non connesso via WebSocket, prova HTTP
            agent_url = agent.agent_url or f"http://{agent.address}:{agent.agent_api_port or 8080}"
            agent_token = agent.agent_token or ""
            
            logger.info(f"[SCAN VIA HTTP] Agent not on WebSocket, trying HTTP to {agent_url}")
            agent_config = AgentConfig(
                agent_id=agent.id,
                agent_url=agent_url,
                agent_token=agent_token,
            )
            
            agent_client = AgentClient(agent_config)
            try:
                scan_result = await agent_client.scan_network(network.ip_network, scan_type=scan_type)
                
                # Arricchisci con MAC da cache ARP
                devices = scan_result.get("devices", [])
                for d in devices:
                    ip = d.get("address", "")
                    if not d.get("mac_address") and ip in arp_cache:
                        d["mac_address"] = arp_cache[ip]
                
                logger.info(f"[SCAN VIA HTTP] Completed: {scan_result.get('devices_found', 0)} devices")
            except Exception as e:
                logger.error(f"HTTP agent scan failed: {e}", exc_info=True)
                raise HTTPException(status_code=500, detail=f"Errore scansione agent: {e}")
            finally:
                await agent_client.close()
    
    # MikroTik agent - Usa API o SSH in base al tipo di connessione
    elif agent.connection_type in ["api", "both"]:
        logger.info(f"[SCAN VIA MIKROTIK API] Using {agent.name} ({agent.address}:{agent.port}) for scan on {network.ip_network}")
        scan_result = scanner.scan_network_via_router(
            router_address=agent.address,
            router_port=agent.port,
            router_username=agent.username or "admin",
            router_password=agent.password or "",
            network=network.ip_network,
            scan_type=scan_type,
            use_ssl=agent.use_ssl,
        )
    elif agent.connection_type == "ssh":
        logger.info(f"[SCAN VIA MIKROTIK SSH] Using {agent.name} ({agent.address}:{agent.ssh_port}) for scan on {network.ip_network}")
        scan_result = scanner.scan_network_via_ssh(
            router_address=agent.address,
            ssh_port=agent.ssh_port,
            username=agent.username or "admin",
            password=agent.password or "",
            network=network.ip_network,
            ssh_key=agent.ssh_key,
        )
    else:
        raise HTTPException(status_code=400, detail="Tipo connessione non valido")
    
    # Salva risultati nel database
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    # Inizializza devices_list prima del try per evitare UnboundLocalError
    devices_list = []
    
    try:
        # Usa record esistente se fornito, altrimenti crea nuovo
        if existing_scan_id:
            scan_record = session.query(ScanResult).filter(ScanResult.id == existing_scan_id).first()
            if not scan_record:
                raise HTTPException(status_code=404, detail=f"Scan record {existing_scan_id} not found")
            # Aggiorna record esistente
            scan_record.devices_found = scan_result.get("devices_found", 0)
            scan_record.status = "completed" if scan_result.get("success") else "failed"
            scan_record.error_message = scan_result.get("error")
            scan_id = existing_scan_id
        else:
            # Crea nuovo record scansione
            scan_record = ScanResult(
                customer_id=agent.customer_id,
                agent_id=agent_id,
                network_id=network.id,
                network_cidr=network.ip_network,
                scan_type=scan_type,
                devices_found=scan_result.get("devices_found", 0),
                status="completed" if scan_result.get("success") else "failed",
                error_message=scan_result.get("error"),
            )
            session.add(scan_record)
            session.flush()  # Per ottenere l'ID
            scan_id = scan_record.id
        
        # Salva dispositivi trovati
        # Supporta sia "results" (vecchio formato) che "devices" (nuovo formato WebSocket)
        devices_list = scan_result.get("results") or scan_result.get("devices") or []
        if scan_result.get("success") and devices_list:
            from ..services.device_probe_service import get_device_probe_service, MikroTikAgent
            from ..services.mikrotik_service import get_mikrotik_service
            
            probe_service = get_device_probe_service()
            mikrotik_service = get_mikrotik_service()
            
            # Prepara lista DNS servers dalla rete
            dns_servers = []
            if network.dns_primary:
                dns_servers.append(network.dns_primary)
            if network.dns_secondary:
                dns_servers.append(network.dns_secondary)
            
            logger.info(f"DNS servers for network {network.ip_network}: {dns_servers}")
            
            # Carica credenziali SNMP del cliente per il probe UDP
            # "public" è sempre inclusa come fallback standard
            snmp_communities = []
            if agent.customer_id:
                try:
                    customer_service = get_customer_service()
                    customer_creds = customer_service.list_credentials(agent.customer_id)
                    for cred in customer_creds:
                        cred_details = customer_service.get_credential(cred.id, include_secrets=True)
                        if cred_details and cred_details.snmp_community and cred_details.snmp_community not in snmp_communities:
                            snmp_communities.append(cred_details.snmp_community)
                except Exception as e:
                    logger.warning(f"Error loading SNMP credentials: {e}")
            # Aggiungi sempre "public" alla fine come fallback
            if "public" not in snmp_communities:
                snmp_communities.append("public")
            logger.info(f"SNMP communities for scan: {snmp_communities}")
            
            # Crea oggetto MikroTikAgent per operazioni remote (solo per agent MikroTik)
            mikrotik_agent = None
            if agent_type == "mikrotik" and agent and agent.address and agent.username:
                mikrotik_agent = MikroTikAgent(
                    address=agent.address,
                    username=agent.username,
                    password=agent.password or "",
                    port=agent.ssh_port or 22,
                    api_port=agent.port or 8728,
                    use_ssl=agent.use_ssl or False,
                    dns_server=dns_servers[0] if dns_servers else None,
                )
            
            logger.info(f"Processing {len(devices_list)} devices, DNS servers: {dns_servers}, agent: {mikrotik_agent.address if mikrotik_agent else 'local'}")
            
            # Prova batch reverse DNS tramite MikroTik se abbiamo un agente
            mikrotik_dns_results = {}
            if mikrotik_agent:
                try:
                    target_ips = [d.get("address", "") for d in devices_list if d.get("address")]
                    
                    mikrotik_dns_results = mikrotik_service.batch_reverse_dns_lookup(
                        address=mikrotik_agent.address,
                        port=mikrotik_agent.api_port,
                        username=mikrotik_agent.username,
                        password=mikrotik_agent.password,
                        target_ips=target_ips,
                        dns_server=mikrotik_agent.dns_server,
                    )
                    logger.info(f"MikroTik batch DNS resolved {len(mikrotik_dns_results)}/{len(target_ips)} hostnames")
                except Exception as e:
                    logger.warning(f"MikroTik batch DNS lookup failed: {e}")
            
            # Processa device in batch per evitare blocchi
            # Limita reverse DNS e port scan per evitare timeout
            import asyncio
            MAX_CONCURRENT_DNS = 5  # Massimo 5 DNS lookup in parallelo
            MAX_CONCURRENT_PORTS = 2  # Massimo 2 port scan in parallelo (molto limitato)
            DNS_TIMEOUT = 5.0  # Timeout DNS lookup: 5 secondi
            PORT_SCAN_TIMEOUT = 15.0  # Timeout port scan: 15 secondi (sufficiente per 13 porte TCP + SNMP UDP)
            
            # Processa device in batch con semafori separati per DNS e port scan
            semaphore_dns = asyncio.Semaphore(MAX_CONCURRENT_DNS)
            semaphore_ports = asyncio.Semaphore(MAX_CONCURRENT_PORTS)
            processed_devices = []
            
            async def process_with_semaphores(device):
                """Processa device con semafori per DNS e port scan"""
                device_ip = device.get("address", "")
                device_mac = device.get("mac_address", "")
                
                # Lookup vendor dal MAC address se non presente
                vendor = device.get("vendor", "")
                if not vendor and device_mac:
                    try:
                        from ..services.mac_vendor_service import get_mac_vendor_service
                        vendor_service = get_mac_vendor_service()
                        vendor_info = vendor_service.lookup_vendor_with_type(device_mac)
                        if vendor_info and vendor_info.get("vendor"):
                            vendor = vendor_info["vendor"]
                            logger.debug(f"Vendor lookup for {device_mac}: {vendor}")
                    except Exception as e:
                        logger.debug(f"Vendor lookup failed for {device_mac}: {e}")
                
                # Reverse DNS lookup (PTR record) - salviamo separatamente dall'hostname reale
                reverse_dns = ""
                
                # Prima prova con risultati batch MikroTik
                if device_ip and device_ip in mikrotik_dns_results:
                    reverse_dns = mikrotik_dns_results[device_ip]
                    logger.debug(f"Reverse DNS from MikroTik: {device_ip} -> {reverse_dns}")
                
                # Fallback a lookup diretto/tramite agente se non trovato (con timeout e semaforo)
                if not reverse_dns and device_ip:
                    async with semaphore_dns:
                        try:
                            # Usa il DNS server della rete se disponibile
                            primary_dns = dns_servers[0] if dns_servers else None
                            fallback_dns_list = dns_servers[1:] if len(dns_servers) > 1 else None
                            
                            logger.debug(f"Reverse DNS lookup for {device_ip} via DNS servers: {dns_servers}")
                            
                            dns_result = await asyncio.wait_for(
                                probe_service.reverse_dns_lookup(
                                    device_ip, 
                                    dns_server=primary_dns,
                                    fallback_dns=fallback_dns_list
                                ),
                                timeout=DNS_TIMEOUT
                            )
                            if dns_result and dns_result.get("success") and dns_result.get("hostname"):
                                reverse_dns = dns_result["hostname"]
                                logger.info(f"Reverse DNS for {device_ip}: {reverse_dns} (via {dns_result.get('dns_server', 'unknown')})")
                            elif dns_result:
                                logger.debug(f"Reverse DNS failed for {device_ip}: {dns_result.get('error', 'unknown error')}")
                        except asyncio.TimeoutError:
                            logger.debug(f"Reverse DNS timeout for {device_ip}")
                        except Exception as e:
                            logger.debug(f"Reverse DNS lookup failed for {device_ip}: {e}")
                
                # Usa nome da reverse DNS se non c'è identity (solo come fallback per display)
                identity = device.get("identity", "")
                if not identity and reverse_dns:
                    identity = reverse_dns.split('.')[0]  # Prendi solo la parte prima del punto
                
                # Scansiona porte critiche per pre-assegnazione OS/device_type (veloce)
                open_ports_data = []
                if device_ip:
                    async with semaphore_ports:
                        try:
                            logger.info(f"[SCAN] Starting quick port scan for {device_ip}")
                            # Scansione porte QUICK - solo porte critiche per pre-assegnazione
                            ports_result = await asyncio.wait_for(
                                probe_service.scan_services_quick(
                                    device_ip, 
                                    snmp_communities=snmp_communities
                                ),
                                timeout=PORT_SCAN_TIMEOUT  # 3 secondi timeout (sufficiente per 13 porte)
                            )
                            open_ports_data = ports_result
                            open_count = len([p for p in ports_result if p.get('open')])
                            logger.info(f"[SCAN] Quick port scan for {device_ip}: {open_count} ports open (total scanned: {len(ports_result)})")
                            if open_count > 0:
                                logger.info(f"[SCAN] Open ports for {device_ip}: {[p.get('port') for p in ports_result if p.get('open')]}")
                        except asyncio.TimeoutError:
                            logger.warning(f"[SCAN] Quick port scan timeout for {device_ip} (skipped)")
                            # Continua senza porte - meglio avere il device senza porte che bloccarsi
                        except Exception as e:
                            logger.error(f"[SCAN] Quick port scan failed for {device_ip}: {e}", exc_info=True)
                            # Continua senza porte
                
                return {
                    "device": device,
                    "device_ip": device_ip,
                    "device_mac": device_mac,
                    "vendor": vendor,  # Aggiungi vendor al risultato
                    "identity": identity,
                    "reverse_dns": reverse_dns,
                    "open_ports_data": open_ports_data,
                }
            
            # Processa tutti i device in parallelo (limitato dai semafori)
            try:
                tasks = [process_with_semaphores(device) for device in devices_list]
                processed_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in processed_results:
                    if isinstance(result, Exception):
                        logger.warning(f"Error processing device: {result}")
                        continue
                    processed_devices.append(result)
            except Exception as e:
                logger.error(f"Error processing devices batch: {e}", exc_info=True)
            
            # Crea record DiscoveredDevice per ogni device processato
            for result in processed_devices:
                if not result:
                    continue
                
                device = result["device"]
                device_ip = result["device_ip"]
                device_mac = result["device_mac"]
                vendor = result.get("vendor", "")  # Vendor dal lookup MAC
                identity = result["identity"]
                reverse_dns = result["reverse_dns"]
                open_ports_data = result["open_ports_data"]
                
                # Pre-assegna OS/device_type in base alle porte aperte
                pre_device_type = None
                pre_category = None
                pre_os_family = None
                
                if open_ports_data:
                    ports_set = {p.get('port') for p in open_ports_data if p.get('open')}
                    services_set = {p.get('service') for p in open_ports_data if p.get('open') and p.get('service')}
                    
                    # Windows indicators (priorità alta)
                    windows_ports = {135, 139, 445, 3389, 5985, 5986}
                    if ports_set & windows_ports:
                        pre_os_family = "Windows"
                        pre_device_type = "windows"
                        if 3389 in ports_set and 445 not in ports_set:
                            pre_category = "workstation"
                        elif 389 in ports_set:
                            pre_category = "server"  # Domain Controller
                        else:
                            pre_category = "server"
                    # MikroTik
                    elif 8728 in ports_set or 8291 in ports_set:
                        pre_os_family = "RouterOS"
                        pre_device_type = "mikrotik"
                        pre_category = "router"
                    # Proxmox
                    elif 8006 in ports_set:
                        pre_os_family = "Proxmox"
                        pre_device_type = "linux"
                        pre_category = "hypervisor"
                    # Linux/Unix (SSH ma non Windows)
                    elif 22 in ports_set and not (ports_set & windows_ports):
                        pre_os_family = "Linux"
                        pre_device_type = "linux"
                        if 3306 in ports_set or 5432 in ports_set:
                            pre_category = "server"  # Database
                        elif 80 in ports_set or 443 in ports_set:
                            pre_category = "server"  # Web
                        elif 2049 in ports_set:
                            pre_category = "server"  # NFS
                        elif 161 in ports_set:
                            pre_category = "network"  # Network device
                        else:
                            pre_category = "server"
                    # SNMP only = network device
                    elif 161 in ports_set:
                        pre_device_type = "network"
                        pre_category = "switch"
                    # NFS
                    elif 2049 in ports_set:
                        pre_os_family = "Linux"
                        pre_device_type = "linux"
                        pre_category = "server"
                
                logger.info(f"[SCAN] Saving device {device_ip}: ports={len(open_ports_data) if open_ports_data else 0}, type={pre_device_type}, category={pre_category}, os={pre_os_family}")
                
                dev_record = DiscoveredDevice(
                    scan_id=scan_record.id,
                    customer_id=agent.customer_id,
                    address=device_ip,
                    mac_address=device_mac,
                    vendor=vendor or device.get("vendor", ""),  # Usa vendor dal lookup o dal device originale
                    identity=identity,  # Identity dal protocollo o nome breve da reverse DNS
                    hostname=device.get("hostname", ""),  # Hostname reale (da probe)
                    reverse_dns=reverse_dns,  # Nome da PTR record (separato)
                    platform=device.get("platform", ""),
                    board=device.get("board", ""),
                    interface=device.get("interface", ""),
                    source=device.get("source", ""),
                    open_ports=open_ports_data if open_ports_data else None,
                    device_type=pre_device_type,
                    category=pre_category,
                    os_family=pre_os_family,
                    # imported_at verrà impostato solo durante l'import, non durante la scansione
                )
                session.add(dev_record)
        
        try:
            session.commit()
        except Exception as commit_error:
            # Se c'è un errore (es: colonna imported_at non esiste), prova senza quel campo
            error_str = str(commit_error).lower()
            if 'imported_at' in error_str or 'column' in error_str:
                logger.warning(f"Database schema mismatch detected, retrying without new fields: {commit_error}")
                session.rollback()
                # Rimuovi temporaneamente imported_at dal modello se causa problemi
                # (il campo verrà aggiunto dalla migration)
                try:
                    # Prova a fare commit senza gestire imported_at esplicitamente
                    # SQLAlchemy dovrebbe gestirlo automaticamente se nullable=True
                    session.commit()
                except Exception as retry_error:
                    logger.error(f"Error committing scan results after retry: {retry_error}")
                    raise
            else:
                raise
        scan_id = scan_record.id
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving scan results: {e}")
        scan_id = None
    finally:
        session.close()
    
    # Prepara risposta con formato compatibile con la UI
    return {
        "scan_id": scan_id,
        "agent_id": agent_id,
        "agent_name": agent.name,
        "customer_id": agent.customer_id,
        "scan_type": scan_type,
        "networks_scanned": 1,
        "results": [{
            "network_id": network.id,
            "network_name": network.name,
            "network_cidr": network.ip_network,
            "success": scan_result.get("success", False),
            "devices_found": scan_result.get("devices_found", 0),
            "devices": devices_list,  # Includi i dispositivi!
            "error": scan_result.get("error"),
        }],
        "message": scan_result.get("message", ""),
        "view_url": f"/customers/{agent.customer_id}/scans/{scan_id}" if scan_id else None
    }


# ==========================================
# SCAN RESULTS
# ==========================================

@router.get("/{customer_id}/scans")
async def list_customer_scans(
    customer_id: str,
    limit: int = Query(20, ge=1, le=100),
):
    """Lista scansioni di un cliente"""
    from ..models.database import ScanResult, init_db, get_session
    from ..config import get_settings
    
    service = get_customer_service()
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scans = session.query(ScanResult).filter(
            ScanResult.customer_id == customer_id
        ).order_by(ScanResult.created_at.desc()).limit(limit).all()
        
        return {
            "customer_id": customer_id,
            "total": len(scans),
            "scans": [
                {
                    "id": s.id,
                    "network_cidr": s.network_cidr,
                    "scan_type": s.scan_type,
                    "devices_found": s.devices_found,
                    "status": s.status,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
                for s in scans
            ]
        }
    finally:
        session.close()


@router.get("/{customer_id}/scans/{scan_id}", response_class=HTMLResponse)
async def scan_results_page(request: Request, customer_id: str, scan_id: str):
    """Pagina HTML per visualizzare i risultati di una scansione"""
    from fastapi.templating import Jinja2Templates
    import os
    
    service = get_customer_service()
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Cliente non trovato")
    
    # Carica dettagli scansione usando la funzione esistente
    scan_data = await _get_scan_details_data(customer_id, scan_id)
    
    # Setup templates
    templates_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
    templates = Jinja2Templates(directory=templates_dir)
    
    return templates.TemplateResponse("scan_results.html", {
        "request": request,
        "page": "scans",
        "title": f"Risultati Scansione - {customer.name}",
        "customer": customer,
        "scan": scan_data["scan"],
        "devices": scan_data["devices"],
    })


async def _get_scan_details_data(customer_id: str, scan_id: str):
    """Helper function per ottenere i dati di una scansione"""
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id
        ).order_by(DiscoveredDevice.identity, DiscoveredDevice.address).all()
        
        return {
            "scan": {
                "id": scan.id,
                "network_cidr": scan.network_cidr,
                "scan_type": scan.scan_type,
                "devices_found": scan.devices_found,
                "status": scan.status,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            },
            "devices": [
                {
                    "id": d.id,
                    "address": d.address,
                    "mac_address": d.mac_address,
                    "identity": d.identity,
                    "hostname": d.hostname,
                    "platform": d.platform,
                    "board": d.board,
                    "interface": d.interface,
                    "source": d.source,
                    "imported": d.imported,
                    "open_ports": d.open_ports,
                    "os_family": d.os_family,
                    "os_version": d.os_version,
                    "vendor": d.vendor,
                    "model": d.model,
                    "category": d.category,
                    "cpu_cores": d.cpu_cores,
                    "ram_total_mb": d.ram_total_mb,
                    "disk_total_gb": d.disk_total_gb,
                    "serial_number": d.serial_number,
                }
                for d in devices
            ]
        }
    finally:
        session.close()


@router.get("/{customer_id}/scans/{scan_id}/api")
async def get_scan_details(customer_id: str, scan_id: str):
    """Dettagli di una scansione con dispositivi trovati (API endpoint)"""
    return await _get_scan_details_data(customer_id, scan_id)


@router.post("/{customer_id}/scans/{scan_id}/resolve")
async def resolve_discovered_devices(
    customer_id: str,
    scan_id: str,
    request: dict = Body(...),
):
    """
    Forza la risoluzione di MAC address (vendor) e DNS (reverse lookup) per i device selezionati.
    """
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..services.device_probe_service import DeviceProbeService
    from ..services.mac_vendor_service import get_mac_vendor_service
    from ..config import get_settings
    
    device_ids = request.get("device_ids", [])
    if not device_ids:
        raise HTTPException(status_code=400, detail="Nessun device_id fornito")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        # Carica device da risolvere
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id,
            DiscoveredDevice.id.in_(device_ids)
        ).all()
        
        if not devices:
            raise HTTPException(status_code=400, detail="Nessun dispositivo trovato")
        
        # Ottieni DNS servers dalla rete se disponibile
        from ..models.database import Network
        network = session.query(Network).filter(Network.id == scan.network_id).first() if scan.network_id else None
        dns_servers = []
        if network:
            if network.dns_primary:
                dns_servers.append(network.dns_primary)
            if network.dns_secondary:
                dns_servers.append(network.dns_secondary)
        
        # Ottieni agent MikroTik se disponibile per batch DNS
        mikrotik_agent = None
        if scan.agent_id:
            from ..models.database import AgentAssignment
            agent = session.query(AgentAssignment).filter(AgentAssignment.id == scan.agent_id).first()
            if agent and agent.agent_type == "mikrotik":
                from ..services.mikrotik_service import MikroTikService
                mikrotik_service = MikroTikService()
                mikrotik_agent = type('obj', (object,), {
                    'address': agent.address,
                    'username': agent.username,
                    'password': agent.password or "",
                    'port': agent.port or 8728,
                    'api_port': agent.port or 8728,
                    'ssh_port': agent.ssh_port or 22,
                    'use_ssl': agent.use_ssl or False,
                })()
        
        probe_service = DeviceProbeService()
        vendor_service = get_mac_vendor_service()
        
        vendor_resolved = 0
        dns_resolved = 0
        total_processed = 0
        
        import asyncio
        
        # Prova batch reverse DNS tramite MikroTik se disponibile
        mikrotik_dns_results = {}
        if mikrotik_agent and dns_servers:
            try:
                from ..services.mikrotik_service import MikroTikService
                mikrotik_service = MikroTikService()
                target_ips = [d.address for d in devices if d.address]
                mikrotik_dns_results = mikrotik_service.batch_reverse_dns_lookup(
                    address=mikrotik_agent.address,
                    port=mikrotik_agent.api_port,
                    username=mikrotik_agent.username,
                    password=mikrotik_agent.password,
                    target_ips=target_ips,
                    dns_server=dns_servers[0] if dns_servers else None,
                )
                logger.info(f"MikroTik batch DNS resolved {len(mikrotik_dns_results)}/{len(target_ips)} hostnames")
            except Exception as e:
                logger.warning(f"MikroTik batch DNS lookup failed: {e}")
        
        # Processa ogni device
        for device in devices:
            total_processed += 1
            updated = False
            
            # Risolvi vendor dal MAC address se presente
            if device.mac_address and not device.vendor:
                try:
                    vendor_info = vendor_service.lookup_vendor_with_type(device.mac_address)
                    if vendor_info and vendor_info.get("vendor"):
                        device.vendor = vendor_info["vendor"]
                        if vendor_info.get("device_type") and not device.category:
                            device.category = vendor_info["device_type"]
                        vendor_resolved += 1
                        updated = True
                        logger.debug(f"Resolved vendor for {device.mac_address}: {device.vendor}")
                except Exception as e:
                    logger.debug(f"Vendor lookup failed for {device.mac_address}: {e}")
            
            # Risolvi reverse DNS se non presente
            if device.address and not device.reverse_dns:
                reverse_dns = ""
                
                # Prova con risultati batch MikroTik
                if device.address in mikrotik_dns_results:
                    reverse_dns = mikrotik_dns_results[device.address]
                    logger.info(f"Reverse DNS from MikroTik batch: {device.address} -> {reverse_dns}")
                
                # Se non trovato nel batch, prova lookup individuale tramite MikroTik
                if not reverse_dns and mikrotik_agent:
                    try:
                        logger.debug(f"Trying MikroTik reverse DNS for {device.address} via {mikrotik_agent.address}")
                        loop = asyncio.get_event_loop()
                        dns_result = await loop.run_in_executor(
                            None,
                            lambda: mikrotik_service.reverse_dns_lookup(
                                address=mikrotik_agent.address,
                                port=mikrotik_agent.api_port,
                                username=mikrotik_agent.username,
                                password=mikrotik_agent.password,
                                target_ip=device.address,
                                dns_server=dns_servers[0] if dns_servers else None,
                                use_ssl=mikrotik_agent.use_ssl,
                            )
                        )
                        if dns_result and dns_result.get("success") and dns_result.get("hostname"):
                            reverse_dns = dns_result["hostname"]
                            logger.info(f"Reverse DNS via MikroTik for {device.address}: {reverse_dns}")
                    except Exception as e:
                        logger.debug(f"MikroTik reverse DNS lookup failed for {device.address}: {e}")
                
                # Fallback a lookup diretto solo se MikroTik non disponibile o fallito
                if not reverse_dns:
                    try:
                        logger.debug(f"Trying direct DNS lookup for {device.address} via DNS servers: {dns_servers}")
                        dns_result = await probe_service.reverse_dns_lookup(
                            device.address,
                            dns_server=dns_servers[0] if dns_servers else None,
                            fallback_dns=dns_servers[1:] if len(dns_servers) > 1 else None,
                            timeout=5.0
                        )
                        if dns_result and dns_result.get("success") and dns_result.get("hostname"):
                            reverse_dns = dns_result["hostname"]
                            logger.info(f"Reverse DNS for {device.address}: {reverse_dns} (via {dns_result.get('dns_server', 'unknown')})")
                        elif dns_result:
                            logger.debug(f"Direct DNS lookup failed for {device.address}: {dns_result.get('error', 'unknown error')}")
                    except Exception as e:
                        logger.debug(f"Direct DNS lookup failed for {device.address}: {e}")
                
                if reverse_dns:
                    device.reverse_dns = reverse_dns
                    # Aggiorna anche hostname se vuoto
                    if not device.hostname:
                        device.hostname = reverse_dns
                    dns_resolved += 1
                    updated = True
                else:
                    logger.debug(f"Could not resolve reverse DNS for {device.address} (tried MikroTik and direct DNS)")
            
            if updated:
                session.add(device)
        
        session.commit()
        
        return {
            "success": True,
            "total_processed": total_processed,
            "vendor_resolved": vendor_resolved,
            "dns_resolved": dns_resolved,
            "message": f"Risoluzione completata: {vendor_resolved} vendor, {dns_resolved} DNS"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving devices: {e}", exc_info=True)
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Errore durante la risoluzione: {str(e)}")
    finally:
        session.close()


@router.post("/{customer_id}/scans/{scan_id}/identify")
async def identify_discovered_devices(
    customer_id: str,
    scan_id: str,
    request: dict = Body(...),
):
    """
    Identifica dispositivi scoperti usando probe SNMP/SSH/WMI e vendor matching.
    Aggiorna DiscoveredDevice con device_type, category, os_family, etc.
    """
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..services.device_probe_service import DeviceProbeService
    from ..services.mac_vendor_service import get_mac_vendor_service
    from ..services.customer_service import get_customer_service
    from ..config import get_settings
    
    device_ids = request.get("device_ids", [])
    if not device_ids:
        raise HTTPException(status_code=400, detail="Nessun device_id fornito")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        # Carica device da identificare
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id,
            DiscoveredDevice.id.in_(device_ids)
        ).all()
        
        if not devices:
            raise HTTPException(status_code=400, detail="Nessun dispositivo trovato")
        
        # Carica credenziali del cliente
        customer_service = get_customer_service()
        credentials_list = []
        try:
            customer_creds = customer_service.list_credentials(customer_id)
            for cred in customer_creds:
                cred_details = customer_service.get_credential(cred.id, include_secrets=True)
                if cred_details:
                    credentials_list.append({
                        "id": cred_details.id,
                        "name": cred_details.name,
                        "type": cred_details.credential_type,
                        "username": cred_details.username,
                        "password": cred_details.password,
                        "ssh_port": getattr(cred_details, 'ssh_port', 22),
                        "ssh_private_key": getattr(cred_details, 'ssh_private_key', None),
                        "snmp_community": getattr(cred_details, 'snmp_community', None),
                        "snmp_version": getattr(cred_details, 'snmp_version', '2c'),
                        "snmp_port": getattr(cred_details, 'snmp_port', 161),
                        "wmi_domain": getattr(cred_details, 'wmi_domain', None),
                        "mikrotik_api_port": getattr(cred_details, 'mikrotik_api_port', 8728),
                    })
        except Exception as e:
            logger.warning(f"Error loading credentials for customer {customer_id}: {e}")
        
        probe_service = DeviceProbeService()
        vendor_service = get_mac_vendor_service()
        
        identified_count = 0
        snmp_count = 0
        ssh_count = 0
        wmi_count = 0
        vendor_count = 0
        total_processed = 0
        
        import asyncio
        
        # Prepara community SNMP (rimuovi duplicati, aggiungi 'public' come fallback)
        snmp_communities_unique = []
        for cred in credentials_list:
            comm = cred.get('snmp_community')
            if comm and comm not in snmp_communities_unique:
                snmp_communities_unique.append(comm)
        if 'public' not in snmp_communities_unique:
            snmp_communities_unique.append('public')
        
        logger.info(f"[IDENTIFY] SNMP communities loaded: {snmp_communities_unique}")
        
        # Processa ogni device
        async def identify_device(device):
            """Identifica un singolo device"""
            nonlocal identified_count, snmp_count, ssh_count, wmi_count, vendor_count, total_processed
            
            updated = False
            
            # 1. Se non ci sono porte aperte, esegui scansione completa
            open_ports = device.open_ports or []
            
            if not open_ports and device.address:
                try:
                    logger.info(f"[IDENTIFY] {device.address}: No ports cached, running port scan...")
                    scanned_ports = await asyncio.wait_for(
                        probe_service.scan_services(
                            device.address, 
                            agent=None,  # Usa scansione diretta
                            use_agent=False,
                            snmp_communities=snmp_communities_unique
                        ),
                        timeout=30.0  # 30 secondi max per scansione porte
                    )
                    if scanned_ports:
                        open_ports = scanned_ports
                        device.open_ports = open_ports  # Salva nel device
                        updated = True
                        logger.info(f"[IDENTIFY] {device.address}: Found {len([p for p in open_ports if p.get('open')])} open ports")
                except asyncio.TimeoutError:
                    logger.warning(f"[IDENTIFY] {device.address}: Port scan timeout")
                except Exception as e:
                    logger.warning(f"[IDENTIFY] {device.address}: Port scan failed: {e}")
            
            # 2. Analizza porte aperte per determinare protocolli disponibili
            available_protocols = []
            
            port_numbers = {p.get('port') for p in open_ports if p.get('open')}
            if 161 in port_numbers:
                available_protocols.append('snmp')
            if 22 in port_numbers:
                available_protocols.append('ssh')
            if any(p in port_numbers for p in [135, 445, 3389]):
                available_protocols.append('wmi')
            if 8728 in port_numbers:
                available_protocols.append('mikrotik_api')
            
            logger.debug(f"Device {device.address}: available protocols {available_protocols} (ports: {port_numbers})")
            
            # 2. Vendor matching dal MAC
            vendor_suggested_type = None
            vendor_suggested_category = None
            if device.mac_address and device.vendor:
                vendor_info = vendor_service.lookup_vendor_with_type(device.mac_address)
                if vendor_info:
                    vendor_name = vendor_info.get("vendor", "").lower()
                    device_type = vendor_info.get("device_type")
                    category = vendor_info.get("category")
                    
                    # Mapping vendor -> device_type più specifico
                    if "cisco" in vendor_name:
                        vendor_suggested_type = "network"
                        vendor_suggested_category = "switch" if not category else category
                    elif "mikrotik" in vendor_name:
                        vendor_suggested_type = "mikrotik"
                        vendor_suggested_category = "router"
                    elif "hp" in vendor_name or "hewlett" in vendor_name:
                        vendor_suggested_type = "network" if "switch" in vendor_name or "procurve" in vendor_name else "server"
                        vendor_suggested_category = "switch" if "switch" in vendor_name else "server"
                    elif "dell" in vendor_name:
                        vendor_suggested_type = "server" if "poweredge" in vendor_name else "workstation"
                        vendor_suggested_category = "server" if "poweredge" in vendor_name else "workstation"
                    else:
                        vendor_suggested_type = device_type or "other"
                        vendor_suggested_category = category
            
            # 3. Esegui probe attivi in ordine di priorità
            probe_result = None
            identified_by = None
            
            # Verifica se ci sono credenziali SNMP non-default
            has_snmp_creds = any(c != 'public' for c in snmp_communities_unique)
            
            logger.info(f"[IDENTIFY] {device.address}: has_snmp_creds={has_snmp_creds}, communities={snmp_communities_unique}, available_protocols={available_protocols}")
            
            # Prova SNMP prima (più veloce e informativo per network devices)
            # Prova sempre se ci sono credenziali SNMP non-default, anche se la porta 161 non è stata rilevata (UDP vs TCP)
            if (has_snmp_creds or 'snmp' in available_protocols) and snmp_communities_unique:
                logger.info(f"[IDENTIFY] {device.address}: Trying SNMP probe with {len(snmp_communities_unique)} communities")
                for community in snmp_communities_unique:
                    logger.info(f"[IDENTIFY] {device.address}: Probing with community '{community}'")
                    try:
                        # Aggiungi timeout per evitare blocchi
                        result = await asyncio.wait_for(
                            probe_service._probe_snmp(
                                device.address,
                                {
                                    "snmp_community": community,
                                    "snmp_version": "2c",
                                    "snmp_port": 161,
                                }
                            ),
                            timeout=10.0  # 10 secondi max per probe SNMP
                        )
                        logger.info(f"[IDENTIFY] {device.address}: SNMP result success={result.success}")
                        if result.success:
                            probe_result = result
                            identified_by = "probe_snmp"
                            snmp_count += 1
                            logger.info(f"SNMP probe successful for {device.address} with community '{community}'")
                            break
                    except asyncio.TimeoutError:
                        logger.warning(f"SNMP probe timeout for {device.address} with community '{community}'")
                        continue
                    except Exception as e:
                        logger.warning(f"SNMP probe failed for {device.address} with community '{community}': {e}")
                        continue
            else:
                logger.info(f"[IDENTIFY] {device.address}: Skipping SNMP (has_snmp_creds={has_snmp_creds}, snmp in protocols={'snmp' in available_protocols})")
            
            # Prova SSH se SNMP non ha funzionato
            if not probe_result and 'ssh' in available_protocols and credentials_list:
                for cred in credentials_list:
                    if cred.get('username') and (cred.get('password') or cred.get('ssh_private_key')):
                        try:
                            result = await probe_service._probe_ssh(
                                device.address,
                                {
                                    "username": cred['username'],
                                    "password": cred.get('password'),
                                    "ssh_private_key": cred.get('ssh_private_key'),
                                    "ssh_port": cred.get('ssh_port', 22),
                                }
                            )
                            if result.success:
                                probe_result = result
                                identified_by = "probe_ssh"
                                ssh_count += 1
                                logger.info(f"SSH probe successful for {device.address}")
                                break
                        except Exception as e:
                            logger.debug(f"SSH probe failed for {device.address}: {e}")
                            continue
            
            # Prova WMI se SSH non ha funzionato
            if not probe_result and 'wmi' in available_protocols and credentials_list:
                for cred in credentials_list:
                    if cred.get('username') and cred.get('password'):
                        try:
                            result = await probe_service._probe_wmi(
                                device.address,
                                {
                                    "username": cred['username'],
                                    "password": cred['password'],
                                    "domain": cred.get('wmi_domain'),
                                }
                            )
                            if result.success:
                                probe_result = result
                                identified_by = "probe_wmi"
                                wmi_count += 1
                                logger.info(f"WMI probe successful for {device.address}")
                                break
                        except Exception as e:
                            logger.debug(f"WMI probe failed for {device.address}: {e}")
                            continue
            
            # 4. Applica risultati probe o vendor matching
            if probe_result:
                # Usa risultati probe (più accurati)
                extra_info = probe_result.extra_info or {}
                
                # Device type e category - determina da os_family se non specificato
                if probe_result.device_type and probe_result.device_type != "other":
                    device.device_type = probe_result.device_type
                elif probe_result.os_family:
                    # Determina device_type da os_family
                    os_family_lower = probe_result.os_family.lower()
                    if "windows" in os_family_lower:
                        device.device_type = "windows"
                    elif any(x in os_family_lower for x in ["linux", "ubuntu", "debian", "centos", "rhel", "alpine"]):
                        device.device_type = "linux"
                    elif "routeros" in os_family_lower or "mikrotik" in os_family_lower:
                        device.device_type = "mikrotik"
                    elif any(x in os_family_lower for x in ["ios", "ios-xe", "nx-os", "asa"]):
                        device.device_type = "network"
                    elif "esxi" in os_family_lower:
                        device.device_type = "hypervisor"
                    elif any(x in os_family_lower for x in ["qts", "qnap", "synology"]):
                        device.device_type = "nas"
                
                # Category - determina da device_type o os_family se non specificato
                if probe_result.category:
                    device.category = probe_result.category
                elif device.device_type:
                    # Mappa device_type a category
                    if device.device_type == "windows":
                        device.category = "workstation" if not device.category else device.category
                    elif device.device_type == "linux":
                        device.category = "server" if not device.category else device.category
                    elif device.device_type == "mikrotik":
                        device.category = "router" if not device.category else device.category
                    elif device.device_type == "network":
                        device.category = "switch" if not device.category else device.category
                    elif device.device_type == "hypervisor":
                        device.category = "hypervisor" if not device.category else device.category
                    elif device.device_type == "nas":
                        device.category = "storage" if not device.category else device.category
                
                # OS e version
                if probe_result.os_family and not device.os_family:
                    device.os_family = probe_result.os_family
                if probe_result.os_version and not device.os_version:
                    device.os_version = probe_result.os_version
                
                # Hostname
                if probe_result.hostname and not device.hostname:
                    device.hostname = probe_result.hostname
                
                # Model
                if probe_result.model and not device.model:
                    device.model = probe_result.model
                elif extra_info.get("model") and not device.model:
                    device.model = extra_info.get("model")
                elif extra_info.get("entPhysicalModelName") and not device.model:
                    device.model = extra_info.get("entPhysicalModelName")
                
                # Vendor/Manufacturer
                if extra_info.get("manufacturer") and not device.vendor:
                    device.vendor = extra_info.get("manufacturer")
                elif extra_info.get("entPhysicalMfgName") and not device.vendor:
                    device.vendor = extra_info.get("entPhysicalMfgName")
                
                # Serial number
                if extra_info.get("serial_number") and not device.serial_number:
                    device.serial_number = extra_info.get("serial_number")
                elif extra_info.get("entPhysicalSerialNum") and not device.serial_number:
                    device.serial_number = extra_info.get("entPhysicalSerialNum")
                
                # Hardware stats
                if extra_info.get("cpu_cores") and not device.cpu_cores:
                    device.cpu_cores = extra_info.get("cpu_cores")
                if extra_info.get("ram_total_mb") and not device.ram_total_mb:
                    device.ram_total_mb = extra_info.get("ram_total_mb")
                if extra_info.get("disk_total_gb") and not device.disk_total_gb:
                    device.disk_total_gb = extra_info.get("disk_total_gb")
                
                # Platform (per MikroTik)
                if extra_info.get("board_name") and not device.platform:
                    device.platform = extra_info.get("board_name")
                elif extra_info.get("platform") and not device.platform:
                    device.platform = extra_info.get("platform")
                
                if identified_by:
                    device.identified_by = identified_by
                identified_count += 1
                updated = True
            elif vendor_suggested_type:
                # Fallback a vendor matching
                if not device.device_type:
                    device.device_type = vendor_suggested_type
                if vendor_suggested_category and not device.category:
                    device.category = vendor_suggested_category
                device.identified_by = "mac_vendor"
                vendor_count += 1
                identified_count += 1
                updated = True
            
            # 5. Inferenza da porte aperte se ancora non identificato
            if not device.device_type or device.device_type == "other":
                if open_ports:
                    open_port_numbers = {p.get('port') for p in open_ports if p.get('open')}
                    
                    # Windows indicators
                    windows_ports = {135, 139, 445, 3389, 5985, 5986}
                    if open_port_numbers & windows_ports:
                        device.device_type = "windows"
                        device.os_family = device.os_family or "Windows"
                        if 3389 in open_port_numbers:
                            device.category = device.category or "workstation"
                        elif 389 in open_port_numbers or 636 in open_port_numbers:
                            device.category = device.category or "server"  # Domain Controller
                        else:
                            device.category = device.category or "server"
                        if not device.identified_by:
                            device.identified_by = "port_inference"
                        updated = True
                    # Linux/SSH indicators
                    elif 22 in open_port_numbers:
                        device.device_type = "linux"
                        device.os_family = device.os_family or "Linux"
                        if any(p in open_port_numbers for p in [3306, 5432, 27017]):
                            device.category = device.category or "server"  # Database server
                        elif 80 in open_port_numbers or 443 in open_port_numbers:
                            device.category = device.category or "server"  # Web server
                        else:
                            device.category = device.category or "server"
                        if not device.identified_by:
                            device.identified_by = "port_inference"
                        updated = True
                    # Network device indicators
                    elif 161 in open_port_numbers:
                        device.device_type = "network"
                        device.category = device.category or "switch"
                        if not device.identified_by:
                            device.identified_by = "port_inference"
                        updated = True
                    # MikroTik indicators
                    elif 8728 in open_port_numbers:
                        device.device_type = "mikrotik"
                        device.category = device.category or "router"
                        device.os_family = device.os_family or "RouterOS"
                        if not device.identified_by:
                            device.identified_by = "port_inference"
                        updated = True
            
            if updated:
                session.add(device)
                total_processed += 1
        
        # Processa tutti i device in parallelo (limitato)
        semaphore = asyncio.Semaphore(5)  # Max 5 identificazioni parallele
        
        async def identify_with_semaphore(device):
            async with semaphore:
                try:
                    await identify_device(device)
                    return True
                except Exception as e:
                    logger.error(f"Error identifying device {device.address}: {e}")
                    return False
        
        tasks = [identify_with_semaphore(device) for device in devices]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        session.commit()
        
        return {
            "success": True,
            "total_processed": total_processed,
            "identified_count": identified_count,
            "snmp_count": snmp_count,
            "ssh_count": ssh_count,
            "wmi_count": wmi_count,
            "vendor_count": vendor_count,
            "message": f"Identificati {identified_count} device: {snmp_count} SNMP, {ssh_count} SSH, {wmi_count} WMI, {vendor_count} vendor"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error identifying devices: {e}", exc_info=True)
        session.rollback()
        raise HTTPException(status_code=500, detail=f"Errore durante l'identificazione: {str(e)}")
    finally:
        session.close()


@router.post("/{customer_id}/scans/{scan_id}/import")
async def import_discovered_devices(
    customer_id: str,
    scan_id: str,
    request: dict = Body(...),
):
    """
    Importa dispositivi scoperti nell'inventory.
    Crea record InventoryDevice per ogni device selezionato.
    Integra deduplicazione intelligente e tracking fields.
    """
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from ..services.device_merge_service import get_device_merge_service
    from datetime import datetime
    
    device_ids = request.get("device_ids", [])
    if not device_ids:
        raise HTTPException(status_code=400, detail="Nessun device_id fornito")
    
    # Verifica che la scansione appartenga al cliente
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    merge_service = get_device_merge_service()
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        # Carica device da importare (permetti anche re-import di device già importati)
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id,
            DiscoveredDevice.id.in_(device_ids)
        ).all()
        
        if not devices:
            raise HTTPException(status_code=400, detail="Nessun dispositivo trovato")
        
        imported_count = 0
        merged_count = 0
        now = datetime.utcnow()
        
        for discovered_device in devices:
            # Usa servizio merge per trovare duplicati (MAC/IP/hostname)
            duplicates = merge_service.find_duplicates(discovered_device, customer_id, session)
            
            if duplicates:
                # Duplicato trovato - usa il primo (più probabile match)
                existing = duplicates[0]
                
                # Calcola confronto e proposta merge
                merge_proposal = merge_service.propose_merge(existing, discovered_device)
                
                # Determina strategia merge
                merge_strategy = 'skip'  # Default
                
                # Se auto-merge abilitato e nuovo è migliore, esegui merge automatico
                if settings.device_merge_auto_enabled:
                    if merge_proposal['recommendation'] in ['merge', 'overwrite']:
                        merge_strategy = merge_proposal['recommendation']
                else:
                    # Se non auto-merge, usa sempre merge conservativo
                    merge_strategy = 'merge'
                
                # Esegui merge
                merge_service.merge_devices(existing, discovered_device, merge_strategy, session)
                
                # Aggiorna tracking fields
                existing.last_verified_at = now
                existing.verification_count = (existing.verification_count or 0) + 1
                if scan.network_id:
                    existing.last_scan_network_id = scan.network_id
                
                # Se device era marcato per pulizia, resettalo (device è ancora attivo)
                if existing.cleanup_marked_at:
                    existing.cleanup_marked_at = None
                
                merged_count += 1
                logger.info(f"Merged discovered device into existing {existing.id} (strategy: {merge_strategy})")
            else:
                # Nessun duplicato - crea nuovo device
                device_name = discovered_device.identity or discovered_device.hostname or discovered_device.reverse_dns or discovered_device.address
                
                new_device = InventoryDevice(
                    customer_id=customer_id,
                    name=device_name,
                    primary_ip=discovered_device.address,
                    mac_address=discovered_device.mac_address,
                    primary_mac=discovered_device.mac_address,
                    hostname=discovered_device.hostname or discovered_device.identity or discovered_device.reverse_dns,
                    manufacturer=discovered_device.vendor,
                    model=discovered_device.model,
                    os_family=discovered_device.os_family,
                    os_version=discovered_device.os_version,
                    category=discovered_device.category,
                    serial_number=discovered_device.serial_number,
                    open_ports=discovered_device.open_ports,
                    identified_by=discovered_device.identified_by,
                    active=True,
                    monitored=False,
                    status="unknown",
                    # Tracking fields per nuovo device
                    first_seen_at=now,
                    last_verified_at=now,
                    verification_count=1,
                    last_scan_network_id=scan.network_id,
                )
                session.add(new_device)
                logger.info(f"Created new device {new_device.id} from scan")
            
            # Marca device come importato e aggiorna imported_at
            discovered_device.imported = True
            discovered_device.imported_at = now
            imported_count += 1
        
        session.commit()
        
        return {
            "success": True,
            "imported_count": imported_count,
            "merged_count": merged_count,
            "new_count": imported_count - merged_count,
            "total_requested": len(device_ids),
            "message": f"Importati {imported_count} dispositivo/i con successo ({merged_count} merge, {imported_count - merged_count} nuovi)"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error importing devices: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante l'importazione: {e}")
    finally:
        session.close()


@router.delete("/{customer_id}/scans/{scan_id}")
async def delete_scan(customer_id: str, scan_id: str):
    """Elimina una scansione e i suoi dispositivi"""
    from ..models.database import ScanResult, init_db, get_session
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        session.delete(scan)  # Cascade elimina anche i devices
        session.commit()
        
        return {"status": "deleted", "scan_id": scan_id}
    finally:
        session.close()


@router.delete("/{customer_id}/scans")
async def cleanup_old_scans(
    customer_id: str,
    days: int = Query(30, ge=1, le=365, description="Elimina scansioni più vecchie di N giorni"),
    dry_run: Optional[str] = Query("false", description="Se 'true', mostra solo preview senza eliminare")
):
    """Elimina scansioni vecchie per un cliente"""
    from ..models.database import ScanResult, init_db, get_session
    from ..config import get_settings
    from datetime import datetime, timedelta
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Calcola la data di cutoff
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Trova scansioni vecchie
        old_scans = session.query(ScanResult).filter(
            ScanResult.customer_id == customer_id,
            ScanResult.created_at < cutoff_date
        ).all()
        
        scan_count = len(old_scans)
        
        if scan_count == 0:
            return {
                "status": "no_scans",
                "message": f"Nessuna scansione trovata più vecchia di {days} giorni",
                "deleted_count": 0
            }
        
        # Converti dry_run da stringa a bool
        is_dry_run = str(dry_run).lower() in ('true', '1', 'yes')
        
        if is_dry_run:
            # Preview mode - restituisci solo informazioni
            scan_ids = [scan.id for scan in old_scans]
            return {
                "status": "preview",
                "message": f"Trovate {scan_count} scansioni più vecchie di {days} giorni",
                "scan_count": scan_count,
                "scan_ids": scan_ids[:10],  # Mostra solo i primi 10
                "cutoff_date": cutoff_date.isoformat()
            }
        
        # Elimina scansioni (cascade elimina anche i discovered_devices)
        deleted_count = 0
        for scan in old_scans:
            session.delete(scan)
            deleted_count += 1
        
        session.commit()
        
        return {
            "status": "deleted",
            "message": f"Eliminate {deleted_count} scansioni più vecchie di {days} giorni",
            "deleted_count": deleted_count,
            "cutoff_date": cutoff_date.isoformat()
        }
    except Exception as e:
        session.rollback()
        logger.error(f"Error cleaning up old scans: {e}")
        raise HTTPException(status_code=500, detail=f"Errore durante la pulizia: {str(e)}")
    finally:
        session.close()


# ==========================================
# DEVICE DUPLICATES MANAGEMENT ENDPOINTS
# ==========================================

@router.post("/{customer_id}/scans/{scan_id}/check-duplicates")
async def check_duplicates(
    customer_id: str,
    scan_id: str,
    request: dict = Body(...),
):
    """
    Verifica duplicati prima dell'import.
    Restituisce lista device con proposte merge.
    """
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..services.device_merge_service import get_device_merge_service
    from ..config import get_settings
    
    device_ids = request.get("device_ids", [])
    if not device_ids:
        raise HTTPException(status_code=400, detail="Nessun device_id fornito")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    merge_service = get_device_merge_service()
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        devices = session.query(DiscoveredDevice).filter(
            DiscoveredDevice.scan_id == scan_id,
            DiscoveredDevice.id.in_(device_ids)
        ).all()
        
        duplicates_found = []
        
        for discovered_device in devices:
            duplicates = merge_service.find_duplicates(discovered_device, customer_id, session)
            
            if duplicates:
                existing = duplicates[0]
                merge_proposal = merge_service.propose_merge(existing, discovered_device)
                
                duplicates_found.append({
                    "discovered_device_id": discovered_device.id,
                    "discovered_device": {
                        "address": discovered_device.address,
                        "mac_address": discovered_device.mac_address,
                        "hostname": discovered_device.hostname,
                        "device_type": discovered_device.device_type,
                    },
                    "existing_device_id": existing.id,
                    "existing_device": {
                        "id": existing.id,
                        "name": existing.name,
                        "primary_ip": existing.primary_ip,
                        "mac_address": existing.mac_address,
                        "hostname": existing.hostname,
                        "device_type": existing.device_type,
                    },
                    "merge_proposal": merge_proposal,
                })
        
        return {
            "success": True,
            "total_checked": len(devices),
            "duplicates_found": len(duplicates_found),
            "duplicates": duplicates_found,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error checking duplicates: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante verifica duplicati: {e}")
    finally:
        session.close()


@router.post("/{customer_id}/scans/{scan_id}/import-with-merge")
async def import_with_merge(
    customer_id: str,
    scan_id: str,
    request: dict = Body(...),
):
    """
    Importa con gestione merge esplicita.
    Body: {"devices": [{"device_id": "...", "merge_strategy": "merge|skip|overwrite"}]}
    """
    from ..models.database import ScanResult, DiscoveredDevice, init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..services.device_merge_service import get_device_merge_service
    from ..config import get_settings
    from datetime import datetime
    
    devices_config = request.get("devices", [])
    if not devices_config:
        raise HTTPException(status_code=400, detail="Nessun device configurato")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    merge_service = get_device_merge_service()
    
    try:
        scan = session.query(ScanResult).filter(
            ScanResult.id == scan_id,
            ScanResult.customer_id == customer_id
        ).first()
        
        if not scan:
            raise HTTPException(status_code=404, detail="Scansione non trovata")
        
        imported_count = 0
        merged_count = 0
        now = datetime.utcnow()
        
        for device_config in devices_config:
            device_id = device_config.get("device_id")
            merge_strategy = device_config.get("merge_strategy", "merge")
            
            if merge_strategy not in ["merge", "skip", "overwrite"]:
                raise HTTPException(status_code=400, detail=f"Strategia merge non valida: {merge_strategy}")
            
            discovered_device = session.query(DiscoveredDevice).filter(
                DiscoveredDevice.scan_id == scan_id,
                DiscoveredDevice.id == device_id
            ).first()
            
            if not discovered_device:
                continue
            
            duplicates = merge_service.find_duplicates(discovered_device, customer_id, session)
            
            if duplicates:
                existing = duplicates[0]
                merge_service.merge_devices(existing, discovered_device, merge_strategy, session)
                
                # Aggiorna tracking
                existing.last_verified_at = now
                existing.verification_count = (existing.verification_count or 0) + 1
                if scan.network_id:
                    existing.last_scan_network_id = scan.network_id
                if existing.cleanup_marked_at:
                    existing.cleanup_marked_at = None
                
                merged_count += 1
            else:
                # Crea nuovo device
                device_name = discovered_device.identity or discovered_device.hostname or discovered_device.reverse_dns or discovered_device.address
                
                new_device = InventoryDevice(
                    customer_id=customer_id,
                    name=device_name,
                    primary_ip=discovered_device.address,
                    mac_address=discovered_device.mac_address,
                    primary_mac=discovered_device.mac_address,
                    hostname=discovered_device.hostname or discovered_device.identity or discovered_device.reverse_dns,
                    manufacturer=discovered_device.vendor,
                    model=discovered_device.model,
                    os_family=discovered_device.os_family,
                    os_version=discovered_device.os_version,
                    category=discovered_device.category,
                    serial_number=discovered_device.serial_number,
                    open_ports=discovered_device.open_ports,
                    identified_by=discovered_device.identified_by,
                    active=True,
                    monitored=False,
                    status="unknown",
                    first_seen_at=now,
                    last_verified_at=now,
                    verification_count=1,
                    last_scan_network_id=scan.network_id,
                )
                session.add(new_device)
            
            discovered_device.imported = True
            discovered_device.imported_at = now
            imported_count += 1
        
        session.commit()
        
        return {
            "success": True,
            "imported_count": imported_count,
            "merged_count": merged_count,
            "new_count": imported_count - merged_count,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error importing with merge: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante importazione: {e}")
    finally:
        session.close()


@router.get("/{customer_id}/devices/duplicates")
async def list_duplicates(
    customer_id: str,
    threshold: float = Query(0.0, ge=0.0, le=1.0, description="Score similarity minimo"),
):
    """
    Lista device potenzialmente duplicati (stesso MAC/IP/hostname ma ID diverso).
    """
    from ..models.inventory import InventoryDevice
    from ..models.database import init_db, get_session
    from ..config import get_settings
    from sqlalchemy import or_, and_
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Trova device con stesso MAC, IP o hostname
        devices = session.query(InventoryDevice).filter(
            InventoryDevice.customer_id == customer_id,
            InventoryDevice.active == True
        ).all()
        
        duplicates_groups = []
        processed_ids = set()
        
        for device in devices:
            if device.id in processed_ids:
                continue
            
            # Cerca altri device con stesso MAC, IP o hostname
            matching_devices = []
            
            if device.mac_address:
                matches = session.query(InventoryDevice).filter(
                    InventoryDevice.customer_id == customer_id,
                    InventoryDevice.active == True,
                    InventoryDevice.mac_address == device.mac_address,
                    InventoryDevice.id != device.id
                ).all()
                matching_devices.extend(matches)
            
            if device.primary_ip:
                matches = session.query(InventoryDevice).filter(
                    InventoryDevice.customer_id == customer_id,
                    InventoryDevice.active == True,
                    InventoryDevice.primary_ip == device.primary_ip,
                    InventoryDevice.id != device.id,
                    ~InventoryDevice.id.in_([d.id for d in matching_devices])
                ).all()
                matching_devices.extend(matches)
            
            if device.hostname:
                matches = session.query(InventoryDevice).filter(
                    InventoryDevice.customer_id == customer_id,
                    InventoryDevice.active == True,
                    InventoryDevice.hostname == device.hostname,
                    InventoryDevice.id != device.id,
                    ~InventoryDevice.id.in_([d.id for d in matching_devices])
                ).all()
                matching_devices.extend(matches)
            
            if matching_devices:
                group = [device] + matching_devices
                duplicates_groups.append({
                    "devices": [
                        {
                            "id": d.id,
                            "name": d.name,
                            "primary_ip": d.primary_ip,
                            "mac_address": d.mac_address,
                            "hostname": d.hostname,
                            "device_type": d.device_type,
                            "last_verified_at": d.last_verified_at.isoformat() if d.last_verified_at else None,
                            "verification_count": d.verification_count,
                        }
                        for d in group
                    ],
                    "count": len(group),
                })
                
                for d in group:
                    processed_ids.add(d.id)
        
        return {
            "success": True,
            "duplicate_groups": duplicates_groups,
            "total_groups": len(duplicates_groups),
        }
        
    except Exception as e:
        logger.error(f"Error listing duplicates: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante ricerca duplicati: {e}")
    finally:
        session.close()


@router.post("/{customer_id}/devices/{device_id}/merge")
async def merge_devices_manual(
    customer_id: str,
    device_id: str,
    request: dict = Body(...),
):
    """
    Merge manuale di due device.
    Body: {"target_device_id": "...", "merge_strategy": "merge|overwrite"}
    """
    from ..models.inventory import InventoryDevice
    from ..models.database import init_db, get_session
    from ..services.device_merge_service import get_device_merge_service
    from ..config import get_settings
    
    target_device_id = request.get("target_device_id")
    merge_strategy = request.get("merge_strategy", "merge")
    
    if not target_device_id:
        raise HTTPException(status_code=400, detail="target_device_id richiesto")
    
    if merge_strategy not in ["merge", "overwrite"]:
        raise HTTPException(status_code=400, detail="merge_strategy deve essere 'merge' o 'overwrite'")
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    merge_service = get_device_merge_service()
    
    try:
        source_device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id,
            InventoryDevice.active == True
        ).first()
        
        target_device = session.query(InventoryDevice).filter(
            InventoryDevice.id == target_device_id,
            InventoryDevice.customer_id == customer_id,
            InventoryDevice.active == True
        ).first()
        
        if not source_device or not target_device:
            raise HTTPException(status_code=404, detail="Device non trovato")
        
        if source_device.id == target_device.id:
            raise HTTPException(status_code=400, detail="Non puoi fare merge di un device con se stesso")
        
        # Crea un DiscoveredDevice temporaneo dal source per usare il servizio merge
        from ..models.database import DiscoveredDevice
        
        # Usa merge service per combinare i dati
        # Per merge manuale, copiamo i dati dal source al target
        if merge_strategy == "overwrite":
            # Sostituisci campi target con source dove source ha valori
            for field in ['hostname', 'manufacturer', 'model', 'os_family', 'os_version', 
                         'serial_number', 'cpu_cores', 'ram_total_gb', 'open_ports']:
                source_value = getattr(source_device, field, None)
                if source_value:
                    setattr(target_device, field, source_value)
        else:  # merge
            # Combina: preferisci valori non-null, ma non sovrascrivere se target ha già valore
            for field in ['hostname', 'manufacturer', 'model', 'os_family', 'os_version', 
                         'serial_number', 'cpu_cores', 'ram_total_gb']:
                source_value = getattr(source_device, field, None)
                target_value = getattr(target_device, field, None)
                if source_value and not target_value:
                    setattr(target_device, field, source_value)
            
            # Gestione speciale per open_ports
            if source_device.open_ports and target_device.open_ports:
                existing_ports = {(p.get('port'), p.get('protocol')) for p in target_device.open_ports}
                new_ports = [p for p in source_device.open_ports if (p.get('port'), p.get('protocol')) not in existing_ports]
                if new_ports:
                    target_device.open_ports = target_device.open_ports + new_ports
            elif source_device.open_ports and not target_device.open_ports:
                target_device.open_ports = source_device.open_ports
        
        # Marca source come non attivo
        source_device.active = False
        
        # Aggiorna tracking su target
        from datetime import datetime
        target_device.last_verified_at = datetime.utcnow()
        target_device.verification_count = (target_device.verification_count or 0) + 1
        
        session.commit()
        
        return {
            "success": True,
            "merged_device_id": target_device.id,
            "source_device_id": source_device.id,
            "message": f"Device {source_device.id} mergiato in {target_device.id}",
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error merging devices: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante merge: {e}")
    finally:
        session.close()


# ==========================================
# DEVICE CLEANUP ENDPOINTS
# ==========================================

@router.post("/{customer_id}/devices/cleanup")
async def cleanup_devices(
    customer_id: str,
    days_threshold: int = Query(90, ge=1, description="Giorni senza verifica prima di pulizia"),
    network_id: Optional[str] = Query(None, description="ID rete specifica (opzionale)"),
    dry_run: bool = Query(True, description="Se True, solo preview senza modifiche"),
):
    """
    Esegue pulizia device non più presenti.
    """
    from ..models.database import init_db, get_session
    from ..services.device_cleanup_service import get_device_cleanup_service
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    cleanup_service = get_device_cleanup_service()
    
    try:
        # Step 1: Marca device per pulizia
        marked_count = cleanup_service.mark_devices_for_cleanup(
            customer_id=customer_id,
            network_id=network_id,
            days_threshold=days_threshold,
            session=session
        )
        
        # Step 2: Pulisci device marcati (se non dry_run)
        cleanup_result = cleanup_service.cleanup_marked_devices(
            customer_id=customer_id,
            dry_run=dry_run,
            session=session
        )
        
        return {
            "success": True,
            "dry_run": dry_run,
            "marked_count": marked_count,
            "cleanup_result": cleanup_result,
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up devices: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante pulizia: {e}")
    finally:
        session.close()


@router.get("/{customer_id}/devices/cleanup-preview")
async def cleanup_preview(
    customer_id: str,
    days_threshold: int = Query(90, ge=1, description="Giorni senza verifica"),
    network_id: Optional[str] = Query(None, description="ID rete specifica (opzionale)"),
):
    """
    Preview di device da pulire.
    """
    from ..models.database import init_db, get_session
    from ..services.device_cleanup_service import get_device_cleanup_service
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    cleanup_service = get_device_cleanup_service()
    
    try:
        preview = cleanup_service.get_cleanup_preview(
            customer_id=customer_id,
            days_threshold=days_threshold,
            network_id=network_id,
            session=session
        )
        
        return {
            "success": True,
            **preview,
        }
        
    except Exception as e:
        logger.error(f"Error getting cleanup preview: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Errore durante preview: {e}")
    finally:
        session.close()
