"""
DaDude - HP/Aruba Router Endpoints
API per gestione switch HP ProCurve/Aruba remoti
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from pydantic import BaseModel
from loguru import logger


router = APIRouter(prefix="/hp-aruba", tags=["HP/Aruba"])


# ==========================================
# SCHEMAS
# ==========================================

class HPArubaTestConnection(BaseModel):
    host: str
    username: str
    password: str
    port: int = 22


# ==========================================
# CREDENTIAL OPERATIONS (via Credential Assignment)
# ==========================================

@router.get("/credentials/{credential_id}/test")
async def test_hp_aruba_connection(credential_id: str):
    """Testa connessione SSH a switch HP/Aruba"""
    from ..services.customer_service import get_customer_service
    from ..services.hp_aruba_collector import HPArubaCollector
    
    customer_service = get_customer_service()
    credential = customer_service.get_credential(credential_id, include_secrets=True)
    
    if not credential:
        raise HTTPException(status_code=404, detail="Credenziale non trovata")
    
    if credential.credential_type not in ["ssh", "device"]:
        raise HTTPException(status_code=400, detail="Credenziale non supporta SSH")
    
    collector = HPArubaCollector()
    result = collector.test_connection(
        host=credential.address or "",
        username=credential.username or "admin",
        password=credential.password or "",
        port=credential.port or 22,
    )
    
    return result


@router.get("/credentials/{credential_id}/system-info")
async def get_hp_aruba_system_info(credential_id: str):
    """Ottiene informazioni sistema dello switch"""
    from ..services.customer_service import get_customer_service
    from ..services.hp_aruba_collector import HPArubaCollector
    
    customer_service = get_customer_service()
    credential = customer_service.get_credential(credential_id, include_secrets=True)
    
    if not credential:
        raise HTTPException(status_code=404, detail="Credenziale non trovata")
    
    collector = HPArubaCollector()
    result = collector.test_connection(
        host=credential.address or "",
        username=credential.username or "admin",
        password=credential.password or "",
        port=credential.port or 22,
    )
    
    return result


@router.get("/credentials/{credential_id}/switch-info")
async def get_hp_aruba_switch_info(credential_id: str):
    """Raccolta completa informazioni switch (interfacce, VLAN, LLDP, PoE)"""
    from ..services.customer_service import get_customer_service
    from ..services.hp_aruba_collector import HPArubaCollector
    
    customer_service = get_customer_service()
    credential = customer_service.get_credential(credential_id, include_secrets=True)
    
    if not credential:
        raise HTTPException(status_code=404, detail="Credenziale non trovata")
    
    collector = HPArubaCollector()
    result = collector.collect_switch_info(
        host=credential.address or "",
        username=credential.username or "admin",
        password=credential.password or "",
        port=credential.port or 22,
    )
    
    return result


@router.post("/credentials/{credential_id}/backup")
async def backup_hp_aruba_config(
    credential_id: str,
    backup_type: str = Query("export", description="Tipo backup: export, binary, both"),
):
    """Esegue backup configurazione switch"""
    from ..services.customer_service import get_customer_service
    from ..services.hp_aruba_collector import HPArubaCollector
    import os
    
    customer_service = get_customer_service()
    credential = customer_service.get_credential(credential_id, include_secrets=True)
    
    if not credential:
        raise HTTPException(status_code=404, detail="Credenziale non trovata")
    
    # Determina customer per path backup
    customer = None
    if credential.customer_id:
        customer = customer_service.get_customer(credential.customer_id)
    
    backup_path = None
    if customer:
        backup_base = os.getenv('BACKUP_PATH', './backups')
        backup_path = os.path.join(backup_base, customer.code or "default")
    
    collector = HPArubaCollector()
    result = collector.backup_configuration(
        host=credential.address or "",
        username=credential.username or "admin",
        password=credential.password or "",
        port=credential.port or 22,
        backup_path=backup_path,
    )
    
    return result


# ==========================================
# DIRECT OPERATIONS (con parametri)
# ==========================================

@router.post("/test-connection")
async def test_connection_direct(request: HPArubaTestConnection):
    """Testa connessione SSH diretta a switch HP/Aruba"""
    from ..services.hp_aruba_collector import HPArubaCollector
    
    collector = HPArubaCollector()
    result = collector.test_connection(
        host=request.host,
        username=request.username,
        password=request.password,
        port=request.port,
    )
    
    return result


@router.post("/switch-info")
async def get_switch_info_direct(request: HPArubaTestConnection):
    """Raccolta informazioni switch con credenziali dirette"""
    from ..services.hp_aruba_collector import HPArubaCollector
    
    collector = HPArubaCollector()
    result = collector.collect_switch_info(
        host=request.host,
        username=request.username,
        password=request.password,
        port=request.port,
    )
    
    return result


@router.post("/backup")
async def backup_config_direct(
    request: HPArubaTestConnection,
    backup_type: str = Query("export", description="Tipo backup"),
    backup_path: Optional[str] = Query(None, description="Path backup (opzionale)"),
):
    """Backup configurazione con credenziali dirette"""
    from ..services.hp_aruba_collector import HPArubaCollector
    
    collector = HPArubaCollector()
    result = collector.backup_configuration(
        host=request.host,
        username=request.username,
        password=request.password,
        port=request.port,
        backup_path=backup_path,
    )
    
    return result

