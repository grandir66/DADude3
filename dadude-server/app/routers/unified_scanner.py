"""
DaDude - Unified Scanner Router
v3.0.0: Endpoint per scanner multi-protocollo unificato

Questo router gestisce le scansioni avanzate che combinano:
- SNMP per device di rete
- SSH per Linux/NAS/Proxmox
- WinRM per Windows
"""
from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from loguru import logger
from datetime import datetime
import uuid

from ..services.unified_scanner_service import (
    get_unified_scanner_service,
    UnifiedScanRequest,
    UnifiedScanResult,
    Protocol as ScanProtocol
)
from ..services.agent_service import get_agent_service
from ..services.customer_service import get_customer_service
from ..config import get_settings

router = APIRouter(prefix="/unified-scanner", tags=["Unified Scanner"])


class UnifiedScanRequestModel(BaseModel):
    """Richiesta scansione unificata"""
    device_id: str = Field(..., description="ID dispositivo da scansionare")
    target_address: str = Field(..., description="IP o hostname del target")
    customer_id: str = Field(..., description="ID cliente")
    agent_id: Optional[str] = Field(None, description="ID agent da usare (auto se non specificato)")
    protocols: List[str] = Field(
        default=["auto"],
        description="Protocolli da usare: auto, snmp, ssh, winrm"
    )
    credential_id: Optional[str] = Field(None, description="ID credenziale specifica")
    timeout: int = Field(120, ge=10, le=600, description="Timeout in secondi")
    include_software: bool = Field(True, description="Includi lista software installato")
    include_services: bool = Field(True, description="Includi lista servizi")
    include_users: bool = Field(False, description="Includi lista utenti")
    auto_save: bool = Field(False, description="Salva automaticamente i risultati nel database dopo la scansione")


class SaveToInventoryRequest(BaseModel):
    """Richiesta salvataggio in inventario"""
    device_id: str
    update_existing: bool = Field(True, description="Aggiorna dispositivo esistente")


@router.post("/scan")
async def unified_scan(request: UnifiedScanRequestModel):
    """
    Esegue scansione unificata multi-protocollo su un dispositivo.
    
    Questa scansione:
    1. Identifica protocolli disponibili in base alle porte aperte
    2. Recupera credenziali (device > cliente > richiesta popup)
    3. Esegue scansione con tutti i protocolli funzionanti
    4. Restituisce dati unificati in formato standardizzato
    
    Protocolli supportati:
    - **auto**: Determina automaticamente in base alle porte
    - **snmp**: Per switch, router, AP, firewall
    - **ssh**: Per Linux, Synology, QNAP, Proxmox
    - **winrm**: Per Windows Server/Client
    
    Returns:
        UnifiedScanResult con tutti i dati raccolti
    """
    logger.info(f"Unified scan request for {request.target_address} (device: {request.device_id})")
    
    try:
        scanner = get_unified_scanner_service()
        agent_service = get_agent_service()
        customer_service = get_customer_service()
        
        # Recupera TUTTE le credenziali disponibili per ogni protocollo
        credentials_list = await _get_all_credentials_for_scan(
            request.customer_id,
            request.device_id,
            request.credential_id,
            request.protocols
        )
        
        # Determina agent
        agent_id = request.agent_id
        if not agent_id:
            # Trova agent per questo cliente
            agents = customer_service.list_agents(
                customer_id=request.customer_id,
                active_only=True
            )
            if agents:
                # Preferisci agent Docker
                docker_agents = [a for a in agents if a.agent_type == "docker"]
                agent_id = docker_agents[0].id if docker_agents else agents[0].id
        
        if not agent_id:
            raise HTTPException(
                status_code=400,
                detail="No agent available for this customer"
            )
        
        # Crea richiesta con lista credenziali
        scan_request = UnifiedScanRequest(
            device_id=request.device_id,
            target_address=request.target_address,
            customer_id=request.customer_id,
            agent_id=agent_id,
            protocols=request.protocols,
            credentials_list=credentials_list,  # Nuova: lista credenziali per tipo
            timeout=request.timeout,
            include_software=request.include_software,
            include_services=request.include_services,
            include_users=request.include_users,
        )
        
        # Esegui scansione
        result = await scanner.scan_device(
            scan_request,
            agent_service=agent_service
        )
        
        # Se auto_save è abilitato, salva automaticamente nel database
        save_summary = None
        if request.auto_save:
            try:
                from ..models.database import init_db, get_session
                settings = get_settings()
                engine = init_db(settings.database_url)
                session = get_session(engine)
                try:
                    save_summary = await _save_unified_scan_to_inventory(
                        request.device_id,
                        result,
                        session
                    )
                    session.commit()
                    logger.info(f"Auto-saved unified scan result for device {request.device_id}: {save_summary}")
                except Exception as e:
                    session.rollback()
                    logger.error(f"Error auto-saving unified scan result: {e}", exc_info=True)
                    # Non fallisce la richiesta se il salvataggio fallisce
                finally:
                    session.close()
            except Exception as e:
                logger.error(f"Error setting up auto-save: {e}", exc_info=True)
        
        response = {
            "success": result.status in ["success", "partial"],
            "result": result.to_dict()
        }
        
        if save_summary:
            response["save_summary"] = save_summary
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unified scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results/{device_id}")
async def get_scan_result(device_id: str):
    """
    Ottiene risultato scansione dalla cache.
    
    Args:
        device_id: ID dispositivo
    
    Returns:
        Ultimo risultato scansione se disponibile
    """
    scanner = get_unified_scanner_service()
    result = scanner.get_cached_result(device_id)
    
    if result:
        return {
            "success": True,
            "result": result.to_dict()
        }
    else:
        return {
            "success": False,
            "error": "No cached result found for this device"
        }


def _parse_size_string(size_str: str) -> int:
    """Converte stringa size (es: '8.0T', '500G', '100M') in bytes."""
    if not size_str:
        return 0
    try:
        size_str = str(size_str).strip().upper()
        multipliers = {'T': 1024**4, 'G': 1024**3, 'M': 1024**2, 'K': 1024, 'B': 1}
        for suffix, mult in multipliers.items():
            if size_str.endswith(suffix):
                num = float(size_str[:-1].replace(',', '.'))
                return int(num * mult)
        return int(float(size_str))
    except (ValueError, TypeError):
        return 0

async def _save_unified_scan_to_inventory(
    device_id: str,
    scan_result: UnifiedScanResult,
    session
) -> Dict[str, Any]:
    """
    Funzione helper per salvare dati unified scan nell'inventario.
    
    Gestisce:
    - Campi base del dispositivo
    - Dati vendor-specific in custom_fields
    - Tabelle relazionali (LLDPNeighbor, CDPNeighbor, NetworkInterface)
    - Tabelle vendor-specific (ProxmoxHost, LinuxDetails, MikroTikDetails, NetworkDeviceDetails)
    
    IMPORTANTE: Usa logica "merge intelligente" - aggiorna SEMPRE se il nuovo dato
    è presente e non vuoto, sovrascrivendo valori esistenti meno completi.
    
    Returns:
        Dict con summary dei dati salvati
    """
    from ..models.inventory import (
        InventoryDevice, LLDPNeighbor, CDPNeighbor, NetworkInterface,
        ProxmoxHost, ProxmoxVM, ProxmoxStorage,
        LinuxDetails, MikroTikDetails, NetworkDeviceDetails
    )
    
    summary = {
        "device_updated": False,
        "fields_updated": [],
        "lldp_neighbors_saved": 0,
        "cdp_neighbors_saved": 0,
        "interfaces_saved": 0,
        "custom_fields_updated": False,
    }
    
    def should_update(new_value, old_value) -> bool:
        """
        Determina se aggiornare un campo.
        Aggiorna se:
        - new_value è presente e non vuoto
        - old_value è vuoto o è un IP address (preferiamo nomi reali)
        - new_value è diverso da old_value (per stringhe)
        - new_value è maggiore di 0 (per numeri)
        """
        import re
        if new_value is None:
            return False
        if isinstance(new_value, str):
            if not new_value.strip():
                return False
            if not old_value:
                return True
            old_str = str(old_value or "")
            # Se old_value sembra un IP, aggiorna sempre con un nome vero
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, old_str):
                return True
            # Aggiorna se il nuovo valore è diverso
            return new_value.strip() != old_str.strip()
        if isinstance(new_value, (int, float)):
            return new_value > 0
        return bool(new_value)
    
    def update_field(device, field_name: str, new_value, summary: dict, force: bool = False):
        """Aggiorna un campo se il nuovo valore è più completo (o force=True)"""
        old_value = getattr(device, field_name, None)
        if force or should_update(new_value, old_value):
            setattr(device, field_name, new_value)
            summary["fields_updated"].append(field_name)
            return True
        return False
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found in inventory")
        
        logger.info(f"[SAVE_UNIFIED] Saving unified scan data to device {device_id} ({device.name})")
        
        # 1. Aggiorna campi base del dispositivo - MERGE INTELLIGENTE
        # Hostname -> name E hostname
        if scan_result.hostname:
            update_field(device, "name", scan_result.hostname, summary)
            update_field(device, "hostname", scan_result.hostname, summary)
        
        # OS info - forza aggiornamento per evitare che "DSM" venga ignorato perché più corto di "Windows"
        if scan_result.os_name:
            logger.info(f"[SAVE_UNIFIED] Setting os_family from os_name: '{scan_result.os_name}' (was: '{device.os_family}')")
            update_field(device, "os_family", scan_result.os_name, summary, force=True)  # os_family per compatibilità
        if scan_result.os_version:
            update_field(device, "os_version", scan_result.os_version, summary)
        
        # Manufacturer, Model, Serial
        update_field(device, "manufacturer", scan_result.manufacturer, summary)
        update_field(device, "model", scan_result.model, summary)
        
        # Serial number - forza update se il nuovo seriale è valido (non un placeholder come "synology_xxx")
        new_serial = scan_result.serial_number
        if new_serial and not new_serial.startswith("synology_") and not new_serial.startswith("qnap_"):
            # Se il vecchio seriale era un placeholder, forza l'aggiornamento
            old_serial = getattr(device, "serial_number", "") or ""
            force_serial = old_serial.startswith("synology_") or old_serial.startswith("qnap_") or not old_serial
            update_field(device, "serial_number", new_serial, summary, force=force_serial or (new_serial != old_serial))
        else:
            update_field(device, "serial_number", scan_result.serial_number, summary)
        
        # Device type - solo se significativo (non "unknown")
        if scan_result.device_type and scan_result.device_type != "unknown":
            update_field(device, "device_type", scan_result.device_type, summary)
        
        # CPU
        update_field(device, "cpu_model", scan_result.cpu_model, summary)
        if scan_result.cpu_cores and scan_result.cpu_cores > 0:
            update_field(device, "cpu_cores", scan_result.cpu_cores, summary)
        if scan_result.cpu_threads and scan_result.cpu_threads > 0:
            update_field(device, "cpu_threads", scan_result.cpu_threads, summary)
        
        # RAM
        if scan_result.ram_total_gb and scan_result.ram_total_gb > 0:
            update_field(device, "ram_total_gb", round(scan_result.ram_total_gb, 2), summary)
        
        # Disk - aggiorna sempre se abbiamo dati validi
        if scan_result.disk_total_gb and scan_result.disk_total_gb > 0:
            # Usa custom_fields per disk_total_gb e disk_free_gb se non esistono nel modello base
            if hasattr(device, "disk_total_gb"):
                update_field(device, "disk_total_gb", round(scan_result.disk_total_gb, 2), summary)
            if hasattr(device, "disk_free_gb") and scan_result.disk_free_gb is not None:
                update_field(device, "disk_free_gb", round(scan_result.disk_free_gb, 2), summary)
        
        # Firmware version - campo importante spesso mancante
        if scan_result.firmware_version:
            # Prova prima il campo diretto, poi os_build come fallback
            if hasattr(device, "firmware_version"):
                update_field(device, "firmware_version", scan_result.firmware_version, summary)
            if hasattr(device, "os_build"):
                update_field(device, "os_build", scan_result.firmware_version, summary)
        
        # Primary IP e MAC - aggiorna se trovati e validi
        if scan_result.primary_ip and scan_result.primary_ip != device.primary_ip:
            # Solo se non abbiamo già un IP primario o se quello nuovo è diverso e valido
            if not device.primary_ip or scan_result.primary_ip.count('.') == 3:
                update_field(device, "primary_ip", scan_result.primary_ip, summary)
        
        if scan_result.primary_mac and len(scan_result.primary_mac) >= 12:
            update_field(device, "primary_mac", scan_result.primary_mac.upper(), summary)
            update_field(device, "mac_address", scan_result.primary_mac.upper(), summary)
        
        # Uptime - salva in custom_fields se presente
        if scan_result.uptime:
            if not device.custom_fields:
                device.custom_fields = {}
            device.custom_fields["uptime"] = scan_result.uptime
            summary["fields_updated"].append("uptime")
        
        # Open ports - salva in campo apposito se presente
        if scan_result.open_ports and hasattr(device, "open_ports"):
            device.open_ports = scan_result.open_ports
            summary["fields_updated"].append("open_ports")
        
        # Timestamps
        device.last_seen = datetime.utcnow()
        device.last_scan = datetime.utcnow()
        
        logger.info(f"[SAVE_UNIFIED] Updated {len(summary['fields_updated'])} fields: {summary['fields_updated']}")
        
        summary["device_updated"] = True
        
        # 2. Aggiorna custom_fields con dati vendor-specific
        # IMPORTANTE: SQLAlchemy non traccia modifiche in-place ai dict JSON
        # Dobbiamo creare un nuovo dict o usare flag_modified
        from sqlalchemy.orm.attributes import flag_modified
        
        if not device.custom_fields:
            device.custom_fields = {}
        
        # Crea copia per evitare problemi SQLAlchemy con mutazioni in-place
        custom_fields = dict(device.custom_fields)
        custom_fields_changed = False
        
        # Merge con dati esistenti (non sovrascrive completamente)
        if scan_result.routing_table:
            custom_fields["routing_table"] = scan_result.routing_table
            custom_fields_changed = True
            logger.debug(f"[SAVE_UNIFIED] Saving {len(scan_result.routing_table)} routing entries")
        
        if scan_result.arp_table:
            custom_fields["arp_table"] = scan_result.arp_table
            custom_fields_changed = True
            logger.debug(f"[SAVE_UNIFIED] Saving {len(scan_result.arp_table)} ARP entries")
        
        if scan_result.dhcp_leases:
            custom_fields["dhcp_leases"] = scan_result.dhcp_leases
            custom_fields_changed = True
        
        if scan_result.vlan_info:
            custom_fields["vlan_info"] = scan_result.vlan_info
            custom_fields_changed = True
        
        if scan_result.firewall_rules_count:
            custom_fields["firewall_rules_count"] = scan_result.firewall_rules_count
            custom_fields_changed = True
        
        # Assegna il nuovo dict e marca come modificato
        if custom_fields_changed:
            device.custom_fields = custom_fields
            flag_modified(device, "custom_fields")
        
        summary["custom_fields_updated"] = custom_fields_changed
        
        # 3. Salva LLDP neighbors nella tabella relazionale
        if scan_result.lldp_neighbors:
            try:
                # Elimina vecchi neighbor per questo device
                session.query(LLDPNeighbor).filter(
                    LLDPNeighbor.device_id == device_id
                ).delete()
                
                for neighbor_data in scan_result.lldp_neighbors:
                    local_interface = neighbor_data.get("local_interface", "")
                    remote_device_name = neighbor_data.get("remote_device_name") or neighbor_data.get("identity", "")
                    remote_interface = neighbor_data.get("remote_interface") or neighbor_data.get("remote_port", "")
                    remote_mac = neighbor_data.get("remote_mac") or neighbor_data.get("mac_address", "")
                    remote_ip = neighbor_data.get("remote_ip") or neighbor_data.get("ip_address", "")
                    chassis_id = neighbor_data.get("chassis_id") or neighbor_data.get("mac_address", "")
                    
                    if local_interface and remote_device_name:
                        lldp = LLDPNeighbor(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            local_interface=local_interface,
                            remote_device_name=remote_device_name,
                            remote_device_description=neighbor_data.get("remote_device_description") or neighbor_data.get("platform", ""),
                            remote_port=remote_interface,
                            remote_mac=remote_mac,
                            remote_ip=remote_ip,
                            chassis_id=chassis_id,
                            chassis_id_type=neighbor_data.get("chassis_id_type", ""),
                            capabilities=neighbor_data.get("capabilities"),
                        )
                        session.add(lldp)
                        summary["lldp_neighbors_saved"] += 1
            except Exception as e:
                logger.error(f"Error saving LLDP neighbors: {e}", exc_info=True)
        
        # 4. Salva CDP neighbors nella tabella relazionale
        if scan_result.cdp_neighbors:
            try:
                # Elimina vecchi neighbor per questo device
                session.query(CDPNeighbor).filter(
                    CDPNeighbor.device_id == device_id
                ).delete()
                
                for neighbor_data in scan_result.cdp_neighbors:
                    cdp = CDPNeighbor(
                        id=uuid.uuid4().hex[:8],
                        device_id=device_id,
                        local_interface=neighbor_data.get("local_interface", ""),
                        remote_device_name=neighbor_data.get("remote_device_name", ""),
                        remote_port=neighbor_data.get("remote_port", ""),
                        remote_platform=neighbor_data.get("platform", ""),
                        capabilities=neighbor_data.get("capabilities", ""),
                    )
                    session.add(cdp)
                    summary["cdp_neighbors_saved"] += 1
            except Exception as e:
                logger.error(f"Error saving CDP neighbors: {e}", exc_info=True)
        
        # 5. Salva dati vendor-specific nelle tabelle dedicate
        # SKIP se lo scan è fallito (status != "success") - non creare record vuoti
        if scan_result.status == "success":
            device_type = scan_result.device_type or device.device_type or ""
            device_type_lower = device_type.lower() if device_type else ""
            os_family = (scan_result.os_name or device.os_family or "").lower()
            manufacturer = (scan_result.manufacturer or device.manufacturer or "").lower()
        
            # === PROXMOX HOST ===
            # Usa proxmox_collector come fa l'auto-detect per raccogliere dati completi
            if device_type_lower == "proxmox" or device_type_lower == "hypervisor" or "proxmox" in os_family or "pve" in os_family:
                try:
                    from ..services.proxmox_collector import get_proxmox_collector
                    proxmox_collector = get_proxmox_collector()
                    
                    # Recupera credenziali per il collector
                    # Prima prova a costruire lista credenziali dalla scansione
                    working_creds = []
                    
                    # Ottieni customer_id dal device
                    device_customer_id = device.customer_id if hasattr(device, 'customer_id') else None
                    
                    if device_customer_id:
                        # Recupera tutte le credenziali SSH del cliente
                        customer_service = get_customer_service()
                        all_creds = customer_service.list_credentials(customer_id=device_customer_id)
                        
                        for cred_safe in all_creds:
                            # Ottieni credenziale completa con secrets
                            cred = customer_service.get_credential(cred_safe.id, include_secrets=True)
                            if cred and cred.credential_type in ['ssh', 'api']:
                                working_creds.append({
                                    'id': cred.id,
                                    'type': cred.credential_type,
                                    'username': cred.username,
                                    'password': cred.password,
                                    'ssh_port': cred.ssh_port or 22,
                                    'ssh_private_key': cred.ssh_private_key,
                                    'proxmox_port': 8006,  # Default Proxmox API port
                                })
                        
                        logger.info(f"[SAVE_UNIFIED] Found {len(working_creds)} credentials for Proxmox collection")
                    
                    # Raccogli informazioni complete via proxmox_collector
                    host_info = None
                    proxmox_vms = []
                    proxmox_storage = []
                    
                    if working_creds:
                        target_ip = device.primary_ip or device.ip_address
                        if target_ip:
                            logger.info(f"[SAVE_UNIFIED] Collecting Proxmox host info for {target_ip}")
                            host_info = await proxmox_collector.collect_proxmox_host_info(target_ip, working_creds)
                            
                            if host_info:
                                node_name = host_info.get('node_name')
                                if node_name:
                                    logger.info(f"[SAVE_UNIFIED] Collecting Proxmox VMs for node {node_name}")
                                    proxmox_vms = await proxmox_collector.collect_proxmox_vms(target_ip, node_name, working_creds)
                                    proxmox_storage = await proxmox_collector.collect_proxmox_storage(target_ip, node_name, working_creds)
                    
                    # Se abbiamo dati dal collector, usiamo quelli
                    if host_info:
                        logger.info(f"[SAVE_UNIFIED] Using proxmox_collector data for {device_id}")
                        
                        existing_proxmox = session.query(ProxmoxHost).filter(
                            ProxmoxHost.device_id == device_id
                        ).first()
                        
                        if existing_proxmox:
                            # Update con dati completi dal collector
                            for key, value in host_info.items():
                                if value is not None and hasattr(existing_proxmox, key):
                                    setattr(existing_proxmox, key, value)
                            existing_proxmox.last_updated = datetime.utcnow()
                            summary["proxmox_host_updated"] = True
                            host_id = existing_proxmox.id
                            logger.info(f"[SAVE_UNIFIED] Updated ProxmoxHost with collector data for device {device_id}")
                        else:
                            # Crea nuovo con dati completi
                            new_proxmox = ProxmoxHost(
                                id=uuid.uuid4().hex[:8],
                                device_id=device_id,
                                **{k: v for k, v in host_info.items() if hasattr(ProxmoxHost, k) and v is not None}
                            )
                            session.add(new_proxmox)
                            session.flush()
                            summary["proxmox_host_created"] = True
                            host_id = new_proxmox.id
                            logger.info(f"[SAVE_UNIFIED] Created ProxmoxHost with collector data for device {device_id}")
                        
                        # Salva VM
                        if proxmox_vms:
                            # Elimina vecchie VM
                            session.query(ProxmoxVM).filter(ProxmoxVM.host_id == host_id).delete()
                            
                            for vm_data in proxmox_vms:
                                try:
                                    new_vm = ProxmoxVM(
                                        id=uuid.uuid4().hex[:8],
                                        host_id=host_id,
                                        vm_id=vm_data.get('vm_id', 0),
                                        name=vm_data.get('name', ''),
                                        status=vm_data.get('status', 'unknown'),
                                        vm_type=vm_data.get('type', 'qemu'),
                                        cpu_cores=vm_data.get('cpu_cores'),
                                        memory_mb=vm_data.get('memory_mb'),
                                        disk_total_gb=vm_data.get('disk_total_gb'),
                                        os_type=vm_data.get('os_type'),
                                        ip_addresses=vm_data.get('ip_addresses'),
                                        template=vm_data.get('template', False),
                                    )
                                    session.add(new_vm)
                                except Exception as e:
                                    logger.warning(f"Error saving VM {vm_data.get('name')}: {e}")
                            
                            summary["proxmox_vms_saved"] = len(proxmox_vms)
                            logger.info(f"[SAVE_UNIFIED] Saved {len(proxmox_vms)} Proxmox VMs")
                        
                        # Salva Storage
                        if proxmox_storage:
                            session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id == host_id).delete()
                            
                            for storage_data in proxmox_storage:
                                try:
                                    new_storage = ProxmoxStorage(
                                        id=uuid.uuid4().hex[:8],
                                        host_id=host_id,
                                        storage_name=storage_data.get('storage', ''),
                                        storage_type=storage_data.get('type', ''),
                                        content_types=storage_data.get('content', []),
                                        total_gb=storage_data.get('total_gb'),
                                        used_gb=storage_data.get('used_gb'),
                                        available_gb=storage_data.get('available_gb'),
                                        usage_percent=storage_data.get('usage_percent'),
                                    )
                                    session.add(new_storage)
                                except Exception as e:
                                    logger.warning(f"Error saving storage {storage_data.get('storage')}: {e}")
                            
                            summary["proxmox_storage_saved"] = len(proxmox_storage)
                            logger.info(f"[SAVE_UNIFIED] Saved {len(proxmox_storage)} Proxmox storage entries")
                        
                        # Aggiorna custom_fields con dati Proxmox
                        device.custom_fields["proxmox_host_info"] = host_info
                        if proxmox_vms:
                            device.custom_fields["proxmox_vms_count"] = len(proxmox_vms)
                        if proxmox_storage:
                            device.custom_fields["proxmox_storage_count"] = len(proxmox_storage)
                    
                    else:
                        # Fallback: usa dati base dallo scan result (logica precedente)
                        logger.warning(f"[SAVE_UNIFIED] Proxmox collector failed, using basic scan data for {device_id}")
                        
                        existing_proxmox = session.query(ProxmoxHost).filter(
                            ProxmoxHost.device_id == device_id
                        ).first()
                        
                        # Calcola storage info dai disks
                        storage_pools = []
                        if scan_result.disks:
                            for disk in scan_result.disks:
                                size_gb = disk.get("size_gb", 0) or 0
                                free_gb = disk.get("free_gb", 0) or 0
                                mount = disk.get("mount", "")
                                device_name = disk.get("device", "")
                                
                                if size_gb > 10:
                                    storage_pools.append({
                                        "name": mount or device_name,
                                        "total_gb": size_gb,
                                        "free_gb": free_gb,
                                        "type": "zfs" if "zfs" in device_name else "lvm" if "mapper" in device_name else "nfs" if ":" in device_name else "local"
                                    })
                        
                        if existing_proxmox:
                            existing_proxmox.node_name = scan_result.hostname or existing_proxmox.node_name
                            existing_proxmox.proxmox_version = scan_result.os_version or existing_proxmox.proxmox_version
                            existing_proxmox.cpu_model = scan_result.cpu_model or existing_proxmox.cpu_model
                            existing_proxmox.cpu_cores = scan_result.cpu_cores or existing_proxmox.cpu_cores
                            existing_proxmox.memory_total_gb = round(scan_result.ram_total_gb or existing_proxmox.memory_total_gb or 0, 2)
                            existing_proxmox.uptime_human = scan_result.uptime or existing_proxmox.uptime_human
                            if storage_pools:
                                existing_proxmox.storage_list = storage_pools
                            summary["proxmox_host_updated"] = True
                        else:
                            new_proxmox = ProxmoxHost(
                                id=uuid.uuid4().hex[:8],
                                device_id=device_id,
                                node_name=scan_result.hostname or device.name,
                                proxmox_version=scan_result.os_version,
                                cpu_model=scan_result.cpu_model,
                                cpu_cores=scan_result.cpu_cores,
                                memory_total_gb=round(scan_result.ram_total_gb or 0, 2),
                                storage_list=storage_pools if storage_pools else None,
                                uptime_human=scan_result.uptime,
                            )
                            session.add(new_proxmox)
                            summary["proxmox_host_created"] = True
                        
                        if storage_pools:
                            device.custom_fields["storage_pools"] = storage_pools
                            
                except Exception as e:
                    logger.error(f"Error saving Proxmox data: {e}", exc_info=True)
            
            # === MIKROTIK DETAILS === (deve venire prima di Linux perché MikroTik può avere device_type="linux_server")
            elif "routeros" in os_family or manufacturer == "mikrotik" or device_type_lower == "router":
                try:
                    existing_mikrotik = session.query(MikroTikDetails).filter(
                        MikroTikDetails.device_id == device_id
                    ).first()
                    
                    routeros_version = scan_result.os_version
                    board_name = scan_result.model
                    
                    if existing_mikrotik:
                        existing_mikrotik.routeros_version = routeros_version or existing_mikrotik.routeros_version
                        existing_mikrotik.board_name = board_name or existing_mikrotik.board_name
                        existing_mikrotik.cpu_model = scan_result.cpu_model or existing_mikrotik.cpu_model
                        existing_mikrotik.cpu_count = scan_result.cpu_cores or existing_mikrotik.cpu_count
                        if scan_result.ram_total_gb:
                            existing_mikrotik.memory_total_mb = int(scan_result.ram_total_gb * 1024)
                        existing_mikrotik.uptime = scan_result.uptime or existing_mikrotik.uptime
                        existing_mikrotik.identity = scan_result.hostname or existing_mikrotik.identity
                        existing_mikrotik.last_updated = datetime.utcnow()
                        summary["mikrotik_details_updated"] = True
                        logger.info(f"[SAVE_UNIFIED] Updated MikroTikDetails for device {device_id}")
                    else:
                        new_mikrotik = MikroTikDetails(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            routeros_version=routeros_version,
                            board_name=board_name,
                            cpu_model=scan_result.cpu_model,
                            cpu_count=scan_result.cpu_cores,
                            memory_total_mb=int((scan_result.ram_total_gb or 0) * 1024),
                            uptime=scan_result.uptime,
                            identity=scan_result.hostname,
                        )
                        session.add(new_mikrotik)
                        summary["mikrotik_details_created"] = True
                        logger.info(f"[SAVE_UNIFIED] Created new MikroTikDetails for device {device_id}")
                except Exception as e:
                    logger.error(f"Error saving MikroTik data: {e}", exc_info=True)
            
            # === LINUX/NAS DETAILS === (esclude MikroTik che è già stato gestito)
            elif (device_type_lower in ["linux_server", "nas", "storage"] or \
                 "linux" in os_family or manufacturer in ["synology", "qnap", "asustor", "terramaster"]) and \
                 manufacturer != "mikrotik" and "routeros" not in os_family:
                try:
                    existing_linux = session.query(LinuxDetails).filter(
                        LinuxDetails.device_id == device_id
                    ).first()
                    
                    # Calcola disk totali
                    total_disk_gb = 0.0
                    free_disk_gb = 0.0
                    volumes = []
                    
                    if scan_result.disks:
                        for disk in scan_result.disks:
                            size_gb = disk.get("size_gb", 0) or 0
                            free_gb = disk.get("free_gb", 0) or 0
                            mount = disk.get("mount", "")
                            
                            # Considera solo volumi significativi
                            if size_gb > 5:
                                total_disk_gb += size_gb
                                free_disk_gb += free_gb
                                volumes.append({
                                    "mount": mount,
                                    "size_gb": size_gb,
                                    "free_gb": free_gb,
                                    "device": disk.get("device", "")
                                })
                    
                    kernel_version = None
                    distro = None
                    
                    # Estrai kernel se disponibile
                    if hasattr(scan_result, 'kernel_version'):
                        kernel_version = scan_result.kernel_version
                    
                    # Determina distro
                    if manufacturer in ["synology", "qnap", "asustor"]:
                        distro = f"{manufacturer.capitalize()} DSM" if manufacturer == "synology" else manufacturer.capitalize()
                    elif "ubuntu" in os_family:
                        distro = "Ubuntu"
                    elif "debian" in os_family:
                        distro = "Debian"
                    elif "centos" in os_family or "rhel" in os_family:
                        distro = "RHEL/CentOS"
                    
                    if existing_linux:
                        existing_linux.kernel_version = kernel_version or existing_linux.kernel_version
                        existing_linux.distro_name = distro or existing_linux.distro_name
                        existing_linux.distro_version = scan_result.os_version or existing_linux.distro_version
                        if volumes:
                            existing_linux.storage_data = volumes
                        # Salva info NAS se Synology/QNAP
                        if manufacturer in ["synology", "qnap", "asustor"]:
                            existing_linux.nas_model = scan_result.model or existing_linux.nas_model
                            existing_linux.nas_serial = scan_result.serial_number or existing_linux.nas_serial
                            existing_linux.firmware_version = scan_result.os_version or existing_linux.firmware_version
                        summary["linux_details_updated"] = True
                        logger.info(f"[SAVE_UNIFIED] Updated LinuxDetails for device {device_id}")
                    else:
                        new_linux = LinuxDetails(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            kernel_version=kernel_version,
                            distro_name=distro,
                            distro_version=scan_result.os_version,
                            storage_data=volumes if volumes else None,
                            nas_model=scan_result.model if manufacturer in ["synology", "qnap", "asustor"] else None,
                            nas_serial=scan_result.serial_number if manufacturer in ["synology", "qnap", "asustor"] else None,
                            firmware_version=scan_result.os_version if manufacturer in ["synology", "qnap", "asustor"] else None,
                        )
                        session.add(new_linux)
                        summary["linux_details_created"] = True
                        logger.info(f"[SAVE_UNIFIED] Created new LinuxDetails for device {device_id}")
                    
                    # Salva volumes in custom_fields
                    if volumes:
                        device.custom_fields["volumes"] = volumes
                    
                    # Costruisci storage_info completo per Synology/QNAP
                    if manufacturer in ["synology", "qnap", "asustor"]:
                        storage_info = {}
                        
                        # Converti volumes nel formato atteso dal frontend
                        volumes_list = getattr(scan_result, 'volumes', None) or []
                        if volumes_list:
                            storage_info["volumes"] = []
                            for vol in volumes_list:
                                # Calcola total_gb, used_gb, free_gb
                                total_bytes = vol.get("total_bytes", 0)
                                used_bytes = vol.get("used_bytes", 0)
                                available_bytes = vol.get("available_bytes", 0)
                                
                                # Se available_bytes è 0 ma abbiamo available come stringa, prova a parsare
                                if not available_bytes and vol.get("available"):
                                    available_str = str(vol.get("available", "")).strip()
                                    # Se contiene "%", calcola da total e used
                                    if "%" in available_str:
                                        if total_bytes and used_bytes:
                                            available_bytes = total_bytes - used_bytes
                                    else:
                                        # Prova a parsare come size string
                                        available_bytes = _parse_size_string(available_str)
                                
                                # Se ancora non abbiamo available_bytes, calcola da total e used
                                if not available_bytes and total_bytes and used_bytes:
                                    available_bytes = total_bytes - used_bytes
                                
                                # Calcola usage_percent se non presente
                                usage_percent = vol.get("usage_percent") or vol.get("use_percent", 0)
                                if not usage_percent and total_bytes and used_bytes:
                                    usage_percent = round((used_bytes / total_bytes) * 100, 1)
                                
                                vol_dict = {
                                    "name": vol.get("name") or vol.get("mount_point", "").split('/')[-1] or vol.get("device", ""),
                                    "mount_point": vol.get("mount_point") or vol.get("path") or "",
                                    "filesystem": vol.get("filesystem", ""),
                                    "total_gb": round(total_bytes / (1024**3), 2) if total_bytes else (vol.get("total_gb", 0) if vol.get("total_gb") else 0),
                                    "used_gb": round(used_bytes / (1024**3), 2) if used_bytes else (vol.get("used_gb", 0) if vol.get("used_gb") else 0),
                                    "free_gb": round(available_bytes / (1024**3), 2) if available_bytes else (vol.get("free_gb", 0) if vol.get("free_gb") else 0),
                                    "usage_percent": usage_percent,
                                }
                                # Rimuovi valori None o 0 non significativi
                                vol_dict = {k: v for k, v in vol_dict.items() if v is not None and v != ""}
                                storage_info["volumes"].append(vol_dict)
                        
                        # Converti disks nel formato atteso dal frontend
                        disks_list = getattr(scan_result, 'disks', None) or []
                        if disks_list:
                            storage_info["disks"] = []
                            for disk in disks_list:
                                disk_dict = {
                                    "name": disk.get("name") or disk.get("device", ""),
                                    "size": disk.get("size") or disk.get("size_human", ""),
                                    "size_bytes": disk.get("size_bytes", 0),
                                    "model": disk.get("model") or disk.get("friendly_name", ""),
                                    "serial": disk.get("serial") or disk.get("serial_number", ""),
                                    "type": disk.get("type") or disk.get("disk_type", ""),
                                    "temperature": disk.get("temperature") or disk.get("temperature_celsius"),
                                    "health": disk.get("health") or disk.get("health_status") or disk.get("smart_status", ""),
                                }
                                # Rimuovi valori None o vuoti
                                disk_dict = {k: v for k, v in disk_dict.items() if v is not None and v != ""}
                                storage_info["disks"].append(disk_dict)
                        
                        # Converti raid_arrays nel formato atteso dal frontend
                        raid_arrays = getattr(scan_result, 'raid_arrays', None) or []
                        if raid_arrays:
                            # Salva tutti i RAID arrays
                            storage_info["raid_arrays"] = []
                            for raid in raid_arrays:
                                raid_dict = {
                                    "name": raid.get("name") or raid.get("device", ""),
                                    "level": raid.get("level") or raid.get("type", ""),
                                    "status": raid.get("status") or raid.get("state", ""),
                                    "devices": raid.get("devices") or raid.get("disks", []),
                                    "size_gb": raid.get("size_gb", 0),
                                    "degraded": raid.get("degraded", False) or (raid.get("status", "").lower() in ["degraded", "warning"]),
                                }
                                # Rimuovi valori None o vuoti
                                raid_dict = {k: v for k, v in raid_dict.items() if v is not None and v != "" and v != []}
                                storage_info["raid_arrays"].append(raid_dict)
                            
                            # Aggiungi anche un riepilogo RAID principale per retrocompatibilità
                            if raid_arrays:
                                raid = raid_arrays[0]
                                raid_info = {
                                    "name": raid.get("name") or raid.get("device", ""),
                                    "level": raid.get("level") or raid.get("type", ""),
                                    "status": raid.get("status") or raid.get("state", ""),
                                    "devices": raid.get("devices") or raid.get("disks", []),
                                    "total_disks": len(raid.get("devices", []) or raid.get("disks", [])),
                                    "arrays_count": len(raid_arrays),
                                    "degraded": raid.get("degraded", False) or (raid.get("status", "").lower() in ["degraded", "warning"]),
                                }
                                storage_info["raid"] = {k: v for k, v in raid_info.items() if v is not None and v != "" and v != []}
                        
                        # Salva storage_info in custom_fields solo se abbiamo almeno un dato
                        if storage_info and (storage_info.get("volumes") or storage_info.get("disks") or storage_info.get("raid")):
                            if not device.custom_fields:
                                device.custom_fields = {}
                            device.custom_fields["storage_info"] = storage_info
                            flag_modified(device, "custom_fields")
                            custom_fields_changed = True
                            logger.info(f"[SAVE_UNIFIED] Saved storage_info for {manufacturer} device {device_id}: "
                                      f"volumes={len(storage_info.get('volumes', []))}, "
                                      f"disks={len(storage_info.get('disks', []))}, "
                                      f"raid={storage_info.get('raid') is not None}")
                        
                        # Salva servizi in custom_fields per Synology/QNAP
                        services_list = getattr(scan_result, 'services', None) or []
                        if services_list:
                            if not device.custom_fields:
                                device.custom_fields = {}
                            # Estrai nomi servizi e stato
                            running_services = []
                            all_services = []
                            for svc in services_list:
                                # Gestisci sia dizionari che oggetti ServiceInfo
                                if isinstance(svc, dict):
                                    svc_name = svc.get("name") or svc.get("service") or str(svc)
                                    state = svc.get("state") or svc.get("status") or ""
                                else:
                                    # Oggetto ServiceInfo con attributi
                                    svc_name = getattr(svc, 'name', None) or getattr(svc, 'service', None) or str(svc)
                                    state = getattr(svc, 'status', None) or getattr(svc, 'state', None) or ""
                                
                                if svc_name:
                                    svc_name_str = str(svc_name).strip()
                                    if svc_name_str:
                                        all_services.append(svc_name_str)
                                        # Verifica se il servizio è in esecuzione
                                        # Per Synology, il comando pgrep restituisce "running" o "stopped"
                                        state_str = str(state).strip().lower() if state else ""
                                        if state_str in ["running", "active", "enabled", "up", "started"]:
                                            running_services.append(svc_name_str)
                                            logger.debug(f"[SAVE_UNIFIED] Service {svc_name_str} is running (status={state_str})")
                                        else:
                                            logger.debug(f"[SAVE_UNIFIED] Service {svc_name_str} is not running (status={state_str})")
                            
                            if all_services:
                                device.custom_fields["running_services"] = running_services
                                device.custom_fields["running_services_count"] = len(running_services)
                                device.custom_fields["all_services"] = all_services
                                device.custom_fields["services_count"] = len(all_services)
                                flag_modified(device, "custom_fields")
                                custom_fields_changed = True
                                logger.info(f"[SAVE_UNIFIED] Saved services for {manufacturer} device {device_id}: "
                                          f"running={len(running_services)}, total={len(all_services)}")
                        
                        # Salva shares in custom_fields per Synology/QNAP
                        shares_list = getattr(scan_result, 'shares', None) or []
                        if shares_list:
                            if not device.custom_fields:
                                device.custom_fields = {}
                            device.custom_fields["shares"] = shares_list
                            device.custom_fields["shares_count"] = len(shares_list)
                            flag_modified(device, "custom_fields")
                            custom_fields_changed = True
                            logger.info(f"[SAVE_UNIFIED] Saved shares for {manufacturer} device {device_id}: "
                                      f"total={len(shares_list)}")
                    
                except Exception as e:
                    logger.error(f"Error saving Linux/NAS data: {e}", exc_info=True)
            
            # === NETWORK DEVICE DETAILS (Switch, AP, Firewall) ===
            elif device_type_lower in ["switch", "ap", "firewall", "access_point", "wireless"] or \
                 manufacturer in ["ubiquiti", "unifi", "cisco", "aruba", "hp", "hpe", "netgear", "d-link", "tplink", "tp-link", "mikrotik-switch"]:
                try:
                    existing_netdev = session.query(NetworkDeviceDetails).filter(
                        NetworkDeviceDetails.device_id == device_id
                    ).first()
                    
                    # Conta porte e VLANs dalle interfacce
                    port_count = 0
                    vlan_count = 0
                    vlans = []
                    
                    if scan_result.interfaces:
                        for iface in scan_result.interfaces:
                            iface_name = iface.get("name", "").lower()
                            if "eth" in iface_name or "port" in iface_name or "ge" in iface_name:
                                port_count += 1
                            if "vlan" in iface_name:
                                vlan_count += 1
                                vlans.append(iface_name)
                    
                    if scan_result.vlan_info:
                        vlan_count = len(scan_result.vlan_info) if isinstance(scan_result.vlan_info, list) else 1
                    
                    if existing_netdev:
                        existing_netdev.firmware_version = scan_result.os_version or scan_result.firmware_version or existing_netdev.firmware_version
                        existing_netdev.total_ports = port_count if port_count > 0 else existing_netdev.total_ports
                        if scan_result.vlan_info or vlans:
                            existing_netdev.vlans_configured = scan_result.vlan_info if scan_result.vlan_info else vlans
                        existing_netdev.vendor = scan_result.manufacturer or existing_netdev.vendor
                        existing_netdev.last_updated = datetime.utcnow()
                        summary["network_device_details_updated"] = True
                        logger.info(f"[SAVE_UNIFIED] Updated NetworkDeviceDetails for device {device_id}")
                    else:
                        new_netdev = NetworkDeviceDetails(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            device_class=device_type_lower if device_type_lower in ["switch", "ap", "firewall"] else "other",
                            vendor=scan_result.manufacturer,
                            firmware_version=scan_result.os_version or scan_result.firmware_version,
                            total_ports=port_count if port_count > 0 else None,
                            vlans_configured=scan_result.vlan_info if scan_result.vlan_info else (vlans if vlans else None),
                        )
                        session.add(new_netdev)
                        summary["network_device_details_created"] = True
                        logger.info(f"[SAVE_UNIFIED] Created new NetworkDeviceDetails for device {device_id}")
                except Exception as e:
                    logger.error(f"Error saving network device data: {e}", exc_info=True)
        
        # 6. Salva network interfaces nella tabella relazionale
        if scan_result.interfaces:
            try:
                for iface_data in scan_result.interfaces:
                    iface_name = iface_data.get("name", "")
                    if not iface_name:
                        continue
                    
                    # Converti ipv4/ipv4_addresses in formato ip_addresses (compatibile con modello)
                    # Supporta vari formati: ipv4_addresses (lista), ipv4 (singolo), address (singolo)
                    ip_addrs = iface_data.get("ipv4_addresses", [])
                    
                    # Se non c'è ipv4_addresses, prova ipv4 singolo
                    if not ip_addrs and iface_data.get("ipv4"):
                        ip_addrs = [iface_data["ipv4"]]
                    
                    # Se non c'è ipv4, prova address (usato da alcuni probe)
                    if not ip_addrs and iface_data.get("address"):
                        addr = iface_data["address"]
                        # Filtra indirizzi IPv6 link-local
                        if not addr.startswith("fe80") and not addr.startswith("::"):
                            ip_addrs = [addr]
                    
                    if ip_addrs and isinstance(ip_addrs, list):
                        # Converti da lista stringhe a lista dict con formato modello
                        ip_addresses_formatted = [
                            {"ip": ip, "type": "static"} if isinstance(ip, str) else ip
                            for ip in ip_addrs
                        ]
                    else:
                        ip_addresses_formatted = None
                    
                    # Cerca interfaccia esistente
                    existing = session.query(NetworkInterface).filter(
                        NetworkInterface.device_id == device_id,
                        NetworkInterface.name == iface_name
                    ).first()
                    
                    # Determina status/oper_status
                    iface_status = iface_data.get("status") or iface_data.get("oper_status") or "unknown"
                    
                    if existing:
                        # Update esistente
                        if iface_data.get("mac_address"):
                            existing.mac_address = iface_data["mac_address"]
                        if ip_addresses_formatted:
                            existing.ip_addresses = ip_addresses_formatted
                        existing.oper_status = iface_status
                        if iface_data.get("speed_mbps"):
                            existing.speed_mbps = iface_data["speed_mbps"]
                        if iface_data.get("mtu"):
                            existing.mtu = iface_data["mtu"]
                        if iface_data.get("description"):
                            existing.description = iface_data["description"]
                        if iface_data.get("interface_type") or iface_data.get("type"):
                            existing.interface_type = iface_data.get("interface_type") or iface_data.get("type")
                    else:
                        # Insert nuovo
                        new_iface = NetworkInterface(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            name=iface_name,
                            mac_address=iface_data.get("mac_address", ""),
                            ip_addresses=ip_addresses_formatted,
                            interface_type=iface_data.get("interface_type") or iface_data.get("type"),
                            oper_status=iface_status,
                            speed_mbps=iface_data.get("speed_mbps"),
                            mtu=iface_data.get("mtu"),
                            description=iface_data.get("description", ""),
                        )
                        session.add(new_iface)
                        summary["interfaces_saved"] += 1
            except Exception as e:
                logger.error(f"Error saving network interfaces: {e}", exc_info=True)
        
        # Aggiorna summary con custom_fields_updated se ci sono state modifiche dopo la riga 397
        # (servizi e storage_info vengono salvati dopo)
        if custom_fields_changed:
            summary["custom_fields_updated"] = True
        
        return summary
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in _save_unified_scan_to_inventory: {e}", exc_info=True)
        raise


@router.post("/save-to-inventory")
async def save_scan_to_inventory(request: SaveToInventoryRequest):
    """
    Salva risultato scansione nell'inventario.
    
    Aggiorna il dispositivo esistente con i dati raccolti dalla scansione unificata,
    inclusi tutti i dati vendor-specific (routing_table, arp_table, dhcp_leases, etc.).
    
    Args:
        device_id: ID dispositivo
        update_existing: Se True, aggiorna dispositivo esistente
    
    Returns:
        Risultato operazione con summary dei dati salvati
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    
    scanner = get_unified_scanner_service()
    result = scanner.get_cached_result(request.device_id)
    
    if not result:
        raise HTTPException(
            status_code=404,
            detail="No scan result found for this device. Run unified-scan first."
        )
    
    settings = get_settings()
    engine = init_db(settings.database_url)
    session = get_session(engine)
    
    try:
        summary = await _save_unified_scan_to_inventory(request.device_id, result, session)
        session.commit()
        
        return {
            "success": True,
            "message": f"Device updated with unified scan data",
            "summary": summary,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error saving scan to inventory: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/protocols")
async def list_available_protocols():
    """
    Lista protocolli di scansione disponibili.
    
    Returns:
        Lista protocolli con descrizioni
    """
    return {
        "protocols": [
            {
                "id": "auto",
                "name": "Automatico",
                "description": "Determina automaticamente protocollo in base alle porte aperte"
            },
            {
                "id": "snmp",
                "name": "SNMP",
                "description": "Per switch, router, access point, firewall",
                "ports": [161],
                "device_types": ["switch", "router", "access_point", "firewall", "printer", "ups"]
            },
            {
                "id": "ssh",
                "name": "SSH",
                "description": "Per Linux, Synology, QNAP, Proxmox, MikroTik",
                "ports": [22],
                "device_types": ["linux_server", "proxmox", "synology", "qnap", "router"]
            },
            {
                "id": "winrm",
                "name": "WinRM/WMI",
                "description": "Per Windows Server e Client",
                "ports": [5985, 5986, 135],
                "device_types": ["windows_server", "windows_workstation"]
            },
        ]
    }


@router.delete("/cache/{device_id}")
async def clear_scan_cache(device_id: str = None):
    """
    Pulisce cache risultati scansione.
    
    Args:
        device_id: Se specificato, pulisce solo questo device
    """
    scanner = get_unified_scanner_service()
    scanner.clear_cache(device_id)
    
    return {
        "success": True,
        "message": f"Cache cleared for {'device ' + device_id if device_id else 'all devices'}"
    }


async def _get_all_credentials_for_scan(
    customer_id: str,
    device_id: str,
    credential_id: Optional[str],
    protocols: List[str]
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Recupera TUTTE le credenziali disponibili per la scansione.
    
    Restituisce una lista di credenziali per ogni tipo di protocollo,
    ordinate per priorità (device-specific prima, poi default, poi altre).
    
    Returns:
        Dict con chiave = tipo protocollo (ssh, snmp, wmi)
        e valore = lista di credenziali da provare in ordine
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    
    customer_service = get_customer_service()
    
    # Dict con liste di credenziali per ogni tipo
    credentials_by_type: Dict[str, List[Dict[str, Any]]] = {
        "ssh": [],
        "snmp": [],
        "wmi": [],
    }
    
    # Set per evitare duplicati (basato su ID credenziale, non username)
    seen_cred_ids = set()
    
    settings = get_settings()
    engine = init_db(settings.database_url)
    session = get_session(engine)
    
    try:
        # 1. Credenziale specifica richiesta - ha priorità massima
        if credential_id:
            cred = customer_service.get_credential(credential_id, include_secrets=True)
            if cred:
                cred_dict = _credential_to_dict(cred)
                for cred_type, cred_data in cred_dict.items():
                    if cred_type in credentials_by_type:
                        credentials_by_type[cred_type].append(cred_data)
                        seen_cred_ids.add(credential_id)
        
        # 2. Credenziale assegnata al device - seconda priorità
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if device and device.credential_id:
            logger.info(f"[CRED_FETCH] Device {device_id} has credential_id: {device.credential_id}")
            cred = customer_service.get_credential(device.credential_id, include_secrets=True)
            if cred:
                logger.info(f"[CRED_FETCH] Got credential: type={cred.credential_type}, username={cred.username}, has_password={bool(cred.password)}")
                cred_dict = _credential_to_dict(cred)
                logger.info(f"[CRED_FETCH] Converted to dict: {list(cred_dict.keys())}")
                for cred_type, cred_data in cred_dict.items():
                    if cred_type in credentials_by_type and device.credential_id not in seen_cred_ids:
                        credentials_by_type[cred_type].append(cred_data)
                        seen_cred_ids.add(device.credential_id)
                        logger.info(f"[CRED_FETCH] Added {cred_type} credential for device")
            else:
                logger.warning(f"[CRED_FETCH] Failed to get credential {device.credential_id}")
        else:
            logger.info(f"[CRED_FETCH] Device {device_id} has no credential_id or device not found")
        
        # 3. TUTTE le credenziali del cliente per i protocolli richiesti
        # Mappa protocolli richiesti a tipi credenziali
        cred_types_to_fetch = set()
        for proto in protocols:
            if proto == "auto":
                cred_types_to_fetch.update(["ssh", "snmp", "wmi", "mikrotik"])
            elif proto == "ssh":
                cred_types_to_fetch.add("ssh")
                cred_types_to_fetch.add("mikrotik")  # MikroTik usa SSH
            elif proto == "snmp":
                cred_types_to_fetch.add("snmp")
            elif proto in ("wmi", "winrm"):
                cred_types_to_fetch.add("wmi")
        
        # Recupera tutte le credenziali del cliente
        all_customer_creds = customer_service.list_credentials(
            customer_id=customer_id,
            active_only=True
        )
        
        # Per ogni credenziale, aggiungi alla lista appropriata
        for cred_safe in all_customer_creds:
            # Recupera credenziale con secrets
            cred = customer_service.get_credential(cred_safe.id, include_secrets=True)
            if not cred:
                continue
            
            cred_type = cred.credential_type
            
            # Skip se già visto (basato su ID, non username)
            if cred_safe.id in seen_cred_ids:
                continue
            seen_cred_ids.add(cred_safe.id)
            
            # SSH e MikroTik
            if cred_type in ("ssh", "mikrotik") and "ssh" in cred_types_to_fetch:
                username = getattr(cred, 'username', None)
                if username:
                    credentials_by_type["ssh"].append({
                        "username": username,
                        "password": getattr(cred, 'password', None),
                        "port": getattr(cred, 'ssh_port', None) or 22,
                        "credential_name": cred_safe.name,  # Per logging
                    })
            
            # SNMP
            if cred_type == "snmp" and "snmp" in cred_types_to_fetch:
                community = getattr(cred, 'snmp_community', None)
                if community:
                    credentials_by_type["snmp"].append({
                        "community": community,
                        "version": getattr(cred, 'snmp_version', None) or "2c",
                        "port": getattr(cred, 'snmp_port', None) or 161,
                        "credential_name": cred_safe.name,
                    })
            
            # WMI
            if cred_type == "wmi" and "wmi" in cred_types_to_fetch:
                username = getattr(cred, 'username', None)
                if username:
                    credentials_by_type["wmi"].append({
                        "username": username,
                        "password": getattr(cred, 'password', None),
                        "domain": getattr(cred, 'wmi_domain', None) or "",
                        "credential_name": cred_safe.name,
                    })
        
        # 4. Aggiungi fallback SNMP public se non ci sono credenziali SNMP
        if not credentials_by_type["snmp"] and "snmp" in cred_types_to_fetch:
            logger.info(f"[CREDENTIALS] No SNMP credentials found, adding public fallback")
            credentials_by_type["snmp"].append({
                "community": "public",
                "version": "2c",
                "port": 161,
                "credential_name": "public (default)",
            })
        
        # Log dettagliato delle credenziali SNMP trovate
        for snmp_cred in credentials_by_type["snmp"]:
            logger.info(f"[CREDENTIALS] SNMP credential: community={snmp_cred.get('community')}, name={snmp_cred.get('credential_name')}")
        
        logger.info(f"[CREDENTIALS] Found credentials for scan: "
                   f"SSH={len(credentials_by_type['ssh'])}, "
                   f"SNMP={len(credentials_by_type['snmp'])}, "
                   f"WMI={len(credentials_by_type['wmi'])}")
        
        return credentials_by_type
        
    finally:
        session.close()


async def _get_credentials_for_scan(
    customer_id: str,
    device_id: str,
    credential_id: Optional[str],
    protocols: List[str]
) -> Dict[str, Any]:
    """
    Wrapper di compatibilità: restituisce la prima credenziale per ogni tipo.
    Per il nuovo flusso multi-credential, usare _get_all_credentials_for_scan.
    """
    all_creds = await _get_all_credentials_for_scan(
        customer_id, device_id, credential_id, protocols
    )
    
    # Restituisce solo la prima credenziale per ogni tipo (backward compatibility)
    result = {}
    for cred_type, cred_list in all_creds.items():
        if cred_list:
            result[cred_type] = cred_list[0]
    
    return result


def _credential_to_dict(cred) -> Dict[str, Any]:
    """Converte credenziale in dict per scansione"""
    result = {}
    
    if cred.credential_type == "snmp":
        result["snmp"] = {
            "community": cred.snmp_community or "public",
            "version": cred.snmp_version or "2c",
            "port": cred.snmp_port or 161
        }
    elif cred.credential_type == "ssh":
        result["ssh"] = {
            "username": cred.username,
            "password": cred.password,
            "port": cred.ssh_port or 22
        }
    elif cred.credential_type in ("wmi", "winrm"):
        result["wmi"] = {
            "username": cred.username,
            "password": cred.password,
            "domain": cred.wmi_domain or ""
        }
    else:
        # Tipo generico - include tutto
        if cred.snmp_community:
            result["snmp"] = {
                "community": cred.snmp_community,
                "version": cred.snmp_version or "2c",
                "port": cred.snmp_port or 161
            }
        if cred.username:
            result["ssh"] = {
                "username": cred.username,
                "password": cred.password,
                "port": cred.ssh_port or 22
            }
            result["wmi"] = {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.wmi_domain or ""
            }
    
    return result


# Import per timestamp
from datetime import datetime
