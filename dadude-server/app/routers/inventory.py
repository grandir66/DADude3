"""
DaDude - Inventory Router
API per gestione inventario dispositivi
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
from loguru import logger
from datetime import datetime
from sqlalchemy.orm.attributes import flag_modified
import json


router = APIRouter(prefix="/inventory", tags=["Inventory"])


# ==========================================
# SCHEMAS
# ==========================================

class DeviceImport(BaseModel):
    """Schema per importare un dispositivo nell'inventario"""
    address: Optional[str] = None
    mac_address: Optional[str] = None
    name: Optional[str] = None
    identity: Optional[str] = None
    hostname: Optional[str] = None  # Hostname risolto via DNS o rilevato
    platform: Optional[str] = None
    board: Optional[str] = None
    device_type: str = "other"  # windows, linux, mikrotik, network, printer, etc
    category: Optional[str] = None  # server, workstation, router, switch, etc
    credential_id: Optional[str] = None  # Credenziale associata per accesso
    open_ports: Optional[List[dict]] = None  # Porte TCP/UDP aperte
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    identified_by: Optional[str] = None
    credential_used: Optional[str] = None


class BulkImport(BaseModel):
    """Schema per importare più dispositivi"""
    devices: List[DeviceImport]


class DeviceProbeRequest(BaseModel):
    """Schema per probe dispositivo"""
    address: str
    mac_address: Optional[str] = None
    credential_ids: Optional[List[str]] = None  # ID credenziali da usare


class BulkProbeRequest(BaseModel):
    """Schema per probe multipli dispositivi"""
    devices: List[DeviceProbeRequest]
    credential_ids: Optional[List[str]] = None  # Credenziali comuni


class EnrichRequest(BaseModel):
    """Schema per arricchire device con vendor info"""
    devices: List[dict]  # Lista di device con almeno mac_address


class AutoDetectRequest(BaseModel):
    """Schema per auto-detect dispositivo con credenziali di default"""
    address: str
    mac_address: Optional[str] = None
    device_id: Optional[str] = None  # ID device inventario (se presente, usa sua credenziale e salva risultati)
    use_default_credentials: bool = True  # Usa credenziali default del cliente
    use_assigned_credential: bool = True  # Usa credenziale assegnata al device (prioritaria)
    use_agent: bool = True  # Usa agent remoto se disponibile
    agent_id: Optional[str] = None  # ID agent specifico (se None, usa default)
    save_results: bool = True  # Salva i risultati nel device


class BulkAutoDetectRequest(BaseModel):
    """Schema per auto-detect multipli dispositivi"""
    devices: List[AutoDetectRequest]
    use_agent: bool = True  # Usa agent remoto per tutti i device


# ==========================================
# MAC VENDOR & DEVICE PROBE
# ==========================================

@router.post("/enrich-devices")
async def enrich_devices_with_vendor(data: EnrichRequest):
    """
    Arricchisce una lista di dispositivi con info vendor dal MAC address.
    Ritorna i device con vendor, suggested_type, suggested_category.
    """
    from ..services.mac_lookup_service import get_mac_lookup_service
    
    mac_service = get_mac_lookup_service()
    
    # Arricchisci ogni dispositivo con lookup MAC
    enriched = []
    found_count = 0
    for device in data.devices:
        mac = device.get("mac_address", "") or device.get("mac", "")
        if mac and mac.strip():
            mac = mac.strip()
            vendor_info = mac_service.lookup(mac)
            if vendor_info:
                device["vendor"] = vendor_info.get("vendor")
                device["suggested_type"] = vendor_info.get("device_type", "other")
                device["suggested_category"] = vendor_info.get("category")
                device["os_family"] = vendor_info.get("os_family")
                found_count += 1
                logger.info(f"Enriched device {device.get('address', 'unknown')} MAC {mac}: {vendor_info.get('vendor')}")
            else:
                # Fallback se non trovato
                device["vendor"] = device.get("vendor")
                device["suggested_type"] = device.get("suggested_type", "other")
                device["suggested_category"] = device.get("suggested_category")
                logger.debug(f"No vendor found for MAC {mac} (device {device.get('address', 'unknown')})")
        else:
            logger.debug(f"Device {device.get('address', 'unknown')} has no MAC address")
        enriched.append(device)
    
    logger.info(f"Enriched {found_count}/{len(data.devices)} devices with vendor info")
    
    return {
        "success": True,
        "devices": enriched,
    }


@router.post("/probe-device")
async def probe_single_device(
    data: DeviceProbeRequest,
    customer_id: str = Query(...),
):
    """
    Esegue probe su un singolo dispositivo per identificarlo.
    Usa le credenziali del cliente specificate.
    """
    from ..services.device_probe_service import get_device_probe_service
    from ..services.customer_service import get_customer_service
    
    probe_service = get_device_probe_service()
    customer_service = get_customer_service()
    
    # Recupera credenziali
    credentials_list = []
    if data.credential_ids:
        for cred_id in data.credential_ids:
            cred = customer_service.get_credential(cred_id, include_secrets=True)
            if cred:
                credentials_list.append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.credential_type,
                    "username": cred.username,
                    "password": cred.password,
                    "ssh_port": getattr(cred, 'ssh_port', 22),
                    "ssh_private_key": getattr(cred, 'ssh_private_key', None),
                    "snmp_community": getattr(cred, 'snmp_community', None),
                    "snmp_version": getattr(cred, 'snmp_version', '2c'),
                    "snmp_port": getattr(cred, 'snmp_port', 161),
                    "wmi_domain": getattr(cred, 'wmi_domain', None),
                    "mikrotik_api_port": getattr(cred, 'mikrotik_api_port', 8728),
                })
    
    # Esegui probe
    result = await probe_service.auto_identify_device(
        address=data.address,
        mac_address=data.mac_address,
        credentials_list=credentials_list
    )
    
    return {
        "success": True,
        "result": result,
    }


@router.post("/auto-detect")
async def auto_detect_device(
    data: AutoDetectRequest,
    customer_id: str = Query(...),
):
    """
    Esegue auto-detect su un dispositivo:
    1. Cerca agent remoto (Docker o MikroTik) per il cliente
    2. Scansiona le porte aperte (via agent se disponibile)
    3. Determina quali protocolli provare (SSH, SNMP, WMI) in base alle porte
    4. Cerca le credenziali di default del cliente per quei protocolli
    5. Esegue il probe con le credenziali appropriate (via agent Docker se disponibile)
    
    Logica porte → protocolli:
    - SSH (22, 23) → credenziali ssh
    - SNMP (161) → credenziali snmp  
    - RDP/SMB/LDAP/WMI (3389, 445, 139, 389, 135, 5985) → credenziali wmi
    - MikroTik API (8728, 8729, 8291) → credenziali mikrotik
    """
    logger.info(f"=== AUTO-DETECT REQUEST START ===")
    logger.info(f"Address: {data.address}, MAC: {data.mac_address}, Device ID: {data.device_id}")
    logger.info(f"Use assigned credential: {data.use_assigned_credential}, Use default: {data.use_default_credentials}, Use agent: {data.use_agent}, Save results: {data.save_results}")
    
    from ..services.device_probe_service import get_device_probe_service
    from ..services.customer_service import get_customer_service
    from ..services.agent_service import get_agent_service
    
    probe_service = get_device_probe_service()
    customer_service = get_customer_service()
    agent_service = get_agent_service()
    
    result = {
        "address": data.address,
        "mac_address": data.mac_address,
        "success": False,
        "scan_result": None,
        "credentials_tested": [],
        "identified": False,
        "agent_used": None,
    }
    
    try:
        # 0. Cerca agent remoto
        agent_info = None
        if data.use_agent:
            if data.agent_id:
                # Agent specifico
                agent = customer_service.get_agent(data.agent_id, include_password=True)
                if agent:
                    agent_info = agent_service._agent_to_dict(agent)
            else:
                # Agent default del cliente
                agent_info = agent_service.get_agent_for_customer(customer_id)
            
            if agent_info:
                result["agent_used"] = {
                    "id": agent_info["id"],
                    "name": agent_info["name"],
                    "type": agent_info["agent_type"],
                }
                logger.info(f"Auto-detect: Using agent {agent_info['name']} ({agent_info['agent_type']})")
        
        # 1. Scansiona le porte - SEMPRE scan completo durante autodetect
        logger.info(f"Auto-detect: Performing FULL port scan on {data.address}...")
        
        # Recupera credenziali SNMP disponibili per il port scan UDP 161
        # Prima prova a recuperare la credenziale assegnata al device (se esiste)
        snmp_communities = []
        if data.device_id and data.use_assigned_credential:
            try:
                from ..models.inventory import InventoryDevice
                from ..models.database import Credential as CredentialDB
                session = customer_service._get_session()
                try:
                    device_record = session.query(InventoryDevice).filter(
                        InventoryDevice.id == data.device_id
                    ).first()
                    
                    if device_record and device_record.credential_id:
                        cred = session.query(CredentialDB).filter(
                            CredentialDB.id == device_record.credential_id
                        ).first()
                        
                        if cred and cred.credential_type == "snmp" and cred.snmp_community:
                            from ..services.encryption_service import get_encryption_service
                            encryption = get_encryption_service()
                            try:
                                snmp_community = encryption.decrypt(cred.snmp_community) if cred.snmp_community else None
                                if snmp_community and snmp_community not in snmp_communities:
                                    snmp_communities.append(snmp_community)
                                    logger.info(f"Auto-detect: Using assigned SNMP community for port scan")
                            except:
                                pass
                finally:
                    session.close()
            except Exception as e:
                logger.debug(f"Auto-detect: Error retrieving assigned SNMP credential for port scan: {e}")
        
        # Se non abbiamo credenziali assegnate, prova a recuperare credenziali di default SNMP
        if not snmp_communities and data.use_default_credentials:
            try:
                default_snmp_cred = customer_service.get_default_credentials_by_type(
                    customer_id=customer_id,
                    credential_types=["snmp"]
                )
                if default_snmp_cred and "snmp" in default_snmp_cred:
                    cred = default_snmp_cred["snmp"]
                    if cred.snmp_community:
                        from ..services.encryption_service import get_encryption_service
                        encryption = get_encryption_service()
                        try:
                            snmp_community = encryption.decrypt(cred.snmp_community)
                            if snmp_community and snmp_community not in snmp_communities:
                                snmp_communities.append(snmp_community)
                                logger.info(f"Auto-detect: Using default SNMP community for port scan")
                        except:
                            pass
            except Exception as e:
                logger.debug(f"Auto-detect: Error retrieving default SNMP credential for port scan: {e}")
        
        # Durante autodetect, sempre usa scan completo con tutte le porte comuni
        # Non limitare a DEFAULT_PORTS anche se viene usato un agent
        # Questo garantisce che tutte le porte importanti vengano scansionate
        # Passa le credenziali SNMP per il probe UDP 161
        open_ports = await probe_service.scan_services(data.address, snmp_communities=snmp_communities if snmp_communities else None)
        
        result["open_ports"] = open_ports
        open_count = len([p for p in open_ports if p.get("open")])
        logger.info(f"Auto-detect: Found {open_count} open ports on {data.address} (full scan completed)")
        
        # 2. Determina credenziali da provare PRIMA di controllare le porte
        # Se c'è una credenziale assegnata al device, proviamo comunque anche senza porte aperte
        credentials_list = []
        device_record = None
        has_assigned_credential = False
        
        # 2a. Prima controlla se c'è una credenziale assegnata al device specifico
        if data.device_id and data.use_assigned_credential:
            from ..models.inventory import InventoryDevice
            from ..models.database import Credential as CredentialDB
            
            session = customer_service._get_session()
            try:
                device_record = session.query(InventoryDevice).filter(
                    InventoryDevice.id == data.device_id
                ).first()
                
                logger.info(f"Auto-detect: Looking for assigned credential for device {data.device_id}: device_record={device_record is not None}, credential_id={device_record.credential_id if device_record else None}")
                
                if device_record and device_record.credential_id:
                    cred = session.query(CredentialDB).filter(
                        CredentialDB.id == device_record.credential_id
                    ).first()
                    
                    logger.info(f"Auto-detect: Found credential record: {cred is not None}, cred_id={cred.id if cred else None}, cred_name={cred.name if cred else None}, cred_type={cred.credential_type if cred else None}, username={cred.username if cred else None}")
                    
                    if cred:
                        # Decripta la password
                        from ..services.encryption_service import get_encryption_service
                        encryption = get_encryption_service()
                        password = None
                        try:
                            password = encryption.decrypt(cred.password) if cred.password else None
                            logger.info(f"Auto-detect: Password decrypted successfully: {'Yes' if password else 'No'}")
                        except Exception as e:
                            logger.error(f"Auto-detect: Failed to decrypt password: {e}")
                        
                        ssh_key = None
                        try:
                            ssh_key = encryption.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None
                        except Exception as e:
                            logger.debug(f"Auto-detect: Failed to decrypt SSH key (may not exist): {e}")
                        
                        cred_dict = {
                            "id": cred.id,
                            "name": cred.name,
                            "type": cred.credential_type,
                            "username": cred.username,
                            "password": password,
                            "ssh_port": cred.ssh_port or 22,
                            "ssh_private_key": ssh_key,
                            "snmp_community": cred.snmp_community,
                            "snmp_version": cred.snmp_version or '2c',
                            "snmp_port": cred.snmp_port or 161,
                            "wmi_domain": cred.wmi_domain,
                            "mikrotik_api_port": cred.mikrotik_api_port or 8728,
                        }
                        credentials_list.append(cred_dict)
                        result["credentials_tested"].append({
                            "id": cred.id,
                            "name": cred.name,
                            "type": cred.credential_type,
                            "source": "device_assigned",
                        })
                        logger.info(f"Auto-detect: ✓ Using device-assigned credential '{cred.name}' ({cred.credential_type}) - username={cred.username}, password={'***' if password else 'None'}, ssh_port={cred.ssh_port or 22}")
                        has_assigned_credential = True
                    else:
                        logger.warning(f"Auto-detect: Credential ID {device_record.credential_id} not found in database")
                else:
                    logger.warning(f"Auto-detect: Device {data.device_id} has no credential_id assigned")
            except Exception as e:
                logger.error(f"Auto-detect: Error retrieving assigned credential: {e}", exc_info=True)
            finally:
                session.close()
        
        # Se non ci sono porte aperte E non c'è una credenziale assegnata, ritorna errore
        if (not open_ports or open_count == 0) and not has_assigned_credential:
            result["error"] = "No open ports found"
            if not credentials_list:
                result["error"] += " and no assigned credential"
            return result
        
        # 2b. Poi aggiungi credenziali di default se richiesto (solo se ci sono porte aperte o se non abbiamo credenziali assegnate)
        if data.use_default_credentials and (open_count > 0 or not has_assigned_credential):
            # Ottieni credenziali di default in base alle porte aperte
            creds = customer_service.get_credentials_for_auto_detect(
                customer_id=customer_id,
                open_ports=open_ports
            )
            
            # Decripta le password delle credenziali di default
            from ..services.encryption_service import get_encryption_service
            encryption = get_encryption_service()
            
            for cred in creds:
                # Skip se già presente (stessa credenziale assegnata)
                if any(c["id"] == cred.id for c in credentials_list):
                    continue
                
                # Decripta password
                password = None
                try:
                    password = encryption.decrypt(cred.password) if cred.password else None
                except Exception as e:
                    logger.error(f"Auto-detect: Failed to decrypt password for credential {cred.id}: {e}")
                
                # Decripta SSH private key se presente
                ssh_key = None
                try:
                    ssh_key = encryption.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None
                except Exception as e:
                    logger.debug(f"Auto-detect: Failed to decrypt SSH key for credential {cred.id} (may not exist): {e}")
                    
                credentials_list.append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.credential_type,
                    "username": cred.username,
                    "password": password,
                    "ssh_port": getattr(cred, 'ssh_port', 22),
                    "ssh_private_key": ssh_key,
                    "snmp_community": getattr(cred, 'snmp_community', None),
                    "snmp_version": getattr(cred, 'snmp_version', '2c'),
                    "snmp_port": getattr(cred, 'snmp_port', 161),
                    "wmi_domain": getattr(cred, 'wmi_domain', None),
                    "mikrotik_api_port": getattr(cred, 'mikrotik_api_port', 8728),
                })
                result["credentials_tested"].append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.credential_type,
                    "source": "default",
                })
        
        if not credentials_list:
            logger.warning(f"Auto-detect: No credentials found for {data.address}!")
            logger.warning(f"Auto-detect: device_id={data.device_id}, use_assigned_credential={data.use_assigned_credential}, use_default_credentials={data.use_default_credentials}, has_assigned_credential={has_assigned_credential}, open_count={open_count}")
            result["error"] = "No credentials found"
            if not has_assigned_credential and open_count == 0:
                result["error"] += " and no open ports found"
            return result
        else:
            logger.info(f"Auto-detect: Testing {len(credentials_list)} credentials on {data.address}: {[c.get('type') for c in credentials_list]}")
            logger.info(f"Auto-detect: Credential details: {[(c.get('id'), c.get('name'), c.get('type'), c.get('username'), 'password=' + ('Yes' if c.get('password') else 'No')) for c in credentials_list]}")
        
        # 3. Esegui probe con credenziali
        # Se abbiamo un agent Docker, usalo per i probe
        if agent_info and agent_info.get("agent_type") == "docker":
            # Probe via agent Docker
            probe_result = await agent_service.auto_probe(
                agent_info=agent_info,
                target=data.address,
                open_ports=open_ports,
                credentials=credentials_list,
            )
            
            # Converti risultato agent in formato compatibile
            if probe_result.get("best_result"):
                best_data = probe_result["best_result"].get("data", {})
                best_data_keys = list(best_data.keys()) if isinstance(best_data, dict) else []
                logger.info(f"Auto-detect: Merging agent probe result, best_result.data has {len(best_data_keys)} fields: {sorted(best_data_keys)[:30]}")
                if isinstance(best_data, dict) and best_data.get("running_services_count"):
                    logger.info(f"Auto-detect: best_result.data includes: running_services_count={best_data.get('running_services_count')}, cron_jobs_count={best_data.get('cron_jobs_count')}, neighbors_count={best_data.get('neighbors_count')}")
                scan_result = {
                    "address": data.address,
                    "mac_address": data.mac_address,
                    "device_type": "unknown",
                    "category": None,
                    "identified_by": f"agent_{probe_result['best_result']['type']}",
                    **best_data,
                }
                scan_result_keys = list(scan_result.keys())
                logger.info(f"Auto-detect: scan_result after merge has {len(scan_result_keys)} fields: {sorted(scan_result_keys)[:30]}")
            else:
                scan_result = {
                    "address": data.address,
                    "mac_address": data.mac_address,
                    "device_type": "unknown",
                    "identified_by": None,
                    "probes": probe_result.get("probes", []),
                }
        else:
            # Probe diretto (senza agent o con agent MikroTik)
            logger.info(f"Auto-detect: Calling probe_service.auto_identify_device with {len(credentials_list)} credentials")
            scan_result = await probe_service.auto_identify_device(
                address=data.address,
                mac_address=data.mac_address,
                credentials_list=credentials_list
            )
            logger.info(f"Auto-detect: probe_service returned: identified_by={scan_result.get('identified_by')}, device_type={scan_result.get('device_type')}, hostname={scan_result.get('hostname')}")
        
        result["scan_result"] = scan_result
        result["success"] = True
        result["identified"] = scan_result.get("identified_by") is not None
        
        # Log dettagliato dei dati raccolti
        collected_data = {k: v for k, v in scan_result.items() if v and k not in ['probe_results', 'open_ports', 'available_protocols']}
        logger.info(f"Auto-detect complete for {data.address}: identified={result['identified']}, method={scan_result.get('identified_by')}")
        logger.info(f"Auto-detect data collected: {collected_data}")
        
        # 3.4. Se identificato come Linux/Storage/Hypervisor via SSH, esegui scan SSH avanzato automaticamente
        if result["identified"] and agent_info and agent_info.get("agent_type") == "docker":
            device_type = scan_result.get("device_type", "").lower()
            os_family = (scan_result.get("os_family") or "").lower()
            identified_by = scan_result.get("identified_by", "").lower()
            
            # Verifica se è un dispositivo Linux/Storage/Hypervisor identificato via SSH
            is_linux_storage_hypervisor = (
                ("ssh" in identified_by or "agent_ssh" in identified_by) and
                (device_type in ["linux", "storage", "hypervisor", "server"] or
                 os_family == "linux" or
                 scan_result.get("kernel") or
                 scan_result.get("distro_name"))
            )
            
            if is_linux_storage_hypervisor:
                # Trova credenziali SSH che hanno funzionato per il probe normale
                ssh_cred = None
                
                # Cerca il probe SSH che ha avuto successo e usa la credenziale tracciata
                if probe_result.get("probes"):
                    for probe in probe_result["probes"]:
                        if probe.get("type") == "ssh" and probe.get("success"):
                            # Il probe contiene la credenziale usata
                            probe_cred = probe.get("credential")
                            if probe_cred:
                                # Cerca la credenziale nella lista usando ID o username
                                for cred in credentials_list:
                                    if cred.get("type") == "ssh":
                                        if probe_cred.get("id") and cred.get("id") == probe_cred.get("id"):
                                            ssh_cred = cred
                                            logger.info(f"Auto-detect: Found working SSH credential from probe (ID match): {cred.get('name', cred.get('username'))}")
                                            break
                                        elif probe_cred.get("username") and cred.get("username") == probe_cred.get("username"):
                                            ssh_cred = cred
                                            logger.info(f"Auto-detect: Found working SSH credential from probe (username match): {cred.get('name', cred.get('username'))}")
                                            break
                            
                            # Se non trovata tramite tracciamento, cerca per username nei dati del probe
                            if not ssh_cred:
                                probe_data = probe.get("data", {})
                                probe_username = probe_data.get("username") or probe_data.get("hostname")
                                if probe_username:
                                    for cred in credentials_list:
                                        if cred.get("type") == "ssh" and cred.get("username") == probe_username:
                                            ssh_cred = cred
                                            logger.info(f"Auto-detect: Found SSH credential by username from probe data: {cred.get('name', cred.get('username'))}")
                                            break
                            
                            if ssh_cred:
                                break
                
                # Se non trovata nei probe riusciti, usa la prima credenziale SSH disponibile
                if not ssh_cred:
                    for cred in credentials_list:
                        if cred.get("type") == "ssh":
                            ssh_cred = cred
                            logger.info(f"Auto-detect: Using first available SSH credential: {cred.get('name', cred.get('username'))}")
                            break
                
                if ssh_cred:
                    logger.info(f"Auto-detect: Executing advanced SSH scan for Linux/Storage/Hypervisor device with username={ssh_cred.get('username')}, has_password={bool(ssh_cred.get('password'))}, has_key={bool(ssh_cred.get('ssh_private_key'))}")
                    try:
                        advanced_result = await agent_service.probe_ssh_advanced(
                            agent_info=agent_info,
                            target=data.address,
                            username=ssh_cred.get("username", ""),
                            password=ssh_cred.get("password"),
                            private_key=ssh_cred.get("ssh_private_key"),
                            port=ssh_cred.get("ssh_port", 22),
                        )
                        
                        if advanced_result.success and advanced_result.data:
                            # Merge dati avanzati con scan_result (dati avanzati hanno priorità)
                            advanced_data = advanced_result.data
                            
                            # Estrai dati base da oggetti annidati e mettili direttamente in scan_result
                            if isinstance(advanced_data, dict):
                                # Estrai da system_info
                                if advanced_data.get("system_info"):
                                    si = advanced_data["system_info"]
                                    if isinstance(si, dict):
                                        scan_result["hostname"] = scan_result.get("hostname") or si.get("hostname")
                                        scan_result["os_name"] = scan_result.get("os_name") or si.get("os_name")
                                        scan_result["os_version"] = scan_result.get("os_version") or si.get("os_version")
                                        scan_result["kernel"] = scan_result.get("kernel") or si.get("kernel_version")
                                        scan_result["architecture"] = scan_result.get("architecture") or si.get("architecture")
                                        sys_type = si.get("system_type", "").lower()
                                        if sys_type in ["synology", "qnap"]:
                                            scan_result["device_type"] = "storage"
                                            scan_result["manufacturer"] = scan_result.get("manufacturer") or ("Synology" if sys_type == "synology" else "QNAP")
                                        elif sys_type == "proxmox":
                                            scan_result["device_type"] = "hypervisor"
                                        elif not scan_result.get("device_type") or scan_result.get("device_type") == "unknown":
                                            scan_result["device_type"] = "linux"
                                        scan_result["model"] = scan_result.get("model") or si.get("nas_model")
                                        scan_result["serial_number"] = scan_result.get("serial_number") or si.get("nas_serial")
                                
                                # Estrai da cpu
                                if advanced_data.get("cpu"):
                                    cpu = advanced_data["cpu"]
                                    if isinstance(cpu, dict):
                                        scan_result["cpu_model"] = scan_result.get("cpu_model") or cpu.get("model")
                                        scan_result["cpu_cores"] = scan_result.get("cpu_cores") or cpu.get("cores_physical")
                                        scan_result["cpu_threads"] = scan_result.get("cpu_threads") or cpu.get("cores_logical")
                                
                                # Estrai da memory
                                if advanced_data.get("memory"):
                                    mem = advanced_data["memory"]
                                    if isinstance(mem, dict):
                                        if mem.get("total_gb"):
                                            scan_result["ram_total_gb"] = mem.get("total_gb")
                                        elif mem.get("total_bytes"):
                                            scan_result["ram_total_mb"] = int(mem.get("total_bytes") / (1024 * 1024))
                                
                                # Estrai da docker
                                if advanced_data.get("docker"):
                                    docker = advanced_data["docker"]
                                    if isinstance(docker, dict):
                                        scan_result["docker_version"] = scan_result.get("docker_version") or docker.get("version")
                                        scan_result["docker_installed"] = True if docker.get("version") else False
                                        scan_result["docker_containers_running"] = scan_result.get("docker_containers_running") or docker.get("containers_running")
                                
                                # Merge tutti i dati avanzati (mantieni anche oggetti annidati per salvataggio avanzato)
                                scan_result.update(advanced_data)
                                logger.info(f"Auto-detect: Advanced SSH scan completed, merged {len(advanced_data)} fields")
                    except Exception as e:
                        logger.warning(f"Auto-detect: Advanced SSH scan failed: {e}", exc_info=True)
                        # Continua comunque con i dati del probe normale
        
        # 3.5. Se identificato come Proxmox o network device, raccogli dati avanzati automaticamente
        if result["identified"] and data.device_id and data.save_results:
            device_type = scan_result.get("device_type", "").lower()
            vendor = (scan_result.get("vendor") or scan_result.get("manufacturer") or "").lower()
            os_family = (scan_result.get("os_family") or "").lower()
            
            is_proxmox = device_type == "hypervisor" or "proxmox" in vendor or "proxmox" in os_family
            is_network = device_type in ["network", "router", "switch"] or "mikrotik" in vendor or "cisco" in vendor or "hp" in vendor or "aruba" in vendor or "ubiquiti" in vendor
            
            if is_proxmox or is_network:
                logger.info(f"Device identified as {'Proxmox' if is_proxmox else 'Network'} device, collecting advanced info automatically...")
                try:
                    # Usa le stesse credenziali che hanno funzionato per l'identificazione
                    # Se non ci sono dati avanzati già nel risultato, chiama i collector
                    if is_proxmox and not scan_result.get("proxmox_host_info"):
                        from ..services.proxmox_collector import get_proxmox_collector
                        proxmox_collector = get_proxmox_collector()
                        
                        # Usa le credenziali che hanno funzionato
                        working_creds = [c for c in credentials_list if c.get("id") in [ct.get("id") for ct in result.get("credentials_tested", [])]]
                        if not working_creds:
                            working_creds = credentials_list  # Fallback a tutte le credenziali
                        
                        host_info = await proxmox_collector.collect_proxmox_host_info(data.address, working_creds)
                        if host_info:
                            scan_result["proxmox_host_info"] = host_info
                            node_name = host_info.get("node_name")
                            if node_name:
                                vms = await proxmox_collector.collect_proxmox_vms(data.address, node_name, working_creds)
                                if vms:
                                    scan_result["proxmox_vms"] = vms
                                storage = await proxmox_collector.collect_proxmox_storage(data.address, node_name, working_creds)
                                if storage:
                                    scan_result["proxmox_storage"] = storage
                            logger.info(f"Collected advanced Proxmox info during auto-detect")
                    
                    # LLDP/CDP per dispositivi di rete (escluso MikroTik che ha logica separata)
                    is_mikrotik_for_lldp = device_type == "mikrotik" or "mikrotik" in vendor or "mikrotik" in os_family or scan_result.get("os_family", "").lower() == "routeros"
                    if is_network and not is_mikrotik_for_lldp and not scan_result.get("lldp_neighbors"):
                        logger.info(f"Collecting LLDP/CDP for network device (device_type={device_type}, vendor={vendor})...")
                        from ..services.lldp_cdp_collector import get_lldp_cdp_collector
                        lldp_collector = get_lldp_cdp_collector()
                        
                        working_creds = [c for c in credentials_list if c.get("id") in [ct.get("id") for ct in result.get("credentials_tested", [])]]
                        if not working_creds:
                            working_creds = credentials_list
                        
                        lldp_neighbors = await lldp_collector.collect_lldp_neighbors(data.address, device_type, vendor, working_creds)
                        if lldp_neighbors:
                            scan_result["lldp_neighbors"] = lldp_neighbors
                            logger.info(f"✓ Collected {len(lldp_neighbors)} LLDP neighbors")
                        
                        if "cisco" in vendor:
                            cdp_neighbors = await lldp_collector.collect_cdp_neighbors(data.address, vendor, working_creds)
                            if cdp_neighbors:
                                scan_result["cdp_neighbors"] = cdp_neighbors
                                logger.info(f"✓ Collected {len(cdp_neighbors)} CDP neighbors")
                        
                        interfaces = await lldp_collector.collect_interface_details(data.address, device_type, vendor, working_creds)
                        if interfaces:
                            scan_result["interface_details"] = interfaces
                            logger.info(f"✓ Collected {len(interfaces)} interface details")
                        logger.info(f"Collected advanced network info during auto-detect")
                    
                    # LLDP per MikroTik (MikroTik supporta LLDP)
                    if is_mikrotik_for_lldp and not scan_result.get("lldp_neighbors"):
                        logger.info(f"Collecting LLDP for MikroTik device...")
                        from ..services.lldp_cdp_collector import get_lldp_cdp_collector
                        lldp_collector = get_lldp_cdp_collector()
                        
                        working_creds = [c for c in credentials_list if c.get("id") in [ct.get("id") for ct in result.get("credentials_tested", [])]]
                        if not working_creds:
                            working_creds = credentials_list
                        
                        if working_creds:
                            try:
                                lldp_neighbors = await lldp_collector.collect_lldp_neighbors(data.address, "mikrotik", vendor, working_creds)
                                if lldp_neighbors:
                                    scan_result["lldp_neighbors"] = lldp_neighbors
                                    logger.info(f"✓ Collected {len(lldp_neighbors)} LLDP neighbors for MikroTik")
                                else:
                                    logger.debug(f"No LLDP neighbors found for MikroTik")
                            except Exception as e:
                                logger.error(f"Error collecting LLDP for MikroTik: {e}", exc_info=True)
                    
                    # MikroTik: raccogli routing e ARP durante auto-detect
                    # MikroTik può essere identificato come device_type="mikrotik" o come network device con vendor="MikroTik"
                    is_mikrotik = device_type == "mikrotik" or "mikrotik" in vendor or "mikrotik" in os_family or scan_result.get("os_family", "").lower() == "routeros"
                    if is_mikrotik:
                        logger.info(f"Detected MikroTik device (device_type={device_type}, vendor={vendor}, os_family={os_family}), collecting routing/ARP...")
                        from ..services.mikrotik_service import get_mikrotik_service
                        import json
                        mikrotik_service = get_mikrotik_service()
                        
                        working_creds = [c for c in credentials_list if c.get("id") in [ct.get("id") for ct in result.get("credentials_tested", [])]]
                        if not working_creds:
                            working_creds = credentials_list
                        
                        if working_creds:
                            cred = working_creds[0]
                            logger.info(f"Using credential '{cred.get('name', 'unknown')}' for MikroTik data collection on {data.address}")
                            
                            # Raccogli routing table
                            try:
                                routes_result = mikrotik_service.get_routes(
                                    data.address,
                                    cred.get("mikrotik_api_port", 8728),
                                    cred.get("username", ""),
                                    cred.get("password", ""),
                                    use_ssl=cred.get("use_ssl", False)
                                )
                                
                                if routes_result.get("success") and routes_result.get("routes"):
                                    scan_result["routing_table"] = routes_result.get("routes")
                                    scan_result["routing_count"] = routes_result.get("count", 0)
                                    logger.info(f"✓ Collected {routes_result.get('count', 0)} routing entries for MikroTik during auto-detect")
                                else:
                                    logger.warning(f"Routing collection returned: success={routes_result.get('success')}, routes={routes_result.get('routes') is not None}, error={routes_result.get('error')}")
                            except Exception as e:
                                logger.error(f"Error collecting routing table during auto-detect: {e}", exc_info=True)
                            
                            # Raccogli ARP table completa
                            try:
                                api = mikrotik_service._get_connection(
                                    data.address,
                                    cred.get("mikrotik_api_port", 8728),
                                    cred.get("username", ""),
                                    cred.get("password", ""),
                                    use_ssl=cred.get("use_ssl", False)
                                )
                                
                                arp_resource = api.get_resource('/ip/arp')
                                arps = arp_resource.get()
                                
                                arp_entries = []
                                for a in arps:
                                    ip_str = a.get("address", "")
                                    mac = a.get("mac-address", "")
                                    if ip_str and mac and mac != "00:00:00:00:00:00":
                                        arp_entries.append({
                                            "ip": ip_str,
                                            "mac": mac.upper(),
                                            "interface": a.get("interface", ""),
                                            "complete": a.get("complete", "") == "true",
                                        })
                                
                                if arp_entries:
                                    scan_result["arp_table"] = arp_entries
                                    scan_result["arp_count"] = len(arp_entries)
                                    logger.info(f"✓ Collected {len(arp_entries)} ARP entries for MikroTik during auto-detect")
                                else:
                                    logger.warning(f"No ARP entries found for MikroTik device")
                            except Exception as e:
                                logger.error(f"Error collecting ARP table during auto-detect: {e}", exc_info=True)
                        else:
                            logger.warning(f"No credentials available for MikroTik data collection on {data.address}")
                    else:
                        logger.debug(f"Device not identified as MikroTik (device_type={device_type}, vendor={vendor}, os_family={os_family})")
                except Exception as e:
                    logger.warning(f"Error collecting advanced info during auto-detect: {e}", exc_info=True)
        
        # 4. Salva i risultati nel device se richiesto
        # Salva anche se non completamente identificato, ma ci sono dati utili
        has_useful_data = (
            scan_result.get("hostname") or 
            scan_result.get("os_family") or 
            scan_result.get("cpu_model") or
            scan_result.get("serial_number") or
            scan_result.get("memory_total_mb") or
            scan_result.get("manufacturer")
        )
        
        if data.save_results and data.device_id and (result["identified"] or has_useful_data):
            from ..models.inventory import InventoryDevice
            import json
            
            session = customer_service._get_session()
            try:
                device = session.query(InventoryDevice).filter(
                    InventoryDevice.id == data.device_id
                ).first()
                
                if device:
                    logger.info(f"Saving probe results for device {data.device_id}: {list(scan_result.keys())}")
                    
                    # PRESERVA credential_id esistente - NON sovrascriverlo!
                    # Se viene usata una credenziale durante il probe e non c'è già una credenziale associata,
                    # oppure se la credenziale usata corrisponde a quella già associata, preservala
                    existing_credential_id = device.credential_id
                    
                    # Se è stata usata una credenziale durante il probe e non c'è già una credenziale associata,
                    # prova ad associare quella usata
                    if result.get("credentials_tested") and not existing_credential_id:
                        # Cerca la credenziale usata tra quelle del cliente
                        # Prova prima con l'ID se disponibile
                        tested_cred = result["credentials_tested"][0]
                        cred_id = tested_cred.get("id")
                        cred_name = tested_cred.get("name")
                        
                        from ..models.database import Credential as CredentialDB
                        cred = None
                        
                        # Cerca per ID se disponibile
                        if cred_id:
                            cred = session.query(CredentialDB).filter(
                                CredentialDB.id == cred_id
                            ).first()
                        
                        # Fallback: cerca per nome se ID non disponibile o non trovato
                        if not cred and cred_name:
                            # Cerca prima tra credenziali del cliente
                            cred = session.query(CredentialDB).filter(
                                CredentialDB.customer_id == device.customer_id,
                                CredentialDB.name == cred_name
                            ).first()
                            
                            # Se non trovata, cerca tra credenziali globali
                            if not cred:
                                cred = session.query(CredentialDB).filter(
                                    CredentialDB.is_global == True,
                                    CredentialDB.name == cred_name
                                ).first()
                        
                        if cred:
                            device.credential_id = cred.id
                            logger.info(f"Auto-detect: Associated credential '{cred_name}' ({cred.id}) to device {data.device_id}")
                        else:
                            logger.warning(f"Auto-detect: Credential '{cred_name}' used but not found in database for device {data.device_id}")
                    
                    # Se c'è già una credential_id, preservala sempre
                    elif existing_credential_id:
                        logger.debug(f"Auto-detect: Preserving existing credential_id {existing_credential_id} for device {data.device_id}")
                    
                    # Hostname
                    hostname = scan_result.get("hostname") or scan_result.get("sysName") or scan_result.get("computer_name")
                    if hostname:
                        device.hostname = hostname
                    
                    # OS
                    # Priorità: os_family da scan_result (più affidabile per Synology/QNAP)
                    if scan_result.get("os_family"):
                        device.os_family = scan_result["os_family"]
                    # os_name viene usato solo se os_family non è già impostato
                    elif scan_result.get("os_name"):
                        # Per Synology/QNAP, os_name è "DSM"/"QTS", quindi impostiamo os_family come Linux
                        os_name_val = scan_result.get("os_name", "").lower()
                        if os_name_val in ["dsm", "qts"]:
                            device.os_family = "Linux"
                        else:
                            device.os_family = scan_result["os_name"]
                    if scan_result.get("os_version") or scan_result.get("version"):
                        device.os_version = scan_result.get("os_version") or scan_result.get("version")
                    
                    # Vendor/Manufacturer
                    manufacturer = (scan_result.get("manufacturer") or scan_result.get("vendor") or 
                                   scan_result.get("system_manufacturer"))
                    if manufacturer:
                        device.manufacturer = manufacturer
                    
                    # Model
                    model = scan_result.get("model") or scan_result.get("system_model")
                    if model:
                        device.model = model
                    
                    # Serial
                    serial = scan_result.get("serial_number") or scan_result.get("serial")
                    if serial:
                        device.serial_number = serial
                    
                    # CPU
                    cpu = scan_result.get("cpu_model") or scan_result.get("cpu")
                    if cpu:
                        device.cpu_model = cpu
                    cores = scan_result.get("cpu_cores") or scan_result.get("cores")
                    if cores:
                        try:
                            device.cpu_cores = int(cores)
                        except (ValueError, TypeError):
                            pass
                    
                    # RAM (vari formati: MB, GB, bytes)
                    ram_mb = scan_result.get("memory_total_mb") or scan_result.get("ram_total_mb")
                    ram_gb = scan_result.get("ram_total_gb") or scan_result.get("memory_total_gb")
                    if ram_gb:
                        try:
                            device.ram_total_gb = float(ram_gb)
                        except (ValueError, TypeError):
                            pass
                    elif ram_mb:
                        try:
                            device.ram_total_gb = float(ram_mb) / 1024
                        except (ValueError, TypeError):
                            pass
                    
                    # Disco
                    disk_gb = scan_result.get("disk_total_gb") or scan_result.get("storage_total_gb")
                    if disk_gb:
                        try:
                            device.disk_total_gb = float(disk_gb)
                        except (ValueError, TypeError):
                            pass
                    disk_free = scan_result.get("disk_free_gb") or scan_result.get("storage_free_gb")
                    if disk_free:
                        try:
                            device.disk_free_gb = float(disk_free)
                        except (ValueError, TypeError):
                            pass
                    
                    # Device Type e Category - Assegnazione automatica in base al risultato probe
                    identified_by = scan_result.get("identified_by") or scan_result.get("probe_type")
                    
                    # Determina device_type in base al metodo di identificazione e ai dati raccolti
                    # PRIORITÀ: 1) scan_result.device_type, 2) os_name, 3) identified_by, 4) os_family, 5) os_version
                    os_name_check = scan_result.get("os_name") or ""
                    os_name_lower = os_name_check.lower()
                    
                    if scan_result.get("device_type") and scan_result["device_type"] != "unknown":
                        device.device_type = scan_result["device_type"]
                        logger.info(f"Setting device_type from scan_result: {device.device_type}")
                    
                    # Priorità alta: determina da os_name (più affidabile)
                    elif os_name_check and (not device.device_type or device.device_type == "other" or device.device_type == "unknown"):
                        if "windows" in os_name_lower or "microsoft" in os_name_lower:
                            device.device_type = "windows"
                            logger.info(f"Setting device_type from os_name: windows (os_name={os_name_check})")
                        elif any(x in os_name_lower for x in ["ubuntu", "debian", "centos", "rhel", "linux", "alpine", "suse", "arch"]):
                            device.device_type = "linux"
                            logger.info(f"Setting device_type from os_name: linux (os_name={os_name_check})")
                        elif "routeros" in os_name_lower or "mikrotik" in os_name_lower:
                            device.device_type = "mikrotik"
                            logger.info(f"Setting device_type from os_name: mikrotik (os_name={os_name_check})")
                    
                    elif not device.device_type or device.device_type == "other" or device.device_type == "unknown":
                        # Verifica se è Synology/QNAP prima di altri controlli
                        manufacturer_lower = (scan_result.get("manufacturer") or scan_result.get("vendor") or "").lower()
                        if "synology" in manufacturer_lower or "qnap" in manufacturer_lower:
                            device.device_type = "storage"
                            device.category = "storage"
                            logger.info(f"Setting device_type from manufacturer: storage (manufacturer={manufacturer_lower})")
                        elif identified_by:
                            # Supporta sia "wmi" che "agent_wmi", "probe_wmi", ecc.
                            if "wmi" in identified_by.lower() or "windows" in identified_by.lower():
                                device.device_type = "windows"
                                logger.info(f"Setting device_type from identified_by: windows (identified_by={identified_by})")
                            elif "ssh" in identified_by.lower() or "linux" in identified_by.lower():
                                device.device_type = "linux"
                                logger.info(f"Setting device_type from identified_by: linux (identified_by={identified_by})")
                            elif "mikrotik" in identified_by.lower() or "routeros" in identified_by.lower():
                                device.device_type = "mikrotik"
                                logger.info(f"Setting device_type from identified_by: mikrotik (identified_by={identified_by})")
                            elif "snmp" in identified_by.lower():
                                # SNMP può essere router, switch, server, etc.
                                device.device_type = "network"
                                logger.info(f"Setting device_type from identified_by: network (identified_by={identified_by})")
                        
                        # Fallback: determina da os_family o os_version
                        if (not device.device_type or device.device_type == "other" or device.device_type == "unknown"):
                            os_family_to_check = device.os_family or scan_result.get("os_family") or ""
                            os_version_to_check = device.os_version or scan_result.get("os_version") or scan_result.get("version") or ""
                            
                            if os_family_to_check:
                                os_family_lower = os_family_to_check.lower()
                                if "windows" in os_family_lower:
                                    device.device_type = "windows"
                                    logger.info(f"Setting device_type from os_family: windows")
                                elif "linux" in os_family_lower or "unix" in os_family_lower:
                                    device.device_type = "linux"
                                    logger.info(f"Setting device_type from os_family: linux")
                                elif "routeros" in os_family_lower or "mikrotik" in os_family_lower:
                                    device.device_type = "mikrotik"
                                    logger.info(f"Setting device_type from os_family: mikrotik")
                                elif "ios" in os_family_lower or "nx-os" in os_family_lower:
                                    device.device_type = "network"
                                    logger.info(f"Setting device_type from os_family: network")
                            
                            # Ultimo fallback: controlla os_version per Windows
                            if (not device.device_type or device.device_type == "other" or device.device_type == "unknown") and os_version_to_check:
                                os_version_lower = os_version_to_check.lower()
                                if "windows" in os_version_lower or "microsoft" in os_version_lower:
                                    device.device_type = "windows"
                                    logger.info(f"Setting device_type from os_version: windows")
                    
                    # Determina category in base ai dati raccolti
                    if not device.category:
                        # Categoria basata su porte aperte e tipo dispositivo
                        windows_ports = [3389, 445, 139, 389, 135, 5985, 5986]
                        server_ports = [3306, 5432, 1433, 1521, 27017, 6379]  # Database
                        network_ports = [161, 162, 8728, 8729, 8291]  # SNMP, MikroTik
                        
                        open_port_numbers = [p.get("port") for p in open_ports if p.get("open")]
                        
                        if device.device_type == "windows":
                            # Windows: determina se server o workstation
                            if any(p in open_port_numbers for p in server_ports):
                                device.category = "server"
                            elif 3389 in open_port_numbers:  # RDP
                                device.category = "workstation"
                            else:
                                device.category = "server"  # Default per Windows
                        elif device.device_type == "linux":
                            # Linux: determina se server o workstation
                            if any(p in open_port_numbers for p in server_ports):
                                device.category = "server"
                            elif 22 in open_port_numbers and not any(p in open_port_numbers for p in server_ports):
                                device.category = "workstation"
                            else:
                                device.category = "server"  # Default per Linux
                        elif device.device_type == "mikrotik":
                            device.category = "router"
                        elif device.device_type == "network":
                            # Network device: determina tipo
                            if any(p in open_port_numbers for p in [8728, 8729, 8291]):
                                device.category = "router"
                            elif 161 in open_port_numbers:
                                # SNMP: potrebbe essere switch, router, firewall
                                device.category = "switch"  # Default, può essere cambiato manualmente
                            else:
                                device.category = "network"
                        else:
                            # Tipo sconosciuto: prova a determinare da porte
                            if any(p in open_port_numbers for p in network_ports):
                                device.category = "network"
                            elif any(p in open_port_numbers for p in server_ports):
                                device.category = "server"
                            else:
                                device.category = "other"
                    
                    # Salva anche device_type e category espliciti dal scan_result se presenti
                    if scan_result.get("device_type") and scan_result["device_type"] != "unknown":
                        device.device_type = scan_result["device_type"]
                    if scan_result.get("category"):
                        device.category = scan_result["category"]
                    
                    # Firmware/Version
                    firmware = scan_result.get("firmware_version") or scan_result.get("bios_version")
                    if firmware:
                        device.firmware_version = firmware
                    
                    # NON sovrascrivere device_type con "unknown" - già gestito sopra con logica corretta
                    # if scan_result.get("device_type") and scan_result["device_type"] != "unknown":
                    #     device.device_type = scan_result["device_type"]
                    
                    # Domain
                    if scan_result.get("domain"):
                        device.domain = scan_result["domain"]
                    
                    # Metodo di identificazione
                    if scan_result.get("identified_by"):
                        device.identified_by = scan_result["identified_by"]
                    
                    # Credenziale usata
                    if result["credentials_tested"]:
                        device.credential_used = result["credentials_tested"][0].get("type")
                    
                    # Porte aperte - preserva quelle esistenti e aggiungi/aggiorna solo quelle nuove
                    if open_ports:
                        # Carica porte esistenti se presenti
                        existing_ports = []
                        if device.open_ports:
                            try:
                                if isinstance(device.open_ports, str):
                                    existing_ports = json.loads(device.open_ports)
                                elif isinstance(device.open_ports, list):
                                    existing_ports = device.open_ports
                            except:
                                existing_ports = []
                        
                        # Crea un dict per merge: porta -> info porta
                        ports_dict = {}
                        for port in existing_ports:
                            port_num = port.get("port") if isinstance(port, dict) else port
                            if port_num:
                                ports_dict[port_num] = port if isinstance(port, dict) else {"port": port, "open": True}
                        
                        # Aggiungi/aggiorna con nuove porte
                        for port in open_ports:
                            port_num = port.get("port") if isinstance(port, dict) else port
                            if port_num:
                                ports_dict[port_num] = port if isinstance(port, dict) else {"port": port, "open": True}
                        
                        # Converti di nuovo in lista
                        merged_ports = list(ports_dict.values())
                        device.open_ports = json.dumps(merged_ports) if isinstance(merged_ports, list) else merged_ports
                        logger.debug(f"Preserved {len(existing_ports)} existing ports, merged with {len(open_ports)} new ports, total: {len(merged_ports)}")
                    
                    # Salva dati extra nel campo custom_fields
                    extra_fields = {}
                    
                    # Dati Windows/Linux dettagliati + SNMP
                    extra_field_names = [
                        "server_roles", "installed_software", "network_adapters", "local_users",
                        "important_services", "memory_modules", "disks", "antivirus",
                        "domain_role", "is_server", "is_domain_controller", "last_boot",
                        "install_date", "registered_user", "organization", "system_type",
                        "cpu_speed_mhz", "cpu_threads", "cpu_manufacturer", "bios_version", "bios_manufacturer",
                        "shell_users", "docker_containers_running", "lxc_containers", "vms",
                        "virtualization", "timezone", "uptime", "last_login", "kernel",
                        "interface_count", "license_level", "firmware", "firmware_version",
                        # Campi SNMP
                        "sysDescr", "sysName", "sysObjectID", "sysUpTime", "sysServices",
                        "entPhysicalDescr", "entPhysicalModelName", "entPhysicalName", 
                        "entPhysicalSerialNum", "entPhysicalSoftwareRev",
                        # Neighbors (LLDP/CDP)
                        "neighbors", "lldp_neighbors", "cdp_neighbors", "neighbors_count",
                        "lldp_neighbors_count", "cdp_neighbors_count",
                        # Routing e ARP
                        "routing_table", "routing_count", "arp_table", "arp_count",
                        # Interfacce avanzate
                        "interfaces", "network_interfaces",
                        # Campi Ubiquiti specifici
                        "ubiquiti_model", "ubiquiti_firmware", "wifi_clients", 
                        "load_average_1m", "ram_available_mb", "vendor_model", "vendor_version",
                        # Campi HP ProCurve specifici
                        "vendor_os_version", "vendor_rom_version", "vendor_product_number",
                        "vendor_mem_total", "vendor_mem_free", "cpu_usage_percent",
                        # Campi HP Comware specifici
                        "vendor_cpu_usage", "vendor_mem_usage", "vendor_temperature",
                        "vendor_fan_status", "vendor_power_status", "memory_usage_percent",
                        # Campi ArubaOS specifici
                        "vendor_sw_version", "vendor_hw_version", "vendor_switch_serial",
                        "vendor_cpu_usage", "vendor_storage_usage",
                        # Campi TP-Link Omada specifici
                        "vendor_description", "vendor_hw_version", "vendor_fw_version",
                        "vendor_mac", "hardware_version"
                    ]
                    
                    for field in extra_field_names:
                        if field in scan_result and scan_result[field]:
                            extra_fields[field] = scan_result[field]
                            logger.debug(f"Auto-detect: Saving extra field {field}={scan_result[field]}")
                        # Prova anche con prefisso vendor_ per campi vendor-specific
                        elif f"vendor_{field}" in scan_result and scan_result[f"vendor_{field}"]:
                            extra_fields[field] = scan_result[f"vendor_{field}"]
                            logger.debug(f"Auto-detect: Saving vendor field vendor_{field}={scan_result[f'vendor_{field}']}")
                    
                    # Aggiungi anche tutti i campi che iniziano con vendor_ se non già inclusi
                    for key, value in scan_result.items():
                        if key.startswith("vendor_") and value and key not in extra_fields:
                            # Rimuovi prefisso vendor_ per salvare direttamente
                            field_name = key.replace("vendor_", "")
                            if field_name not in extra_fields:
                                extra_fields[key] = value  # Mantieni anche con prefisso
                                extra_fields[field_name] = value  # Salva anche senza prefisso
                                logger.debug(f"Auto-detect: Saving vendor field {key}={value}")
                    
                    # Log summary of extra fields
                    if extra_fields:
                        logger.info(f"Auto-detect: Saving {len(extra_fields)} extra fields to custom_fields: {list(extra_fields.keys())[:20]}")
                    else:
                        logger.warning(f"Auto-detect: No extra fields found in scan_result. Available keys: {list(scan_result.keys())[:30]}")
                    
                    if extra_fields:
                        # Merge con custom_fields esistenti
                        existing = device.custom_fields or {}
                        if isinstance(existing, str):
                            try:
                                existing = json.loads(existing)
                            except:
                                existing = {}
                        existing.update(extra_fields)
                        device.custom_fields = existing
                        flag_modified(device, "custom_fields")
                        logger.debug(f"Saved {len(extra_fields)} extra fields to custom_fields: {list(extra_fields.keys())}")
                    
                    # Timestamp
                    from datetime import datetime
                    import uuid
                    device.last_scan = datetime.utcnow()
                    
                    # Salva WindowsDetails se disponibili (dati WMI o dati Windows rilevati)
                    # I dati vengono mergeati direttamente in scan_result, non in extra_info
                    # Salva anche se il device è una VM Windows (non necessariamente identificata via WMI)
                    is_windows_device = (
                        device.device_type == "windows" or 
                        "windows" in (device.os_family or "").lower() or 
                        "windows" in (scan_result.get("os_family") or "").lower() or
                        "windows" in (scan_result.get("os_name") or "").lower() or
                        "microsoft" in (scan_result.get("os_name") or "").lower()
                    )
                    has_wmi_data = (
                        "wmi" in scan_result.get("identified_by", "").lower() or  # Supporta probe_wmi, agent_wmi, etc.
                        scan_result.get("domain") or 
                        scan_result.get("server_roles") or 
                        scan_result.get("installed_software") or
                        scan_result.get("local_users")
                    )
                    
                    if is_windows_device and has_wmi_data:
                        try:
                            from ..models.inventory import WindowsDetails
                            # I dati WMI sono mergeati direttamente in scan_result
                            extra_info = scan_result
                            logger.info(f"Saving WindowsDetails for device {data.device_id}, scan_result keys: {list(scan_result.keys())[:20]}")
                            
                            # Estrai dati Windows da scan_result (contiene tutti i dati mergeati)
                            windows_data = {}
                            
                            # Dati OS - usa scan_result che contiene tutti i dati mergeati
                            os_name = scan_result.get("name") or scan_result.get("os_name") or scan_result.get("caption")
                            if os_name:
                                windows_data["edition"] = str(os_name).split("(")[0].strip()
                            elif scan_result.get("os_version") or scan_result.get("version"):
                                # Se non c'è il nome completo, usa almeno la versione
                                windows_data["edition"] = scan_result.get("os_version") or scan_result.get("version")
                            
                            # Domain info - usa scan_result direttamente
                            if scan_result.get("domain"):
                                windows_data["domain_name"] = scan_result.get("domain")
                                # Determina domain role
                                if scan_result.get("is_domain_controller"):
                                    windows_data["domain_role"] = "DC"
                                elif scan_result.get("server_roles") and any("Active Directory" in str(r) or "Domain Controller" in str(r) for r in scan_result.get("server_roles", [])):
                                    windows_data["domain_role"] = "DC"
                                else:
                                    windows_data["domain_role"] = "Workstation" if device.category == "workstation" else "Member Server"
                            
                            # BIOS
                            if scan_result.get("bios_version"):
                                windows_data["bios_version"] = scan_result.get("bios_version")
                            
                            # Updates e reboot
                            if scan_result.get("last_boot"):
                                try:
                                    from datetime import datetime
                                    # WMI restituisce formato WMI datetime
                                    boot_str = str(scan_result.get("last_boot"))
                                    if boot_str:
                                        windows_data["last_reboot"] = datetime.now()  # Placeholder, parsing WMI datetime è complesso
                                except:
                                    pass
                            
                            # Antivirus
                            if scan_result.get("antivirus_name"):
                                windows_data["antivirus_name"] = scan_result.get("antivirus_name")
                            if scan_result.get("antivirus_status"):
                                windows_data["antivirus_status"] = scan_result.get("antivirus_status")
                            
                            # Users
                            if scan_result.get("local_admins"):
                                windows_data["local_admins"] = scan_result.get("local_admins")
                            if scan_result.get("logged_users"):
                                windows_data["logged_users"] = scan_result.get("logged_users")
                            
                            # Software installato
                            if scan_result.get("installed_software"):
                                from ..models.inventory import InstalledSoftware
                                # Elimina vecchio software
                                session.query(InstalledSoftware).filter(InstalledSoftware.device_id == data.device_id).delete()
                                
                                # Salva nuovo software - usa scan_result direttamente
                                for sw in scan_result.get("installed_software", [])[:50]:  # Limita a 50 per evitare troppi dati
                                    try:
                                        sw_obj = InstalledSoftware(
                                            id=uuid.uuid4().hex[:8],
                                            device_id=data.device_id,
                                            name=sw.get("name", ""),
                                            version=sw.get("version"),
                                            vendor=sw.get("vendor"),
                                        )
                                        session.add(sw_obj)
                                    except Exception as sw_error:
                                        logger.debug(f"Error saving software {sw.get('name')}: {sw_error}")
                                        continue
                            
                            # Crea o aggiorna WindowsDetails
                            existing_wd = session.query(WindowsDetails).filter(WindowsDetails.device_id == data.device_id).first()
                            if existing_wd:
                                for key, value in windows_data.items():
                                    if hasattr(existing_wd, key) and value is not None:
                                        setattr(existing_wd, key, value)
                                existing_wd.last_updated = datetime.now()
                            else:
                                if windows_data:
                                    wd = WindowsDetails(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        **{k: v for k, v in windows_data.items() if hasattr(WindowsDetails, k)}
                                    )
                                    session.add(wd)
                                    logger.info(f"Created WindowsDetails for device {data.device_id}")
                        except Exception as e:
                            logger.error(f"Error saving WindowsDetails: {e}", exc_info=True)
                    
                    # Salva LinuxDetails se disponibili (dati SSH o dati Linux rilevati)
                    # I dati vengono mergeati direttamente in scan_result, non in extra_info
                    # Salva anche se il device è una VM Linux (non necessariamente identificata via SSH)
                    os_name_lower = (scan_result.get("os_name") or "").lower()
                    os_id_lower = (scan_result.get("os_id") or "").lower()
                    is_linux_device = (
                        device.device_type == "linux" or 
                        "linux" in (device.os_family or "").lower() or 
                        "linux" in (scan_result.get("os_family") or "").lower() or 
                        any(x in os_name_lower for x in ["ubuntu", "debian", "centos", "rhel", "alpine", "suse", "arch", "linux"]) or
                        any(x in os_id_lower for x in ["ubuntu", "debian", "centos", "rhel", "alpine", "suse", "arch"])
                    )
                    has_ssh_data = (
                        scan_result.get("identified_by", "").startswith("probe_ssh") or 
                        "agent_ssh" in scan_result.get("identified_by", "") or
                        scan_result.get("kernel") or 
                        scan_result.get("distro_name") or 
                        scan_result.get("docker_installed")
                    )
                    
                    if is_linux_device and has_ssh_data:
                        try:
                            from ..models.inventory import LinuxDetails
                            from ..services.linux_details_service import save_advanced_linux_data
                            
                            # I dati SSH sono mergeati direttamente in scan_result
                            logger.info(f"Saving LinuxDetails for device {data.device_id}, scan_result keys: {list(scan_result.keys())[:30]}")
                            
                            # IMPORTANTE: Aggiorna prima i campi base del device per il modal
                            # Questo deve essere fatto sempre, anche per dati non avanzati
                            if scan_result.get("hostname") and not device.hostname:
                                device.hostname = scan_result.get("hostname")
                            if scan_result.get("os_name") or scan_result.get("os_family"):
                                if not device.os_family or device.os_family == "unknown":
                                    device.os_family = scan_result.get("os_family") or "Linux"
                                if not device.os_version:
                                    device.os_version = scan_result.get("os_version")
                            if scan_result.get("cpu_model") and not device.cpu_model:
                                device.cpu_model = scan_result.get("cpu_model")
                            if scan_result.get("cpu_cores") and not device.cpu_cores:
                                device.cpu_cores = scan_result.get("cpu_cores")
                            if scan_result.get("ram_total_gb"):
                                device.ram_total_gb = scan_result.get("ram_total_gb")
                            elif scan_result.get("ram_total_mb"):
                                device.ram_total_gb = round(scan_result.get("ram_total_mb") / 1024, 2)
                            elif scan_result.get("memory_total_mb"):
                                device.ram_total_gb = round(scan_result.get("memory_total_mb") / 1024, 2)
                            if scan_result.get("model") and not device.model:
                                device.model = scan_result.get("model")
                            if scan_result.get("manufacturer") and not device.manufacturer:
                                device.manufacturer = scan_result.get("manufacturer")
                            if scan_result.get("serial_number") and not device.serial_number:
                                device.serial_number = scan_result.get("serial_number")
                            if scan_result.get("device_type") and (not device.device_type or device.device_type == "other"):
                                device.device_type = scan_result.get("device_type")
                            
                            # Controlla se abbiamo dati avanzati (da scanner avanzato)
                            has_advanced_data = (
                                scan_result.get("system_info") or
                                scan_result.get("cpu") or
                                scan_result.get("memory") or
                                scan_result.get("disks") or
                                scan_result.get("volumes") or
                                scan_result.get("raid_arrays") or
                                scan_result.get("network_interfaces") or
                                scan_result.get("services") or
                                scan_result.get("docker") or
                                scan_result.get("vms")
                            )
                            
                            if has_advanced_data:
                                # Usa il servizio avanzato per salvare i dati
                                logger.info(f"Detected advanced SSH scan data, using advanced save service")
                                advanced_data = {
                                    "system_info": scan_result.get("system_info", {}),
                                    "cpu": scan_result.get("cpu", {}),
                                    "memory": scan_result.get("memory", {}),
                                    "disks": scan_result.get("disks", []),
                                    "volumes": scan_result.get("volumes", []),
                                    "raid_arrays": scan_result.get("raid_arrays", []),
                                    "network_interfaces": scan_result.get("network_interfaces", []),
                                    "services": scan_result.get("services", []),
                                    "docker": scan_result.get("docker", {}),
                                    "vms": scan_result.get("vms", []),
                                    "default_gateway": scan_result.get("default_gateway"),
                                    "dns_servers": scan_result.get("dns_servers", []),
                                }
                                
                                # Salva dati avanzati (questo aggiorna anche i campi base di InventoryDevice e LinuxDetails)
                                save_advanced_linux_data(session, data.device_id, advanced_data)
                                logger.info(f"Advanced Linux data saved for device {data.device_id}")
                                
                                # IMPORTANTE: Ricarica il device per assicurarsi che abbia i dati aggiornati
                                session.refresh(device)
                            
                            linux_data = {}
                            
                            # Distro - controlla os_name, os_id, os_family, os_pretty_name
                            distro_name = None
                            if scan_result.get("os_id"):
                                # os_id è solitamente il nome della distro in minuscolo (ubuntu, debian, etc)
                                distro_name = scan_result.get("os_id").capitalize()
                            elif scan_result.get("os_family") and scan_result.get("os_family") != "Linux":
                                distro_name = scan_result.get("os_family")
                            elif scan_result.get("os_name"):
                                # Estrai nome distro da os_name (es: "Ubuntu 24.04.2 LTS")
                                os_name = scan_result.get("os_name", "")
                                if "Ubuntu" in os_name:
                                    distro_name = "Ubuntu"
                                elif "Debian" in os_name:
                                    distro_name = "Debian"
                                elif "CentOS" in os_name or "Rocky" in os_name or "AlmaLinux" in os_name:
                                    distro_name = "RHEL"
                                elif "SUSE" in os_name:
                                    distro_name = "SUSE"
                                elif "Arch" in os_name:
                                    distro_name = "Arch"
                                elif "Alpine" in os_name:
                                    distro_name = "Alpine"
                            
                            if distro_name:
                                linux_data["distro_name"] = distro_name
                            
                            # Distro version
                            if scan_result.get("os_version"):
                                linux_data["distro_version"] = scan_result.get("os_version")
                            
                            # Kernel - controlla kernel e architecture
                            if scan_result.get("kernel"):
                                linux_data["kernel_version"] = scan_result.get("kernel")
                            if scan_result.get("architecture"):
                                linux_data["kernel_arch"] = scan_result.get("architecture")
                            elif scan_result.get("arch"):
                                linux_data["kernel_arch"] = scan_result.get("arch")
                            
                            # Uptime - prova a parsare se disponibile
                            if scan_result.get("uptime"):
                                uptime_str = str(scan_result.get("uptime", ""))
                                # Prova a estrarre giorni dall'uptime
                                if "day" in uptime_str.lower():
                                    try:
                                        import re
                                        days_match = re.search(r'(\d+)\s*day', uptime_str.lower())
                                        if days_match:
                                            linux_data["uptime_days"] = float(days_match.group(1))
                                    except:
                                        pass
                            
                            # Docker - usa scan_result direttamente
                            if scan_result.get("docker_installed"):
                                linux_data["docker_installed"] = True
                                linux_data["docker_version"] = scan_result.get("docker_version")
                            
                            # Virtualization - usa direttamente se presente, altrimenti determina da manufacturer/model
                            if scan_result.get("virtualization"):
                                linux_data["virtualization"] = scan_result.get("virtualization")
                            elif scan_result.get("manufacturer"):
                                manufacturer_lower = scan_result.get("manufacturer", "").lower()
                                if "qemu" in manufacturer_lower or "vmware" in manufacturer_lower or "microsoft" in manufacturer_lower or "virtualbox" in manufacturer_lower:
                                    linux_data["virtualization"] = scan_result.get("manufacturer")
                                elif scan_result.get("model"):
                                    model_lower = scan_result.get("model", "").lower()
                                    if "qemu" in model_lower or "vmware" in model_lower or "virtual" in model_lower:
                                        linux_data["virtualization"] = scan_result.get("model")
                            
                            # Package manager - determina da distro
                            if linux_data.get("distro_name"):
                                distro_lower = linux_data["distro_name"].lower()
                                if distro_lower in ["ubuntu", "debian"]:
                                    linux_data["package_manager"] = "apt"
                                elif distro_lower in ["centos", "rhel", "rocky", "almalinux"]:
                                    linux_data["package_manager"] = "yum"
                                elif distro_lower == "arch":
                                    linux_data["package_manager"] = "pacman"
                                elif distro_lower == "alpine":
                                    linux_data["package_manager"] = "apk"
                            
                            # Init system - la maggior parte dei Linux moderni usa systemd
                            if linux_data.get("distro_name"):
                                linux_data["init_system"] = "systemd"
                            
                            # SSH port
                            if scan_result.get("ssh_port"):
                                linux_data["ssh_port"] = scan_result.get("ssh_port")
                            
                            # Logged users
                            if scan_result.get("shell_users"):
                                linux_data["logged_users"] = scan_result.get("shell_users")
                            
                            # Load average
                            if scan_result.get("load_average"):
                                linux_data["load_average"] = scan_result.get("load_average")
                            
                            # Packages installed count
                            if scan_result.get("packages_installed"):
                                linux_data["packages_installed"] = scan_result.get("packages_installed")
                            
                            # Docker containers running
                            if scan_result.get("docker_containers_running"):
                                linux_data["containers_running"] = scan_result.get("docker_containers_running")
                            
                            logger.info(f"Linux data collected: {list(linux_data.keys())}")
                            
                            # Crea o aggiorna LinuxDetails
                            existing_ld = session.query(LinuxDetails).filter(LinuxDetails.device_id == data.device_id).first()
                            if existing_ld:
                                for key, value in linux_data.items():
                                    if hasattr(existing_ld, key) and value is not None:
                                        setattr(existing_ld, key, value)
                                existing_ld.last_updated = datetime.now()
                                logger.info(f"Updated LinuxDetails for device {data.device_id} with {len(linux_data)} fields")
                            else:
                                if linux_data:
                                    ld = LinuxDetails(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        **{k: v for k, v in linux_data.items() if hasattr(LinuxDetails, k)}
                                    )
                                    session.add(ld)
                                    logger.info(f"Created LinuxDetails for device {data.device_id} with fields: {list(linux_data.keys())}")
                                else:
                                    logger.warning(f"No Linux data to save for device {data.device_id}, available keys: {list(scan_result.keys())[:30]}")
                            
                            # Salva dati estesi Linux in custom_fields
                            extended_linux_data = {}
                            
                            # Servizi attivi
                            if scan_result.get("running_services"):
                                extended_linux_data["running_services"] = scan_result.get("running_services")
                                extended_linux_data["running_services_count"] = scan_result.get("running_services_count", len(scan_result.get("running_services", [])))
                            if scan_result.get("important_services"):
                                extended_linux_data["important_services"] = scan_result.get("important_services")
                            
                            # Cron jobs
                            if scan_result.get("cron_jobs"):
                                extended_linux_data["cron_jobs"] = scan_result.get("cron_jobs")
                                extended_linux_data["cron_jobs_count"] = scan_result.get("cron_jobs_count", len(scan_result.get("cron_jobs", [])))
                            
                            # Hardware inventory
                            if scan_result.get("hardware_inventory"):
                                extended_linux_data["hardware_inventory"] = scan_result.get("hardware_inventory")
                            if scan_result.get("bios_vendor"):
                                extended_linux_data["bios_vendor"] = scan_result.get("bios_vendor")
                            if scan_result.get("bios_version"):
                                extended_linux_data["bios_version"] = scan_result.get("bios_version")
                            if scan_result.get("bios_date"):
                                extended_linux_data["bios_date"] = scan_result.get("bios_date")
                            
                            # Block devices / Dischi
                            if scan_result.get("block_devices"):
                                extended_linux_data["block_devices"] = scan_result.get("block_devices")
                            if scan_result.get("disks"):
                                extended_linux_data["disks"] = scan_result.get("disks")
                            
                            # Network
                            if scan_result.get("ip_addresses"):
                                extended_linux_data["ip_addresses"] = scan_result.get("ip_addresses")
                            if scan_result.get("network_interfaces"):
                                extended_linux_data["network_interfaces"] = scan_result.get("network_interfaces")
                            if scan_result.get("routes"):
                                extended_linux_data["routes"] = scan_result.get("routes")
                            if scan_result.get("default_gateway"):
                                extended_linux_data["default_gateway"] = scan_result.get("default_gateway")
                            if scan_result.get("dns_servers"):
                                extended_linux_data["dns_servers"] = scan_result.get("dns_servers")
                            if scan_result.get("listening_ports"):
                                extended_linux_data["listening_ports"] = scan_result.get("listening_ports")
                            
                            # MAC addresses
                            if scan_result.get("mac_addresses"):
                                extended_linux_data["mac_addresses"] = scan_result.get("mac_addresses")
                            
                            # Timezone
                            if scan_result.get("timezone"):
                                extended_linux_data["timezone"] = scan_result.get("timezone")
                            
                            # Salva in custom_fields se ci sono dati estesi
                            if extended_linux_data:
                                if not device.custom_fields:
                                    device.custom_fields = {}
                                if isinstance(device.custom_fields, str):
                                    try:
                                        device.custom_fields = json.loads(device.custom_fields)
                                    except:
                                        device.custom_fields = {}
                                
                                device.custom_fields.update(extended_linux_data)
                                flag_modified(device, "custom_fields")
                                logger.info(f"Saved extended Linux data to custom_fields for device {data.device_id}: {list(extended_linux_data.keys())}")
                        except Exception as e:
                            logger.error(f"Error saving LinuxDetails: {e}", exc_info=True)
                    
                    # Salva storage_info se disponibile (Synology/QNAP)
                    if scan_result.get("storage_info"):
                        try:
                            storage_info = scan_result.get("storage_info")
                            if not device.custom_fields:
                                device.custom_fields = {}
                            if isinstance(device.custom_fields, str):
                                try:
                                    device.custom_fields = json.loads(device.custom_fields)
                                except:
                                    device.custom_fields = {}
                            device.custom_fields["storage_info"] = storage_info
                            flag_modified(device, "custom_fields")
                            logger.info(f"Saved storage_info to custom_fields for device {data.device_id}: volumes={len(storage_info.get('volumes', []))}, disks={len(storage_info.get('disks', []))}, raid={storage_info.get('raid') is not None}")
                        except Exception as e:
                            logger.error(f"Error saving storage_info: {e}", exc_info=True)
                    
                    # Salva MikroTikDetails se disponibili
                    # I dati vengono mergeati direttamente in scan_result, non in extra_info
                    # MikroTik può essere identificato come probe_mikrotik_api o probe_ssh
                    if device.device_type == "mikrotik" and scan_result.get("identified_by"):
                        try:
                            from ..models.inventory import MikroTikDetails
                            # I dati MikroTik sono mergeati direttamente in scan_result
                            logger.info(f"Saving MikroTikDetails for device {data.device_id}, identified_by={scan_result.get('identified_by')}, scan_result keys: {list(scan_result.keys())[:20]}")
                            
                            mikrotik_data = {}
                            
                            # RouterOS version
                            if scan_result.get("os_version"):
                                mikrotik_data["routeros_version"] = scan_result.get("os_version")
                            
                            # Hardware - model può essere in model o board_name
                            if scan_result.get("model"):
                                mikrotik_data["board_name"] = scan_result.get("model")
                            if scan_result.get("architecture"):
                                mikrotik_data["platform"] = scan_result.get("architecture")
                            elif scan_result.get("arch"):
                                mikrotik_data["platform"] = scan_result.get("arch")
                            
                            # CPU
                            if scan_result.get("cpu_model"):
                                mikrotik_data["cpu_model"] = scan_result.get("cpu_model")
                            if scan_result.get("cpu_cores"):
                                mikrotik_data["cpu_count"] = scan_result.get("cpu_cores")
                            
                            # Memoria
                            if scan_result.get("ram_total_mb"):
                                mikrotik_data["memory_total_mb"] = scan_result.get("ram_total_mb")
                            elif scan_result.get("memory_total_mb"):
                                mikrotik_data["memory_total_mb"] = scan_result.get("memory_total_mb")
                            if scan_result.get("ram_free_mb"):
                                mikrotik_data["memory_free_mb"] = scan_result.get("ram_free_mb")
                            
                            # Identity
                            if scan_result.get("hostname"):
                                mikrotik_data["identity"] = scan_result.get("hostname")
                            
                            # License
                            if scan_result.get("license_level"):
                                mikrotik_data["license_level"] = scan_result.get("license_level")
                            
                            # Firmware
                            if scan_result.get("firmware"):
                                mikrotik_data["firmware_version"] = scan_result.get("firmware")
                            
                            # Uptime
                            if scan_result.get("uptime"):
                                mikrotik_data["uptime"] = scan_result.get("uptime")
                            
                            # Crea o aggiorna MikroTikDetails
                            existing_md = session.query(MikroTikDetails).filter(MikroTikDetails.device_id == data.device_id).first()
                            if existing_md:
                                for key, value in mikrotik_data.items():
                                    if hasattr(existing_md, key) and value is not None:
                                        setattr(existing_md, key, value)
                                existing_md.last_updated = datetime.now()
                            else:
                                if mikrotik_data:
                                    md = MikroTikDetails(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        **{k: v for k, v in mikrotik_data.items() if hasattr(MikroTikDetails, k)}
                                    )
                                    session.add(md)
                                    logger.info(f"Created MikroTikDetails for device {data.device_id}")
                            
                            # Salva routing e ARP in custom_fields se raccolti durante auto-detect
                            if scan_result.get("routing_table") or scan_result.get("arp_table"):
                                if not device.custom_fields:
                                    device.custom_fields = {}
                                if isinstance(device.custom_fields, str):
                                    try:
                                        device.custom_fields = json.loads(device.custom_fields)
                                    except:
                                        device.custom_fields = {}
                                
                                if scan_result.get("routing_table"):
                                    device.custom_fields["routing_table"] = scan_result.get("routing_table")
                                    device.custom_fields["routing_count"] = scan_result.get("routing_count", 0)
                                
                                if scan_result.get("arp_table"):
                                    device.custom_fields["arp_table"] = scan_result.get("arp_table")
                                    device.custom_fields["arp_count"] = scan_result.get("arp_count", 0)
                                
                                # Neighbors (LLDP/CDP/MNDP)
                                if scan_result.get("neighbors"):
                                    device.custom_fields["neighbors"] = scan_result.get("neighbors")
                                    device.custom_fields["neighbors_count"] = scan_result.get("neighbors_count", 0)
                                
                                flag_modified(device, "custom_fields")
                                logger.info(f"Saved routing/ARP/neighbors data to custom_fields for MikroTik device {data.device_id}")
                        except Exception as e:
                            logger.error(f"Error saving MikroTikDetails: {e}", exc_info=True)
                    
                    # Salva LLDP neighbors se raccolti durante auto-detect
                    if scan_result.get("lldp_neighbors"):
                        try:
                            from ..models.inventory import LLDPNeighbor
                            
                            # Elimina vecchi neighbor per questo device
                            session.query(LLDPNeighbor).filter(LLDPNeighbor.device_id == data.device_id).delete()
                            
                            for neighbor_data in scan_result.get("lldp_neighbors", []):
                                # Normalizza i nomi dei campi (supporta sia formato standard che formato MikroTik)
                                local_interface = neighbor_data.get("local_interface", "")
                                remote_device_name = neighbor_data.get("remote_device_name") or neighbor_data.get("identity", "")
                                remote_interface = neighbor_data.get("remote_interface") or neighbor_data.get("remote_port", "")
                                remote_mac = neighbor_data.get("remote_mac") or neighbor_data.get("mac_address", "")
                                remote_ip = neighbor_data.get("remote_ip") or neighbor_data.get("ip_address", "")
                                chassis_id = neighbor_data.get("chassis_id") or neighbor_data.get("mac_address", "")
                                chassis_id_type = neighbor_data.get("chassis_id_type", "")
                                
                                # Se abbiamo almeno local_interface e remote_device_name, salva
                                if local_interface and remote_device_name:
                                    lldp = LLDPNeighbor(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        local_interface=local_interface,
                                        remote_device_name=remote_device_name,
                                        remote_device_description=neighbor_data.get("remote_device_description") or neighbor_data.get("platform", ""),
                                        remote_port=remote_interface,
                                        remote_mac=remote_mac,
                                        remote_ip=remote_ip,
                                        chassis_id=chassis_id,
                                        chassis_id_type=chassis_id_type,
                                        capabilities=neighbor_data.get("capabilities"),
                                    )
                                    session.add(lldp)
                            
                            logger.info(f"Saved {len(scan_result.get('lldp_neighbors', []))} LLDP neighbors for device {data.device_id}")
                        except Exception as e:
                            logger.error(f"Error saving LLDP neighbors: {e}", exc_info=True)
                    
                    # Salva CDP neighbors se raccolti durante auto-detect
                    if scan_result.get("cdp_neighbors"):
                        try:
                            from ..models.inventory import CDPNeighbor
                            
                            # Elimina vecchi neighbor per questo device
                            session.query(CDPNeighbor).filter(CDPNeighbor.device_id == data.device_id).delete()
                            
                            for neighbor_data in scan_result.get("cdp_neighbors", []):
                                cdp = CDPNeighbor(
                                    id=uuid.uuid4().hex[:8],
                                    device_id=data.device_id,
                                    local_interface=neighbor_data.get("local_interface", ""),
                                    remote_device_name=neighbor_data.get("remote_device_name", ""),
                                    remote_interface=neighbor_data.get("remote_interface", ""),
                                    remote_mac=neighbor_data.get("remote_mac", ""),
                                    remote_ip=neighbor_data.get("remote_ip", ""),
                                    remote_platform=neighbor_data.get("remote_platform", ""),
                                    capabilities=neighbor_data.get("capabilities", {}),
                                )
                                session.add(cdp)
                            
                            logger.info(f"Saved {len(scan_result.get('cdp_neighbors', []))} CDP neighbors for device {data.device_id}")
                        except Exception as e:
                            logger.error(f"Error saving CDP neighbors: {e}", exc_info=True)
                    
                    # Salva interfacce se raccolte durante auto-detect
                    if scan_result.get("interface_details"):
                        try:
                            from ..models.inventory import NetworkInterface
                            
                            for iface_data in scan_result.get("interface_details", []):
                                # Aggiorna o crea interfaccia
                                existing = session.query(NetworkInterface).filter(
                                    NetworkInterface.device_id == data.device_id,
                                    NetworkInterface.name == iface_data.get("name")
                                ).first()
                                
                                if existing:
                                    for key, value in iface_data.items():
                                        if hasattr(existing, key) and value is not None:
                                            setattr(existing, key, value)
                                    existing.last_updated = datetime.now()
                                else:
                                    new_iface = NetworkInterface(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        name=iface_data.get("name", ""),
                                        description=iface_data.get("description"),
                                        interface_type=iface_data.get("interface_type"),
                                        mac_address=iface_data.get("mac_address"),
                                        ip_addresses=iface_data.get("ip_addresses"),
                                        speed_mbps=iface_data.get("speed_mbps"),
                                        admin_status=iface_data.get("admin_status"),
                                        oper_status=iface_data.get("oper_status"),
                                    )
                                    session.add(new_iface)
                            
                            logger.info(f"Saved {len(scan_result.get('interface_details', []))} interfaces for device {data.device_id}")
                        except Exception as e:
                            logger.error(f"Error saving interfaces: {e}", exc_info=True)
                    
                    # Salva dati avanzati per dispositivi SNMP e SSH network (Cisco, HP, Ubiquiti, Omada, etc.)
                    # Non MikroTik (già gestito sopra)
                    is_mikrotik = (
                        device.device_type == "mikrotik" or 
                        "mikrotik" in (scan_result.get("vendor") or scan_result.get("manufacturer") or "").lower() or 
                        "routeros" in (scan_result.get("os_name") or "").lower()
                    )
                    is_network_device = (
                        device.device_type in ["router", "switch", "ap", "network"] or
                        device.category == "network" or
                        scan_result.get("device_type") in ["router", "switch", "ap", "network"] or
                        scan_result.get("category") == "network"
                    )
                    is_snmp_or_ssh_network = (
                        "snmp" in scan_result.get("identified_by", "").lower() or
                        ("ssh" in scan_result.get("identified_by", "").lower() and is_network_device) or
                        scan_result.get("vendor") in ["Cisco", "HP", "Ubiquiti", "TP-Link"] or
                        scan_result.get("os_name") in ["IOS", "Comware", "ProCurve", "ArubaOS", "EdgeOS", "Omada"]
                    )
                    
                    # Salva dati vendor-specific per tutti i dispositivi di rete (incluso MikroTik)
                    if is_network_device or is_mikrotik:
                        try:
                            # Salva routing_table, arp_table, dhcp_leases, vlan_info in custom_fields
                            if not device.custom_fields:
                                device.custom_fields = {}
                            
                            # Routing table
                            if scan_result.get("routing_table"):
                                device.custom_fields["routing_table"] = scan_result.get("routing_table")
                            
                            # ARP table
                            if scan_result.get("arp_table"):
                                device.custom_fields["arp_table"] = scan_result.get("arp_table")
                            
                            # DHCP leases (solo MikroTik)
                            if is_mikrotik and scan_result.get("dhcp_leases"):
                                device.custom_fields["dhcp_leases"] = scan_result.get("dhcp_leases")
                            
                            # VLAN info
                            if scan_result.get("vlan_info"):
                                device.custom_fields["vlan_info"] = scan_result.get("vlan_info")
                            
                            logger.info(f"Saved vendor-specific data for device {data.device_id}: routing_table={bool(scan_result.get('routing_table'))}, arp_table={bool(scan_result.get('arp_table'))}, dhcp_leases={bool(scan_result.get('dhcp_leases'))}, vlan_info={bool(scan_result.get('vlan_info'))}")
                        except Exception as e:
                            logger.error(f"Error saving vendor-specific data: {e}", exc_info=True)
                    
                    if is_network_device and is_snmp_or_ssh_network and not is_mikrotik:
                        try:
                            # Salva neighbors, routing_table, arp_table, interfaces in custom_fields
                            network_data = {}
                            
                            # Neighbors (LLDP/CDP)
                            if scan_result.get("neighbors") or scan_result.get("lldp_neighbors") or scan_result.get("cdp_neighbors"):
                                neighbors_list = []
                                if scan_result.get("neighbors"):
                                    neighbors_list = scan_result.get("neighbors")
                                elif scan_result.get("lldp_neighbors"):
                                    neighbors_list = scan_result.get("lldp_neighbors")
                                elif scan_result.get("cdp_neighbors"):
                                    neighbors_list = scan_result.get("cdp_neighbors")
                                
                                if neighbors_list:
                                    network_data["neighbors"] = neighbors_list
                                    network_data["neighbors_count"] = len(neighbors_list)
                            
                            # Routing Table
                            if scan_result.get("routing_table"):
                                network_data["routing_table"] = scan_result.get("routing_table")
                                network_data["routing_count"] = scan_result.get("routing_count", len(scan_result.get("routing_table", [])))
                            
                            # ARP Table (solo per router)
                            if scan_result.get("arp_table") and (device.device_type == "router" or scan_result.get("device_type") == "router"):
                                network_data["arp_table"] = scan_result.get("arp_table")
                                network_data["arp_count"] = scan_result.get("arp_count", len(scan_result.get("arp_table", [])))
                            
                            # Interfaces
                            if scan_result.get("interfaces"):
                                network_data["interfaces"] = scan_result.get("interfaces")
                                network_data["interfaces_count"] = scan_result.get("interfaces_count", len(scan_result.get("interfaces", [])))
                            
                            # Salva in custom_fields se ci sono dati
                            if network_data:
                                if not device.custom_fields:
                                    device.custom_fields = {}
                                if isinstance(device.custom_fields, str):
                                    try:
                                        device.custom_fields = json.loads(device.custom_fields)
                                    except:
                                        device.custom_fields = {}
                                
                                device.custom_fields.update(network_data)
                                flag_modified(device, "custom_fields")
                                logger.info(f"Saved network data to custom_fields for device {data.device_id}: {list(network_data.keys())}")
                        except Exception as e:
                            logger.error(f"Error saving network device data: {e}", exc_info=True)
                    
                    # Salva informazioni Proxmox se disponibili (raccolte durante autodetect)
                    if scan_result.get("proxmox_host_info") or scan_result.get("proxmox_vms") or scan_result.get("proxmox_storage"):
                        try:
                            from ..models.inventory import ProxmoxHost, ProxmoxVM, ProxmoxStorage
                            import uuid
                            
                            host_info = scan_result.get("proxmox_host_info")
                            if host_info:
                                # Aggiorna o crea ProxmoxHost
                                existing_host = session.query(ProxmoxHost).filter(
                                    ProxmoxHost.device_id == data.device_id
                                ).first()
                                
                                if existing_host:
                                    # Aggiorna
                                    for key, value in host_info.items():
                                        if hasattr(existing_host, key):
                                            setattr(existing_host, key, value)
                                    existing_host.last_updated = datetime.now()
                                    host_id = existing_host.id
                                else:
                                    # Crea nuovo
                                    new_host = ProxmoxHost(
                                        id=uuid.uuid4().hex[:8],
                                        device_id=data.device_id,
                                        **{k: v for k, v in host_info.items() if hasattr(ProxmoxHost, k)}
                                    )
                                    session.add(new_host)
                                    session.flush()
                                    host_id = new_host.id
                                
                                # Salva VM
                                if scan_result.get("proxmox_vms"):
                                    # Elimina vecchie VM
                                    session.query(ProxmoxVM).filter(ProxmoxVM.host_id == host_id).delete()
                                    
                                    # Salva nuove VM con conversione safe_int/safe_float
                                    def safe_int(value):
                                        if value is None:
                                            return None
                                        try:
                                            return int(value)
                                        except (ValueError, TypeError):
                                            return None
                                    
                                    def safe_float(value):
                                        if value is None:
                                            return None
                                        try:
                                            return float(value)
                                        except (ValueError, TypeError):
                                            return None
                                    
                                    # Funzione helper per creare dispositivi inventory per VM
                                    def create_vm_inventory_devices(vms_data, host_device):
                                        from ..models.inventory import InventoryDevice
                                        created_count = 0
                                        for vm_data_item in vms_data:
                                            try:
                                                vm_data_clean_item = {k: v for k, v in vm_data_item.items() if k != 'vmid'}
                                                ip_addresses_str = vm_data_clean_item.get("ip_addresses")
                                                
                                                # Estrai il primo IP valido
                                                primary_ip = None
                                                if ip_addresses_str:
                                                    ips = [ip.strip() for ip in ip_addresses_str.split(';') if ip.strip()]
                                                    for ip in ips:
                                                        if not ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                                                            primary_ip = ip
                                                            break
                                                
                                                if primary_ip:
                                                    vm_name = vm_data_clean_item.get("name", f"VM-{vm_data_clean_item.get('vm_id', 'unknown')}")
                                                    vm_type = vm_data_clean_item.get("type", "qemu")
                                                    
                                                    existing = session.query(InventoryDevice).filter(
                                                        InventoryDevice.customer_id == customer_id,
                                                        InventoryDevice.primary_ip == primary_ip
                                                    ).first()
                                                    
                                                    if not existing:
                                                        device_type = "linux" if vm_type == "lxc" else "server"
                                                        category = "vm" if vm_type == "qemu" else "container"
                                                        
                                                        os_family = None
                                                        os_type = vm_data_clean_item.get("os_type", "").lower()
                                                        if "windows" in os_type or "win" in os_type:
                                                            os_family = "Windows"
                                                            device_type = "windows"
                                                        elif "linux" in os_type or "debian" in os_type or "ubuntu" in os_type:
                                                            os_family = "Linux"
                                                        elif "bsd" in os_type:
                                                            os_family = "BSD"
                                                        
                                                        new_vm_device = InventoryDevice(
                                                            customer_id=customer_id,
                                                            name=f"{vm_name} (VM)",
                                                            hostname=vm_name,
                                                            device_type=device_type,
                                                            category=category,
                                                            primary_ip=primary_ip,
                                                            manufacturer="Proxmox",
                                                            os_family=os_family,
                                                            cpu_cores=safe_int(vm_data_clean_item.get("cpu_cores")),
                                                            ram_total_gb=safe_float(vm_data_clean_item.get("memory_mb")) / 1024.0 if vm_data_clean_item.get("memory_mb") else None,
                                                            identified_by="proxmox_vm",
                                                            status=vm_data_clean_item.get("status", "unknown"),
                                                            description=f"Proxmox {vm_type.upper()} VM su host {host_device.name if host_device else 'Unknown'}",
                                                            last_seen=datetime.now(),
                                                        )
                                                        session.add(new_vm_device)
                                                        created_count += 1
                                                        logger.info(f"Created inventory device for VM {vm_name} ({primary_ip})")
                                            except Exception as e:
                                                logger.error(f"Error creating inventory device for VM: {e}", exc_info=True)
                                                continue
                                        return created_count
                                    
                                    for vm_data in scan_result["proxmox_vms"]:
                                        try:
                                            # Rimuovi 'vmid' se presente per evitare errori
                                            vm_data_clean = {k: v for k, v in vm_data.items() if k != 'vmid'}
                                            vm = ProxmoxVM(
                                                id=uuid.uuid4().hex[:8],
                                                host_id=host_id,
                                                vm_id=safe_int(vm_data_clean.get("vm_id", vm_data.get("vmid", 0))),
                                                vm_type=vm_data_clean.get("type"),  # qemu, lxc
                                                name=vm_data_clean.get("name", ""),
                                                status=vm_data_clean.get("status"),
                                                cpu_cores=safe_int(vm_data_clean.get("cpu_cores")),
                                                cpu_sockets=safe_int(vm_data_clean.get("cpu_sockets")),
                                                cpu_total=safe_int(vm_data_clean.get("cpu_total")),
                                                memory_mb=safe_int(vm_data_clean.get("memory_mb", vm_data_clean.get("memory_total_mb"))),
                                                disk_total_gb=safe_float(vm_data_clean.get("disk_total_gb")),
                                                bios=vm_data_clean.get("bios"),
                                                machine=vm_data_clean.get("machine"),
                                                agent_installed=vm_data_clean.get("agent_installed"),
                                                network_interfaces=vm_data_clean.get("network_interfaces"),
                                                num_networks=safe_int(vm_data_clean.get("num_networks")),
                                                networks=vm_data_clean.get("networks"),
                                                ip_addresses=vm_data_clean.get("ip_addresses"),
                                                num_disks=safe_int(vm_data_clean.get("num_disks")),
                                                disks=vm_data_clean.get("disks"),
                                                disks_details=vm_data_clean.get("disks_details"),
                                                os_type=vm_data_clean.get("os_type", vm_data_clean.get("guest_os")),
                                                template=vm_data_clean.get("template", False),
                                                uptime=safe_int(vm_data_clean.get("uptime")),
                                                cpu_usage=safe_float(vm_data_clean.get("cpu_usage")),
                                                mem_used=safe_int(vm_data_clean.get("mem_used")),
                                                netin=safe_int(vm_data_clean.get("netin")),
                                                netout=safe_int(vm_data_clean.get("netout")),
                                                diskread=safe_int(vm_data_clean.get("diskread")),
                                                diskwrite=safe_int(vm_data_clean.get("diskwrite")),
                                            )
                                            session.add(vm)
                                        except Exception as vm_error:
                                            logger.error("Error saving VM {}: {}", vm_data_clean.get('vm_id', 'unknown'), vm_error, exc_info=True)
                                            continue
                                    
                                    try:
                                        session.flush()  # Flush prima del commit per verificare errori
                                        logger.info("Auto-detect: Flushed %d Proxmox VMs for device %s", len(scan_result['proxmox_vms']), data.device_id)
                                        
                                        # v3.0.0: Aggiunta VM all'inventario è ora MANUALE
                                        # Le VM vengono salvate in ProxmoxVM ma non aggiunte automaticamente
                                        # all'inventario. Usare endpoint /proxmox/create-vm-devices per aggiungerle manualmente.
                                        # 
                                        # COMMENTATO - Era chiamata automatica:
                                        # device = session.query(InventoryDevice).filter(InventoryDevice.id == data.device_id).first()
                                        # if device:
                                        #     created_count = create_vm_inventory_devices(scan_result["proxmox_vms"], device)
                                        #     if created_count > 0:
                                        #         logger.info(f"Created {created_count} inventory devices for Proxmox VMs")
                                        logger.info("v3.0.0: Proxmox VMs saved to ProxmoxVM table. Use /proxmox/create-vm-devices to add to inventory manually.")
                                    except Exception as flush_error:
                                        import traceback
                                        flush_trace = traceback.format_exc()
                                        logger.error("Error flushing VMs to database: {}\n{}", flush_error, flush_trace, exc_info=False)
                                        raise
                                
                                # Salva storage
                                if scan_result.get("proxmox_storage"):
                                    # Elimina vecchio storage
                                    session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id == host_id).delete()
                                    
                                    # Salva nuovo storage
                                    for storage_data in scan_result["proxmox_storage"]:
                                        # Calcola usage_percent se disponibile
                                        usage_percent = None
                                        total_gb = storage_data.get("total_gb")
                                        used_gb = storage_data.get("used_gb")
                                        if total_gb and used_gb and total_gb > 0:
                                            usage_percent = round((used_gb / total_gb) * 100, 2)
                                        
                                        storage = ProxmoxStorage(
                                            id=uuid.uuid4().hex[:8],
                                            host_id=host_id,
                                            storage_name=storage_data.get("storage"),
                                            storage_type=storage_data.get("type"),
                                            total_gb=total_gb,
                                            used_gb=used_gb,
                                            available_gb=storage_data.get("available_gb", storage_data.get("free_gb")),  # Campo corretto: available_gb
                                            usage_percent=usage_percent,
                                            content_types=storage_data.get("content", []),
                                        )
                                        session.add(storage)
                                    
                                    try:
                                        session.flush()  # Flush prima del commit per verificare errori
                                        logger.info("Auto-detect: Flushed %d Proxmox storage for device %s", len(scan_result['proxmox_storage']), data.device_id)
                                    except Exception as flush_error:
                                        logger.error("Error flushing storage to database: %s", str(flush_error), exc_info=True)
                                        raise
                        except Exception as e:
                            import traceback
                            error_trace = traceback.format_exc()
                            logger.error("Error saving Proxmox info during auto-detect for device {}: {}\n{}", data.device_id, e, error_trace, exc_info=False)
                            # Non fare raise qui, continua con il commit degli altri dati
                    
                    try:
                        session.commit()
                        logger.info("Auto-detect: Successfully committed all data for device %s", data.device_id)
                    except Exception as commit_error:
                        import traceback
                        commit_trace = traceback.format_exc()
                        logger.error("Error committing Proxmox data for device {}: {}\n{}", data.device_id, commit_error, commit_trace, exc_info=False)
                        session.rollback()
                        raise
                    logger.info(f"Auto-detect: Saved results to device {data.device_id} - hostname={device.hostname}, os={device.os_family}, cpu={device.cpu_model}")
                    result["saved"] = True
            except Exception as save_err:
                logger.error("Failed to save auto-detect results: {}", save_err, exc_info=True)
                session.rollback()
                result["save_error"] = str(save_err)
            finally:
                session.close()
        
    except Exception as e:
        logger.error(f"Auto-detect failed for {data.address}: {e}")
        result["error"] = str(e)
    
    return result


def _get_credentials_for_protocols(
    device_id: str,
    protocols: List[str],
    customer_id: str,
    customer_service,
    use_assigned: bool = True,
    use_defaults: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Recupera credenziali per multipli protocolli con fallback intelligente.
    
    Args:
        device_id: ID dispositivo
        protocols: Lista protocolli ['ssh', 'snmp', 'winrm']
        customer_id: ID cliente
        customer_service: Istanza CustomerService
        use_assigned: Usa credenziali assegnate al device
        use_defaults: Usa credenziali di default del cliente
    
    Returns:
        Dict[protocol: credential_dict]
    """
    from ..models.inventory import InventoryDevice
    from ..models.database import Credential as CredentialDB
    from ..services.encryption_service import get_encryption_service
    
    credentials = {}
    encryption = get_encryption_service()
    session = customer_service._get_session()
    
    try:
        device_record = None
        if use_assigned:
            device_record = session.query(InventoryDevice).filter(
                InventoryDevice.id == device_id
            ).first()
        
        # Per ogni protocollo, cerca credenziali
        for protocol in protocols:
            cred_dict = None
            logger.debug(f"Looking for {protocol} credentials for device {device_id}")
            
            # 1. Credenziale assegnata al device per questo protocollo
            if use_assigned and device_record and device_record.credential_id:
                cred = session.query(CredentialDB).filter(
                    CredentialDB.id == device_record.credential_id
                ).first()
                
                logger.debug(f"Device credential: {cred.name if cred else None} (type={cred.credential_type if cred else None})")
                
                if cred and cred.credential_type == protocol:
                    logger.info(f"Using device credential {cred.name} for {protocol}")
                    cred_dict = _decrypt_credential_to_dict(cred, encryption, protocol)
                    logger.debug(f"Decrypted {protocol} cred: username={cred_dict.get('username')}, has_password={bool(cred_dict.get('password'))}")
            
            # 2. Credenziale di default del cliente per questo protocollo
            if not cred_dict and use_defaults:
                default_creds = customer_service.get_default_credentials_by_type(
                    customer_id=customer_id,
                    credential_types=[protocol]
                )
                
                if default_creds and protocol in default_creds:
                    cred = default_creds[protocol]
                    cred_dict = _decrypt_credential_to_dict(cred, encryption, protocol)
            
            # 3. Credenziale globale per questo protocollo
            if not cred_dict:
                logger.debug(f"No device/default cred for {protocol}, trying global")
                global_creds = customer_service.list_global_credentials(
                    credential_type=protocol,
                    active_only=True
                )
                logger.debug(f"Found {len(global_creds) if global_creds else 0} global {protocol} credentials")
                if global_creds:
                    cred = global_creds[0]  # Prendi la prima
                    # Recupera credenziale completa con secrets
                    full_cred = session.query(CredentialDB).filter(
                        CredentialDB.id == cred.id
                    ).first()
                    if full_cred:
                        cred_dict = _decrypt_credential_to_dict(full_cred, encryption, protocol)
            
            # 3b. Per WinRM, se non trovata, prova a usare credenziali WMI
            if not cred_dict and protocol == "winrm":
                # Cerca credenziali WMI assegnate al device
                if use_assigned and device_record and device_record.credential_id:
                    cred = session.query(CredentialDB).filter(
                        CredentialDB.id == device_record.credential_id
                    ).first()
                    if cred and cred.credential_type == "wmi":
                        cred_dict = _decrypt_credential_to_dict(cred, encryption, "wmi")
                        # Converti WMI a WinRM (stessi parametri)
                        if cred_dict:
                            logger.info(f"Using WMI credentials for WinRM on device {device_id}")
                
                # Se ancora non trovata, cerca WMI di default del cliente
                if not cred_dict and use_defaults:
                    default_creds = customer_service.get_default_credentials_by_type(
                        customer_id=customer_id,
                        credential_types=["wmi"]
                    )
                    if default_creds and "wmi" in default_creds:
                        cred = default_creds["wmi"]
                        cred_dict = _decrypt_credential_to_dict(cred, encryption, "wmi")
                        if cred_dict:
                            logger.info(f"Using default WMI credentials for WinRM")
                
                # Se ancora non trovata, cerca WMI globale
                if not cred_dict:
                    global_creds = customer_service.list_global_credentials(
                        credential_type="wmi",
                        active_only=True
                    )
                    if global_creds:
                        cred = global_creds[0]
                        full_cred = session.query(CredentialDB).filter(
                            CredentialDB.id == cred.id
                        ).first()
                        if full_cred:
                            cred_dict = _decrypt_credential_to_dict(full_cred, encryption, "wmi")
                            if cred_dict:
                                logger.info(f"Using global WMI credentials for WinRM")
            
            # 4. Default per SNMP (solo se non trovata)
            if not cred_dict and protocol == "snmp":
                cred_dict = {
                    "community": "public",
                    "version": "2c",
                    "port": 161
                }
            
            if cred_dict:
                credentials[protocol] = cred_dict
                
    finally:
        session.close()
    
    return credentials


def _decrypt_credential_to_dict(cred, encryption, protocol: str) -> Dict[str, Any]:
    """Converte Credential in dict con valori decriptati"""
    result = {}
    
    logger.debug(f"_decrypt_credential_to_dict: protocol={protocol}, cred.id={cred.id}, cred.name={cred.name}")
    
    if protocol == "ssh":
        result["username"] = cred.username
        logger.debug(f"SSH cred: username={cred.username}, has_password={bool(cred.password)}, password_type={type(cred.password)}")
        if cred.password:
            logger.debug(f"SSH password value: {str(cred.password)[:50]}...")
            try:
                result["password"] = encryption.decrypt(cred.password)
                logger.info(f"SSH password decrypted OK for user {cred.username}")
            except Exception as e:
                logger.error(f"SSH password decrypt failed for {cred.username}: {e}")
        if cred.ssh_private_key:
            try:
                result["private_key"] = encryption.decrypt(cred.ssh_private_key)
            except:
                pass
        result["port"] = cred.ssh_port or 22
    
    elif protocol == "snmp":
        if cred.snmp_community:
            try:
                result["community"] = encryption.decrypt(cred.snmp_community)
            except:
                # Se decrypt fallisce, prova come plain text
                result["community"] = cred.snmp_community
        else:
            result["community"] = "public"
        result["version"] = cred.snmp_version or 2
        result["port"] = cred.snmp_port or 161
    
    elif protocol == "wmi" or protocol == "winrm":
        result["username"] = cred.username
        if cred.password:
            try:
                result["password"] = encryption.decrypt(cred.password)
            except:
                pass
        result["domain"] = cred.wmi_domain or ""
        result["port"] = 5985  # Default WinRM
    
    return result


@router.post("/auto-detect-batch")
async def auto_detect_batch(
    data: BulkAutoDetectRequest,
    customer_id: str = Query(...),
):
    """
    Esegue auto-detect su più dispositivi in parallelo.
    """
    import asyncio
    
    results = []
    
    async def detect_one(device: AutoDetectRequest):
        return await auto_detect_device(device, customer_id)
    
    # Esegui in parallelo (max 5 alla volta per evitare sovraccarico)
    semaphore = asyncio.Semaphore(5)
    
    async def detect_with_semaphore(device):
        async with semaphore:
            return await detect_one(device)
    
    tasks = [detect_with_semaphore(d) for d in data.devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Processa risultati
    processed = []
    success_count = 0
    identified_count = 0
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            processed.append({
                "address": data.devices[i].address,
                "success": False,
                "error": str(result),
            })
        else:
            processed.append(result)
            if result.get("success"):
                success_count += 1
            if result.get("identified"):
                identified_count += 1
    
    return {
        "success": True,
        "total": len(data.devices),
        "scanned": success_count,
        "identified": identified_count,
        "results": processed,
    }


@router.post("/probe-devices")
async def probe_multiple_devices(
    data: BulkProbeRequest,
    customer_id: str = Query(...),
):
    """
    Esegue probe su più dispositivi in parallelo.
    """
    from ..services.device_probe_service import get_device_probe_service
    from ..services.customer_service import get_customer_service
    import asyncio
    
    probe_service = get_device_probe_service()
    customer_service = get_customer_service()
    
    # Recupera credenziali comuni
    credentials_list = []
    credential_ids = data.credential_ids or []
    
    if credential_ids:
        for cred_id in credential_ids:
            cred = customer_service.get_credential(cred_id, include_secrets=True)
            if cred:
                credentials_list.append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.credential_type,
                    "username": cred.username,
                    "password": cred.password,
                    "ssh_port": getattr(cred, 'ssh_port', 22),
                    "ssh_private_key": getattr(cred, 'ssh_private_key', None),
                    "snmp_community": getattr(cred, 'snmp_community', None),
                    "snmp_version": getattr(cred, 'snmp_version', '2c'),
                    "snmp_port": getattr(cred, 'snmp_port', 161),
                    "wmi_domain": getattr(cred, 'wmi_domain', None),
                    "mikrotik_api_port": getattr(cred, 'mikrotik_api_port', 8728),
                })
    
    # Probe paralleli
    async def probe_one(device):
        device_creds = credentials_list.copy()
        if device.credential_ids:
            # Aggiungi credenziali specifiche per questo device
            for cred_id in device.credential_ids:
                if cred_id not in credential_ids:
                    cred = customer_service.get_credential(cred_id, include_secrets=True)
                    if cred:
                        device_creds.append({
                            "id": cred.id,
                            "name": cred.name,
                            "type": cred.credential_type,
                            "username": cred.username,
                            "password": cred.password,
                            "ssh_port": getattr(cred, 'ssh_port', 22),
                            "snmp_community": getattr(cred, 'snmp_community', None),
                        })
        
        return await probe_service.auto_identify_device(
            address=device.address,
            mac_address=device.mac_address,
            credentials_list=device_creds
        )
    
    tasks = [probe_one(d) for d in data.devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Formatta risultati
    formatted = []
    for device, result in zip(data.devices, results):
        if isinstance(result, Exception):
            formatted.append({
                "address": device.address,
                "mac_address": device.mac_address,
                "error": str(result),
            })
        else:
            formatted.append(result)
    
    return {
        "success": True,
        "results": formatted,
        "probed": len([r for r in formatted if not r.get("error")]),
        "errors": len([r for r in formatted if r.get("error")]),
    }


@router.get("/detect-protocols/{address}")
async def detect_protocols(address: str):
    """Rileva quali protocolli sono disponibili su un host"""
    from ..services.device_probe_service import get_device_probe_service

    probe_service = get_device_probe_service()
    protocols = await probe_service.detect_available_protocols(address)

    return {
        "success": True,
        "address": address,
        "protocols": protocols,
    }


@router.get("/scan-ports/{address}")
async def scan_ports_for_address(address: str):
    """
    Scansiona le porte TCP/UDP di un indirizzo IP.
    Restituisce l'elenco delle porte aperte con relativi servizi.
    """
    from ..services.device_probe_service import get_device_probe_service

    probe_service = get_device_probe_service()
    
    try:
        open_ports = await probe_service.scan_services(address)
        
        # Filtra solo porte aperte
        active_ports = [p for p in open_ports if p.get("open")]
        
        return {
            "success": True,
            "address": address,
            "open_ports": open_ports,
            "active_count": len(active_ports),
            "services": [p["service"] for p in active_ports if p.get("service")],
        }
    except Exception as e:
        logger.error(f"Error scanning ports for {address}: {e}")
        return {
            "success": False,
            "address": address,
            "error": str(e),
            "open_ports": [],
        }


@router.get("/suggest-credential-type/{address}")
async def suggest_credential_type(address: str):
    """
    Suggerisce il tipo di credenziali da usare in base alle porte aperte.

    Regole:
    - Se risponde a 389 (LDAP), 445 (SMB), o 3389 (RDP) -> wmi (Windows)
    - Se risponde a 161 (SNMP) -> snmp
    - Se risponde a 22 (SSH) ma non SNMP e non WMI -> ssh (Linux)
    - Se risponde a 8728 (RouterOS API) -> mikrotik
    """
    from ..services.device_probe_service import get_device_probe_service

    probe_service = get_device_probe_service()
    suggested_type = await probe_service.suggest_credential_type(address)

    return {
        "success": True,
        "address": address,
        "suggested_type": suggested_type,
    }


@router.get("/reverse-dns/{address}")
async def reverse_dns_lookup(
    address: str,
    dns_server: Optional[str] = Query(None, description="DNS server da usare (opzionale)"),
):
    """
    Esegue reverse DNS lookup per un indirizzo IP.
    Supporta fallback DNS server se quello specificato non risponde.
    """
    from ..services.device_probe_service import get_device_probe_service
    
    probe_service = get_device_probe_service()
    
    # Usa il nuovo metodo con fallback
    result = await probe_service.reverse_dns_lookup(
        address=address,
        dns_server=dns_server,
        fallback_dns=["8.8.8.8", "1.1.1.1"],
        timeout=5
    )
    
    return result
async def reverse_dns_lookup(address: str):
    """Esegue reverse DNS lookup per ottenere hostname da IP"""
    from ..services.device_probe_service import get_device_probe_service

    probe_service = get_device_probe_service()
    hostname = await probe_service.reverse_dns_lookup(address)

    return {
        "success": True,
        "address": address,
        "hostname": hostname,
    }


# ==========================================
# INVENTORY CRUD
# ==========================================

@router.get("/devices/monitored")
async def list_monitored_devices(
    customer_id: Optional[str] = Query(None, description="Filtra per cliente"),
    monitoring_type: Optional[str] = Query(None, description="Filtra per tipo monitoraggio (none, icmp, tcp, netwatch, agent)"),
    monitored_only: bool = Query(True, description="Solo device con monitoraggio attivo"),
    limit: int = Query(500, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """
    Lista device con monitoraggio configurato o da configurare.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice).filter(InventoryDevice.active == True)
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        if monitored_only:
            # Solo device con monitoraggio attivo (monitored=True) o configurato (monitoring_type != "none")
            query = query.filter(
                (InventoryDevice.monitored == True) | 
                (InventoryDevice.monitoring_type != "none")
            )
        
        if monitoring_type:
            query = query.filter(InventoryDevice.monitoring_type == monitoring_type)
        
        total = query.count()
        devices = query.order_by(InventoryDevice.name).offset(offset).limit(limit).all()
        
        # Converti in dict per JSON
        devices_list = []
        for dev in devices:
            devices_list.append({
                "id": dev.id,
                "customer_id": dev.customer_id,
                "name": dev.name,
                "hostname": dev.hostname,
                "primary_ip": dev.primary_ip,
                "primary_mac": dev.primary_mac,
                "device_type": dev.device_type,
                "category": dev.category,
                "manufacturer": dev.manufacturer,
                "status": dev.status,
                "monitored": dev.monitored,
                "monitoring_type": dev.monitoring_type or "none",
                "monitoring_port": dev.monitoring_port,
                "monitoring_agent_id": dev.monitoring_agent_id,
                "netwatch_id": dev.netwatch_id,
                "last_check": dev.last_check.isoformat() if dev.last_check else None,
                "last_seen": dev.last_seen.isoformat() if dev.last_seen else None,
            })
        
        return {
            "total": total,
            "devices": devices_list,
            "offset": offset,
            "limit": limit,
        }
    finally:
        session.close()


@router.get("/devices")
async def list_inventory_devices(
    customer_id: Optional[str] = Query(None),
    device_type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Lista dispositivi inventariati"""
    from ..models.database import init_db, get_session, Credential
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice)
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        if device_type:
            query = query.filter(InventoryDevice.device_type == device_type)
        if status:
            query = query.filter(InventoryDevice.status == status)
        
        total = query.count()
        devices = query.order_by(InventoryDevice.name).offset(offset).limit(limit).all()
        
        # Prepara dict delle credenziali per lookup veloce
        cred_ids = [d.credential_id for d in devices if d.credential_id]
        credentials_map = {}
        if cred_ids:
            creds = session.query(Credential).filter(Credential.id.in_(cred_ids)).all()
            credentials_map = {c.id: {"name": c.name, "type": c.credential_type} for c in creds}
        
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "devices": [
                {
                    "id": d.id,
                    "customer_id": d.customer_id,
                    "name": d.name,
                    "hostname": d.hostname,
                    "domain": d.domain,
                    "device_type": d.device_type,
                    "category": d.category,
                    "manufacturer": d.manufacturer,
                    "model": d.model,
                    "primary_ip": d.primary_ip,
                    "primary_mac": d.primary_mac,
                    "mac_address": d.mac_address or d.primary_mac,  # Usa mac_address se disponibile, altrimenti primary_mac
                    "status": d.status,
                    "os_family": d.os_family,
                    "os_version": d.os_version,
                    "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                    "dude_device_id": d.dude_device_id,
                    "tags": d.tags,
                    "credential_id": d.credential_id,
                    "credential_name": credentials_map.get(d.credential_id, {}).get("name") if d.credential_id else None,
                    "credential_type": credentials_map.get(d.credential_id, {}).get("type") if d.credential_id else None,
                    "open_ports": d.open_ports,  # Porte aperte
                    "identified_by": d.identified_by,  # Metodo identificazione
                    "serial_number": d.serial_number,
                    "cpu_model": d.cpu_model,
                    "cpu_cores": d.cpu_cores,
                    "ram_total_gb": d.ram_total_gb,
                }
                for d in devices
            ]
        }
    finally:
        session.close()


@router.get("/devices/{device_id}")
async def get_inventory_device(device_id: str):
    """Dettagli singolo dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import (
        InventoryDevice, NetworkInterface, DiskInfo, 
        InstalledSoftware, ServiceInfo,
        WindowsDetails, LinuxDetails, MikroTikDetails, NetworkDeviceDetails
    )
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        # Base info
        result = {
            "id": device.id,
            "customer_id": device.customer_id,
            "name": device.name,
            "hostname": device.hostname,
            "domain": device.domain,
            "device_type": device.device_type,
            "category": device.category,
            "manufacturer": device.manufacturer,
            "model": device.model,
            "serial_number": device.serial_number,
            "asset_tag": device.asset_tag,
            "primary_ip": device.primary_ip,
            "primary_mac": device.primary_mac,
            "mac_address": device.mac_address or device.primary_mac,
            "site_name": device.site_name,
            "location": device.location,
            "status": device.status,
            "monitor_source": device.monitor_source,
            "dude_device_id": device.dude_device_id,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "last_scan": device.last_scan.isoformat() if device.last_scan else None,
            "os_family": device.os_family,
            "os_version": device.os_version,
            "os_build": device.os_build,
            "architecture": device.architecture,
            "cpu_model": device.cpu_model,
            "cpu_cores": device.cpu_cores,
            "cpu_threads": device.cpu_threads,
            "ram_total_gb": device.ram_total_gb,
            "description": device.description,
            "notes": device.notes,
            "tags": device.tags,
            "custom_fields": device.custom_fields,
            "open_ports": device.open_ports,
            "identified_by": device.identified_by,
            "credential_used": device.credential_used,
            "credential_id": device.credential_id,
            "firmware_version": getattr(device, 'firmware_version', None),
            "interface_count": getattr(device, 'interface_count', None),
            "created_at": device.created_at.isoformat() if device.created_at else None,
            "updated_at": device.updated_at.isoformat() if device.updated_at else None,
        }
        
        # Aggiungi campi SNMP da custom_fields se presenti
        if device.custom_fields:
            import json
            try:
                if isinstance(device.custom_fields, str):
                    cf = json.loads(device.custom_fields)
                else:
                    cf = device.custom_fields
                
                # Estrai campi SNMP da custom_fields
                if isinstance(cf, dict):
                    if "firmware_version" in cf and not result.get("firmware_version"):
                        result["firmware_version"] = cf["firmware_version"]
                    if "interface_count" in cf and not result.get("interface_count"):
                        result["interface_count"] = cf["interface_count"]
                    if "sysDescr" in cf:
                        result["sysDescr"] = cf["sysDescr"]
                    if "sysName" in cf:
                        result["sysName"] = cf["sysName"]
                    if "sysObjectID" in cf:
                        result["sysObjectID"] = cf["sysObjectID"]
                    # Campi Ubiquiti
                    if "ubiquiti_model" in cf:
                        result["ubiquiti_model"] = cf["ubiquiti_model"]
                    if "ubiquiti_firmware" in cf:
                        result["ubiquiti_firmware"] = cf["ubiquiti_firmware"]
                    if "vendor_model" in cf:
                        result["vendor_model"] = cf["vendor_model"]
                    if "vendor_version" in cf:
                        result["vendor_version"] = cf["vendor_version"]
                    if "wifi_clients" in cf:
                        result["wifi_clients"] = cf["wifi_clients"]
                    if "load_average_1m" in cf:
                        result["load_average_1m"] = cf["load_average_1m"]
                    if "ram_available_mb" in cf:
                        result["ram_available_mb"] = cf["ram_available_mb"]
                    # Campi HP ProCurve
                    if "vendor_os_version" in cf:
                        result["vendor_os_version"] = cf["vendor_os_version"]
                    if "vendor_rom_version" in cf:
                        result["vendor_rom_version"] = cf["vendor_rom_version"]
                    if "vendor_product_number" in cf:
                        result["vendor_product_number"] = cf["vendor_product_number"]
                    if "vendor_mem_total" in cf:
                        result["vendor_mem_total"] = cf["vendor_mem_total"]
                    if "vendor_mem_free" in cf:
                        result["vendor_mem_free"] = cf["vendor_mem_free"]
                    if "cpu_usage_percent" in cf:
                        result["cpu_usage_percent"] = cf["cpu_usage_percent"]
                    # Campi HP Comware
                    if "vendor_cpu_usage" in cf:
                        result["vendor_cpu_usage"] = cf["vendor_cpu_usage"]
                    if "vendor_mem_usage" in cf:
                        result["vendor_mem_usage"] = cf["vendor_mem_usage"]
                    if "vendor_temperature" in cf:
                        result["vendor_temperature"] = cf["vendor_temperature"]
                    if "vendor_fan_status" in cf:
                        result["vendor_fan_status"] = cf["vendor_fan_status"]
                    if "vendor_power_status" in cf:
                        result["vendor_power_status"] = cf["vendor_power_status"]
                    if "memory_usage_percent" in cf:
                        result["memory_usage_percent"] = cf["memory_usage_percent"]
                    # Campi ArubaOS
                    if "vendor_sw_version" in cf:
                        result["vendor_sw_version"] = cf["vendor_sw_version"]
                    if "vendor_hw_version" in cf:
                        result["vendor_hw_version"] = cf["vendor_hw_version"]
                    if "vendor_switch_serial" in cf:
                        result["vendor_switch_serial"] = cf["vendor_switch_serial"]
                    if "vendor_storage_usage" in cf:
                        result["vendor_storage_usage"] = cf["vendor_storage_usage"]
                    # Campi TP-Link Omada
                    if "vendor_description" in cf:
                        result["vendor_description"] = cf["vendor_description"]
                    if "vendor_fw_version" in cf:
                        result["vendor_fw_version"] = cf["vendor_fw_version"]
                    if "vendor_mac" in cf:
                        result["vendor_mac"] = cf["vendor_mac"]
                    if "hardware_version" in cf:
                        result["hardware_version"] = cf["hardware_version"]
                    # Storage info (Synology/QNAP)
                    if "storage_info" in cf:
                        result["storage_info"] = cf["storage_info"]
                    
                    # Aggiungi anche tutti i campi vendor_* direttamente per debug
                    for key, value in cf.items():
                        if key.startswith("vendor_") and key not in result:
                            result[key] = value
            except:
                pass
        
        # Network interfaces
        result["network_interfaces"] = [
            {
                "name": n.name,
                "mac_address": n.mac_address,
                "ip_addresses": n.ip_addresses,
                "speed_mbps": n.speed_mbps,
                "admin_status": n.admin_status,
            }
            for n in device.network_interfaces
        ]
        
        # Disks
        result["disks"] = [
            {
                "name": d.name,
                "mount_point": d.mount_point,
                "size_gb": d.size_gb,
                "used_gb": d.used_gb,
                "filesystem": d.filesystem,
            }
            for d in device.disks
        ]
        
        # Type-specific details - Restituisce TUTTI i campi disponibili
        if device.device_type == "windows" and device.windows_details:
            wd = device.windows_details
            result["windows_details"] = {
                "edition": wd.edition,
                "product_key": wd.product_key,
                "activation_status": wd.activation_status,
                "domain_role": wd.domain_role,
                "domain_name": wd.domain_name,
                "ou_path": wd.ou_path,
                "bios_version": wd.bios_version,
                "bios_date": wd.bios_date.isoformat() if wd.bios_date else None,
                "secure_boot": wd.secure_boot,
                "tpm_version": wd.tpm_version,
                "last_update_check": wd.last_update_check.isoformat() if wd.last_update_check else None,
                "pending_updates": wd.pending_updates,
                "last_reboot": wd.last_reboot.isoformat() if wd.last_reboot else None,
                "uptime_days": wd.uptime_days,
                "antivirus_name": wd.antivirus_name,
                "antivirus_status": wd.antivirus_status,
                "firewall_enabled": wd.firewall_enabled,
                "bitlocker_status": wd.bitlocker_status,
                "local_admins": wd.local_admins,
                "logged_users": wd.logged_users,
            }
        
        if device.device_type == "linux" and device.linux_details:
            ld = device.linux_details
            result["linux_details"] = {
                "distro_name": ld.distro_name,
                "distro_version": ld.distro_version,
                "distro_codename": ld.distro_codename,
                "kernel_version": ld.kernel_version,
                "kernel_arch": ld.kernel_arch,
                "package_manager": ld.package_manager,
                "packages_installed": ld.packages_installed,
                "packages_upgradable": ld.packages_upgradable,
                "init_system": ld.init_system,
                "selinux_status": ld.selinux_status,
                "virtualization": ld.virtualization,
                "last_reboot": ld.last_reboot.isoformat() if ld.last_reboot else None,
                "uptime_days": ld.uptime_days,
                "load_average": ld.load_average,
                "root_login_enabled": ld.root_login_enabled,
                "ssh_port": ld.ssh_port,
                "logged_users": ld.logged_users,
                "docker_installed": ld.docker_installed,
                "docker_version": ld.docker_version,
                "containers_running": ld.containers_running,
            }
        
        if device.device_type == "mikrotik" and device.mikrotik_details:
            md = device.mikrotik_details
            result["mikrotik_details"] = {
                "routeros_version": md.routeros_version,
                "routeros_channel": md.routeros_channel,
                "firmware_version": md.firmware_version,
                "factory_firmware": md.factory_firmware,
                "board_name": md.board_name,
                "platform": md.platform,
                "identity": md.identity,
                "license_level": md.license_level,
                "cpu_model": md.cpu_model,
                "cpu_count": md.cpu_count,
                "cpu_load": md.cpu_load,
                "cpu_frequency": md.cpu_frequency,
                "memory_total_mb": md.memory_total_mb,
                "memory_free_mb": md.memory_free_mb,
                "hdd_total_mb": md.hdd_total_mb,
                "hdd_free_mb": md.hdd_free_mb,
                "uptime": md.uptime,
                "dude_agent_enabled": md.dude_agent_enabled,
                "dude_agent_status": md.dude_agent_status,
            }
        
        # Se il device è Proxmox/hypervisor con credenziali ma senza dati avanzati completi, avvia autodetect in background
        is_proxmox = (
            device.device_type == "hypervisor" or 
            (device.manufacturer and "proxmox" in device.manufacturer.lower()) or
            (device.os_family and "proxmox" in device.os_family.lower())
        )
        
        if is_proxmox and device.primary_ip and device.credential_id:
            from ..models.inventory import ProxmoxHost
            proxmox_host = session.query(ProxmoxHost).filter(
                ProxmoxHost.device_id == device_id
            ).first()
            
            # Esegui autodetect se non ci sono dati Proxmox o se mancano dati avanzati (temperature, BIOS, hardware)
            needs_refresh = (
                not proxmox_host or
                not proxmox_host.temperature_summary or
                not proxmox_host.bios_vendor or
                not proxmox_host.hardware_product
            )
            
            if needs_refresh:
                logger.info(f"Device {device_id} is Proxmox with credentials but no advanced data, triggering auto-detect in background")
                try:
                    import asyncio
                    from .inventory import AutoDetectRequest
                    
                    async def run_autodetect():
                        try:
                            await auto_detect_device(
                                AutoDetectRequest(
                                    address=device.primary_ip,
                                    mac_address=device.primary_mac,
                                    device_id=device_id,
                                    use_assigned_credential=True,
                                    use_default_credentials=False,
                                    use_agent=True,
                                    save_results=True
                                ),
                                customer_id=device.customer_id
                            )
                            logger.info(f"Auto-detect completed for device {device_id}")
                        except Exception as e:
                            logger.error(f"Error in background auto-detect for device {device_id}: {e}", exc_info=True)
                    
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            loop.create_task(run_autodetect())
                        else:
                            asyncio.run(run_autodetect())
                    except RuntimeError:
                        asyncio.run(run_autodetect())
                except Exception as auto_detect_error:
                    logger.warning(f"Failed to trigger auto-detect for device {device_id}: {auto_detect_error}")
        
        return result
        
    finally:
        session.close()


@router.post("/devices")
async def create_inventory_device(
    customer_id: str,
    device: DeviceImport,
):
    """Crea nuovo dispositivo inventariato"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Determina nome
        name = device.name or device.identity or device.address or "Unknown"
        
        # Controlla duplicati per IP
        if device.address:
            existing = session.query(InventoryDevice).filter(
                InventoryDevice.customer_id == customer_id,
                InventoryDevice.primary_ip == device.address
            ).first()
            
            if existing:
                return {
                    "success": False,
                    "error": "duplicate",
                    "message": f"Dispositivo con IP {device.address} già presente",
                    "existing_id": existing.id,
                }
        
        # Crea dispositivo
        new_device = InventoryDevice(
            customer_id=customer_id,
            name=name,
            hostname=device.identity,
            device_type=device.device_type,
            category=device.category,
            primary_ip=device.address,
            primary_mac=device.mac_address,
            mac_address=device.mac_address,  # Alias per retrocompatibilità
            manufacturer=device.platform if device.platform else None,
            model=device.board,
            os_family=device.os_family if hasattr(device, 'os_family') else None,
            os_version=device.os_version if hasattr(device, 'os_version') else None,
            identified_by=device.identified_by if hasattr(device, 'identified_by') else None,
            credential_used=device.credential_used if hasattr(device, 'credential_used') else None,
            open_ports=device.open_ports if hasattr(device, 'open_ports') else None,
            status="unknown",
            last_seen=datetime.now(),
        )
        
        session.add(new_device)
        session.commit()
        
        # Se il device ha un IP e una credenziale, esegui autodetect automatico in background
        # Nota: L'autodetect verrà eseguito automaticamente quando il device viene visualizzato o modificato
        # Non lo eseguiamo qui per evitare di bloccare la risposta
        if new_device.primary_ip and new_device.credential_id:
            logger.info(f"New device {new_device.id} created with IP and credential - autodetect will run automatically on next access")
        
        return {
            "success": True,
            "device_id": new_device.id,
            "name": new_device.name,
            "message": f"Dispositivo {name} creato",
        }
        
    finally:
        session.close()


@router.post("/devices/bulk-import")
async def bulk_import_devices(
    customer_id: str,
    data: BulkImport,
    skip_duplicates: bool = Query(True),
):
    """Importa più dispositivi nell'inventario"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Ottieni IP esistenti
        existing_ips = set()
        if skip_duplicates:
            existing = session.query(InventoryDevice.primary_ip).filter(
                InventoryDevice.customer_id == customer_id,
                InventoryDevice.primary_ip.isnot(None)
            ).all()
            existing_ips = {e[0] for e in existing}
        
        imported = 0
        skipped = 0
        skipped_no_mac = 0
        errors = []
        
        for device in data.devices:
            try:
                # MAC address è opzionale - non bloccare se mancante
                has_mac = device.mac_address and device.mac_address.strip() != ''
                if not has_mac:
                    skipped_no_mac += 1  # Conta ma non blocca
                
                # Skip se IP già presente
                if device.address and device.address in existing_ips:
                    skipped += 1
                    continue
                
                # Determina il nome: priorità a name, poi hostname, poi identity, poi address
                name = device.name or device.hostname or device.identity or device.address or "Unknown"
                
                # Determina hostname: priorità a hostname, poi identity
                hostname = device.hostname or device.identity or None

                new_device = InventoryDevice(
                    customer_id=customer_id,
                    name=name,
                    hostname=hostname,
                    device_type=device.device_type,
                    category=device.category,
                    primary_ip=device.address,
                    primary_mac=device.mac_address,
                    mac_address=device.mac_address,  # Alias per retrocompatibilità
                    manufacturer=device.platform if device.platform else None,
                    model=device.board,
                    os_family=device.os_family if hasattr(device, 'os_family') else None,
                    os_version=device.os_version if hasattr(device, 'os_version') else None,
                    identified_by=device.identified_by if hasattr(device, 'identified_by') else None,
                    credential_used=device.credential_used if hasattr(device, 'credential_used') else None,
                    open_ports=device.open_ports if hasattr(device, 'open_ports') else None,
                    status="unknown",
                    last_seen=datetime.now(),
                )
                
                logger.debug(f"Importing device: {name} ({device.address}) - hostname: {hostname}, ports: {len(device.open_ports or [])}")
                
                session.add(new_device)
                imported += 1
                
                if device.address:
                    existing_ips.add(device.address)
                    
            except Exception as e:
                errors.append(f"{device.address}: {str(e)}")
        
        session.commit()
        
        return {
            "success": True,
            "imported": imported,
            "skipped": skipped,
            "without_mac": skipped_no_mac,  # Info only, not skipped
            "errors": errors,
            "message": f"Importati {imported} dispositivi ({skipped_no_mac} senza MAC), {skipped} duplicati",
        }
        
    finally:
        session.close()


@router.delete("/devices/clear")
async def clear_inventory(customer_id: Optional[str] = Query(None)):
    """Elimina tutti i dispositivi dall'inventario di un cliente"""
    from ..models.database import init_db, get_session
    from ..models.inventory import (
        InventoryDevice, LinuxDetails, WindowsDetails, 
        MikroTikDetails, NetworkDeviceDetails,
        LLDPNeighbor, CDPNeighbor, ProxmoxHost, ProxmoxVM, ProxmoxStorage
    )
    from ..config import get_settings

    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)

    try:
        # Costruisci query
        query = session.query(InventoryDevice)

        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        else:
            raise HTTPException(status_code=400, detail="customer_id è richiesto")

        # Carica tutti i dispositivi per eliminare correttamente le relazioni
        devices = query.all()
        count = len(devices)
        
        # Ottieni tutti gli ID dei dispositivi
        device_ids = [d.id for d in devices]
        
        if device_ids:
            # Elimina manualmente TUTTI i record correlati prima di eliminare i dispositivi
            # Questo è necessario perché query.delete() non rispetta sempre i cascade
            
            # Tabelle detail (one-to-one) - ELIMINA PRIMA DI TUTTO
            deleted_linux = session.query(LinuxDetails).filter(LinuxDetails.device_id.in_(device_ids)).delete(synchronize_session=False)
            deleted_windows = session.query(WindowsDetails).filter(WindowsDetails.device_id.in_(device_ids)).delete(synchronize_session=False)
            deleted_mikrotik = session.query(MikroTikDetails).filter(MikroTikDetails.device_id.in_(device_ids)).delete(synchronize_session=False)
            deleted_network = session.query(NetworkDeviceDetails).filter(NetworkDeviceDetails.device_id.in_(device_ids)).delete(synchronize_session=False)
            logger.debug(f"Deleted detail records: Linux={deleted_linux}, Windows={deleted_windows}, MikroTik={deleted_mikrotik}, Network={deleted_network}")
            
            # Flush per assicurarsi che le eliminazioni siano visibili
            session.flush()
            
            # Le altre tabelle (network_interfaces, disks, software, services)
            from ..models.inventory import NetworkInterface, DiskInfo, InstalledSoftware, ServiceInfo
            session.query(NetworkInterface).filter(NetworkInterface.device_id.in_(device_ids)).delete(synchronize_session=False)
            session.query(DiskInfo).filter(DiskInfo.device_id.in_(device_ids)).delete(synchronize_session=False)
            session.query(InstalledSoftware).filter(InstalledSoftware.device_id.in_(device_ids)).delete(synchronize_session=False)
            session.query(ServiceInfo).filter(ServiceInfo.device_id.in_(device_ids)).delete(synchronize_session=False)
            
            # Flush per assicurarsi che le eliminazioni siano visibili
            session.flush()
            
            # Tabelle correlate senza cascade esplicito
            session.query(LLDPNeighbor).filter(LLDPNeighbor.device_id.in_(device_ids)).delete(synchronize_session=False)
            session.query(CDPNeighbor).filter(CDPNeighbor.device_id.in_(device_ids)).delete(synchronize_session=False)
            
            # ProxmoxHost e relative VM/Storage
            proxmox_hosts = session.query(ProxmoxHost).filter(ProxmoxHost.device_id.in_(device_ids)).all()
            proxmox_host_ids = [h.id for h in proxmox_hosts]
            if proxmox_host_ids:
                session.query(ProxmoxVM).filter(ProxmoxVM.host_id.in_(proxmox_host_ids)).delete(synchronize_session=False)
                session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id.in_(proxmox_host_ids)).delete(synchronize_session=False)
            session.query(ProxmoxHost).filter(ProxmoxHost.device_id.in_(device_ids)).delete(synchronize_session=False)
            
            # Flush finale prima di eliminare i dispositivi principali
            session.flush()
        
        # Ora elimina i dispositivi principali uno per uno
        for device in devices:
            session.delete(device)
        
        session.commit()

        logger.info(f"Cleared {count} devices from inventory for customer {customer_id}")

        return {
            "success": True,
            "deleted": count,
            "message": f"Eliminati {count} dispositivi"
        }

    except Exception as e:
        session.rollback()
        logger.error(f"Error clearing inventory: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


# ==========================================
# PORT SCANNING
# ==========================================

@router.post("/devices/{device_id}/scan-ports")
async def scan_device_ports(device_id: str):
    """
    Riesegue la scansione delle porte per un dispositivo inventariato.
    Aggiorna il campo open_ports nel database.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..services.device_probe_service import get_device_probe_service
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        if not device.primary_ip:
            raise HTTPException(status_code=400, detail="Dispositivo senza IP")
        
        # Esegui scansione porte
        probe_service = get_device_probe_service()
        open_ports = await probe_service.scan_services(device.primary_ip)
        
        # Aggiorna dispositivo
        device.open_ports = open_ports
        device.last_seen = datetime.now()
        session.commit()
        
        logger.info(f"Port scan completed for device {device_id} ({device.primary_ip}): {len([p for p in open_ports if p.get('open')])} ports open")
        
        return {
            "success": True,
            "device_id": device_id,
            "address": device.primary_ip,
            "open_ports": open_ports,
            "open_count": len([p for p in open_ports if p.get('open')]),
            "message": f"Scansione completata: {len([p for p in open_ports if p.get('open')])} porte aperte"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error scanning ports for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


class BatchPortScanRequest(BaseModel):
    """Schema per scansione porte batch"""
    device_ids: List[str]


@router.post("/devices/batch-scan-ports")
async def batch_scan_device_ports(
    customer_id: Optional[str] = Query(None),
    data: Optional[BatchPortScanRequest] = None,
):
    """
    Riesegue la scansione delle porte per più dispositivi inventariati.
    Se customer_id è specificato, scansiona tutti i device del cliente.
    Se data.device_ids è specificato, scansiona solo quei device.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..services.device_probe_service import get_device_probe_service
    from ..config import get_settings
    import asyncio
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Determina quali device scansionare
        query = session.query(InventoryDevice).filter(
            InventoryDevice.primary_ip.isnot(None)
        )
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        if data and data.device_ids:
            query = query.filter(InventoryDevice.id.in_(data.device_ids))
        
        devices = query.all()
        
        if not devices:
            return {
                "success": True,
                "scanned": 0,
                "errors": [],
                "message": "Nessun dispositivo da scansionare"
            }
        
        # Esegui scansione in parallelo
        probe_service = get_device_probe_service()
        
        async def scan_one_device(device):
            """Scansiona un singolo device"""
            try:
                open_ports = await probe_service.scan_services(device.primary_ip)
                device.open_ports = open_ports
                device.last_seen = datetime.now()
                return {
                    "device_id": device.id,
                    "address": device.primary_ip,
                    "success": True,
                    "open_count": len([p for p in open_ports if p.get('open')]),
                }
            except Exception as e:
                logger.error(f"Error scanning {device.primary_ip}: {e}")
                return {
                    "device_id": device.id,
                    "address": device.primary_ip,
                    "success": False,
                    "error": str(e),
                }
        
        # Esegui scansioni in parallelo (max 10 alla volta)
        tasks = [scan_one_device(d) for d in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Processa risultati
        scanned = 0
        errors = []
        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result))
            elif result.get("success"):
                scanned += 1
            else:
                errors.append(f"{result.get('address', 'unknown')}: {result.get('error', 'unknown error')}")
        
        session.commit()
        
        logger.info(f"Batch port scan completed: {scanned}/{len(devices)} devices scanned")
        
        return {
            "success": True,
            "scanned": scanned,
            "total": len(devices),
            "errors": errors,
            "message": f"Scansione completata: {scanned}/{len(devices)} dispositivi"
        }
        
    except Exception as e:
        session.rollback()
        logger.error(f"Error in batch port scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.delete("/devices/{device_id}")
async def delete_inventory_device(device_id: str):
    """Elimina dispositivo dall'inventario"""
    from ..models.database import init_db, get_session
    from ..models.inventory import (
        InventoryDevice, LinuxDetails, WindowsDetails, 
        MikroTikDetails, NetworkDeviceDetails,
        LLDPNeighbor, CDPNeighbor, ProxmoxHost, ProxmoxVM, ProxmoxStorage
    )
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        # Carica il dispositivo con tutte le relazioni
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        name = device.name
        
        # Elimina manualmente TUTTI i record correlati prima di eliminare il dispositivo
        # Questo è necessario perché i cascade potrebbero non funzionare correttamente
        
        # Tabelle detail (one-to-one)
        session.query(LinuxDetails).filter(LinuxDetails.device_id == device_id).delete()
        session.query(WindowsDetails).filter(WindowsDetails.device_id == device_id).delete()
        session.query(MikroTikDetails).filter(MikroTikDetails.device_id == device_id).delete()
        session.query(NetworkDeviceDetails).filter(NetworkDeviceDetails.device_id == device_id).delete()
        
        # Tabelle correlate senza cascade esplicito
        session.query(LLDPNeighbor).filter(LLDPNeighbor.device_id == device_id).delete()
        session.query(CDPNeighbor).filter(CDPNeighbor.device_id == device_id).delete()
        
        # ProxmoxHost e relative VM/Storage
        proxmox_host = session.query(ProxmoxHost).filter(ProxmoxHost.device_id == device_id).first()
        if proxmox_host:
            session.query(ProxmoxVM).filter(ProxmoxVM.host_id == proxmox_host.id).delete()
            session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id == proxmox_host.id).delete()
            session.query(ProxmoxHost).filter(ProxmoxHost.device_id == device_id).delete()
        
        # Le altre tabelle (network_interfaces, disks, software, services)
        from ..models.inventory import NetworkInterface, DiskInfo, InstalledSoftware, ServiceInfo
        session.query(NetworkInterface).filter(NetworkInterface.device_id == device_id).delete()
        session.query(DiskInfo).filter(DiskInfo.device_id == device_id).delete()
        session.query(InstalledSoftware).filter(InstalledSoftware.device_id == device_id).delete()
        session.query(ServiceInfo).filter(ServiceInfo.device_id == device_id).delete()
        
        # Ora elimina il dispositivo principale
        session.delete(device)
        session.commit()
        
        logger.info(f"Deleted inventory device: {name} (id: {device_id})")
        return {
            "success": True,
            "message": f"Dispositivo {name} eliminato",
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error deleting inventory device {device_id}: {e}", exc_info=True)
        
        # Se è un errore di foreign key, fornisci un messaggio più chiaro
        error_str = str(e)
        if "ForeignKeyViolation" in error_str or "foreign key constraint" in error_str.lower():
            raise HTTPException(
                status_code=409,
                detail=f"Impossibile eliminare il dispositivo: esistono ancora dati correlati. Errore: {error_str}"
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Errore durante eliminazione dispositivo: {str(e)}"
        )
    finally:
        session.close()


@router.put("/devices/{device_id}")
async def update_inventory_device(device_id: str, updates: dict):
    """Aggiorna dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        # PRESERVA credential_id esistente se non viene esplicitamente passato nell'update
        existing_credential_id = device.credential_id
        
        # Campi aggiornabili
        allowed_fields = [
            'name', 'hostname', 'device_type', 'category', 'manufacturer',
            'model', 'serial_number', 'asset_tag', 'site_name', 'location',
            'description', 'notes', 'tags', 'status', 'credential_id',
            'os_family', 'os_version', 'domain'
        ]
        
        for field, value in updates.items():
            if field in allowed_fields:
                # Protezione speciale per credential_id: preserva se non viene esplicitamente passato o se viene passato None
                if field == 'credential_id':
                    # Permetti solo se viene esplicitamente passato un valore non-None
                    # Se viene passato None o non viene passato, preserva quello esistente
                    if value is not None:
                        setattr(device, field, value)
                    # Se value è None, non fare nulla (preserva esistente)
                else:
                    setattr(device, field, value)
        
        # Assicurati che credential_id non venga perso accidentalmente
        if device.credential_id != existing_credential_id and 'credential_id' not in updates:
            logger.warning(f"Preserving existing credential_id {existing_credential_id} for device {device_id} (was about to be lost)")
            device.credential_id = existing_credential_id
        
        # Verifica se credential_id è stato modificato
        credential_changed = 'credential_id' in updates and updates['credential_id'] is not None and updates['credential_id'] != existing_credential_id
        
        session.commit()
        
        # Se è stata assegnata/modificata una credenziale e il device ha un IP, 
        # l'autodetect verrà eseguito automaticamente quando il device viene visualizzato
        if credential_changed and device.primary_ip:
            logger.info(f"Credential changed for device {device_id} - autodetect will run automatically on next access")
        
        return {
            "success": True,
            "message": f"Dispositivo {device.name} aggiornato",
        }
        
    finally:
        session.close()


@router.post("/devices/{device_id}/monitoring")
async def configure_device_monitoring(device_id: str, config: dict):
    """
    Configura il monitoraggio per un dispositivo.
    
    monitoring_type: none, icmp, tcp, mikrotik, agent
    monitoring_port: porta TCP (richiesto se monitoring_type == "tcp")
    monitoring_agent_id: ID agent per mikrotik/agent (opzionale)
    interval: intervallo check in secondi (opzionale, default: 30)
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from ..services.customer_service import get_customer_service
    from ..services.mikrotik_service import get_mikrotik_service
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        monitoring_type = config.get("monitoring_type", "none")
        monitoring_port = config.get("monitoring_port")
        monitoring_agent_id = config.get("monitoring_agent_id")
        interval = config.get("interval", 30)
        customer_id = config.get("customer_id", device.customer_id)
        
        # Se customer_id è fornito nel config e il device non ne ha uno, o se è diverso, aggiornalo
        if customer_id and (not device.customer_id or device.customer_id != customer_id):
            device.customer_id = customer_id
            logger.info(f"Aggiornato customer_id per device {device_id}: {customer_id}")
        
        # Validazione
        if monitoring_type == "tcp" and not monitoring_port:
            raise HTTPException(status_code=400, detail="monitoring_port è richiesto per monitoraggio TCP")
        
        # Risultato operazione
        result = {
            "success": True,
            "device_id": device_id,
            "device_ip": device.primary_ip,
            "monitoring_type": monitoring_type,
            "monitoring_port": monitoring_port,
            "monitoring_agent_id": monitoring_agent_id,
            "netwatch_configured": False,
            "agent_configured": False,
        }
        
        # Ottieni servizio clienti per sonde
        customer_service = get_customer_service()
        
        # Se disabilito il monitoraggio, rimuovi eventuali configurazioni
        if monitoring_type == "none":
            # Rimuovi Netwatch se configurato
            if device.netwatch_id and device.monitoring_agent_id:
                try:
                    agent = customer_service.get_agent(device.monitoring_agent_id, include_password=True)
                    if agent and agent.agent_type == "mikrotik":
                        mikrotik_service = get_mikrotik_service()
                        mikrotik_service.remove_netwatch(
                            address=agent.address,
                            port=agent.port or 8728,
                            username=agent.username or "admin",
                            password=agent.password or "",
                            netwatch_id=device.netwatch_id,
                            use_ssl=agent.use_ssl or False,
                        )
                        logger.info(f"Rimosso Netwatch {device.netwatch_id} da {agent.name}")
                except Exception as e:
                    logger.warning(f"Errore rimozione Netwatch: {e}")
            
            device.monitored = False
            device.monitoring_type = "none"
            device.monitoring_agent_id = None
            device.netwatch_id = None
            device.monitoring_port = None
            
        elif monitoring_type == "icmp":
            # Monitoraggio ICMP (Ping)
            device.monitored = True
            device.monitoring_type = "icmp"
            device.monitoring_port = None  # ICMP non usa porta
            # Se c'è un agent specificato, usalo, altrimenti None (monitoraggio locale)
            if monitoring_agent_id:
                device.monitoring_agent_id = monitoring_agent_id
            else:
                device.monitoring_agent_id = None
            device.netwatch_id = None
            logger.info(f"ICMP monitoring configurato per {device.primary_ip}")
            
        elif monitoring_type == "tcp":
            # Monitoraggio TCP (Porta)
            if not monitoring_port:
                raise HTTPException(status_code=400, detail="monitoring_port è richiesto per monitoraggio TCP")
            
            device.monitored = True
            device.monitoring_type = "tcp"
            device.monitoring_port = monitoring_port
            # Se c'è un agent specificato, usalo, altrimenti None (monitoraggio locale)
            if monitoring_agent_id:
                device.monitoring_agent_id = monitoring_agent_id
            else:
                device.monitoring_agent_id = None
            device.netwatch_id = None
            logger.info(f"TCP monitoring configurato per {device.primary_ip}:{monitoring_port}")
            
        elif monitoring_type == "netwatch":
            # Configura Netwatch su MikroTik
            # Cerca una sonda MikroTik per questo cliente
            agents = customer_service.list_agents(customer_id=customer_id, active_only=True)
            mikrotik_agent = None
            for ag in agents:
                if ag.agent_type == "mikrotik":
                    mikrotik_agent = customer_service.get_agent(ag.id, include_password=True)
                    break
            
            if not mikrotik_agent:
                return {
                    "success": False,
                    "error": "Nessuna sonda MikroTik configurata per questo cliente"
                }
            
            mikrotik_service = get_mikrotik_service()
            
            try:
                # Aggiungi o aggiorna Netwatch
                netwatch_result = mikrotik_service.add_netwatch(
                    address=mikrotik_agent.address,
                    port=mikrotik_agent.port or 8728,
                    username=mikrotik_agent.username or "admin",
                    password=mikrotik_agent.password or "",
                    target_ip=device.primary_ip,
                    target_name=device.name or device.hostname or device.primary_ip,
                    interval="30s",
                    use_ssl=mikrotik_agent.use_ssl or False,
                )
                
                if netwatch_result.get("success"):
                    device.monitored = True
                    device.monitoring_type = "mikrotik"
                    device.monitoring_port = None  # Netwatch usa ICMP di default
                    device.monitoring_agent_id = mikrotik_agent.id
                    device.netwatch_id = netwatch_result.get("netwatch_id")
                    result["netwatch_configured"] = True
                    result["mikrotik_name"] = mikrotik_agent.name
                    logger.info(f"Netwatch configurato per {device.primary_ip} su {mikrotik_agent.name}")
                else:
                    result["success"] = False
                    result["error"] = netwatch_result.get("error", "Errore configurazione Netwatch")
                    
            except Exception as e:
                logger.error(f"Errore configurazione Netwatch: {e}")
                result["success"] = False
                result["error"] = str(e)
                
        elif monitoring_type == "agent":
            # Configura monitoring via Docker agent
            agents = customer_service.list_agents(customer_id=customer_id, active_only=True)
            docker_agent = None
            for ag in agents:
                if ag.agent_type == "docker":
                    docker_agent = customer_service.get_agent(ag.id, include_password=True)
                    break
            
            if not docker_agent:
                # Fallback a MikroTik se non c'è Docker
                for ag in agents:
                    if ag.agent_type == "mikrotik":
                        docker_agent = customer_service.get_agent(ag.id, include_password=True)
                        break
            
            if not docker_agent:
                return {
                    "success": False,
                    "error": "Nessuna sonda configurata per questo cliente"
                }
            
            device.monitored = True
            device.monitoring_type = "agent"
            device.monitoring_agent_id = docker_agent.id
            # Per agent monitoring, monitoring_port può essere specificato per TCP check
            if monitoring_port:
                device.monitoring_port = monitoring_port
            else:
                device.monitoring_port = None  # Default ICMP per agent
            device.netwatch_id = None
            result["agent_configured"] = True
            result["agent_name"] = docker_agent.name
            logger.info(f"Agent monitoring configurato per {device.primary_ip} via {docker_agent.name}")
        else:
            # Tipo non riconosciuto
            raise HTTPException(status_code=400, detail=f"Tipo monitoraggio non valido: {monitoring_type}")
        
        # Aggiorna timestamp
        from datetime import datetime
        device.last_check = None  # Reset last_check, sarà aggiornato dal monitoring service
        device.last_seen = datetime.utcnow() if device.last_seen else None
        
        session.commit()
        logger.info(f"Monitoring config salvato: device={device_id}, type={monitoring_type}, monitored={device.monitored}, port={device.monitoring_port}, agent_id={device.monitoring_agent_id}")
        return result
        
    except Exception as e:
        session.rollback()
        logger.error(f"Errore configurazione monitoring: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        
    finally:
        session.close()


@router.post("/devices/{device_id}/identify")
async def identify_inventory_device(
    device_id: str,
    credential_ids: List[str] = Query(default=[]),
):
    """
    Ri-identifica un dispositivo esistente e aggiorna automaticamente le info.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from ..services.device_probe_service import get_device_probe_service
    from ..services.customer_service import get_customer_service
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        # Prepara credenziali
        credentials_list = []
        if credential_ids:
            customer_service = get_customer_service()
            for cred_id in credential_ids:
                cred = customer_service.get_credential(cred_id, include_secrets=True)
                if cred:
                    credentials_list.append({
                        "id": cred.id,
                        "name": cred.name,
                        "type": cred.credential_type,
                        "username": cred.username,
                        "password": cred.password,
                        "ssh_port": getattr(cred, 'ssh_port', 22),
                        "snmp_community": getattr(cred, 'snmp_community', None),
                        "snmp_version": getattr(cred, 'snmp_version', '2c'),
                        "snmp_port": getattr(cred, 'snmp_port', 161),
                        "wmi_domain": getattr(cred, 'wmi_domain', None),
                        "mikrotik_api_port": getattr(cred, 'mikrotik_api_port', 8728),
                    })
        
        # Esegui probe
        probe_service = get_device_probe_service()
        result = await probe_service.auto_identify_device(
            address=device.primary_ip,
            mac_address=device.primary_mac,
            credentials_list=credentials_list
        )
        
        # PRESERVA credential_id esistente - NON sovrascriverlo!
        # Il credential_id viene gestito solo tramite l'interfaccia utente o durante la creazione del device
        existing_credential_id = device.credential_id
        
        # Aggiorna dispositivo con info identificate
        updates_applied = []
        
        if result.get("hostname") and not device.hostname:
            device.hostname = result["hostname"]
            updates_applied.append("hostname")
        
        if result.get("device_type") and result["device_type"] != "other":
            device.device_type = result["device_type"]
            updates_applied.append("device_type")
        
        if result.get("category"):
            device.category = result["category"]
            updates_applied.append("category")
        
        if result.get("os_family"):
            device.os_family = result["os_family"]
            updates_applied.append("os_family")
        
        if result.get("model"):
            device.model = result["model"]
            updates_applied.append("model")
        
        if result.get("vendor"):
            device.manufacturer = result["vendor"]
            updates_applied.append("manufacturer")
        
        # Hardware Info
        if result.get("cpu_model"):
            device.cpu_model = result["cpu_model"]
            updates_applied.append("cpu_model")
            
        if result.get("cpu_cores"):
            device.cpu_cores = result["cpu_cores"]
            updates_applied.append("cpu_cores")
            
        if result.get("memory_total_mb"):
            device.ram_total_gb = round(result["memory_total_mb"] / 1024, 2)
            updates_applied.append("ram_total_gb")
            
        if result.get("serial_number"):
            device.serial_number = result["serial_number"]
            updates_applied.append("serial_number")
            
        # OS Version - può venire da "version" (WMI) o altri campi
        if result.get("version") and not device.os_version:
            device.os_version = result["version"]
            updates_applied.append("os_version")
        elif result.get("os_version") and not device.os_version:
            device.os_version = result["os_version"]
            updates_applied.append("os_version")

        # Disk info
        if result.get("disk_total_gb"):
            # Salva in custom_fields o in un campo specifico se disponibile
            if not device.custom_fields:
                device.custom_fields = {}
            device.custom_fields["disk_total_gb"] = result["disk_total_gb"]
            device.custom_fields["disk_free_gb"] = result.get("disk_free_gb")
            updates_applied.append("disk_info")
            
        # Manufacturer - può venire da "manufacturer" (WMI) o "vendor" (MAC)
        if result.get("manufacturer") and not device.manufacturer:
            device.manufacturer = result["manufacturer"]
            updates_applied.append("manufacturer")
            
        # Domain - può venire direttamente da WMI
        if result.get("domain") and not device.domain:
            device.domain = result["domain"]
            updates_applied.append("domain")
            
        # Architecture
        if result.get("architecture"):
            device.architecture = result["architecture"]
            updates_applied.append("architecture")
        
        # Assicurati che credential_id non venga perso
        if existing_credential_id and device.credential_id != existing_credential_id:
            logger.warning(f"Preserving existing credential_id {existing_credential_id} for device {device_id}")
            device.credential_id = existing_credential_id

        # Salva porte aperte rilevate
        if result.get("open_ports"):
            device.open_ports = result["open_ports"]
            updates_applied.append("open_ports")

        # Salva informazioni avanzate se disponibili
        # LLDP/CDP neighbors e dettagli interfacce per switch/router
        if result.get("lldp_neighbors") or result.get("cdp_neighbors") or result.get("interface_details"):
            try:
                from ..services.lldp_cdp_collector import get_lldp_cdp_collector
                from ..models.inventory import LLDPNeighbor, CDPNeighbor, NetworkInterface
                from datetime import datetime
                import uuid
                
                # Salva LLDP neighbors
                if result.get("lldp_neighbors"):
                    # Elimina vecchi neighbor
                    session.query(LLDPNeighbor).filter(LLDPNeighbor.device_id == device_id).delete()
                    
                    # Salva nuovi neighbor
                    for neighbor in result["lldp_neighbors"]:
                        lldp_neighbor = LLDPNeighbor(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            local_interface=neighbor.get("local_interface", ""),
                            remote_device_name=neighbor.get("remote_device_name"),
                            remote_device_description=neighbor.get("remote_device_description"),
                            remote_port=neighbor.get("remote_port"),
                            remote_mac=neighbor.get("remote_mac"),
                            remote_ip=neighbor.get("remote_ip"),
                            chassis_id=neighbor.get("chassis_id"),
                            chassis_id_type=neighbor.get("chassis_id_type"),
                            capabilities=neighbor.get("capabilities"),
                            last_seen=datetime.now(),
                        )
                        session.add(lldp_neighbor)
                    logger.info(f"Saved {len(result['lldp_neighbors'])} LLDP neighbors for device {device_id}")
                
                # Salva CDP neighbors
                if result.get("cdp_neighbors"):
                    # Elimina vecchi neighbor
                    session.query(CDPNeighbor).filter(CDPNeighbor.device_id == device_id).delete()
                    
                    # Salva nuovi neighbor
                    for neighbor in result["cdp_neighbors"]:
                        cdp_neighbor = CDPNeighbor(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            local_interface=neighbor.get("local_interface", ""),
                            remote_device_id=neighbor.get("remote_device_id"),
                            remote_device_name=neighbor.get("remote_device_name"),
                            remote_port=neighbor.get("remote_port"),
                            remote_ip=neighbor.get("remote_ip"),
                            remote_version=neighbor.get("remote_version"),
                            platform=neighbor.get("platform"),
                            capabilities=neighbor.get("capabilities"),
                            last_seen=datetime.now(),
                        )
                        session.add(cdp_neighbor)
                    logger.info(f"Saved {len(result['cdp_neighbors'])} CDP neighbors for device {device_id}")
                
                # Salva dettagli interfacce avanzati
                if result.get("interface_details"):
                    for iface_data in result["interface_details"]:
                        existing = session.query(NetworkInterface).filter(
                            NetworkInterface.device_id == device_id,
                            NetworkInterface.name == iface_data.get("name")
                        ).first()
                        
                        if existing:
                            # Aggiorna con dati avanzati
                            existing.lldp_enabled = iface_data.get("lldp_enabled")
                            existing.cdp_enabled = iface_data.get("cdp_enabled")
                            existing.poe_enabled = iface_data.get("poe_enabled")
                            existing.poe_power_watts = iface_data.get("poe_power_watts")
                            existing.vlan_native = iface_data.get("vlan_native")
                            existing.vlan_trunk_allowed = iface_data.get("vlan_trunk_allowed")
                            existing.stp_state = iface_data.get("stp_state")
                            existing.lacp_enabled = iface_data.get("lacp_enabled")
                            existing.last_updated = datetime.now()
                        else:
                            # Crea nuova interfaccia con dati avanzati
                            new_iface = NetworkInterface(
                                id=uuid.uuid4().hex[:8],
                                device_id=device_id,
                                name=iface_data.get("name", ""),
                                description=iface_data.get("description"),
                                interface_type=iface_data.get("interface_type"),
                                mac_address=iface_data.get("mac_address"),
                                ip_addresses=iface_data.get("ip_addresses"),
                                speed_mbps=iface_data.get("speed_mbps"),
                                duplex=iface_data.get("duplex"),
                                mtu=iface_data.get("mtu"),
                                admin_status=iface_data.get("admin_status"),
                                oper_status=iface_data.get("oper_status"),
                                lldp_enabled=iface_data.get("lldp_enabled"),
                                cdp_enabled=iface_data.get("cdp_enabled"),
                                poe_enabled=iface_data.get("poe_enabled"),
                                poe_power_watts=iface_data.get("poe_power_watts"),
                                vlan_native=iface_data.get("vlan_native"),
                                vlan_trunk_allowed=iface_data.get("vlan_trunk_allowed"),
                                stp_state=iface_data.get("stp_state"),
                                lacp_enabled=iface_data.get("lacp_enabled"),
                            )
                            session.add(new_iface)
                    logger.info(f"Updated {len(result['interface_details'])} interfaces with advanced details for device {device_id}")
            except Exception as e:
                logger.error(f"Error saving advanced network info for device {device_id}: {e}", exc_info=True)
        
        # Salva informazioni Proxmox se disponibili
        if result.get("proxmox_host_info") or result.get("proxmox_vms") or result.get("proxmox_storage"):
            try:
                from ..models.inventory import ProxmoxHost, ProxmoxVM, ProxmoxStorage
                from datetime import datetime
                import uuid
                
                host_info = result.get("proxmox_host_info")
                if host_info:
                    # Aggiorna o crea ProxmoxHost
                    existing_host = session.query(ProxmoxHost).filter(
                        ProxmoxHost.device_id == device_id
                    ).first()
                    
                    if existing_host:
                        # Aggiorna
                        for key, value in host_info.items():
                            if hasattr(existing_host, key):
                                setattr(existing_host, key, value)
                        existing_host.last_updated = datetime.now()
                        host_id = existing_host.id
                    else:
                        # Crea nuovo
                        new_host = ProxmoxHost(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            **{k: v for k, v in host_info.items() if hasattr(ProxmoxHost, k)}
                        )
                        session.add(new_host)
                        session.flush()
                        host_id = new_host.id
                    
                    # Salva VM
                    if result.get("proxmox_vms"):
                        # Elimina vecchie VM
                        session.query(ProxmoxVM).filter(ProxmoxVM.host_id == host_id).delete()
                        
                        # Salva nuove VM con tutti i campi da Proxreporter
                        for vm_data in result["proxmox_vms"]:
                            vm = ProxmoxVM(
                                id=uuid.uuid4().hex[:8],
                                host_id=host_id,
                                vm_id=vm_data.get("vm_id", vm_data.get("vmid", 0)),
                                vm_type=vm_data.get("type"),  # qemu, lxc
                                name=vm_data.get("name", ""),
                                status=vm_data.get("status"),
                                cpu_cores=vm_data.get("cpu_cores"),
                                cpu_sockets=vm_data.get("cpu_sockets"),
                                cpu_total=vm_data.get("cpu_total"),
                                memory_mb=vm_data.get("memory_mb", vm_data.get("memory_total_mb")),
                                disk_total_gb=vm_data.get("disk_total_gb"),
                                bios=vm_data.get("bios"),
                                machine=vm_data.get("machine"),
                                agent_installed=vm_data.get("agent_installed"),
                                network_interfaces=vm_data.get("network_interfaces"),
                                num_networks=vm_data.get("num_networks"),
                                networks=vm_data.get("networks"),
                                ip_addresses=vm_data.get("ip_addresses"),
                                num_disks=vm_data.get("num_disks"),
                                disks=vm_data.get("disks"),
                                disks_details=vm_data.get("disks_details"),
                                os_type=vm_data.get("os_type", vm_data.get("guest_os")),
                                template=vm_data.get("template", False),
                                uptime=vm_data.get("uptime"),
                                cpu_usage=vm_data.get("cpu_usage"),
                                mem_used=vm_data.get("mem_used"),
                                netin=vm_data.get("netin"),
                                netout=vm_data.get("netout"),
                                diskread=vm_data.get("diskread"),
                                diskwrite=vm_data.get("diskwrite"),
                            )
                            session.add(vm)
                        session.flush()
                        logger.info(f"Saved {len(result['proxmox_vms'])} Proxmox VMs for device {device_id}")
                        
                        # Crea dispositivi InventoryDevice per ogni VM (solo se hanno IP)
                        device = session.query(InventoryDevice).filter(InventoryDevice.id == device_id).first()
                        if device:
                            from ..models.inventory import InventoryDevice as InvDevice
                            created_count = 0
                            for vm_data_item in result["proxmox_vms"]:
                                try:
                                    ip_addresses_str = vm_data_item.get("ip_addresses")
                                    primary_ip = None
                                    if ip_addresses_str:
                                        ips = [ip.strip() for ip in ip_addresses_str.split(';') if ip.strip()]
                                        for ip in ips:
                                            if not ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                                                primary_ip = ip
                                                break
                                    
                                    if primary_ip:
                                        vm_name = vm_data_item.get("name", f"VM-{vm_data_item.get('vm_id', 'unknown')}")
                                        vm_type = vm_data_item.get("type", "qemu")
                                        
                                        existing = session.query(InvDevice).filter(
                                            InvDevice.customer_id == device.customer_id,
                                            InvDevice.primary_ip == primary_ip
                                        ).first()
                                        
                                        if not existing:
                                            device_type = "linux" if vm_type == "lxc" else "server"
                                            category = "vm" if vm_type == "qemu" else "container"
                                            
                                            os_family = None
                                            os_type = vm_data_item.get("os_type", "").lower()
                                            if "windows" in os_type or "win" in os_type:
                                                os_family = "Windows"
                                                device_type = "windows"
                                            elif "linux" in os_type or "debian" in os_type or "ubuntu" in os_type:
                                                os_family = "Linux"
                                            elif "bsd" in os_type:
                                                os_family = "BSD"
                                            
                                            def safe_int_local(value):
                                                if value is None:
                                                    return None
                                                try:
                                                    return int(value)
                                                except (ValueError, TypeError):
                                                    return None
                                            
                                            def safe_float_local(value):
                                                if value is None:
                                                    return None
                                                try:
                                                    return float(value)
                                                except (ValueError, TypeError):
                                                    return None
                                            
                                            new_vm_device = InvDevice(
                                                customer_id=device.customer_id,
                                                name=f"{vm_name} (VM)",
                                                hostname=vm_name,
                                                device_type=device_type,
                                                category=category,
                                                primary_ip=primary_ip,
                                                manufacturer="Proxmox",
                                                os_family=os_family,
                                                cpu_cores=safe_int_local(vm_data_item.get("cpu_cores")),
                                                ram_total_gb=safe_float_local(vm_data_item.get("memory_mb")) / 1024.0 if vm_data_item.get("memory_mb") else None,
                                                identified_by="proxmox_vm",
                                                status=vm_data_item.get("status", "unknown"),
                                                description=f"Proxmox {vm_type.upper()} VM su host {device.name if device else 'Unknown'}",
                                                last_seen=datetime.now(),
                                            )
                                            session.add(new_vm_device)
                                            created_count += 1
                                            logger.info(f"Created inventory device for VM {vm_name} ({primary_ip})")
                                except Exception as e:
                                    logger.error(f"Error creating inventory device for VM: {e}", exc_info=True)
                                    continue
                            
                            if created_count > 0:
                                logger.info(f"Created {created_count} inventory devices for Proxmox VMs")
                    
                    # Salva storage
                    if result.get("proxmox_storage"):
                        # Elimina vecchio storage
                        session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id == host_id).delete()
                        
                        # Salva nuovo storage
                        for storage_data in result["proxmox_storage"]:
                            # Calcola usage_percent se disponibile
                            usage_percent = None
                            total_gb = storage_data.get("total_gb")
                            used_gb = storage_data.get("used_gb")
                            if total_gb and used_gb and total_gb > 0:
                                usage_percent = round((used_gb / total_gb) * 100, 2)
                            
                            storage = ProxmoxStorage(
                                id=uuid.uuid4().hex[:8],
                                host_id=host_id,
                                storage_name=storage_data.get("storage", storage_data.get("storage_name", "")),
                                storage_type=storage_data.get("type", storage_data.get("storage_type")),
                                total_gb=total_gb,
                                used_gb=used_gb,
                                available_gb=storage_data.get("available_gb", storage_data.get("free_gb")),  # Campo corretto: available_gb
                                usage_percent=usage_percent,
                                content_types=storage_data.get("content", storage_data.get("content_types", [])),
                            )
                            session.add(storage)
                        logger.info(f"Saved {len(result['proxmox_storage'])} Proxmox storage for device {device_id}")
            except Exception as e:
                logger.error(f"Error saving Proxmox info for device {device_id}: {e}", exc_info=True)
        
        # Estrai dominio da hostname se non già impostato
        if not device.domain and result.get("hostname") and "." in result["hostname"]:
            parts = result["hostname"].split(".", 1)
            if len(parts) > 1:
                device.domain = parts[1]
                updates_applied.append("domain_from_hostname")
        
        # Nome OS completo (da WMI: "Windows 10 Pro", etc.)
        if result.get("name") and "Windows" in result.get("name", ""):
            # Salva il nome OS completo in description o custom_fields
            if not device.description:
                device.description = result["name"]
                updates_applied.append("os_description")
                
        # Aggiorna identificato_by e credential_used
        if result.get("identified_by"):
            device.identified_by = result["identified_by"]
            updates_applied.append("identified_by")
            
        if result.get("credential_used"):
            device.credential_used = result["credential_used"]
            updates_applied.append("credential_used")
        
        # Aggiorna last_seen
        device.last_seen = datetime.now()
        device.last_scan = datetime.now()
        
        logger.info(f"Device {device_id} identification complete. Updates: {updates_applied}")
        
        session.commit()
        
        return {
            "success": True,
            "device_id": device_id,
            "probe_result": result,
            "updates_applied": updates_applied,
            "message": f"Dispositivo aggiornato: {', '.join(updates_applied)}" if updates_applied else "Nessun aggiornamento necessario"
        }
        
    finally:
        session.close()


# ==========================================
# STATISTICS
# ==========================================

@router.get("/stats")
async def get_inventory_stats(customer_id: Optional[str] = None):
    """Statistiche inventario"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from sqlalchemy import func
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice)
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        total = query.count()
        
        # Per tipo
        by_type = session.query(
            InventoryDevice.device_type,
            func.count(InventoryDevice.id)
        )
        if customer_id:
            by_type = by_type.filter(InventoryDevice.customer_id == customer_id)
        by_type = dict(by_type.group_by(InventoryDevice.device_type).all())
        
        # Per stato
        by_status = session.query(
            InventoryDevice.status,
            func.count(InventoryDevice.id)
        )
        if customer_id:
            by_status = by_status.filter(InventoryDevice.customer_id == customer_id)
        by_status = dict(by_status.group_by(InventoryDevice.status).all())
        
        return {
            "total": total,
            "by_type": by_type,
            "by_status": by_status,
        }
        
    finally:
        session.close()


# ==========================================
# SYNC WITH THE DUDE
# ==========================================

@router.post("/devices/{device_id}/add-to-dude")
async def add_device_to_dude(device_id: str):
    """Aggiunge dispositivo a The Dude per monitoraggio"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..services.dude_service import get_dude_service
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Dispositivo non trovato")
        
        if not device.primary_ip:
            raise HTTPException(status_code=400, detail="Dispositivo senza IP")
        
        if device.dude_device_id:
            return {
                "success": True,
                "already_exists": True,
                "dude_device_id": device.dude_device_id,
                "message": "Dispositivo già in The Dude",
            }
        
        # Aggiungi a The Dude
        dude = get_dude_service()
        
        # Determina tipo dispositivo per Dude
        dude_type = "Generic Device"
        if device.device_type == "mikrotik":
            dude_type = "RouterOS"
        elif device.device_type == "windows":
            dude_type = "Windows"
        elif device.device_type == "linux":
            dude_type = "Linux"
        elif device.device_type in ["network", "switch"]:
            dude_type = "SNMP Device"
        
        result = dude.add_device(
            name=device.name,
            address=device.primary_ip,
            device_type=dude_type,
        )
        
        if result:
            # Aggiorna riferimento
            device.dude_device_id = result
            device.monitor_source = "dude"
            session.commit()
            
            return {
                "success": True,
                "dude_device_id": result,
                "message": f"Dispositivo {device.name} aggiunto a The Dude",
            }
        else:
            return {
                "success": False,
                "message": "Errore aggiunta a The Dude",
            }
        
    finally:
        session.close()


# ==========================================
# UNIQUE VALUES ENDPOINTS (for autocomplete)
# ==========================================

@router.get("/device-types")
async def get_device_types(customer_id: Optional[str] = Query(None)):
    """
    Restituisce lista di valori unici per device_type dall'inventario.
    Utile per autocompletamento nei form.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from sqlalchemy import distinct
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice.device_type).distinct()
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        types = [t[0] for t in query.filter(InventoryDevice.device_type.isnot(None)).all() if t[0]]
        types.sort()
        
        return {
            "success": True,
            "values": types
        }
    except Exception as e:
        logger.error(f"Error fetching device types: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/categories")
async def get_categories(customer_id: Optional[str] = Query(None)):
    """
    Restituisce lista di valori unici per category dall'inventario.
    Utile per autocompletamento nei form.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from sqlalchemy import distinct
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice.category).distinct()
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        categories = [c[0] for c in query.filter(InventoryDevice.category.isnot(None)).all() if c[0]]
        categories.sort()
        
        return {
            "success": True,
            "values": categories
        }
    except Exception as e:
        logger.error(f"Error fetching categories: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/os-families")
async def get_os_families(customer_id: Optional[str] = Query(None)):
    """
    Restituisce lista di valori unici per os_family dall'inventario.
    Utile per autocompletamento nei form.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from sqlalchemy import distinct
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice.os_family).distinct()
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        os_families = [o[0] for o in query.filter(InventoryDevice.os_family.isnot(None)).all() if o[0]]
        os_families.sort()
        
        return {
            "success": True,
            "values": os_families
        }
    except Exception as e:
        logger.error(f"Error fetching OS families: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/manufacturers")
async def get_manufacturers(customer_id: Optional[str] = Query(None)):
    """
    Restituisce lista di valori unici per manufacturer dall'inventario.
    Utile per autocompletamento nei form.
    """
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice
    from ..config import get_settings
    from sqlalchemy import distinct
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        query = session.query(InventoryDevice.manufacturer).distinct()
        
        if customer_id:
            query = query.filter(InventoryDevice.customer_id == customer_id)
        
        manufacturers = [m[0] for m in query.filter(InventoryDevice.manufacturer.isnot(None)).all() if m[0]]
        manufacturers.sort()
        
        return {
            "success": True,
            "values": manufacturers
        }
    except Exception as e:
        logger.error(f"Error fetching manufacturers: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


# ==========================================
# ADVANCED DEVICE INFORMATION ENDPOINTS
# ==========================================

@router.get("/{customer_id}/devices/{device_id}/lldp-neighbors")
async def get_device_lldp_neighbors(customer_id: str, device_id: str):
    """Ottiene lista neighbor LLDP per un dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, LLDPNeighbor
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        neighbors = session.query(LLDPNeighbor).filter(
            LLDPNeighbor.device_id == device_id
        ).order_by(LLDPNeighbor.local_interface, LLDPNeighbor.last_seen.desc()).all()
        
        return {
            "success": True,
            "device_id": device_id,
            "neighbors": [
                {
                    "id": n.id,
                    "local_interface": n.local_interface,
                    "remote_device_name": n.remote_device_name,
                    "remote_device_description": n.remote_device_description,
                    "remote_port": n.remote_port,
                    "remote_mac": n.remote_mac,
                    "remote_ip": n.remote_ip,
                    "chassis_id": n.chassis_id,
                    "chassis_id_type": n.chassis_id_type,
                    "capabilities": n.capabilities,
                    "last_seen": n.last_seen.isoformat() if n.last_seen else None,
                }
                for n in neighbors
            ],
            "count": len(neighbors)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching LLDP neighbors: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/{customer_id}/devices/{device_id}/cdp-neighbors")
async def get_device_cdp_neighbors(customer_id: str, device_id: str):
    """Ottiene lista neighbor CDP per un dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, CDPNeighbor
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        neighbors = session.query(CDPNeighbor).filter(
            CDPNeighbor.device_id == device_id
        ).order_by(CDPNeighbor.local_interface, CDPNeighbor.last_seen.desc()).all()
        
        return {
            "success": True,
            "device_id": device_id,
            "neighbors": [
                {
                    "id": n.id,
                    "local_interface": n.local_interface,
                    "remote_device_id": n.remote_device_id,
                    "remote_device_name": n.remote_device_name,
                    "remote_port": n.remote_port,
                    "remote_ip": n.remote_ip,
                    "remote_version": n.remote_version,
                    "platform": n.platform,
                    "capabilities": n.capabilities,
                    "last_seen": n.last_seen.isoformat() if n.last_seen else None,
                }
                for n in neighbors
            ],
            "count": len(neighbors)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching CDP neighbors: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/{customer_id}/devices/{device_id}/interfaces")
async def get_device_interfaces(customer_id: str, device_id: str):
    """Ottiene dettagli interfacce di rete per un dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, NetworkInterface
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        interfaces = session.query(NetworkInterface).filter(
            NetworkInterface.device_id == device_id
        ).order_by(NetworkInterface.name).all()
        
        return {
            "success": True,
            "device_id": device_id,
            "interfaces": [
                {
                    "id": i.id,
                    "name": i.name,
                    "description": i.description,
                    "interface_type": i.interface_type,
                    "mac_address": i.mac_address,
                    "ip_addresses": i.ip_addresses,
                    "speed_mbps": i.speed_mbps,
                    "duplex": i.duplex,
                    "mtu": i.mtu,
                    "admin_status": i.admin_status,
                    "oper_status": i.oper_status,
                    "vlan_id": i.vlan_id,
                    "is_management": i.is_management,
                    "lldp_enabled": i.lldp_enabled,
                    "cdp_enabled": i.cdp_enabled,
                    "poe_enabled": i.poe_enabled,
                    "poe_power_watts": i.poe_power_watts,
                    "vlan_native": i.vlan_native,
                    "vlan_trunk_allowed": i.vlan_trunk_allowed,
                    "stp_state": i.stp_state,
                    "lacp_enabled": i.lacp_enabled,
                    "last_updated": i.last_updated.isoformat() if i.last_updated else None,
                }
                for i in interfaces
            ],
            "count": len(interfaces)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching interfaces: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/{customer_id}/devices/{device_id}/proxmox/host")
async def get_proxmox_host_info(customer_id: str, device_id: str):
    """Ottiene informazioni host Proxmox"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, ProxmoxHost
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        host_info = session.query(ProxmoxHost).filter(
            ProxmoxHost.device_id == device_id
        ).first()
        
        if not host_info:
            return {
                "success": False,
                "message": "Proxmox host info not available. Run refresh-advanced-info first."
            }
        
        return {
            "success": True,
            "device_id": device_id,
            "host_info": {
                "node_name": host_info.node_name,
                "cluster_name": host_info.cluster_name,
                "proxmox_version": host_info.proxmox_version,
                "manager_version": host_info.manager_version,
                "kernel_version": host_info.kernel_version,
                "boot_mode": host_info.boot_mode,
                "cpu_model": host_info.cpu_model,
                "cpu_cores": host_info.cpu_cores,
                "cpu_sockets": host_info.cpu_sockets,
                "cpu_threads": host_info.cpu_threads,
                "cpu_total_cores": host_info.cpu_total_cores,
                "cpu_usage_percent": host_info.cpu_usage_percent,
                "io_delay_percent": host_info.io_delay_percent,
                "memory_total_gb": host_info.memory_total_gb,
                "memory_used_gb": host_info.memory_used_gb,
                "memory_free_gb": host_info.memory_free_gb,
                "memory_usage_percent": host_info.memory_usage_percent,
                "ksm_sharing_gb": host_info.ksm_sharing_gb,
                "swap_total_gb": host_info.swap_total_gb,
                "swap_used_gb": host_info.swap_used_gb,
                "swap_free_gb": host_info.swap_free_gb,
                "swap_usage_percent": host_info.swap_usage_percent,
                "rootfs_total_gb": host_info.rootfs_total_gb,
                "rootfs_used_gb": host_info.rootfs_used_gb,
                "rootfs_free_gb": host_info.rootfs_free_gb,
                "rootfs_usage_percent": host_info.rootfs_usage_percent,
                "storage_list": host_info.storage_list,
                "network_interfaces": host_info.network_interfaces,
                "license_status": host_info.license_status,
                "license_message": host_info.license_message,
                "license_level": host_info.license_level,
                "subscription_type": host_info.subscription_type,
                "subscription_key": host_info.subscription_key,
                "subscription_server_id": host_info.subscription_server_id,
                "subscription_sockets": host_info.subscription_sockets,
                "subscription_last_check": host_info.subscription_last_check,
                "subscription_next_due": host_info.subscription_next_due,
                "repository_status": host_info.repository_status,
                "uptime_seconds": host_info.uptime_seconds,
                "uptime_human": host_info.uptime_human,
                "load_average_1m": host_info.load_average_1m,
                "load_average_5m": host_info.load_average_5m,
                "load_average_15m": host_info.load_average_15m,
                "temperature_summary": host_info.temperature_summary,
                "temperature_highest_c": host_info.temperature_highest_c,
                "bios_vendor": host_info.bios_vendor,
                "bios_version": host_info.bios_version,
                "bios_release_date": host_info.bios_release_date,
                "system_manufacturer": host_info.system_manufacturer,
                "system_product": host_info.system_product,
                "system_serial": host_info.system_serial,
                "board_vendor": host_info.board_vendor,
                "board_name": host_info.board_name,
                "boot_devices": host_info.boot_devices,
                "boot_devices_details": host_info.boot_devices_details,
                "boot_entries": host_info.boot_entries,
                "hardware_system": host_info.hardware_system,
                "hardware_bus": host_info.hardware_bus,
                "hardware_memory": host_info.hardware_memory,
                "hardware_processor": host_info.hardware_processor,
                "hardware_storage": host_info.hardware_storage,
                "hardware_disk": host_info.hardware_disk,
                "hardware_volume": host_info.hardware_volume,
                "hardware_network": host_info.hardware_network,
                "hardware_product": host_info.hardware_product,
                "pci_devices": host_info.pci_devices,
                "usb_devices": host_info.usb_devices,
                "last_updated": host_info.last_updated.isoformat() if host_info.last_updated else None,
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Proxmox host info: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.post("/{customer_id}/devices/{device_id}/proxmox/create-vm-devices")
async def create_inventory_devices_for_vms(customer_id: str, device_id: str):
    """Crea dispositivi InventoryDevice per tutte le VM Proxmox che hanno IP ma non sono ancora nell'inventario"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, ProxmoxHost, ProxmoxVM
    from ..config import get_settings
    from datetime import datetime
    import uuid
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        host_info = session.query(ProxmoxHost).filter(
            ProxmoxHost.device_id == device_id
        ).first()
        
        if not host_info:
            return {
                "success": False,
                "message": "Proxmox host info not available"
            }
        
        vms = session.query(ProxmoxVM).filter(
            ProxmoxVM.host_id == host_info.id,
            ProxmoxVM.ip_addresses.isnot(None)
        ).all()
        
        created_count = 0
        skipped_count = 0
        
        def safe_int(value):
            if value is None:
                return None
            try:
                return int(value)
            except (ValueError, TypeError):
                return None
        
        def safe_float(value):
            if value is None:
                return None
            try:
                return float(value)
            except (ValueError, TypeError):
                return None
        
        for vm in vms:
            try:
                ip_addresses_str = vm.ip_addresses
                if not ip_addresses_str:
                    continue
                
                # Estrai il primo IP valido
                primary_ip = None
                ips = [ip.strip() for ip in ip_addresses_str.split(';') if ip.strip()]
                for ip in ips:
                    if not ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                        primary_ip = ip
                        break
                
                if not primary_ip:
                    continue
                
                # Verifica se esiste già un dispositivo con questo IP
                existing = session.query(InventoryDevice).filter(
                    InventoryDevice.customer_id == customer_id,
                    InventoryDevice.primary_ip == primary_ip
                ).first()
                
                if existing:
                    skipped_count += 1
                    continue
                
                vm_name = vm.name or f"VM-{vm.vm_id}"
                vm_type = vm.vm_type or "qemu"
                
                # Determina device_type e category
                device_type = "linux" if vm_type == "lxc" else "server"
                category = "vm" if vm_type == "qemu" else "container"
                
                # Determina OS family dal os_type
                os_family = None
                os_type = (vm.os_type or "").lower()
                if "windows" in os_type or "win" in os_type:
                    os_family = "Windows"
                    device_type = "windows"
                elif "linux" in os_type or "debian" in os_type or "ubuntu" in os_type:
                    os_family = "Linux"
                elif "bsd" in os_type:
                    os_family = "BSD"
                
                new_vm_device = InventoryDevice(
                    customer_id=customer_id,
                    name=f"{vm_name} (VM)",
                    hostname=vm_name,
                    device_type=device_type,
                    category=category,
                    primary_ip=primary_ip,
                    manufacturer="Proxmox",
                    os_family=os_family,
                    cpu_cores=safe_int(vm.cpu_cores),
                    ram_total_gb=safe_float(vm.memory_mb) / 1024.0 if vm.memory_mb else None,
                    identified_by="proxmox_vm",
                    status=vm.status or "unknown",
                    description=f"Proxmox {vm_type.upper()} VM su host {device.name if device else 'Unknown'}",
                    last_seen=datetime.now(),
                )
                session.add(new_vm_device)
                created_count += 1
                logger.info(f"Created inventory device for VM {vm_name} ({primary_ip})")
            except Exception as e:
                logger.error(f"Error creating inventory device for VM {vm.name}: {e}", exc_info=True)
                continue
        
        session.commit()
        
        return {
            "success": True,
            "created": created_count,
            "skipped": skipped_count,
            "message": f"Creati {created_count} dispositivi inventario per VM Proxmox"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating VM inventory devices: {e}")
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/{customer_id}/devices/{device_id}/proxmox/vms")
async def get_proxmox_vms(customer_id: str, device_id: str):
    """Ottiene lista VM Proxmox per un host"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, ProxmoxHost, ProxmoxVM
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        host_info = session.query(ProxmoxHost).filter(
            ProxmoxHost.device_id == device_id
        ).first()
        
        if not host_info:
            return {
                "success": False,
                "message": "Proxmox host info not available. Run refresh-advanced-info first."
            }
        
        vms = session.query(ProxmoxVM).filter(
            ProxmoxVM.host_id == host_info.id
        ).order_by(ProxmoxVM.vm_id).all()
        
        return {
            "success": True,
            "device_id": device_id,
            "host_id": host_info.id,
            "vms": [
                {
                    "id": vm.id,
                    "vm_id": vm.vm_id,
                    "vm_type": vm.vm_type,
                    "name": vm.name,
                    "status": vm.status,
                    "cpu_cores": vm.cpu_cores,
                    "cpu_sockets": vm.cpu_sockets,
                    "cpu_total": vm.cpu_total,
                    "memory_mb": vm.memory_mb,
                    "disk_total_gb": vm.disk_total_gb,
                    "bios": vm.bios,
                    "machine": vm.machine,
                    "agent_installed": vm.agent_installed,
                    "network_interfaces": vm.network_interfaces,
                    "num_networks": vm.num_networks,
                    "networks": vm.networks,
                    "ip_addresses": vm.ip_addresses,
                    "num_disks": vm.num_disks,
                    "disks": vm.disks,
                    "disks_details": vm.disks_details,
                    "os_type": vm.os_type,
                    "template": vm.template,
                    "uptime": vm.uptime,
                    "cpu_usage": vm.cpu_usage,
                    "mem_used": vm.mem_used,
                    "netin": vm.netin,
                    "netout": vm.netout,
                    "diskread": vm.diskread,
                    "diskwrite": vm.diskwrite,
                    "backup_enabled": vm.backup_enabled,
                    "last_backup": vm.last_backup.isoformat() if vm.last_backup else None,
                    "created_at": vm.created_at.isoformat() if vm.created_at else None,
                    "last_updated": vm.last_updated.isoformat() if vm.last_updated else None,
                }
                for vm in vms
            ],
            "count": len(vms)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Proxmox VMs: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.get("/{customer_id}/devices/{device_id}/proxmox/storage")
async def get_proxmox_storage(customer_id: str, device_id: str):
    """Ottiene lista storage Proxmox per un host"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, ProxmoxHost, ProxmoxStorage
    from ..config import get_settings
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        host_info = session.query(ProxmoxHost).filter(
            ProxmoxHost.device_id == device_id
        ).first()
        
        if not host_info:
            return {
                "success": False,
                "message": "Proxmox host info not available. Run refresh-advanced-info first."
            }
        
        storage_list = session.query(ProxmoxStorage).filter(
            ProxmoxStorage.host_id == host_info.id
        ).order_by(ProxmoxStorage.storage_name).all()
        
        return {
            "success": True,
            "device_id": device_id,
            "host_id": host_info.id,
            "storage": [
                {
                    "id": s.id,
                    "storage_name": s.storage_name,
                    "storage_type": s.storage_type,
                    "content_types": s.content_types,
                    "total_gb": s.total_gb,
                    "used_gb": s.used_gb,
                    "available_gb": s.available_gb,
                    "usage_percent": s.usage_percent,
                    "last_updated": s.last_updated.isoformat() if s.last_updated else None,
                }
                for s in storage_list
            ],
            "count": len(storage_list)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching Proxmox storage: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@router.post("/{customer_id}/devices/{device_id}/refresh-advanced-info")
async def refresh_advanced_info(customer_id: str, device_id: str):
    """Forza refresh informazioni avanzate per un dispositivo"""
    from ..models.database import init_db, get_session
    from ..models.inventory import InventoryDevice, LLDPNeighbor, CDPNeighbor, NetworkInterface, ProxmoxHost, ProxmoxVM, ProxmoxStorage
    from ..config import get_settings
    from ..services.device_probe_service import get_device_probe_service
    from ..services.lldp_cdp_collector import get_lldp_cdp_collector
    from ..services.proxmox_collector import get_proxmox_collector
    from datetime import datetime
    import uuid
    
    settings = get_settings()
    db_url = settings.database_url
    engine = init_db(db_url)
    session = get_session(engine)
    
    try:
        device = session.query(InventoryDevice).filter(
            InventoryDevice.id == device_id,
            InventoryDevice.customer_id == customer_id
        ).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Usa SOLO la credenziale assegnata al device (se presente)
        from ..models.database import Credential
        from ..services.encryption_service import get_encryption_service
        
        encryption = get_encryption_service()
        credentials_list = []
        
        # Usa SOLO la credenziale assegnata al device
        if device.credential_id:
            cred = session.query(Credential).filter(
                Credential.id == device.credential_id
            ).first()
            
            if cred:
                password = encryption.decrypt(cred.password) if cred.password else None
                ssh_key = encryption.decrypt(cred.ssh_private_key) if cred.ssh_private_key else None
                
                credentials_list.append({
                    "id": cred.id,
                    "name": cred.name,
                    "type": cred.credential_type,
                    "username": cred.username,
                    "password": password,
                    "ssh_port": cred.ssh_port or 22,
                    "ssh_private_key": ssh_key,
                    "snmp_community": cred.snmp_community,
                    "snmp_port": cred.snmp_port or 161,
                    "snmp_version": cred.snmp_version or '2c',
                    "wmi_domain": cred.wmi_domain,
                    "mikrotik_api_port": cred.mikrotik_api_port or 8728,
                })
                logger.info(f"Using device-assigned credential '{cred.name}' ({cred.credential_type})")
            else:
                logger.warning(f"Device credential_id {device.credential_id} not found")
        else:
            logger.warning(f"No credential assigned to device {device_id}. Please assign a credential to the device first.")
        
        device_type = device.device_type or ""
        vendor = device.manufacturer or ""
        
        logger.info(f"Refresh advanced info for device {device_id}: type={device_type}, vendor={vendor}, credentials={len(credentials_list)}")
        
        # Switch/Router: raccogli LLDP/CDP e interfacce
        device_type_lower = device_type.lower()
        vendor_lower = vendor.lower()
        is_network_device = (
            device_type_lower in ["network", "router", "switch"] or 
            "mikrotik" in vendor_lower or 
            "cisco" in vendor_lower or 
            "hp" in vendor_lower or 
            "aruba" in vendor_lower or 
            "ubiquiti" in vendor_lower
        )
        
        if is_network_device:
            logger.info(f"Device {device_id} identified as network device, collecting LLDP/CDP/interfaces...")
            lldp_collector = get_lldp_cdp_collector()
            
            # LLDP neighbors
            try:
                lldp_neighbors = await lldp_collector.collect_lldp_neighbors(
                    device.primary_ip, device_type, vendor, credentials_list
                )
                
                # Elimina vecchi neighbor
                session.query(LLDPNeighbor).filter(LLDPNeighbor.device_id == device_id).delete()
                
                # Salva nuovi neighbor
                for neighbor in lldp_neighbors:
                    lldp_neighbor = LLDPNeighbor(
                        id=uuid.uuid4().hex[:8],
                        device_id=device_id,
                        local_interface=neighbor.get("local_interface", ""),
                        remote_device_name=neighbor.get("remote_device_name"),
                        remote_device_description=neighbor.get("remote_device_description"),
                        remote_port=neighbor.get("remote_port"),
                        remote_mac=neighbor.get("remote_mac"),
                        remote_ip=neighbor.get("remote_ip"),
                        chassis_id=neighbor.get("chassis_id"),
                        chassis_id_type=neighbor.get("chassis_id_type"),
                        capabilities=neighbor.get("capabilities"),
                        last_seen=datetime.now(),
                    )
                    session.add(lldp_neighbor)
                
                logger.info(f"Saved {len(lldp_neighbors)} LLDP neighbors for device {device_id}")
            except Exception as e:
                logger.error(f"Error collecting LLDP neighbors: {e}")
            
            # CDP neighbors (solo Cisco)
            if "cisco" in vendor.lower():
                try:
                    cdp_neighbors = await lldp_collector.collect_cdp_neighbors(
                        device.primary_ip, vendor, credentials_list
                    )
                    
                    # Elimina vecchi neighbor
                    session.query(CDPNeighbor).filter(CDPNeighbor.device_id == device_id).delete()
                    
                    # Salva nuovi neighbor
                    for neighbor in cdp_neighbors:
                        cdp_neighbor = CDPNeighbor(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            local_interface=neighbor.get("local_interface", ""),
                            remote_device_id=neighbor.get("remote_device_id"),
                            remote_device_name=neighbor.get("remote_device_name"),
                            remote_port=neighbor.get("remote_port"),
                            remote_ip=neighbor.get("remote_ip"),
                            remote_version=neighbor.get("remote_version"),
                            platform=neighbor.get("platform"),
                            capabilities=neighbor.get("capabilities"),
                            last_seen=datetime.now(),
                        )
                        session.add(cdp_neighbor)
                    
                    logger.info(f"Saved {len(cdp_neighbors)} CDP neighbors for device {device_id}")
                except Exception as e:
                    logger.error(f"Error collecting CDP neighbors: {e}")
            
            # Dettagli interfacce
            try:
                interfaces = await lldp_collector.collect_interface_details(
                    device.primary_ip, device_type, vendor, credentials_list
                )
                
                # Aggiorna interfacce esistenti o crea nuove
                for iface_data in interfaces:
                    existing = session.query(NetworkInterface).filter(
                        NetworkInterface.device_id == device_id,
                        NetworkInterface.name == iface_data.get("name")
                    ).first()
                    
                    if existing:
                        # Aggiorna
                        existing.description = iface_data.get("description")
                        existing.interface_type = iface_data.get("interface_type")
                        existing.mac_address = iface_data.get("mac_address")
                        existing.ip_addresses = iface_data.get("ip_addresses")
                        existing.speed_mbps = iface_data.get("speed_mbps")
                        existing.duplex = iface_data.get("duplex")
                        existing.mtu = iface_data.get("mtu")
                        existing.admin_status = iface_data.get("admin_status")
                        existing.oper_status = iface_data.get("oper_status")
                        existing.lldp_enabled = iface_data.get("lldp_enabled")
                        existing.cdp_enabled = iface_data.get("cdp_enabled")
                        existing.poe_enabled = iface_data.get("poe_enabled")
                        existing.poe_power_watts = iface_data.get("poe_power_watts")
                        existing.vlan_native = iface_data.get("vlan_native")
                        existing.vlan_trunk_allowed = iface_data.get("vlan_trunk_allowed")
                        existing.stp_state = iface_data.get("stp_state")
                        existing.lacp_enabled = iface_data.get("lacp_enabled")
                        existing.last_updated = datetime.now()
                    else:
                        # Crea nuova
                        new_iface = NetworkInterface(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            name=iface_data.get("name", ""),
                            description=iface_data.get("description"),
                            interface_type=iface_data.get("interface_type"),
                            mac_address=iface_data.get("mac_address"),
                            ip_addresses=iface_data.get("ip_addresses"),
                            speed_mbps=iface_data.get("speed_mbps"),
                            duplex=iface_data.get("duplex"),
                            mtu=iface_data.get("mtu"),
                            admin_status=iface_data.get("admin_status"),
                            oper_status=iface_data.get("oper_status"),
                            lldp_enabled=iface_data.get("lldp_enabled"),
                            cdp_enabled=iface_data.get("cdp_enabled"),
                            poe_enabled=iface_data.get("poe_enabled"),
                            poe_power_watts=iface_data.get("poe_power_watts"),
                            vlan_native=iface_data.get("vlan_native"),
                            vlan_trunk_allowed=iface_data.get("vlan_trunk_allowed"),
                            stp_state=iface_data.get("stp_state"),
                            lacp_enabled=iface_data.get("lacp_enabled"),
                        )
                        session.add(new_iface)
                
                logger.info(f"Updated {len(interfaces)} interfaces for device {device_id}")
            except Exception as e:
                logger.error(f"Error collecting interface details: {e}")
        
        # MikroTik: raccogli routing, ARP e dettagli
        is_mikrotik = device_type_lower == "mikrotik" or "mikrotik" in vendor_lower
        if is_mikrotik and credentials_list:
            logger.info(f"Device {device_id} identified as MikroTik, collecting details/routing/ARP...")
            from ..services.mikrotik_service import get_mikrotik_service
            from ..models.inventory import MikroTikDetails
            import json
            mikrotik_service = get_mikrotik_service()
            
            # Raccogli dettagli MikroTik via API
            try:
                cred = credentials_list[0]
                api = mikrotik_service._get_connection(
                    device.primary_ip,
                    cred.get("mikrotik_api_port", 8728),
                    cred.get("username", ""),
                    cred.get("password", ""),
                    use_ssl=cred.get("use_ssl", False)
                )
                
                mikrotik_data = {}
                
                # System resource
                try:
                    resource_resource = api.get_resource('/system/resource')
                    resources = resource_resource.get()
                    if resources:
                        res = resources[0]
                        mikrotik_data["routeros_version"] = res.get("version", "")
                        mikrotik_data["cpu_model"] = res.get("cpu", "")
                        mikrotik_data["cpu_count"] = int(res.get("cpu-count", 1)) if res.get("cpu-count") else None
                        mikrotik_data["memory_total_mb"] = int(res.get("total-memory", 0)) if res.get("total-memory") else None
                        mikrotik_data["memory_free_mb"] = int(res.get("free-memory", 0)) if res.get("free-memory") else None
                        mikrotik_data["uptime"] = res.get("uptime", "")
                        mikrotik_data["cpu_load"] = float(res.get("cpu-load", 0)) if res.get("cpu-load") else None
                except Exception as e:
                    logger.debug(f"Error getting system resource: {e}")
                
                # Routerboard info
                try:
                    rb_resource = api.get_resource('/system/routerboard')
                    rbs = rb_resource.get()
                    if rbs:
                        rb = rbs[0]
                        mikrotik_data["board_name"] = rb.get("board-name", "")
                        mikrotik_data["platform"] = rb.get("platform", "")
                        mikrotik_data["firmware_version"] = rb.get("current-firmware", "")
                        mikrotik_data["factory_firmware"] = rb.get("factory-firmware", "")
                except Exception as e:
                    logger.debug(f"Error getting routerboard info: {e}")
                
                # Identity
                try:
                    identity_resource = api.get_resource('/system/identity')
                    identities = identity_resource.get()
                    if identities:
                        mikrotik_data["identity"] = identities[0].get("name", "")
                except Exception as e:
                    logger.debug(f"Error getting identity: {e}")
                
                # License
                try:
                    license_resource = api.get_resource('/system/license')
                    licenses = license_resource.get()
                    if licenses:
                        lic = licenses[0]
                        mikrotik_data["license_level"] = lic.get("nlevel", "")
                        mikrotik_data["license_key"] = lic.get("software-id", "")
                except Exception as e:
                    logger.debug(f"Error getting license: {e}")
                
                # Salva o aggiorna MikroTikDetails
                existing_md = session.query(MikroTikDetails).filter(MikroTikDetails.device_id == device_id).first()
                if existing_md:
                    for key, value in mikrotik_data.items():
                        if hasattr(existing_md, key) and value is not None:
                            setattr(existing_md, key, value)
                    existing_md.last_updated = datetime.now()
                else:
                    if mikrotik_data:
                        md = MikroTikDetails(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            **{k: v for k, v in mikrotik_data.items() if hasattr(MikroTikDetails, k)}
                        )
                        session.add(md)
                        logger.info(f"Created MikroTikDetails for device {device_id}")
            except Exception as e:
                logger.error(f"Error collecting MikroTik details: {e}", exc_info=True)
            
            # Raccogli routing table
            try:
                cred = credentials_list[0]
                routes_result = mikrotik_service.get_routes(
                    device.primary_ip,
                    cred.get("mikrotik_api_port", 8728),
                    cred.get("username", ""),
                    cred.get("password", ""),
                    use_ssl=cred.get("use_ssl", False)
                )
                
                if routes_result.get("success") and routes_result.get("routes"):
                    # Salva routing in custom_fields
                    if not device.custom_fields:
                        device.custom_fields = {}
                    if isinstance(device.custom_fields, str):
                        try:
                            device.custom_fields = json.loads(device.custom_fields)
                        except:
                            device.custom_fields = {}
                    device.custom_fields["routing_table"] = routes_result.get("routes")
                    device.custom_fields["routing_count"] = routes_result.get("count", 0)
                    logger.info(f"Saved {routes_result.get('count', 0)} routing entries for MikroTik device {device_id}")
            except Exception as e:
                logger.error(f"Error collecting routing table: {e}", exc_info=True)
            
            # Raccogli ARP table completa
            try:
                cred = credentials_list[0]
                api = mikrotik_service._get_connection(
                    device.primary_ip,
                    cred.get("mikrotik_api_port", 8728),
                    cred.get("username", ""),
                    cred.get("password", ""),
                    use_ssl=cred.get("use_ssl", False)
                )
                
                arp_resource = api.get_resource('/ip/arp')
                arps = arp_resource.get()
                
                arp_entries = []
                for a in arps:
                    ip_str = a.get("address", "")
                    mac = a.get("mac-address", "")
                    if ip_str and mac and mac != "00:00:00:00:00:00":
                        arp_entries.append({
                            "ip": ip_str,
                            "mac": mac.upper(),
                            "interface": a.get("interface", ""),
                            "complete": a.get("complete", "") == "true",
                        })
                
                if arp_entries:
                    # Salva ARP in custom_fields
                    if not device.custom_fields:
                        device.custom_fields = {}
                    if isinstance(device.custom_fields, str):
                        try:
                            device.custom_fields = json.loads(device.custom_fields)
                        except:
                            device.custom_fields = {}
                    device.custom_fields["arp_table"] = arp_entries
                    device.custom_fields["arp_count"] = len(arp_entries)
                    logger.info(f"Saved {len(arp_entries)} ARP entries for MikroTik device {device_id}")
            except Exception as e:
                logger.error(f"Error collecting ARP table: {e}", exc_info=True)
        
        # Proxmox: raccogli info host, VM, storage
        os_family_lower = (device.os_family or "").lower()
        is_proxmox = (
            device_type_lower == "hypervisor" or 
            "proxmox" in vendor_lower or 
            "proxmox" in os_family_lower
        )
        
        if is_proxmox:
            logger.info(f"Device {device_id} identified as Proxmox, collecting host/VM/storage info...")
            logger.info(f"Proxmox collector: Using {len(credentials_list)} credentials for {device.primary_ip}")
            if credentials_list:
                logger.info(f"Credential types: {[c.get('type') for c in credentials_list]}")
            else:
                logger.warning(f"No credentials available for Proxmox device {device_id} at {device.primary_ip}")
            
            proxmox_collector = get_proxmox_collector()
            
            try:
                host_info = await proxmox_collector.collect_proxmox_host_info(
                    device.primary_ip, credentials_list
                )
                
                if host_info:
                    logger.info(f"Proxmox host info collected successfully for {device_id}: node_name={host_info.get('node_name')}")
                    
                    # Aggiorna o crea ProxmoxHost
                    existing_host = session.query(ProxmoxHost).filter(
                        ProxmoxHost.device_id == device_id
                    ).first()
                    
                    if existing_host:
                        # Aggiorna con tutti i campi (inclusi i nuovi)
                        for key, value in host_info.items():
                            if hasattr(existing_host, key):
                                setattr(existing_host, key, value)
                        existing_host.last_updated = datetime.now()
                        host_id = existing_host.id
                        # Flush per salvare l'host anche se ci sono errori dopo
                        try:
                            session.flush()
                            logger.info(f"Host info updated and flushed for device {device_id}")
                        except Exception as host_error:
                            logger.error(f"Error flushing host info: {host_error}", exc_info=True)
                            session.rollback()
                            raise
                    else:
                        # Crea nuovo
                        new_host = ProxmoxHost(
                            id=uuid.uuid4().hex[:8],
                            device_id=device_id,
                            **{k: v for k, v in host_info.items() if hasattr(ProxmoxHost, k)}
                        )
                        session.add(new_host)
                        session.flush()
                        host_id = new_host.id
                        logger.info(f"Host info created and flushed for device {device_id}")
                    
                    # Raccogli VM
                    node_name = host_info.get("node_name")
                    if node_name:
                        vms = await proxmox_collector.collect_proxmox_vms(
                            device.primary_ip, node_name, credentials_list
                        )
                        
                        if vms:
                            # Elimina vecchie VM
                            session.query(ProxmoxVM).filter(ProxmoxVM.host_id == host_id).delete()
                            
                            # Salva nuove VM con tutti i campi da Proxreporter
                            for vm_data in vms:
                                try:
                                    # Converti valori numerici esplicitamente
                                    def safe_int(value):
                                        if value is None:
                                            return None
                                        try:
                                            return int(value)
                                        except (ValueError, TypeError):
                                            return None
                                    
                                    def safe_float(value):
                                        if value is None:
                                            return None
                                        try:
                                            return float(value)
                                        except (ValueError, TypeError):
                                            return None
                                    
                                    vm = ProxmoxVM(
                                        id=uuid.uuid4().hex[:8],
                                        host_id=host_id,
                                        vm_id=safe_int(vm_data.get("vm_id", vm_data.get("vmid", 0))),
                                        vm_type=vm_data.get("type"),  # qemu, lxc
                                        name=vm_data.get("name", ""),
                                        status=vm_data.get("status"),
                                        cpu_cores=safe_int(vm_data.get("cpu_cores")),
                                        cpu_sockets=safe_int(vm_data.get("cpu_sockets")),
                                        cpu_total=safe_int(vm_data.get("cpu_total")),
                                        memory_mb=safe_int(vm_data.get("memory_mb", vm_data.get("memory_total_mb"))),
                                        disk_total_gb=safe_float(vm_data.get("disk_total_gb")),
                                        bios=vm_data.get("bios"),
                                        machine=vm_data.get("machine"),
                                        agent_installed=vm_data.get("agent_installed"),
                                        network_interfaces=vm_data.get("network_interfaces"),
                                        num_networks=safe_int(vm_data.get("num_networks")),
                                        networks=vm_data.get("networks"),
                                        ip_addresses=vm_data.get("ip_addresses"),
                                        num_disks=safe_int(vm_data.get("num_disks")),
                                        disks=vm_data.get("disks"),
                                        disks_details=vm_data.get("disks_details"),
                                        os_type=vm_data.get("os_type", vm_data.get("guest_os")),
                                        template=vm_data.get("template", False),
                                        uptime=safe_int(vm_data.get("uptime")),
                                        cpu_usage=safe_float(vm_data.get("cpu_usage")),
                                        mem_used=safe_int(vm_data.get("mem_used")),
                                        netin=safe_int(vm_data.get("netin")),
                                        netout=safe_int(vm_data.get("netout")),
                                        diskread=safe_int(vm_data.get("diskread")),
                                        diskwrite=safe_int(vm_data.get("diskwrite")),
                                    )
                                    session.add(vm)
                                except Exception as vm_error:
                                    logger.error(f"Error saving VM {vm_data.get('vm_id', 'unknown')}: {vm_error}", exc_info=True)
                                    continue
                            
                            try:
                                session.flush()  # Flush per verificare errori prima del commit finale
                                logger.info(f"Saved {len(vms)} Proxmox VMs for device {device_id}")
                                
                                # Crea dispositivi InventoryDevice per ogni VM (solo se hanno IP)
                                device = session.query(InventoryDevice).filter(InventoryDevice.id == device_id).first()
                                if device:
                                    from ..models.inventory import InventoryDevice as InvDevice
                                    created_count = 0
                                    for vm_data_item in vms:
                                        try:
                                            ip_addresses_str = vm_data_item.get("ip_addresses")
                                            primary_ip = None
                                            if ip_addresses_str:
                                                ips = [ip.strip() for ip in ip_addresses_str.split(';') if ip.strip()]
                                                for ip in ips:
                                                    if not ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                                                        primary_ip = ip
                                                        break
                                            
                                            if primary_ip:
                                                vm_name = vm_data_item.get("name", f"VM-{vm_data_item.get('vm_id', 'unknown')}")
                                                vm_type = vm_data_item.get("type", "qemu")
                                                
                                                existing = session.query(InvDevice).filter(
                                                    InvDevice.customer_id == device.customer_id,
                                                    InvDevice.primary_ip == primary_ip
                                                ).first()
                                                
                                                if not existing:
                                                    device_type = "linux" if vm_type == "lxc" else "server"
                                                    category = "vm" if vm_type == "qemu" else "container"
                                                    
                                                    os_family = None
                                                    os_type = vm_data_item.get("os_type", "").lower()
                                                    if "windows" in os_type or "win" in os_type:
                                                        os_family = "Windows"
                                                        device_type = "windows"
                                                    elif "linux" in os_type or "debian" in os_type or "ubuntu" in os_type:
                                                        os_family = "Linux"
                                                    elif "bsd" in os_type:
                                                        os_family = "BSD"
                                                    
                                                    new_vm_device = InvDevice(
                                                        customer_id=device.customer_id,
                                                        name=f"{vm_name} (VM)",
                                                        hostname=vm_name,
                                                        device_type=device_type,
                                                        category=category,
                                                        primary_ip=primary_ip,
                                                        manufacturer="Proxmox",
                                                        os_family=os_family,
                                                        cpu_cores=safe_int(vm_data_item.get("cpu_cores")),
                                                        ram_total_gb=safe_float(vm_data_item.get("memory_mb")) / 1024.0 if vm_data_item.get("memory_mb") else None,
                                                        identified_by="proxmox_vm",
                                                        status=vm_data_item.get("status", "unknown"),
                                                        description=f"Proxmox {vm_type.upper()} VM su host {device.name if device else 'Unknown'}",
                                                        last_seen=datetime.now(),
                                                    )
                                                    session.add(new_vm_device)
                                                    created_count += 1
                                                    logger.info(f"Created inventory device for VM {vm_name} ({primary_ip})")
                                        except Exception as e:
                                            logger.error(f"Error creating inventory device for VM: {e}", exc_info=True)
                                            continue
                                    
                                    if created_count > 0:
                                        logger.info(f"Created {created_count} inventory devices for Proxmox VMs")
                            except Exception as flush_error:
                                # Usa %s invece di f-string per evitare problemi con caratteri speciali nel messaggio
                                logger.error("Error flushing VMs to database: %s", str(flush_error), exc_info=True)
                                import traceback
                                logger.error("VM flush traceback: %s", traceback.format_exc())
                                # Commit parziale: salva solo l'host, non le VM
                                try:
                                    # Rimuovi le VM dalla sessione per evitare che vengano incluse nel commit
                                    for vm in session.new:
                                        if isinstance(vm, ProxmoxVM) and vm.host_id == host_id:
                                            session.expunge(vm)
                                    session.commit()  # Commit solo dell'host
                                    logger.info(f"Host info committed despite VM save failure")
                                except Exception as commit_error:
                                    logger.error("Error committing host after VM failure: %s", str(commit_error), exc_info=True)
                                    session.rollback()
                                # Continua con lo storage anche se le VM sono fallite
                                logger.warning(f"VM save failed, continuing with storage collection")
                        else:
                            logger.warning(f"No VMs collected for device {device_id}")
                        
                        # Raccogli storage
                        storage_list = await proxmox_collector.collect_proxmox_storage(
                            device.primary_ip, node_name, credentials_list
                        )
                        
                        if storage_list:
                            # Elimina vecchio storage
                            session.query(ProxmoxStorage).filter(ProxmoxStorage.host_id == host_id).delete()
                            
                            # Salva nuovo storage
                            for storage_data in storage_list:
                                try:
                                    # Calcola usage_percent se disponibile
                                    usage_percent = None
                                    total_gb = storage_data.get("total_gb")
                                    used_gb = storage_data.get("used_gb")
                                    if total_gb and used_gb and total_gb > 0:
                                        usage_percent = round((used_gb / total_gb) * 100, 2)
                                    
                                    storage = ProxmoxStorage(
                                        id=uuid.uuid4().hex[:8],
                                        host_id=host_id,
                                        storage_name=storage_data.get("storage", storage_data.get("storage_name", "")),
                                        storage_type=storage_data.get("type", storage_data.get("storage_type")),
                                        total_gb=total_gb,
                                        used_gb=used_gb,
                                        available_gb=storage_data.get("available_gb", storage_data.get("free_gb")),
                                        usage_percent=usage_percent,
                                        content_types=storage_data.get("content", storage_data.get("content_types", [])),
                                    )
                                    session.add(storage)
                                except Exception as storage_error:
                                    logger.error(f"Error saving storage {storage_data.get('storage_name', 'unknown')}: {storage_error}", exc_info=True)
                                    continue
                            
                            try:
                                session.flush()  # Flush per verificare errori prima del commit finale
                                logger.info(f"Saved {len(storage_list)} Proxmox storage for device {device_id}")
                            except Exception as flush_error:
                                logger.error(f"Error flushing storage to database: {flush_error}", exc_info=True)
                                session.rollback()
                                raise
                        else:
                            logger.warning(f"No storage collected for device {device_id}")
                else:
                    logger.warning(f"Proxmox host info collection returned None for {device_id}")
                
            except Exception as e:
                logger.error(f"Error collecting Proxmox info for device {device_id}: {e}", exc_info=True)
                import traceback
                logger.error(f"Traceback: {traceback.format_exc()}")
                # Non fare rollback qui, potrebbe cancellare altri dati già salvati
                # Il commit finale salverà tutto quello che è stato flushato
        
        if not is_network_device and not is_proxmox:
            logger.info(f"Device {device_id} (type={device_type}, vendor={vendor}) does not match network or Proxmox criteria, skipping advanced info collection")
        
        try:
            session.commit()
            logger.info(f"Successfully committed all changes for device {device_id}")
        except Exception as commit_error:
            logger.error(f"Error committing changes for device {device_id}: {commit_error}", exc_info=True)
            session.rollback()
            raise
        
        return {
            "success": True,
            "message": "Advanced info refreshed successfully",
            "device_id": device_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        session.rollback()
        logger.error(f"Error refreshing advanced info: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()
