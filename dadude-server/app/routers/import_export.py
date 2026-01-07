"""
DaDude - Import/Export Router
API endpoints per import/export dati in CSV
"""
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from fastapi.responses import StreamingResponse
from typing import Optional, List
from datetime import datetime
from loguru import logger
import csv
import io

from ..services.customer_service import get_customer_service
from ..services.encryption_service import get_encryption_service
from ..models.customer_schemas import (
    NetworkCreate, NetworkType,
    CredentialCreate, CredentialType,
)

router = APIRouter(prefix="/import-export", tags=["Import/Export"])


# ==========================================
# EXPORT ENDPOINTS
# ==========================================

@router.get("/customers/csv")
async def export_customers_csv(
    active_only: bool = Query(True),
):
    """
    Esporta tutti i clienti in formato CSV.
    """
    service = get_customer_service()
    customers = service.list_customers(active_only=active_only, limit=10000)
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'code', 'name', 'description', 'contact_name', 'contact_email',
        'contact_phone', 'address', 'notes', 'active'
    ])
    writer.writeheader()
    
    for c in customers:
        writer.writerow({
            'code': c.code,
            'name': c.name,
            'description': c.description or '',
            'contact_name': c.contact_name or '',
            'contact_email': c.contact_email or '',
            'contact_phone': c.contact_phone or '',
            'address': c.address or '',
            'notes': c.notes or '',
            'active': c.active,
        })
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=customers_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )


@router.get("/customers/{customer_id}/networks/csv")
async def export_networks_csv(customer_id: str):
    """
    Esporta le reti di un cliente in formato CSV.
    """
    service = get_customer_service()
    
    # Verifica cliente
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    networks = service.list_networks(customer_id=customer_id, active_only=False)
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'name', 'network_type', 'ip_network', 'gateway', 'vlan_id', 'vlan_name',
        'dns_primary', 'dns_secondary', 'dhcp_start', 'dhcp_end',
        'description', 'notes', 'active'
    ])
    writer.writeheader()
    
    for n in networks:
        writer.writerow({
            'name': n.name,
            'network_type': n.network_type,
            'ip_network': n.ip_network,
            'gateway': n.gateway or '',
            'vlan_id': n.vlan_id or '',
            'vlan_name': n.vlan_name or '',
            'dns_primary': n.dns_primary or '',
            'dns_secondary': n.dns_secondary or '',
            'dhcp_start': n.dhcp_start or '',
            'dhcp_end': n.dhcp_end or '',
            'description': n.description or '',
            'notes': n.notes or '',
            'active': n.active,
        })
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=networks_{customer.code}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )


@router.get("/customers/{customer_id}/credentials/csv")
async def export_credentials_csv(
    customer_id: str,
    include_secrets: bool = Query(False, description="Includi password (ATTENZIONE: dati sensibili!)"),
):
    """
    Esporta le credenziali di un cliente in formato CSV.
    
    **ATTENZIONE**: Se include_secrets=True, il file conterrà password in chiaro!
    """
    service = get_customer_service()
    encryption = get_encryption_service()
    
    # Verifica cliente
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    credentials = service.list_credentials(customer_id=customer_id, active_only=False)
    
    fieldnames = [
        'name', 'credential_type', 'username', 'snmp_community', 'snmp_version',
        'api_endpoint', 'vpn_type', 'is_default', 'device_filter',
        'description', 'notes', 'active'
    ]
    
    if include_secrets:
        fieldnames.extend(['password', 'snmp_auth_password', 'snmp_priv_password', 'api_key', 'api_secret'])
    
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    
    for c in credentials:
        row = {
            'name': c.name,
            'credential_type': c.credential_type,
            'username': c.username or '',
            'snmp_community': c.snmp_community or '',
            'snmp_version': c.snmp_version or '',
            'api_endpoint': c.api_endpoint or '',
            'vpn_type': c.vpn_type or '',
            'is_default': c.is_default,
            'device_filter': c.device_filter or '',
            'description': c.description or '',
            'notes': c.notes or '',
            'active': c.active,
        }
        
        if include_secrets:
            # Ottieni credenziale completa con secrets decriptati
            full_cred = service.get_credential(c.id, include_secrets=True)
            row['password'] = full_cred.password or ''
            row['snmp_auth_password'] = full_cred.snmp_auth_password or ''
            row['snmp_priv_password'] = full_cred.snmp_priv_password or ''
            row['api_key'] = full_cred.api_key or ''
            row['api_secret'] = full_cred.api_secret or ''
        
        writer.writerow(row)
    
    output.seek(0)
    
    filename_suffix = "_WITH_SECRETS" if include_secrets else ""
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=credentials_{customer.code}{filename_suffix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        }
    )


# ==========================================
# IMPORT ENDPOINTS
# ==========================================

@router.post("/customers/{customer_id}/networks/csv")
async def import_networks_csv(
    customer_id: str,
    file: UploadFile = File(...),
    skip_errors: bool = Query(False, description="Continua anche in caso di errori"),
):
    """
    Importa reti da file CSV.
    
    Il CSV deve avere le colonne: name, network_type, ip_network, gateway, vlan_id, etc.
    """
    service = get_customer_service()
    
    # Verifica cliente
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    # Leggi file
    content = await file.read()
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        text_content = content.decode('latin-1')
    
    reader = csv.DictReader(io.StringIO(text_content))
    
    results = {
        "imported": 0,
        "skipped": 0,
        "errors": []
    }
    
    for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
        try:
            # Parse network type
            network_type = row.get('network_type', 'lan').lower()
            try:
                network_type_enum = NetworkType(network_type)
            except ValueError:
                network_type_enum = NetworkType.LAN
            
            # Parse VLAN ID
            vlan_id = None
            if row.get('vlan_id'):
                try:
                    vlan_id = int(row['vlan_id'])
                except ValueError:
                    pass
            
            network_data = NetworkCreate(
                customer_id=customer_id,
                name=row['name'],
                network_type=network_type_enum,
                ip_network=row['ip_network'],
                gateway=row.get('gateway') or None,
                vlan_id=vlan_id,
                vlan_name=row.get('vlan_name') or None,
                dns_primary=row.get('dns_primary') or None,
                dns_secondary=row.get('dns_secondary') or None,
                dhcp_start=row.get('dhcp_start') or None,
                dhcp_end=row.get('dhcp_end') or None,
                description=row.get('description') or None,
                notes=row.get('notes') or None,
                active=str(row.get('active', 'true')).lower() in ('true', '1', 'yes'),
            )
            
            service.create_network(network_data)
            results["imported"] += 1
            
        except Exception as e:
            error_msg = f"Riga {row_num}: {str(e)}"
            results["errors"].append(error_msg)
            
            if not skip_errors:
                raise HTTPException(status_code=400, detail=error_msg)
            
            results["skipped"] += 1
    
    logger.info(f"Imported {results['imported']} networks for customer {customer_id}")
    
    return {
        "status": "success",
        "customer_id": customer_id,
        "results": results
    }


@router.post("/customers/{customer_id}/credentials/csv")
async def import_credentials_csv(
    customer_id: str,
    file: UploadFile = File(...),
    skip_errors: bool = Query(False, description="Continua anche in caso di errori"),
):
    """
    Importa credenziali da file CSV.
    
    Il CSV deve avere le colonne: name, credential_type, username, password, etc.
    Le password verranno automaticamente criptate.
    """
    service = get_customer_service()
    
    # Verifica cliente
    customer = service.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail=f"Cliente {customer_id} non trovato")
    
    # Leggi file
    content = await file.read()
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        text_content = content.decode('latin-1')
    
    reader = csv.DictReader(io.StringIO(text_content))
    
    results = {
        "imported": 0,
        "skipped": 0,
        "errors": []
    }
    
    for row_num, row in enumerate(reader, start=2):
        try:
            # Parse credential type
            cred_type = row.get('credential_type', 'device').lower()
            try:
                cred_type_enum = CredentialType(cred_type)
            except ValueError:
                cred_type_enum = CredentialType.DEVICE
            
            cred_data = CredentialCreate(
                customer_id=customer_id,
                name=row['name'],
                credential_type=cred_type_enum,
                username=row.get('username') or None,
                password=row.get('password') or None,
                snmp_community=row.get('snmp_community') or None,
                snmp_version=row.get('snmp_version') or None,
                snmp_auth_password=row.get('snmp_auth_password') or None,
                snmp_priv_password=row.get('snmp_priv_password') or None,
                api_key=row.get('api_key') or None,
                api_secret=row.get('api_secret') or None,
                api_endpoint=row.get('api_endpoint') or None,
                vpn_type=row.get('vpn_type') or None,
                vpn_config=row.get('vpn_config') or None,
                is_default=str(row.get('is_default', 'false')).lower() in ('true', '1', 'yes'),
                device_filter=row.get('device_filter') or None,
                description=row.get('description') or None,
                notes=row.get('notes') or None,
                active=str(row.get('active', 'true')).lower() in ('true', '1', 'yes'),
            )
            
            service.create_credential(cred_data)
            results["imported"] += 1
            
        except Exception as e:
            error_msg = f"Riga {row_num}: {str(e)}"
            results["errors"].append(error_msg)
            
            if not skip_errors:
                raise HTTPException(status_code=400, detail=error_msg)
            
            results["skipped"] += 1
    
    logger.info(f"Imported {results['imported']} credentials for customer {customer_id}")
    
    return {
        "status": "success",
        "customer_id": customer_id,
        "results": results
    }


# ==========================================
# TEMPLATES
# ==========================================

@router.get("/templates/networks")
async def get_networks_template():
    """
    Scarica template CSV per import reti.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'name', 'network_type', 'ip_network', 'gateway', 'vlan_id', 'vlan_name',
        'dns_primary', 'dns_secondary', 'dhcp_start', 'dhcp_end',
        'description', 'notes', 'active'
    ])
    writer.writeheader()
    
    # Esempio
    writer.writerow({
        'name': 'LAN Uffici',
        'network_type': 'lan',
        'ip_network': '192.168.1.0/24',
        'gateway': '192.168.1.1',
        'vlan_id': '100',
        'vlan_name': 'VLAN_UFFICI',
        'dns_primary': '8.8.8.8',
        'dns_secondary': '8.8.4.4',
        'dhcp_start': '192.168.1.100',
        'dhcp_end': '192.168.1.200',
        'description': 'Rete uffici principale',
        'notes': '',
        'active': 'true'
    })
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=template_networks.csv"
        }
    )


@router.get("/templates/credentials")
async def get_credentials_template():
    """
    Scarica template CSV per import credenziali.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        'name', 'credential_type', 'username', 'password', 'snmp_community', 'snmp_version',
        'snmp_auth_password', 'snmp_priv_password', 'api_key', 'api_secret', 'api_endpoint',
        'vpn_type', 'is_default', 'device_filter', 'description', 'notes', 'active'
    ])
    writer.writeheader()
    
    # Esempio device
    writer.writerow({
        'name': 'Router Admin Default',
        'credential_type': 'device',
        'username': 'admin',
        'password': 'secret123',
        'snmp_community': '',
        'snmp_version': '',
        'snmp_auth_password': '',
        'snmp_priv_password': '',
        'api_key': '',
        'api_secret': '',
        'api_endpoint': '',
        'vpn_type': '',
        'is_default': 'true',
        'device_filter': '',
        'description': 'Credenziali di default per router',
        'notes': '',
        'active': 'true'
    })
    
    # Esempio SNMP
    writer.writerow({
        'name': 'SNMP v2c',
        'credential_type': 'snmp',
        'username': '',
        'password': '',
        'snmp_community': 'public',
        'snmp_version': 'v2c',
        'snmp_auth_password': '',
        'snmp_priv_password': '',
        'api_key': '',
        'api_secret': '',
        'api_endpoint': '',
        'vpn_type': '',
        'is_default': 'false',
        'device_filter': 'switch-*',
        'description': 'SNMP per switch',
        'notes': '',
        'active': 'true'
    })
    
    output.seek(0)
    
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=template_credentials.csv"
        }
    )
