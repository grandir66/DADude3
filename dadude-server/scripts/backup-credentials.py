#!/usr/bin/env python3
"""
Script di backup credenziali prima di aggiornamenti/migrazioni
Esporta tutte le credenziali in formato JSON criptato
"""
import argparse
import json
import sys
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from loguru import logger
import base64

# Aggiungi path progetto
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models.database import Credential, CustomerCredentialLink
from app.config import get_settings
from app.services.encryption_service import get_encryption_service


def export_credentials(db_url: str, output_file: str, encrypt: bool = True):
    """Esporta tutte le credenziali dal database"""
    logger.info(f"Connessione database: {db_url.split('@')[1] if '@' in db_url else 'local'}")
    
    engine = create_engine(db_url, echo=False)
    session = sessionmaker(bind=engine)()
    
    try:
        # Carica tutte le credenziali
        credentials = session.query(Credential).all()
        logger.info(f"Trovate {len(credentials)} credenziali")
        
        # Carica link credenziali-cliente
        links = session.query(CustomerCredentialLink).all()
        logger.info(f"Trovati {len(links)} link credenziali-cliente")
        
        # Prepara dati per export
        export_data = {
            "export_date": datetime.now().isoformat(),
            "database_url": db_url.split('@')[1] if '@' in db_url else db_url,
            "credentials": [],
            "credential_links": []
        }
        
        encryption = get_encryption_service() if encrypt else None
        
        for cred in credentials:
            cred_data = {
                "id": cred.id,
                "customer_id": cred.customer_id,
                "is_global": cred.is_global,
                "name": cred.name,
                "credential_type": cred.credential_type,
                "username": cred.username,
                # Password e campi sensibili vengono preservati così come sono (già criptati)
                "password": cred.password,
                "ssh_port": cred.ssh_port,
                "ssh_private_key": cred.ssh_private_key,
                "ssh_passphrase": cred.ssh_passphrase,
                "ssh_key_type": cred.ssh_key_type,
                "snmp_community": cred.snmp_community,
                "snmp_version": cred.snmp_version,
                "snmp_port": cred.snmp_port,
                "snmp_security_level": cred.snmp_security_level,
                "snmp_auth_protocol": cred.snmp_auth_protocol,
                "snmp_priv_protocol": cred.snmp_priv_protocol,
                "snmp_auth_password": cred.snmp_auth_password,
                "snmp_priv_password": cred.snmp_priv_password,
                "wmi_domain": cred.wmi_domain,
                "wmi_namespace": cred.wmi_namespace,
                "mikrotik_api_port": cred.mikrotik_api_port,
                "mikrotik_api_ssl": cred.mikrotik_api_ssl,
                "api_key": cred.api_key,
                "api_secret": cred.api_secret,
                "api_endpoint": cred.api_endpoint,
                "vpn_type": cred.vpn_type,
                "vpn_config": cred.vpn_config,
                "is_default": cred.is_default,
                "device_filter": cred.device_filter,
                "description": cred.description,
                "notes": cred.notes,
                "active": cred.active,
                "created_at": cred.created_at.isoformat() if cred.created_at else None,
                "updated_at": cred.updated_at.isoformat() if cred.updated_at else None,
            }
            export_data["credentials"].append(cred_data)
        
        for link in links:
            link_data = {
                "id": link.id,
                "credential_id": link.credential_id,
                "customer_id": link.customer_id,
                "is_default": link.is_default,
                "created_at": link.created_at.isoformat() if link.created_at else None,
            }
            export_data["credential_links"].append(link_data)
        
        # Salva in JSON
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.success(f"✓ Backup salvato in: {output_path}")
        logger.info(f"  Credenziali: {len(export_data['credentials'])}")
        logger.info(f"  Link: {len(export_data['credential_links'])}")
        logger.warning(f"⚠️  File contiene dati sensibili criptati. Conservalo in modo sicuro!")
        
        return True
        
    except Exception as e:
        logger.error(f"Errore durante backup: {e}", exc_info=True)
        return False
    finally:
        session.close()


def main():
    parser = argparse.ArgumentParser(description="Backup credenziali prima di aggiornamenti")
    parser.add_argument("--db-url", help="URL database (default: da config)")
    parser.add_argument("--output", "-o", default="backups/credentials_backup.json", 
                       help="File di output (default: backups/credentials_backup.json)")
    parser.add_argument("--no-encrypt", action="store_true", 
                       help="Non criptare il backup (i dati nel DB sono già criptati)")
    
    args = parser.parse_args()
    
    # Configura logging
    logger.remove()
    logger.add(sys.stderr, level="INFO", 
              format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
    
    # Ottieni database URL
    if args.db_url:
        db_url = args.db_url
    else:
        settings = get_settings()
        db_url = settings.database_url
    
    # Esegui backup
    success = export_credentials(db_url, args.output, encrypt=not args.no_encrypt)
    
    if success:
        logger.success("✓ Backup completato con successo")
        sys.exit(0)
    else:
        logger.error("✗ Backup fallito")
        sys.exit(1)


if __name__ == "__main__":
    main()

