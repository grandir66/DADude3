#!/usr/bin/env python3
"""
Script di validazione post-migrazione per verificare integrità credenziali
Verifica che tutte le credenziali siano state migrate correttamente
e che i device mantengano i riferimenti alle credenziali
"""
import argparse
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from loguru import logger

# Aggiungi path progetto
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models.database import Credential, CustomerCredentialLink
from app.models.inventory import InventoryDevice


def validate_credentials_migration(sqlite_url: str, postgres_url: str):
    """Valida che la migrazione delle credenziali sia corretta"""
    logger.info("Connessione database SQLite...")
    sqlite_engine = create_engine(sqlite_url, echo=False)
    sqlite_session = sessionmaker(bind=sqlite_engine)()
    
    logger.info("Connessione database PostgreSQL...")
    pg_engine = create_engine(postgres_url, echo=False)
    pg_session = sessionmaker(bind=pg_engine)()
    
    all_ok = True
    
    try:
        # 1. Verifica conteggio credenziali
        logger.info("Verifica conteggio credenziali...")
        sqlite_cred_count = sqlite_session.query(Credential).count()
        pg_cred_count = pg_session.query(Credential).count()
        
        if sqlite_cred_count == pg_cred_count:
            logger.success(f"  ✓ Credenziali: {pg_cred_count} (match)")
        else:
            logger.error(f"  ✗ Credenziali: SQLite={sqlite_cred_count}, PostgreSQL={pg_cred_count}")
            all_ok = False
        
        # 2. Verifica campi critici (password criptate)
        logger.info("Verifica campi critici (password criptate)...")
        sqlite_creds = sqlite_session.query(Credential).all()
        pg_creds = {c.id: c for c in pg_session.query(Credential).all()}
        
        critical_fields = ['password', 'ssh_private_key', 'ssh_passphrase', 
                          'snmp_auth_password', 'snmp_priv_password', 
                          'api_key', 'api_secret']
        
        fields_ok = 0
        fields_failed = 0
        
        for sqlite_cred in sqlite_creds:
            if sqlite_cred.id not in pg_creds:
                logger.error(f"  ✗ Credenziale {sqlite_cred.id} ({sqlite_cred.name}) non trovata in PostgreSQL")
                all_ok = False
                continue
            
            pg_cred = pg_creds[sqlite_cred.id]
            
            for field in critical_fields:
                sqlite_value = getattr(sqlite_cred, field, None)
                pg_value = getattr(pg_cred, field, None)
                
                if sqlite_value and sqlite_value not in [None, '']:
                    if pg_value == sqlite_value:
                        fields_ok += 1
                    else:
                        logger.warning(f"  ⚠ Campo {field} potrebbe essere diverso per credenziale {sqlite_cred.id}")
                        fields_failed += 1
        
        if fields_failed == 0:
            logger.success(f"  ✓ Campi critici preservati: {fields_ok} verificati")
        else:
            logger.error(f"  ✗ Campi critici: {fields_failed} potenziali problemi")
            all_ok = False
        
        # 3. Verifica link credenziali-cliente
        logger.info("Verifica link credenziali-cliente...")
        sqlite_link_count = sqlite_session.query(CustomerCredentialLink).count()
        pg_link_count = pg_session.query(CustomerCredentialLink).count()
        
        if sqlite_link_count == pg_link_count:
            logger.success(f"  ✓ Link credenziali-cliente: {pg_link_count} (match)")
        else:
            logger.error(f"  ✗ Link: SQLite={sqlite_link_count}, PostgreSQL={pg_link_count}")
            all_ok = False
        
        # 4. Verifica foreign keys credential_id nei device
        logger.info("Verifica foreign keys credential_id nei device...")
        
        # Verifica se la tabella inventory_devices esiste
        sqlite_inspector = inspect(sqlite_engine)
        pg_inspector = inspect(pg_engine)
        
        if 'inventory_devices' in sqlite_inspector.get_table_names():
            sqlite_devices_with_cred = sqlite_session.execute(
                "SELECT COUNT(*) FROM inventory_devices WHERE credential_id IS NOT NULL"
            ).scalar() or 0
            
            if 'inventory_devices' in pg_inspector.get_table_names():
                pg_devices_with_cred = pg_session.execute(
                    "SELECT COUNT(*) FROM inventory_devices WHERE credential_id IS NOT NULL"
                ).scalar() or 0
                
                if sqlite_devices_with_cred == pg_devices_with_cred:
                    logger.success(f"  ✓ Device con credential_id: {pg_devices_with_cred} (match)")
                else:
                    logger.error(f"  ✗ Device con credential_id: SQLite={sqlite_devices_with_cred}, PostgreSQL={pg_devices_with_cred}")
                    all_ok = False
                
                # Verifica che i credential_id referenzino credenziali esistenti
                logger.info("Verifica integrità referenziale credential_id...")
                invalid_refs = pg_session.execute("""
                    SELECT COUNT(*) FROM inventory_devices d
                    WHERE d.credential_id IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM credentials c WHERE c.id = d.credential_id
                    )
                """).scalar() or 0
                
                if invalid_refs == 0:
                    logger.success(f"  ✓ Tutti i credential_id referenziano credenziali esistenti")
                else:
                    logger.error(f"  ✗ Trovati {invalid_refs} credential_id che referenziano credenziali inesistenti")
                    all_ok = False
            else:
                logger.warning("  ⚠ Tabella inventory_devices non trovata in PostgreSQL")
        else:
            logger.info("  ℹ Tabella inventory_devices non presente in SQLite")
        
        # 5. Verifica credenziali per tipo
        logger.info("Verifica credenziali per tipo...")
        sqlite_types = {}
        for cred in sqlite_creds:
            cred_type = cred.credential_type or 'unknown'
            sqlite_types[cred_type] = sqlite_types.get(cred_type, 0) + 1
        
        pg_types = {}
        for cred in pg_creds.values():
            cred_type = cred.credential_type or 'unknown'
            pg_types[cred_type] = pg_types.get(cred_type, 0) + 1
        
        types_match = True
        for cred_type in set(list(sqlite_types.keys()) + list(pg_types.keys())):
            sqlite_count = sqlite_types.get(cred_type, 0)
            pg_count = pg_types.get(cred_type, 0)
            if sqlite_count == pg_count:
                logger.success(f"  ✓ Tipo {cred_type}: {pg_count} (match)")
            else:
                logger.error(f"  ✗ Tipo {cred_type}: SQLite={sqlite_count}, PostgreSQL={pg_count}")
                types_match = False
        
        if not types_match:
            all_ok = False
        
        return all_ok
        
    finally:
        sqlite_session.close()
        pg_session.close()


def main():
    parser = argparse.ArgumentParser(description="Valida migrazione credenziali")
    parser.add_argument("--sqlite", required=True, help="URL database SQLite")
    parser.add_argument("--postgres", required=True, help="URL database PostgreSQL")
    
    args = parser.parse_args()
    
    # Configura logging
    logger.remove()
    logger.add(sys.stderr, level="INFO", 
              format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
    
    logger.info("Inizio validazione migrazione credenziali...")
    
    all_ok = validate_credentials_migration(args.sqlite, args.postgres)
    
    if all_ok:
        logger.success("✓ Validazione completata: tutte le verifiche superate!")
        sys.exit(0)
    else:
        logger.error("✗ Validazione fallita: alcune verifiche non superate")
        sys.exit(1)


if __name__ == "__main__":
    main()

