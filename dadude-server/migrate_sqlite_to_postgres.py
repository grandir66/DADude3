#!/usr/bin/env python3
"""
Script di migrazione dati da SQLite a PostgreSQL
"""
import argparse
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from loguru import logger

# Aggiungi path progetto
sys.path.insert(0, str(Path(__file__).parent))

from app.models.database import (
    Base, Customer, Network, Credential, CustomerCredentialLink,
    DeviceAssignment, AlertHistory, AgentAssignment, ScanResult, DiscoveredDevice
)
from app.models.inventory import InventoryDevice

# Ordine di migrazione (rispetta foreign keys)
# IMPORTANTE: Credential deve essere prima di InventoryDevice per preservare foreign keys
MIGRATION_ORDER = [
    Customer,
    Credential,  # Prima delle tabelle che referenziano credenziali
    CustomerCredentialLink,
    Network,
    AgentAssignment,
    DeviceAssignment,
    ScanResult,
    DiscoveredDevice,
    AlertHistory,
]

# Tabelle aggiuntive da migrare (se esistono)
ADDITIONAL_TABLES = [
    InventoryDevice,  # Se esiste nella vecchia versione
]


def migrate_table(sqlite_session, pg_session, model_class, table_name):
    """Migra una singola tabella"""
    logger.info(f"Migrazione tabella: {table_name}")
    
    # Conta record esistenti
    count = sqlite_session.query(model_class).count()
    if count == 0:
        logger.info(f"  Nessun record da migrare")
        return 0
    
    logger.info(f"  Trovati {count} record")
    
    # Migra record
    migrated = 0
    for record in sqlite_session.query(model_class).all():
        try:
            # Converte record SQLite in dict preservando tutti i valori
            data = {}
            for column in model_class.__table__.columns:
                value = getattr(record, column.name)
                
                # Preserva valori criptati (stringhe non vuote)
                if isinstance(value, str) and value:
                    data[column.name] = value
                # Gestisci conversioni tipo
                elif isinstance(value, bool):
                    data[column.name] = value
                elif value is None:
                    data[column.name] = None
                elif isinstance(value, (int, float)):
                    data[column.name] = value
                elif hasattr(value, 'isoformat'):  # datetime
                    data[column.name] = value
                else:
                    # Fallback: converti a stringa per sicurezza
                    data[column.name] = str(value) if value is not None else None
            
            # Verifica che i campi critici siano preservati (per Credential)
            if table_name == "credentials":
                critical_fields = ['password', 'ssh_private_key', 'ssh_passphrase', 
                                 'snmp_auth_password', 'snmp_priv_password', 
                                 'api_key', 'api_secret']
                for field in critical_fields:
                    if hasattr(record, field):
                        original_value = getattr(record, field)
                        if original_value and original_value not in [None, '']:
                            if field not in data or data[field] != original_value:
                                logger.warning(f"  Campo critico {field} potrebbe essere perso per credenziale {record.id}")
                                data[field] = original_value
            
            # Crea nuovo record PostgreSQL
            pg_record = model_class(**data)
            pg_session.merge(pg_record)  # merge gestisce duplicati
            migrated += 1
            
        except Exception as e:
            logger.error(f"  Errore migrazione record {getattr(record, 'id', 'unknown')}: {e}")
            logger.debug(f"  Dettagli errore: {type(e).__name__}: {str(e)}")
            continue
    
    pg_session.commit()
    logger.success(f"  Migrati {migrated}/{count} record")
    return migrated


def verify_migration(sqlite_session, pg_session, model_class, table_name):
    """Verifica che la migrazione sia corretta"""
    sqlite_count = sqlite_session.query(model_class).count()
    pg_count = pg_session.query(model_class).count()
    
    if sqlite_count == pg_count:
        logger.success(f"  ✓ Verifica {table_name}: {pg_count} record")
        return True
    else:
        logger.error(f"  ✗ Verifica {table_name}: SQLite={sqlite_count}, PostgreSQL={pg_count}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Migra dati da SQLite a PostgreSQL")
    parser.add_argument("--sqlite", required=True, help="URL database SQLite")
    parser.add_argument("--postgres", required=True, help="URL database PostgreSQL")
    parser.add_argument("--verify-only", action="store_true", help="Solo verifica, non migra")
    parser.add_argument("--force", action="store_true", help="Forza migrazione anche se PostgreSQL non è vuoto")
    
    args = parser.parse_args()
    
    # Configura logging
    logger.remove()
    logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")
    
    # Connessioni database
    logger.info("Connessione database SQLite...")
    sqlite_engine = create_engine(args.sqlite, echo=False)
    sqlite_session = sessionmaker(bind=sqlite_engine)()
    
    logger.info("Connessione database PostgreSQL...")
    pg_engine = create_engine(args.postgres, echo=False)
    pg_session = sessionmaker(bind=pg_engine)()
    
    # Verifica che PostgreSQL sia vuoto (se non --force)
    if not args.force:
        inspector = inspect(pg_engine)
        existing_tables = inspector.get_table_names()
        if existing_tables:
            logger.warning(f"PostgreSQL contiene già {len(existing_tables)} tabelle")
            response = input("Vuoi continuare? I dati esistenti potrebbero essere sovrascritti (s/n): ")
            if response.lower() != 's':
                logger.info("Migrazione annullata")
                return
    
    # Crea schema PostgreSQL se non esiste
    logger.info("Creazione schema PostgreSQL...")
    Base.metadata.create_all(pg_engine)
    
    if args.verify_only:
        # Solo verifica
        logger.info("Modalità verifica...")
        all_ok = True
        for model_class in MIGRATION_ORDER:
            table_name = model_class.__table__.name
            if not verify_migration(sqlite_session, pg_session, model_class, table_name):
                all_ok = False
        
        if all_ok:
            logger.success("✓ Tutte le verifiche superate!")
        else:
            logger.error("✗ Alcune verifiche fallite")
        return
    
    # Migrazione
    logger.info("Inizio migrazione dati...")
    total_migrated = 0
    
    for model_class in MIGRATION_ORDER:
        table_name = model_class.__table__.name
        try:
            migrated = migrate_table(sqlite_session, pg_session, model_class, table_name)
            total_migrated += migrated
        except Exception as e:
            logger.error(f"Errore migrazione {table_name}: {e}", exc_info=True)
            pg_session.rollback()
    
    # Migra tabelle aggiuntive se esistono
    logger.info("Verifica tabelle aggiuntive...")
    inspector = inspect(sqlite_engine)
    sqlite_tables = set(inspector.get_table_names())
    
    for model_class in ADDITIONAL_TABLES:
        table_name = model_class.__table__.name
        if table_name in sqlite_tables:
            logger.info(f"Trovata tabella aggiuntiva: {table_name}")
            try:
                migrated = migrate_table(sqlite_session, pg_session, model_class, table_name)
                total_migrated += migrated
            except Exception as e:
                logger.warning(f"Errore migrazione tabella aggiuntiva {table_name}: {e}")
    
    # Verifica finale
    logger.info("Verifica finale migrazione...")
    all_ok = True
    
    # Verifica tabelle principali
    for model_class in MIGRATION_ORDER:
        table_name = model_class.__table__.name
        if not verify_migration(sqlite_session, pg_session, model_class, table_name):
            all_ok = False
    
    # Verifica foreign keys critiche
    logger.info("Verifica foreign keys critiche...")
    if sqlite_tables and 'credentials' in sqlite_tables and 'inventory_devices' in sqlite_tables:
        # Verifica che i device mantengano i riferimenti alle credenziali
        sqlite_devices_with_cred = sqlite_session.execute(
            "SELECT COUNT(*) FROM inventory_devices WHERE credential_id IS NOT NULL"
        ).scalar() or 0
        
        pg_devices_with_cred = pg_session.execute(
            "SELECT COUNT(*) FROM inventory_devices WHERE credential_id IS NOT NULL"
        ).scalar() or 0
        
        if sqlite_devices_with_cred == pg_devices_with_cred:
            logger.success(f"  ✓ Foreign keys credential_id preservate: {pg_devices_with_cred} device")
        else:
            logger.error(f"  ✗ Foreign keys credential_id perse: SQLite={sqlite_devices_with_cred}, PostgreSQL={pg_devices_with_cred}")
            all_ok = False
    
    if all_ok:
        logger.success(f"✓ Migrazione completata: {total_migrated} record migrati")
    else:
        logger.error("✗ Migrazione completata con errori di verifica")
    
    # Chiudi connessioni
    sqlite_session.close()
    pg_session.close()


if __name__ == "__main__":
    main()

