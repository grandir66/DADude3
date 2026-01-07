#!/usr/bin/env python3
"""
Migration: Add device tracking fields for intelligent data management
Aggiunge campi per tracking date, deduplicazione e pulizia automatica
"""
import sys
import os
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, inspect, text, Index
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.models.database import Base, init_db, DiscoveredDevice
from app.config import Settings


def migrate_add_device_tracking_fields(database_url: str = None):
    """Aggiunge campi tracking a inventory_devices e discovered_devices"""
    
    if not database_url:
        settings = Settings()
        database_url = settings.database_url
    
    engine = create_engine(database_url, echo=False)
    inspector = inspect(engine)
    
    # Verifica se è PostgreSQL o SQLite
    is_postgres = 'postgresql' in database_url.lower()
    is_sqlite = 'sqlite' in database_url.lower()
    
    print(f"Database rilevato: {'PostgreSQL' if is_postgres else 'SQLite'}")
    
    try:
        # Verifica colonne esistenti in inventory_devices
        if inspector.has_table('inventory_devices'):
            columns = [col['name'] for col in inspector.get_columns('inventory_devices')]
            
            # Campi da aggiungere a inventory_devices
            tracking_fields = {
                'first_seen_at': ('TIMESTAMP', 'DATETIME'),
                'last_verified_at': ('TIMESTAMP', 'DATETIME'),
                'verification_count': ('INTEGER', 'INTEGER'),
                'last_scan_network_id': ('VARCHAR(8)', 'VARCHAR(8)'),
                'cleanup_marked_at': ('TIMESTAMP', 'DATETIME'),
            }
            
            for col_name, (pg_type, sqlite_type) in tracking_fields.items():
                if col_name not in columns:
                    col_type = pg_type if is_postgres else sqlite_type
                    print(f"Aggiungo colonna {col_name} a inventory_devices...")
                    
                    with engine.connect() as conn:
                        if col_name == 'verification_count':
                            # Con default value
                            conn.execute(text(
                                f"ALTER TABLE inventory_devices ADD COLUMN {col_name} {col_type} DEFAULT 0"
                            ))
                        else:
                            # Nullable
                            conn.execute(text(
                                f"ALTER TABLE inventory_devices ADD COLUMN {col_name} {col_type}"
                            ))
                        conn.commit()
            
            # Aggiungi foreign key per last_scan_network_id se non esiste
            if 'last_scan_network_id' not in columns:
                # La colonna è già stata aggiunta sopra, ora aggiungiamo FK se PostgreSQL
                if is_postgres:
                    try:
                        with engine.connect() as conn:
                            conn.execute(text(
                                "ALTER TABLE inventory_devices ADD CONSTRAINT fk_inventory_last_scan_network "
                                "FOREIGN KEY (last_scan_network_id) REFERENCES networks(id)"
                            ))
                            conn.commit()
                        print("✓ Foreign key aggiunta per last_scan_network_id")
                    except Exception as e:
                        print(f"⚠ Impossibile aggiungere FK (potrebbe esistere già): {e}")
            
            # Crea indici se non esistono
            indexes = [idx['name'] for idx in inspector.get_indexes('inventory_devices')]
            
            if 'idx_inventory_last_verified' not in indexes:
                print("Creo indice idx_inventory_last_verified...")
                with engine.connect() as conn:
                    conn.execute(text(
                        "CREATE INDEX idx_inventory_last_verified ON inventory_devices(last_verified_at)"
                    ))
                    conn.commit()
            
            if 'idx_inventory_cleanup_marked' not in indexes:
                print("Creo indice idx_inventory_cleanup_marked...")
                with engine.connect() as conn:
                    conn.execute(text(
                        "CREATE INDEX idx_inventory_cleanup_marked ON inventory_devices(cleanup_marked_at)"
                    ))
                    conn.commit()
            
            # Inizializza valori per device esistenti
            print("Inizializzo valori per device esistenti...")
            Session = sessionmaker(bind=engine)
            session = Session()
            
            try:
                # Per device esistenti, imposta first_seen_at e last_verified_at con created_at
                if is_postgres:
                    session.execute(text("""
                        UPDATE inventory_devices 
                        SET first_seen_at = created_at,
                            last_verified_at = created_at,
                            verification_count = 1
                        WHERE first_seen_at IS NULL
                    """))
                else:
                    session.execute(text("""
                        UPDATE inventory_devices 
                        SET first_seen_at = created_at,
                            last_verified_at = created_at,
                            verification_count = 1
                        WHERE first_seen_at IS NULL
                    """))
                
                session.commit()
                print("✓ Valori inizializzati per device esistenti")
            except Exception as e:
                session.rollback()
                print(f"⚠ Errore inizializzazione valori: {e}")
            finally:
                session.close()
        
        # Verifica colonne esistenti in discovered_devices
        if inspector.has_table('discovered_devices'):
            columns = [col['name'] for col in inspector.get_columns('discovered_devices')]
            
            if 'imported_at' not in columns:
                col_type = 'TIMESTAMP' if is_postgres else 'DATETIME'
                print(f"Aggiungo colonna imported_at a discovered_devices...")
                with engine.connect() as conn:
                    conn.execute(text(
                        f"ALTER TABLE discovered_devices ADD COLUMN imported_at {col_type}"
                    ))
                    conn.commit()
        
        print("✓ Migrazione completata con successo")
        
    except Exception as e:
        print(f"✗ Errore durante la migrazione: {e}")
        raise


if __name__ == "__main__":
    migrate_add_device_tracking_fields()
