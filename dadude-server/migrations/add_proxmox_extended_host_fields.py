#!/usr/bin/env python3
"""
Migration: Add extended host fields to ProxmoxHost
Aggiunge colonne per temperature, BIOS, boot devices, hardware, PCI/USB
"""
import sys
import os
from pathlib import Path
from sqlalchemy import create_engine, inspect, text

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import Settings


def migrate_add_proxmox_extended_host_fields(database_url: str = None):
    """Aggiunge colonne estese a ProxmoxHost"""
    
    if not database_url:
        settings = Settings()
        database_url = settings.database_url
    
    engine = create_engine(database_url, echo=False)
    inspector = inspect(engine)
    
    is_postgres = 'postgresql' in database_url.lower()
    
    print(f"Database rilevato: {'PostgreSQL' if is_postgres else 'SQLite'}")
    
    try:
        with engine.connect() as conn:
            if inspector.has_table('inventory_proxmox_hosts'):
                columns = {col['name']: col for col in inspector.get_columns('inventory_proxmox_hosts')}
                
                fields_to_add = {
                    'temperature_summary': 'JSONB' if is_postgres else 'JSON',
                    'temperature_highest_c': 'REAL',
                    'bios_vendor': 'VARCHAR(100)',
                    'bios_version': 'VARCHAR(100)',
                    'bios_release_date': 'VARCHAR(50)',
                    'system_manufacturer': 'VARCHAR(100)',
                    'system_product': 'VARCHAR(200)',
                    'system_serial': 'VARCHAR(100)',
                    'board_vendor': 'VARCHAR(100)',
                    'board_name': 'VARCHAR(200)',
                    'boot_devices': 'JSONB' if is_postgres else 'JSON',
                    'boot_devices_details': 'JSONB' if is_postgres else 'JSON',
                    'boot_entries': 'JSONB' if is_postgres else 'JSON',
                    'hardware_system': 'JSONB' if is_postgres else 'JSON',
                    'hardware_bus': 'JSONB' if is_postgres else 'JSON',
                    'hardware_memory': 'JSONB' if is_postgres else 'JSON',
                    'hardware_processor': 'JSONB' if is_postgres else 'JSON',
                    'hardware_storage': 'JSONB' if is_postgres else 'JSON',
                    'hardware_disk': 'JSONB' if is_postgres else 'JSON',
                    'hardware_volume': 'JSONB' if is_postgres else 'JSON',
                    'hardware_network': 'JSONB' if is_postgres else 'JSON',
                    'hardware_product': 'VARCHAR(200)',
                    'pci_devices': 'JSONB' if is_postgres else 'JSON',
                    'usb_devices': 'JSONB' if is_postgres else 'JSON',
                }
                
                for col_name, col_type in fields_to_add.items():
                    if col_name not in columns:
                        print(f"Aggiungendo colonna {col_name} in inventory_proxmox_hosts...")
                        if is_postgres:
                            conn.execute(text(
                                f"ALTER TABLE inventory_proxmox_hosts ADD COLUMN {col_name} {col_type}"
                            ))
                        else:
                            # SQLite non supporta ALTER TABLE ADD COLUMN per alcuni tipi
                            print(f"  Skipping {col_name} in SQLite (richiede ricreazione tabella)")
                        conn.commit()
                    else:
                        print(f"Colonna {col_name} già presente in inventory_proxmox_hosts.")
            else:
                print("Tabella inventory_proxmox_hosts non trovata.")
        
        print("✓ Migrazione completata con successo")
        
    except Exception as e:
        print(f"✗ Errore durante la migrazione: {e}")
        raise


if __name__ == "__main__":
    migrate_add_proxmox_extended_host_fields()

