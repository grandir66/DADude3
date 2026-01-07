#!/usr/bin/env python3
"""
Migration: Add advanced Linux fields for SSH advanced scanner
Adds fields for detailed CPU, memory, storage, network, services, Docker, VM data
"""
import sys
import os
from pathlib import Path

# Aggiungi il path del progetto
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from app.models.database import init_db
from app.config import get_settings
from sqlalchemy import text

def run_migration():
    """Esegue la migration per aggiungere i campi avanzati Linux"""
    settings = get_settings()
    engine = init_db(settings.database_url)
    
    print("→ Esecuzione migration: Add Linux Advanced Fields")
    print(f"  Database: {settings.database_url.split('@')[-1] if '@' in settings.database_url else 'local'}")
    
    migration_sql = """
    -- Docker extended fields
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS containers_stopped INTEGER;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS containers_total INTEGER;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS docker_images_count INTEGER;
    
    -- CPU detailed fields
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_frequency_mhz REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_cache_size VARCHAR(50);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_usage_percent REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_temperature_celsius REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_load_1min REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_load_5min REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS cpu_load_15min REAL;
    
    -- Memory detailed fields
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_available_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_used_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_free_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_cached_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_buffers_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS memory_usage_percent REAL;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS swap_total_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS swap_used_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS swap_free_bytes BIGINT;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS swap_usage_percent REAL;
    
    -- Storage advanced fields (JSON)
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS storage_data JSON;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS disks_data JSON;
    
    -- Network advanced fields
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS network_interfaces_data JSON;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS default_gateway VARCHAR(50);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS dns_servers JSON;
    
    -- Services and VMs
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS services_data JSON;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS vms_data JSON;
    
    -- System info
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS timezone VARCHAR(100);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS boot_time TIMESTAMP;
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS uptime_seconds INTEGER;
    
    -- NAS specific fields
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS nas_model VARCHAR(100);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS nas_serial VARCHAR(100);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS firmware_version VARCHAR(100);
    ALTER TABLE inventory_linux_details ADD COLUMN IF NOT EXISTS firmware_build VARCHAR(50);
    """
    
    try:
        with engine.connect() as conn:
            # Esegui ogni statement separatamente per gestire meglio gli errori
            statements = [s.strip() for s in migration_sql.split(';') if s.strip()]
            
            for i, statement in enumerate(statements, 1):
                if statement:
                    try:
                        conn.execute(text(statement))
                        conn.commit()
                        print(f"  ✓ Statement {i}/{len(statements)} executed")
                    except Exception as e:
                        # Se la colonna esiste già, ignora l'errore
                        if "already exists" in str(e).lower() or "duplicate column" in str(e).lower():
                            print(f"  ⊘ Statement {i}/{len(statements)} skipped (column already exists)")
                        else:
                            print(f"  ✗ Statement {i}/{len(statements)} failed: {e}")
                            raise
        
        print("✓ Migration completed successfully")
        
    except Exception as e:
        print(f"✗ Migration failed: {e}")
        raise
    finally:
        engine.dispose()


if __name__ == "__main__":
    run_migration()

