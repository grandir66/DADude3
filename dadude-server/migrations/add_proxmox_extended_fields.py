#!/usr/bin/env python3
"""
Migration: Add extended Proxmox fields from Proxreporter integration
Adds swap, rootfs, KSM, subscription details, boot mode, and VM extended fields
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
    """Esegue la migration per aggiungere i campi estesi Proxmox"""
    settings = get_settings()
    engine = init_db(settings.database_url)
    
    print("→ Esecuzione migration: Add Proxmox Extended Fields")
    print(f"  Database: {settings.database_url.split('@')[-1] if '@' in settings.database_url else 'local'}")
    
    migration_sql = """
    -- Swap info
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS swap_total_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS swap_used_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS swap_free_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS swap_usage_percent REAL;
    
    -- Rootfs info
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS rootfs_total_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS rootfs_used_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS rootfs_free_gb REAL;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS rootfs_usage_percent REAL;
    
    -- KSM sharing
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS ksm_sharing_gb REAL;
    
    -- Subscription dettagliata
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS subscription_server_id VARCHAR(255);
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS subscription_sockets INTEGER;
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS subscription_last_check VARCHAR(100);
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS subscription_next_due VARCHAR(100);
    
    -- Repository status
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS repository_status TEXT;
    
    -- Boot mode
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS boot_mode VARCHAR(50);
    
    -- Manager version
    ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS manager_version VARCHAR(50);
    
    -- VM Type (qemu, lxc)
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS vm_type VARCHAR(20);
    
    -- CPU dettagliato
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS cpu_sockets INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS cpu_total INTEGER;
    
    -- BIOS e Machine
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS bios VARCHAR(50);
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS machine VARCHAR(50);
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS agent_installed BOOLEAN;
    
    -- Network dettagliato
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS num_networks INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS networks VARCHAR(500);
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS ip_addresses VARCHAR(500);
    
    -- Dischi dettagliati
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS num_disks INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS disks VARCHAR(500);
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS disks_details JSON;
    
    -- Performance metrics
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS uptime INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS cpu_usage REAL;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS mem_used INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS netin INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS netout INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS diskread INTEGER;
    ALTER TABLE inventory_proxmox_vms ADD COLUMN IF NOT EXISTS diskwrite INTEGER;
    """
    
    # Per SQLite, usa un approccio diverso
    if 'sqlite' in settings.database_url.lower():
        print("  ⚠ SQLite rilevato - alcune colonne potrebbero già esistere")
        print("  → Verifica manuale consigliata")
    
    try:
        with engine.connect() as conn:
            # Esegui ogni statement separatamente per gestire meglio gli errori
            statements = [s.strip() for s in migration_sql.split(';') if s.strip() and not s.strip().startswith('--')]
            
            for i, statement in enumerate(statements, 1):
                if not statement:
                    continue
                try:
                    conn.execute(text(statement))
                    conn.commit()
                    print(f"  ✓ Statement {i}/{len(statements)} eseguito")
                except Exception as e:
                    # Ignora errori "column already exists" per SQLite
                    if 'already exists' in str(e).lower() or 'duplicate column' in str(e).lower():
                        print(f"  ⚠ Statement {i}: colonna già esistente (ignorato)")
                    else:
                        print(f"  ✗ Errore statement {i}: {e}")
                        raise
            
            print("  ✓ Migration completata con successo")
            
    except Exception as e:
        print(f"  ✗ Errore durante la migration: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == '__main__':
    success = run_migration()
    sys.exit(0 if success else 1)

