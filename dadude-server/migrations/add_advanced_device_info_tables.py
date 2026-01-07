#!/usr/bin/env python3
"""
Migration: Add advanced device information tables
Aggiunge tabelle per LLDP/CDP neighbors, Proxmox info e estende NetworkInterface
"""
import sys
import os
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, inspect, text, Index
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import Settings


def migrate_add_advanced_device_info_tables(database_url: str = None):
    """Aggiunge tabelle per informazioni avanzate device"""
    
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
        with engine.connect() as conn:
            # Estendi NetworkInterface con nuovi campi
            if inspector.has_table('inventory_network_interfaces'):
                columns = [col['name'] for col in inspector.get_columns('inventory_network_interfaces')]
                
                new_fields = {
                    'lldp_enabled': ('BOOLEAN', 'BOOLEAN'),
                    'cdp_enabled': ('BOOLEAN', 'BOOLEAN'),
                    'poe_enabled': ('BOOLEAN', 'BOOLEAN'),
                    'poe_power_watts': ('REAL', 'REAL'),
                    'vlan_native': ('INTEGER', 'INTEGER'),
                    'vlan_trunk_allowed': ('JSONB', 'JSON'),
                    'stp_state': ('VARCHAR(20)', 'VARCHAR(20)'),
                    'lacp_enabled': ('BOOLEAN', 'BOOLEAN'),
                }
                
                for col_name, (pg_type, sqlite_type) in new_fields.items():
                    if col_name not in columns:
                        col_type = pg_type if is_postgres else sqlite_type
                        print(f"Aggiungo colonna {col_name} a inventory_network_interfaces...")
                        conn.execute(text(
                            f"ALTER TABLE inventory_network_interfaces ADD COLUMN {col_name} {col_type}"
                        ))
                        conn.commit()
            
            # Crea tabella LLDPNeighbor
            if not inspector.has_table('inventory_lldp_neighbors'):
                print("Creo tabella inventory_lldp_neighbors...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_lldp_neighbors (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            local_interface VARCHAR(100) NOT NULL,
                            remote_device_name VARCHAR(255),
                            remote_device_description VARCHAR(500),
                            remote_port VARCHAR(100),
                            remote_mac VARCHAR(20),
                            remote_ip VARCHAR(50),
                            chassis_id VARCHAR(100),
                            chassis_id_type VARCHAR(20),
                            capabilities JSONB,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_lldp_neighbors (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            local_interface VARCHAR(100) NOT NULL,
                            remote_device_name VARCHAR(255),
                            remote_device_description VARCHAR(500),
                            remote_port VARCHAR(100),
                            remote_mac VARCHAR(20),
                            remote_ip VARCHAR(50),
                            chassis_id VARCHAR(100),
                            chassis_id_type VARCHAR(20),
                            capabilities JSON,
                            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_lldp_device ON inventory_lldp_neighbors(device_id)"))
                conn.execute(text("CREATE INDEX idx_lldp_local_interface ON inventory_lldp_neighbors(local_interface)"))
                conn.execute(text("CREATE INDEX idx_lldp_remote_mac ON inventory_lldp_neighbors(remote_mac)"))
                conn.commit()
                print("✓ Tabella inventory_lldp_neighbors creata")
            
            # Crea tabella CDPNeighbor
            if not inspector.has_table('inventory_cdp_neighbors'):
                print("Creo tabella inventory_cdp_neighbors...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_cdp_neighbors (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            local_interface VARCHAR(100) NOT NULL,
                            remote_device_id VARCHAR(255),
                            remote_device_name VARCHAR(255),
                            remote_port VARCHAR(100),
                            remote_ip VARCHAR(50),
                            remote_version VARCHAR(255),
                            platform VARCHAR(100),
                            capabilities JSONB,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_cdp_neighbors (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            local_interface VARCHAR(100) NOT NULL,
                            remote_device_id VARCHAR(255),
                            remote_device_name VARCHAR(255),
                            remote_port VARCHAR(100),
                            remote_ip VARCHAR(50),
                            remote_version VARCHAR(255),
                            platform VARCHAR(100),
                            capabilities JSON,
                            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_cdp_device ON inventory_cdp_neighbors(device_id)"))
                conn.execute(text("CREATE INDEX idx_cdp_local_interface ON inventory_cdp_neighbors(local_interface)"))
                conn.execute(text("CREATE INDEX idx_cdp_remote_device_id ON inventory_cdp_neighbors(remote_device_id)"))
                conn.commit()
                print("✓ Tabella inventory_cdp_neighbors creata")
            
            # Crea tabella ProxmoxHost
            if not inspector.has_table('inventory_proxmox_hosts'):
                print("Creo tabella inventory_proxmox_hosts...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_hosts (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL UNIQUE REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            node_name VARCHAR(100) NOT NULL,
                            cluster_name VARCHAR(100),
                            proxmox_version VARCHAR(50),
                            kernel_version VARCHAR(100),
                            cpu_model VARCHAR(200),
                            cpu_cores INTEGER,
                            cpu_sockets INTEGER,
                            cpu_threads INTEGER,
                            cpu_total_cores INTEGER,
                            memory_total_gb REAL,
                            memory_used_gb REAL,
                            memory_free_gb REAL,
                            memory_usage_percent REAL,
                            storage_list JSONB,
                            network_interfaces JSONB,
                            license_status VARCHAR(50),
                            license_message TEXT,
                            license_level VARCHAR(50),
                            subscription_type VARCHAR(50),
                            subscription_key VARCHAR(255),
                            uptime_seconds INTEGER,
                            uptime_human VARCHAR(100),
                            load_average_1m REAL,
                            load_average_5m REAL,
                            load_average_15m REAL,
                            cpu_usage_percent REAL,
                            io_delay_percent REAL,
                            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_hosts (
                            id VARCHAR(8) PRIMARY KEY,
                            device_id VARCHAR(8) NOT NULL UNIQUE REFERENCES inventory_devices(id) ON DELETE CASCADE,
                            node_name VARCHAR(100) NOT NULL,
                            cluster_name VARCHAR(100),
                            proxmox_version VARCHAR(50),
                            kernel_version VARCHAR(100),
                            cpu_model VARCHAR(200),
                            cpu_cores INTEGER,
                            cpu_sockets INTEGER,
                            cpu_threads INTEGER,
                            cpu_total_cores INTEGER,
                            memory_total_gb REAL,
                            memory_used_gb REAL,
                            memory_free_gb REAL,
                            memory_usage_percent REAL,
                            storage_list JSON,
                            network_interfaces JSON,
                            license_status VARCHAR(50),
                            license_message TEXT,
                            license_level VARCHAR(50),
                            subscription_type VARCHAR(50),
                            subscription_key VARCHAR(255),
                            uptime_seconds INTEGER,
                            uptime_human VARCHAR(100),
                            load_average_1m REAL,
                            load_average_5m REAL,
                            load_average_15m REAL,
                            cpu_usage_percent REAL,
                            io_delay_percent REAL,
                            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_proxmox_host_device ON inventory_proxmox_hosts(device_id)"))
                conn.execute(text("CREATE INDEX idx_proxmox_host_node ON inventory_proxmox_hosts(node_name)"))
                conn.commit()
                print("✓ Tabella inventory_proxmox_hosts creata")
            
            # Crea tabella ProxmoxVM
            if not inspector.has_table('inventory_proxmox_vms'):
                print("Creo tabella inventory_proxmox_vms...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_vms (
                            id VARCHAR(8) PRIMARY KEY,
                            host_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_hosts(id) ON DELETE CASCADE,
                            vm_id INTEGER NOT NULL,
                            name VARCHAR(255) NOT NULL,
                            status VARCHAR(20),
                            cpu_cores INTEGER,
                            memory_mb INTEGER,
                            disk_total_gb REAL,
                            network_interfaces JSONB,
                            os_type VARCHAR(50),
                            template BOOLEAN DEFAULT FALSE,
                            backup_enabled BOOLEAN,
                            last_backup TIMESTAMP,
                            created_at TIMESTAMP,
                            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_vms (
                            id VARCHAR(8) PRIMARY KEY,
                            host_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_hosts(id) ON DELETE CASCADE,
                            vm_id INTEGER NOT NULL,
                            name VARCHAR(255) NOT NULL,
                            status VARCHAR(20),
                            cpu_cores INTEGER,
                            memory_mb INTEGER,
                            disk_total_gb REAL,
                            network_interfaces JSON,
                            os_type VARCHAR(50),
                            template BOOLEAN DEFAULT FALSE,
                            backup_enabled BOOLEAN,
                            last_backup DATETIME,
                            created_at DATETIME,
                            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_proxmox_vm_host ON inventory_proxmox_vms(host_id)"))
                conn.execute(text("CREATE INDEX idx_proxmox_vm_vm_id ON inventory_proxmox_vms(vm_id)"))
                conn.execute(text("CREATE INDEX idx_proxmox_vm_status ON inventory_proxmox_vms(status)"))
                conn.commit()
                print("✓ Tabella inventory_proxmox_vms creata")
            
            # Crea tabella ProxmoxStorage
            if not inspector.has_table('inventory_proxmox_storage'):
                print("Creo tabella inventory_proxmox_storage...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_storage (
                            id VARCHAR(8) PRIMARY KEY,
                            host_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_hosts(id) ON DELETE CASCADE,
                            storage_name VARCHAR(100) NOT NULL,
                            storage_type VARCHAR(50),
                            content_types JSONB,
                            total_gb REAL,
                            used_gb REAL,
                            available_gb REAL,
                            usage_percent REAL,
                            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_storage (
                            id VARCHAR(8) PRIMARY KEY,
                            host_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_hosts(id) ON DELETE CASCADE,
                            storage_name VARCHAR(100) NOT NULL,
                            storage_type VARCHAR(50),
                            content_types JSON,
                            total_gb REAL,
                            used_gb REAL,
                            available_gb REAL,
                            usage_percent REAL,
                            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_proxmox_storage_host ON inventory_proxmox_storage(host_id)"))
                conn.execute(text("CREATE INDEX idx_proxmox_storage_name ON inventory_proxmox_storage(storage_name)"))
                conn.commit()
                print("✓ Tabella inventory_proxmox_storage creata")
            
            # Crea tabella ProxmoxBackup
            if not inspector.has_table('inventory_proxmox_backups'):
                print("Creo tabella inventory_proxmox_backups...")
                if is_postgres:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_backups (
                            id VARCHAR(8) PRIMARY KEY,
                            vm_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_vms(id) ON DELETE CASCADE,
                            backup_id VARCHAR(255) NOT NULL,
                            backup_type VARCHAR(20),
                            size_gb REAL,
                            status VARCHAR(20),
                            start_time TIMESTAMP,
                            end_time TIMESTAMP,
                            duration_seconds INTEGER,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                else:
                    conn.execute(text("""
                        CREATE TABLE inventory_proxmox_backups (
                            id VARCHAR(8) PRIMARY KEY,
                            vm_id VARCHAR(8) NOT NULL REFERENCES inventory_proxmox_vms(id) ON DELETE CASCADE,
                            backup_id VARCHAR(255) NOT NULL,
                            backup_type VARCHAR(20),
                            size_gb REAL,
                            status VARCHAR(20),
                            start_time DATETIME,
                            end_time DATETIME,
                            duration_seconds INTEGER,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )
                    """))
                conn.commit()
                
                # Crea indici
                conn.execute(text("CREATE INDEX idx_proxmox_backup_vm ON inventory_proxmox_backups(vm_id)"))
                conn.execute(text("CREATE INDEX idx_proxmox_backup_status ON inventory_proxmox_backups(status)"))
                conn.execute(text("CREATE INDEX idx_proxmox_backup_start_time ON inventory_proxmox_backups(start_time)"))
                conn.commit()
                print("✓ Tabella inventory_proxmox_backups creata")
        
        print("✓ Migrazione completata con successo")
        
    except Exception as e:
        print(f"✗ Errore durante la migrazione: {e}")
        raise


if __name__ == "__main__":
    migrate_add_advanced_device_info_tables()

