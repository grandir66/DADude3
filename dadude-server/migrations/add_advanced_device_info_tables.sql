-- Migration: Add advanced device information tables
-- Esegui questo script direttamente nel database PostgreSQL

-- Estendi NetworkInterface (già fatto, ma per sicurezza)
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS lldp_enabled BOOLEAN;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS cdp_enabled BOOLEAN;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS poe_enabled BOOLEAN;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS poe_power_watts REAL;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS vlan_native INTEGER;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS vlan_trunk_allowed JSONB;
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS stp_state VARCHAR(20);
ALTER TABLE inventory_network_interfaces ADD COLUMN IF NOT EXISTS lacp_enabled BOOLEAN;

-- Crea tabella LLDPNeighbor
CREATE TABLE IF NOT EXISTS inventory_lldp_neighbors (
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
);

CREATE INDEX IF NOT EXISTS idx_lldp_device ON inventory_lldp_neighbors(device_id);
CREATE INDEX IF NOT EXISTS idx_lldp_local_interface ON inventory_lldp_neighbors(local_interface);
CREATE INDEX IF NOT EXISTS idx_lldp_remote_mac ON inventory_lldp_neighbors(remote_mac);

-- Crea tabella CDPNeighbor
CREATE TABLE IF NOT EXISTS inventory_cdp_neighbors (
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
);

CREATE INDEX IF NOT EXISTS idx_cdp_device ON inventory_cdp_neighbors(device_id);
CREATE INDEX IF NOT EXISTS idx_cdp_local_interface ON inventory_cdp_neighbors(local_interface);
CREATE INDEX IF NOT EXISTS idx_cdp_remote_device_id ON inventory_cdp_neighbors(remote_device_id);

-- Crea tabella ProxmoxHost
CREATE TABLE IF NOT EXISTS inventory_proxmox_hosts (
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
);

CREATE INDEX IF NOT EXISTS idx_proxmox_host_device ON inventory_proxmox_hosts(device_id);
CREATE INDEX IF NOT EXISTS idx_proxmox_host_node ON inventory_proxmox_hosts(node_name);

-- Crea tabella ProxmoxVM
CREATE TABLE IF NOT EXISTS inventory_proxmox_vms (
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
);

CREATE INDEX IF NOT EXISTS idx_proxmox_vm_host ON inventory_proxmox_vms(host_id);
CREATE INDEX IF NOT EXISTS idx_proxmox_vm_vm_id ON inventory_proxmox_vms(vm_id);
CREATE INDEX IF NOT EXISTS idx_proxmox_vm_status ON inventory_proxmox_vms(status);

-- Crea tabella ProxmoxStorage
CREATE TABLE IF NOT EXISTS inventory_proxmox_storage (
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
);

CREATE INDEX IF NOT EXISTS idx_proxmox_storage_host ON inventory_proxmox_storage(host_id);
CREATE INDEX IF NOT EXISTS idx_proxmox_storage_name ON inventory_proxmox_storage(storage_name);

-- Crea tabella ProxmoxBackup
CREATE TABLE IF NOT EXISTS inventory_proxmox_backups (
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
);

CREATE INDEX IF NOT EXISTS idx_proxmox_backup_vm ON inventory_proxmox_backups(vm_id);
CREATE INDEX IF NOT EXISTS idx_proxmox_backup_status ON inventory_proxmox_backups(status);
CREATE INDEX IF NOT EXISTS idx_proxmox_backup_start_time ON inventory_proxmox_backups(start_time);

