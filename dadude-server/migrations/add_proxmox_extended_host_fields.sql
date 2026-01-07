-- Migration: Add extended host fields to ProxmoxHost
-- Esegui questo script direttamente nel database PostgreSQL

-- Temperature
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS temperature_summary JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS temperature_highest_c REAL;

-- BIOS info
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS bios_vendor VARCHAR(100);
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS bios_version VARCHAR(100);
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS bios_release_date VARCHAR(50);

-- System info
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS system_manufacturer VARCHAR(100);
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS system_product VARCHAR(200);
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS system_serial VARCHAR(100);

-- Board info
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS board_vendor VARCHAR(100);
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS board_name VARCHAR(200);

-- Boot devices
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS boot_devices JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS boot_devices_details JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS boot_entries JSONB;

-- Hardware info (lshw)
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_system JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_bus JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_memory JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_processor JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_storage JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_disk JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_volume JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_network JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS hardware_product VARCHAR(200);

-- PCI/USB devices
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS pci_devices JSONB;
ALTER TABLE inventory_proxmox_hosts ADD COLUMN IF NOT EXISTS usb_devices JSONB;

