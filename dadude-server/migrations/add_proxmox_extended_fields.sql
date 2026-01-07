-- Migration: Add extended Proxmox fields from Proxreporter integration
-- Date: 2024-12-24
-- Description: Adds swap, rootfs, KSM, subscription details, boot mode, and VM extended fields

-- ==========================================
-- PROXMOX HOST EXTENDED FIELDS
-- ==========================================

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

-- ==========================================
-- PROXMOX VM EXTENDED FIELDS
-- ==========================================

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

-- Note: Per SQLite, alcune colonne potrebbero già esistere se create automaticamente da SQLAlchemy
-- Questa migration è compatibile con PostgreSQL e SQLite

