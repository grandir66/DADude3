-- Migration: Add disk_total_gb, disk_free_gb, firmware_version to inventory_devices
-- DaDude Inventory v2.3.13
-- Date: 2026-01-07
-- Database: PostgreSQL

-- Aggiungi campi storage base e firmware al modello InventoryDevice
-- Questi campi vengono popolati dall'Unified Scanner

ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS disk_total_gb DOUBLE PRECISION;
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS disk_free_gb DOUBLE PRECISION;
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS firmware_version VARCHAR(100);

-- Commento per documentazione
COMMENT ON COLUMN inventory_devices.disk_total_gb IS 'Spazio disco totale in GB (da Unified Scanner)';
COMMENT ON COLUMN inventory_devices.disk_free_gb IS 'Spazio disco libero in GB (da Unified Scanner)';
COMMENT ON COLUMN inventory_devices.firmware_version IS 'Versione firmware dispositivo (da Unified Scanner)';
