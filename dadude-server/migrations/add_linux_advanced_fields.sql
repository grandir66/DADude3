-- Migration: Add advanced Linux fields for SSH advanced scanner
-- Adds fields for detailed CPU, memory, storage, network, services, Docker, VM data

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

