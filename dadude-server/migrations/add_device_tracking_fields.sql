-- Migration SQL per aggiungere campi tracking device
-- Eseguire direttamente sul database PostgreSQL

-- Aggiungi campi a inventory_devices
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMP;
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMP;
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS verification_count INTEGER DEFAULT 0;
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS last_scan_network_id VARCHAR(8);
ALTER TABLE inventory_devices ADD COLUMN IF NOT EXISTS cleanup_marked_at TIMESTAMP;

-- Aggiungi foreign key per last_scan_network_id (se non esiste già)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'fk_inventory_last_scan_network'
    ) THEN
        ALTER TABLE inventory_devices 
        ADD CONSTRAINT fk_inventory_last_scan_network 
        FOREIGN KEY (last_scan_network_id) REFERENCES networks(id);
    END IF;
END $$;

-- Crea indici (se non esistono già)
CREATE INDEX IF NOT EXISTS idx_inventory_last_verified ON inventory_devices(last_verified_at);
CREATE INDEX IF NOT EXISTS idx_inventory_cleanup_marked ON inventory_devices(cleanup_marked_at);

-- Inizializza valori per device esistenti
UPDATE inventory_devices 
SET first_seen_at = created_at,
    last_verified_at = created_at,
    verification_count = 1
WHERE first_seen_at IS NULL;

-- Aggiungi campo a discovered_devices
ALTER TABLE discovered_devices ADD COLUMN IF NOT EXISTS imported_at TIMESTAMP;

