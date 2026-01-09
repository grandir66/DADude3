-- Migration: Aggiunge campi category, subcategory, feature, location, cespite
-- PostgreSQL ONLY - NON supporta SQLite
-- Esegui questo script SQL direttamente sul database PostgreSQL

-- Aggiungi subcategory (solo se non esiste)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'inventory_devices' AND column_name = 'subcategory'
    ) THEN
        ALTER TABLE inventory_devices ADD COLUMN subcategory VARCHAR(50) NULL;
    END IF;
END $$;

-- Aggiungi feature (solo se non esiste)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'inventory_devices' AND column_name = 'feature'
    ) THEN
        ALTER TABLE inventory_devices ADD COLUMN feature VARCHAR(100) NULL;
    END IF;
END $$;

-- Aggiungi location (solo se non esiste)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'inventory_devices' AND column_name = 'location'
    ) THEN
        ALTER TABLE inventory_devices ADD COLUMN location VARCHAR(255) NULL;
    END IF;
END $$;

-- Aggiungi cespite (solo se non esiste)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'inventory_devices' AND column_name = 'cespite'
    ) THEN
        ALTER TABLE inventory_devices ADD COLUMN cespite VARCHAR(100) NULL;
    END IF;
END $$;

-- Crea indici (solo se non esistono)
CREATE INDEX IF NOT EXISTS idx_inventory_subcategory 
ON inventory_devices(subcategory);

CREATE INDEX IF NOT EXISTS idx_inventory_category_subcategory 
ON inventory_devices(category, subcategory);

CREATE INDEX IF NOT EXISTS idx_inventory_category 
ON inventory_devices(category);
