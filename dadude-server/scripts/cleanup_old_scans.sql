-- Script SQL per pulire scansioni vecchie
-- Mantiene solo le ultime 5 scansioni completate per ogni rete

-- Elimina DiscoveredDevice associati alle scansioni vecchie
DELETE FROM discovered_devices
WHERE scan_id IN (
    SELECT id FROM (
        SELECT 
            id,
            network_id,
            ROW_NUMBER() OVER (
                PARTITION BY network_id 
                ORDER BY created_at DESC
            ) as rn
        FROM scan_results
        WHERE status = 'completed'
    ) ranked
    WHERE rn > 5
);

-- Elimina le scansioni vecchie (dopo aver eliminato i device associati)
DELETE FROM scan_results
WHERE id IN (
    SELECT id FROM (
        SELECT 
            id,
            network_id,
            ROW_NUMBER() OVER (
                PARTITION BY network_id 
                ORDER BY created_at DESC
            ) as rn
        FROM scan_results
        WHERE status = 'completed'
    ) ranked
    WHERE rn > 5
);

-- Mostra statistiche
SELECT 
    network_id,
    COUNT(*) as scans_remaining
FROM scan_results
WHERE status = 'completed'
GROUP BY network_id
ORDER BY network_id;

