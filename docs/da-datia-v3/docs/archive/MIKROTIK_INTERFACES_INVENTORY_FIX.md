# Fix Visualizzazione Interfacce MikroTik dall'Inventario

## Problema

Le interfacce MikroTik erano presenti nel JSON dell'inventario ma non venivano visualizzate correttamente nella pagina di dettaglio MikroTik. La pagina caricava le interfacce solo dall'API MikroTik diretta, ignorando i dati già presenti nell'inventario.

## Soluzione

Modificata la funzione `loadInterfaces()` nella pagina di dettaglio MikroTik per:

1. **Prima prova a recuperare le interfacce dall'inventario**:
   - Cerca il dispositivo nell'inventario usando l'indirizzo IP dell'agent
   - Recupera le interfacce dall'endpoint `/api/v1/inventory/{customer_id}/devices/{device_id}/interfaces`
   - Mappa i dati dell'inventario al formato atteso dalla tabella

2. **Fallback all'API MikroTik**:
   - Se le interfacce non sono disponibili nell'inventario, recupera dall'API MikroTik diretta
   - Mantiene la compatibilità con il comportamento precedente

3. **Indicatore visivo**:
   - Badge "Inv" per indicare quando i dati provengono dall'inventario
   - Aiuta a distinguere tra dati dall'inventario e dati live dall'API

## Modifiche

**File**: `dadude/app/templates/mikrotik_detail.html`

- Modificata funzione `loadInterfaces()` per recuperare prima dall'inventario
- Mapping dei dati dall'inventario al formato della tabella:
  - `interface_type` → `type`
  - `oper_status`/`admin_status` → `running`/`disabled`
  - Gestione campi mancanti (rx_bytes, tx_bytes)

## Comportamento

### Prima del Fix
- Caricava interfacce solo dall'API MikroTik diretta
- Ignorava i dati presenti nell'inventario

### Dopo il Fix
- Prova prima a recuperare dall'inventario
- Se disponibili, le visualizza con badge "Inv"
- Se non disponibili, fallback all'API MikroTik
- I dati vengono sempre visualizzati correttamente

## Mapping Dati Inventario → Tabella

```javascript
{
    name: i.name,
    type: i.interface_type || i.description || '-',
    mac_address: i.mac_address,
    running: i.oper_status === 'up' || i.admin_status === 'up',
    disabled: i.admin_status === 'down',
    rx_bytes: 0, // Non disponibile dall'inventario
    tx_bytes: 0  // Non disponibile dall'inventario
}
```

## Deploy

**Commit**: `bca47a3`  
**Data**: 2026-01-07  
**Server**: PCT 600

## Test

Per testare il fix:

1. Aprire la pagina di dettaglio di un MikroTik agent
2. Cliccare sul tab "Interfacce"
3. Verificare che le interfacce vengano visualizzate correttamente
4. Se i dati provengono dall'inventario, verificare il badge "Inv"
5. Se i dati provengono dall'API MikroTik, non ci sarà il badge "Inv"

## Note

- I dati dall'inventario hanno priorità rispetto all'API MikroTik
- Se le interfacce sono disponibili nell'inventario, vengono visualizzate anche se l'API MikroTik non è raggiungibile
- I campi `rx_bytes` e `tx_bytes` sono impostati a 0 per i dati dall'inventario (non disponibili)
- Il badge "Inv" aiuta a distinguere la fonte dei dati
