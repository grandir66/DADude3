# Fix Timeout SNMP per Evitare Blocchi Agent

## Problema
L'agent si blocca durante le scansioni SNMP quando il dispositivo non risponde, creando un down persistente fino al riavvio manuale.

## Modifiche Implementate

### 1. Timeout Transport SNMP Ridotto
- **Prima**: `timeout=10, retries=2` (max 20s per query)
- **Dopo**: `timeout=3, retries=1` (max 6s per query)
- **File**: `dadude-agent/app/probes/snmp_probe.py` linea ~475

### 2. Timeout Query Singole OID
- Aggiunto `asyncio.wait_for` con timeout 5s per ogni `query_oid`
- **File**: `dadude-agent/app/probes/snmp_probe.py` linea ~305

### 3. Timeout Walk OID
- Aggiunto timeout 5s per ogni iterazione di `walk_oid`
- Ridotto `max_rows` da 200 a 100
- **File**: `dadude-agent/app/probes/snmp_probe.py` linea ~362

### 4. Timeout Query Table
- Aggiunto timeout totale 30s per `query_table`
- **File**: `dadude-agent/app/probes/snmp_probe.py` linea ~329

### 5. Funzione Helper per Async For
- Creata `safe_async_for_next_cmd()` per wrappare `async for` con timeout
- Timeout totale: 15s (configurabile)
- Timeout per iterazione: 5s
- Max iterazioni: 100 (configurabile)
- **File**: `dadude-agent/app/probes/snmp_probe.py` linea ~304

### 6. Ridotti Max Rows
- Tutti i `max_rows=200` ridotti a `max_rows=100`
- Applicato a: LLDP, interfaces, routes, storage

## Modifiche da Completare

### Sostituire Async For Diretti con Helper

Ci sono ancora **11 `async for`** che iterano direttamente su `next_cmd` senza timeout. Questi devono essere sostituiti con `safe_async_for_next_cmd()`:

1. **Linea 778**: Synology volume name walk
2. **Linea 870**: Synology disk name walk  
3. **Linea 893**: Synology disk status/model/temperature walk
4. **Linea 939**: Synology RAID name walk
5. **Linea 958**: Synology RAID status/level walk
6. **Linea 1021**: QNAP volume name walk
7. **Linea 1044**: QNAP volume status/total/used/free walk
8. **Linea 1108**: QNAP disk name walk
9. **Linea 1131**: QNAP disk status/model/temperature walk
10. **Linea 1177**: QNAP RAID name walk
11. **Linea 1196**: QNAP RAID status/level walk

### Pattern di Sostituzione

**Prima:**
```python
async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
    dispatcher,
    CommunityData(community, mpModel=1 if version == "2c" else 0),
    transport,
    ObjectType(ObjectIdentity(oid)),
    lexicographicMode=False
):
    # ... codice ...
```

**Dopo:**
```python
async for (errorIndication, errorStatus, errorIndex, varBinds) in safe_async_for_next_cmd(
    oid,
    timeout=15.0,
    max_iterations=50
):
    # ... codice ...
```

## Testing

Dopo aver completato le modifiche, testare:

1. **Scansione SNMP su dispositivo non raggiungibile**: deve fallire velocemente (< 10s) senza bloccare l'agent
2. **Scansione SNMP su dispositivo con LLDP**: deve completarsi senza blocchi
3. **Scansione SNMP su Synology/QNAP**: deve completarsi senza blocchi
4. **Scansione SNMP su dispositivo con molte interfacce**: deve completarsi senza blocchi

## Note

- I timeout sono stati ridotti per evitare blocchi, ma potrebbero causare scansioni incomplete su dispositivi lenti
- Se necessario, aumentare i timeout per dispositivi specifici (es. Synology/QNAP con molti volumi)
- Monitorare i log per verificare che i timeout funzionino correttamente
