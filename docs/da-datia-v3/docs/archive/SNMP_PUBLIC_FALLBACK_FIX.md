# Fix SNMP Community 'public' come Fallback

## Problema

La community SNMP "public" veniva usata come default invece che come fallback. Dovrebbe essere usata solo se la community del cliente non funziona o non è presente.

## Soluzione

Modificata la logica SNMP per provare prima con la community del cliente, poi con "public" come fallback:

### 1. Unified Scanner Probe (`dadude-agent/app/probes/unified_scanner_probe.py`)

- Modificata funzione `_probe_snmp()` per provare più communities
- Prima prova con community del cliente (se presente)
- Solo se quella fallisce, prova con "public"
- Logging migliorato per tracciare quale community viene usata

### 2. Device Probe Service (`dadude/app/services/device_probe_service.py`)

- Modificata funzione `_probe_snmp()` con stessa logica
- Loop che prova ogni community fino a che una funziona
- Se una community restituisce dati validi, esce dal loop
- Se tutte falliscono, ritorna errore

## Logica Implementata

```python
# Lista di communities da provare (prima quella del cliente, poi 'public' come fallback)
communities_to_try = []

# Prima aggiungi la community del cliente se presente
client_community = credentials.get("snmp_community")
if client_community and client_community.strip():
    communities_to_try.append(client_community.strip())

# Aggiungi 'public' come fallback solo se non è già nella lista
if "public" not in communities_to_try:
    communities_to_try.append("public")

# Prova ogni community fino a che una funziona
for community in communities_to_try:
    try:
        # Esegui probe SNMP
        result = await snmp_probe(...)
        
        # Se abbiamo ottenuto dati validi, esci dal loop
        if result and (result.get("sysDescr") or result.get("sysName")):
            break
    except Exception:
        # Continua con la prossima community
        continue
```

## Comportamento

### Prima del Fix
- Usava sempre "public" come default
- Ignorava la community del cliente se presente

### Dopo il Fix
- Prova prima con community del cliente (se presente)
- Solo se quella fallisce, prova con "public"
- Logging dettagliato per tracciare quale community funziona

## Modifiche

**File modificati**:
- `dadude-agent/app/probes/unified_scanner_probe.py`
- `dadude/app/services/device_probe_service.py`

**Commit**: `3ad10da`  
**Data**: 2026-01-07

## Deploy

**Container**: PCT 601 (dadude-agent-Domarc)  
**Versione**: v3.0.0

## Test

Per testare il fix:

1. Verificare nei log che viene provata prima la community del cliente:
   ```
   SNMP probe: Will try client community '<community>' first for <target>
   ```

2. Se quella fallisce, verificare che viene provata "public":
   ```
   SNMP probe: Will use 'public' as fallback for <target>
   ```

3. Verificare quale community ha funzionato:
   ```
   SNMP probe succeeded with community '<community>' for <target>
   ```

## Note

- La community "public" viene aggiunta solo se non è già nella lista (evita duplicati)
- Se la community del cliente è "public", viene provata solo una volta
- Il logging è migliorato per tracciare quale community viene usata con successo
