# Fix SSH Fallback per UniFi/MikroTik

## Problema

Il sistema stava usando solo SNMP per UniFi, anche quando la porta 22 (SSH) era aperta. SNMP su UniFi spesso restituisce dati limitati (solo hostname e modello), mentre SSH può recuperare informazioni complete (interfacce, LLDP neighbors, versioni firmware, ecc.).

### Esempio Problema

```json
{
  "device_id": "1efa5d92",
  "target": "192.168.40.245",
  "status": "partial",
  "protocol_used": "snmp",
  "model": "USW-Enterprise",
  "interfaces": [],
  "lldp_neighbors": [],
  "os_version": "",
  "firmware_version": ""
}
```

## Soluzione

Aggiunta logica di **fallback SSH automatico** nel `unified_scanner_probe.py`:

1. **Dopo SNMP**, controlla se ha restituito pochi dati utili:
   - Nessuna interfaccia (`interfaces` vuoto)
   - Nessun neighbor LLDP (`lldp_neighbors` vuoto)
   - Nessuna versione OS (`os_version` vuoto)
   - Nessuna versione firmware (`firmware_version` vuoto)

2. **Rilevamento automatico UniFi/MikroTik**:
   - UniFi: modello contiene "usw", "uap", "usg", "unifi", "edge", "edgerouter", "edgeswitch"
   - MikroTik: manufacturer contiene "mikrotik" o os_name contiene "routeros"

3. **Se SNMP ha restituito pochi dati E (è UniFi/MikroTik O ha dati minimi) E porta 22 è aperta**, prova SSH automaticamente.

## Modifiche

**File**: `dadude-agent/app/probes/unified_scanner_probe.py`

- Aggiunta variabile `snmp_result` per tracciare risultato SNMP
- Aggiunta variabile `ssh_tried` per evitare doppio tentativo SSH
- Aggiunta sezione fallback dopo il loop principale dei protocolli
- Logica di rilevamento UniFi/MikroTik dal modello/manufacturer
- Logging dettagliato per debug

## Comportamento

### Prima del Fix
```
Port scan → SNMP (restituisce pochi dati) → Fine
```

### Dopo il Fix
```
Port scan → SNMP (restituisce pochi dati) → Rileva UniFi → SSH fallback → Merge risultati
```

## Log Esempio

```
[UNIFIED] SNMP returned minimal data for 192.168.40.245, trying SSH fallback (UniFi=True, MikroTik=False)
[UNIFIED] SSH fallback succeeded for 192.168.40.245
```

## Deploy

**Commit**: `5f50440`  
**Data**: 2026-01-07 00:42  
**Container**: PCT 601 (dadude-agent-Domarc)  
**Versione**: v3.0.0

## Test

Per testare il fix:

1. Eseguire una scansione su un dispositivo UniFi (es. 192.168.40.245)
2. Verificare nei log che SSH fallback viene attivato:
   ```
   [UNIFIED] SNMP returned minimal data for 192.168.40.245, trying SSH fallback
   ```
3. Verificare che i dati siano completi:
   - `interfaces` non vuoto
   - `lldp_neighbors` non vuoto (se disponibili)
   - `os_version` e `firmware_version` popolati
   - `protocol_used` contiene "snmp,ssh"

## Note

- Il fallback SSH viene provato solo se:
  - SNMP ha restituito qualche risultato (non completamente fallito)
  - SSH non è già stato provato nella lista originale dei protocolli
  - Porta 22 è aperta
  - SNMP ha restituito pochi dati O il dispositivo è UniFi/MikroTik

- Il timeout SSH per il fallback è lo stesso del normale probe SSH (70% del timeout totale, minimo 90s)

- I risultati SSH vengono mergiati con quelli SNMP, quindi se SNMP ha restituito qualche dato utile, viene mantenuto
