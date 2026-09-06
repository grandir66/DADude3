# DaDude - Fix Applicati

**Versione**: 3.0.0  
**Ultimo aggiornamento**: 2026-01-07

Questo documento raccoglie tutti i fix applicati al sistema DaDude Inventory System.

---

## Indice Fix

1. [Fix Compatibilità Unified Scanner](#fix-compatibilità-unified-scanner)
2. [Fix SNMP Public Fallback](#fix-snmp-public-fallback)
3. [Fix SSH Fallback UniFi/MikroTik](#fix-ssh-fallback-unifi-mikrotik)
4. [Fix Visualizzazione Interfacce MikroTik](#fix-visualizzazione-interfacce-mikrotik)
5. [Fix Visualizzazione LLDP Neighbors](#fix-visualizzazione-lldp-neighbors)
6. [Fix Supporto UniFi CLI Avanzato](#fix-supporto-unifi-cli-avanzato)

---

## Fix Compatibilità Unified Scanner

**Data**: 2025-01-07  
**Problema**: I dati di interfacce e LLDP neighbors non venivano acquisiti per MikroTik e Ubiquiti

### Problema Identificato

Il sistema usa `unified_scanner_probe.py` che chiama `ssh_probe.py`, ma:

1. **`ssh_probe.py`** salva i dati in:
   - `info["interfaces"]` per MikroTik/Ubiquiti
   - `info["neighbors"]` per MikroTik/Ubiquiti

2. **`_normalize_ssh_result()`** cerca solo:
   - `data.get("network_interfaces")` - NON trova `interfaces`!
   - NON cerca affatto `lldp_neighbors` o `neighbors`!

**Risultato**: I dati vengono raccolti ma non vengono passati al risultato unificato.

### Fix Applicati

#### 1. Modificato `unified_scanner_probe.py`

**File**: `dadude-agent/app/probes/unified_scanner_probe.py`

**Funzione**: `_normalize_ssh_result()` (riga ~415)

**Modifiche**:
```python
# PRIMA:
"network_interfaces": _safe_list(data.get("network_interfaces")),
# Non cercava lldp_neighbors

# DOPO:
"network_interfaces": _safe_list(data.get("network_interfaces") or data.get("interfaces")),
"lldp_neighbors": _safe_list(data.get("lldp_neighbors") or data.get("neighbors")),

# Aggiunto anche fallback esplicito:
if data.get("neighbors") and not result["lldp_neighbors"]:
    result["lldp_neighbors"] = _safe_list(data.get("neighbors"))

if data.get("interfaces") and not result["network_interfaces"]:
    result["network_interfaces"] = _safe_list(data.get("interfaces"))
```

#### 2. Modificato `ssh_probe.py`

**File**: `dadude-agent/app/probes/ssh_probe.py`

**Modifiche**: Aggiunto alias per compatibilità con unified scanner

**Per MikroTik**:
```python
# DOPO raccolta interfaces:
info["interfaces"] = interfaces
info["network_interfaces"] = interfaces  # Alias per compatibilità
info["interfaces_count"] = len(interfaces)

# DOPO raccolta neighbors:
info["neighbors"] = neighbors
info["lldp_neighbors"] = neighbors  # Alias per compatibilità
info["neighbors_count"] = len(neighbors)
```

**Per Ubiquiti EdgeOS e UniFi**: Stesso pattern - aggiunto alias `network_interfaces` e `lldp_neighbors`

### Risultato Atteso

Dopo il fix, quando viene eseguito `probe_unified`:

1. **SSH probe** raccoglie:
   - `interfaces` → salvato anche come `network_interfaces`
   - `neighbors` → salvato anche come `lldp_neighbors`

2. **Unified scanner** normalizza:
   - Cerca `network_interfaces` o `interfaces` → trova i dati
   - Cerca `lldp_neighbors` o `neighbors` → trova i dati

3. **Risultato finale** contiene:
   - `network_interfaces`: lista interfacce complete
   - `lldp_neighbors`: lista neighbors LLDP completi

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato  
**Commit**: 5b0c7784

---

## Fix SNMP Public Fallback

**Data**: 2026-01-07  
**Problema**: La community SNMP "public" veniva usata come default invece che come fallback

### Problema

La community SNMP "public" veniva usata come default invece che come fallback. Dovrebbe essere usata solo se la community del cliente non funziona o non è presente.

### Soluzione

Modificata la logica SNMP per provare prima con la community del cliente, poi con "public" come fallback:

#### 1. Unified Scanner Probe (`dadude-agent/app/probes/unified_scanner_probe.py`)

- Modificata funzione `_probe_snmp()` per provare più communities
- Prima prova con community del cliente (se presente)
- Solo se quella fallisce, prova con "public"
- Logging migliorato per tracciare quale community viene usata

#### 2. Device Probe Service (`dadude/app/services/device_probe_service.py`)

- Modificata funzione `_probe_snmp()` con stessa logica
- Loop che prova ogni community fino a che una funziona
- Se una community restituisce dati validi, esce dal loop
- Se tutte falliscono, ritorna errore

### Logica Implementata

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

### Comportamento

**Prima del Fix**:
- Usava sempre "public" come default
- Ignorava la community del cliente se presente

**Dopo il Fix**:
- Prova prima con community del cliente (se presente)
- Solo se quella fallisce, prova con "public"
- Logging dettagliato per tracciare quale community funziona

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato  
**Commit**: 3ad10da

---

## Fix SSH Fallback UniFi/MikroTik

**Data**: 2026-01-07  
**Problema**: Il sistema stava usando solo SNMP per UniFi, anche quando la porta 22 (SSH) era aperta

### Problema

Il sistema stava usando solo SNMP per UniFi, anche quando la porta 22 (SSH) era aperta. SNMP su UniFi spesso restituisce dati limitati (solo hostname e modello), mentre SSH può recuperare informazioni complete (interfacce, LLDP neighbors, versioni firmware, ecc.).

### Soluzione

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

### Modifiche

**File**: `dadude-agent/app/probes/unified_scanner_probe.py`

- Aggiunta variabile `snmp_result` per tracciare risultato SNMP
- Aggiunta variabile `ssh_tried` per evitare doppio tentativo SSH
- Aggiunta sezione fallback dopo il loop principale dei protocolli
- Logica di rilevamento UniFi/MikroTik dal modello/manufacturer
- Logging dettagliato per debug

### Comportamento

**Prima del Fix**:
```
Port scan → SNMP (restituisce pochi dati) → Fine
```

**Dopo il Fix**:
```
Port scan → SNMP (restituisce pochi dati) → Rileva UniFi → SSH fallback → Merge risultati
```

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato  
**Commit**: 5f50440

---

## Fix Visualizzazione Interfacce MikroTik

**Data**: 2026-01-07  
**Problema**: Le interfacce MikroTik erano presenti nel JSON dell'inventario ma non venivano visualizzate correttamente nella pagina di dettaglio MikroTik

### Problema

Le interfacce MikroTik erano presenti nel JSON dell'inventario ma non venivano visualizzate correttamente nella pagina di dettaglio MikroTik. La pagina caricava le interfacce solo dall'API MikroTik diretta, ignorando i dati già presenti nell'inventario.

### Soluzione

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

### Modifiche

**File**: `dadude/app/templates/mikrotik_detail.html`

- Modificata funzione `loadInterfaces()` per recuperare prima dall'inventario
- Mapping dei dati dall'inventario al formato della tabella:
  - `interface_type` → `type`
  - `oper_status`/`admin_status` → `running`/`disabled`
  - Gestione campi mancanti (rx_bytes, tx_bytes)

### Mapping Dati Inventario → Tabella

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

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato  
**Commit**: bca47a3

---

## Fix Visualizzazione LLDP Neighbors

**Data**: 2026-01-07  
**Problema**: I dati LLDP erano presenti nel JSON ma non venivano visualizzati nell'interfaccia web

### Problema

I dati LLDP erano presenti nel JSON ma non venivano visualizzati nell'interfaccia web della pagina di dettaglio MikroTik.

### Soluzione

Aggiunta sezione dedicata per visualizzare i dati LLDP neighbors nel template `mikrotik_detail.html`:

1. **Nuovo tab "LLDP Neighbors"** nella pagina di dettaglio MikroTik
2. **Funzione JavaScript `loadLLDPNeighbors()`** che:
   - Cerca il dispositivo nell'inventario usando l'indirizzo IP dell'agent
   - Carica i dati LLDP dall'endpoint API `/api/v1/inventory/{customer_id}/devices/{device_id}/lldp-neighbors`
   - Come fallback, recupera i dati da `custom_fields` del dispositivo
   - Visualizza i dati in una tabella con colonne:
     - Interfaccia Locale
     - Dispositivo Remoto
     - Porta Remota
     - MAC Remoto
     - IP Remoto
     - Chassis ID
     - Scoperto via (LLDP/CDP/MNDP)
     - Ultimo visto

### Modifiche

**File**: `dadude/app/templates/mikrotik_detail.html`

- Aggiunto tab "LLDP Neighbors" nella lista dei tab
- Aggiunto contenuto del tab con tabella per visualizzazione neighbors
- Aggiunta funzione `loadLLDPNeighbors()` in JavaScript
- Integrata chiamata `loadLLDPNeighbors()` nel refresh automatico quando il tab è attivo

### Comportamento

**Prima del Fix**:
- Dati LLDP presenti nel JSON ma non visualizzati
- Nessuna sezione dedicata per neighbors

**Dopo il Fix**:
- Tab dedicato "LLDP Neighbors" visibile nella pagina di dettaglio MikroTik
- Dati LLDP caricati automaticamente quando si apre il tab
- Tabella completa con tutte le informazioni sui neighbors
- Messaggio informativo se il dispositivo non è nell'inventario o non ci sono neighbors

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato  
**Commit**: 5c749f4

---

## Fix Supporto UniFi CLI Avanzato

**Data**: 2026-01-07  
**Problema**: Supporto migliorato per comandi UniFi CLI avanzati

### Dettagli

Aggiunto supporto per comandi UniFi CLI avanzati per migliorare la raccolta dati da dispositivi UniFi.

**File modificati**:
- `dadude-agent/app/probes/ssh_vendors/ubiquiti.py`

**Stato**: ✅ Fix completato  
**Deploy**: ✅ Completato

---

## Note Generali

- Tutti i fix sono stati testati e deployati in produzione
- I commit sono disponibili nel repository Git
- Per problemi o domande, consultare i log del sistema o aprire una issue

---

**Documento aggiornato**: 2026-01-07
