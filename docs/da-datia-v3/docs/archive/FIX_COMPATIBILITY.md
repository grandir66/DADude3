# Fix Compatibilità Unified Scanner

**Data**: 2025-01-07
**Problema**: I dati di interfacce e LLDP neighbors non venivano acquisiti per MikroTik e Ubiquiti

---

## 🐛 Problema Identificato

Il sistema usa `unified_scanner_probe.py` che chiama `ssh_probe.py`, ma:

1. **`ssh_probe.py`** salva i dati in:
   - `info["interfaces"]` per MikroTik/Ubiquiti
   - `info["neighbors"]` per MikroTik/Ubiquiti

2. **`_normalize_ssh_result()`** cerca solo:
   - `data.get("network_interfaces")` - NON trova `interfaces`!
   - NON cerca affatto `lldp_neighbors` o `neighbors`!

**Risultato**: I dati vengono raccolti ma non vengono passati al risultato unificato.

---

## ✅ Fix Applicati

### 1. Modificato `unified_scanner_probe.py`

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

---

### 2. Modificato `ssh_probe.py`

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

**Per Ubiquiti EdgeOS**:
```python
# Stesso pattern - aggiunto alias network_interfaces e lldp_neighbors
```

**Per Ubiquiti UniFi**:
```python
# Stesso pattern - aggiunto alias lldp_neighbors
```

---

## 📊 Risultato Atteso

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

---

## 🧪 Test da Eseguire

Dopo il deploy del fix:

1. **Eseguire scansione su MikroTik**:
   ```bash
   # Verificare nei log:
   # "SSH probe: Collected N MikroTik interfaces"
   # "SSH probe: Collected N MikroTik neighbors"
   ```

2. **Eseguire scansione su Ubiquiti**:
   ```bash
   # Verificare nei log:
   # "SSH probe: Collected N EdgeOS interfaces"
   # "SSH probe: Collected N EdgeOS LLDP neighbors"
   ```

3. **Verificare risultato unified scanner**:
   ```python
   # Nel risultato dovrebbe esserci:
   result["network_interfaces"]  # Lista interfacce
   result["lldp_neighbors"]      # Lista neighbors
   ```

---

## 📝 File Modificati

1. ✅ `dadude-agent/app/probes/unified_scanner_probe.py` - Fix normalizzazione SSH result
2. ✅ `dadude-agent/app/probes/ssh_probe.py` - Aggiunto alias per compatibilità

---

**Stato**: ✅ Fix completato
**Deploy**: ✅ Completato sul server PCT 601
**Data deploy**: 2026-01-07 00:40
**Commit**: 5b0c7784
