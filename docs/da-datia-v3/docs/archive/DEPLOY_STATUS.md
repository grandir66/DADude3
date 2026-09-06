# Stato Deploy - Integrazione Scansione Vendor

**Data**: 2025-01-06
**Server**: PCT 600 (192.168.40.1)
**Versione**: DaDude Inventory System

---

## ✅ Deploy Completato

### Modifiche Deployate

**File**: `dadude-agent/app/probes/ssh_probe.py`

**Funzionalità aggiunte**:
1. ✅ Raccolta interfacce dettagliate MikroTik RouterOS
2. ✅ Raccolta interfacce dettagliate Ubiquiti EdgeOS
3. ✅ Miglioramento raccolta LLDP neighbors Ubiquiti EdgeOS
4. ✅ Miglioramento raccolta LLDP neighbors Ubiquiti UniFi

---

## 🧪 Test da Eseguire

### 1. Test MikroTik RouterOS

**Dispositivo**: Router MikroTik con SSH abilitato

**Verifiche**:
- [ ] Eseguire scansione SSH su dispositivo MikroTik
- [ ] Verificare che vengano raccolte le interfacce dettagliate
- [ ] Verificare formato dati: `interfaces` con campi `name`, `type`, `mac_address`, `mtu`, `running`, `disabled`
- [ ] Verificare che i neighbors vengano raccolti correttamente
- [ ] Verificare salvataggio nel database (`inventory_network_interfaces`)
- [ ] Verificare visualizzazione nelle tabelle HTML

**Comandi da verificare**:
```bash
# Nel log dell'agent dovrebbe apparire:
# "SSH probe: Collected N MikroTik interfaces"
# "SSH probe: Collected N MikroTik neighbors"
```

---

### 2. Test Ubiquiti EdgeOS

**Dispositivo**: Router/Switch Ubiquiti EdgeOS con SSH abilitato

**Verifiche**:
- [ ] Eseguire scansione SSH su dispositivo EdgeOS
- [ ] Verificare che vengano raccolte le interfacce dettagliate
- [ ] Verificare formato dati: `interfaces` con campi `name`, `mac_address`, `ipv4`
- [ ] Verificare che i LLDP neighbors vengano raccolti con formato detail
- [ ] Verificare salvataggio nel database
- [ ] Verificare visualizzazione nelle tabelle HTML

**Comandi da verificare**:
```bash
# Nel log dell'agent dovrebbe apparire:
# "SSH probe: Collected N EdgeOS interfaces"
# "SSH probe: Collected N EdgeOS LLDP neighbors"
```

---

### 3. Test Ubiquiti UniFi

**Dispositivo**: Switch UniFi con SSH abilitato

**Verifiche**:
- [ ] Eseguire scansione SSH su dispositivo UniFi
- [ ] Verificare che vengano raccolti i LLDP neighbors via CLI
- [ ] Verificare formato dati: `neighbors` con campi `local_port`, `remote_device`, `remote_port`, `platform`
- [ ] Verificare salvataggio nel database
- [ ] Verificare visualizzazione nelle tabelle HTML

**Comandi da verificare**:
```bash
# Nel log dell'agent dovrebbe apparire:
# "SSH probe: Collected N UniFi LLDP neighbors via CLI"
```

---

## 📊 Verifica Database

### Network Interfaces

**Tabella**: `inventory_network_interfaces`

**Verifiche**:
```sql
-- Verificare che le interfacce vengano salvate
SELECT device_id, name, mac_address, speed_mbps, admin_status, oper_status 
FROM inventory_network_interfaces 
WHERE device_id IN (
    SELECT id FROM inventory_devices 
    WHERE manufacturer IN ('MikroTik', 'Ubiquiti')
    AND device_type IN ('router', 'switch')
)
ORDER BY device_id, name;
```

### LLDP Neighbors

**Tabella**: `lldp_neighbors` o campo JSON `custom_fields.neighbors`

**Verifiche**:
```sql
-- Verificare che i neighbors vengano salvati
SELECT device_id, local_interface, remote_device_name, remote_interface
FROM lldp_neighbors
WHERE device_id IN (
    SELECT id FROM inventory_devices 
    WHERE manufacturer IN ('MikroTik', 'Ubiquiti')
)
ORDER BY device_id, local_interface;
```

---

## 🔍 Verifica Log

### Log Agent

**Percorso**: Log dell'agent Docker o container

**Cosa cercare**:
```
SSH probe: Collected N MikroTik interfaces
SSH probe: Collected N MikroTik neighbors
SSH probe: Collected N EdgeOS interfaces
SSH probe: Collected N EdgeOS LLDP neighbors
SSH probe: Collected N UniFi LLDP neighbors via CLI
```

### Log Server

**Percorso**: Log del server FastAPI

**Cosa cercare**:
```
✓ Collected N interface details
✓ Collected N LLDP neighbors
Saved N interfaces for device
Saved N LLDP neighbors for device
```

---

## 🐛 Troubleshooting

### Problema: Interfacce non raccolte

**Possibili cause**:
1. Comando SSH non disponibile sul dispositivo
2. Timeout troppo breve
3. Permessi SSH insufficienti

**Soluzione**:
- Verificare che SSH sia abilitato
- Aumentare timeout se necessario
- Verificare credenziali SSH

### Problema: LLDP neighbors non raccolti

**Possibili cause**:
1. LLDP non abilitato sul dispositivo
2. Nessun neighbor connesso
3. Comando `show lldp neighbors detail` non disponibile

**Soluzione**:
- Verificare che LLDP sia abilitato sul dispositivo
- Verificare che ci siano dispositivi connessi
- Il codice ha fallback a formato semplice se detail non disponibile

### Problema: Dati non salvati nel database

**Possibili cause**:
1. Schema database non aggiornato
2. Errore durante il salvataggio
3. Dati in formato non corretto

**Soluzione**:
- Verificare log del server per errori
- Verificare schema database
- Verificare formato dati raccolti

---

## ✅ Checklist Post-Deploy

- [ ] Deploy completato sul server PCT 600
- [ ] Agent riavviato con nuovo codice
- [ ] Test su dispositivo MikroTik reale
- [ ] Test su dispositivo Ubiquiti EdgeOS reale
- [ ] Test su dispositivo Ubiquiti UniFi reale
- [ ] Verifica salvataggio nel database
- [ ] Verifica visualizzazione nelle tabelle HTML
- [ ] Verifica log per eventuali errori

---

**Stato**: ✅ Deploy completato
**Data deploy**: 2026-01-07 00:40
**Container**: PCT 601 (dadude-agent-Domarc)
**Commit deployato**: 5b0c7784
**Versione**: v3.0.0
**Prossimo passo**: Test su dispositivi reali
