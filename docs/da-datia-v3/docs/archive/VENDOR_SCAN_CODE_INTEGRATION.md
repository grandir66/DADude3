# Codice Scansione Vendor - Guida Integrazione

**⚠️ IMPORTANTE**: Questo documento identifica il codice di scansione vendor sviluppato che deve essere integrato passo passo nella versione funzionante del PCT 600.

**NON modificare il sistema attuale** - usare questo documento come riferimento per integrazione futura.

---

## 📋 Situazione Attuale

### Versione Funzionante (PCT 600)
- ✅ Sistema stabile e funzionante
- ❌ Recupera pochi dati da MikroTik e Ubiquiti
- ❌ Non acquisisce interfacce di rete
- ❌ Non acquisisce LLDP neighbors
- ❌ Interfaccia visualizzazione tabelle persa (solo JSON)

### Codice Sviluppato (Locale)
- ✅ Scansione SNMP avanzata con LLDP e interfacce
- ✅ Scansione SSH MikroTik con interfacce e neighbors
- ✅ Scansione SSH Ubiquiti con interfacce e LLDP
- ✅ Scanner unificato con supporto completo

---

## 🔍 File da Integrare

### 1. SNMP Probe Avanzato
**File**: `dadude-agent/app/probes/snmp_probe.py`

**Funzionalità sviluppate**:
- **LLDP Neighbors** (righe 1120-1211)
  - Query LLDP Remote Table OIDs
  - Estrazione system names, chassis IDs, port IDs
  - Matching per costruire lista neighbors

- **Interfacce Dettagliate** (righe 1428-1557)
  - Query IF-MIB completa
  - Estrazione: nome, tipo, velocità, stato admin/oper, MAC address
  - Costruzione lista interfacce con dettagli completi

- **Routing Table** (righe 1298-1360)
  - Query IP Forwarding Table MIB
  - Estrazione destinazioni, gateway, tipo route

- **ARP Table** (righe 1362-1425)
  - Query ARP table (solo per router)
  - Estrazione IP, MAC, interfaccia

**Campi aggiunti al risultato**:
```python
{
    "lldp_neighbors": [...],      # Lista neighbors LLDP
    "neighbors": [...],           # Alias per compatibilità
    "neighbors_count": N,
    "interfaces": [...],          # Lista interfacce dettagliate
    "interfaces_count": N,
    "interface_details": [...],   # Alias per compatibilità
    "routing_table": [...],
    "routing_count": N,
    "arp_table": [...],
    "arp_count": N
}
```

**OID utilizzati**:
- LLDP: `1.0.8802.1.1.2.1.4.1.1.*` (IEEE 802.1AB)
- IF-MIB: `1.3.6.1.2.1.2.2.1.*` (Standard MIB-II)
- Routing: `1.3.6.1.2.1.4.21.1.*` (IP Forwarding Table)
- ARP: `1.3.6.1.2.1.4.22.1.*` (IP NetToMedia Table)

---

### 2. SSH MikroTik Probe
**File**: `dadude-agent/app/probes/ssh_vendors/mikrotik.py`

**Funzionalità sviluppate**:
- **Interfacce** (righe 155-173)
  - Comando: `/interface print terse`
  - Estrazione: nome, tipo, MAC, MTU, stato running/disabled

- **Neighbors** (righe 175-219)
  - Comando: `/ip neighbor print detail`
  - Estrazione: local_interface, ip_address, mac_address, identity, platform, board, version
  - Supporto MNDP/LLDP/CDP

- **Routing Table** (righe 221-237)
  - Comando: `/ip route print terse where active`
  - Estrazione: dst-address, gateway, distance, interface

- **ARP Table** (righe 239-255)
  - Comando: `/ip arp print terse`
  - Estrazione: address, mac-address, interface, dynamic

**Campi aggiunti**:
```python
{
    "interfaces": [
        {
            "name": "ether1",
            "type": "ether",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "mtu": 1500,
            "running": True,
            "disabled": False
        }
    ],
    "neighbors": [
        {
            "local_interface": "ether1",
            "ip_address": "192.168.1.1",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "remote_device_name": "Router",
            "platform": "RouterOS",
            "discovered_by": "mndp"
        }
    ],
    "routing_table": [...],
    "arp_table": [...]
}
```

---

### 3. SSH Ubiquiti Probe
**File**: `dadude-agent/app/probes/ssh_vendors/ubiquiti.py`

**Funzionalità sviluppate**:
- **EdgeOS Interfaces** (righe 119-154)
  - Comando: `show interfaces`
  - Estrazione: nome, MAC, IPv4

- **EdgeOS LLDP Neighbors** (righe 156-187)
  - Comando: `show lldp neighbors detail`
  - Estrazione: local_interface, remote_device_name, remote_interface, platform

- **UniFi CLI LLDP** (righe 407-422)
  - Modalità CLI interattiva (`cli` -> `enable`)
  - Comando: `show lldp neighbors`
  - Estrazione neighbors per UniFi Switch

**Campi aggiunti**:
```python
{
    "interfaces": [
        {
            "name": "eth0",
            "mac_address": "AA:BB:CC:DD:EE:FF",
            "ipv4": "192.168.1.1"
        }
    ],
    "neighbors": [
        {
            "local_port": "eth0",
            "remote_device": "Switch-01",
            "discovered_by": "lldp"
        }
    ]
}
```

---

### 4. Unified Scanner
**File**: `dadude-agent/app/probes/unified_scanner.py`

**Funzionalità sviluppate**:
- **MikroTik Neighbor Discovery** (righe 2043-2103)
  - Parse `/ip neighbor print detail`
  - Costruzione `LLDPNeighbor` objects

- **Interfacce SNMP** (righe 2820-2925)
  - Walk IF-MIB completo
  - Estrazione: nome, velocità, stato, MAC, tipo, MTU, RX/TX bytes

- **LLDP SNMP** (righe 2994-3122)
  - Walk LLDP Remote Table completo
  - Estrazione: system names, descriptions, chassis IDs, port IDs, management IPs
  - Matching per costruire neighbors completi

**Strutture dati**:
```python
class NetworkInterface:
    name: str
    description: str
    interface_type: str
    mac_address: str
    speed_mbps: int
    state: str  # up/down
    admin_status: str
    oper_status: str
    mtu: int
    rx_bytes: int
    tx_bytes: int

class LLDPNeighbor:
    local_port: str
    remote_device: str
    remote_ip: str
    remote_port: str
    remote_description: str
```

---

## 🔄 Piano di Integrazione

### Fase 1: Backup e Preparazione
1. ✅ Backup sistema PCT 600 (già fatto)
2. ✅ Identificare codice sviluppato (questo documento)
3. ⏳ Verificare compatibilità con versione attuale

### Fase 2: Integrazione SNMP Probe
1. Copiare sezione LLDP da `snmp_probe.py` (righe 1120-1211)
2. Copiare sezione Interfacce da `snmp_probe.py` (righe 1428-1557)
3. Testare su dispositivo MikroTik/Ubiquiti
4. Verificare salvataggio nel database

### Fase 3: Integrazione SSH MikroTik
1. Copiare metodo `_get_interfaces()` da `mikrotik.py` (righe 155-173)
2. Copiare metodo `_get_neighbors()` da `mikrotik.py` (righe 175-219)
3. Integrare nel probe SSH esistente
4. Testare connessione SSH MikroTik

### Fase 4: Integrazione SSH Ubiquiti
1. Copiare metodo `_get_edgeos_interfaces()` da `ubiquiti.py` (righe 119-154)
2. Copiare metodo `_get_edgeos_neighbors()` da `ubiquiti.py` (righe 156-187)
3. Copiare metodo `_try_unifi_cli()` per UniFi Switch (righe 356-432)
4. Testare su EdgeOS e UniFi

### Fase 5: Database Schema
1. Verificare tabelle `inventory_network_interfaces` esistente
2. Verificare campi per LLDP neighbors
3. Aggiungere migrazioni se necessario

### Fase 6: UI - Visualizzazione Tabelle
**⚠️ NOTA**: Gli endpoint API e i template HTML esistono già!

**Endpoint API esistenti**:
- ✅ `/api/v1/mikrotik/agents/{agent_id}/interfaces` - Interfacce MikroTik
- ✅ `/api/v1/mikrotik/agents/{agent_id}/ip-addresses` - IP addresses MikroTik
- ✅ `/api/v1/inventory/{customer_id}/devices/{device_id}/lldp-neighbors` - LLDP neighbors
- ✅ `/api/v1/inventory/{customer_id}/devices/{device_id}/cdp-neighbors` - CDP neighbors

**Template HTML esistenti**:
- ✅ `dadude/app/templates/mikrotik_detail.html` - Tab interfacce (righe 167-209)
- ✅ `dadude/app/templates/router_detail.html` - Tab interfacce (righe 206-233)
- ✅ Funzione JavaScript `loadInterfaces()` già presente (righe 581-634)

**Problema identificato**:
- I template HTML esistono ma potrebbero non funzionare perché:
  1. I dati non vengono raccolti durante la scansione automatica
  2. I dati vengono raccolti ma non salvati nel database
  3. Gli endpoint API non restituiscono i dati corretti

**Azioni da fare**:
1. Verificare che i dati vengano raccolti durante la scansione
2. Verificare che i dati vengano salvati nel database
3. Testare gli endpoint API e verificare risposta JSON
4. Verificare che i template HTML chiamino correttamente gli endpoint
5. Aggiungere visualizzazione LLDP neighbors nei template (se mancante)

---

## 📊 Struttura Dati Database

### Network Interfaces
**Tabella**: `inventory_network_interfaces`

```python
{
    "id": "uuid",
    "device_id": "uuid",
    "name": "eth0",
    "description": "Ethernet interface",
    "interface_type": "ethernet",
    "mac_address": "AA:BB:CC:DD:EE:FF",
    "ip_addresses": [{"ip": "192.168.1.1", "mask": "24"}],
    "speed_mbps": 1000,
    "duplex": "full",
    "mtu": 1500,
    "admin_status": "up",
    "oper_status": "up",
    "vlan_id": null,
    "is_management": False
}
```

### LLDP Neighbors
**Campo JSON**: `device.advanced_info.lldp_neighbors` o tabella dedicata

```python
{
    "local_port": "eth0",
    "remote_device": "Switch-01",
    "remote_ip": "192.168.1.10",
    "remote_port": "Port 1",
    "remote_description": "Platform: RouterOS, Version: 7.x",
    "discovered_by": "lldp"
}
```

---

## 🧪 Test Checklist

### SNMP Probe
- [ ] Test LLDP su switch MikroTik
- [ ] Test LLDP su switch Ubiquiti
- [ ] Test interfacce su router MikroTik
- [ ] Test interfacce su switch Ubiquiti
- [ ] Verifica salvataggio nel database

### SSH MikroTik
- [ ] Test `/interface print terse`
- [ ] Test `/ip neighbor print detail`
- [ ] Verifica parsing corretto
- [ ] Verifica salvataggio nel database

### SSH Ubiquiti
- [ ] Test `show interfaces` (EdgeOS)
- [ ] Test `show lldp neighbors detail` (EdgeOS)
- [ ] Test CLI mode UniFi Switch
- [ ] Verifica parsing corretto
- [ ] Verifica salvataggio nel database

### UI
- [ ] Visualizzazione tabella interfacce
- [ ] Visualizzazione tabella LLDP neighbors
- [ ] Aggiornamento dati in tempo reale
- [ ] Filtri e ricerca

---

## 📝 Note Importanti

1. **NON modificare codice funzionante** - integrare solo le nuove funzionalità
2. **Test incrementale** - testare ogni fase prima di procedere
3. **Backup continuo** - fare backup prima di ogni modifica
4. **Compatibilità** - verificare che i dati siano compatibili con schema DB esistente
5. **Performance** - le query SNMP/SSH possono essere lente, aggiungere timeout appropriati
6. **Endpoint API esistenti** - gli endpoint API per interfacce e LLDP esistono già, verificare che funzionino
7. **Template HTML esistenti** - i template HTML esistono già, verificare che chiamino correttamente gli endpoint
8. **Salvataggio automatico** - il codice in `inventory.py` già salva LLDP neighbors e interfacce (righe 1727-1813), verificare che funzioni

---

## 🔗 File Correlati

### Agent
- `dadude-agent/app/probes/snmp_probe.py` - SNMP avanzato
- `dadude-agent/app/probes/ssh_vendors/mikrotik.py` - SSH MikroTik
- `dadude-agent/app/probes/ssh_vendors/ubiquiti.py` - SSH Ubiquiti
- `dadude-agent/app/probes/unified_scanner.py` - Scanner unificato

### Server
- `dadude/app/models/inventory.py` - Modelli database (NetworkInterface, LLDPNeighbor, CDPNeighbor)
- `dadude/app/routers/inventory.py` - Endpoint API per LLDP/CDP neighbors (righe 4698-4801)
- `dadude/app/routers/mikrotik.py` - Endpoint API interfacce MikroTik (righe 263-300)
- `dadude/app/templates/mikrotik_detail.html` - Template interfacce MikroTik (righe 167-209, 581-634)
- `dadude/app/templates/router_detail.html` - Template interfacce router (righe 206-233)
- `dadude/app/services/device_probe_service.py` - Servizio probe dispositivi
- `dadude/app/services/mikrotik_service.py` - Servizio MikroTik (metodo `get_interfaces()`)
- `dadude/app/services/lldp_cdp_collector.py` - Collector LLDP/CDP (referenziato in inventory.py)

---

## ✅ Stato Integrazione

- [x] Fase 1: Backup e Preparazione
- [ ] Fase 2: Integrazione SNMP Probe (non necessaria - già presente)
- [x] Fase 3: Integrazione SSH MikroTik ✅ **COMPLETATA E DEPLOYATA**
- [x] Fase 4: Integrazione SSH Ubiquiti ✅ **COMPLETATA E DEPLOYATA**
- [x] Fase 5: Database Schema (già presente)
- [x] Fase 6: UI - Visualizzazione Tabelle (già presente)

**Deploy**: ✅ Completato sul server PCT 600
**File modificato**: `dadude-agent/app/probes/ssh_probe.py`
**Data deploy**: 2025-01-06

---

**Ultimo aggiornamento**: 2025-01-06
**Versione riferimento**: PCT 600 (stabile)
**Versione sviluppo**: Locale (da integrare)
