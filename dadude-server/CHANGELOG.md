# Changelog DaDude

Tutte le modifiche notevoli al progetto sono documentate in questo file.

## [3.0.0] - 2026-01-06

### Nuove Funzionalità

#### Unified Scanner Multi-Protocollo
- Nuovo sistema di scansione unificato che combina SSH, SNMP e WinRM
- Endpoint dedicati `/api/v1/unified-scanner/*`
- Supporto automatico rilevamento protocolli in base alle porte aperte
- Gestione credenziali multi-livello (device → cliente → popup)
- Risultati standardizzati per tutti i tipi di dispositivo

#### Sistema di Backup Automatico
- Nuovo servizio `backup_scheduler.py` per backup automatici schedulati
- Backup database PostgreSQL, configurazioni, certificati PKI
- Retention configurabile (default 30 giorni)
- Compressione automatica in `.tar.gz`
- Endpoint `/api/v1/backup/*` per gestione backup

#### Sistema di Versioning
- Nuovo servizio `version_manager.py` per gestione versioni
- Supporto auto-incremento (patch, minor, major)
- Storico versioni in JSON
- File VERSION nella root del progetto
- Endpoint `/api/v1/backup/version` per info versione

#### Log Viewer (già esistente)
- Visualizzazione log dall'interfaccia web
- Filtri per livello, ricerca testuale
- Auto-refresh configurabile
- Download file log

### Miglioramenti

#### Scansione Porte UDP
- Aggiunto supporto scansione UDP nell'agent
- Porte UDP scansionate: 53 (DNS), 161 (SNMP), 162 (SNMP Trap), 123 (NTP), 500 (IKE)
- Payload specifici per ogni protocollo (SNMP GET, DNS query)

#### Gestione VM Proxmox
- Aggiunta VM all'inventario ora è MANUALE
- Le VM vengono salvate in `ProxmoxVM` ma non aggiunte automaticamente
- Usare endpoint `/proxmox/create-vm-devices` per aggiunta manuale

### Fix

#### Router Cleanup
- Aggiunto router `cleanup.py` mancante in `main_dual.py`
- Pulsanti pulizia inventario ora funzionanti

#### Database
- Rimosso default SQLite da `init_db()`
- PostgreSQL è ora l'unico database supportato per il server

### Sicurezza

#### Gestione Credenziali
- Verificata corretta decryption credenziali SNMP
- Test multipli community SNMP (assegnate + "public")
- Sintassi pysnmp v7.x verificata e conforme

### Versioni Componenti

- Server: 3.0.0
- Agent: 3.0.0
- Agent WebSocket Client: 3.0.0
- Dockerfile.dual: 3.0.0

### Note di Migrazione

1. **Backup pre-aggiornamento**: Consigliato backup completo prima di aggiornare
2. **Database**: Assicurarsi che PostgreSQL sia configurato correttamente
3. **Agent**: Aggiornare tutti gli agent alla versione 3.0.0
4. **VM Proxmox**: Le VM esistenti in inventario rimarranno, le nuove non saranno aggiunte automaticamente

---

## [2.7.4] - Versione precedente

Supporto pysnmp v7.x con API asincrona.
