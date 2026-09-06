# SSH Advanced Scanner - Documentazione

## Panoramica

È stato implementato un sistema di scansione SSH avanzato che raccoglie informazioni complete da sistemi Linux, storage (Synology/QNAP) e hypervisor (Proxmox VE).

## Caratteristiche

### Dati Raccolti

Il scanner avanzato raccoglie:

1. **Informazioni Sistema**
   - Hostname, FQDN, OS, kernel, architettura
   - Uptime, boot time, timezone
   - Informazioni NAS-specifiche (modello, seriale, firmware)

2. **CPU**
   - Modello, core fisici/logici, frequenza
   - Utilizzo percentuale, load average (1/5/15 min)
   - Temperatura (se disponibile)
   - Cache size

3. **Memoria**
   - Totale, usata, disponibile, cache, buffer
   - Utilizzo percentuale
   - Swap totale/usato/libero

4. **Storage**
   - Dischi fisici (modello, seriale, dimensione, tipo SSD/HDD/NVMe)
   - Volumi/filesystem (mount point, spazio totale/usato/disponibile)
   - RAID arrays (livello, stato, dispositivi, rebuild progress)
   - SMART status e temperatura dischi

5. **Rete**
   - Interfacce di rete (nome, MAC, IP, stato, velocità)
   - Default gateway
   - DNS servers

6. **Servizi**
   - Servizi systemd attivi/inattivi
   - PID, memoria utilizzata
   - Stato enabled/disabled

7. **Docker**
   - Versione Docker
   - Container running/stopped/total
   - Immagini installate

8. **VM/Container (Proxmox)**
   - Lista VM QEMU e container LXC
   - Stato, memoria, tipo

### Supporto Sudo

Il scanner supporta automaticamente comandi con `sudo` quando necessario:
- Se viene fornita una password, usa `echo 'password' | sudo -S command`
- Se non c'è password, prova `sudo command` (per utenti con NOPASSWD configurato)

## Architettura

### Componenti

1. **Scanner SSH Avanzato** (`dadude-agent/app/probes/ssh_advanced_scanner.py`)
   - Classe `SSHAdvancedScanner` per eseguire scansioni
   - Funzione `scan_advanced()` per uso asincrono
   - Rilevamento automatico del tipo di sistema (Linux, Synology, QNAP, Proxmox)

2. **Endpoint API Agent** (`dadude-agent/app/main.py`)
   - `POST /probe/ssh-advanced` - Esegue scansione avanzata

3. **Modello Database** (`dadude/app/models/inventory.py`)
   - Tabella `LinuxDetails` estesa con campi avanzati
   - Campi JSON per dati complessi (storage, dischi, rete, servizi, VM)

4. **Servizio Salvataggio** (`dadude/app/services/linux_details_service.py`)
   - Funzione `save_advanced_linux_data()` per salvare dati nel database

5. **Migration Database** (`dadude/migrations/add_linux_advanced_fields.py`)
   - Script per aggiungere nuovi campi al database

## Utilizzo

### Via Agent API

```python
import requests

response = requests.post(
    "http://agent:8080/probe/ssh-advanced",
    json={
        "target": "192.168.1.10",
        "username": "admin",
        "password": "password",
        "port": 22
    },
    headers={"Authorization": "Bearer <token>"}
)

result = response.json()
```

### Integrazione nel Sistema Esistente

Il scanner avanzato può essere integrato nel sistema di probe esistente:

```python
from app.services.linux_details_service import save_advanced_linux_data

# Dopo aver eseguito la scansione avanzata
scan_data = await scan_advanced(...)

# Salva nel database
save_advanced_linux_data(session, device_id, scan_data)
```

## Migration Database

Per applicare le modifiche al database:

```bash
# SQLite
sqlite3 data/dadude.db < migrations/add_linux_advanced_fields.sql

# PostgreSQL
psql -U user -d database -f migrations/add_linux_advanced_fields.sql

# O usando lo script Python
python migrations/add_linux_advanced_fields.py
```

## Sistemi Supportati

- **Linux Generico**: Debian, Ubuntu, CentOS, RHEL, Alpine, etc.
- **Synology DSM**: Rilevamento automatico, raccolta info storage/RAID
- **QNAP QTS/QuTS**: Rilevamento automatico, raccolta info storage/RAID
- **Proxmox VE**: Rilevamento automatico, raccolta VM/container

## Limitazioni e Note

1. **Permessi**: Alcuni comandi richiedono sudo (es. `smartctl`, `lshw`)
   - Il sistema prova automaticamente con sudo se disponibile
   - Se l'utente non ha permessi sudo, alcuni dati potrebbero non essere disponibili

2. **Performance**: La scansione completa può richiedere 10-30 secondi
   - Dipende dal numero di dischi, servizi, VM
   - Alcuni comandi hanno timeout configurati

3. **Compatibilità**: Testato su:
   - Linux moderni con systemd
   - Synology DSM 6.x/7.x
   - QNAP QTS 4.x/5.x
   - Proxmox VE 6.x/7.x/8.x

## Prossimi Sviluppi

Possibili miglioramenti futuri:

1. **Supporto NAS Avanzato**
   - Raccolta share SMB/NFS per Synology/QNAP
   - Storage pools dettagliati
   - Snapshot info

2. **Supporto Hypervisor**
   - Raccolta dettagli VM per Proxmox
   - Storage pools Proxmox
   - Cluster info

3. **Ottimizzazioni**
   - Caching risultati
   - Scansioni incrementali
   - Parallelizzazione comandi

4. **Monitoraggio**
   - Alert su dischi con SMART FAILED
   - Alert su RAID degraded
   - Alert su servizi critici down

## Troubleshooting

### Errore: "Permission denied"
- Verificare che l'utente abbia permessi sudo
- Verificare che la password sia corretta
- Controllare configurazione sudoers

### Errore: "Command not found"
- Alcuni comandi potrebbero non essere installati (es. `smartctl`, `lsblk`)
- Il sistema continua comunque raccogliendo dati disponibili

### Dati mancanti
- Verificare che il sistema sia supportato
- Controllare log per errori specifici
- Verificare permessi utente

## Riferimenti

- Script originale: Fornito dall'utente
- Database schema: `dadude/app/models/inventory.py`
- Agent API: `dadude-agent/app/main.py`

