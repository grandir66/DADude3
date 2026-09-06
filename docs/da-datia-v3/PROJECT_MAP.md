# DaDude Inventory System - Mappa Completa del Progetto

**Versione:** 3.0.0  
**Data Analisi:** 2025-01-07  
**Architettura:** Dual-Port (Agent API 8000 + Admin UI 8001)

---

## 📋 Indice

1. [Architettura Generale](#architettura-generale)
2. [Struttura Progetto](#struttura-progetto)
3. [Componenti Core](#componenti-core)
4. [Mappa Interazioni](#mappa-interazioni)
5. [Interfaccia Grafica](#interfaccia-grafica)
6. [Flussi Dati](#flussi-dati)
7. [Agent Architecture](#agent-architecture)
8. [Sicurezza](#sicurezza)
9. [Deployment](#deployment)

---

## 🏗️ Architettura Generale

```
┌─────────────────────────────────────────────────────────────────┐
│                    DaDude Inventory System                       │
│                         v3.0.0                                   │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
   ┌────▼────┐          ┌─────▼─────┐         ┌────▼────┐
   │  Agent  │          │   Server  │         │  Agent  │
   │  Site 1 │◄─────────┤  DaDude   │─────────►│  Site 2 │
   │         │ WebSocket│  (Dual)   │ WebSocket│         │
   └─────────┘  mTLS    └─────┬─────┘  mTLS   └─────────┘
                              │
                    ┌─────────┼─────────┐
                    │         │         │
              ┌─────▼──┐ ┌───▼───┐ ┌───▼───┐
              │ Admin  │ │  DB   │ │ The   │
              │   UI   │ │Postgres│ │ Dude  │
              │ :8001  │ │ SQLite │ │Server │
              └────────┘ └────────┘ └───────┘
```

**Separazione Porte:**
- **Porta 8000 (Agent API)**: Solo endpoint per comunicazione agent, esposta su Internet
- **Porta 8001 (Admin UI)**: Dashboard web + Management API, solo rete interna

---

## 📁 Struttura Progetto Completa

### Root Directory
```
DATIA-inventtory/
├── dadude/                    # Server principale (150 file)
│   ├── app/
│   │   ├── main_dual.py       # ⭐ Entry point dual-port
│   │   ├── run_dual.py        # 🚀 Runner multiprocesso
│   │   ├── config.py          # ⚙️ Configurazione
│   │   ├── auth.py            # 🔐 Autenticazione
│   │   ├── models/            # 🗄️ Modelli database (6 file)
│   │   ├── routers/           # 📡 API endpoints (19 file)
│   │   ├── services/          # 🔧 Logica business (36 file)
│   │   ├── templates/         # 🎨 HTML templates (20 file)
│   │   ├── static/            # 📦 Risorse statiche (10 file)
│   │   └── utils/             # 🛠️ Utilities (1 file)
│   ├── migrations/            # 📊 Migrazioni DB (10 file)
│   ├── deploy/                # 🚀 Script deployment
│   ├── docker-compose-dual.yml
│   ├── Dockerfile.dual
│   └── requirements.txt
├── dadude-agent/              # Agent distribuito (48 file Python)
│   ├── app/
│   │   ├── agent.py          # 🤖 Agent principale
│   │   ├── connection/       # 🔌 WebSocket client
│   │   ├── commands/         # 📨 Gestore comandi
│   │   ├── probes/           # 🔬 Probe modulari
│   │   ├── scanners/         # 🔍 Scanner rete
│   │   ├── storage/          # 💾 Coda locale
│   │   ├── workers/          # 👷 Worker coda
│   │   ├── updater/          # 🔄 Auto-update
│   │   └── scheduler/        # ⏰ Scheduler locale
│   ├── docker-compose.yml
│   └── Dockerfile
├── backups/                   # 📦 Backup storici
├── docs/                      # 📚 Documentazione
└── [script root]             # Script deployment/update
```

---

## 🎯 Componenti Core - Dettaglio Completo

### 1. **dadude/app/main_dual.py** ⭐ ENTRY POINT

**Funzione**: Applicazione FastAPI dual-port

**Componenti Principali:**
- `agent_app`: FastAPI app per porta 8000 (Agent API)
  - Router registrati: `agents`, `customers`, `inventory`, `unified_scanner`
  - WebSocket Hub attivo
  - Device Monitoring Service attivo
  
- `admin_app`: FastAPI app per porta 8001 (Admin UI)
  - Router registrati: Tutti i router (19 totali)
  - Dashboard router incluso
  - Auth Middleware attivo
  - Proxy endpoints per WebSocket Hub

**Lifecycle Management:**
- `_init_shared_services()`: Inizializza servizi condivisi una sola volta
- `agent_lifespan()`: Lifecycle Agent API
- `admin_lifespan()`: Lifecycle Admin UI

**Dipendenze:**
- Tutti i router (`routers/*`)
- Tutti i servizi (`services/*`)
- WebSocket Hub (singleton)
- Dude Service (opzionale)
- Sync Service (opzionale)

---

### 2. **app/models/database.py** 🗄️ MODELLI DATABASE

**Tabelle Principali:**

1. **Customer** (Cliente/Tenant)
   - Campi: `id`, `code`, `name`, `contact_email`, `active`
   - Relazioni: `networks`, `credentials`, `devices`, `agents`

2. **Network** (Rete IP/VLAN)
   - Campi: `ip_network`, `gateway`, `vlan_id`, `gateway_agent_id`
   - Relazione: `customer` (N:1)
   - Supporta reti sovrapposte tra clienti

3. **Credential** (Credenziali Criptate)
   - Campi: `credential_type`, `username`, `password_encrypted`, `is_default`
   - Relazione: `customer` (N:1)
   - Criptazione: AES-256-GCM

4. **DeviceAssignment** (Assegnazione Device)
   - Campi: `dude_device_id`, `customer_id`, `role`, `location`
   - Relazione: `customer` (N:1)

5. **AgentAssignment** (Assegnazione Agent)
   - Campi: `agent_id`, `customer_id`, `assigned_networks`
   - Relazione: `customer` (N:1)

6. **DudeAgent** (Agent The Dude)
   - Campi: `dude_id`, `name`, `address`, `active`
   - Sincronizzato da The Dude Server

7. **BackupTemplate** (Template Backup)
   - Campi: `name`, `device_type`, `backup_command`, `schedule_cron`
   
8. **BackupJob** (Job Backup)
   - Campi: `template_id`, `device_id`, `status`, `scheduled_at`
   
9. **BackupVersion** (Versione Backup)
   - Campi: `job_id`, `version`, `backup_data`, `created_at`
   - Versioning automatico

**Indici:**
- `idx_network_customer`: Ricerca reti per cliente
- `idx_network_vlan`: Ricerca per VLAN
- `idx_credential_customer`: Ricerca credenziali per cliente

---

### 3. **app/routers/** - API Endpoints Completi

#### **agents.py** 🤖 (1200+ righe)
**Endpoints Principali:**
- `POST /api/v1/agents/register`: Registrazione agent con certificato mTLS
- `GET /api/v1/agents/pending`: Lista agent in attesa approvazione
- `POST /api/v1/agents/{id}/approve`: Approva agent (auto-approval supportato)
- `GET /api/v1/agents/ws/connected`: Lista agent connessi via WebSocket
- `POST /api/v1/agents/ws/{agent_id}/command`: Invia comando via WebSocket
- `POST /api/v1/agents/{id}/exec`: Esegue comando su agent
- `GET /api/v1/agents/{id}/verify-version`: Verifica versione agent
- `POST /api/v1/agents/{id}/trigger-update`: Triggera update agent

**Dipendenze:**
- `websocket_hub`: Comunicazione real-time
- `agent_service`: Logica business agent
- `customer_service`: Gestione clienti
- `pki_service`: Certificati mTLS
- `version_manager`: Gestione versioni

#### **customers.py** 👥 (800+ righe)
**Endpoints:**
- CRUD Clienti: `GET/POST/PUT/DELETE /api/v1/customers`
- CRUD Reti: `GET/POST/PUT/DELETE /api/v1/customers/{id}/networks`
- CRUD Credenziali: `GET/POST/PUT/DELETE /api/v1/customers/{id}/credentials`
- Assegnazione Device: `POST /api/v1/customers/{id}/devices`
- Scan Reti: `POST /api/v1/customers/agents/{agent_id}/scan-customer-networks`
- Test Agent: `POST /api/v1/customers/agents/{agent_id}/test`

**Dipendenze:**
- `customer_service`: Logica business clienti
- `agent_service`: Selezione agent per scan
- `websocket_hub`: Comunicazione con agent
- `encryption_service`: Decriptazione credenziali

#### **inventory.py** 📦 (2200+ righe)
**Endpoints Principali:**
- `GET /api/v1/inventory/devices`: Lista dispositivi inventariati
- `GET /api/v1/inventory/devices/{id}`: Dettaglio dispositivo completo
- `POST /api/v1/inventory/auto-detect`: Auto-detect dispositivo singolo
- `POST /api/v1/inventory/auto-detect-batch`: Auto-detect multipli
- `POST /api/v1/inventory/probe`: Probe dispositivo
- `POST /api/v1/inventory/ssh-advanced-scan`: Scan SSH avanzato

**Features:**
- Auto-detect multi-protocollo (SSH/WMI/SNMP)
- Probe avanzati per Linux/Windows/MikroTik/Proxmox
- Collect LLDP/CDP neighbors
- Collect ARP tables
- Collect Proxmox VMs/Hosts

**Dipendenze:**
- `device_probe_service`: Logica probe
- `agent_service`: Selezione agent
- `unified_scanner_service`: Scanner unificato
- `websocket_hub`: Comunicazione agent
- `mikrotik_service`, `proxmox_collector`, `lldp_cdp_collector`: Collector specifici

#### **unified_scanner.py** 🔍 (500+ righe)
**Endpoints:**
- `POST /api/v1/unified-scanner/scan`: Scan multi-protocollo
- `GET /api/v1/unified-scanner/results/{device_id}`: Risultati scan

**Protocolli Supportati:**
- SSH: Linux, Cisco, HP, MikroTik, Ubiquiti, Proxmox, QNAP, Synology
- WMI: Windows Server, Workstation, Hyper-V
- SNMP: v1, v2c, v3

**Dipendenze:**
- `unified_scanner_service`: Logica scanner
- `agent_service`: Selezione agent
- `websocket_hub`: Comunicazione agent

#### **dashboard.py** 🎨 (300+ righe)
**Endpoints Web (HTML):**
- `GET /`: Dashboard principale
- `GET /dashboard`: Dashboard principale
- `GET /monitoring`: Pagina monitoraggio dispositivi
- `GET /customers`: Lista clienti (UI)
- `GET /customers/{id}`: Dettaglio cliente (UI)
- `GET /devices`: Lista dispositivi (UI)
- `GET /agents`: Gestione agent (UI)
- `GET /settings`: Impostazioni (UI)
- `GET /login`: Pagina login
- `POST /login`: Autenticazione

**Funzione `get_dashboard_data()`:**
- Raccoglie dati da: `customer_service`, `sync_service`, `alert_service`
- Conta dispositivi da Inventory DB
- Conta agent connessi via WebSocket Hub
- Statistiche The Dude (se connesso)

**Dipendenze:**
- `templates`: Jinja2 templates HTML
- `customer_service`: Dati clienti
- `dude_service`: Dati The Dude
- `sync_service`: Dati sincronizzati
- `alert_service`: Alert non riconosciuti

#### **Altri Router Importanti:**

**device_backup.py** 💾 (400+ righe)
- Gestione backup dispositivi
- Template, job, versioning
- Dipende: `device_backup_service`, `backup_scheduler`

**cleanup.py** 🧹 (200+ righe)
- Pulizia dispositivi obsoleti
- Merge dispositivi duplicati
- Dipende: `device_cleanup_service`, `device_merge_service`

**backup.py** 📦 (300+ righe)
- Backup sistema completo
- Versioning backup
- Dipende: `version_manager`

**mikrotik.py** 🛡️ (600+ righe)
- Operazioni MikroTik specifiche
- Backup configurazione
- Dipende: `mikrotik_service`, `mikrotik_backup_collector`

---

### 4. **app/services/** - Logica Business Completa

#### **websocket_hub.py** 🔌 (500+ righe) - SINGLETON
**Funzione**: Hub centrale per tutte le connessioni WebSocket agent

**Pattern**: Singleton (una sola istanza globale)

**Metodi Principali:**
- `connect(agent_id, websocket)`: Registra connessione agent
- `disconnect(agent_id)`: Rimuove connessione
- `send_command(agent_id, command, timeout)`: Invia comando e attende risposta
- `broadcast(message)`: Broadcast a tutti gli agent connessi
- `connected_count()`: Conta agent connessi
- `get_connected_agents()`: Lista agent connessi

**Storage:**
- `_connections: Dict[str, WebSocket]`: Connessioni attive
- `_pending_responses: Dict[str, asyncio.Future]`: Risposte in attesa

**Uso**: Tutti i router che comunicano con agent

#### **agent_service.py** 🤖 (300+ righe)
**Funzione**: Logica business per selezione/gestione agent

**Metodi:**
- `get_agent_for_customer(customer_id, network_id, target_ip)`: Seleziona agent ottimale
  - Cerca agent assegnato al cliente
  - Cerca agent per rete specifica
  - Cerca agent per IP target (subnet matching)
  - Fallback: primo agent attivo
  
- `_agent_to_dict(agent)`: Converte agent in dict con password decriptata

**Dipendenze**: `customer_service`, `encryption_service`

#### **customer_service.py** 👥 (800+ righe)
**Funzione**: CRUD completo clienti, reti, credenziali

**Metodi Principali:**
- `create_customer()`, `update_customer()`, `delete_customer()`
- `create_network()`, `update_network()`, `delete_network()`
- `create_credential()`, `update_credential()`, `delete_credential()`
- `get_agent(agent_id, include_password)`: Ottiene agent con password decriptata
- `list_customers()`, `get_customer()`, `get_customer_by_code()`

**Dipendenze**: `database`, `encryption_service`

#### **unified_scanner_service.py** 🔍 (400+ righe)
**Funzione**: Coordina scan multi-protocollo

**Metodi:**
- `scan_device(target, protocols, credentials)`: Esegue scan con protocolli multipli
- `_select_protocols()`: Seleziona protocolli da provare
- `_try_protocol()`: Prova singolo protocollo

**Dipendenze**: `agent_service`, `websocket_hub`

#### **device_probe_service.py** 🔬 (500+ righe)
**Funzione**: Esegue probe su dispositivi

**Metodi:**
- `probe_device()`: Probe generico
- `probe_ssh()`, `probe_wmi()`, `probe_snmp()`: Probe specifici
- `probe_mikrotik()`, `probe_proxmox()`: Probe vendor-specific

**Dipendenze**: `agent_service`, `websocket_hub`

#### **device_backup_service.py** 💾 (600+ righe)
**Funzione**: Gestisce backup dispositivi

**Metodi:**
- `create_backup_job()`: Crea job backup
- `execute_backup()`: Esegue backup
- `get_backup_versions()`: Lista versioni backup
- `restore_backup()`: Ripristina backup

**Dipendenze**: `backup_scheduler`, `mikrotik_backup_collector`, `proxmox_backup_collector`

#### **backup_scheduler.py** ⏰ (400+ righe)
**Funzione**: Scheduler automatico backup

**Metodi:**
- `start()`: Avvia scheduler
- `stop()`: Ferma scheduler
- `_execute_scheduled_backups()`: Esegue backup schedulati
- `_backup_config_files()`: Backup file configurazione

**Dipendenze**: `device_backup_service`

#### **device_monitoring_service.py** 📊 (300+ righe)
**Funzione**: Monitora stato dispositivi

**Metodi:**
- `start_async()`: Avvia monitoring async
- `stop()`: Ferma monitoring
- `_check_devices()`: Verifica stato dispositivi periodico

**Dipendenze**: `websocket_hub`

#### **dude_service.py** 🛡️ (500+ righe)
**Funzione**: Comunicazione con The Dude Server

**Metodi:**
- `connect()`: Connessione RouterOS API
- `get_devices()`: Lista dispositivi The Dude
- `get_probes()`: Lista probe
- `get_alerts()`: Lista alert
- `add_device()`: Aggiunge dispositivo
- `get_discovery_results()`: Risultati discovery

**Dipendenze**: `routeros_api` (libreria esterna)

#### **sync_service.py** 🔄 (400+ righe)
**Funzione**: Sincronizza dati da The Dude

**Metodi:**
- `full_sync()`: Sync completo
- `start()`: Avvia polling periodico
- `stop()`: Ferma polling
- `_sync_devices()`, `_sync_probes()`, `_sync_alerts()`: Sync specifici

**Dipendenze**: `dude_service`

#### **Altri Servizi Importanti:**

- `encryption_service.py`: AES-256-GCM encryption
- `mikrotik_service.py`: Operazioni MikroTik
- `pki_service.py`: Gestione certificati mTLS
- `version_manager.py`: Gestione versioni
- `settings_service.py`: Gestione settings
- `mac_lookup_service.py`: Lookup MAC vendor
- `proxmox_collector.py`: Collector Proxmox
- `mikrotik_backup_collector.py`: Collector backup MikroTik
- `hp_aruba_collector.py`: Collector HP/Aruba
- `lldp_cdp_collector.py`: Collector LLDP/CDP
- `linux_details_service.py`: Dettagli Linux avanzati
- `snmp_arp_service.py`: ARP via SNMP
- `dude_agent_sync.py`: Sync agent da The Dude
- `agent_client.py`: Client HTTP per agent remoti
- `command_execution_service.py`: Esecuzione comandi
- `device_merge_service.py`: Merge dispositivi duplicati
- `device_cleanup_service.py`: Pulizia dispositivi obsoleti

---

### 5. **app/templates/** - Interfaccia Grafica

#### **base.html** 🎨 TEMPLATE BASE (400+ righe)
**Funzione**: Template base per tutte le pagine

**Framework:**
- Bootstrap 5 (CSS Framework)
- Vue.js 3 (JavaScript Framework)
- Chart.js (Grafici)
- Bootstrap Icons

**Componenti Inclusi:**
- Sidebar navigazione
- Header con breadcrumb
- Footer
- Toast notifications container
- Loading overlay container

**CSS Variables:**
- Palette colori (primary, success, warning, danger)
- Spacing, typography, shadows
- Responsive breakpoints

#### **dashboard.html** 📊 (300+ righe)
**Funzione**: Dashboard principale con statistiche

**Componenti Vue.js:**
- `AnimatedCounter`: Contatori animati per statistiche
- `Chart.js`: Grafici dispositivi/alert
- Cards statistiche: Clienti, Dispositivi, Agent, Alert

**Dati Visualizzati:**
- Totale clienti
- Dispositivi inventariati (totali, monitorati, online, offline)
- Agent connessi (MikroTik, Docker)
- Alert non riconosciuti
- Statistiche The Dude (se connesso)

#### **monitoring.html** 📡 (500+ righe)
**Funzione**: Lista dispositivi con filtri avanzati

**Filtri:**
- Cliente (dropdown con autocomplete)
- Stato (online/offline/all)
- Tipo monitoraggio (Dude/Inventory/All)
- Mostra tutti (include disattivati)

**Componenti:**
- `DataTable`: Tabella dispositivi con ordinamento/filtri
- Filtri avanzati Vue.js
- Paginazione

**Dati:**
- Device da The Dude (via `sync_service`)
- Device da Inventory DB (via `InventoryDevice`)

#### **customers.html** 👥 (400+ righe)
**Funzione**: Lista clienti con azioni

**Azioni:**
- Crea nuovo cliente (modale Vue.js)
- Modifica cliente
- Elimina cliente
- Visualizza dettaglio

**Componenti:**
- `DataTable`: Tabella clienti
- Modali Vue.js per creazione/modifica

#### **customer_detail.html** 👤 (800+ righe)
**Funzione**: Dettaglio completo cliente

**Sezioni (Tabs):**
1. Info Cliente: Dati anagrafici
2. Reti: Lista reti con gestione
3. Credenziali: Lista credenziali con gestione
4. Agent: Agent assegnati
5. Dispositivi: Dispositivi assegnati

**Componenti:**
- Tabs Bootstrap
- Form Vue.js per ogni sezione
- `DataTable` per liste

#### **agents.html** 🤖 (600+ righe)
**Funzione**: Gestione agent

**Features:**
- Lista agent pending (in attesa approvazione)
- Lista agent approvati
- Stato connessione WebSocket (real-time)
- Azioni: Approva, Rifiuta, Comandi, Update

**Componenti:**
- WebSocket status indicator (colore verde/rosso)
- Modali per comandi
- Form per trigger update

#### **Altri Template:**

- `devices.html`: Lista dispositivi The Dude
- `discovery.html`: Network discovery con form
- `settings.html`: Impostazioni sistema (tabs multipli)
- `alerts.html`: Gestione alert
- `backups.html`: Gestione backup dispositivi
- `credentials.html`: Gestione credenziali
- `logs.html`: Visualizzazione log
- `mikrotik_detail.html`: Dettaglio MikroTik con interfacce/route
- `router_detail.html`: Dettaglio router generico
- `scan_results.html`: Risultati unified scanner
- `customer_discovery.html`: Discovery per cliente specifico
- `settings_import_export.html`: Import/export dati
- `settings_webhooks.html`: Configurazione webhook
- `login.html`: Pagina login con form

---

### 6. **app/static/** - Risorse Statiche

#### **js/app.js** 📜 (50 righe)
**Funzione**: Inizializza app Vue.js globale

**Componenti Registrati:**
- `ToastNotifications`
- `LoadingOverlay`
- `DataTable`
- `AnimatedCounter`

**Utilities Globali:**
- `window.toastSuccess(message)`
- `window.toastError(message)`
- `window.toastWarning(message)`
- `window.toastInfo(message)`

#### **js/api-utils.js** 🔌 (200+ righe)
**Funzione**: Funzioni helper per chiamate API

**Funzioni:**
- `apiCall(url, options)`: Chiamata API generica con error handling
- `handleApiError(error)`: Gestione errori standardizzata
- `getCsrfToken()`: Ottiene CSRF token
- `buildQueryString(params)`: Costruisce query string

**Uso**: Tutti i componenti Vue.js

#### **js/cache-utils.js** 💾 (100+ righe)
**Funzione**: Gestione cache lato client

**Funzioni:**
- `getCached(key, ttl)`: Ottiene dato cached
- `setCached(key, value, ttl)`: Salva dato cached
- `clearCache(pattern)`: Pulisce cache

**Uso**: Cache dati per performance (es: lista clienti)

#### **js/components/DataTable.js** 📊 (500+ righe)
**Funzione**: Componente Vue.js per tabelle dati

**Features:**
- Ordinamento colonne
- Filtri per colonna
- Paginazione
- Ricerca globale
- Selezione multipla
- Azioni per riga

**Props:**
- `data`: Array di oggetti
- `columns`: Configurazione colonne
- `actions`: Azioni per riga
- `filters`: Filtri disponibili

#### **js/components/ToastNotifications.js** 🔔 (200+ righe)
**Funzione**: Sistema notifiche toast

**Tipi:**
- Success (verde)
- Error (rosso)
- Warning (giallo)
- Info (blu)

**Features:**
- Auto-dismiss dopo timeout
- Stack multipli
- Animazioni

#### **js/components/LoadingOverlay.js** ⏳ (100+ righe)
**Funzione**: Overlay durante operazioni async

**Features:**
- Mostra/nascondi programmaticamente
- Messaggio personalizzabile
- Spinner animato

#### **js/components/AnimatedCounter.js** 🔢 (100+ righe)
**Funzione**: Contatore animato per numeri

**Features:**
- Animazione incrementale
- Formattazione numeri
- Suffissi (K, M, etc.)

#### **js/components/AutocompleteSelect.js** 🔍 (300+ righe)
**Funzione**: Select con autocomplete

**Features:**
- Ricerca in tempo reale
- Filtri custom
- Selezione multipla opzionale

#### **js/unified-scanner-display.js** 🔍 (400+ righe)
**Funzione**: Visualizzazione risultati unified scanner

**Features:**
- Tabs per protocollo (SSH/WMI/SNMP)
- Visualizzazione dati strutturati
- Highlight differenze tra scan

#### **css/vue-components.css** 🎨 (200+ righe)
**Funzione**: Stili custom per componenti Vue.js

**Classi:**
- `.vue-component`: Stili base
- `.data-table`: Stili tabella
- `.toast-*`: Stili notifiche
- `.loading-overlay`: Stili overlay

---

### 7. **dadude-agent/** - Agent Distribuito

#### **app/agent.py** 🤖 (650+ righe)
**Funzione**: Entry point agent principale

**Classe**: `DaDudeAgent`

**Componenti:**
- `AgentWebSocketClient`: Client WebSocket mTLS
- `CommandHandler`: Gestione comandi dal server
- `LocalQueue`: Coda locale persistente (SQLite)
- `QueueWorker`: Worker per processare coda
- `SFTPFallbackUploader`: Fallback SFTP quando server offline
- `SelfUpdater`: Auto-update agent
- `LocalScheduler`: Scheduler task locali
- `ConnectionManager`: Gestione stati connessione

**Lifecycle:**
- `start()`: Avvia agent
- `stop()`: Ferma agent graceful
- `_setup_logging()`: Configura logging
- `_setup_components()`: Inizializza componenti

#### **app/connection/ws_client.py** 🔌 (400+ righe)
**Funzione**: Client WebSocket mTLS

**Classe**: `AgentWebSocketClient`

**Features:**
- Auto-reconnect con backoff esponenziale
- Heartbeat periodico
- mTLS (mutual TLS) per autenticazione
- Gestione timeout

**Stati:**
- `Connecting`: In connessione
- `Connected`: Connesso
- `Disconnected`: Disconnesso
- `Reconnecting`: In riconnessione

#### **app/connection/state_machine.py** 🔄 (300+ righe)
**Funzione**: Macchina stati connessione

**Classe**: `ConnectionStateMachine`

**Stati:**
- `Idle`: Inattivo
- `Connecting`: In connessione
- `Connected`: Connesso
- `Disconnected`: Disconnesso
- `Error`: Errore

**Eventi:**
- `Connect`: Avvia connessione
- `Disconnect`: Disconnette
- `Error`: Gestisce errore
- `Reconnect`: Riconnette

#### **app/commands/handler.py** 📨 (1400+ righe)
**Funzione**: Gestisce comandi dal server

**Classe**: `CommandHandler`

**Comandi Supportati:**
- `scan`: Network scan
- `probe`: Probe dispositivo
- `exec`: Esegue comando shell
- `update`: Triggera update
- `unified_scan`: Unified scanner

**Dipendenze**: Tutti i probe/scanner

#### **app/probes/** 🔬 PROBE MODULARI

**ssh_probe.py** (300+ righe)
- Probe SSH generico
- Supporta password e chiave privata

**ssh_advanced_scanner.py** (500+ righe)
- Scanner SSH avanzato
- Collect dettagli sistema

**ssh_vendors/** (8 file)
- `base.py`: Classe base vendor
- `cisco.py`: Cisco specific
- `hp.py`: HP specific
- `linux.py`: Linux specific
- `mikrotik.py`: MikroTik specific
- `proxmox.py`: Proxmox specific
- `qnap.py`: QNAP specific
- `synology.py`: Synology specific
- `ubiquiti.py`: Ubiquiti specific

**wmi_probe.py** (200+ righe)
- Probe WMI Windows

**wmi_vendors/** (4 file)
- `base.py`: Classe base
- `windows_server.py`: Windows Server
- `windows_workstation.py`: Windows Workstation
- `hyperv.py`: Hyper-V

**snmp_probe.py** (200+ righe)
- Probe SNMP (v1, v2c, v3)

**unified_scanner.py** (600+ righe)
- Scanner unificato multi-protocollo
- Prova protocolli in sequenza
- Ritorna primo risultato valido

#### **app/scanners/** 🔍 SCANNER

**port_scanner.py** (200+ righe)
- Port scanner con nmap
- Supporta range porte

**dns_resolver.py** (100+ righe)
- DNS resolver
- Lookup forward/reverse

#### **app/storage/local_queue.py** 💾 (200+ righe)
**Funzione**: Coda persistente per offline mode

**Classe**: `LocalQueue`

**Storage**: SQLite locale

**Metodi:**
- `enqueue(message)`: Aggiunge messaggio
- `dequeue()`: Rimuove messaggio
- `size()`: Dimensione coda

#### **app/workers/queue_worker.py** 👷 (300+ righe)
**Funzione**: Processa coda locale

**Classe**: `QueueWorker`

**Features:**
- Retry con backoff
- Error handling
- Store-and-forward

#### **app/updater/self_update.py** 🔄 (200+ righe)
**Funzione**: Auto-update agent

**Classe**: `SelfUpdater`

**Metodo:**
- `update()`: Git pull + restart

#### **app/scheduler/local_scheduler.py** ⏰ (200+ righe)
**Funzione**: Scheduler task locali

**Classe**: `LocalScheduler`

**Features:**
- Task periodici
- Cron expressions

---

## 🔄 Mappa Interazioni Dettagliata

### 1. Flusso Registrazione Agent

```
┌─────────────┐                    ┌──────────────┐
│    Agent    │                    │ Server :8000 │
│   (Site)    │                    │              │
└──────┬──────┘                    └──────┬───────┘
       │                                   │
       │─── POST /agents/register ────────►│
       │    {agent_id, cert_request}       │
       │                                   │─── pki_service.generate_cert()
       │                                   │─── Salva in database
       │                                   │─── Stato: PENDING
       │◄─── 200 OK ──────────────────────│
       │    {certificate, server_cert}     │
       │                                   │
       │─── WebSocket Connect ────────────►│
       │    (mTLS handshake)               │
       │                                   │─── websocket_hub.connect()
       │                                   │─── Verifica certificato
       │                                   │─── Registra in _connections
       │◄─── Connected ────────────────────│
       │                                   │
       │─── Heartbeat (periodico) ────────►│
       │    {type: "heartbeat"}            │
       │                                   │
```

### 2. Flusso Scan Dispositivo

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ Admin UI     │    │ Agent API    │    │   Agent     │
│   :8001      │    │   :8000      │    │  (Site)     │
└──────┬───────┘    └──────┬───────┘    └──────┬──────┘
       │                   │                   │
       │─── POST /unified-scanner/scan ───────►│
       │    {target, protocols}                │
       │                   │                   │
       │                   │─── agent_service.get_agent_for_customer()
       │                   │─── websocket_hub.send_command() ────►│
       │                   │                   │─── command_handler.handle()
       │                   │                   │─── unified_scanner.scan()
       │                   │                   │    ├─ Try SSH
       │                   │                   │    ├─ Try WMI
       │                   │                   │    └─ Try SNMP
       │                   │◄─── {results} ────│
       │◄─── 200 OK ───────│                   │
       │    {scan_results}│                   │
       │                   │                   │
       │─── Salva in InventoryDevice ─────────│
```

### 3. Flusso Dashboard

```
┌──────────────┐                    ┌──────────────┐
│   Browser    │                    │ Admin UI     │
│              │                    │   :8001      │
└──────┬───────┘                    └──────┬───────┘
       │                                   │
       │─── GET /dashboard ───────────────►│
       │                                   │─── dashboard.get_dashboard_data()
       │                                   │    ├─ customer_service.list_customers()
       │                                   │    ├─ sync_service.devices
       │                                   │    ├─ alert_service.get_unacknowledged()
       │                                   │    ├─ InventoryDevice.query()
       │                                   │    └─ websocket_hub.connected_count()
       │◄─── HTML + Data ──────────────────│
       │    (dashboard.html + JSON)        │
       │                                   │
       │─── Vue.js mount ──────────────────│
       │─── Render components               │
       │    ├─ AnimatedCounter (statistiche)
       │    ├─ Chart.js (grafici)
       │    └─ Cards (dati)
```

### 4. Flusso Backup Dispositivo

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│Backup        │    │Device Backup │    │   Agent     │
│Scheduler     │    │  Service     │    │  (via WS)   │
└──────┬───────┘    └──────┬───────┘    └──────┬──────┘
       │                   │                   │
       │─── Trigger (cron) ─►│                   │
       │                   │─── Crea BackupJob │
       │                   │─── agent_service.get_agent()
       │                   │─── websocket_hub.send_command() ────►│
       │                   │                   │─── mikrotik_backup_collector
       │                   │                   │    o proxmox_backup_collector
       │                   │◄─── {backup_data} ─│
       │                   │─── Crea BackupVersion
       │                   │─── Versioning (incrementa)
       │                   │                   │
```

### 5. Flusso Multi-Tenant

```
Customer
  │
  ├─── Networks (1:N)
  │     │
  │     └─── Gateway Agent (N:1)
  │
  ├─── Credentials (1:N)
  │     │
  │     └─── Encryption (AES-256-GCM)
  │
  ├─── Device Assignments (1:N)
  │     │
  │     └─── Dude Device (N:1)
  │
  └─── Agent Assignments (1:N)
        │
        └─── Agent (N:1)
              │
              └─── WebSocket Connection
```

---

## 🎨 Interfaccia Grafica - Architettura Dettagliata

### Stack Tecnologico Completo

```
┌─────────────────────────────────────────────────────────┐
│              Browser (Client-Side)                       │
├─────────────────────────────────────────────────────────┤
│  HTML5 + CSS3                                           │
│  Bootstrap 5.3.2 (CSS Framework)                       │
│  Bootstrap Icons 1.11.1                                  │
│  Vue.js 3 (Production Build)                            │
│  Chart.js 4.4.0 (Grafici)                               │
│  Custom Vue Components                                   │
│  Custom CSS (vue-components.css)                        │
└─────────────────────────────────────────────────────────┘
                    │ HTTP/HTTPS
                    ▼
┌─────────────────────────────────────────────────────────┐
│           Admin UI Server (Port 8001)                    │
├─────────────────────────────────────────────────────────┤
│  FastAPI (Python)                                       │
│  Jinja2 Templates (Server-side rendering)              │
│  Static Files (CSS/JS serviti da FastAPI)              │
│  Auth Middleware (Basic Auth + Session)                 │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Services Layer                              │
│  customer_service, dude_service, sync_service, etc.    │
└─────────────────────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Database Layer                              │
│  PostgreSQL (produzione) / SQLite (sviluppo)            │
└─────────────────────────────────────────────────────────┘
```

### Componenti Vue.js Gerarchia

```
Vue App (app.js)
│
├── ToastNotifications (globale)
│   └── Mostra notifiche toast
│
├── LoadingOverlay (globale)
│   └── Overlay durante operazioni async
│
├── DataTable (riutilizzabile)
│   ├── Ordinamento colonne
│   ├── Filtri
│   ├── Paginazione
│   └── Azioni per riga
│
├── AnimatedCounter (riutilizzabile)
│   └── Contatore animato
│
└── AutocompleteSelect (riutilizzabile)
    └── Select con ricerca
```

### Flusso Rendering Pagina Completo

```
1. Browser richiede GET /dashboard
   │
   ▼
2. FastAPI router.dashboard() chiama get_dashboard_data()
   │
   ▼
3. get_dashboard_data() raccoglie dati:
   ├─ customer_service.list_customers()
   ├─ sync_service.devices (cache The Dude)
   ├─ alert_service.get_unacknowledged()
   ├─ InventoryDevice.query() (database)
   └─ websocket_hub.connected_count()
   │
   ▼
4. Template Jinja2 renderizza dashboard.html:
   ├─ Inietta dati nel template
   ├─ Genera HTML con dati embedded
   └─ Include script Vue.js
   │
   ▼
5. Browser riceve HTML + dati embedded
   │
   ▼
6. Browser esegue JavaScript:
   ├─ Carica Vue.js
   ├─ Carica componenti Vue.js
   └─ Vue.js si monta su #vue-app
   │
   ▼
7. Vue.js renderizza componenti:
   ├─ AnimatedCounter (statistiche)
   ├─ Chart.js (grafici)
   └─ Cards (dati)
   │
   ▼
8. Interazioni utente:
   ├─ Click → Event handler Vue.js
   ├─ Form submit → apiCall() → API endpoint
   └─ Risultato → Toast notification
```

### Template Inheritance

```
base.html (template base)
│
├── dashboard.html (extends base.html)
├── monitoring.html (extends base.html)
├── customers.html (extends base.html)
├── customer_detail.html (extends base.html)
├── agents.html (extends base.html)
├── devices.html (extends base.html)
├── settings.html (extends base.html)
└── ... (tutti gli altri template)
```

**base.html fornisce:**
- Sidebar navigazione
- Header con breadcrumb
- Footer
- Container Vue.js app
- Toast notifications container
- Loading overlay container
- CSS/JS globali

---

## 📊 Flussi Dati Principali

### 1. Multi-Tenant Data Flow

```
┌──────────┐
│ Customer │
└────┬─────┘
     │
     ├──────────┐
     │          │
     ▼          ▼
┌─────────┐ ┌──────────────┐
│ Network │ │ Credential   │
└────┬────┘ └──────┬───────┘
     │             │
     │             └───► Device Assignment
     │
     └───► Agent Assignment
              │
              ▼
         WebSocket Connection
```

### 2. Agent Communication Flow

```
┌─────────────────────┐
│ WebSocket Hub       │
│ (Singleton)         │
└──────┬──────────────┘
       │
       ├───► Agent 1 (Site A) ────► Customer A Networks
       ├───► Agent 2 (Site B) ────► Customer B Networks
       └───► Agent 3 (Site C) ────► Customer C Networks
```

### 3. Inventory Data Flow

```
Agent Scan
    │
    ▼
Unified Scanner Service
    │
    ├───► Try SSH ────► SSH Probe ────► Results
    ├───► Try WMI ────► WMI Probe ────► Results
    └───► Try SNMP ───► SNMP Probe ───► Results
    │
    ▼
Probe Results
    │
    ▼
InventoryDevice (Database)
    │
    ├───► Network Interfaces
    ├───► MikroTik Details
    ├───► Linux Details
    ├───► Windows Details
    └───► Proxmox Details
```

### 4. Backup Data Flow

```
Backup Scheduler (Cron)
    │
    ▼
Device Backup Service
    │
    ├───► Crea BackupJob
    ├───► Seleziona Agent
    └───► Esegue Backup (via WebSocket)
         │
         ▼
    Backup Collector
    ├───► MikroTik Backup Collector
    └───► Proxmox Backup Collector
         │
         ▼
    Backup Data
         │
         ▼
    BackupVersion (Database)
    ├───► Version 1
    ├───► Version 2
    └───► Version N (versioning automatico)
```

---

## 🔐 Sicurezza

### Autenticazione

**Admin UI (Porta 8001):**
- Basic Auth + Session management
- Middleware `AuthMiddleware`
- Session cookie sicuro

**Agent API (Porta 8000):**
- mTLS (mutual TLS)
- Certificati generati da `pki_service`
- Verifica certificato server ↔ agent

**Credenziali:**
- AES-256-GCM encryption
- Chiave master in `ENCRYPTION_KEY`
- Decriptazione on-demand

### Separazione Porte

**Porta 8000 (Agent API):**
- Solo endpoint agent
- WebSocket Hub attivo
- Esposta su Internet
- Nessuna autenticazione HTTP (solo mTLS)

**Porta 8001 (Admin UI):**
- Dashboard web
- Management API
- Solo rete interna
- Basic Auth richiesto

---

## 📈 Metriche e Monitoring

### Health Checks

**`/health`** (entrambe le porte):
- Stato base servizio
- Connessione The Dude
- Cache sync service

**`/api/v1/system/health`** (Admin UI):
- Health check dettagliato
- Database connectivity
- WebSocket Hub status
- Agent connessi

### Logging

**Server:**
- Libreria: Loguru
- File: `./logs/dadude.log`
- Rotation: 10 MB, retention 7 giorni
- Compression: gzip

**Agent:**
- Libreria: Loguru
- File: `/var/lib/dadude-agent/logs/agent.log`
- Rotation: 10 MB, retention 7 giorni

**Livelli:**
- DEBUG: Dettagli operazioni
- INFO: Operazioni normali
- WARNING: Situazioni anomale
- ERROR: Errori

---

## 🚀 Deployment

### Container Docker

**Dockerfile.dual:**
- Base: Python 3.11-slim
- Dipendenze: requirements.txt
- Porte: 8000, 8001
- CMD: `python -m app.run_dual`

**docker-compose-dual.yml:**
- Servizio: dadude
- Volumi: data, logs, app code
- Network: dadude_network
- Healthcheck: Entrambe le porte

**docker-compose-postgres.yml:**
- Servizio: postgres (PostgreSQL 16)
- Servizio: dadude (connesso a postgres)
- Volumi: postgres_data, dadude_data

### Script Deployment

**Server:**
- `deploy/docker/install-server.sh`: Installazione Docker standalone
- `deploy/proxmox/install-server.sh`: Installazione Proxmox LXC
- `update.sh`: Aggiornamento server

**Agent:**
- `deploy/docker/install-agent.sh`: Installazione Docker
- `deploy/proxmox/install.sh`: Installazione Proxmox LXC
- `update.sh`: Aggiornamento agent

**Multi-Agent:**
- `update-agents.sh`: Aggiornamento agent multipli
- `update-agent-proxmox.sh`: Aggiornamento agent Proxmox
- `restart-all-agents.sh`: Riavvio tutti gli agent

---

## 📝 Note Finali

### Versioni

- **Server**: 3.0.0
- **Agent**: 3.0.0

### Database Supportati

- **PostgreSQL**: Produzione (raccomandato)
- **SQLite**: Sviluppo/test

### Protocolli Supportati

- **SSH**: Linux, Cisco, HP, MikroTik, Ubiquiti, Proxmox, QNAP, Synology
- **WMI**: Windows Server, Workstation, Hyper-V
- **SNMP**: v1, v2c, v3
- **RouterOS API**: The Dude Server

### Architettura

- **Pattern**: Multi-tenant MSP/MSSP
- **Comunicazione**: WebSocket bidirezionale mTLS
- **Separazione**: Dual-port per sicurezza
- **Scalabilità**: Agent distribuiti, server centralizzato

---

## 📚 File di Documentazione

### Documentazione Principale

- `README.md`: Guida principale progetto
- `CHANGELOG.md`: Storico modifiche
- `OPERATIONS.md`: Operazioni comuni
- `PROJECT_MAP.md`: Questo documento

### Guide Deployment

- `DEPLOY_TO_DOCKER.md`: Deploy Docker
- `DEPLOY_LXC_PROXMOX.md`: Deploy Proxmox LXC
- `MIGRATION_DUAL_PORT.md`: Migrazione dual-port
- `MIGRATE_CONTAINER_600.md`: Migrazione container 600

### Guide Moduli

- `DEVICE_BACKUP_MODULE.md`: Modulo backup dispositivi
- `BACKUP_MODULE_README.md`: README backup
- `SSH_ADVANCED_SCANNER.md`: Scanner SSH avanzato
- `INTEGRATION_GUIDE.md`: Guida integrazione

### Fix e Compatibility

- `FIX_COMPATIBILITY.md`: Fix compatibilità
- `SNMP_PUBLIC_FALLBACK_FIX.md`: Fix SNMP
- `UNIFI_SSH_FALLBACK_FIX.md`: Fix UniFi SSH
- `MIKROTIK_INTERFACES_INVENTORY_FIX.md`: Fix MikroTik
- `MIKROTIK_LLDP_VISUALIZATION_FIX.md`: Fix LLDP

---

**Documento generato il 2025-01-07**  
**Versione Progetto: 3.0.0**  
**Autore: Analisi Automatica Codebase**
