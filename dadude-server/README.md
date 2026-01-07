# DaDude - The Dude MikroTik Connector

![Version](https://img.shields.io/badge/version-1.1.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

**DaDude** è un connector multi-tenant che espone i dati di monitoraggio di **The Dude** (MikroTik) tramite API REST, ideale per **MSP/MSSP** che gestiscono più clienti.

## 🚀 Funzionalità

- 📡 **Dispositivi**: Lista e stato di tutti i dispositivi monitorati
- 🔍 **Probe/Sonde**: Metriche e valori delle sonde configurate  
- 🚨 **Alert**: Notifiche e allarmi in tempo reale
- 🔄 **Webhook bidirezionale**: Ricevi e inoltra notifiche
- 👥 **Multi-Tenant**: Gestione clienti con configurazioni dedicate
- 🌐 **Reti Sovrapposte**: Supporto reti IP/VLAN indipendenti per cliente
- 🔐 **Credenziali Segregate**: Credenziali per device specifici o di default
- 📊 **API REST**: Integrazione semplice con qualsiasi applicazione
- 🐳 **Docker ready**: Deploy semplice con Docker Compose

## 📋 Requisiti

- **The Dude** in esecuzione su RouterOS/CHR (con API abilitata)
- Python 3.11+ (per sviluppo locale)
- Docker + Docker Compose (per deploy)

## ⚡ Quick Start

### 1. Configurazione

```bash
cd /path/to/dadude
cp .env.example .env
nano .env  # Configura connessione Dude
```

### 2. Avvio

```bash
# Con Docker (dual-port)
docker compose -f docker-compose-dual.yml up -d

# Oppure locale
python -m app.run_dual
```

### 3. Accedi

- **API Docs**: http://localhost:8000/docs
- **Health**: http://localhost:8000/health

## 👥 Gestione Multi-Tenant

### Concetti Chiave

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENTE                               │
│  (codice: ACME001, nome: Acme Corp)                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   RETI      │  │ CREDENZIALI │  │   DEVICE    │         │
│  │             │  │             │  │             │         │
│  │ LAN Uffici  │  │ Router Admin│  │ Router-01   │         │
│  │ 192.168.1.0 │  │ user: admin │  │ role: router│         │
│  │ VLAN: 100   │  │ pwd: ****   │  │             │         │
│  │             │  │             │  │ Switch-01   │         │
│  │ DMZ         │  │ SNMP Default│  │ role: switch│         │
│  │ 10.0.0.0/24 │  │ v2c: public │  │             │         │
│  │ VLAN: 200   │  │             │  │ FW-01       │         │
│  └─────────────┘  └─────────────┘  │ role: fw    │         │
│                                     └─────────────┘         │
└─────────────────────────────────────────────────────────────┘
```

### Reti Sovrapposte

Ogni cliente può avere le proprie reti, anche con IP sovrapposti:

```
Cliente A: 192.168.1.0/24 (VLAN 100) - LAN Uffici
Cliente B: 192.168.1.0/24 (VLAN 100) - LAN Sede    ← Stesso range, clienti diversi!
Cliente C: 192.168.1.0/24 (VLAN 200) - Produzione
```

### Credenziali

- **Default**: Usate per tutti i device del cliente senza credenziali specifiche
- **Specifiche**: Assegnate a singoli device o tramite pattern (`router-*`, `*-fw`)
- **Tipi**: device, SNMP, API, VPN, SSH

## 📡 API Endpoints

### Clienti (`/api/v1/customers`)

| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/customers` | Lista clienti |
| POST | `/customers` | Crea cliente |
| GET | `/customers/{id}` | Dettaglio cliente |
| GET | `/customers/code/{code}` | Cliente per codice |
| PUT | `/customers/{id}` | Aggiorna cliente |
| DELETE | `/customers/{id}` | Disattiva cliente |
| GET | `/customers/{id}/summary` | Riepilogo completo |

### Reti (`/api/v1/customers/{id}/networks`)

| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/customers/{id}/networks` | Lista reti cliente |
| POST | `/customers/{id}/networks` | Crea rete |
| PUT | `/customers/networks/{net_id}` | Aggiorna rete |
| DELETE | `/customers/networks/{net_id}` | Elimina rete |

### Credenziali (`/api/v1/customers/{id}/credentials`)

| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/customers/{id}/credentials` | Lista credenziali (safe) |
| POST | `/customers/{id}/credentials` | Crea credenziali |
| GET | `/customers/credentials/{cred_id}` | Dettaglio credenziali |

### Device Assignment (`/api/v1/customers/{id}/devices`)

| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/customers/{id}/devices` | Device assegnati al cliente |
| POST | `/customers/{id}/devices` | Assegna device a cliente |
| GET | `/customers/devices/{dude_id}` | Assegnazione device |
| PUT | `/customers/devices/{dude_id}` | Aggiorna assegnazione |
| DELETE | `/customers/devices/{dude_id}` | Rimuovi assegnazione |

### Dispositivi Dude (`/api/v1/devices`)

| Metodo | Endpoint | Descrizione |
|--------|----------|-------------|
| GET | `/devices` | Lista tutti i dispositivi |
| GET | `/devices/summary` | Riepilogo stati |
| GET | `/devices/{id}` | Dettaglio dispositivo |
| GET | `/devices/{id}/probes` | Probe del dispositivo |

## 💡 Esempi di Utilizzo

### Creare un cliente con reti e credenziali

```python
import requests

API = "http://localhost:8000/api/v1"

# 1. Crea cliente
customer = requests.post(f"{API}/customers", json={
    "code": "ACME001",
    "name": "Acme Corporation",
    "contact_email": "it@acme.com"
}).json()

customer_id = customer["id"]

# 2. Aggiungi reti
requests.post(f"{API}/customers/{customer_id}/networks", json={
    "name": "LAN Uffici",
    "network_type": "lan",
    "ip_network": "192.168.1.0/24",
    "gateway": "192.168.1.1",
    "vlan_id": 100,
    "dns_primary": "8.8.8.8"
})

requests.post(f"{API}/customers/{customer_id}/networks", json={
    "name": "DMZ",
    "network_type": "dmz", 
    "ip_network": "10.0.0.0/24",
    "vlan_id": 200
})

# 3. Aggiungi credenziali di default
requests.post(f"{API}/customers/{customer_id}/credentials", json={
    "name": "Router Admin Default",
    "credential_type": "device",
    "username": "admin",
    "password": "secret123",
    "is_default": True
})

# 4. Credenziali specifiche per firewall
requests.post(f"{API}/customers/{customer_id}/credentials", json={
    "name": "Firewall Admin",
    "credential_type": "device",
    "username": "admin",
    "password": "fw-secret",
    "device_filter": "*-fw"  # Match tutti i device che finiscono con -fw
})

# 5. Assegna device dal Dude
requests.post(f"{API}/customers/{customer_id}/devices", json={
    "dude_device_id": "*1",  # ID dal Dude
    "dude_device_name": "Router-Main",
    "role": "router",
    "location": "Sede Centrale",
    "contract_type": "premium",
    "sla_level": "gold"
})
```

### Query device per cliente

```python
# Tutti i device di un cliente
devices = requests.get(f"{API}/customers/{customer_id}/devices").json()

# Solo router
routers = requests.get(
    f"{API}/customers/{customer_id}/devices",
    params={"role": "router"}
).json()

# Riepilogo completo cliente
summary = requests.get(f"{API}/customers/{customer_id}/summary").json()
print(f"Cliente: {summary['customer']['name']}")
print(f"Reti: {summary['summary']['networks']}")
print(f"Device: {summary['summary']['devices']}")
```

## 🏗️ Architettura

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Device Remoti  │────▶│   Dude Server    │────▶│    DaDude       │
│  (per cliente)  │     │   (RouterOS)     │     │    (FastAPI)    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                                        │
                              ┌──────────────────────────┤
                              │                          │
                              ▼                          ▼
                        ┌──────────┐            ┌──────────────┐
                        │ SQLite   │            │  Tua App     │
                        │ Database │            │  (Client)    │
                        │          │            │              │
                        │ - Clienti│            │ Per-cliente: │
                        │ - Reti   │            │ - Dashboard  │
                        │ - Creds  │            │ - Report     │
                        │ - Assign │            │ - Alerting   │
                        └──────────┘            └──────────────┘
```

## 📁 Struttura Progetto

```
dadude/
├── app/
│   ├── main_dual.py              # Entry point FastAPI (dual-port)
│   ├── run_dual.py               # Runner per dual-port
│   ├── config.py                 # Configurazione
│   ├── models/
│   │   ├── schemas.py            # Modelli Dude (Device, Probe)
│   │   ├── customer_schemas.py   # Modelli Multi-Tenant
│   │   └── database.py           # SQLAlchemy Models
│   ├── routers/
│   │   ├── devices.py            # API dispositivi Dude
│   │   ├── probes.py             # API probe
│   │   ├── alerts.py             # API alert
│   │   ├── webhook.py            # Webhook in/out
│   │   ├── system.py             # Sistema
│   │   └── customers.py          # API Multi-Tenant
│   └── services/
│       ├── dude_service.py       # Connessione Dude
│       ├── sync_service.py       # Polling
│       ├── alert_service.py       # Alert
│       ├── webhook_service.py    # Webhook
│       └── customer_service.py   # Gestione Clienti
├── data/                         # Database SQLite/PostgreSQL
├── logs/
├── docker-compose-dual.yml        # Configurazione Docker (dual-port)
├── docker-compose-postgres.yml   # Configurazione con PostgreSQL
├── Dockerfile.dual               # Dockerfile per dual-port
├── requirements.txt
└── README.md
```

## 🔧 Configurazione Avanzata

### Variabili Environment

```env
# Dude Server
DUDE_HOST=192.168.1.1
DUDE_API_PORT=8728
DUDE_USERNAME=admin
DUDE_PASSWORD=secret

# DaDude
DADUDE_PORT=8000
DADUDE_API_KEY=my-secret-key

# Database (default: SQLite locale)
DATABASE_URL=sqlite:///./data/dadude.db

# Polling
POLL_INTERVAL=60
FULL_SYNC_INTERVAL=300

# Webhook esterno (opzionale)
WEBHOOK_URL=https://hooks.slack.com/xxx
```

## 🛠️ Sviluppo

```bash
# Setup
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run con hot-reload (dual-port)
python -m app.run_dual

# Oppure manualmente:
uvicorn app.main_dual:agent_app --reload --port 8000 &
uvicorn app.main_dual:admin_app --reload --port 8001

# Test
pytest tests/
```

## 📝 License

MIT License - Domarc Srl

## 🤝 Supporto

Per supporto: [Domarc Srl](https://www.domarc.it)
