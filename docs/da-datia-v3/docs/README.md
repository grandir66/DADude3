# DaDude - Documentazione

**Versione**: 3.0.0  
**Ultimo aggiornamento**: 2026-01-07

Questa directory contiene tutta la documentazione del progetto DaDude Inventory System, organizzata per categoria.

---

## 📚 Struttura Documentazione

```
docs/
├── README.md                    # Questo file - Indice documentazione
├── PROJECT_MAP.md              # Mappa completa progetto (root)
├── OPERATIONS.md               # Guida operativa (root)
├── guides/                     # Guide e tutorial
│   ├── FIXES.md               # Fix applicati (consolidato)
│   ├── INTEGRATION_GUIDE.md   # Guida integrazione moduli
│   ├── BACKUP_MODULE_README.md # Modulo backup dispositivi
│   ├── DEVICE_BACKUP_MODULE.md # Documentazione backup
│   └── SSH_ADVANCED_SCANNER.md # Scanner SSH avanzato
├── deployment/                 # Guide deployment
│   ├── MIGRATION_DUAL_PORT.md # Migrazione dual-port
│   ├── DUAL_PORT_SUMMARY.md   # Riepilogo dual-port
│   ├── MIGRATE_CONTAINER_600.md # Migrazione container 600
│   ├── DEPLOY_TO_DOCKER.md    # Deploy Docker
│   ├── DEPLOY_LXC_PROXMOX.md  # Deploy Proxmox LXC
│   ├── DEPLOY_192.168.4.45.md # Deploy specifico server
│   ├── INSTALL_POSTGRES.md    # Installazione PostgreSQL
│   └── MIKROTIK_CONTAINER_SETUP.md # Installazione su MikroTik RouterOS
└── archive/                    # Documenti storici/obsoleti
    ├── INTEGRATION_COMPLETE.md
    ├── READY_FOR_DEPLOYMENT.md
    ├── FINAL_INTEGRATION_SUMMARY.md
    ├── INTEGRATION_COMPLETED.md
    ├── VENDOR_SCAN_CODE_INTEGRATION.md
    ├── FIX_COMPATIBILITY.md
    ├── SNMP_PUBLIC_FALLBACK_FIX.md
    ├── UNIFI_SSH_FALLBACK_FIX.md
    ├── MIKROTIK_INTERFACES_INVENTORY_FIX.md
    ├── MIKROTIK_LLDP_VISUALIZATION_FIX.md
    ├── UNIFI_CLI_ADVANCED_SUPPORT.md
    ├── DEPLOY_STATUS.md
    └── AGENT_UPDATE_COMMANDS.md
```

---

## 📖 Documentazione Principale

### Root Directory

- **`PROJECT_MAP.md`**: Mappa completa del progetto con architettura, componenti, interazioni
- **`OPERATIONS.md`**: Guida operativa per gestione quotidiana del sistema
- **`README.md`**: Guida principale installazione e configurazione

### Guide (`guides/`)

- **`FIXES.md`**: Tutti i fix applicati al sistema (consolidato)
- **`INTEGRATION_GUIDE.md`**: Come integrare nuovi moduli nel sistema
- **`BACKUP_MODULE_README.md`**: Documentazione modulo backup dispositivi
- **`DEVICE_BACKUP_MODULE.md`**: Guida completa backup dispositivi
- **`SSH_ADVANCED_SCANNER.md`**: Documentazione scanner SSH avanzato

### Deployment (`deployment/`)

- **`MIGRATION_DUAL_PORT.md`**: Guida migrazione a configurazione dual-port
- **`DUAL_PORT_SUMMARY.md`**: Riepilogo implementazione dual-port
- **`MIGRATE_CONTAINER_600.md`**: Migrazione container 600 (SQLite → PostgreSQL)
- **`DEPLOY_TO_DOCKER.md`**: Deploy su Docker standalone
- **`DEPLOY_LXC_PROXMOX.md`**: Deploy su Proxmox LXC
- **`DEPLOY_192.168.4.45.md`**: Deploy su server specifico
- **`INSTALL_POSTGRES.md`**: Installazione e configurazione PostgreSQL
- **`MIKROTIK_CONTAINER_SETUP.md`**: Installazione agent su MikroTik RouterOS 7.x

### Archive (`archive/`)

Documenti storici mantenuti per riferimento ma non più attivi:
- Documenti di integrazione completati
- Fix applicati (ora consolidati in `guides/FIXES.md`)
- Status deploy storici

---

## 🚀 Quick Start

### Per Sviluppatori

1. Leggi **`PROJECT_MAP.md`** per capire l'architettura
2. Consulta **`guides/INTEGRATION_GUIDE.md`** per integrare nuovi moduli
3. Vedi **`guides/FIXES.md`** per fix applicati

### Per Operatori

1. Leggi **`OPERATIONS.md`** per operazioni quotidiane
2. Consulta **`deployment/`** per deploy e migrazioni
3. Vedi **`guides/FIXES.md`** per troubleshooting

### Per Deployment

1. Scegli la guida appropriata in **`deployment/`**
2. Segui la procedura step-by-step
3. Verifica con i comandi in **`OPERATIONS.md`**

---

## 📝 Convenzioni Documentazione

### Versioni

Tutti i documenti indicano la versione del sistema a cui si riferiscono:
- **v3.0.0**: Versione corrente (dual-port, unified scanner)

### Riferimenti File

I riferimenti ai file usano sempre:
- `app/main_dual.py` (non `main.py`)
- `docker-compose-dual.yml` (non `docker-compose.yml`)
- `Dockerfile.dual` (non `Dockerfile`)

### Comandi

I comandi Docker usano sempre:
- `docker compose -f docker-compose-dual.yml` per il server
- `docker compose` per gli agent

---

## 🔄 Aggiornamenti Documentazione

Quando si aggiunge/modifica documentazione:

1. **Nuove funzionalità**: Aggiungi a `CHANGELOG.md`
2. **Fix**: Aggiungi a `guides/FIXES.md`
3. **Deploy**: Aggiungi guida in `deployment/`
4. **Guide**: Aggiungi in `guides/`
5. **Storico**: Sposta in `archive/` quando non più attivo

---

## 📞 Supporto

Per problemi o domande:
1. Consulta **`OPERATIONS.md`** per troubleshooting
2. Vedi **`guides/FIXES.md`** per fix noti
3. Controlla i log del sistema
4. Apri una issue su GitHub

---

**Ultimo aggiornamento**: 2026-01-07
