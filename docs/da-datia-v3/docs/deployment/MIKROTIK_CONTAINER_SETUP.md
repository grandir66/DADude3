# DaDude Agent - Installazione su MikroTik RouterOS

**Versione**: 3.0.0  
**Modalità**: WebSocket mTLS (agent-initiated)  
**Ultimo aggiornamento**: 2026-01-07

---

## 📋 Panoramica

Questa guida spiega come installare il DaDude Agent su un router MikroTik RouterOS 7.x utilizzando il supporto Container nativo.

### Architettura

```
┌─────────────────────────────────────────────────────────┐
│              MikroTik RouterOS 7.x                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │         Container Support (Docker)                  │  │
│  │  ┌─────────────────────────────────────────────┐  │  │
│  │  │         DaDude Agent Container               │  │  │
│  │  │                                             │  │  │
│  │  │  • WebSocket Client (mTLS)                 │  │  │
│  │  │  • Unified Scanner (SSH/SNMP/WMI)          │  │  │
│  │  │  • Port Scanner                            │  │  │
│  │  │  • Local Queue (offline mode)              │  │  │
│  │  │  • Self-Update                            │  │  │
│  │  └─────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────┘  │
│                          │                                │
│                    WebSocket (mTLS)                       │
└──────────────────────────┼────────────────────────────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  DaDude Server       │
                │  (Porta 8000)        │
                └──────────────────────┘
```

---

## ✅ Requisiti

### Hardware MikroTik

- **RouterOS**: 7.x o superiore
- **RAM**: Minimo 256MB liberi (consigliati 512MB)
- **Storage**: Minimo 100MB liberi per immagine Docker
- **Container Support**: Abilitato

### Software

- **Container Support**: RouterOS deve supportare container Docker
- **Connessione Internet**: Per scaricare immagine Docker da GitHub Container Registry

---

## 🚀 Installazione

### Metodo 1: Script Automatico (CONSIGLIATO)

#### Step 1: Prepara le Variabili d'Ambiente

Prima di eseguire lo script, configura le variabili d'ambiente sul router:

```routeros
# URL Server DaDude (porta 8000 per Agent API)
/container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://dadude.domarc.it:8000

# ID univoco agent (es: agent-router-milano-01)
/container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-NOME-ROUTER

# Nome descrittivo agent
/container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=NOME-ROUTER

# Token di autenticazione (generato dal server o scelto manualmente)
/container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=TOKEN-SICURO-32-CARATTERI

# Modalità connessione (WebSocket)
/container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket

# Server DNS per reverse lookup (opzionale)
/container/envs/add list=dadude-env key=DADUDE_DNS_SERVERS value=8.8.8.8,192.168.4.1
```

**Nota**: Il token può essere generato dal server DaDude o creato manualmente (minimo 32 caratteri).

#### Step 2: Abilita Container Support

```routeros
/system/device-mode/update container=yes
```

**IMPORTANTE**: Riavvia il router dopo questo comando!

#### Step 3: Esegui Script di Installazione

Copia il contenuto del file `mikrotik-install.rsc` e incollalo nella console RouterOS, oppure caricalo via FTP/SCP e eseguilo:

```routeros
/system/script/run source=[/file get mikrotik-install.rsc contents]
```

Lo script eseguirà automaticamente:
1. Verifica variabili d'ambiente
2. Pulizia container precedenti (mantiene env vars)
3. Configurazione rete (VETH, bridge, NAT)
4. Preparazione storage
5. Download e avvio container

#### Step 4: Verifica Installazione

```routeros
# Controlla stato container
/container/print

# Controlla log
/container/log print

# Se status=stopped, avvia manualmente
/container/start 0
```

---

### Metodo 2: Installazione Manuale

#### Step 1: Abilita Container Support

```routeros
/system/device-mode/update container=yes
```

Riavvia il router.

#### Step 2: Configura Variabili d'Ambiente

```routeros
# Crea lista env vars
/container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://dadude.domarc.it:8000
/container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-router-001
/container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=Router-Milano
/container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=IL-TUO-TOKEN-SICURO
/container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket
/container/envs/add list=dadude-env key=DADUDE_DNS_SERVERS value=8.8.8.8,192.168.4.1
```

#### Step 3: Configura Rete

```routeros
# Crea VETH interface per container
/interface/veth/add name=veth-dadude address=172.17.0.2/24 gateway=172.17.0.1

# Crea bridge per container
/interface/bridge/add name=br-dadude

# Aggiungi VETH al bridge
/interface/bridge/port/add bridge=br-dadude interface=veth-dadude

# Configura IP sul bridge
/ip/address/add address=172.17.0.1/24 interface=br-dadude comment="dadude"

# Configura NAT per container
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 comment="dadude"
```

#### Step 4: Prepara Storage

```routeros
# Crea directory per container
/file/make-directory name="usb1/container-tmp"
/file/make-directory name="usb1/dadude-agent"

# Configura registry Docker
/container/config/set tmpdir=usb1/container-tmp registry-url=https://ghcr.io
```

#### Step 5: Crea e Avvia Container

```routeros
/container/add \
    remote-image=ghcr.io/grandir66/dadude-agent-mikrotik:latest \
    interface=veth-dadude \
    root-dir=usb1/dadude-agent \
    envlist=dadude-env \
    dns=8.8.8.8 \
    start-on-boot=yes \
    logging=yes
```

#### Step 6: Verifica

```routeros
# Controlla stato
/container/print

# Se status=stopped, avvia
/container/start 0

# Controlla log
/container/log print
```

---

## 🔧 Configurazione

### Variabili d'Ambiente

| Variabile | Descrizione | Esempio | Obbligatorio |
|-----------|-------------|---------|--------------|
| `DADUDE_SERVER_URL` | URL server DaDude (porta 8000) | `http://dadude.domarc.it:8000` | ✅ Sì |
| `DADUDE_AGENT_ID` | ID univoco agent | `agent-router-milano-01` | ✅ Sì |
| `DADUDE_AGENT_NAME` | Nome descrittivo | `Router Milano` | ✅ Sì |
| `DADUDE_AGENT_TOKEN` | Token autenticazione | `abc123...` (32+ caratteri) | ✅ Sì |
| `DADUDE_CONNECTION_MODE` | Modalità connessione | `websocket` | ✅ Sì |
| `DADUDE_DNS_SERVERS` | Server DNS (comma-separated) | `8.8.8.8,192.168.4.1` | ❌ No |

### Modifica Variabili d'Ambiente

```routeros
# Rimuovi env var esistente
/container/envs/remove [find key=DADUDE_SERVER_URL]

# Aggiungi nuova env var
/container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://nuovo-server:8000

# Riavvia container per applicare modifiche
/container/stop 0
/container/start 0
```

---

## 🔐 Registrazione Agent sul Server

Dopo l'installazione, devi registrare l'agent sul server DaDude:

### Metodo 1: Auto-Registrazione (CONSIGLIATO)

1. L'agent si connetterà automaticamente al server via WebSocket
2. Vai su `http://server:8001/agents` (Admin UI)
3. L'agent apparirà nella lista con stato "Pending"
4. Clicca "Approva" e assegna a un cliente
5. L'agent si riconnetterà automaticamente

### Metodo 2: Registrazione Manuale

1. Vai su `http://server:8001/agents`
2. Clicca "Nuovo Agent"
3. Compila:
   - **ID**: Stesso di `DADUDE_AGENT_ID`
   - **Nome**: Stesso di `DADUDE_AGENT_NAME`
   - **Token**: Stesso di `DADUDE_AGENT_TOKEN`
   - **Cliente**: Seleziona cliente
4. Clicca "Crea"
5. L'agent si connetterà automaticamente

---

## 📊 Monitoraggio

### Verifica Stato Container

```routeros
# Stato container
/container/print

# Log container
/container/log print

# Log ultimi 50 righe
/container/log print count=50
```

### Verifica Connessione WebSocket

```routeros
# Controlla log per messaggi di connessione
/container/log print | find "WebSocket\|Connected\|Connection"
```

Messaggi attesi:
- `WebSocket connected to ws://...`
- `Agent registered successfully`
- `Heartbeat sent`

### Verifica dal Server

1. Vai su `http://server:8001/agents`
2. Cerca l'agent per ID o nome
3. Verifica stato:
   - **Connected**: ✅ Connesso e operativo
   - **Disconnected**: ❌ Non connesso (controlla log)
   - **Pending**: ⏳ In attesa di approvazione

---

## 🔄 Aggiornamento

### Aggiornamento Automatico

L'agent supporta auto-update. Quando il server rileva una nuova versione:

1. Il server invia comando `update` via WebSocket
2. L'agent scarica nuova immagine
3. L'agent si riavvia automaticamente

### Aggiornamento Manuale

```routeros
# Ferma container
/container/stop 0

# Rimuovi container (mantiene env vars)
/container/remove 0

# Ricrea container (scarica nuova immagine)
/container/add \
    remote-image=ghcr.io/grandir66/dadude-agent-mikrotik:latest \
    interface=veth-dadude \
    root-dir=usb1/dadude-agent \
    envlist=dadude-env \
    dns=8.8.8.8 \
    start-on-boot=yes \
    logging=yes

# Avvia
/container/start 0
```

---

## 🐛 Troubleshooting

### Container Non Si Avvia

**Problema**: Container status = `stopped`

**Soluzione**:
```routeros
# Controlla log errori
/container/log print

# Verifica env vars
/container/envs/print

# Verifica storage disponibile
/file/print

# Riavvia manualmente
/container/start 0
```

### Agent Non Si Connette

**Problema**: Container avviato ma agent non connesso

**Soluzione**:
1. Verifica `DADUDE_SERVER_URL` corretto (porta 8000)
2. Verifica connettività:
   ```routeros
   /ping server-ip count=3
   ```
3. Verifica log:
   ```routeros
   /container/log print | find "Error\|Failed\|Connection"
   ```
4. Verifica token corretto sul server

### Errore "Env vars mancanti"

**Problema**: Script installazione fallisce con errore env vars

**Soluzione**:
```routeros
# Verifica env vars configurate
/container/envs/print

# Se vuote, configura manualmente (vedi Step 1 Metodo 1)
```

### Errore Download Immagine

**Problema**: Container non scarica immagine da registry

**Soluzione**:
1. Verifica connettività internet:
   ```routeros
   /ping 8.8.8.8 count=3
   ```
2. Verifica registry configurato:
   ```routeros
   /container/config/print
   ```
3. Verifica storage disponibile:
   ```routeros
   /file/print
   ```

### Container Consuma Troppa RAM

**Problema**: Router lento dopo installazione agent

**Soluzione**:
1. Limita RAM container (RouterOS 7.8+):
   ```routeros
   /container/set 0 memory-limit=256M
   ```
2. Riavvia container:
   ```routeros
   /container/stop 0
   /container/start 0
   ```

---

## 📝 Note Importanti

### Porte Utilizzate

- **Porta 8000**: Connessione WebSocket al server (outbound)
- **Nessuna porta in ascolto**: L'agent non apre porte sul router (agent-initiated)

### Sicurezza

- **mTLS**: Connessione WebSocket usa mutual TLS per autenticazione
- **Token**: Token salvato solo in memoria container (non su disco)
- **NAT**: Container usa NAT per connettersi al server (non richiede port forwarding)

### Performance

- **RAM**: ~100-200MB in uso normale
- **CPU**: Bassa (solo durante scansioni)
- **Storage**: ~100MB per immagine Docker

### Limitazioni MikroTik

- **RouterOS 7.x**: Richiesto per supporto container
- **Storage**: Deve essere su USB o disco (non solo RAM)
- **RAM**: Minimo 256MB liberi

---

## 🔗 Riferimenti

- **Script Installazione**: `dadude-agent/mikrotik-install.rsc`
- **Dockerfile MikroTik**: `dadude-agent/Dockerfile.mikrotik`
- **Documentazione Agent**: `dadude-agent/README.md`
- **Troubleshooting**: `docs/deployment/TROUBLESHOOTING-AGENT-CONNECTION.md`

---

## ✅ Checklist Installazione

- [ ] RouterOS 7.x installato
- [ ] Container support abilitato
- [ ] Router riavviato dopo abilitazione container
- [ ] Variabili d'ambiente configurate
- [ ] Storage preparato (USB/disco)
- [ ] Container creato e avviato
- [ ] Log verificati (nessun errore)
- [ ] Agent registrato sul server
- [ ] Connessione WebSocket verificata
- [ ] Test scansione eseguito

---

**Ultimo aggiornamento**: 2026-01-07
