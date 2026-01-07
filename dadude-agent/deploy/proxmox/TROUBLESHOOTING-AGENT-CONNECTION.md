# Troubleshooting: Agent Non Si Collega

## Problema
Gli agent su PCT 601 e 602 (server 192.168.40.4) non si collegano al server DaDude.

## Diagnostica Rapida

### 1. Esegui Script di Diagnostica

Sui container PCT 601 e 602, esegui:

```bash
# Copia lo script sul container
pct push 601 /path/to/diagnose-agent-connection.sh /root/diagnose.sh
pct push 602 /path/to/diagnose-agent-connection.sh /root/diagnose.sh

# Esegui la diagnostica
pct exec 601 -- bash /root/diagnose.sh
pct exec 602 -- bash /root/diagnose.sh
```

### 2. Verifica Manuale Configurazione

#### Su ogni container (601 e 602):

```bash
# Entra nel container
pct enter 601  # o 602

# Verifica variabili d'ambiente
cat /opt/dadude-agent/.env | grep DADUDE_

# Dovresti vedere:
# DADUDE_SERVER_URL=http://192.168.4.45:8000  (o https://dadude.domarc.it:8000)
# DADUDE_AGENT_ID=agent-Domarc-601  (o simile)
# DADUDE_AGENT_TOKEN=...
# DADUDE_AGENT_NAME=...
```

#### Verifica connettività:

```bash
# Test ping al server
ping -c 3 192.168.4.45

# Test connessione porta 8000
nc -zv 192.168.4.45 8000

# Test HTTP
curl -v http://192.168.4.45:8000/api/v1/agents/pending
```

### 3. Verifica Registrazione sul Server

#### Controlla se gli agent sono registrati:

```bash
# Sul server DaDude (192.168.4.45)
curl http://localhost:8000/api/v1/agents/pending
```

Oppure vai su: `http://192.168.4.45:8001/agents` (interfaccia web)

#### Verifica stato agent:

Gli agent devono avere:
- **Status**: `online` (non `pending_approval`)
- **Customer ID**: assegnato a un cliente
- **Active**: `true`

### 4. Problemi Comuni e Soluzioni

#### Problema 1: Agent Non Registrato

**Sintomi**: Lo script di diagnostica mostra "Agent not registered"

**Soluzione**:
1. Verifica che l'agent stia eseguendo la registrazione automatica
2. Controlla i log: `tail -f /var/lib/dadude-agent/logs/agent.log`
3. Se necessario, riavvia l'agent:
   ```bash
   systemctl restart dadude-agent
   # oppure
   pct restart 601
   ```

#### Problema 2: Agent Non Approvato

**Sintomi**: Agent registrato ma status = `pending_approval`

**Soluzione**:
1. Vai su `http://192.168.4.45:8001/agents`
2. Trova l'agent con nome corrispondente
3. Clicca "Approva" e assegna a un cliente
4. L'agent si riconnetterà automaticamente

#### Problema 3: URL Server Errato

**Sintomi**: Connessione TCP fallita, DNS non risolto

**Soluzione**:
1. Verifica che `DADUDE_SERVER_URL` sia corretto:
   - Per rete interna: `http://192.168.4.45:8000`
   - Per DNS: `https://dadude.domarc.it:8000`
2. Aggiorna il file `.env`:
   ```bash
   nano /opt/dadude-agent/.env
   # Modifica DADUDE_SERVER_URL
   ```
3. Riavvia l'agent

#### Problema 4: Token Errato o Mancante

**Sintomi**: Errore 401/403 durante registrazione

**Soluzione**:
1. Rigenera la configurazione:
   ```bash
   /opt/dadude-agent/dadude-agent/deploy/proxmox/regenerate-env.sh
   ```
2. Oppure ottieni il token dal server:
   - Vai su `http://192.168.4.45:8001/agents`
   - Trova l'agent e copia il token
   - Aggiorna `/opt/dadude-agent/.env`

#### Problema 5: Problemi di Rete/Firewall

**Sintomi**: Ping fallito, connessione TCP fallita

**Soluzione**:
1. Verifica routing tra 192.168.40.4 e 192.168.4.45:
   ```bash
   # Su PCT 601/602
   ip route get 192.168.4.45
   
   # Verifica firewall Proxmox
   iptables -L -n | grep 192.168.4.45
   ```

2. Verifica che il server sia raggiungibile:
   ```bash
   # Dal container
   curl -v http://192.168.4.45:8000/api/v1/agents/pending
   ```

3. Se necessario, configura firewall:
   ```bash
   # Su Proxmox host (192.168.40.4)
   # Permetti traffico verso 192.168.4.45:8000
   ```

#### Problema 6: WebSocket Non Raggiungibile

**Sintomi**: Connessione HTTP OK ma WebSocket fallisce

**Soluzione**:
1. Verifica che il server esponga WebSocket sulla porta 8000:
   ```bash
   # Sul server
   netstat -tlnp | grep 8000
   ```

2. Test WebSocket manuale:
   ```bash
   # Installa wscat se disponibile
   npm install -g wscat
   
   # Test connessione
   wscat -c ws://192.168.4.45:8000/api/v1/agents/ws/agent-Domarc-601 \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```

### 5. Rigenera Configurazione Agent

Se la configurazione è corrotta o mancante:

```bash
# Sul container
cd /opt/dadude-agent/dadude-agent/deploy/proxmox
./regenerate-env.sh
```

Questo script:
1. Legge la configurazione dal server
2. Rigenera il file `.env`
3. Riavvia l'agent

### 6. Log Dettagliati

Per vedere log dettagliati:

```bash
# Log agent
tail -f /var/lib/dadude-agent/logs/agent.log

# Log sistema
journalctl -u dadude-agent -f

# Log container
pct exec 601 -- journalctl -f
```

Cerca errori come:
- `Connection failed`
- `Agent not approved`
- `Invalid token`
- `DNS resolution failed`
- `Connection timeout`

### 7. Verifica Stato Finale

Dopo aver risolto i problemi, verifica:

```bash
# 1. Agent in esecuzione
ps aux | grep agent

# 2. Connessione WebSocket attiva
# Vai su http://192.168.4.45:8001/agents
# L'agent dovrebbe mostrare "Connected" con timestamp recente

# 3. Heartbeat recente
# Nel log dovresti vedere heartbeat ogni 30 secondi
tail -f /var/lib/dadude-agent/logs/agent.log | grep heartbeat
```

## Checklist Completa

- [ ] Variabili d'ambiente configurate correttamente
- [ ] Server raggiungibile via ping
- [ ] Porta 8000 raggiungibile via TCP
- [ ] HTTP endpoint risponde
- [ ] Agent registrato sul server
- [ ] Agent approvato (status = online)
- [ ] Agent assegnato a un cliente
- [ ] Token valido e configurato
- [ ] Processo agent in esecuzione
- [ ] WebSocket connesso (verificabile dall'interfaccia web)

## Contatti e Supporto

Se il problema persiste:
1. Raccogli output completo dello script di diagnostica
2. Raccogli ultimi 100 righe del log agent
3. Verifica configurazione rete Proxmox
4. Controlla log server DaDude per errori correlati

