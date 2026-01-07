# Quick Start - Installazione Rapida PCT 1600/1601

## Checklist Pre-Installazione

- [ ] PCT 1600 creato e accessibile
- [ ] PCT 1601 creato e accessibile  
- [ ] Accesso SSH a root@192.168.40.1
- [ ] Repository dadude-native disponibile

## Comandi Rapidi

### 1. Server (PCT 1600)

```bash
# Setup rete temporanea
ssh root@192.168.40.1 "pct set 1600 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.100/24,gw=192.168.4.1 && pct start 1600"

# Trasferisci e installa (da directory locale dadude-native)
cd /Users/riccardo/Progetti/dadude-native
tar czf - dadude-server/ install-server-native.sh | ssh root@192.168.40.1 "pct exec 1600 -- bash -c 'cd /opt && tar xzf - && bash install-server-native.sh'"

# Migra database (dopo backup da PCT 600)
# Vedi MIGRATION_DB.md per dettagli

# Avvia servizio
ssh root@192.168.40.1 "pct exec 1600 -- systemctl start dadude-server"
```

### 2. Agent (PCT 1601)

```bash
# Setup rete temporanea
ssh root@192.168.40.1 "pct set 1601 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.101/24,gw=192.168.4.1 && pct start 1601"

# Trasferisci e installa
cd /Users/riccardo/Progetti/dadude-native
tar czf - dadude-agent/ install-agent-native.sh | ssh root@192.168.40.1 "pct exec 1601 -- bash -c 'cd /opt && tar xzf - && bash install-agent-native.sh'"

# Avvia servizio
ssh root@192.168.40.1 "pct exec 1601 -- systemctl start dadude-agent"
```

### 3. Cutover IP

```bash
# Stop vecchio sistema
ssh root@192.168.40.1 "pct exec 600 -- docker stop dadude"

# Cambia IP PCT 1600 a 192.168.4.45
ssh root@192.168.40.1 "pct stop 1600 && pct set 1600 --net0 name=eth0,bridge=vmbr0,ip=192.168.4.45/24,gw=192.168.4.1 && pct start 1600"

# Aggiorna agent
ssh root@192.168.40.1 "pct exec 1601 -- sed -i 's|192.168.4.100|192.168.4.45|g' /opt/dadude-agent/dadude-agent/.env && systemctl restart dadude-agent"
```

## Verifica

```bash
# Server
curl -k https://192.168.4.45:8000/health
curl -k https://192.168.4.45:8001/health

# Log
ssh root@192.168.40.1 "pct exec 1600 -- journalctl -u dadude-server -n 20"
ssh root@192.168.40.1 "pct exec 1601 -- journalctl -u dadude-agent -n 20"
```
