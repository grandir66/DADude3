# Comandi per Aggiornare Manualmente gli Agent DaDude

## 0. Agent su Proxmox LXC (da dentro container agent)

### Metodo 1: Script automatico
```bash
./update-agent-proxmox.sh <proxmox_ip> <container_id> [ssh_user] [ssh_password]
```

Esempio:
```bash
./update-agent-proxmox.sh 192.168.40.15 600 root
./update-agent-proxmox.sh 192.168.40.15 610 root mypassword
```

### Metodo 2: Comando manuale SSH
```bash
ssh root@<proxmox_ip> "pct exec <container_id> -- bash -c 'cd /opt/dadude-agent/dadude-agent && git pull origin main && docker restart dadude-agent'"
```

### Metodo 3: Via API Agent (comando update_agent_proxmox)
Dal server DaDude, invia comando WebSocket all'agent:
```json
{
  "action": "update_agent_proxmox",
  "params": {
    "proxmox_ip": "192.168.40.15",
    "container_id": "600",
    "ssh_user": "root",
    "ssh_password": "password"
  }
}
```

## 1. Agent Docker Standalone (via SSH)

### Metodo 1: Script automatico
```bash
./update-agents.sh <agent_ip> docker
```

### Metodo 2: Comando manuale
```bash
ssh root@<agent_ip> "cd /opt/dadude-agent && git pull origin main && docker restart \$(docker ps --format '{{.Names}}' | grep -i agent | head -1)"
```

### Metodo 3: Se usa docker-compose
```bash
ssh root@<agent_ip> "cd /opt/dadude-agent && git pull origin main && docker compose down && docker compose up -d --build"
```

## 2. Agent su Router MikroTik (Container)

### Metodo 1: Via RouterOS CLI
```bash
ssh admin@<router_ip>
```

Poi sul router:
```routeros
# Riavvia container (aggiorna automaticamente se codice è montato)
/container/restart [find where name~"dadude"]

# OPPURE aggiorna codice e riavvia
/container/exec [find where name~"dadude"] git pull origin main
/container/restart [find where name~"dadude"]
```

### Metodo 2: Script automatico
```bash
./update-agents.sh <router_ip> mikrotik
```

## 3. Aggiornamento Multi-Agent (Batch)

### Script per aggiornare più agent
```bash
#!/bin/bash
AGENTS=(
    "192.168.4.100:docker"
    "192.168.4.101:mikrotik"
    "192.168.4.102:docker"
)

for agent in "${AGENTS[@]}"; do
    IFS=':' read -r ip type <<< "$agent"
    echo "Aggiornando $ip ($type)..."
    ./update-agents.sh "$ip" "$type"
    echo ""
done
```

## 4. Verifica Stato Agent

### Controlla versione agent
```bash
# Via API agent
curl -k https://<agent_ip>:8080/admin/status \
  -H "Authorization: Bearer <agent_token>"

# Via Docker logs
ssh root@<agent_ip> "docker logs \$(docker ps --format '{{.Names}}' | grep -i agent | head -1) --tail 50"
```

## 5. Troubleshooting

### Agent non si connette dopo update
```bash
# Verifica logs
ssh root@<agent_ip> "docker logs <container_name> --tail 100"

# Verifica connessione WebSocket
ssh root@<agent_ip> "docker exec <container_name> python -c 'from app.agent import DaDudeAgent; import asyncio; agent = DaDudeAgent(); print(asyncio.run(agent.get_status()))'"
```

### Reset completo agent
```bash
ssh root@<agent_ip> "cd /opt/dadude-agent && docker compose down && docker compose up -d --build --force-recreate"
```

