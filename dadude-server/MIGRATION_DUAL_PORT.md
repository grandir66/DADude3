# Migrazione a Configurazione Dual Port

## 📋 Panoramica

Questa guida spiega come migrare dalla configurazione single-port (8000) alla nuova configurazione **dual-port** per maggiore sicurezza:

- **Porta 8000**: Agent API (pubblica, esposta su Internet)
- **Porta 8001**: Admin UI + Management API (privata, solo rete interna)

## 🎯 Motivazione

**Problema precedente**: Tutti gli endpoint (agent, dashboard, API admin) erano sulla stessa porta 8000, senza autenticazione. Esponendo la porta 8000 su Internet per gli agent, l'intera interfaccia di gestione era accessibile pubblicamente.

**Soluzione**: Separazione fisica su due porte:
- Gli agent si connettono solo alla porta 8000 (endpoint limitati)
- La gestione avviene solo su porta 8001 (non esposta)

## 🔧 Modifiche Implementate

### File Nuovi Creati

1. **`app/main_dual.py`** - Definisce due applicazioni FastAPI separate:
   - `agent_app` (porta 8000)
   - `admin_app` (porta 8001)

2. **`app/run_dual.py`** - Script per avviare entrambe le applicazioni in parallelo

3. **`docker-compose-dual.yml`** - Configurazione Docker con entrambe le porte

4. **`Dockerfile.dual`** - Dockerfile aggiornato per esporre entrambe le porte

### Endpoint Separati

**Porta 8000 - Agent API (PUBBLICO)**
```
/api/v1/agents/register          - Registrazione agent
/api/v1/agents/heartbeat         - Heartbeat agent
/api/v1/agents/ws/{agent_id}     - WebSocket agent
/api/v1/agents/config/{agent_id} - Configurazione agent
/api/v1/agents/enroll            - Enrollment certificati mTLS
/health                          - Health check
```

**Porta 8001 - Admin UI (PRIVATO)**
```
/dashboard                       - Dashboard web
/api/v1/customers/*              - Gestione clienti
/api/v1/inventory/*              - Gestione inventario
/api/v1/discovery/*              - Discovery reti
/api/v1/devices/*                - Dispositivi
/api/v1/probes/*                 - Sonde monitoring
/api/v1/alerts/*                 - Allarmi
/api/v1/system/*                 - Sistema
/api/v1/mikrotik/*               - MikroTik
/api/v1/import-export/*          - Import/Export
/api/v1/webhook/*                - Webhook
/health                          - Health check
```

## 🚀 Procedura di Migrazione

### Opzione A: Nuovo Deployment (CONSIGLIATO per test)

1. **Backup del database attuale**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- docker cp dadude:/app/data/dadude.db /tmp/dadude.db.backup.$(date +%Y%m%d)"
```

2. **Pull codice aggiornato**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c 'cd /opt/dadude && git pull origin main'"
```

3. **Build con nuovo Dockerfile**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c 'cd /opt/dadude/dadude && docker compose -f docker-compose-dual.yml build'"
```

4. **Aggiorna docker-compose per usare Dockerfile.dual**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c 'cd /opt/dadude/dadude && cat docker-compose-dual.yml'"
```

5. **Ferma il vecchio container**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c 'cd /opt/dadude/dadude && docker compose down'"
```

6. **Avvia con nuova configurazione**:
```bash
ssh root@192.168.40.3 "pct exec 800 -- bash -c 'cd /opt/dadude/dadude && docker compose -f docker-compose-dual.yml up -d'"
```

7. **Verifica entrambe le porte**:
```bash
# Agent API
curl http://192.168.4.45:8000/health

# Admin UI
curl http://192.168.4.45:8001/health
```

### Opzione B: Aggiornamento in-place

1. **Backup**:
```bash
docker cp dadude:/app/data/dadude.db /tmp/dadude.db.backup
```

2. **Pull repo aggiornato**:
```bash
cd /opt/dadude && git pull
```

3. **Update docker-compose.yml**:
```bash
cd dadude
cp docker-compose-dual.yml docker-compose.yml
cp Dockerfile.dual Dockerfile
```

4. **Rebuild e restart**:
```bash
docker compose down
docker compose build
docker compose up -d
```

## 🔒 Configurazione Firewall/Traefik

### Firewall (iptables)

Esporre solo porta 8000 su Internet:

```bash
# Permetti porta 8000 (Agent API) dall'esterno
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT

# Blocca porta 8001 dall'esterno (solo rete locale)
iptables -A INPUT -p tcp --dport 8001 -s 192.168.4.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 8001 -j DROP
```

### Traefik Configuration

```yaml
# /etc/traefik/conf.d/dadude-dual.yaml
http:
  routers:
    # PUBBLICO: Agent API (esposto su Internet)
    dadude-agents:
      rule: "Host(`agents.tuodominio.it`)"
      entryPoints:
        - websecure
      service: dadude-agent-api
      tls:
        certResolver: letsencrypt
      priority: 100

    # PRIVATO: Admin UI (solo rete interna o VPN)
    dadude-admin:
      rule: "Host(`admin.tuodominio.it`)"
      entryPoints:
        - websecure
      service: dadude-admin-ui
      middlewares:
        - internal-only  # Middleware che limita a IP interni
      tls:
        certResolver: letsencrypt
      priority: 90

  services:
    dadude-agent-api:
      loadBalancer:
        servers:
          - url: "http://192.168.4.45:8000"

    dadude-admin-ui:
      loadBalancer:
        servers:
          - url: "http://192.168.4.45:8001"

  middlewares:
    internal-only:
      ipWhiteList:
        sourceRange:
          - "192.168.0.0/16"   # Rete locale
          - "10.0.0.0/8"       # VPN
```

## 🧪 Testing

### Test Agent API (porta 8000)

```bash
# Health check
curl http://192.168.4.45:8000/health

# Endpoint info
curl http://192.168.4.45:8000/

# Docs (Swagger UI)
open http://192.168.4.45:8000/docs

# Test registrazione agent (simulato)
curl -X POST http://192.168.4.45:8000/api/v1/agents/register \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "test-agent",
    "agent_name": "Test Agent",
    "agent_type": "docker",
    "version": "2.2.3"
  }'

# Verifica che dashboard NON sia accessibile
curl http://192.168.4.45:8000/dashboard
# Dovrebbe rispondere 404 Not Found
```

### Test Admin UI (porta 8001)

```bash
# Health check
curl http://192.168.4.45:8001/health

# Dashboard (HTML)
curl http://192.168.4.45:8001/dashboard

# API clienti
curl http://192.168.4.45:8001/api/v1/customers

# Docs (Swagger UI)
open http://192.168.4.45:8001/docs

# Verifica che agent WebSocket NON sia accessibile
curl http://192.168.4.45:8001/api/v1/agents/register
# Dovrebbe rispondere 404 Not Found
```

### Test Agent Connection

Verifica che gli agent esistenti si connettano correttamente alla porta 8000:

```bash
# Dall'agent (es. container 610)
ssh root@192.168.40.3 "pct exec 610 -- docker logs dadude-agent --tail 50"
```

Dovresti vedere:
```
WebSocket connection successful to ws://dadude.domarc.it:8000/api/v1/agents/ws/agent-Domarc
```

## 📝 Aggiornamento Agent

Gli agent devono essere aggiornati per puntare alla porta 8000 (se usavano una porta diversa):

```bash
# Nel file .env dell'agent
DADUDE_SERVER_URL=http://dadude.domarc.it:8000
```

**NOTA**: Se gli agent già usavano porta 8000, non serve alcuna modifica!

## 🔄 Rollback

In caso di problemi, rollback alla configurazione precedente:

```bash
# Ferma nuova configurazione
docker compose -f docker-compose-dual.yml down

# Ripristina backup database
docker cp /tmp/dadude.db.backup dadude:/app/data/dadude.db

# Torna alla configurazione single-port (se necessario)
# NOTA: La configurazione dual-port è ora quella standard
# git checkout HEAD~1 -- app/main_dual.py Dockerfile.dual docker-compose-dual.yml

# Riavvia
docker compose up -d
```

## ⚠️ Checklist Pre-Migrazione

- [ ] Backup database eseguito
- [ ] Git pull completato con successo
- [ ] Nessun agent in esecuzione (o pronti a riconnettersi)
- [ ] Firewall/Traefik configurato correttamente
- [ ] Test plan definito
- [ ] Rollback plan pronto

## ⚠️ Checklist Post-Migrazione

- [ ] Porta 8000 risponde correttamente (`/health`)
- [ ] Porta 8001 risponde correttamente (`/health`)
- [ ] Dashboard accessibile su porta 8001
- [ ] Agent si connettono su porta 8000
- [ ] WebSocket agent funzionanti
- [ ] Database migrato correttamente
- [ ] Log senza errori critici
- [ ] Firewall/Traefik applica le regole correttamente

## 📚 Ulteriori Passi (Opzionali)

### Aggiungere Autenticazione su Porta 8001

Anche con porta separata, è consigliato aggiungere autenticazione:

```python
# app/middleware/auth.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Skip health check
        if request.url.path == "/health":
            return await call_next(request)

        # Richiedi API key per Admin UI
        api_key = request.headers.get("X-Admin-Key")
        if not api_key or api_key != os.getenv("ADMIN_API_KEY"):
            raise HTTPException(status_code=401, detail="Unauthorized")

        return await call_next(request)

# In main_dual.py
admin_app.add_middleware(AdminAuthMiddleware)
```

### Monitoraggio

Aggiungere metriche Prometheus:

```python
from prometheus_fastapi_instrumentator import Instrumentator

# Agent API metrics
Instrumentator().instrument(agent_app).expose(agent_app, endpoint="/metrics")

# Admin UI metrics
Instrumentator().instrument(admin_app).expose(admin_app, endpoint="/metrics")
```

## 🆘 Troubleshooting

### Problema: Agent non si connette

**Sintomo**: `Connection refused` o `404 Not Found`

**Soluzione**:
1. Verifica che porta 8000 sia esposta: `docker ps | grep dadude`
2. Controlla URL agent: `DADUDE_SERVER_URL=http://dadude.domarc.it:8000`
3. Verifica log server: `docker logs dadude | grep WebSocket`

### Problema: Dashboard non carica

**Sintomo**: Errore 404 o timeout

**Soluzione**:
1. Verifica porta 8001: `curl http://192.168.4.45:8001/health`
2. Controlla che processo admin sia avviato: `docker logs dadude | grep "Admin UI"`
3. Verifica template path: `ls -la app/templates/`

### Problema: Entrambe le porte usano lo stesso servizio

**Sintomo**: Dashboard visibile su porta 8000

**Soluzione**:
1. Verifica di usare `docker-compose-dual.yml`
2. Controlla CMD in Dockerfile: `CMD ["python", "-m", "app.run_dual"]`
3. Rebuild container: `docker compose down && docker compose build --no-cache`

## 📞 Supporto

Per problemi o domande:
- Issue GitHub: https://github.com/grandir66/dadude/issues
- Documentazione completa: `/docs` su entrambe le porte
