# Build Container MikroTik - Documentazione Tecnica

**Versione**: 3.0.0  
**Architettura**: Monolitica (tutto incluso nell'immagine)  
**Ultimo aggiornamento**: 2026-01-07

---

## 📋 Panoramica

Il container MikroTik è un'immagine Docker **monolitica** costruita per ARM64, ottimizzata per RouterOS 7.x. Tutto il necessario per far funzionare l'agent è incluso nell'immagine - nessuna dipendenza esterna a runtime.

### Caratteristiche

- ✅ **Monolitico**: Tutto incluso, nessun volume mount necessario
- ✅ **ARM64**: Buildato per architettura ARM64 (compatibile con MikroTik)
- ✅ **WebSocket-only**: Nessuna API REST, solo WebSocket mTLS
- ✅ **Leggero**: Immagine ottimizzata per RouterOS (minimo spazio)
- ✅ **Self-contained**: Nessuna dipendenza esterna a runtime

---

## 🏗️ Struttura Build

### Dockerfile

**File**: `dadude-agent/Dockerfile.mikrotik`

```dockerfile
FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    gcc libffi-dev iputils-ping dnsutils \
    net-tools iproute2 nmap procps curl

# Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Application code
COPY app/ /app/app/
COPY config/ /app/config/

# Run agent (WebSocket mode)
CMD ["python", "-m", "app.agent"]
```

### Componenti Inclusi

1. **Base Image**: `python:3.11-slim` (Debian-based, minimale)
2. **System Tools**: 
   - `nmap` - Port scanning
   - `ping` - Network connectivity
   - `dnsutils` - DNS resolution
   - `iproute2` - Network tools
   - `curl` - HTTP client
3. **Python Dependencies**: Tutte le librerie da `requirements.txt`
4. **Application Code**: Tutto il codice in `/app/app/`
5. **Configuration**: Template config in `/app/config/`

---

## 🔨 Build Process

### Build Locale

```bash
cd dadude-agent

# Build per ARM64 (MikroTik)
docker buildx build \
  --platform linux/arm64 \
  -f Dockerfile.mikrotik \
  -t dadude-agent-mikrotik:latest \
  --load .

# Export per MikroTik
docker save dadude-agent-mikrotik:latest -o dadude-agent-mikrotik.tar
```

### Build Automatico (GitHub Actions)

**Workflow**: `.github/workflows/build-mikrotik-image.yml`

Il workflow si attiva automaticamente quando:
- Push su branch `main` con modifiche in `dadude-agent/**`
- Manualmente tramite `workflow_dispatch`

**Processo**:
1. Checkout codice
2. Setup QEMU per emulazione ARM64
3. Setup Docker Buildx
4. Login a GitHub Container Registry
5. Build e push immagine:
   - Tag: `ghcr.io/grandir66/dadude-agent-mikrotik:latest`
   - Tag: `ghcr.io/grandir66/dadude-agent-mikrotik:$GITHUB_SHA`

**Registry**: `ghcr.io/grandir66/dadude-agent-mikrotik`

---

## 📦 Immagine Monolitica

### Cosa Significa "Monolitico"

L'immagine è **completamente self-contained**:

- ✅ **Nessun volume mount necessario**: Tutto il codice è nell'immagine
- ✅ **Nessuna dipendenza esterna**: Tutte le librerie sono incluse
- ✅ **Nessuna API REST**: Solo WebSocket, nessuna porta in ascolto
- ✅ **Configurazione via env vars**: Nessun file config esterno necessario

### Vantaggi per MikroTik

1. **Semplicità**: Un solo file tar da caricare
2. **Affidabilità**: Nessuna dipendenza da filesystem esterno
3. **Portabilità**: Funziona su qualsiasi MikroTik con Container support
4. **Sicurezza**: Nessun accesso a file esterni necessario

---

## 🔍 Verifica Immagine

### Controllo Dimensione

```bash
# Dimensione immagine
docker images dadude-agent-mikrotik:latest

# Dimensione tar export
ls -lh dadude-agent-mikrotik.tar
```

**Target**: < 200MB (compressa)

### Verifica Contenuti

```bash
# Entra nel container
docker run -it --rm dadude-agent-mikrotik:latest /bin/bash

# Verifica struttura
ls -la /app/app/
ls -la /app/config/

# Verifica Python packages
pip list

# Verifica tools
which nmap ping curl
```

### Test Funzionamento

```bash
# Test run (richiede env vars)
docker run --rm \
  -e DADUDE_SERVER_URL=http://server:8000 \
  -e DADUDE_AGENT_ID=test-agent \
  -e DADUDE_AGENT_TOKEN=test-token \
  -e DADUDE_CONNECTION_MODE=websocket \
  dadude-agent-mikrotik:latest
```

---

## 📤 Pubblicazione

### GitHub Container Registry

L'immagine viene pubblicata automaticamente su:
- `ghcr.io/grandir66/dadude-agent-mikrotik:latest`
- `ghcr.io/grandir66/dadude-agent-mikrotik:$GITHUB_SHA`

### Download per MikroTik

Il router MikroTik può scaricare l'immagine direttamente:

```routeros
# Configura registry
/container/config/set registry-url=https://ghcr.io

# Pull immagine
/container/add remote-image=ghcr.io/grandir66/dadude-agent-mikrotik:latest ...
```

### Export Manuale

Se necessario, l'immagine può essere esportata come tar:

```bash
# Export
docker save ghcr.io/grandir66/dadude-agent-mikrotik:latest \
  -o dadude-agent-mikrotik.tar

# Upload su GitHub Releases (opzionale)
gh release upload latest dadude-agent-mikrotik.tar
```

---

## 🔧 Ottimizzazioni

### Layer Caching

Il Dockerfile è ottimizzato per caching:

1. **System deps** (raramente cambiano)
2. **Python deps** (cambiano più spesso)
3. **App code** (cambia spesso)

### Riduzione Dimensione

- Usa `python:3.11-slim` invece di `python:3.11`
- Rimuove cache apt: `rm -rf /var/lib/apt/lists/*`
- Rimuove cache pip: `rm -rf /root/.cache/pip`
- Installa solo pacchetti necessari: `--no-install-recommends`

### Multi-stage Build (Futuro)

Per ridurre ulteriormente la dimensione, si potrebbe usare multi-stage:

```dockerfile
# Stage 1: Build
FROM python:3.11-slim as builder
RUN pip install --user -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim
COPY --from=builder /root/.local /root/.local
COPY app/ /app/app/
CMD ["python", "-m", "app.agent"]
```

**Nota**: Attualmente non usato per semplicità.

---

## 🐛 Troubleshooting Build

### Errore: "platform linux/arm64 not supported"

**Soluzione**: Usa Docker Buildx con QEMU:

```bash
docker buildx create --use
docker buildx build --platform linux/arm64 ...
```

### Errore: "no space left on device"

**Soluzione**: Pulisci Docker:

```bash
docker system prune -a
```

### Errore: "failed to push to ghcr.io"

**Soluzione**: Verifica:
1. Token GitHub configurato
2. Permessi su repository
3. Registry URL corretto

---

## 📝 Note Tecniche

### Architettura ARM64

- MikroTik RouterOS 7 usa ARM64
- Build deve essere per `linux/arm64`
- QEMU emula ARM64 su x86_64 durante build

### WebSocket vs REST API

- **Prima (v2.x)**: API REST sulla porta 8080
- **Ora (v3.0)**: Solo WebSocket, nessuna porta in ascolto
- **Vantaggio**: Più sicuro, NAT-friendly

### Configurazione

- **Prima**: File `config.json` montato come volume
- **Ora**: Solo variabili d'ambiente (env vars)
- **Vantaggio**: Più semplice, più sicuro

---

## ✅ Checklist Build

- [ ] Dockerfile.mikrotik aggiornato
- [ ] Requirements.txt aggiornato
- [ ] Test build locale OK
- [ ] Immagine < 200MB
- [ ] Test run container OK
- [ ] Push su ghcr.io OK
- [ ] Tag corretto (latest + SHA)
- [ ] Documentazione aggiornata

---

**Ultimo aggiornamento**: 2026-01-07
