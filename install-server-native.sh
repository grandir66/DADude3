#!/bin/bash
#
# DaDude Server - Installazione NATIVA (NO Docker) su Proxmox LXC
# 
# Uso:
#   curl -fsSL https://raw.githubusercontent.com/.../install-server-native.sh | bash
#   oppure: bash install-server-native.sh
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[DaDude]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Verifica che siamo su Debian/Ubuntu
if ! command -v apt-get &> /dev/null; then
    error "Questo script richiede Debian/Ubuntu"
fi

# Verifica root
if [[ $EUID -ne 0 ]]; then
   error "Questo script deve essere eseguito come root"
fi

log "=== DaDude Server - Installazione Nativa ==="

# 1. Aggiornamento sistema
log "Aggiornamento sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get upgrade -y

# 2. Installazione dipendenze di sistema
log "Installazione dipendenze di sistema..."
apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    libpq-dev \
    postgresql \
    postgresql-contrib \
    nmap \
    curl \
    git \
    openssl \
    ca-certificates

# 3. Setup PostgreSQL
log "Configurazione PostgreSQL..."
systemctl start postgresql
systemctl enable postgresql

# Crea utente e database
sudo -u postgres psql <<EOF
CREATE USER dadude WITH PASSWORD 'dadude_temp_password_change_me';
CREATE DATABASE dadude OWNER dadude;
GRANT ALL PRIVILEGES ON DATABASE dadude TO dadude;
\q
EOF

log "PostgreSQL configurato. Password temporanea: dadude_temp_password_change_me"
warn "IMPORTANTE: Cambiare la password PostgreSQL dopo l'installazione!"

# 4. Creazione directory
log "Creazione directory..."
mkdir -p /opt/dadude-server
mkdir -p /var/log/dadude
mkdir -p /etc/dadude

# 5. Clone/Copy codice (assumendo che il codice sia già presente o da copiare)
if [[ ! -d "/opt/dadude-server/dadude-server" ]]; then
    log "Copia codice sorgente..."
    # Se eseguito da dentro la directory del progetto:
    if [[ -d "dadude-server" ]]; then
        cp -r dadude-server /opt/dadude-server/
    else
        error "Directory dadude-server non trovata. Eseguire lo script dalla root del progetto."
    fi
fi

# 6. Creazione virtualenv
log "Creazione virtualenv..."
cd /opt/dadude-server
python3 -m venv venv
source venv/bin/activate

# 7. Installazione dipendenze Python
log "Installazione dipendenze Python..."
pip install --upgrade pip
pip install -r dadude-server/requirements.txt

# 8. Configurazione .env
log "Configurazione file .env..."
if [[ ! -f "/opt/dadude-server/dadude-server/data/.env" ]]; then
    cat > /opt/dadude-server/dadude-server/data/.env <<EOF
# DaDude Server Configuration
DATABASE_URL=postgresql://dadude:dadude_temp_password_change_me@localhost:5432/dadude
SECRET_KEY=$(openssl rand -hex 32)
ENCRYPTION_KEY=$(openssl rand -hex 32)
SSL_ENABLED=false
LOG_LEVEL=INFO
EOF
    log "File .env creato in /opt/dadude-server/dadude-server/data/.env"
    warn "IMPORTANTE: Modificare DATABASE_URL con password corretta!"
fi

# 9. Setup database (migrazioni)
log "Esecuzione migrazioni database..."
cd /opt/dadude-server/dadude-server
# Le migrazioni verranno eseguite al primo avvio o manualmente
# python -m alembic upgrade head  # Se usando Alembic

# 10. Installazione systemd service
log "Installazione servizio systemd..."
if [[ -f "dadude-server/dadude-server.service" ]]; then
    cp dadude-server/dadude-server.service /etc/systemd/system/
elif [[ -f "/opt/dadude-server/dadude-server/dadude-server.service" ]]; then
    cp /opt/dadude-server/dadude-server/dadude-server.service /etc/systemd/system/
else
    error "File dadude-server.service non trovato!"
fi
systemctl daemon-reload
systemctl enable dadude-server.service

log "Installazione completata!"
echo ""
echo -e "${GREEN}Prossimi passi:${NC}"
echo "1. Modificare /opt/dadude-server/dadude-server/data/.env con password PostgreSQL corretta"
echo "2. (Opzionale) Importare dati esistenti dal vecchio sistema"
echo "3. Avviare il servizio: systemctl start dadude-server"
echo "4. Verificare log: journalctl -u dadude-server -f"
echo ""
echo -e "${YELLOW}Per importare dati dal vecchio sistema Docker:${NC}"
echo "  pg_dump -h <old_host> -U <user> -d dadude > backup.sql"
echo "  psql -U dadude -d dadude < backup.sql"
