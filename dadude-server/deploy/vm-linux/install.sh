#!/bin/bash
# DaDude - Installazione su VM Linux (non container)
# ===================================================
# Installa PostgreSQL, Python, dipendenze e configura il sistema

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variabili configurazione
INSTALL_DIR="${INSTALL_DIR:-/opt/dadude}"
DATA_DIR="${DATA_DIR:-/var/lib/dadude}"
LOG_DIR="${LOG_DIR:-/var/log/dadude}"
SERVICE_USER="${SERVICE_USER:-dadude}"
POSTGRES_DB="${POSTGRES_DB:-dadude}"
POSTGRES_USER="${POSTGRES_USER:-dadude}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DaDude - Installazione VM Linux${NC}"
echo -e "${BLUE}========================================${NC}"

# Verifica root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Errore: Esegui come root (sudo)${NC}"
    exit 1
fi

# Rileva distribuzione
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    echo -e "${RED}Impossibile rilevare la distribuzione${NC}"
    exit 1
fi

echo -e "${GREEN}Distribuzione rilevata: ${OS} ${VER}${NC}"

# Funzione installazione dipendenze
install_dependencies() {
    echo -e "${BLUE}[1/7] Installazione dipendenze sistema...${NC}"
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt-get update
        apt-get install -y \
            python3.11 \
            python3.11-venv \
            python3-pip \
            postgresql \
            postgresql-contrib \
            git \
            curl \
            build-essential \
            libpq-dev \
            python3-dev \
            net-tools \
            iproute2 \
            openssl
        
    elif [ "$OS" = "centos" ] || [ "$OS" = "rhel" ] || [ "$OS" = "rocky" ]; then
        yum install -y \
            python3.11 \
            python3-pip \
            postgresql-server \
            postgresql-contrib \
            git \
            curl \
            gcc \
            postgresql-devel \
            python3-devel \
            net-tools \
            iproute2 \
            openssl
        
        # Inizializza PostgreSQL se non già fatto
        if [ ! -d /var/lib/pgsql/data ]; then
            postgresql-setup --initdb
        fi
        
    else
        echo -e "${RED}Distribuzione non supportata: ${OS}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Dipendenze installate${NC}"
}

# Funzione configurazione PostgreSQL
setup_postgresql() {
    echo -e "${BLUE}[2/7] Configurazione PostgreSQL...${NC}"
    
    # Avvia PostgreSQL
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        systemctl enable postgresql
        systemctl start postgresql
    else
        systemctl enable postgresql
        systemctl start postgresql
    fi
    
    # Genera password se non fornita
    if [ -z "$POSTGRES_PASSWORD" ]; then
        POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        echo -e "${YELLOW}Password PostgreSQL generata: ${POSTGRES_PASSWORD}${NC}"
        echo -e "${YELLOW}Salvala in un posto sicuro!${NC}"
    fi
    
    # Crea database e utente
    sudo -u postgres psql <<EOF
-- Crea utente
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_user WHERE usename = '${POSTGRES_USER}') THEN
        CREATE USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';
    END IF;
END
\$\$;

-- Crea database
SELECT 'CREATE DATABASE ${POSTGRES_DB} OWNER ${POSTGRES_USER}'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '${POSTGRES_DB}')\gexec

-- Permessi
GRANT ALL PRIVILEGES ON DATABASE ${POSTGRES_DB} TO ${POSTGRES_USER};

-- Estensioni utili
\c ${POSTGRES_DB}
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
EOF
    
    echo -e "${GREEN}✓ PostgreSQL configurato${NC}"
    echo -e "${YELLOW}  Database: ${POSTGRES_DB}${NC}"
    echo -e "${YELLOW}  User: ${POSTGRES_USER}${NC}"
}

# Funzione creazione utente sistema
create_system_user() {
    echo -e "${BLUE}[3/7] Creazione utente sistema...${NC}"
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$INSTALL_DIR" -m "$SERVICE_USER"
        echo -e "${GREEN}✓ Utente ${SERVICE_USER} creato${NC}"
    else
        echo -e "${YELLOW}Utente ${SERVICE_USER} già esistente${NC}"
    fi
}

# Funzione installazione applicazione
install_application() {
    echo -e "${BLUE}[4/7] Installazione applicazione DaDude...${NC}"
    
    # Crea directory
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR" "$DATA_DIR" "$LOG_DIR"
    
    # Clona repository se non presente
    if [ ! -d "$INSTALL_DIR/.git" ]; then
        echo -e "${BLUE}Clonazione repository...${NC}"
        sudo -u "$SERVICE_USER" git clone https://github.com/grandir66/Dadude.git "$INSTALL_DIR"
    else
        echo -e "${BLUE}Repository già presente, aggiornamento...${NC}"
        cd "$INSTALL_DIR"
        sudo -u "$SERVICE_USER" git pull
    fi
    
    # Crea virtual environment
    echo -e "${BLUE}Creazione virtual environment...${NC}"
    sudo -u "$SERVICE_USER" python3.11 -m venv "$INSTALL_DIR/venv"
    
    # Installa dipendenze Python
    echo -e "${BLUE}Installazione dipendenze Python...${NC}"
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install --upgrade pip
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/dadude/requirements.txt"
    
    # Installa psycopg2 per PostgreSQL
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/pip" install psycopg2-binary
    
    echo -e "${GREEN}✓ Applicazione installata${NC}"
}

# Funzione configurazione ambiente
setup_environment() {
    echo -e "${BLUE}[5/7] Configurazione ambiente...${NC}"
    
    # Crea file .env
    ENV_FILE="$DATA_DIR/.env"
    cat > "$ENV_FILE" <<EOF
# DaDude Configuration
DADUDE_HOST=0.0.0.0
DADUDE_AGENT_PORT=8000
DADUDE_ADMIN_PORT=8001

# PostgreSQL Database
DATABASE_URL=postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}

# Logging
LOG_LEVEL=INFO
LOG_FILE=${LOG_DIR}/dadude.log

# Dude Server (configura manualmente)
DUDE_HOST=192.168.1.1
DUDE_API_PORT=8728
DUDE_USE_SSL=false
DUDE_USERNAME=admin
DUDE_PASSWORD=

# API Key (genera una nuova)
DADUDE_API_KEY=$(openssl rand -hex 32)
EOF
    
    chown "$SERVICE_USER:$SERVICE_USER" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    
    echo -e "${GREEN}✓ Ambiente configurato${NC}"
    echo -e "${YELLOW}  File config: ${ENV_FILE}${NC}"
}

# Funzione inizializzazione database
init_database() {
    echo -e "${BLUE}[6/7] Inizializzazione database...${NC}"
    
    cd "$INSTALL_DIR/dadude"
    
    # Esegui migrazione schema
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" <<EOF
import sys
import os
sys.path.insert(0, '$INSTALL_DIR/dadude')

from app.models.database import init_db

# Carica configurazione da .env
os.environ['DATABASE_URL'] = 'postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}'

# Inizializza database
engine = init_db(os.environ['DATABASE_URL'])
print("✓ Database inizializzato correttamente")
EOF
    
    echo -e "${GREEN}✓ Database inizializzato${NC}"
}

# Funzione creazione systemd service
create_systemd_service() {
    echo -e "${BLUE}[7/7] Creazione systemd service...${NC}"
    
    SERVICE_FILE="/etc/systemd/system/dadude.service"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=DaDude - The Dude MikroTik Connector
After=network.target postgresql.service
Requires=postgresql.service

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/dadude
Environment="PYTHONPATH=${INSTALL_DIR}/dadude"
EnvironmentFile=${DATA_DIR}/.env
ExecStart=${INSTALL_DIR}/venv/bin/python -m app.run_dual
Restart=always
RestartSec=10

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dadude

# Security
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable dadude
    
    echo -e "${GREEN}✓ Systemd service creato${NC}"
}

# Funzione migrazione dati SQLite (opzionale)
migrate_sqlite_data() {
    if [ -f "$DATA_DIR/dadude.db" ]; then
        echo -e "${YELLOW}Trovato database SQLite esistente.${NC}"
        read -p "Vuoi migrare i dati a PostgreSQL? (s/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Ss]$ ]]; then
            echo -e "${BLUE}Migrazione dati SQLite -> PostgreSQL...${NC}"
            sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" "$INSTALL_DIR/dadude/migrate_sqlite_to_postgres.py" \
                --sqlite "sqlite:///$DATA_DIR/dadude.db" \
                --postgres "postgresql+psycopg2://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:5432/${POSTGRES_DB}"
            echo -e "${GREEN}✓ Migrazione completata${NC}"
        fi
    fi
}

# Esecuzione
main() {
    install_dependencies
    setup_postgresql
    create_system_user
    install_application
    setup_environment
    init_database
    create_systemd_service
    migrate_sqlite_data
    
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Installazione completata!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Per avviare il servizio:"
    echo -e "  ${BLUE}systemctl start dadude${NC}"
    echo ""
    echo -e "Per verificare lo stato:"
    echo -e "  ${BLUE}systemctl status dadude${NC}"
    echo ""
    echo -e "Per vedere i log:"
    echo -e "  ${BLUE}journalctl -u dadude -f${NC}"
    echo ""
    echo -e "${YELLOW}IMPORTANTE:${NC}"
    echo -e "  - Configura ${DATA_DIR}/.env con le credenziali Dude Server"
    echo -e "  - Password PostgreSQL: ${POSTGRES_PASSWORD}"
    echo ""
}

main "$@"

