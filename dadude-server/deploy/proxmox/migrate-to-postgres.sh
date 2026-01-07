#!/bin/bash
# Script di migrazione container DaDude da SQLite a PostgreSQL
# Per container Proxmox (es: CTID 600)
# ===================================================

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurazione
CTID="${CTID:-600}"
PROXMOX_HOST="${PROXMOX_HOST:-192.168.40.1}"
CONTAINER_NAME="dadude"
BACKUP_DIR="/tmp/dadude-migration-$(date +%Y%m%d-%H%M%S)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}DaDude - Migrazione a PostgreSQL${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo -e "Container ID: ${CTID}"
echo -e "Proxmox Host: ${PROXMOX_HOST}"
echo ""

# Verifica root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Errore: Esegui come root${NC}"
    exit 1
fi

# Funzione esecuzione comando nel container
run_in_container() {
    pct exec $CTID -- "$@"
}

# Funzione backup database SQLite
backup_sqlite() {
    echo -e "${BLUE}[1/8] Backup database SQLite...${NC}"
    
    mkdir -p "$BACKUP_DIR"
    
    # Copia database SQLite
    if run_in_container test -f /app/data/dadude.db; then
        run_in_container cp /app/data/dadude.db /tmp/dadude.db.backup
        pct pull $CTID /tmp/dadude.db.backup "$BACKUP_DIR/dadude.db"
        echo -e "${GREEN}✓ Backup SQLite completato: ${BACKUP_DIR}/dadude.db${NC}"
    else
        echo -e "${YELLOW}⚠ Database SQLite non trovato (prima installazione?)${NC}"
    fi
    
    # Backup configurazione
    if run_in_container test -f /app/data/.env; then
        run_in_container cp /app/data/.env /tmp/.env.backup
        pct pull $CTID /tmp/.env.backup "$BACKUP_DIR/.env"
        echo -e "${GREEN}✓ Backup configurazione completato${NC}"
    fi
}

# Funzione stop container
stop_container() {
    echo -e "${BLUE}[2/8] Stop container...${NC}"
    
    if run_in_container docker ps | grep -q "$CONTAINER_NAME"; then
        run_in_container docker stop "$CONTAINER_NAME" || true
        echo -e "${GREEN}✓ Container fermato${NC}"
    else
        echo -e "${YELLOW}Container già fermo${NC}"
    fi
}

# Funzione aggiorna repository
update_repo() {
    echo -e "${BLUE}[3/8] Aggiornamento repository...${NC}"
    
    REPO_PATH=$(run_in_container docker inspect "$CONTAINER_NAME" --format '{{range .Mounts}}{{if eq .Destination "/app/repo"}}{{.Source}}{{end}}{{end}}' 2>/dev/null || echo "")
    
    if [ -z "$REPO_PATH" ]; then
        echo -e "${YELLOW}⚠ Repository path non trovato, procedo comunque${NC}"
        return
    fi
    
    if [ -d "$REPO_PATH" ]; then
        cd "$REPO_PATH"
        git pull
        echo -e "${GREEN}✓ Repository aggiornato${NC}"
    else
        echo -e "${YELLOW}⚠ Repository path non valido: $REPO_PATH${NC}"
    fi
}

# Funzione installa dipendenze PostgreSQL
install_postgres_deps() {
    echo -e "${BLUE}[4/8] Installazione dipendenze PostgreSQL...${NC}"
    
    # Installa psycopg2 nel container applicazione
    run_in_container docker exec "$CONTAINER_NAME" pip install psycopg2-binary || {
        echo -e "${YELLOW}⚠ Impossibile installare psycopg2 nel container fermo${NC}"
        echo -e "${YELLOW}  Verrà installato al prossimo avvio${NC}"
    }
    
    echo -e "${GREEN}✓ Dipendenze PostgreSQL preparate${NC}"
}

# Funzione configura docker-compose con PostgreSQL
setup_docker_compose() {
    echo -e "${BLUE}[5/8] Configurazione docker-compose PostgreSQL...${NC}"
    
    # Genera password PostgreSQL se non fornita
    if [ -z "$POSTGRES_PASSWORD" ]; then
        POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
        echo -e "${YELLOW}Password PostgreSQL generata: ${POSTGRES_PASSWORD}${NC}"
        echo -e "${YELLOW}Salvala in un posto sicuro!${NC}"
    fi
    
    # Crea file .env per docker-compose
    ENV_FILE="$BACKUP_DIR/.env.postgres"
    cat > "$ENV_FILE" <<EOF
POSTGRES_DB=dadude
POSTGRES_USER=dadude
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
DADUDE_REPO_PATH=${DADUDE_REPO_PATH:-/opt/dadude}
EOF
    
    echo -e "${GREEN}✓ Configurazione docker-compose creata${NC}"
    echo -e "${YELLOW}  File: ${ENV_FILE}${NC}"
    echo -e "${YELLOW}  Copialo nel container e usa: docker-compose -f docker-compose-postgres.yml up -d${NC}"
}

# Funzione avvia PostgreSQL
start_postgres() {
    echo -e "${BLUE}[6/8] Avvio PostgreSQL...${NC}"
    
    # Carica variabili ambiente
    if [ -f "$BACKUP_DIR/.env.postgres" ]; then
        source "$BACKUP_DIR/.env.postgres"
    fi
    
    # Avvia con docker-compose
    REPO_PATH="${DADUDE_REPO_PATH:-/opt/dadude}"
    if [ -d "$REPO_PATH/dadude" ]; then
        cd "$REPO_PATH/dadude"
        
        # Carica variabili ambiente
        export $(cat "$BACKUP_DIR/.env.postgres" | xargs)
        
        # Avvia PostgreSQL e applicazione
        docker-compose -f docker-compose-postgres.yml up -d
        
        echo -e "${GREEN}✓ PostgreSQL avviato${NC}"
    else
        echo -e "${RED}✗ Repository non trovato: $REPO_PATH/dadude${NC}"
        echo -e "${YELLOW}  Avvia manualmente:${NC}"
        echo -e "${YELLOW}  cd /path/to/dadude && docker-compose -f docker-compose-postgres.yml up -d${NC}"
    fi
}

# Funzione migrazione dati
migrate_data() {
    echo -e "${BLUE}[7/8] Migrazione dati SQLite -> PostgreSQL...${NC}"
    
    if [ ! -f "$BACKUP_DIR/dadude.db" ]; then
        echo -e "${YELLOW}⚠ Nessun database SQLite da migrare${NC}"
        return
    fi
    
    # Carica variabili ambiente
    if [ -f "$BACKUP_DIR/.env.postgres" ]; then
        source "$BACKUP_DIR/.env.postgres"
    fi
    
    # Attendi che PostgreSQL sia pronto
    echo -e "${BLUE}Attesa PostgreSQL pronto...${NC}"
    sleep 10
    
    # Esegui migrazione
    docker exec dadude python /app/migrate_sqlite_to_postgres.py \
        --sqlite "sqlite:///$BACKUP_DIR/dadude.db" \
        --postgres "postgresql+psycopg2://${POSTGRES_USER:-dadude}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-dadude}" \
        --force
    
    echo -e "${GREEN}✓ Migrazione dati completata${NC}"
}

# Funzione verifica
verify() {
    echo -e "${BLUE}[8/8] Verifica installazione...${NC}"
    
    # Verifica container attivi
    if docker ps | grep -q "dadude-postgres"; then
        echo -e "${GREEN}✓ Container PostgreSQL attivo${NC}"
    else
        echo -e "${RED}✗ Container PostgreSQL non trovato${NC}"
    fi
    
    if docker ps | grep -q "dadude$"; then
        echo -e "${GREEN}✓ Container applicazione attivo${NC}"
    else
        echo -e "${RED}✗ Container applicazione non trovato${NC}"
    fi
    
    # Verifica connessione PostgreSQL
    if docker exec dadude-postgres pg_isready -U dadude > /dev/null 2>&1; then
        echo -e "${GREEN}✓ PostgreSQL risponde${NC}"
    else
        echo -e "${RED}✗ PostgreSQL non risponde${NC}"
    fi
    
    # Verifica API
    sleep 5
    if curl -f http://localhost:8000/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ API risponde${NC}"
    else
        echo -e "${YELLOW}⚠ API non risponde (può essere normale durante avvio)${NC}"
    fi
}

# Funzione riepilogo
summary() {
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Migrazione completata!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Backup salvato in: ${BACKUP_DIR}"
    echo ""
    
    if [ -f "$BACKUP_DIR/.env.postgres" ]; then
        echo -e "${YELLOW}Credenziali PostgreSQL:${NC}"
        cat "$BACKUP_DIR/.env.postgres"
        echo ""
    fi
    
    echo -e "Per accedere a PostgreSQL:"
    echo -e "  ${BLUE}docker exec -it dadude-postgres psql -U dadude -d dadude${NC}"
    echo ""
    echo -e "Per verificare lo stato:"
    echo -e "  ${BLUE}docker-compose -f docker-compose-postgres.yml ps${NC}"
    echo ""
    echo -e "Per vedere i log:"
    echo -e "  ${BLUE}docker-compose -f docker-compose-postgres.yml logs -f${NC}"
    echo ""
}

# Esecuzione principale
main() {
    echo -e "${YELLOW}ATTENZIONE: Questo script migrerà il database da SQLite a PostgreSQL.${NC}"
    echo -e "${YELLOW}Assicurati di avere un backup completo prima di procedere.${NC}"
    echo ""
    read -p "Vuoi continuare? (s/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Ss]$ ]]; then
        echo "Migrazione annullata"
        exit 0
    fi
    
    backup_sqlite
    stop_container
    update_repo
    install_postgres_deps
    setup_docker_compose
    start_postgres
    migrate_data
    verify
    summary
}

main "$@"

