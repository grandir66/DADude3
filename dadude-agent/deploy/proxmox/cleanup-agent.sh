#!/bin/bash
#
# DaDude Agent - Cleanup Script
# Rimuove file non necessari dall'installazione agent
#
# Uso: 
#   bash cleanup-agent.sh [--dry-run]
#   
# Opzioni:
#   --dry-run    Mostra cosa verrebbe eliminato senza cancellare nulla
#   --force      Non chiedere conferma
#
# Questo script:
# - Rimuove codice server (non serve sull'agent)
# - Rimuove script di deployment (già eseguiti)
# - Rimuove documentazione (non serve in produzione)
# - Rimuove file duplicati e temporanei
# - Mantiene SOLO i file essenziali per l'agent
#

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

DRY_RUN=false
FORCE=false

for arg in "$@"; do
    case $arg in
        --dry-run) DRY_RUN=true ;;
        --force) FORCE=true ;;
    esac
done

if $DRY_RUN; then
    echo -e "${YELLOW}[DRY-RUN MODE] Nessun file verrà eliminato${NC}"
    echo ""
fi

log() { echo -e "${GREEN}[CLEANUP]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

remove_item() {
    local path="$1"
    local desc="$2"
    
    if [[ -e "$path" ]] || [[ -d "$path" ]]; then
        if $DRY_RUN; then
            echo -e "  ${YELLOW}[DRY-RUN]${NC} Rimuoverei: $path ($desc)"
        else
            rm -rf "$path"
            echo -e "  ${GREEN}✓${NC} Rimosso: $path ($desc)"
        fi
    fi
}

# Banner
echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          DaDude Agent - Cleanup Script                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Verifica root
if [[ $EUID -ne 0 ]]; then
   error "Questo script deve essere eseguito come root"
fi

# Verifica che l'agent esista
if [[ ! -d "/opt/dadude-agent" ]]; then
    error "Directory /opt/dadude-agent non trovata"
fi

# =============================================================================
# ANALISI INIZIALE
# =============================================================================

log "Analisi spazio disco attuale..."
echo ""
echo -e "${BLUE}Spazio utilizzato in /opt:${NC}"
du -sh /opt/* 2>/dev/null | sort -rh | head -10
echo ""

echo -e "${BLUE}Contenuto /opt/dadude-agent:${NC}"
ls -la /opt/dadude-agent/ 2>/dev/null || true
echo ""

# Salva dimensione iniziale
INITIAL_SIZE=$(du -sm /opt/dadude-agent 2>/dev/null | cut -f1)

# =============================================================================
# BACKUP CONFIGURAZIONE
# =============================================================================

log "Backup configurazione esistente..."
BACKUP_DIR="/tmp/dadude-agent-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup .env files
find /opt -name ".env" -type f 2>/dev/null | while read env_file; do
    cp "$env_file" "$BACKUP_DIR/$(echo $env_file | tr '/' '_')" 2>/dev/null || true
done

# Backup config.json files
find /opt -name "config.json" -type f 2>/dev/null | while read config_file; do
    cp "$config_file" "$BACKUP_DIR/$(echo $config_file | tr '/' '_')" 2>/dev/null || true
done

info "Backup salvato in: $BACKUP_DIR"

# Conferma (skip se --force o --dry-run)
if ! $FORCE && ! $DRY_RUN; then
    echo ""
    read -p "Procedere con la pulizia? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Pulizia annullata"
        exit 0
    fi
fi

# =============================================================================
# PULIZIA
# =============================================================================

echo ""
log "Inizio pulizia..."
echo ""

# ---- 1. Rimuovi codice SERVER (non serve sull'agent) ----
echo -e "${YELLOW}[1/8] Rimozione codice server...${NC}"
remove_item "/opt/dadude-server" "Intero folder server"
remove_item "/opt/dadude-agent/dadude-server" "Server dentro agent folder"
remove_item "/opt/dadude-native" "Folder native completo"

# Cerca altri folder server nascosti
find /opt -type d -name "*server*" 2>/dev/null | while read dir; do
    remove_item "$dir" "Directory server trovata"
done

# ---- 2. Rimuovi script di deployment ----
echo ""
echo -e "${YELLOW}[2/8] Rimozione script deployment...${NC}"
remove_item "/opt/dadude-agent/deploy" "Folder deploy"
remove_item "/opt/dadude-agent/dadude-agent/deploy" "Folder deploy in agent"
remove_item "/opt/install-agent-native.sh" "Installer script"
remove_item "/opt/install-server-native.sh" "Server installer"

# Script vari nella root
for script in install*.sh quick-deploy.sh deploy*.sh DEPLOY*.md MIGRATION*.md; do
    find /opt -maxdepth 3 -name "$script" 2>/dev/null | while read f; do
        remove_item "$f" "Script deployment"
    done
done

# ---- 3. Rimuovi documentazione ----
echo ""
echo -e "${YELLOW}[3/8] Rimozione documentazione...${NC}"
find /opt -name "*.md" -type f 2>/dev/null | while read f; do
    remove_item "$f" "Documentazione Markdown"
done
find /opt -name "README*" -type f 2>/dev/null | while read f; do
    remove_item "$f" "README file"
done
find /opt -name "CHANGELOG*" -type f 2>/dev/null | while read f; do
    remove_item "$f" "CHANGELOG file"
done

# ---- 4. Rimuovi archivi e file temporanei ----
echo ""
echo -e "${YELLOW}[4/8] Rimozione archivi e temporanei...${NC}"
find /opt -name "*.tar.gz" -type f 2>/dev/null | while read f; do
    remove_item "$f" "Archivio tar.gz"
done
find /opt -name "*.zip" -type f 2>/dev/null | while read f; do
    remove_item "$f" "Archivio zip"
done
find /opt -name "*.bak" -type f 2>/dev/null | while read f; do
    remove_item "$f" "File backup"
done
find /opt -name "*~" -type f 2>/dev/null | while read f; do
    remove_item "$f" "File temporaneo"
done
find /opt -name "*.pyc" -type f 2>/dev/null | while read f; do
    remove_item "$f" "File Python compilato"
done
find /opt -name "__pycache__" -type d 2>/dev/null | while read d; do
    remove_item "$d" "Cache Python"
done

# ---- 5. Rimuovi directory .git ----
echo ""
echo -e "${YELLOW}[5/8] Rimozione repository Git...${NC}"
find /opt -name ".git" -type d 2>/dev/null | while read d; do
    remove_item "$d" "Repository Git"
done
find /opt -name ".gitignore" -type f 2>/dev/null | while read f; do
    remove_item "$f" "Gitignore"
done

# ---- 6. Rimuovi file di build ----
echo ""
echo -e "${YELLOW}[6/8] Rimozione file di build...${NC}"
remove_item "/opt/dadude-agent/build.sh" "Build script"
remove_item "/opt/dadude-agent/dadude-agent/build.sh" "Build script"
remove_item "/opt/dadude-agent/Dockerfile" "Dockerfile"
remove_item "/opt/dadude-agent/dadude-agent/Dockerfile" "Dockerfile"
remove_item "/opt/dadude-agent/docker-compose.yml" "Docker compose"
remove_item "/opt/dadude-agent/dadude-agent/docker-compose.yml" "Docker compose"

# ---- 7. Rimuovi config examples ----
echo ""
echo -e "${YELLOW}[7/8] Rimozione config examples...${NC}"
remove_item "/opt/dadude-agent/config" "Folder config examples"
remove_item "/opt/dadude-agent/dadude-agent/config" "Folder config examples"

# ---- 8. Rimuovi file MikroTik (non necessari su Linux) ----
echo ""
echo -e "${YELLOW}[8/8] Rimozione file MikroTik...${NC}"
find /opt -name "*mikrotik*" -type f 2>/dev/null | while read f; do
    remove_item "$f" "File MikroTik"
done
find /opt -name "*.rsc" -type f 2>/dev/null | while read f; do
    remove_item "$f" "Script RouterOS"
done

# =============================================================================
# VERIFICA STRUTTURA FINALE
# =============================================================================

echo ""
log "Verifica struttura finale..."
echo ""

echo -e "${BLUE}Struttura attesa /opt/dadude-agent:${NC}"
cat << 'EOF'
/opt/dadude-agent/
├── venv/                       # Virtualenv Python
└── dadude-agent/
    ├── app/                    # Codice Python (ESSENZIALE)
    │   ├── __init__.py
    │   ├── agent.py
    │   ├── commands/
    │   ├── config.py
    │   ├── connection/
    │   ├── fallback/
    │   ├── main.py
    │   ├── probes/
    │   ├── scanners/
    │   ├── scheduler/
    │   ├── services/
    │   ├── storage/
    │   ├── updater/
    │   └── workers/
    ├── requirements.txt        # Dipendenze Python
    ├── VERSION                 # Versione agent
    ├── dadude-agent.service    # Systemd service
    └── .env                    # Configurazione
EOF

echo ""
echo -e "${BLUE}Struttura attuale:${NC}"
if [[ -d "/opt/dadude-agent/dadude-agent" ]]; then
    ls -la /opt/dadude-agent/dadude-agent/ 2>/dev/null || true
elif [[ -d "/opt/dadude-agent/app" ]]; then
    ls -la /opt/dadude-agent/ 2>/dev/null || true
else
    ls -la /opt/dadude-agent/ 2>/dev/null || true
fi

# Calcola spazio recuperato
FINAL_SIZE=$(du -sm /opt/dadude-agent 2>/dev/null | cut -f1)
SAVED=$((INITIAL_SIZE - FINAL_SIZE))

echo ""
echo -e "${BLUE}Spazio disco:${NC}"
echo -e "  Prima:     ${INITIAL_SIZE} MB"
echo -e "  Dopo:      ${FINAL_SIZE} MB"
echo -e "  Risparmiato: ${GREEN}${SAVED} MB${NC}"

# =============================================================================
# VERIFICA INTEGRITÀ
# =============================================================================

echo ""
log "Verifica integrità agent..."

ERRORS=0

# Verifica file essenziali
ESSENTIAL_FILES=(
    "/opt/dadude-agent/dadude-agent/app/agent.py"
    "/opt/dadude-agent/dadude-agent/app/main.py"
    "/opt/dadude-agent/dadude-agent/app/config.py"
    "/opt/dadude-agent/dadude-agent/requirements.txt"
    "/opt/dadude-agent/dadude-agent/.env"
    "/opt/dadude-agent/venv/bin/python"
)

for file in "${ESSENTIAL_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo -e "  ${GREEN}✓${NC} $file"
    else
        echo -e "  ${RED}✗${NC} $file ${RED}MANCANTE${NC}"
        ERRORS=$((ERRORS + 1))
    fi
done

# Verifica systemd service
if systemctl list-unit-files | grep -q dadude-agent; then
    echo -e "  ${GREEN}✓${NC} Systemd service installato"
else
    echo -e "  ${YELLOW}!${NC} Systemd service non installato"
fi

# =============================================================================
# COMPLETATO
# =============================================================================

echo ""
if [[ $ERRORS -eq 0 ]]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║           ✅ CLEANUP COMPLETATO CON SUCCESSO             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
else
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║           ⚠️  CLEANUP COMPLETATO CON AVVISI              ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${RED}Trovati $ERRORS file mancanti. Potrebbe essere necessario reinstallare.${NC}"
fi

echo ""
echo -e "Backup configurazione: ${CYAN}$BACKUP_DIR${NC}"
echo ""

if ! $DRY_RUN; then
    echo -e "${YELLOW}Prossimi passi:${NC}"
    echo "  1. Riavvia l'agent:  systemctl restart dadude-agent"
    echo "  2. Verifica status:  systemctl status dadude-agent"
    echo "  3. Verifica logs:    journalctl -u dadude-agent -f"
    echo ""
fi
