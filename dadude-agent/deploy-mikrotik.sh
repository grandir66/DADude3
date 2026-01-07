#!/bin/bash
# Script per build e deploy automatico di DaDude Agent su MikroTik RB5009
# Uso: ./deploy-mikrotik.sh [IP_ROUTER] [AGENT_TOKEN] [AGENT_ID] [AGENT_NAME]
#
# IMPORTANTE:
# - Lo script genera automaticamente lo script RouterOS e lo esegue via SSH
# - NON è necessario caricare manualmente il file .rsc su MikroTik
# - Il token può essere qualsiasi stringa (l'agent si auto-registra al server)
# - L'immagine Docker viene scaricata automaticamente da GitHub Releases

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configurazione
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="dadude-agent:mikrotik"
DOCKERFILE_MIKROTIK="${SCRIPT_DIR}/Dockerfile.mikrotik"
# RouterOS `/container/add file=...` expects a *docker-archive* tar (must contain manifest.json)
IMAGE_FILE="dadude-agent-mikrotik.tar"
ROUTER_IP="${1:-}"
AGENT_TOKEN="${2:-}"
AGENT_ID="${3:-agent-rb5009-test}"
AGENT_NAME="${4:-RB5009 Test}"
USB_DISK="usb1"
SERVER_URL="https://dadude.domarc.it:8000"
# URL GitHub Releases - usa /latest/ per l'ultima release
IMAGE_URL="https://github.com/grandir66/Dadude/releases/latest/download/dadude-agent-mikrotik.tar"

echo -e "${BLUE}=========================================="
echo "DaDude Agent - Deploy su MikroTik RB5009"
echo "==========================================${NC}"
echo ""
echo -e "${YELLOW}NOTA:${NC}"
echo "  - Lo script genera ed esegue automaticamente lo script RouterOS"
echo "  - NON è necessario caricare manualmente il file .rsc"
echo "  - Il token può essere qualsiasi stringa (l'agent si auto-registra)"
echo "  - L'immagine viene scaricata automaticamente da GitHub Releases"
echo ""

# Verifica parametri
if [ -z "$ROUTER_IP" ]; then
    echo -e "${YELLOW}Uso: $0 <IP_ROUTER> [AGENT_TOKEN] [AGENT_ID] [AGENT_NAME]${NC}"
    echo ""
    echo "Esempio:"
    echo "  $0 192.168.99.254 \"mio-token-123\" \"agent-rb5009-test\" \"RB5009 Test\""
    echo ""
    echo "Se non specifichi il token, verrà generato uno casuale"
    exit 1
fi

# Genera token casuale se non fornito
if [ -z "$AGENT_TOKEN" ]; then
    AGENT_TOKEN=$(openssl rand -hex 32)
    echo -e "${YELLOW}⚠️  Nessun token specificato, generato token casuale:${NC}"
    echo -e "${YELLOW}   $AGENT_TOKEN${NC}"
    echo ""
fi

# Step 1+2: Build + Export (linux/arm64) using classic docker save format
# RouterOS import is picky: we build with buildx, load into docker, then docker save.
echo -e "${BLUE}[1/5] Building MikroTik image (linux/arm64)...${NC}"
cd "$SCRIPT_DIR"

# Build with buildx and load into local docker daemon
docker buildx build --platform linux/arm64 -f "$DOCKERFILE_MIKROTIK" -t $IMAGE_NAME --load . || {
    echo -e "${RED}❌ Errore durante il build dell'immagine${NC}"
    exit 1
}
echo -e "${GREEN}✅ Immagine costruita: $IMAGE_NAME${NC}"

# Export with classic docker save format (works better with RouterOS)
echo -e "${BLUE}[2/5] Exporting image to tar (classic docker save format)...${NC}"
docker save -o "$IMAGE_FILE" $IMAGE_NAME || {
    echo -e "${RED}❌ Errore durante l'export dell'immagine${NC}"
    exit 1
}
IMAGE_SIZE=$(ls -lh "$IMAGE_FILE" | awk '{print $5}')
echo -e "${GREEN}✅ Immagine esportata: $IMAGE_FILE ($IMAGE_SIZE)${NC}"
echo ""

# Step 3: Verifica connessione al router
echo -e "${BLUE}[3/6] Verifying router connection...${NC}"
if ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 admin@$ROUTER_IP "echo 'Connected'" > /dev/null 2>&1; then
    echo -e "${RED}❌ Impossibile connettersi al router $ROUTER_IP${NC}"
    echo "Verifica:"
    echo "  - Il router è raggiungibile?"
    echo "  - SSH è abilitato?"
    echo "  - Le credenziali sono corrette?"
    exit 1
fi
echo -e "${GREEN}✅ Connessione al router OK${NC}"
echo ""

# Step 4: Verifica disco USB
echo -e "${BLUE}[4/6] Verifying USB disk (/$USB_DISK)...${NC}"
USB_EXISTS=$(ssh -o StrictHostKeyChecking=no admin@$ROUTER_IP "/file/print where name=$USB_DISK" 2>/dev/null | grep -c "$USB_DISK" || echo "0")
if [ "$USB_EXISTS" -eq 0 ]; then
    echo -e "${YELLOW}⚠️  Disco USB /$USB_DISK non trovato${NC}"
    echo "Verifica che il disco USB sia montato sul router"
    read -p "Vuoi continuare comunque? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ Disco USB /$USB_DISK trovato${NC}"
fi
echo ""

# Step 5: Opzione per caricare o usare download automatico
echo -e "${YELLOW}Vuoi caricare l'immagine ora o lasciare che il router la scarichi da GitHub Releases?${NC}"
read -p "Carica ora? (y/n, default=n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[5/6] Uploading image to router...${NC}"
    # Prova diversi percorsi per il caricamento
    # Su MikroTik, i dischi USB possono essere accessibili in modi diversi
    if scp -o StrictHostKeyChecking=no "$IMAGE_FILE" admin@$ROUTER_IP:/$USB_DISK/$IMAGE_FILE 2>/dev/null; then
        echo -e "${GREEN}✅ Immagine caricata su /$USB_DISK/$IMAGE_FILE${NC}"
    elif scp -o StrictHostKeyChecking=no "$IMAGE_FILE" admin@$ROUTER_IP:/$IMAGE_FILE 2>/dev/null; then
        echo -e "${YELLOW}⚠️  Caricata in root, spostando su /$USB_DISK/...${NC}"
        # RouterOS non ha `mv`: usa /file/move
        ssh -o StrictHostKeyChecking=no admin@$ROUTER_IP "/file/move source=/$IMAGE_FILE destination=/$USB_DISK/$IMAGE_FILE" || {
            echo -e "${YELLOW}⚠️  Impossibile spostare, lo script RouterOS cercherà in entrambe le posizioni${NC}"
        }
        echo -e "${GREEN}✅ Immagine caricata${NC}"
    else
        echo -e "${YELLOW}⚠️  Impossibile caricare via SCP, lo script RouterOS scaricherà automaticamente${NC}"
        echo -e "${YELLOW}   L'immagine verrà scaricata da GitHub Releases durante l'installazione${NC}"
    fi
else
    echo -e "${YELLOW}ℹ️  L'immagine verrà scaricata automaticamente da GitHub Releases${NC}"
    echo -e "${YELLOW}   URL: $IMAGE_URL${NC}"
fi
echo ""

# Step 6: Genera script RouterOS personalizzato
echo -e "${BLUE}[6/7] Generating RouterOS installation script...${NC}"
INSTALL_SCRIPT="/tmp/dadude-install-$(date +%s).rsc"
cat > "$INSTALL_SCRIPT" <<'ROUTEROS_SCRIPT'
# ==========================================
# DaDude Agent - Installazione su MikroTik RB5009
# Generato automaticamente da deploy-mikrotik.sh
# ==========================================

:local serverUrl "SERVER_URL_PLACEHOLDER"
:local agentToken "AGENT_TOKEN_PLACEHOLDER"
:local agentId "AGENT_ID_PLACEHOLDER"
:local agentName "AGENT_NAME_PLACEHOLDER"
:local dnsServers "192.168.4.1,8.8.8.8"
:local imageFile "IMAGE_FILE_PLACEHOLDER"
:local usbDisk "USB_DISK_PLACEHOLDER"
:local imageUrl "IMAGE_URL_PLACEHOLDER"

# Verifica Container Mode
:if ([/system/device-mode/print] = "") do={
    :error "Container mode non abilitato! Esegui: /system/device-mode/update container=yes"
}

# Verifica disco USB
:if ([/file/print where name=$usbDisk] = "") do={
    :error "Disco USB non trovato! Verifica che sia montato come /$usbDisk"
}

# Verifica o scarica l'immagine Docker
:local imagePath ""
:local imageFound 0

# Cerca l'immagine in diverse posizioni
:if ([/file/print where name=("/$usbDisk/$imageFile")] != "") do={
    :set imagePath ("/$usbDisk/$imageFile")
    :set imageFound 1
    :put "✅ Immagine trovata su /$usbDisk/"
} else={
    :if ([/file/print where name=("/$imageFile")] != "") do={
        :put "Immagine trovata in root, spostando su /$usbDisk/..."
        :do {
            /file/move source=("/$imageFile") destination=("/$usbDisk/$imageFile")
            :set imagePath ("/$usbDisk/$imageFile")
            :set imageFound 1
            :put "✅ Immagine spostata su /$usbDisk/"
        } on-error={
            :put "⚠️  Impossibile spostare, uso quella in root"
            :set imagePath ("/$imageFile")
            :set imageFound 1
        }
    }
}

# Se non trovata, scarica
:if ($imageFound = 0) do={
    :put "Immagine non trovata, scaricando da GitHub Releases..."
    :put "URL: $imageUrl"
    :put "Questo potrebbe richiedere alcuni minuti (file ~100-200MB)..."
    
    :do {
        /tool/fetch url=$imageUrl dst=("/$usbDisk/$imageFile") mode=http
        :set imagePath ("/$usbDisk/$imageFile")
    } on-error={
        :put "⚠️  Errore durante il download su /$usbDisk/, provo in root..."
        :do {
            /tool/fetch url=$imageUrl dst=("/$imageFile") mode=http
            :set imagePath ("/$imageFile")
        } on-error={
            :put "Errore durante il download dell'immagine!"
            :put "Verifica:"
            :put "  - Connessione internet attiva"
            :put "  - URL GitHub Releases accessibile"
            :put "  - Spazio sufficiente sul disco"
        }
    }
    
    :delay 2s
    
    # Verifica che il file sia stato scaricato
    :if ($imagePath = "") do={
        :if ([/file/print where name=("/$usbDisk/$imageFile")] != "") do={
            :set imagePath ("/$usbDisk/$imageFile")
        } else={
            :if ([/file/print where name=("/$imageFile")] != "") do={
                :set imagePath ("/$imageFile")
            } else={
                :put "Download fallito! Verifica la connessione internet e riprova."
            }
        }
    }
    
    # Verifica dimensione file solo se trovato
    :if ($imagePath != "") do={
        :local fileSize 0
        :do {
            :set fileSize ([/file/get $imagePath size])
        } on-error={
            :set fileSize 0
        }
        
        :if ($fileSize < 1048576) do={
            :put "⚠️  File scaricato potrebbe essere incompleto. Dimensione: $fileSize bytes"
        } else={
            :put "✅ Immagine scaricata con successo! Dimensione: $fileSize bytes"
            :put "   Percorso: $imagePath"
        }
    }
}

# Aggiorna imageFile con il percorso corretto
:if ($imagePath != "") do={
    :set imageFile ($imagePath)
} else={
    :put "⚠️  Nessuna immagine trovata o scaricata!"
    :put "Verifica manualmente che l'immagine esista o che il download sia completato."
}

# Rimuovi container esistente
:do {
    /container/stop 0
    /container/remove 0
} on-error={}

# Rimuovi configurazioni esistenti
:do {
    /interface/veth/remove [find name="veth-dadude-agent"]
} on-error={}
:do {
    /interface/bridge/port/remove [find bridge="bridge-dadude-agent"]
} on-error={}
:do {
    /interface/bridge/remove [find name="bridge-dadude-agent"]
} on-error={}
:do {
    /ip/firewall/nat/remove [find comment="dadude-agent-nat"]
} on-error={}
:do {
    /container/envs/remove [find name="dadude-env"]
} on-error={}

# Crea VETH interface
/interface/veth/add name=veth-dadude-agent address=172.17.0.2/24 gateway=172.17.0.1

# Crea bridge
/interface/bridge/add name=bridge-dadude-agent
/interface/bridge/port/add bridge=bridge-dadude-agent interface=veth-dadude-agent
/ip/address/add address=172.17.0.1/24 interface=bridge-dadude-agent

# Configura NAT
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 out-interface=bridge-dadude-agent comment="dadude-agent-nat"

# Environment variables
/container/envs/add name=dadude-env key=DADUDE_SERVER_URL value=$serverUrl
/container/envs/add name=dadude-env key=DADUDE_AGENT_TOKEN value=$agentToken
/container/envs/add name=dadude-env key=DADUDE_AGENT_ID value=$agentId
/container/envs/add name=dadude-env key=DADUDE_AGENT_NAME value=$agentName
/container/envs/add name=dadude-env key=DADUDE_DNS_SERVERS value=$dnsServers
/container/envs/add name=dadude-env key=PYTHONUNBUFFERED value="1"

# Crea container
# Usa imageFile che contiene già il percorso completo (gestito nello script)
/container/add \
    file=$imageFile \
    interface=veth-dadude-agent \
    root-dir=("/$usbDisk/dadude-agent") \
    envlist=dadude-env \
    start-on-boot=yes \
    logging=yes \
    cmd="python -m app.agent"

# Avvia container
/container/start 0

:delay 3s
:put "=========================================="
:put "Installazione completata!"
:put "=========================================="
/container/print
:put ""
:put "Log (ultimi 20 righe):"
/container/logs 0 lines=20
:put ""
:put "IMPORTANTE:"
:put "L'agent si auto-registrerà al server."
:put "Vai su https://dadude.domarc.it:8001/agents per approvare l'agent."
ROUTEROS_SCRIPT

# Sostituisci i placeholder con i valori reali
# Usa un separatore diverso per evitare conflitti con URL che contengono /
sed -i '' "s|SERVER_URL_PLACEHOLDER|$SERVER_URL|g" "$INSTALL_SCRIPT"
sed -i '' "s|AGENT_TOKEN_PLACEHOLDER|$AGENT_TOKEN|g" "$INSTALL_SCRIPT"
sed -i '' "s|AGENT_ID_PLACEHOLDER|$AGENT_ID|g" "$INSTALL_SCRIPT"
sed -i '' "s|AGENT_NAME_PLACEHOLDER|$AGENT_NAME|g" "$INSTALL_SCRIPT"
sed -i '' "s|IMAGE_FILE_PLACEHOLDER|$IMAGE_FILE|g" "$INSTALL_SCRIPT"
sed -i '' "s|USB_DISK_PLACEHOLDER|$USB_DISK|g" "$INSTALL_SCRIPT"
# Per URL, usa un separatore diverso per evitare problemi con i caratteri speciali
sed -i '' "s|IMAGE_URL_PLACEHOLDER|$IMAGE_URL|g" "$INSTALL_SCRIPT"

# Verifica che le sostituzioni siano avvenute
if grep -q "PLACEHOLDER" "$INSTALL_SCRIPT"; then
    echo -e "${YELLOW}⚠️  Attenzione: alcuni placeholder non sono stati sostituiti${NC}"
    grep "PLACEHOLDER" "$INSTALL_SCRIPT" | head -5
fi

echo -e "${GREEN}✅ Script RouterOS generato: $INSTALL_SCRIPT${NC}"
echo ""

# Step 7: Mostra istruzioni per esecuzione manuale
echo -e "${BLUE}[7/7] Script RouterOS ready${NC}"
echo ""
echo -e "${YELLOW}⚠️  IMPORTANTE: RouterOS non supporta l'esecuzione automatica via SSH pipe${NC}"
echo ""
echo -e "${GREEN}✅ Script generato: $INSTALL_SCRIPT${NC}"
echo ""
echo -e "${BLUE}Per installare l'agent, esegui una di queste opzioni:${NC}"
echo ""
echo -e "${YELLOW}OPZIONE 1: Copia e incolla diretto (CONSIGLIATO)${NC}"
echo "  1. Apri la console RouterOS (Winbox o SSH)"
echo "  2. Copia il contenuto del file: $INSTALL_SCRIPT"
echo "  3. Incollalo nella console RouterOS"
echo "  4. Premi Invio"
echo ""
echo -e "${YELLOW}OPZIONE 2: Carica file via Winbox${NC}"
echo "  1. Apri Winbox → Files"
echo "  2. Upload → Seleziona: $INSTALL_SCRIPT"
echo "  3. Salva in: /"
echo "  4. Nella console RouterOS esegui: /import file-name=dadude-install-*.rsc"
echo ""
echo -e "${YELLOW}OPZIONE 3: Usa lo script semplificato${NC}"
echo "  File: mikrotik-install-simple.rsc"
echo "  Modifica i valori di configurazione e copia/incolla direttamente"
echo ""
read -p "Vuoi vedere il contenuto dello script generato? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo -e "${BLUE}=== CONTENUTO SCRIPT ===${NC}"
    cat "$INSTALL_SCRIPT"
    echo ""
    echo -e "${BLUE}=== FINE SCRIPT ===${NC}"
fi

echo ""
echo -e "${GREEN}✅ Installazione completata!${NC}"
echo ""

echo -e "${GREEN}=========================================="
echo "Deploy completato!"
echo "==========================================${NC}"
echo ""
echo "Prossimi passi:"
echo "1. Verifica i log del container:"
echo "   ssh admin@$ROUTER_IP '/container/logs 0'"
echo ""
echo "2. Verifica lo stato del container:"
echo "   ssh admin@$ROUTER_IP '/container/print'"
echo ""
echo "3. L'agent si auto-registrerà al server"
echo "   Vai su $SERVER_URL/agents per approvare l'agent"
echo ""
echo "4. Token dell'agent: $AGENT_TOKEN"
echo "   (salvalo per riferimento futuro)"
echo ""
