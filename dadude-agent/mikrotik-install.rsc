# ============================================================================
# DaDude Agent v3.0.0 - Installazione MikroTik Container
# WebSocket mTLS Mode (agent-initiated)
# ============================================================================
# 
# ISTRUZIONI:
# 1. PRIMA configura le env vars manualmente:
#
#    /container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://dadude.domarc.it:8000
#    /container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-NOME-ROUTER
#    /container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=NOME-ROUTER
#    /container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=TOKEN-SCELTO
#    /container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket
#
# 2. POI esegui questo script
#
# NOTA: L'agent ora usa WebSocket invece di API REST.
# Vedi: docs/deployment/MIKROTIK_CONTAINER_SETUP.md per guida completa.
#
# ============================================================================

:put "=========================================="
:put "DaDude Agent Installer"
:put "=========================================="

# Verifica che le env vars esistano
:local envCount [/container/envs/print count-only]
:if ($envCount = 0) do={
    :put "ERRORE: Devi prima configurare le env vars!"
    :put ""
    :put "Esegui questi comandi (modifica i valori):"
    :put ""
    :put "/container/envs/add list=dadude-env key=DADUDE_SERVER_URL value=http://dadude.domarc.it:8000"
    :put "/container/envs/add list=dadude-env key=DADUDE_AGENT_ID value=agent-NOME-ROUTER"
    :put "/container/envs/add list=dadude-env key=DADUDE_AGENT_NAME value=NOME-ROUTER"  
    :put "/container/envs/add list=dadude-env key=DADUDE_AGENT_TOKEN value=TOKEN-SCELTO"
    :put "/container/envs/add list=dadude-env key=DADUDE_CONNECTION_MODE value=websocket"
    :put ""
    :put "Poi riesegui questo script."
    :error "Env vars mancanti"
}

:put "Env vars trovate, procedo..."

# --- PULIZIA CONTAINER (ma NON le env vars!) ---
:do { /container/stop [find] } on-error={}
:delay 2s
:do { /container/remove [find] } on-error={}
:do { /container/mounts/remove [find] } on-error={}
:do { /interface/veth/remove [find name="veth-dadude"] } on-error={}
:do { /interface/bridge/port/remove [find interface="veth-dadude"] } on-error={}
:do { /interface/bridge/remove [find name="br-dadude"] } on-error={}
:do { /ip/address/remove [find comment="dadude"] } on-error={}
:do { /ip/firewall/nat/remove [find comment="dadude"] } on-error={}

# --- RETE ---
:put "Configurazione rete..."
/interface/veth/add name=veth-dadude address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/add name=br-dadude
/interface/bridge/port/add bridge=br-dadude interface=veth-dadude
/ip/address/add address=172.17.0.1/24 interface=br-dadude comment="dadude"
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24 comment="dadude"

# --- STORAGE ---
:put "Preparazione storage..."
:do { /file/make-directory name="usb1/container-tmp" } on-error={}
:do { /file/make-directory name="usb1/dadude-agent" } on-error={}
/container/config/set tmpdir=usb1/container-tmp registry-url=https://ghcr.io

# --- CONTAINER ---
:put "Creazione container..."
/container/add remote-image=ghcr.io/grandir66/dadude-agent-mikrotik:latest interface=veth-dadude root-dir=usb1/dadude-agent envlist=dadude-env dns=8.8.8.8 start-on-boot=yes logging=yes

:put ""
:put "=========================================="
:put "INSTALLAZIONE COMPLETATA!"
:put "=========================================="
:put ""
:put "Attendi download immagine (1-2 minuti)..."
:put "Controlla stato: /container/print"
:put ""
:put "Quando status=stopped: /container/start 0"
:put "Log: /container/log print"
:put ""
                                                            