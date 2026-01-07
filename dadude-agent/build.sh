#!/bin/bash
# Build script per DaDude Agent

set -e

# Colori
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

VERSION="${1:-1.0.0}"
IMAGE_NAME="dadude-agent"

echo -e "${GREEN}Building DaDude Agent v${VERSION}${NC}"

# Build immagine
echo -e "${YELLOW}Building Docker image...${NC}"
docker build -t ${IMAGE_NAME}:${VERSION} -t ${IMAGE_NAME}:latest .

# Mostra dimensione
echo -e "${YELLOW}Image size:${NC}"
docker images ${IMAGE_NAME}:${VERSION} --format "{{.Size}}"

# Crea export per MikroTik (tar)
echo -e "${YELLOW}Creating tar export for MikroTik...${NC}"
docker save ${IMAGE_NAME}:${VERSION} | gzip > ${IMAGE_NAME}-${VERSION}.tar.gz

ls -lh ${IMAGE_NAME}-${VERSION}.tar.gz

echo -e "${GREEN}Build complete!${NC}"
echo ""
echo "Usage:"
echo "  Local:    docker run -d -p 8080:8080 ${IMAGE_NAME}:${VERSION}"
echo "  MikroTik: Upload ${IMAGE_NAME}-${VERSION}.tar.gz to router"

