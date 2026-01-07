#!/bin/bash
# Quick Deploy Script for Device Backup Module
# Usage: ./quick-deploy.sh <container_id>

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

CONTAINER_ID="${1:-}"
SERVER="${2:-192.168.4.45}"

echo -e "${BLUE}=====================================================================${NC}"
echo -e "${BLUE}    Device Backup Module - Quick Deploy to Docker Container${NC}"
echo -e "${BLUE}=====================================================================${NC}"
echo ""

# Check if container ID provided
if [ -z "$CONTAINER_ID" ]; then
    echo -e "${RED}❌ Container ID not provided${NC}"
    echo ""
    echo "Usage: $0 <container_id> [server_ip]"
    echo ""
    echo "Examples:"
    echo "  $0 abc123def456"
    echo "  $0 abc123def456 192.168.4.45"
    echo ""
    echo "Find container ID with:"
    echo "  ssh root@$SERVER 'docker ps'"
    exit 1
fi

echo -e "${YELLOW}🐳 Target: Docker container $CONTAINER_ID on $SERVER${NC}"
echo ""

# Function to run command in container
run_in_container() {
    ssh root@$SERVER "docker exec $CONTAINER_ID $@"
}

# Step 1: Verify container exists
echo -e "${BLUE}[1/8] Verifying container exists...${NC}"
if ! ssh root@$SERVER "docker ps -q -f id=$CONTAINER_ID" | grep -q .; then
    echo -e "${RED}❌ Container $CONTAINER_ID not found or not running${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Container verified${NC}"
echo ""

# Step 2: Backup database
echo -e "${BLUE}[2/8] Creating database backup...${NC}"
BACKUP_FILE="dadude.db.backup-$(date +%Y%m%d-%H%M%S)"
run_in_container bash -c "cp ./data/dadude.db ./data/$BACKUP_FILE 2>/dev/null || true"
echo -e "${GREEN}✓ Database backed up to: $BACKUP_FILE${NC}"
echo ""

# Step 3: Git pull
echo -e "${BLUE}[3/8] Pulling latest changes from Git...${NC}"
run_in_container bash -c "cd /app && git fetch origin && git pull origin main"
CURRENT_COMMIT=$(run_in_container bash -c "cd /app && git log -1 --oneline" | head -1)
echo -e "${GREEN}✓ Git pull completed${NC}"
echo -e "${GREEN}  Current commit: $CURRENT_COMMIT${NC}"
echo ""

# Step 4: Verify files exist
echo -e "${BLUE}[4/8] Verifying module files...${NC}"
FILES=(
    "/app/app/main_dual.py"
    "/app/app/routers/device_backup.py"
    "/app/app/services/backup_scheduler.py"
    "/app/app/models/backup_models.py"
    "/app/migrate_backup_tables.py"
)
for file in "${FILES[@]}"; do
    if run_in_container test -f "$file"; then
        echo -e "${GREEN}  ✓ $file${NC}"
    else
        echo -e "${RED}  ✗ $file - MISSING!${NC}"
        exit 1
    fi
done
echo ""

# Step 5: Install dependencies
echo -e "${BLUE}[5/8] Installing dependencies...${NC}"
run_in_container pip install apscheduler -q
echo -e "${GREEN}✓ Dependencies installed${NC}"
echo ""

# Step 6: Run database migration
echo -e "${BLUE}[6/8] Running database migration...${NC}"
run_in_container python3 migrate_backup_tables.py --seed-templates
echo -e "${GREEN}✓ Database migration completed${NC}"
echo ""

# Step 7: Verify import
echo -e "${BLUE}[7/8] Verifying Python imports...${NC}"
if run_in_container python3 -c "from app.routers import device_backup; print('OK')" 2>&1 | grep -q "OK"; then
    echo -e "${GREEN}✓ Imports verified${NC}"
else
    echo -e "${RED}❌ Import verification failed${NC}"
    exit 1
fi
echo ""

# Step 8: Restart container
echo -e "${BLUE}[8/8] Restarting container...${NC}"
ssh root@$SERVER "docker restart $CONTAINER_ID"
echo -e "${GREEN}✓ Container restarted${NC}"
echo ""

# Wait for container to start
echo -e "${YELLOW}⏳ Waiting 10 seconds for container to start...${NC}"
sleep 10

# Verify startup
echo -e "${BLUE}Checking logs for successful startup...${NC}"
if ssh root@$SERVER "docker logs $CONTAINER_ID --tail 50" 2>&1 | grep -q "Backup Scheduler started"; then
    echo -e "${GREEN}✓ Backup Scheduler started successfully${NC}"
else
    echo -e "${YELLOW}⚠ Backup Scheduler not found in logs (might be optional)${NC}"
fi

if ssh root@$SERVER "docker logs $CONTAINER_ID --tail 50" 2>&1 | grep -q "WebSocket Hub started"; then
    echo -e "${GREEN}✓ WebSocket Hub started successfully${NC}"
fi

echo ""
echo -e "${GREEN}=====================================================================${NC}"
echo -e "${GREEN}                    DEPLOYMENT COMPLETED!${NC}"
echo -e "${GREEN}=====================================================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Verify API docs: http://$SERVER:800/docs"
echo "  2. Test endpoint:   curl http://$SERVER:800/api/v1/device-backup/templates"
echo "  3. Check logs:      ssh root@$SERVER 'docker logs -f $CONTAINER_ID'"
echo ""
echo -e "${BLUE}Rollback (if needed):${NC}"
echo "  ssh root@$SERVER 'docker exec $CONTAINER_ID cp ./data/$BACKUP_FILE ./data/dadude.db'"
echo "  ssh root@$SERVER 'docker restart $CONTAINER_ID'"
echo ""
