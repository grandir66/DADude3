#!/bin/bash
# Script per pulire scansioni vecchie tramite API
# Mantiene solo le ultime 5 scansioni per ogni rete

API_URL="${DADUDE_API_URL:-http://localhost:8001}"
KEEP_COUNT="${KEEP_COUNT:-5}"

echo "Pulizia scansioni vecchie via API"
echo "API URL: $API_URL"
echo "Mantieni ultime $KEEP_COUNT scansioni per rete"
echo ""

# Ottieni lista clienti
CUSTOMERS=$(curl -s "${API_URL}/api/v1/customers?active_only=true&limit=100" | jq -r '.customers[]?.id // empty')

if [ -z "$CUSTOMERS" ]; then
    echo "Nessun cliente trovato"
    exit 1
fi

TOTAL_DELETED=0
CUSTOMERS_PROCESSED=0

for CUSTOMER_ID in $CUSTOMERS; do
    echo "Pulizia scansioni per cliente: $CUSTOMER_ID"
    
    RESULT=$(curl -s -X POST "${API_URL}/api/v1/customers/${CUSTOMER_ID}/scans/cleanup?keep_count=${KEEP_COUNT}")
    
    DELETED=$(echo "$RESULT" | jq -r '.total_deleted // 0')
    
    if [ "$DELETED" -gt 0 ]; then
        echo "  Eliminate $DELETED scansioni"
        TOTAL_DELETED=$((TOTAL_DELETED + DELETED))
        CUSTOMERS_PROCESSED=$((CUSTOMERS_PROCESSED + 1))
    else
        echo "  Nessuna scansione da eliminare"
    fi
done

echo ""
echo "=========================================="
echo "Pulizia completata!"
echo "Totale scansioni eliminate: $TOTAL_DELETED"
echo "Clienti processati: $CUSTOMERS_PROCESSED"
echo "=========================================="

