#!/usr/bin/env python3
"""
Script per pulire scansioni vecchie tramite API
Mantiene solo le ultime 5 scansioni per ogni rete
"""
import os
import sys
import requests
import json

API_URL = os.getenv("DADUDE_API_URL", "http://localhost:8001")
KEEP_COUNT = int(os.getenv("KEEP_COUNT", "5"))

def cleanup_scans():
    print("Pulizia scansioni vecchie via API")
    print(f"API URL: {API_URL}")
    print(f"Mantieni ultime {KEEP_COUNT} scansioni per rete")
    print("")
    
    # Ottieni lista clienti
    try:
        response = requests.get(f"{API_URL}/api/v1/customers?active_only=true&limit=100", timeout=10)
        response.raise_for_status()
        data = response.json()
        customers = [c.get("id") for c in data.get("customers", [])]
    except Exception as e:
        print(f"Errore nel recupero clienti: {e}")
        return
    
    if not customers:
        print("Nessun cliente trovato")
        return
    
    total_deleted = 0
    customers_processed = 0
    
    for customer_id in customers:
        print(f"Pulizia scansioni per cliente: {customer_id}")
        
        try:
            response = requests.post(
                f"{API_URL}/api/v1/customers/{customer_id}/scans/cleanup",
                params={"keep_count": KEEP_COUNT},
                timeout=30
            )
            response.raise_for_status()
            result = response.json()
            
            deleted = result.get("total_deleted", 0)
            
            if deleted > 0:
                print(f"  Eliminate {deleted} scansioni")
                networks_cleaned = result.get("networks_cleaned", [])
                for net_info in networks_cleaned:
                    print(f"    - {net_info.get('network_name', 'Unknown')} ({net_info.get('network_cidr', 'N/A')}): "
                          f"eliminate {net_info.get('deleted_count', 0)} scansioni")
                total_deleted += deleted
                customers_processed += 1
            else:
                print("  Nessuna scansione da eliminare")
        except Exception as e:
            print(f"  Errore durante pulizia: {e}")
    
    print("")
    print("=" * 60)
    print("Pulizia completata!")
    print(f"Totale scansioni eliminate: {total_deleted}")
    print(f"Clienti processati: {customers_processed}")
    print("=" * 60)

if __name__ == "__main__":
    cleanup_scans()

