#!/usr/bin/env python3
"""
Script per scaricare e aggiornare il database OUI (MAC vendor) da fonti multiple.
Eseguire periodicamente per mantenere il database aggiornato.
"""
import os
import json
import requests
import re
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUI_FILE = os.path.join(SCRIPT_DIR, 'app', 'services', 'oui_database.json')
DATA_OUI_FILE = os.path.join(SCRIPT_DIR, 'data', 'oui_database.json')


def download_ieee_oui():
    """
    Scarica il database OUI da fonti multiple.
    """
    print("Downloading OUI database from multiple sources...")
    
    oui_data = {}
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    
    # Fonte 1: linuxnet.ca (mirror IEEE OUI)
    try:
        print("  Fetching from linuxnet.ca...")
        response = requests.get(
            'https://linuxnet.ca/ieee/oui.txt',
            headers=headers,
            timeout=60
        )
        response.raise_for_status()
        
        # Parse formato IEEE:
        # 00-00-00   (hex)		XEROX CORPORATION
        for line in response.text.split('\n'):
            match = re.match(r'^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$', line)
            if match:
                oui = match.group(1).replace('-', ':').upper()
                vendor = match.group(2).strip()
                if vendor and vendor != 'PRIVATE':
                    oui_data[oui] = vendor
        
        print(f"    Found {len(oui_data)} entries")
    except Exception as e:
        print(f"  Error: {e}")
    
    # Fonte 2: Prova alternativa - IEEE OUI registry ufficiale
    if len(oui_data) < 100:
        print("  Trying alternative source: IEEE OUI registry...")
        try:
            response = requests.get(
                'https://standards-oui.ieee.org/oui/oui.txt',
                headers=headers,
                timeout=60
            )
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    match = re.match(r'^\s*([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+)$', line)
                    if match:
                        oui = match.group(1).replace('-', ':').upper()
                        vendor = match.group(2).strip()
                        if vendor and vendor != 'PRIVATE' and oui not in oui_data:
                            oui_data[oui] = vendor
                print(f"    Found {len(oui_data)} entries from IEEE")
        except Exception as e:
            print(f"  Error from IEEE: {e}")
    
    # Fonte 3: Crea database base da VENDOR_DATABASE già presente
    if len(oui_data) < 100:
        print("  Using built-in vendor database as fallback...")
        try:
            # Leggi direttamente il file invece di importare
            vendor_db_file = os.path.join(SCRIPT_DIR, 'app', 'services', 'vendor_database.py')
            if os.path.exists(vendor_db_file):
                with open(vendor_db_file, 'r') as f:
                    content = f.read()
                    # Estrai VENDOR_DATABASE usando regex
                    pattern = r"VENDOR_DATABASE\s*=\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}"
                    match = re.search(pattern, content, re.DOTALL)
                    if match:
                        # Parse manuale delle voci - cerca pattern 'XX:XX:XX': {'vendor': 'Nome', ...
                        entries = re.findall(r"'([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})':\s*\{[^}]*'vendor':\s*'([^']+)'", match.group(1))
                        added = 0
                        for oui, vendor in entries:
                            if oui not in oui_data:
                                oui_data[oui] = vendor
                                added += 1
                        print(f"    Added {added} entries from VENDOR_DATABASE")
                    else:
                        print("    Could not parse VENDOR_DATABASE from file")
        except Exception as e:
            print(f"  Error loading VENDOR_DATABASE: {e}")
            import traceback
            traceback.print_exc()
    
    return oui_data


def save_database(oui_data):
    """Salva il database in formato JSON."""
    # Crea directory se non esiste
    os.makedirs(os.path.dirname(OUI_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(DATA_OUI_FILE), exist_ok=True)
    
    print(f"Saving database to {OUI_FILE}...")
    
    # Salva formato semplice (solo vendor names)
    with open(OUI_FILE, 'w') as f:
        json.dump(oui_data, f, indent=2)
    
    # Salva anche nella cartella data
    with open(DATA_OUI_FILE, 'w') as f:
        json.dump(oui_data, f, indent=2)
    
    print(f"  Saved {len(oui_data)} entries to both locations")


def main():
    print("=" * 60)
    print("OUI Database Downloader for DaDude")
    print("=" * 60)
    
    # Scarica da IEEE
    oui_data = download_ieee_oui()
    
    if not oui_data:
        print("ERROR: No data downloaded!")
        return False
    
    # Salva
    save_database(oui_data)
    
    print("=" * 60)
    print(f"Done! Database contains {len(oui_data)} vendor entries.")
    print(f"Files saved to:")
    print(f"  - {OUI_FILE}")
    print(f"  - {DATA_OUI_FILE}")
    print("=" * 60)
    
    return True


if __name__ == '__main__':
    main()

