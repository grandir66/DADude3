#!/usr/bin/env python3
"""
Script per controllare i log delle scansioni fallite verso dispositivi MikroTik.
Cerca errori di autenticazione SSH, problemi di decrittazione password, ecc.
"""
import sys
import re
from pathlib import Path
from datetime import datetime, timedelta

# Aggiungi il path del progetto
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.config import get_settings
from loguru import logger

def check_logs_for_mikrotik_scans(target_ips=None, hours=24):
    """
    Controlla i log per errori di scansione MikroTik.
    
    Args:
        target_ips: Lista di IP da cercare (es. ['192.168.99.254', '192.168.99.3'])
        hours: Quante ore indietro cercare nei log
    """
    settings = get_settings()
    log_file = Path(settings.log_file)
    
    if not log_file.exists():
        print(f"❌ File di log non trovato: {log_file}")
        return
    
    print(f"📋 Controllo log: {log_file}")
    print(f"🔍 Cercando errori per gli ultimi {hours} ore")
    if target_ips:
        print(f"🎯 IP target: {', '.join(target_ips)}")
    print("-" * 80)
    
    # Pattern da cercare
    patterns = [
        r'(?i)(192\.168\.99\.(?:254|3|253))',  # IP MikroTik
        r'(?i)(ssh.*authentication.*failed)',
        r'(?i)(authentication.*failed)',
        r'(?i)(failed to decrypt password)',
        r'(?i)(password.*none|password.*empty)',
        r'(?i)(ssh.*probe.*error)',
        r'(?i)(credential.*mikrotik)',
        r'(?i)(mikrotik.*credential)',
        r'(?i)(ssh.*connection.*failed)',
        r'(?i)(CREDENTIALS.*SSH)',
        r'(?i)(CRED_RESULT.*FAILED)',
    ]
    
    # Leggi il file di log
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"❌ Errore lettura log: {e}")
        return
    
    # Filtra per timestamp (ultime N ore)
    cutoff_time = datetime.now() - timedelta(hours=hours)
    relevant_lines = []
    
    for line in lines:
        # Estrai timestamp (formato loguru: YYYY-MM-DD HH:mm:ss)
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', line)
        if timestamp_match:
            try:
                line_time = datetime.strptime(timestamp_match.group(1), '%Y-%m-%d %H:%M:%S')
                if line_time >= cutoff_time:
                    relevant_lines.append((line_time, line))
            except:
                # Se non riesce a parsare, include comunque la riga
                relevant_lines.append((datetime.now(), line))
        else:
            # Se non c'è timestamp, include comunque (potrebbe essere continuazione)
            relevant_lines.append((datetime.now(), line))
    
    # Cerca pattern rilevanti
    found_errors = []
    found_warnings = []
    found_info = []
    
    for timestamp, line in relevant_lines:
        line_lower = line.lower()
        
        # Verifica se contiene gli IP target
        if target_ips:
            ip_found = False
            for ip in target_ips:
                if ip in line:
                    ip_found = True
                    break
            if not ip_found:
                continue
        
        # Cerca pattern
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                if 'error' in line_lower or 'failed' in line_lower or 'exception' in line_lower:
                    found_errors.append((timestamp, line.strip()))
                elif 'warning' in line_lower:
                    found_warnings.append((timestamp, line.strip()))
                else:
                    found_info.append((timestamp, line.strip()))
                break
    
    # Mostra risultati
    print(f"\n🔴 ERRORI trovati: {len(found_errors)}")
    if found_errors:
        for timestamp, line in found_errors[-20:]:  # Ultimi 20 errori
            print(f"  [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {line}")
    
    print(f"\n⚠️  WARNING trovati: {len(found_warnings)}")
    if found_warnings:
        for timestamp, line in found_warnings[-10:]:  # Ultimi 10 warning
            print(f"  [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {line}")
    
    print(f"\nℹ️  INFO rilevanti: {len(found_info)}")
    if found_info:
        for timestamp, line in found_info[-10:]:  # Ultimi 10 info
            print(f"  [{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {line}")
    
    # Riepilogo
    print("\n" + "=" * 80)
    print("📊 RIEPILOGO")
    print("=" * 80)
    
    if not found_errors and not found_warnings:
        print("✅ Nessun errore trovato nei log recenti!")
        print("💡 Prova a eseguire una scansione ora e controlla di nuovo i log.")
    else:
        print(f"⚠️  Trovati {len(found_errors)} errori e {len(found_warnings)} warning")
        print("\n💡 Suggerimenti:")
        print("   1. Verifica che la password sia stata salvata correttamente")
        print("   2. Controlla che la porta SSH sia corretta (default: 22)")
        print("   3. Verifica che il dispositivo sia raggiungibile dalla rete")
        print("   4. Controlla i log dell'agent per dettagli aggiuntivi")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Controlla log scansioni MikroTik fallite")
    parser.add_argument("--ips", nargs="+", help="IP da cercare (es. 192.168.99.254 192.168.99.3)")
    parser.add_argument("--hours", type=int, default=24, help="Ore indietro da cercare (default: 24)")
    
    args = parser.parse_args()
    
    check_logs_for_mikrotik_scans(target_ips=args.ips, hours=args.hours)
