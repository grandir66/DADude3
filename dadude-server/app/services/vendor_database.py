"""
Database locale di vendor basato su MAC address prefix (OUI).
Questo permette riconoscimento offline e più veloce.
Include database IEEE OUI completo (38.000+ vendor).
"""
import os
import json

# Carica database OUI completo da file JSON
_OUI_DATABASE = {}
# Prova prima nella cartella services (se copiato da DA-inventory)
_oui_file = os.path.join(os.path.dirname(__file__), 'oui_database.json')
if not os.path.exists(_oui_file):
    # Fallback alla cartella data del progetto
    _oui_file = os.path.join(os.path.dirname(__file__), '../../data/oui_database.json')
if os.path.exists(_oui_file):
    try:
        with open(_oui_file, 'r') as f:
            data = json.load(f)
            # Supporta sia formato semplice (dict di stringhe) che formato con metadata
            if isinstance(data, dict):
                if 'oui' in data:
                    # Formato con metadata
                    _OUI_DATABASE = data['oui']
                else:
                    # Formato semplice (dict diretto)
                    _OUI_DATABASE = data
            else:
                _OUI_DATABASE = {}
    except Exception as e:
        import sys
        print(f"Warning: Could not load OUI database from {_oui_file}: {e}", file=sys.stderr)
        pass

# Database vendor comuni con info aggiuntive (tipo dispositivo, OS)
# Formato: 'XX:XX:XX': {'vendor': 'Nome', 'type': 'tipo_dispositivo'}
VENDOR_DATABASE = {
    # Proxmox/QEMU
    'BC:24:11': {'vendor': 'Proxmox Server Solutions GmbH', 'type': 'server', 'os': 'linux'},
    '52:54:00': {'vendor': 'QEMU Virtual NIC', 'type': 'server', 'os': 'linux'},
    
    # VMware
    '00:50:56': {'vendor': 'VMware', 'type': 'server', 'os': 'unknown'},
    '00:0C:29': {'vendor': 'VMware', 'type': 'server', 'os': 'unknown'},
    '00:05:69': {'vendor': 'VMware', 'type': 'server', 'os': 'unknown'},
    
    # Microsoft Hyper-V
    '00:15:5D': {'vendor': 'Microsoft Hyper-V', 'type': 'server', 'os': 'windows'},
    
    # Cisco
    '00:00:0C': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:42': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:43': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:63': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:64': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:96': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:01:97': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:02:16': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:02:17': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:02:3D': {'vendor': 'Cisco', 'type': 'switch', 'os': 'cisco_ios'},
    '00:03:6B': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:03:FD': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:04:4D': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:17:94': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:18:0A': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:18:BA': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:1A:2F': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:1B:54': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:21:A0': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:22:55': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:25:45': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    '00:26:99': {'vendor': 'Cisco', 'type': 'network', 'os': 'cisco_ios'},
    
    # HP/HPE
    '00:1E:0B': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    '00:21:5A': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    '00:25:B3': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    '18:A9:05': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    '3C:4A:92': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    '94:57:A5': {'vendor': 'HP', 'type': 'server', 'os': 'unknown'},
    'B4:B5:2F': {'vendor': 'HP', 'type': 'switch', 'os': 'unknown'},
    
    # Dell
    '00:06:5B': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:0B:DB': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:0D:56': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:12:3F': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:13:72': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:14:22': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:15:C5': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:18:8B': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:1A:A0': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:1C:23': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:1D:09': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:1E:4F': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:1E:C9': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:21:9B': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:22:19': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:23:AE': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:24:E8': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '00:26:B9': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '14:18:77': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '18:03:73': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '18:A9:9B': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '24:B6:FD': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    '34:17:EB': {'vendor': 'Dell', 'type': 'server', 'os': 'unknown'},
    
    # Juniper
    '00:05:85': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:10:DB': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:12:1E': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:14:F6': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:17:CB': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:19:E2': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:21:59': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:23:9C': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    '00:26:88': {'vendor': 'Juniper Networks', 'type': 'network', 'os': 'junos'},
    
    # Fortinet
    '00:09:0F': {'vendor': 'Fortinet', 'type': 'firewall', 'os': 'fortios'},
    '08:5B:0E': {'vendor': 'Fortinet', 'type': 'firewall', 'os': 'fortios'},
    '70:4C:A5': {'vendor': 'Fortinet', 'type': 'firewall', 'os': 'fortios'},
    '90:6C:AC': {'vendor': 'Fortinet', 'type': 'firewall', 'os': 'fortios'},
    
    # Stormshield
    '00:03:50': {'vendor': 'Stormshield', 'type': 'firewall', 'os': 'stormshield'},
    
    # Ubiquiti
    '00:15:6D': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '00:27:22': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '04:18:D6': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '24:A4:3C': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '44:D9:E7': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '68:72:51': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '74:83:C2': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '78:8A:20': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    '80:2A:A8': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    'AC:8B:A9': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    'B4:FB:E4': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    'DC:9F:DB': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    'F0:9F:C2': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    'FC:EC:DA': {'vendor': 'Ubiquiti', 'type': 'network', 'os': 'unknown'},
    
    # MikroTik
    '00:0C:42': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    '4C:5E:0C': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    '64:D1:54': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    '6C:3B:6B': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    'B8:69:F4': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    'C4:AD:34': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    'D4:CA:6D': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    'E4:8D:8C': {'vendor': 'MikroTik', 'type': 'router', 'os': 'routeros'},
    
    # TP-Link
    '00:1D:0F': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    '14:CC:20': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    '50:C7:BF': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    '54:C8:0F': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    '60:E3:27': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    '90:F6:52': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    'B0:4E:26': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    'C0:25:E9': {'vendor': 'TP-Link', 'type': 'network', 'os': 'unknown'},
    
    # Netgear
    '00:09:5B': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:0F:B5': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:14:6C': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:18:4D': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:1B:2F': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:1E:2A': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:1F:33': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:22:3F': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:24:B2': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    '00:26:F2': {'vendor': 'Netgear', 'type': 'network', 'os': 'unknown'},
    
    # Apple
    '00:03:93': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:0A:27': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:0A:95': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:0D:93': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:11:24': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:14:51': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:16:CB': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:17:F2': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:19:E3': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1B:63': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1C:B3': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1D:4F': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1E:52': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1E:C2': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1F:5B': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:1F:F3': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:21:E9': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:22:41': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:23:12': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:23:32': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:23:6C': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:23:DF': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:24:36': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:25:00': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:25:4B': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:25:BC': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:26:08': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:26:4A': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:26:B0': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    '00:26:BB': {'vendor': 'Apple', 'type': 'workstation', 'os': 'macos'},
    
    # Intel (spesso PC/Server)
    '00:02:B3': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:03:47': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:04:23': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:07:E9': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:0C:F1': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:0E:0C': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:0E:35': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:11:11': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:12:F0': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:13:02': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:13:20': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:13:CE': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:13:E8': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:15:00': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:15:17': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:16:6F': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:16:76': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:16:EA': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:16:EB': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:18:DE': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:19:D1': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:19:D2': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1A:A0': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1B:21': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1B:77': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1C:BF': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1C:C0': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1D:E0': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1D:E1': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1E:64': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1E:65': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1E:67': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1F:3B': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:1F:3C': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:20:E0': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:21:5C': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:21:5D': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:21:6A': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:21:6B': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:22:FA': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:22:FB': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:24:D6': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:24:D7': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:26:C6': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:26:C7': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    '00:27:10': {'vendor': 'Intel', 'type': 'workstation', 'os': 'unknown'},
    
    # Synology NAS
    '00:11:32': {'vendor': 'Synology', 'type': 'storage', 'os': 'linux'},
    
    # QNAP NAS  
    '00:08:9B': {'vendor': 'QNAP', 'type': 'storage', 'os': 'linux'},
    '24:5E:BE': {'vendor': 'QNAP', 'type': 'storage', 'os': 'linux'},
    
    # Raspberry Pi
    'B8:27:EB': {'vendor': 'Raspberry Pi', 'type': 'server', 'os': 'linux'},
    'DC:A6:32': {'vendor': 'Raspberry Pi', 'type': 'server', 'os': 'linux'},
    'E4:5F:01': {'vendor': 'Raspberry Pi', 'type': 'server', 'os': 'linux'},
    
    # Lenovo
    '00:06:1B': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:09:2D': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:1A:6B': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:21:CC': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:22:68': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:23:7D': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:24:7E': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:25:00': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    '00:26:2D': {'vendor': 'Lenovo', 'type': 'workstation', 'os': 'unknown'},
    
    # Samsung
    '00:00:F0': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:02:78': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:07:AB': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:09:18': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:0D:AE': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:0D:E5': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:12:47': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:12:FB': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:13:77': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:15:99': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:15:B9': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:16:32': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:16:6B': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:16:6C': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:16:DB': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:17:C9': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:17:D5': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    '00:18:AF': {'vendor': 'Samsung', 'type': 'unknown', 'os': 'unknown'},
    
    # Huawei
    '00:E0:FC': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    '04:F9:38': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    '10:1B:54': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    '20:F3:A3': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    '24:09:95': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    '30:D1:7E': {'vendor': 'Huawei', 'type': 'network', 'os': 'unknown'},
    
    # Hikvision (IP Cameras)
    '4C:BD:8F': {'vendor': 'Hikvision', 'type': 'ipcamera', 'os': 'unknown'},
    '54:C4:15': {'vendor': 'Hikvision', 'type': 'ipcamera', 'os': 'unknown'},
    '80:48:E3': {'vendor': 'Hikvision', 'type': 'ipcamera', 'os': 'unknown'},
    'BC:AD:28': {'vendor': 'Hikvision', 'type': 'ipcamera', 'os': 'unknown'},
    'C0:56:E3': {'vendor': 'Hikvision', 'type': 'ipcamera', 'os': 'unknown'},
    
    # Dahua (IP Cameras)
    '3C:EF:8C': {'vendor': 'Dahua', 'type': 'ipcamera', 'os': 'unknown'},
    '4C:11:BF': {'vendor': 'Dahua', 'type': 'ipcamera', 'os': 'unknown'},
    '90:02:A9': {'vendor': 'Dahua', 'type': 'ipcamera', 'os': 'unknown'},
    'A0:BD:CD': {'vendor': 'Dahua', 'type': 'ipcamera', 'os': 'unknown'},
    
    # Axis (IP Cameras)
    '00:40:8C': {'vendor': 'Axis', 'type': 'ipcamera', 'os': 'unknown'},
    'AC:CC:8E': {'vendor': 'Axis', 'type': 'ipcamera', 'os': 'unknown'},
    'B8:A4:4F': {'vendor': 'Axis', 'type': 'ipcamera', 'os': 'unknown'},
    
    # Printer vendors
    '00:00:48': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:14:38': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:17:A4': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:18:71': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:1B:78': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:1C:C4': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:1E:0A': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:1F:29': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:21:5A': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    '00:23:7D': {'vendor': 'HP Printer', 'type': 'printer', 'os': 'unknown'},
    
    # Brother Printer
    '00:1B:A9': {'vendor': 'Brother', 'type': 'printer', 'os': 'unknown'},
    '00:80:77': {'vendor': 'Brother', 'type': 'printer', 'os': 'unknown'},
    
    # Canon Printer
    '00:1E:8F': {'vendor': 'Canon', 'type': 'printer', 'os': 'unknown'},
    '00:BB:C1': {'vendor': 'Canon', 'type': 'printer', 'os': 'unknown'},
    '18:0C:AC': {'vendor': 'Canon', 'type': 'printer', 'os': 'unknown'},
    
    # Epson Printer
    '00:00:48': {'vendor': 'Epson', 'type': 'printer', 'os': 'unknown'},
    '00:26:AB': {'vendor': 'Epson', 'type': 'printer', 'os': 'unknown'},
    '64:EB:8C': {'vendor': 'Epson', 'type': 'printer', 'os': 'unknown'},
    
    # APC UPS
    '00:C0:B7': {'vendor': 'APC', 'type': 'ups', 'os': 'unknown'},
    
    # Eaton UPS
    '00:20:85': {'vendor': 'Eaton', 'type': 'ups', 'os': 'unknown'},
}


def normalize_mac_for_lookup(mac_address: str):
    """
    Normalizza MAC address per lookup, generando tutte le varianti possibili.
    
    Returns:
        MAC normalizzato in formato XX:XX:XX:XX:XX:XX o None se invalido
    """
    if not mac_address:
        return None
    
    # Rimuovi spazi e converti in maiuscolo
    mac_clean = mac_address.replace(' ', '').replace('-', '').replace(':', '').replace('.', '').upper()
    
    # Verifica formato (12 caratteri esadecimali)
    if len(mac_clean) != 12:
        return None
    
    try:
        int(mac_clean, 16)  # Verifica che sia esadecimale
    except ValueError:
        return None
    
    # Formatta come XX:XX:XX:XX:XX:XX
    return ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])


def lookup_vendor_local(mac_address: str) -> dict:
    """
    Cerca vendor nel database locale usando MULTIPLE fonti con matching migliorato.
    Prima cerca nel database con info complete (tipo, OS),
    poi nel database OUI IEEE completo.
    Prova tutte le varianti di formato per massimizzare il matching.
    
    Args:
        mac_address: MAC address in formato XX:XX:XX:XX:XX:XX o varianti
        
    Returns:
        Dict con vendor, type, os o None se non trovato
    """
    if not mac_address:
        return None
    
    # Normalizza MAC address
    mac_normalized = normalize_mac_for_lookup(mac_address)
    if not mac_normalized:
        # Se la normalizzazione fallisce, prova comunque con il formato originale
        mac_normalized = mac_address.upper().strip()
    
    # Estrai OUI (primi 3 byte) in tutti i formati possibili
    oui_variants = []
    
    # Rimuovi separatori per ottenere formato compatto
    mac_clean = mac_normalized.replace(':', '').replace('-', '').replace('.', '').replace(' ', '')
    if len(mac_clean) < 6:
        return None
    
    # Estrai primi 6 caratteri (3 byte)
    oui_hex = mac_clean[:6]
    
    # Genera tutte le varianti del formato OUI
    oui_variants = [
        ':'.join([oui_hex[i:i+2] for i in range(0, 6, 2)]),  # XX:XX:XX
        oui_hex,  # XXXXXX (compatto)
        '-'.join([oui_hex[i:i+2] for i in range(0, 6, 2)]),  # XX-XX-XX
        ' '.join([oui_hex[i:i+2] for i in range(0, 6, 2)]),  # XX XX XX
    ]
    
    # FONTE 1: Database con info complete (VENDOR_DATABASE) - prova tutte le varianti
    for oui_var in oui_variants:
        if oui_var in VENDOR_DATABASE:
            result = VENDOR_DATABASE[oui_var]
            if isinstance(result, dict):
                return result
            elif isinstance(result, str):
                # Se è solo una stringa, convertila come vendor
                return {
                    'vendor': result,
                    'type': get_device_type_from_vendor(result),
                    'os': get_os_from_vendor(result)
                }
    
    # FONTE 2: Database OUI IEEE completo (_OUI_DATABASE) - prova tutte le varianti
    for oui_var in oui_variants:
        # Prova anche varianti con/senza separatori nel database
        search_variants = [
            oui_var,
            oui_var.replace(':', '').replace('-', '').replace(' ', ''),
            oui_var.replace('-', ':'),
            oui_var.replace(' ', ':'),
        ]
        
        for search_var in search_variants:
            if search_var in _OUI_DATABASE:
                vendor_name = _OUI_DATABASE[search_var]
                # Se è un dict, estrai il vendor
                if isinstance(vendor_name, dict):
                    vendor_name = vendor_name.get('vendor', '')
                # Se è una stringa, usala direttamente
                if vendor_name and vendor_name.strip():
                    # Inferisci tipo e OS dal nome vendor
                    device_type = get_device_type_from_vendor(vendor_name)
                    os_hint = get_os_from_vendor(vendor_name)
                    return {
                        'vendor': vendor_name.strip(),
                        'type': device_type,
                        'os': os_hint
                    }
    
    # FONTE 3: Matching case-insensitive nel database OUI
    # Alcuni database potrebbero avere chiavi in lowercase
    for oui_var in oui_variants:
        oui_lower = oui_var.lower()
        if oui_lower in _OUI_DATABASE:
            vendor_name = _OUI_DATABASE[oui_lower]
            if isinstance(vendor_name, dict):
                vendor_name = vendor_name.get('vendor', '')
            if vendor_name and vendor_name.strip():
                device_type = get_device_type_from_vendor(vendor_name)
                os_hint = get_os_from_vendor(vendor_name)
                return {
                    'vendor': vendor_name.strip(),
                    'type': device_type,
                    'os': os_hint
                }
    
    return None


def get_device_type_from_vendor(vendor: str) -> str:
    """
    Inferisce il tipo di dispositivo dal nome vendor.
    
    Args:
        vendor: Nome del vendor
        
    Returns:
        Tipo di dispositivo inferito
    """
    if not vendor:
        return 'unknown'
    
    vendor_lower = vendor.lower()
    
    # Mappature vendor -> tipo
    type_mappings = {
        # Firewall / Security
        'cisco': 'network',
        'juniper': 'network',
        'fortinet': 'firewall',
        'fortigate': 'firewall',
        'stormshield': 'firewall',
        'palo alto': 'firewall',
        'sophos': 'firewall',
        'checkpoint': 'firewall',
        'watchguard': 'firewall',
        'sonicwall': 'firewall',
        
        # Network devices
        'ubiquiti': 'network',
        'unifi': 'network',
        'mikrotik': 'router',
        'routerboard': 'router',
        'netgear': 'network',
        'tp-link': 'network',
        'dlink': 'network',
        'd-link': 'network',
        'linksys': 'network',
        'asus': 'network',
        'aruba': 'network',
        'ruckus': 'network',
        'extreme': 'network',
        'nokia': 'network',
        'ericsson': 'network',
        'huawei': 'network',
        'zte': 'network',
        'alcatel': 'network',
        
        # Server / Hypervisor
        'hp inc': 'server',
        'hewlett': 'server',
        'dell': 'server',
        'ibm': 'server',
        'supermicro': 'server',
        'vmware': 'server',
        'proxmox': 'server',
        'qemu': 'server',
        'hyper-v': 'server',
        
        # Workstation / PC
        'lenovo': 'workstation',
        'apple': 'workstation',
        'intel': 'workstation',
        'realtek': 'workstation',
        'broadcom': 'workstation',
        'acer': 'workstation',
        'asustek': 'workstation',
        'msi': 'workstation',
        'gigabyte': 'workstation',
        
        # Storage
        'synology': 'storage',
        'qnap': 'storage',
        'netapp': 'storage',
        'emc': 'storage',
        'buffalo': 'storage',
        'drobo': 'storage',
        'wd': 'storage',
        'western digital': 'storage',
        'seagate': 'storage',
        
        # IP Camera
        'hikvision': 'ipcamera',
        'dahua': 'ipcamera',
        'axis': 'ipcamera',
        'vivotek': 'ipcamera',
        'foscam': 'ipcamera',
        'reolink': 'ipcamera',
        'amcrest': 'ipcamera',
        'annke': 'ipcamera',
        
        # IoT / Smart Home
        'espressif': 'iot',
        'tuya': 'iot',
        'shelly': 'iot',
        'sonoff': 'iot',
        'tasmota': 'iot',
        'wemos': 'iot',
        'nodemcu': 'iot',
        'amazon': 'iot',  # Echo, Alexa
        'google': 'iot',  # Home, Chromecast
        'sonos': 'iot',   # Speaker
        'nest': 'iot',
        'ring': 'iot',
        'philips hue': 'iot',
        'lifx': 'iot',
        'wyze': 'iot',
        'arlo': 'ipcamera',
        'eufy': 'iot',
        'meross': 'iot',
        'woan': 'iot',
        'orbit': 'iot',  # Irrigazione
        'dreame': 'iot',  # Robot aspirapolvere
        'roborock': 'iot',
        'ecovacs': 'iot',
        'irobot': 'iot',  # Roomba
        'hanwha': 'ipcamera',
        'samsung wisenet': 'ipcamera',
        'brother': 'printer',
        'canon': 'printer',
        'epson': 'printer',
        'xerox': 'printer',
        'lexmark': 'printer',
        'ricoh': 'printer',
        'kyocera': 'printer',
        'konica': 'printer',
        'apc': 'ups',
        'eaton': 'ups',
        'cyberpower': 'ups',
        'raspberry': 'server',
        'espressif': 'iot',
        'arduino': 'iot',
        'texas instruments': 'iot',
    }
    
    for keyword, device_type in type_mappings.items():
        if keyword in vendor_lower:
            return device_type
    
    return 'unknown'


def get_os_from_vendor(vendor: str) -> str:
    """
    Inferisce il sistema operativo dal vendor.
    
    Args:
        vendor: Nome del vendor
        
    Returns:
        Sistema operativo inferito
    """
    if not vendor:
        return 'unknown'
    
    vendor_lower = vendor.lower()
    
    os_mappings = {
        'cisco': 'cisco_ios',
        'juniper': 'junos',
        'fortinet': 'fortios',
        'fortigate': 'fortios',
        'stormshield': 'stormshield',
        'mikrotik': 'routeros',
        'ubiquiti': 'ubnt',
        'apple': 'macos',
        'vmware': 'esxi',
        'proxmox': 'linux',
        'qemu': 'linux',
        'synology': 'linux',
        'qnap': 'linux',
        'raspberry': 'linux',
        'hyper-v': 'windows',
        'microsoft': 'windows',
    }
    
    for keyword, os_type in os_mappings.items():
        if keyword in vendor_lower:
            return os_type
    
    return 'unknown'

