"""
DaDude Agent - SNMP Probe
Scansione dettagliata dispositivi di rete via SNMP
Supporta: Ubiquiti, MikroTik, Cisco, HP, Dell, Synology, QNAP, APC, Fortinet
"""
import asyncio
import re
from typing import Dict, Any, Optional, List
from loguru import logger


async def probe(
    target: str,
    community: str = "public",
    version: str = "2c",
    port: int = 161,
) -> Dict[str, Any]:
    """
    Esegue probe SNMP dettagliato su un target.
    
    Returns:
        Dict con info complete: vendor, model, serial, firmware, interfaces, etc.
    """
    from pysnmp.hlapi.v1arch.asyncio import (
        get_cmd, next_cmd, SnmpDispatcher, CommunityData, UdpTransportTarget,
        ObjectType, ObjectIdentity
    )
    
    logger.debug(f"SNMP probe: querying {target}:{port} community={community}")
    
    # ==========================================
    # OID DEFINITIONS
    # ==========================================
    
    # Standard MIB-II
    oids_basic = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysContact": "1.3.6.1.2.1.1.4.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysServices": "1.3.6.1.2.1.1.7.0",
    }
    
    # Interface count
    oids_interfaces = {
        "ifNumber": "1.3.6.1.2.1.2.1.0",  # Total interfaces
    }
    
    # Entity MIB (RFC 4133)
    oids_entity = {
        "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2.1",
        "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7.1",
        "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8.1",
        "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9.1",
        "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10.1",
        "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11.1",
        "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12.1",
        "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13.1",
    }
    
    # Host Resources MIB (for servers/hosts)
    oids_host = {
        "hrSystemUptime": "1.3.6.1.2.1.25.1.1.0",
        "hrSystemNumUsers": "1.3.6.1.2.1.25.1.5.0",
        "hrSystemProcesses": "1.3.6.1.2.1.25.1.6.0",
        "hrMemorySize": "1.3.6.1.2.1.25.2.2.0",  # KB
    }
    
    # Vendor-specific OIDs
    vendor_oids = {
        # Ubiquiti (41112)
        "ubiquiti": {
            # UniFi AP OIDs
            "ap_model": "1.3.6.1.4.1.41112.1.6.1.1",
            "ap_version": "1.3.6.1.4.1.41112.1.6.1.2",
            "ap_uptime": "1.3.6.1.4.1.41112.1.6.1.3",
            "ap_hostname": "1.3.6.1.4.1.41112.1.6.1.4",
            "ap_ip": "1.3.6.1.4.1.41112.1.6.1.5",
            "ap_mac": "1.3.6.1.4.1.41112.1.6.1.6",
            # UniFi Switch OIDs
            "sw_model": "1.3.6.1.4.1.41112.1.4.1.1.1",
            "sw_version": "1.3.6.1.4.1.41112.1.4.1.1.2",
            "sw_serial": "1.3.6.1.4.1.41112.1.4.1.1.3",
            # Generic UniFi OIDs (scalari con .0)
            "model": "1.3.6.1.4.1.41112.1.6.3.3.0",  # Modello UniFi (scalare con .0)
            "model_scalar": "1.3.6.1.4.1.41112.1.6.3.3",  # Senza .0 per compatibilità
            "version": "1.3.6.1.4.1.41112.1.6.3.6.0",  # Firmware UniFi (scalare con .0)
            "version_scalar": "1.3.6.1.4.1.41112.1.6.3.6",  # Senza .0 per compatibilità
            "mac": "1.3.6.1.4.1.41112.1.6.3.1.0",
            # Ubiquiti advanced
            "cpu_usage": "1.3.6.1.4.1.41112.1.4.7.1.5.1",
            "mem_usage": "1.3.6.1.4.1.41112.1.4.7.1.5.2",
            "temperature": "1.3.6.1.4.1.41112.1.4.7.1.5.3",
            # WiFi clients - questo è una tabella, quindi proviamo sia con che senza indice
            "wifi_clients": "1.3.6.1.4.1.41112.1.6.1.2.1.8.0",  # Client WiFi connessi (scalare)
            # Host Resources MIB (standard per Linux-based devices)
            "load_average_1m": "1.3.6.1.4.1.2021.10.1.3.1.0",  # Load Average 1 minuto (scalare)
            "ram_available": "1.3.6.1.4.1.2021.4.6.0",  # RAM Disponibile (MB)
        },
        # MikroTik (14988)
        "mikrotik": {
            # License info
            "license_software_id": "1.3.6.1.4.1.14988.1.1.4.1.0",
            "license_version": "1.3.6.1.4.1.14988.1.1.4.4.0",
            # System info
            "serial": "1.3.6.1.4.1.14988.1.1.7.3.0",
            "firmware_version": "1.3.6.1.4.1.14988.1.1.7.4.0",
            "firmware_upgrade_version": "1.3.6.1.4.1.14988.1.1.7.7.0",
            "board_name": "1.3.6.1.4.1.14988.1.1.7.8.0",
            "model": "1.3.6.1.4.1.14988.1.1.7.1.0",
            "version": "1.3.6.1.4.1.14988.1.1.4.4.0",  # Alias per compatibilità
            "firmware": "1.3.6.1.4.1.14988.1.1.7.4.0",  # Alias per compatibilità
            "license": "1.3.6.1.4.1.14988.1.1.4.1.0",  # Alias per compatibilità
            # Health monitoring
            "cpu_temperature": "1.3.6.1.4.1.14988.1.1.3.10.0",
            "board_temperature": "1.3.6.1.4.1.14988.1.1.3.11.0",
            "voltage": "1.3.6.1.4.1.14988.1.1.3.8.0",
            "active_fan": "1.3.6.1.4.1.14988.1.1.3.9.0",
            "temperature": "1.3.6.1.4.1.14988.1.1.3.100.0",
            # System resources (HOST-RESOURCES-MIB)
            "processor_load": "1.3.6.1.2.1.25.3.3.1.2",
            "storage_size": "1.3.6.1.2.1.25.2.3.1.5",
            "storage_used": "1.3.6.1.2.1.25.2.3.1.6",
            # Wireless (per AP mode)
            "wl_ap_ssid": "1.3.6.1.4.1.14988.1.1.1.3.1.4",
            "wl_ap_band": "1.3.6.1.4.1.14988.1.1.1.3.1.5",
            "wl_ap_noise_floor": "1.3.6.1.4.1.14988.1.1.1.3.1.9",
            "wl_ap_client_count": "1.3.6.1.4.1.14988.1.1.1.3.1.6",
        },
        # Cisco (9)
        "cisco": {
            "serial": "1.3.6.1.4.1.9.3.6.3.0",
            "model": "1.3.6.1.4.1.9.9.25.1.1.1.2.3",
            "ios_version": "1.3.6.1.4.1.9.9.25.1.1.1.2.5",
            # Cisco advanced
            "cpu_usage": "1.3.6.1.4.1.9.9.109.1.1.1.1.5",
            "mem_usage": "1.3.6.1.4.1.9.9.48.1.1.1.5.1",
            "temperature": "1.3.6.1.4.1.9.9.13.1.3.1.3",
        },
        # HP ProCurve (11.2.3.7.11, 11.2.3.7.8)
        "hp_procurve": {
            "os_version": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.3.0",
            "rom_version": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.4.0",
            "serial": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.6.0",
            "product_number": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.10.0",
            "cpu_usage": "1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0",
            "mem_total": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.5",
            "mem_free": "1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6",
            "temperature": "1.3.6.1.4.1.11.2.14.11.1.2.6.1.4",
            # Entity MIB per info moduli
            "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
            "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",
            "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
            "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
            "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
        },
        # HP Comware/H3C (25506)
        "hp_comware": {
            "cpu_usage": "1.3.6.1.4.1.25506.2.6.1.1.1.1.6",
            "mem_usage": "1.3.6.1.4.1.25506.2.6.1.1.1.1.8",
            "temperature": "1.3.6.1.4.1.25506.2.6.1.1.1.1.12",
            "fan_status": "1.3.6.1.4.1.25506.8.35.9.1.1.1.2",
            "power_status": "1.3.6.1.4.1.25506.8.35.9.1.2.1.2",
            # Entity MIB
            "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",
            "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11",
            "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13",
            "entPhysicalSoftwareRev": "1.3.6.1.2.1.47.1.1.1.1.10",
            "entPhysicalHardwareRev": "1.3.6.1.2.1.47.1.1.1.1.8",
        },
        # HP/Aruba (11, 25506) - Legacy compatibility
        "hp": {
            "serial": "1.3.6.1.4.1.11.2.36.1.1.2.9.0",
            "model": "1.3.6.1.4.1.11.2.36.1.1.2.5.0",
            # HP ProCurve/ArubaOS specific
            "cpu_usage": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.2.1.1.1.1",
            "mem_usage": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.2.1.1.1.2",
            "temperature": "1.3.6.1.4.1.11.2.14.11.5.1.1.1.2.1.1.1.3",
        },
        # ArubaOS (14823)
        "aruba": {
            "model": "1.3.6.1.4.1.14823.2.2.1.2.1.2.0",
            "serial": "1.3.6.1.4.1.14823.2.2.1.2.1.15.0",
            "sw_version": "1.3.6.1.4.1.14823.2.2.1.2.1.6.0",
            "hw_version": "1.3.6.1.4.1.14823.2.2.1.2.1.8.0",
            "cpu_usage": "1.3.6.1.4.1.14823.2.2.1.2.1.30.0",
            "mem_usage": "1.3.6.1.4.1.14823.2.2.1.2.1.31.0",
            "storage_usage": "1.3.6.1.4.1.14823.2.2.1.2.1.32.0",
            # Aruba Switch specific
            "switch_serial": "1.3.6.1.4.1.14823.2.3.1.2.1.2.0",
            # Aruba AP info (table)
            "ap_serial": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.3",
            "ap_model": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.4",
            "ap_sw_version": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.6",
            "ap_status": "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.19",
        },
        # Dell (674)
        "dell": {
            "serial": "1.3.6.1.4.1.674.10892.5.1.3.2.0",
            "model": "1.3.6.1.4.1.674.10892.5.1.3.12.0",
        },
        # Synology (6574)
        "synology": {
            "model": "1.3.6.1.4.1.6574.1.5.1.0",
            "serial": "1.3.6.1.4.1.6574.1.5.2.0",
            "version": "1.3.6.1.4.1.6574.1.5.3.0",
            "temperature": "1.3.6.1.4.1.6574.1.2.0",
            "cpu_fan": "1.3.6.1.4.1.6574.1.4.1.0",
            "disk_count": "1.3.6.1.4.1.6574.2.1.1.2.0",
        },
        # Synology Storage OIDs (6574)
        "synology_storage": {
            # Volumi
            "volume_count": "1.3.6.1.4.1.6574.2.1.1.1",  # Numero volumi (table)
            "volume_name": "1.3.6.1.4.1.6574.2.1.1.2",   # Nome volumi (table)
            "volume_status": "1.3.6.1.4.1.6574.2.1.1.5",  # Stato volumi (table)
            "volume_total": "1.3.6.1.4.1.6574.2.1.1.6",  # Dimensione totale volumi (table)
            "volume_used": "1.3.6.1.4.1.6574.2.1.1.7",   # Spazio utilizzato volumi (table)
            "volume_free": "1.3.6.1.4.1.6574.2.1.1.8",   # Spazio libero volumi (table)
            # Dischi
            "disk_index": "1.3.6.1.4.1.6574.2.1.1.1",    # Indice dischi (table)
            "disk_name": "1.3.6.1.4.1.6574.2.1.1.2",     # Nome dischi (table)
            "disk_status": "1.3.6.1.4.1.6574.2.1.1.3",   # Stato dischi (table)
            "disk_model": "1.3.6.1.4.1.6574.2.1.1.5",    # Modello dischi (table)
            "disk_temperature": "1.3.6.1.4.1.6574.2.1.1.6", # Temperatura dischi (table)
            "disk_smart_status": "1.3.6.1.4.1.6574.2.1.1.7", # SMART status dischi (table)
            # RAID
            "raid_index": "1.3.6.1.4.1.6574.3.1.1.1",    # Indice RAID (table)
            "raid_name": "1.3.6.1.4.1.6574.3.1.1.2",     # Nome RAID (table)
            "raid_status": "1.3.6.1.4.1.6574.3.1.1.3",   # Stato RAID (table)
            "raid_level": "1.3.6.1.4.1.6574.3.1.1.4",    # Livello RAID (table)
        },
        # QNAP (24681)
        "qnap": {
            "model": "1.3.6.1.4.1.24681.1.2.12.0",
            "serial": "1.3.6.1.4.1.24681.1.2.13.0",
            "version": "1.3.6.1.4.1.24681.1.2.14.0",
            "cpu_temp": "1.3.6.1.4.1.24681.1.2.5.0",
            "sys_temp": "1.3.6.1.4.1.24681.1.2.6.0",
        },
        # QNAP Storage OIDs (24681)
        "qnap_storage": {
            # Volumi
            "volume_index": "1.3.6.1.4.1.24681.1.2.17.1.4.1",  # Indice volumi (table)
            "volume_name": "1.3.6.1.4.1.24681.1.2.17.1.4.2",  # Nome volumi (table)
            "volume_status": "1.3.6.1.4.1.24681.1.2.17.1.4.3", # Stato volumi (table)
            "volume_total": "1.3.6.1.4.1.24681.1.2.17.1.4.4",  # Dimensione totale volumi (table)
            "volume_used": "1.3.6.1.4.1.24681.1.2.17.1.4.5",  # Spazio utilizzato volumi (table)
            "volume_free": "1.3.6.1.4.1.24681.1.2.17.1.4.6",  # Spazio libero volumi (table)
            # Dischi
            "disk_index": "1.3.6.1.4.1.24681.1.2.11.1.1",     # Indice dischi (table)
            "disk_name": "1.3.6.1.4.1.24681.1.2.11.1.2",     # Nome dischi (table)
            "disk_status": "1.3.6.1.4.1.24681.1.2.11.1.3",   # Stato dischi (table)
            "disk_model": "1.3.6.1.4.1.24681.1.2.11.1.4",    # Modello dischi (table)
            "disk_temperature": "1.3.6.1.4.1.24681.1.2.11.1.5", # Temperatura dischi (table)
            # RAID
            "raid_index": "1.3.6.1.4.1.24681.1.2.12.1.1",    # Indice RAID (table)
            "raid_name": "1.3.6.1.4.1.24681.1.2.12.1.2",    # Nome RAID (table)
            "raid_status": "1.3.6.1.4.1.24681.1.2.12.1.3",  # Stato RAID (table)
            "raid_level": "1.3.6.1.4.1.24681.1.2.12.1.4",    # Livello RAID (table)
        },
        # APC (318)
        "apc": {
            "model": "1.3.6.1.4.1.318.1.1.1.1.1.1.0",
            "serial": "1.3.6.1.4.1.318.1.1.1.1.2.3.0",
            "firmware": "1.3.6.1.4.1.318.1.1.1.1.2.1.0",
            "battery_status": "1.3.6.1.4.1.318.1.1.1.2.1.1.0",
            "battery_capacity": "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
            "battery_runtime": "1.3.6.1.4.1.318.1.1.1.2.2.3.0",
            "output_load": "1.3.6.1.4.1.318.1.1.1.4.2.3.0",
        },
        # Fortinet (12356)
        "fortinet": {
            "serial": "1.3.6.1.4.1.12356.100.1.1.1.0",
            "model": "1.3.6.1.4.1.12356.100.1.1.2.0",
            "version": "1.3.6.1.4.1.12356.100.1.1.3.0",
            "cpu_usage": "1.3.6.1.4.1.12356.101.4.1.3.0",
            "mem_usage": "1.3.6.1.4.1.12356.101.4.1.4.0",
            "sessions": "1.3.6.1.4.1.12356.101.4.1.8.0",
        },
        # Juniper (2636)
        "juniper": {
            "serial": "1.3.6.1.4.1.2636.3.1.3.0",
            "model": "1.3.6.1.4.1.2636.3.1.2.0",
        },
        # TP-Link/Omada (11863)
        "tp-link": {
            "model": "1.3.6.1.4.1.11863.1.1.1.1.0",
            "description": "1.3.6.1.4.1.11863.1.1.1.2.0",
            "hw_version": "1.3.6.1.4.1.11863.1.1.1.3.0",
            "fw_version": "1.3.6.1.4.1.11863.1.1.1.4.0",
            "serial": "1.3.6.1.4.1.11863.1.1.1.5.0",
            "mac": "1.3.6.1.4.1.11863.1.1.1.6.0",
            "version": "1.3.6.1.4.1.11863.1.1.1.4.0",  # Alias per compatibilità
            "serial": "1.3.6.1.4.1.11863.1.1.1.3.0",
        },
    }
    
    info = {}
    dispatcher = SnmpDispatcher()
    
    async def query_oid(oid: str) -> Optional[str]:
        """Query single OID and return value"""
        try:
            errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
                dispatcher,
                CommunityData(community, mpModel=1 if version == "2c" else 0),
                transport,
                ObjectType(ObjectIdentity(oid))
            )
            if not errorIndication and not errorStatus:
                for varBind in varBinds:
                    value = str(varBind[1])
                    if value and "No Such" not in value and value != "":
                        return value
        except:
            pass
        return None
    
    async def query_table(oid_base: str, max_rows: int = 100) -> List[Dict[str, Any]]:
        """Query SNMP table (walk) and return list of rows"""
        results = []
        try:
            count = 0
            # next_cmd restituisce un async iterator
            # Deve essere chiamato correttamente per essere iterabile
            async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                dispatcher,
                CommunityData(community, mpModel=1 if version == "2c" else 0),
                transport,
                ObjectType(ObjectIdentity(oid_base)),
                lexicographicMode=False
            ):
                if errorIndication or errorStatus:
                    break
                if count >= max_rows:
                    break
                row = {}
                for varBind in varBinds:
                    oid_str = str(varBind[0])
                    value = str(varBind[1])
                    if value and "No Such" not in value and value != "":
                        # Extract index from OID
                        index = oid_str.split('.')[-1] if '.' in oid_str else oid_str
                        row[oid_str] = value
                if row:
                    results.append(row)
                count += 1
        except Exception as e:
            logger.debug(f"query_table error for {oid_base}: {e}")
        return results
    
    async def walk_oid(oid_base: str, max_rows: int = 200) -> Dict[str, str]:
        """Helper per walk SNMP che restituisce dict {oid: value}"""
        result_dict = {}
        try:
            # In pysnmp 7 v1arch.asyncio, next_cmd deve essere chiamato ripetutamente in un loop
            # Ogni chiamata restituisce il prossimo elemento della tabella
            # L'OID viene aggiornato con l'ultimo OID ricevuto per continuare il walk
            current_oid = ObjectIdentity(oid_base)
            count = 0
            
            while count < max_rows:
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(current_oid),
                        lexicographicMode=False
                    )
                    
                    if errorIndication:
                        logger.debug(f"walk_oid error indication for {oid_base}: {errorIndication}")
                        break
                    if errorStatus:
                        # noSuchName o endOfMibView significa fine della tabella
                        if hasattr(errorStatus, 'prettyPrint'):
                            error_str = errorStatus.prettyPrint()
                            if 'noSuchName' in error_str.lower() or 'endOfMibView' in error_str.lower():
                                break
                        logger.debug(f"walk_oid error status for {oid_base}: {errorStatus.prettyPrint() if hasattr(errorStatus, 'prettyPrint') else errorStatus}")
                        break
                    
                    if not varBinds:
                        break
                    
                    # Processa i risultati e aggiorna current_oid per la prossima iterazione
                    should_stop = False
                    for varBind in varBinds:
                        oid_str = str(varBind[0])
                        value_obj = varBind[1]
                        
                        # Verifica che l'OID sia ancora sotto l'OID base
                        if not oid_str.startswith(oid_base + '.'):
                            should_stop = True
                            break
                        
                        # Estrai valore in modo corretto in base al tipo SNMP
                        try:
                            from pysnmp.proto.rfc1902 import OctetString, Integer, Counter32, Counter64, Gauge32, TimeTicks
                            
                            # Gestisci diversi tipi SNMP correttamente
                            if isinstance(value_obj, OctetString):
                                # OctetString: potrebbe essere testo o binario (es. MAC address)
                                raw_bytes = value_obj.asOctets()
                                
                                # MAC address: esattamente 6 byte binari e NON tutti caratteri ASCII stampabili
                                # Distingui tra MAC (byte non stampabili) e testo (caratteri ASCII)
                                if len(raw_bytes) == 6:
                                    # Controlla se tutti i byte sono caratteri ASCII stampabili (32-126)
                                    all_printable = all(32 <= b <= 126 for b in raw_bytes)
                                    if all_printable:
                                        # È testo ASCII, non un MAC
                                        value_str = raw_bytes.decode('utf-8', errors='replace').strip()
                                    else:
                                        # È un MAC address, converti in formato hex xx:xx:xx:xx:xx:xx
                                        value_str = ':'.join(f'{b:02x}' for b in raw_bytes)
                                else:
                                    # Prova a decodificare come UTF-8
                                    try:
                                        value_str = raw_bytes.decode('utf-8', errors='strict').strip()
                                    except UnicodeDecodeError:
                                        # Se contiene caratteri non-UTF8, potrebbe essere binario
                                        # Controlla se la maggior parte dei byte sono stampabili
                                        printable_count = sum(1 for b in raw_bytes if 32 <= b < 127)
                                        if printable_count > len(raw_bytes) * 0.7:
                                            # Principalmente testo, usa replace per caratteri invalidi
                                            value_str = raw_bytes.decode('utf-8', errors='replace').strip()
                                        else:
                                            # Principalmente binario, converti in hex
                                            value_str = raw_bytes.hex()
                                            # Se sembra un MAC (12 caratteri hex), formatta come MAC
                                            if len(value_str) == 12:
                                                value_str = ':'.join(value_str[i:i+2] for i in range(0, 12, 2))
                            elif isinstance(value_obj, (Integer, Counter32, Counter64, Gauge32, TimeTicks)):
                                # Numeri: converti direttamente
                                value_str = str(int(value_obj))
                            elif hasattr(value_obj, 'prettyPrint'):
                                # Altri tipi: usa prettyPrint
                                value_str = value_obj.prettyPrint()
                            else:
                                # Fallback: usa str()
                                value_str = str(value_obj)
                            
                            # Pulisci valore da caratteri non stampabili e null
                            value_str = ''.join(c for c in value_str if c.isprintable() or c in '\n\r\t').strip()
                            # Rimuovi caratteri null
                            value_str = value_str.replace('\x00', '').strip()
                            
                            if value_str and "No Such" not in value_str and value_str != "":
                                result_dict[oid_str] = value_str
                                # Aggiorna current_oid con l'ultimo OID ricevuto per continuare il walk
                                current_oid = varBind[0]
                        except Exception as e:
                            logger.debug(f"walk_oid value extraction error for {oid_str}: {e}")
                            continue
                    
                    if should_stop:
                        break
                    
                    count += 1
                except Exception as e:
                    logger.debug(f"walk_oid next_cmd error for {oid_base}: {e}")
                    break
        except Exception as e:
            logger.debug(f"walk_oid error for {oid_base}: {e}", exc_info=True)
        return result_dict
    
    try:
        transport = await UdpTransportTarget.create(
            (target, port),
            timeout=10,
            retries=2
        )
        
        # ==========================================
        # QUERY BASIC INFO
        # ==========================================
        for name, oid in oids_basic.items():
            value = await query_oid(oid)
            if value:
                info[name] = value
        
        # ==========================================
        # QUERY INTERFACE COUNT
        # ==========================================
        for name, oid in oids_interfaces.items():
            value = await query_oid(oid)
            if value:
                try:
                    info["interface_count"] = int(value)
                except:
                    pass
        
        # ==========================================
        # QUERY ENTITY MIB
        # ==========================================
        for name, oid in oids_entity.items():
            value = await query_oid(oid)
            if value:
                info[name] = value
        
        # ==========================================
        # QUERY HOST RESOURCES (for servers)
        # ==========================================
        for name, oid in oids_host.items():
            value = await query_oid(oid)
            if value:
                info[name] = value
        
        # ==========================================
        # DETECT VENDOR FROM sysObjectID
        # ==========================================
        sys_oid = info.get("sysObjectID", "")
        sys_descr = info.get("sysDescr", "").lower()
        detected_vendor = None
        device_type = "network"
        category = "unknown"
        
        # Vendor detection (basato su sysObjectID prefix)
        vendor_patterns = {
            "1.3.6.1.4.1.41112": ("Ubiquiti", "ubiquiti"),
            "1.3.6.1.4.1.10002": ("Ubiquiti", "ubiquiti"),  # UBNT
            "1.3.6.1.4.1.4413": ("Ubiquiti", "ubiquiti"),  # Ubiquiti Networks (USW, USXG, etc.)
            "1.3.6.1.4.1.14988": ("MikroTik", "mikrotik"),
            "1.3.6.1.4.1.9.": ("Cisco", "cisco"),
            "1.3.6.1.4.1.11.2.3.7.11": ("HP ProCurve", "hp_procurve"),  # HP ProCurve
            "1.3.6.1.4.1.11.2.3.7.8": ("HP ProCurve", "hp_procurve"),  # HP ProCurve older
            "1.3.6.1.4.1.25506": ("HP Comware", "hp_comware"),  # H3C/Comware
            "1.3.6.1.4.1.2011": ("HP Comware", "hp_comware"),  # Huawei (Comware compatible)
            "1.3.6.1.4.1.14823.1.1": ("Aruba Controller", "aruba"),  # Aruba Controller
            "1.3.6.1.4.1.14823.1.2": ("Aruba AP", "aruba"),  # Aruba AP
            "1.3.6.1.4.1.14823.2.3": ("Aruba Switch", "aruba"),  # Aruba Switch
            "1.3.6.1.4.1.11.": ("HP", "hp"),  # HP generic (fallback)
            "1.3.6.1.4.1.674": ("Dell", "dell"),
            "1.3.6.1.4.1.6574": ("Synology", "synology"),
            "1.3.6.1.4.1.24681": ("QNAP", "qnap"),
            "1.3.6.1.4.1.318": ("APC", "apc"),
            "1.3.6.1.4.1.12356": ("Fortinet", "fortinet"),
            "1.3.6.1.4.1.2636": ("Juniper", "juniper"),
            "1.3.6.1.4.1.11863": ("TP-Link", "tp-link"),
        }
        
        for prefix, (vendor_name, vendor_key) in vendor_patterns.items():
            if sys_oid.startswith(prefix):
                info["vendor"] = vendor_name
                detected_vendor = vendor_key
                break
        
        # Fallback vendor detection from sysDescr
        if not detected_vendor:
            descr_vendors = {
                "ubiquiti": "Ubiquiti", "unifi": "Ubiquiti", "ubnt": "Ubiquiti",
                "mikrotik": "MikroTik", "routeros": "MikroTik",
                "cisco": "Cisco", "ios": "Cisco",
                "hp ": "HP", "procurve": "HP", "aruba": "HP",
                "dell": "Dell",
                "synology": "Synology", "dsm": "Synology",
                "qnap": "QNAP", "qts": "QNAP",
                "apc": "APC",
                "fortinet": "Fortinet", "fortigate": "Fortinet",
                "juniper": "Juniper", "junos": "Juniper",
                "tp-link": "TP-Link", "omada": "TP-Link", "tplink": "TP-Link",
            }
            for pattern, vendor_name in descr_vendors.items():
                if pattern in sys_descr:
                    info["vendor"] = vendor_name
                    detected_vendor = pattern.split()[0]
                    break
        
        # Fallback vendor detection from model name (per UniFi che spesso ha sysObjectID generico)
        if not detected_vendor:
            model = info.get("model", "").lower()
            hostname = info.get("sysName", "").lower()
            if any(x in model for x in ["usw", "uap", "usg", "unifi", "ubiquiti", "edge", "edgerouter", "edgeswitch"]):
                info["vendor"] = "Ubiquiti"
                detected_vendor = "ubiquiti"
            elif any(x in hostname for x in ["usw", "uap", "usg", "unifi", "ubiquiti", "edge", "edgerouter", "edgeswitch"]):
                info["vendor"] = "Ubiquiti"
                detected_vendor = "ubiquiti"
        
        # ==========================================
        # QUERY VENDOR-SPECIFIC OIDs
        # ==========================================
        # Mappa vendor detection a vendor_oids keys
        vendor_oid_key = detected_vendor
        if detected_vendor == "hp_procurve" and "hp_procurve" not in vendor_oids:
            vendor_oid_key = "hp"  # Fallback a hp generico
        elif detected_vendor == "hp_comware" and "hp_comware" not in vendor_oids:
            vendor_oid_key = "hp"  # Fallback a hp generico
        
        if detected_vendor and vendor_oid_key in vendor_oids:
            logger.info(f"SNMP probe: Querying vendor-specific OIDs for {detected_vendor} (using {vendor_oid_key} OIDs)")
            # Prova prima vendor-specific, poi fallback
            oids_to_query = {}
            if detected_vendor in vendor_oids:
                oids_to_query = vendor_oids[detected_vendor]
            elif vendor_oid_key in vendor_oids:
                oids_to_query = vendor_oids[vendor_oid_key]
            
            for name, oid in oids_to_query.items():
                # Skip scalar versions if base OID exists
                if name.endswith("_scalar"):
                    continue
                value = await query_oid(oid)
                if not value and name + "_scalar" in oids_to_query:
                    # Try scalar version as fallback
                    scalar_oid = oids_to_query[name + "_scalar"]
                    logger.debug(f"SNMP probe: Trying scalar OID {scalar_oid} for {name}")
                    value = await query_oid(scalar_oid)
                if value:
                    info[f"vendor_{name}"] = value
                    logger.info(f"SNMP probe: Collected vendor_{name}={value} from OID {oid}")
                    # Per Ubiquiti, salva anche direttamente in info per compatibilità
                    if detected_vendor == "ubiquiti":
                        if name == "model":
                            info["ubiquiti_model"] = value
                            info["model"] = value  # Salva anche direttamente in model
                        elif name == "version":
                            info["ubiquiti_firmware"] = value
                            info["firmware_version"] = value  # Salva anche direttamente in firmware_version
                        elif name == "wifi_clients":
                            info["wifi_clients"] = value
                        elif name == "load_average_1m":
                            info["load_average_1m"] = value
                        elif name == "ram_available":
                            info["ram_available_mb"] = value
                else:
                    logger.debug(f"SNMP probe: No value for vendor_{name} (OID {oid})")
        
        # ==========================================
        # DETERMINE DEVICE TYPE AND CATEGORY
        # ==========================================
        # Check sysDescr for device type hints
        if any(x in sys_descr for x in ["uap", "u6-", "u7-", "unifi ap", "access point"]):
            device_type = "ap"
            category = "wireless"
        elif any(x in sys_descr for x in ["usw", "switch", "procurve", "catalyst"]):
            device_type = "switch"
            category = "network"
        elif any(x in sys_descr for x in ["router", "routeros", "usg", "fortigate", "firewall"]):
            device_type = "router"
            category = "network"
        elif any(x in sys_descr for x in ["nas", "synology", "qnap", "diskstation"]):
            device_type = "storage"
            category = "storage"
            # Imposta os_family per Synology/QNAP
            if "synology" in sys_descr.lower() or "diskstation" in sys_descr.lower():
                info["os_family"] = "Linux"
                info["os_name"] = "DSM"
            elif "qnap" in sys_descr.lower():
                info["os_family"] = "Linux"
                info["os_name"] = "QTS"
        elif any(x in sys_descr for x in ["ups", "apc", "smart-ups"]):
            device_type = "ups"
            category = "power"
        elif any(x in sys_descr for x in ["linux", "windows", "server"]):
            device_type = "server"
            category = "server"
        
        info["device_type"] = device_type
        info["category"] = category
        
        # ==========================================
        # STORAGE INFO COLLECTION (Synology/QNAP)
        # ==========================================
        vendor_name = info.get("vendor", "")
        is_storage_device = device_type == "storage" or device_type == "nas" or vendor_name in ["Synology", "QNAP"]
        
        if is_storage_device and vendor_name == "Synology":
            logger.info(f"SNMP probe: Collecting storage info for Synology device {target}")
            storage_info = {}
            
            try:
                # Volumi Synology
                volumes = []
                volume_names = {}
                volume_statuses = {}
                volume_totals = {}
                volume_useds = {}
                volume_frees = {}
                
                # Walk volume table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["synology_storage"]["volume_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                volume_names[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: Synology volume name walk failed: {e}")
                logger.info(f"SNMP probe: Synology volume names collected: {len(volume_names)}")
                
                # Walk volume status, total, used, free
                for oid_type in ["volume_status", "volume_total", "volume_used", "volume_free"]:
                    oid = vendor_oids["synology_storage"][oid_type]
                    try:
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "volume_status":
                                        volume_statuses[index] = value
                                    elif oid_type == "volume_total":
                                        try:
                                            volume_totals[index] = int(value) / (1024 * 1024 * 1024)  # Converti bytes to GB
                                        except:
                                            pass
                                    elif oid_type == "volume_used":
                                        try:
                                            volume_useds[index] = int(value) / (1024 * 1024 * 1024)
                                        except:
                                            pass
                                    elif oid_type == "volume_free":
                                        try:
                                            volume_frees[index] = int(value) / (1024 * 1024 * 1024)
                                        except:
                                            pass
                    except Exception as e:
                        logger.debug(f"SNMP probe: Synology {oid_type} walk failed: {e}")
                
                # Build volumes list
                for index in volume_names.keys():
                    total_gb = volume_totals.get(index, 0)
                    used_gb = volume_useds.get(index, 0)
                    free_gb = volume_frees.get(index, 0)
                    usage_percent = (used_gb / total_gb * 100) if total_gb > 0 else 0
                    
                    volumes.append({
                        "name": volume_names.get(index, f"volume{index}"),
                        "mount_point": f"/volume{index}",
                        "total_gb": round(total_gb, 2),
                        "used_gb": round(used_gb, 2),
                        "free_gb": round(free_gb, 2),
                        "filesystem": "ext4",  # Default per Synology
                        "usage_percent": round(usage_percent, 1),
                        "status": volume_statuses.get(index, "unknown")
                    })
                
                if volumes:
                    storage_info["volumes"] = volumes
                
                # Dischi Synology
                disks = []
                disk_names = {}
                disk_statuses = {}
                disk_models = {}
                disk_temperatures = {}
                
                # Walk disk table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["synology_storage"]["disk_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                disk_names[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: Synology disk name walk failed: {e}")
                logger.info(f"SNMP probe: Synology disk names collected: {len(disk_names)}")
                
                # Walk disk status, model, temperature
                for oid_type in ["disk_status", "disk_model", "disk_temperature"]:
                    oid = vendor_oids["synology_storage"][oid_type]
                    try:
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "disk_status":
                                        disk_statuses[index] = value
                                    elif oid_type == "disk_model":
                                        disk_models[index] = value
                                    elif oid_type == "disk_temperature":
                                        try:
                                            disk_temperatures[index] = int(value)
                                        except:
                                            pass
                    except Exception as e:
                        logger.debug(f"SNMP probe: Synology {oid_type} walk failed: {e}")
                
                # Build disks list
                for index in disk_names.keys():
                    health = "good" if disk_statuses.get(index, "").lower() in ["normal", "healthy"] else "warning"
                    disks.append({
                        "name": disk_names.get(index, f"disk{index}"),
                        "model": disk_models.get(index, ""),
                        "health": health,
                        "temperature": disk_temperatures.get(index)
                    })
                
                if disks:
                    storage_info["disks"] = disks
                
                # RAID Synology
                raid_names = {}
                raid_statuses = {}
                raid_levels = {}
                
                # Walk RAID table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["synology_storage"]["raid_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                raid_names[index] = value
                    
                    # Walk RAID status and level
                    for oid_type in ["raid_status", "raid_level"]:
                        oid = vendor_oids["synology_storage"][oid_type]
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "raid_status":
                                        raid_statuses[index] = value
                                    elif oid_type == "raid_level":
                                        raid_levels[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: Synology RAID walk failed: {e}")
                logger.info(f"SNMP probe: Synology RAID names collected: {len(raid_names)}")
                
                # Build RAID info
                if raid_names:
                    raid_devices = list(raid_names.values())
                    raid_status = raid_statuses.get(list(raid_names.keys())[0], "unknown")
                    raid_level = raid_levels.get(list(raid_names.keys())[0], "unknown")
                    degraded = "degraded" in raid_status.lower() or "error" in raid_status.lower()
                    
                    storage_info["raid"] = {
                        "level": raid_level,
                        "status": raid_status,
                        "devices": raid_devices,
                        "degraded": degraded
                    }
                
                # Temperatura sistema (già raccolta sopra)
                if info.get("temperature"):
                    storage_info["temperature"] = {
                        "system": int(info["temperature"]) if str(info["temperature"]).isdigit() else None
                    }
                
                if storage_info:
                    info["storage_info"] = storage_info
                    logger.info(f"SNMP probe: Collected storage info for Synology: {len(volumes)} volumes, {len(disks)} disks")
            except Exception as e:
                logger.warning(f"SNMP probe: Error collecting Synology storage info: {e}", exc_info=True)
        
        elif is_storage_device and vendor_name == "QNAP":
            logger.info(f"SNMP probe: Collecting storage info for QNAP device {target} (sysObjectID={sys_oid})")
            storage_info = {}
            
            try:
                # Volumi QNAP
                volumes = []
                volume_names = {}
                volume_statuses = {}
                volume_totals = {}
                volume_useds = {}
                volume_frees = {}
                
                # Walk volume table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["qnap_storage"]["volume_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                volume_names[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: QNAP volume name walk failed: {e}")
                logger.info(f"SNMP probe: QNAP volume names collected: {len(volume_names)}")
                
                # Walk volume status, total, used, free
                for oid_type in ["volume_status", "volume_total", "volume_used", "volume_free"]:
                    oid = vendor_oids["qnap_storage"][oid_type]
                    try:
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "volume_status":
                                        volume_statuses[index] = value
                                    elif oid_type == "volume_total":
                                        try:
                                            volume_totals[index] = int(value) / (1024 * 1024 * 1024)  # Converti bytes to GB
                                        except:
                                            pass
                                    elif oid_type == "volume_used":
                                        try:
                                            volume_useds[index] = int(value) / (1024 * 1024 * 1024)
                                        except:
                                            pass
                                    elif oid_type == "volume_free":
                                        try:
                                            volume_frees[index] = int(value) / (1024 * 1024 * 1024)
                                        except:
                                            pass
                    except Exception as e:
                        logger.debug(f"SNMP probe: QNAP {oid_type} walk failed: {e}")
                
                # Build volumes list
                for index in volume_names.keys():
                    total_gb = volume_totals.get(index, 0)
                    used_gb = volume_useds.get(index, 0)
                    free_gb = volume_frees.get(index, 0)
                    usage_percent = (used_gb / total_gb * 100) if total_gb > 0 else 0
                    
                    volumes.append({
                        "name": volume_names.get(index, f"volume{index}"),
                        "mount_point": f"/share/{volume_names.get(index, f'volume{index}')}",
                        "total_gb": round(total_gb, 2),
                        "used_gb": round(used_gb, 2),
                        "free_gb": round(free_gb, 2),
                        "filesystem": "ext4",
                        "usage_percent": round(usage_percent, 1),
                        "status": volume_statuses.get(index, "unknown")
                    })
                
                if volumes:
                    storage_info["volumes"] = volumes
                
                # Dischi QNAP
                disks = []
                disk_names = {}
                disk_statuses = {}
                disk_models = {}
                disk_temperatures = {}
                
                # Walk disk table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["qnap_storage"]["disk_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                disk_names[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: QNAP disk name walk failed: {e}")
                logger.info(f"SNMP probe: QNAP disk names collected: {len(disk_names)}")
                
                # Walk disk status, model, temperature
                for oid_type in ["disk_status", "disk_model", "disk_temperature"]:
                    oid = vendor_oids["qnap_storage"][oid_type]
                    try:
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "disk_status":
                                        disk_statuses[index] = value
                                    elif oid_type == "disk_model":
                                        disk_models[index] = value
                                    elif oid_type == "disk_temperature":
                                        try:
                                            disk_temperatures[index] = int(value)
                                        except:
                                            pass
                    except Exception as e:
                        logger.debug(f"SNMP probe: QNAP {oid_type} walk failed: {e}")
                
                # Build disks list
                for index in disk_names.keys():
                    health = "good" if disk_statuses.get(index, "").lower() in ["normal", "healthy", "ready"] else "warning"
                    disks.append({
                        "name": disk_names.get(index, f"disk{index}"),
                        "model": disk_models.get(index, ""),
                        "health": health,
                        "temperature": disk_temperatures.get(index)
                    })
                
                if disks:
                    storage_info["disks"] = disks
                
                # RAID QNAP
                raid_names = {}
                raid_statuses = {}
                raid_levels = {}
                
                # Walk RAID table
                try:
                    async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                        dispatcher,
                        CommunityData(community, mpModel=1 if version == "2c" else 0),
                        transport,
                        ObjectType(ObjectIdentity(vendor_oids["qnap_storage"]["raid_name"])),
                        lexicographicMode=False
                    ):
                        if errorIndication or errorStatus:
                            break
                        for varBind in varBinds:
                            oid_str = str(varBind[0])
                            value = str(varBind[1])
                            if value and "No Such" not in value:
                                index = oid_str.split('.')[-1]
                                raid_names[index] = value
                    
                    # Walk RAID status and level
                    for oid_type in ["raid_status", "raid_level"]:
                        oid = vendor_oids["qnap_storage"][oid_type]
                        async for (errorIndication, errorStatus, errorIndex, varBinds) in next_cmd(
                            dispatcher,
                            CommunityData(community, mpModel=1 if version == "2c" else 0),
                            transport,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        ):
                            if errorIndication or errorStatus:
                                break
                            for varBind in varBinds:
                                oid_str = str(varBind[0])
                                value = str(varBind[1])
                                if value and "No Such" not in value:
                                    index = oid_str.split('.')[-1]
                                    if oid_type == "raid_status":
                                        raid_statuses[index] = value
                                    elif oid_type == "raid_level":
                                        raid_levels[index] = value
                except Exception as e:
                    logger.warning(f"SNMP probe: QNAP RAID walk failed: {e}")
                logger.info(f"SNMP probe: QNAP RAID names collected: {len(raid_names)}")
                
                # Build RAID info
                if raid_names:
                    raid_devices = list(raid_names.values())
                    raid_status = raid_statuses.get(list(raid_names.keys())[0], "unknown")
                    raid_level = raid_levels.get(list(raid_names.keys())[0], "unknown")
                    degraded = "degraded" in raid_status.lower() or "error" in raid_status.lower()
                    
                    storage_info["raid"] = {
                        "level": raid_level,
                        "status": raid_status,
                        "devices": raid_devices,
                        "degraded": degraded
                    }
                
                # Temperatura sistema
                temp_info = {}
                if info.get("cpu_temp"):
                    try:
                        temp_info["cpu"] = int(info["cpu_temp"])
                    except:
                        pass
                if info.get("sys_temp"):
                    try:
                        temp_info["system"] = int(info["sys_temp"])
                    except:
                        pass
                
                if temp_info:
                    storage_info["temperature"] = temp_info
                
                if storage_info:
                    info["storage_info"] = storage_info
                    logger.info(f"SNMP probe: Collected storage info for QNAP: {len(volumes)} volumes, {len(disks)} disks")
            except Exception as e:
                logger.warning(f"SNMP probe: Error collecting QNAP storage info: {e}", exc_info=True)
        
        # ==========================================
        # EXTRACT NORMALIZED FIELDS
        # ==========================================
        # Model - check multiple sources
        info["model"] = (
            info.get("model") or  # Già impostato da vendor-specific
            info.get("vendor_board_name") or  # MikroTik board_name
            info.get("vendor_model") or
            info.get("entPhysicalModelName") or
            info.get("vendor_product_number") or  # HP ProCurve product_number
            info.get("entPhysicalName") or
            info.get("ubiquiti_model") or  # Ubiquiti model
            info.get("vendor_ap_model") or  # Ubiquiti AP model
            info.get("vendor_sw_model") or  # Ubiquiti Switch model
            _extract_model_from_descr(info.get("sysDescr", ""))
        )
        
        # Serial - check multiple sources
        info["serial_number"] = (
            info.get("serial_number") or  # Già impostato da vendor-specific
            info.get("entPhysicalSerialNum") or
            info.get("vendor_serial") or
            info.get("vendor_sw_serial") or  # Ubiquiti Switch serial
            info.get("vendor_switch_serial")  # Aruba switch serial
        )
        
        # Firmware - check multiple sources
        info["firmware_version"] = (
            info.get("firmware_version") or  # Già impostato da vendor-specific
            info.get("vendor_firmware_version") or  # MikroTik firmware_version
            info.get("vendor_firmware") or
            info.get("entPhysicalFirmwareRev") or
            info.get("vendor_version") or
            info.get("vendor_license_version") or  # MikroTik license_version (RouterOS)
            info.get("vendor_os_version") or  # HP ProCurve os_version
            info.get("vendor_sw_version") or  # ArubaOS sw_version
            info.get("vendor_fw_version") or  # TP-Link fw_version
            info.get("vendor_ap_version") or  # Ubiquiti AP version
            info.get("ubiquiti_firmware") or  # Ubiquiti firmware
            info.get("entPhysicalSoftwareRev")
        )
        
        # Hardware version
        if not info.get("hardware_version"):
            info["hardware_version"] = (
                info.get("vendor_hw_version") or
                info.get("entPhysicalHardwareRev")
            )
        
        # Manufacturer
        info["manufacturer"] = (
            info.get("vendor") or
            info.get("entPhysicalMfgName")
        )
        
        # Parse uptime
        if info.get("sysUpTime"):
            try:
                ticks = int(info["sysUpTime"])
                seconds = ticks // 100
                days = seconds // 86400
                hours = (seconds % 86400) // 3600
                info["uptime_formatted"] = f"{days}d {hours}h"
                info["uptime_seconds"] = seconds
            except:
                pass
        
        # ==========================================
        # COLLECT ADVANCED DATA FOR NETWORK DEVICES
        # ==========================================
        # Considera dispositivo di rete se:
        # - device_type è router/switch/ap/network
        # - category è network
        # - vendor è un vendor di rete (Cisco, HP, Ubiquiti, etc.)
        vendor_lower = info.get("vendor", "").lower()
        is_network_device = (
            device_type in ["router", "switch", "ap", "network"] or
            category == "network" or
            vendor_lower in ["cisco", "hp", "ubiquiti", "mikrotik", "aruba", "juniper", "fortinet", "dell", "tp-link"]
        )
        is_router = device_type == "router"
        
        logger.info(f"SNMP probe: device_type={device_type}, category={category}, vendor={info.get('vendor', 'unknown')}, vendor_lower={vendor_lower}, sysObjectID={sys_oid}")
        logger.info(f"SNMP probe: is_network_device check: device_type in network_types={device_type in ['router', 'switch', 'ap', 'network']}, category==network={category == 'network'}, vendor in network_vendors={vendor_lower in ['cisco', 'hp', 'ubiquiti', 'mikrotik', 'aruba', 'juniper', 'fortinet', 'dell', 'tp-link']}")
        logger.info(f"SNMP probe: is_network_device={is_network_device}, is_router={is_router}")
        
        if is_network_device:
            logger.info(f"SNMP probe: Starting advanced data collection for network device {target}")
            logger.info(f"SNMP probe: Collecting advanced data for network device {target} (type={device_type}, vendor={info.get('vendor', 'unknown')})")
            try:
                # ==========================================
                # LLDP NEIGHBORS (IEEE 802.1AB)
                # ==========================================
                logger.info(f"SNMP probe: [LLDP] Starting LLDP neighbor collection for {target}...")
                lldp_neighbors = []
                
                # LLDP Remote Table OIDs
                lldp_oids = {
                    "local_port": "1.0.8802.1.1.2.1.4.1.1.2",   # lldpRemLocalPortNum (corrected: was .1 which is TimeMark)
                    "chassis_id": "1.0.8802.1.1.2.1.4.1.1.5",   # lldpRemChassisId
                    "port_id": "1.0.8802.1.1.2.1.4.1.1.7",      # lldpRemPortId
                    "port_desc": "1.0.8802.1.1.2.1.4.1.1.8",    # lldpRemPortDesc
                    "sys_name": "1.0.8802.1.1.2.1.4.1.1.9",     # lldpRemSysName
                    "sys_desc": "1.0.8802.1.1.2.1.4.1.1.10",    # lldpRemSysDesc
                }
                
                # Try to walk LLDP table
                try:
                    # LLDP OID structure: lldpRemEntry = lldpRemLocalPortNum.timeMark.lldpRemLocalPortNum.lldpRemIndex
                    # OID format: 1.0.8802.1.1.2.1.4.1.1.X.timeMark.localPortNum.remoteIndex
                    # We need to match by timeMark.localPortNum.remoteIndex
                    
                    # Get local port numbers first
                    # LLDP OID structure: 1.0.8802.1.1.2.1.4.1.1.X.timeMark.localPortNum.remoteIndex
                    # Base OID length: 13 parts (1.0.8802.1.1.2.1.4.1.1.1)
                    # Index suffix: timeMark.localPortNum.remoteIndex (last 3 parts)
                    local_ports = {}  # Key: full OID suffix after base, Value: port number
                    try:
                        local_ports_raw = await walk_oid(lldp_oids["local_port"], max_rows=200)
                        base_oid_parts = lldp_oids["local_port"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in local_ports_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                # Extract index suffix (everything after base OID)
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    # Index suffix is everything after the base OID
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    # LLDP index format: timeMark.localPortNum.remoteIndex (3 parts)
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue  # Skip non-lldpRemTable entries
                                    # Store both the index and the port value
                                    local_ports[index_key] = {
                                        "port_value": str(value),
                                        "full_oid": oid_str
                                    }
                                    logger.debug(f"LLDP local_port: index={index_key}, value={value}, oid={oid_str}")
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP local_port walk error: {e}")
                    
                    logger.info(f"SNMP probe: [LLDP] Collected {len(local_ports)} LLDP local ports")
                    
                    # Get system names, chassis IDs, port IDs, and descriptions
                    sys_names = {}  # Key: index suffix, Value: system name
                    chassis_ids = {}  # Key: index suffix, Value: chassis ID
                    port_ids = {}  # Key: index suffix, Value: remote port ID
                    sys_descs = {}  # Key: index suffix, Value: system description
                    
                    # System names
                    logger.info(f"SNMP probe: [LLDP] Querying LLDP system names OID {lldp_oids['sys_name']}...")
                    try:
                        sys_names_raw = await walk_oid(lldp_oids["sys_name"], max_rows=200)
                        base_oid_parts = lldp_oids["sys_name"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in sys_names_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    # LLDP index format: timeMark.localPortNum.remoteIndex (3 parts)
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue  # Skip non-lldpRemTable entries
                                    sys_names[index_key] = str(value)
                                    logger.debug(f"LLDP sys_name: index={index_key}, value={value}")
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP sys_name walk error: {e}")
                    
                    # Chassis IDs
                    try:
                        chassis_ids_raw = await walk_oid(lldp_oids["chassis_id"], max_rows=200)
                        base_oid_parts = lldp_oids["chassis_id"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in chassis_ids_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    # LLDP index format: timeMark.localPortNum.remoteIndex (3 parts)
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue  # Skip non-lldpRemTable entries
                                    chassis_ids[index_key] = str(value)
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP chassis_id walk error: {e}")
                    
                    # System descriptions
                    try:
                        sys_descs_raw = await walk_oid(lldp_oids["sys_desc"], max_rows=200)
                        base_oid_parts = lldp_oids["sys_desc"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in sys_descs_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    # LLDP index format: timeMark.localPortNum.remoteIndex (3 parts)
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue  # Skip non-lldpRemTable entries
                                    sys_descs[index_key] = str(value)
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP sys_desc walk error: {e}")
                    
                    # Port IDs (remote port identifier)
                    try:
                        port_ids_raw = await walk_oid(lldp_oids["port_id"], max_rows=200)
                        base_oid_parts = lldp_oids["port_id"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in port_ids_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue
                                    port_ids[index_key] = str(value)
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP port_id walk error: {e}")
                    
                    # Port descriptions
                    port_descs = {}
                    try:
                        port_descs_raw = await walk_oid(lldp_oids["port_desc"], max_rows=200)
                        base_oid_parts = lldp_oids["port_desc"].split('.')
                        base_oid_len = len(base_oid_parts)
                        
                        for oid_str, value in port_descs_raw.items():
                            if value and "No Such" not in str(value) and str(value) != "":
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    index_key = '.'.join(oid_parts[base_oid_len:])
                                    index_parts = index_key.split('.')
                                    if len(index_parts) != 3:
                                        continue
                                    port_descs[index_key] = str(value)
                    except Exception as e:
                        logger.debug(f"SNMP probe: LLDP port_desc walk error: {e}")
                    
                    logger.info(f"SNMP probe: [LLDP] Collected {len(sys_names)} LLDP system names, {len(chassis_ids)} chassis IDs, {len(port_ids)} port IDs")
                    
                    # Match by index key to build neighbor list
                    # Also need to map port number to interface name using IF-MIB
                    interface_map = {}  # Map ifIndex to interface name
                    if info.get("interfaces"):
                        for iface in info.get("interfaces", []):
                            if_index = iface.get("if_index")
                            if_name = iface.get("name")
                            if if_index and if_name:
                                interface_map[str(if_index)] = if_name
                    
                    # Use local_ports, sys_names, or chassis_ids as primary keys (in order of preference)
                    # Some devices don't implement all LLDP OIDs
                    if local_ports:
                        primary_keys = local_ports
                    elif sys_names:
                        primary_keys = {k: {"port_value": ""} for k in sys_names}
                    elif chassis_ids:
                        # Fallback: use chassis_ids as keys (for devices without sys_names)
                        primary_keys = {k: {"port_value": ""} for k in chassis_ids}
                        logger.info(f"SNMP probe: [LLDP] Using chassis_ids as primary keys ({len(chassis_ids)} entries)")
                    else:
                        primary_keys = {}
                    
                    for index_key, port_data in list(primary_keys.items())[:50]:  # Limit to 50 neighbors
                        port_value = port_data.get("port_value", "") if isinstance(port_data, dict) else ""
                        # If port_value is empty, extract localPortNum from index (format: timeMark.localPortNum.remoteIndex)
                        if not port_value:
                            index_parts = index_key.split('.')
                            if len(index_parts) >= 2:
                                port_value = index_parts[1]  # localPortNum is the second part
                        
                        sys_name = sys_names.get(index_key, "")
                        chassis_id = chassis_ids.get(index_key, "")
                        sys_desc = sys_descs.get(index_key, "")
                        port_id = port_ids.get(index_key, "")
                        port_desc = port_descs.get(index_key, "")
                        
                        # Clean sys_name
                        sys_name_clean = ''
                        if sys_name and sys_name.strip():
                            sys_name_clean = ''.join(c for c in sys_name if c.isprintable() and ord(c) < 128).strip()
                            # Filter invalid values: only numbers, null chars, too short
                            if sys_name_clean.isdigit() or len(sys_name_clean) < 2:
                                sys_name_clean = ''
                        
                        # Valida chassis_id
                        chassis_id_clean = ''
                        if chassis_id:
                            chassis_id_clean = ''.join(c for c in str(chassis_id) if c.isprintable() and ord(c) < 128).strip()
                            if len(chassis_id_clean) < 2:
                                chassis_id_clean = ''
                        
                        # Se non abbiamo né sys_name né chassis_id, skip
                        if not sys_name_clean and not chassis_id_clean:
                            continue
                        
                        # Usa chassis_id come device name se sys_name non disponibile
                        device_name = sys_name_clean if sys_name_clean else chassis_id_clean
                        
                        # Valida sys_desc
                        sys_desc_clean = ''
                        if sys_desc:
                            sys_desc_clean = ''.join(c for c in str(sys_desc) if c.isprintable() and ord(c) < 128).strip()
                            if len(sys_desc_clean) < 2:
                                sys_desc_clean = ''
                        
                        # Valida port_id e port_desc
                        port_id_clean = ''
                        if port_id:
                            port_id_clean = ''.join(c for c in str(port_id) if c.isprintable() and ord(c) < 128).strip()
                        port_desc_clean = ''
                        if port_desc:
                            port_desc_clean = ''.join(c for c in str(port_desc) if c.isprintable() and ord(c) < 128).strip()
                        
                        # Map port number to interface name
                        local_if_name = interface_map.get(port_value, f"Interface {port_value}")
                        
                        # Solo aggiungi se abbiamo dati significativi
                        neighbor = {
                            "local_interface": local_if_name,
                            "local_interface_index": port_value,
                            "remote_device_name": device_name,
                            "remote_chassis_id": chassis_id_clean,
                            "remote_port_id": port_id_clean,
                            "remote_port_desc": port_desc_clean,
                            "remote_system_description": sys_desc_clean,
                            "discovered_by": "lldp"
                        }
                        lldp_neighbors.append(neighbor)
                    
                    logger.debug(f"SNMP probe: Built {len(lldp_neighbors)} LLDP neighbors from {len(local_ports)} ports and {len(sys_names)} names")
                    
                    if lldp_neighbors:
                        info["lldp_neighbors"] = lldp_neighbors
                        info["neighbors"] = lldp_neighbors  # Also set in neighbors for compatibility
                        info["lldp_neighbors_count"] = len(lldp_neighbors)
                        info["neighbors_count"] = len(lldp_neighbors)
                        logger.info(f"SNMP probe: [LLDP] ✓ Found {len(lldp_neighbors)} LLDP neighbors")
                    else:
                        logger.warning(f"SNMP probe: [LLDP] ✗ No LLDP neighbors found (sys_names={len(sys_names)}, local_ports={len(local_ports)})")
                except Exception as e:
                    logger.error(f"SNMP probe: [LLDP] ✗ LLDP query failed for {target}: {e}", exc_info=True)
                
                # ==========================================
                # CDP NEIGHBORS (Cisco Discovery Protocol)
                # ==========================================
                if detected_vendor == "cisco":
                    try:
                        logger.debug(f"Collecting CDP neighbors for Cisco device {target}...")
                        cdp_neighbors = []
                        
                        # CDP Cache OIDs
                        cdp_cache_device_id = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId
                        cdp_cache_port = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"        # cdpCacheDevicePort
                        cdp_cache_platform = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"    # cdpCachePlatform
                        cdp_cache_version = "1.3.6.1.4.1.9.9.23.1.2.1.1.9"      # cdpCacheVersion
                        
                        device_ids = await walk_oid(cdp_cache_device_id, max_rows=100)
                        ports = await walk_oid(cdp_cache_port, max_rows=100)
                        platforms = await walk_oid(cdp_cache_platform, max_rows=100)
                        
                        # Match by OID index
                        for oid, device_id in list(device_ids.items())[:50]:  # Limit to 50
                            neighbor = {
                                "remote_device_name": device_id,
                                "local_interface": ports.get(oid, ""),
                                "platform": platforms.get(oid, ""),
                                "discovered_by": "cdp"
                            }
                            if neighbor["remote_device_name"]:
                                cdp_neighbors.append(neighbor)
                        
                        if cdp_neighbors:
                            # Merge with LLDP neighbors if any
                            if "lldp_neighbors" in info:
                                info["neighbors"] = info["lldp_neighbors"] + cdp_neighbors
                            else:
                                info["neighbors"] = cdp_neighbors
                            info["neighbors_count"] = len(info["neighbors"])
                            logger.debug(f"Found {len(cdp_neighbors)} CDP neighbors")
                    except Exception as e:
                        logger.debug(f"CDP query failed: {e}")
                
                # ==========================================
                # ROUTING TABLE (IP Forwarding Table MIB)
                # ==========================================
                try:
                    logger.info(f"SNMP probe: Collecting routing table for {target}...")
                    routes = []
                    
                    # IP Route Table OIDs
                    ip_route_dest = "1.3.6.1.2.1.4.21.1.1"  # ipRouteDest
                    ip_route_next_hop = "1.3.6.1.2.1.4.21.1.7"  # ipRouteNextHop
                    ip_route_type = "1.3.6.1.2.1.4.21.1.8"  # ipRouteType
                    ip_route_proto = "1.3.6.1.2.1.4.21.1.9"  # ipRouteProto
                    
                    route_dests = await walk_oid(ip_route_dest, max_rows=200)
                    
                    next_hops = await walk_oid(ip_route_next_hop, max_rows=200)
                    
                    # Build route list
                    for oid, dest in list(route_dests.items())[:100]:
                        route = {
                            "dst": dest,
                            "gateway": next_hops.get(oid, ""),
                            "interface": ""  # Would need additional query for interface
                        }
                        routes.append(route)
                    
                    if routes:
                        info["routing_table"] = routes
                        info["routing_count"] = len(routes)
                        logger.info(f"SNMP probe: Found {len(routes)} routes")
                    else:
                        logger.debug(f"SNMP probe: No routes found (route_dests={len(route_dests)}, next_hops={len(next_hops)})")
                except Exception as e:
                    logger.warning(f"SNMP probe: Routing table query failed for {target}: {e}", exc_info=True)
                
                # ==========================================
                # ARP TABLE (SOLO per Router)
                # ==========================================
                if is_router:
                    try:
                        logger.info(f"SNMP probe: Collecting ARP table for router {target}...")
                        arp_entries = []
                        
                        # ARP Table OIDs - ipNetToMediaPhysAddress contiene MAC indexato per ifIndex.IP
                        # OID format: 1.3.6.1.2.1.4.22.1.2.ifIndex.IP1.IP2.IP3.IP4
                        arp_phys_address = "1.3.6.1.2.1.4.22.1.2"  # ipNetToMediaPhysAddress
                        
                        arp_macs_raw = await walk_oid(arp_phys_address, max_rows=500)
                        
                        # Parse OID to extract ifIndex and IP, value is MAC
                        base_oid = arp_phys_address + "."
                        for oid, mac in arp_macs_raw.items():
                            if not oid.startswith(base_oid):
                                continue
                            try:
                                # Estrai la parte dopo il base OID: ifIndex.IP1.IP2.IP3.IP4
                                suffix = oid[len(base_oid):]
                                parts = suffix.split('.')
                                if len(parts) >= 5:
                                    if_index = parts[0]
                                    ip_parts = parts[1:5]
                                    ip_address = '.'.join(ip_parts)
                                    
                                    # MAC: walk_oid già converte 6-byte OctetString in formato XX:XX:XX:XX:XX:XX
                                    mac_address = str(mac) if mac else ""
                                    
                                    # Ottieni nome interfaccia se disponibile
                                    try:
                                        iface_name = interface_map.get(if_index, f"if{if_index}")
                                    except NameError:
                                        iface_name = f"if{if_index}"
                                    
                                    arp_entries.append({
                                        "address": ip_address,
                                        "mac-address": mac_address,
                                        "interface": iface_name
                                    })
                            except Exception:
                                continue
                        
                        if arp_entries:
                            info["arp_table"] = arp_entries
                            info["arp_count"] = len(arp_entries)
                            logger.info(f"SNMP probe: Found {len(arp_entries)} ARP entries")
                        else:
                            logger.debug(f"SNMP probe: No ARP entries found")
                    except Exception as e:
                        logger.warning(f"SNMP probe: ARP table query failed for {target}: {e}", exc_info=True)
                
                # ==========================================
                # INTERFACES DETTAGLIATE (IF-MIB)
                # ==========================================
                try:
                    logger.info(f"SNMP probe: Collecting detailed interfaces for {target}...")
                    interfaces = []
                    
                    # IF-MIB OIDs
                    if_descr = "1.3.6.1.2.1.2.2.1.2"  # ifDescr
                    if_type = "1.3.6.1.2.1.2.2.1.3"    # ifType
                    if_speed = "1.3.6.1.2.1.2.2.1.5"    # ifSpeed
                    if_admin_status = "1.3.6.1.2.1.2.2.1.7"  # ifAdminStatus
                    if_oper_status = "1.3.6.1.2.1.2.2.1.8"    # ifOperStatus
                    if_phys_address = "1.3.6.1.2.1.2.2.1.6"   # ifPhysAddress
                    
                    logger.info(f"SNMP probe: Walking IF-MIB ifDescr OID {if_descr} for {target}...")
                    if_descriptions_raw = await walk_oid(if_descr, max_rows=200)
                    logger.info(f"SNMP probe: Collected {len(if_descriptions_raw)} interface descriptions")
                    
                    # Extract ifIndex from OID and build dict keyed by ifIndex
                    # OID format: 1.3.6.1.2.1.2.2.1.2.ifIndex
                    # Base OID: 1.3.6.1.2.1.2.2.1.2 (10 parts)
                    if_descriptions = {}  # Key: ifIndex, Value: description
                    base_oid_parts = if_descr.split('.')
                    base_oid_len = len(base_oid_parts)
                    
                    for oid_str, value in if_descriptions_raw.items():
                        if value and "No Such" not in str(value) and str(value) != "":
                            oid_parts = oid_str.split('.')
                            if len(oid_parts) > base_oid_len:
                                # Extract ifIndex (last part after base OID)
                                if_index = oid_parts[-1]
                                value_str = str(value).strip()
                                # Valida che il valore sia un nome interfaccia valido (non solo numeri)
                                # Filtra valori che sono solo numeri o caratteri strani
                                if value_str and not value_str.isdigit() and len(value_str) < 100:
                                    # Rimuovi caratteri null e non stampabili
                                    value_str = ''.join(c for c in value_str if c.isprintable() and ord(c) < 128)
                                    if value_str:
                                        if_descriptions[if_index] = value_str
                    
                    # ifSpeed (bps) - per interfacce fino a 100Mbps
                    logger.info(f"SNMP probe: Walking IF-MIB ifSpeed OID {if_speed} for {target}...")
                    if_speeds_raw = await walk_oid(if_speed, max_rows=200)
                    logger.info(f"SNMP probe: Collected {len(if_speeds_raw)} interface speeds")
                    if_speeds = {}  # Key: ifIndex, Value: speed_mbps
                    base_oid_parts = if_speed.split('.')
                    base_oid_len = len(base_oid_parts)
                    
                    for oid_str, value in if_speeds_raw.items():
                        if value and "No Such" not in str(value):
                            try:
                                oid_parts = oid_str.split('.')
                                if len(oid_parts) > base_oid_len:
                                    if_index = oid_parts[-1]
                                    try:
                                        if_index_int = int(if_index)
                                        if if_index_int < 1 or if_index_int > 2147483647:
                                            continue
                                    except ValueError:
                                        continue
                                    
                                    speed_bps = int(value)
                                    # ifSpeed = 4294967295 significa "velocità sconosciuta" (>100Mbps)
                                    if speed_bps > 0 and speed_bps < 4294967295:
                                        speed_mbps = speed_bps // 1000000
                                        if_speeds[if_index] = speed_mbps
                            except (ValueError, TypeError):
                                pass
                    
                    # ifHighSpeed (Mbps) - per interfacce ad alta velocità (1.3.6.1.2.1.31.1.1.1.15)
                    if_high_speed = "1.3.6.1.2.1.31.1.1.1.15"
                    if_high_speeds_raw = await walk_oid(if_high_speed, max_rows=200)
                    for oid_str, value in if_high_speeds_raw.items():
                        if value and "No Such" not in str(value):
                            try:
                                if_index = oid_str.split('.')[-1]
                                speed_mbps = int(value)
                                # Usa ifHighSpeed se maggiore di ifSpeed o se ifSpeed non disponibile
                                if speed_mbps > 0 and speed_mbps > if_speeds.get(if_index, 0):
                                    if_speeds[if_index] = speed_mbps
                            except (ValueError, TypeError):
                                pass
                    
                    logger.info(f"SNMP probe: Parsed {len(if_speeds)} interfaces with valid speeds")
                    
                    # ifMtu (1.3.6.1.2.1.2.2.1.4)
                    if_mtu_oid = "1.3.6.1.2.1.2.2.1.4"
                    if_mtus_raw = await walk_oid(if_mtu_oid, max_rows=200)
                    if_mtus = {}
                    for oid_str, value in if_mtus_raw.items():
                        if value and "No Such" not in str(value):
                            try:
                                if_index = oid_str.split('.')[-1]
                                mtu = int(value)
                                if mtu > 0:
                                    if_mtus[if_index] = mtu
                            except (ValueError, TypeError):
                                pass
                    
                    # ifType (1.3.6.1.2.1.2.2.1.3) - e.g. 6=ethernet, 53=propVirtual, 131=tunnel
                    if_type_oid = "1.3.6.1.2.1.2.2.1.3"
                    if_types_raw = await walk_oid(if_type_oid, max_rows=200)
                    if_types = {}
                    if_type_map = {
                        1: "other", 6: "ethernet", 23: "ppp", 24: "softwareLoopback",
                        53: "propVirtual", 131: "tunnel", 135: "l2vlan", 136: "l3ipvlan",
                        161: "ieee8023adLag"  # bond/aggregate
                    }
                    for oid_str, value in if_types_raw.items():
                        if value and "No Such" not in str(value):
                            try:
                                if_index = oid_str.split('.')[-1]
                                if_type_num = int(value)
                                if_types[if_index] = if_type_map.get(if_type_num, f"type{if_type_num}")
                            except (ValueError, TypeError):
                                pass
                    
                    if_admin_statuses_raw = await walk_oid(if_admin_status, max_rows=200)
                    if_admin_statuses = {}  # Key: ifIndex, Value: status
                    base_oid_parts = if_admin_status.split('.')
                    base_oid_len = len(base_oid_parts)
                    
                    for oid_str, value in if_admin_statuses_raw.items():
                        if value and "No Such" not in str(value):
                            oid_parts = oid_str.split('.')
                            if len(oid_parts) > base_oid_len:
                                if_index = oid_parts[-1]
                                # Valida ifIndex
                                try:
                                    if_index_int = int(if_index)
                                    if if_index_int < 1 or if_index_int > 2147483647:
                                        continue
                                except ValueError:
                                    continue
                                
                                try:
                                    # Valida che il valore sia un numero tra 1-5
                                    status_val = int(value)
                                    if 1 <= status_val <= 5:
                                        status_map = {1: "up", 2: "down", 3: "testing"}
                                        if_admin_statuses[if_index] = status_map.get(status_val, str(status_val))
                                except (ValueError, TypeError):
                                    pass
                    
                    if_oper_statuses_raw = await walk_oid(if_oper_status, max_rows=200)
                    if_oper_statuses = {}  # Key: ifIndex, Value: status
                    base_oid_parts = if_oper_status.split('.')
                    base_oid_len = len(base_oid_parts)
                    
                    for oid_str, value in if_oper_statuses_raw.items():
                        if value and "No Such" not in str(value):
                            oid_parts = oid_str.split('.')
                            if len(oid_parts) > base_oid_len:
                                if_index = oid_parts[-1]
                                # Valida ifIndex
                                try:
                                    if_index_int = int(if_index)
                                    if if_index_int < 1 or if_index_int > 2147483647:
                                        continue
                                except ValueError:
                                    continue
                                
                                try:
                                    # Valida che il valore sia un numero tra 1-7
                                    status_val = int(value)
                                    if 1 <= status_val <= 7:
                                        status_map = {1: "up", 2: "down", 3: "testing", 4: "unknown", 5: "dormant"}
                                        if_oper_statuses[if_index] = status_map.get(status_val, str(status_val))
                                except (ValueError, TypeError):
                                    pass
                    
                    if_macs_raw = await walk_oid(if_phys_address, max_rows=200)
                    if_macs = {}  # Key: ifIndex, Value: MAC address
                    base_oid_parts = if_phys_address.split('.')
                    base_oid_len = len(base_oid_parts)
                    
                    for oid_str, value in if_macs_raw.items():
                        if value and "No Such" not in str(value):
                            oid_parts = oid_str.split('.')
                            if len(oid_parts) > base_oid_len:
                                if_index = oid_parts[-1]
                                mac_str = str(value).strip()
                                # Valida formato MAC: deve contenere ':' o '-' e avere lunghezza ragionevole
                                # Filtra caratteri non stampabili
                                mac_str = ''.join(c for c in mac_str if c.isprintable() and ord(c) < 128)
                                # MAC address valido: contiene ':' o '-' e ha almeno 12 caratteri hex
                                if mac_str and (':' in mac_str or '-' in mac_str) and len(mac_str) >= 12:
                                    if_macs[if_index] = mac_str
                                elif mac_str and len(mac_str) == 12 and all(c in '0123456789ABCDEFabcdef' for c in mac_str):
                                    # MAC senza separatori, aggiungi ':'
                                    if_macs[if_index] = ':'.join(mac_str[i:i+2] for i in range(0, 12, 2))
                    
                    # Build interface list using ifIndex as common key
                    # Filtra interfacce con nomi validi (non solo numeri)
                    for if_index, descr in list(if_descriptions.items())[:100]:
                        # Salta interfacce con nomi che sono solo numeri o invalidi
                        if descr.isdigit() or len(descr) < 1:
                            continue
                        
                        interface = {
                            "name": descr,
                            "if_index": if_index,
                            "type": if_types.get(if_index, ""),
                            "speed_mbps": if_speeds.get(if_index, 0),
                            "mtu": if_mtus.get(if_index, 0),
                            "admin_status": if_admin_statuses.get(if_index, ""),
                            "oper_status": if_oper_statuses.get(if_index, ""),
                            "mac_address": if_macs.get(if_index, "")
                        }
                        interfaces.append(interface)
                    
                    logger.debug(f"SNMP probe: Built {len(interfaces)} interfaces from {len(if_descriptions)} descriptions")
                    
                    if interfaces:
                        info["interfaces"] = interfaces
                        info["interfaces_count"] = len(interfaces)
                        info["interface_details"] = interfaces  # Alias per compatibilità
                        logger.info(f"SNMP probe: Found {len(interfaces)} interfaces")
                    else:
                        logger.debug(f"SNMP probe: No interfaces found (if_descriptions={len(if_descriptions)}, if_speeds={len(if_speeds)})")
                except Exception as e:
                    logger.warning(f"SNMP probe: Interface details query failed for {target}: {e}", exc_info=True)
                
                # Log summary of advanced data collected
                advanced_data_summary = []
                if info.get("neighbors") or info.get("lldp_neighbors") or info.get("cdp_neighbors"):
                    neighbors_count = len(info.get("neighbors", [])) or len(info.get("lldp_neighbors", [])) or len(info.get("cdp_neighbors", []))
                    advanced_data_summary.append(f"{neighbors_count} neighbors")
                if info.get("routing_table"):
                    advanced_data_summary.append(f"{len(info.get('routing_table', []))} routes")
                if info.get("arp_table"):
                    advanced_data_summary.append(f"{len(info.get('arp_table', []))} ARP entries")
                if info.get("interfaces"):
                    advanced_data_summary.append(f"{len(info.get('interfaces', []))} interfaces")
                
                if advanced_data_summary:
                    logger.info(f"SNMP probe: Advanced data collected for {target}: {', '.join(advanced_data_summary)}")
            except Exception as e:
                logger.warning(f"SNMP probe: Error collecting advanced data for {target}: {e}", exc_info=True)
        
    finally:
        dispatcher.transport_dispatcher.close_dispatcher()
    
    logger.info(f"SNMP probe successful: {info.get('sysName')} ({info.get('vendor', 'unknown')}) - {len(info)} fields")
    return info


def _extract_model_from_descr(descr: str) -> Optional[str]:
    """Extract model name from sysDescr string"""
    if not descr:
        return None
    
    # Common patterns
    patterns = [
        r'U[67]-\w+',  # Ubiquiti U6-LR, U7-Pro
        r'UAP-\w+',    # Ubiquiti UAP-*
        r'USW-\w+',    # Ubiquiti USW-*
        r'RB\d+\w*',   # MikroTik RB*
        r'CCR\d+\w*',  # MikroTik CCR*
        r'hAP\w*',     # MikroTik hAP
        r'CRS\d+\w*',  # MikroTik CRS*
        r'Catalyst \d+', # Cisco Catalyst
        r'DS\d+\w*',   # Synology DS*
        r'RS\d+\w*',   # Synology RS*
        r'TS-\d+\w*',  # QNAP TS-*
        r'Smart-UPS \w+', # APC UPS
    ]
    
    for pattern in patterns:
        match = re.search(pattern, descr, re.IGNORECASE)
        if match:
            return match.group(0)
    
    # Fallback: first word after vendor name or "Linux"
    parts = descr.split()
    if len(parts) > 1:
        if parts[0].lower() == "linux":
            return parts[1]
        return parts[0]
    
    return None
