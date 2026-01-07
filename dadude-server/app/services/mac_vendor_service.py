"""
DaDude - MAC Vendor Lookup Service
Identifica il vendor dal MAC address usando database OUI
"""
from typing import Optional, Dict, Any
from loguru import logger
import os
import json

# Database OUI comuni (può essere espanso o caricato da file)
# Formato: primi 6 caratteri MAC (senza :) -> vendor
OUI_DATABASE = {
    # MikroTik
    "D4CA6D": "MikroTik",
    "E48D8C": "MikroTik",
    "6C3B6B": "MikroTik",
    "DC2C6E": "MikroTik",
    "B8A3E0": "MikroTik",
    "C8AF40": "MikroTik",
    "789A18": "MikroTik",
    "4C5E0C": "MikroTik",
    "2C9E15": "MikroTik",
    "485073": "MikroTik",
    "74D435": "MikroTik",
    "E4:8D:8C": "MikroTik",
    
    # Cisco
    "000C29": "VMware",
    "005056": "VMware",
    "001C42": "Cisco",
    "0019AA": "Cisco",
    "001B54": "Cisco",
    "0023EA": "Cisco",
    "001E7A": "Cisco",
    "001FCA": "Cisco",
    "002155": "Cisco",
    "0022BD": "Cisco",
    "002312": "Cisco",
    "0024C4": "Cisco",
    "0025B4": "Cisco",
    "0026CB": "Cisco",
    "002A6A": "Cisco",
    "00906D": "Cisco",
    "5475D0": "Cisco",
    "F4CFE2": "Cisco",
    
    # HP / HPE
    "3C4A92": "HP",
    "308D99": "HP",
    "0019BB": "HP",
    "001871": "HP",
    "001A4B": "HP",
    "001B78": "HP",
    "001CC4": "HP",
    "001E0B": "HP",
    "001F29": "HP",
    "002128": "HP",
    "0022B1": "HP",
    "0023E2": "HP",
    "002561": "HP",
    "002655": "HP",
    "0030C1": "HP",
    "0050DA": "HP",
    "9457A5": "HP",
    "D4C9EF": "HP",
    
    # Dell
    "0018A4": "Dell",
    "0019B9": "Dell",
    "001A2F": "Dell",
    "001C23": "Dell",
    "001D09": "Dell",
    "001E4F": "Dell",
    "001EC9": "Dell",
    "002170": "Dell",
    "0022BD": "Dell",
    "0024E8": "Dell",
    "0025B3": "Dell",
    "0026B9": "Dell",
    "14187D": "Dell",
    "14FEB5": "Dell",
    "18A99B": "Dell",
    "18DB3E": "Dell",
    "246E96": "Dell",
    "3417EB": "Dell",
    "34E6D7": "Dell",
    "4C4C45": "Dell",
    "509CB1": "Dell",
    "5C260A": "Dell",
    "5CF9DD": "Dell",
    "782BCB": "Dell",
    "848F69": "Dell",
    "B499BA": "Dell",
    "B8CA3A": "Dell",
    "C81F66": "Dell",
    "D4BE3A": "Dell",
    "F48E38": "Dell",
    "F8BC12": "Dell",
    
    # Lenovo
    "6C0B84": "Lenovo",
    "887766": "Lenovo",
    "503EAA": "Lenovo",
    "98EEC6": "Lenovo",
    "B8AC6F": "Lenovo",
    "F0F002": "Lenovo",
    
    # Apple
    "000393": "Apple",
    "000502": "Apple",
    "000A27": "Apple",
    "000D93": "Apple",
    "001124": "Apple",
    "00125A": "Apple",
    "001451": "Apple",
    "0016CB": "Apple",
    "0017F2": "Apple",
    "0019E3": "Apple",
    "001B63": "Apple",
    "001CB3": "Apple",
    "001D4F": "Apple",
    "001E52": "Apple",
    "001EC2": "Apple",
    "001F5B": "Apple",
    "001FF3": "Apple",
    "002241": "Apple",
    "002312": "Apple",
    "002436": "Apple",
    "00254B": "Apple",
    "002608": "Apple",
    "00264A": "Apple",
    "003065": "Apple",
    "0050E4": "Apple",
    "04F7E4": "Apple",
    "086D41": "Apple",
    "0C4DE9": "Apple",
    "10DDB1": "Apple",
    "14205E": "Apple",
    "182032": "Apple",
    "1C1AC0": "Apple",
    "20A286": "Apple",
    "24A074": "Apple",
    "283737": "Apple",
    "285AEB": "Apple",
    "28CFDA": "Apple",
    "2CB43A": "Apple",
    "3010E4": "Apple",
    "34C059": "Apple",
    "3C0754": "Apple",
    "40A6D9": "Apple",
    "40D32D": "Apple",
    "442A60": "Apple",
    "48746E": "Apple",
    "48D705": "Apple",
    "4C32A9": "Apple",
    "4C7C5F": "Apple",
    "4CEAEF": "Apple",
    "50EAD6": "Apple",
    "544E45": "Apple",
    "54E43A": "Apple",
    "54EAA8": "Apple",
    "587F57": "Apple",
    "5855CA": "Apple",
    "58B035": "Apple",
    "5C969D": "Apple",
    "600308": "Apple",
    "6C709F": "Apple",
    "702303": "Apple",
    "7014A6": "Apple",
    "70CD60": "Apple",
    "70DEE2": "Apple",
    "74E1B6": "Apple",
    "78A3E4": "Apple",
    "7C0191": "Apple",
    "7CC537": "Apple",
    "7CD1C3": "Apple",
    "80006E": "Apple",
    "80E650": "Apple",
    "8440DB": "Apple",
    "848506": "Apple",
    "84788B": "Apple",
    "84788B": "Apple",
    "848E0C": "Apple",
    "84B153": "Apple",
    "84FCFE": "Apple",
    "881FA1": "Apple",
    "8866A5": "Apple",
    "8C2937": "Apple",
    "8C5877": "Apple",
    "8C7C92": "Apple",
    "903C92": "Apple",
    "9027E4": "Apple",
    "90840D": "Apple",
    "90B21F": "Apple",
    "9801A7": "Apple",
    "9803D8": "Apple",
    "98B8E3": "Apple",
    "98D6BB": "Apple",
    "98F0AB": "Apple",
    "98FE94": "Apple",
    "9C04EB": "Apple",
    "9C20A0": "Apple",
    "9C35EB": "Apple",
    "9CF387": "Apple",
    "A02195": "Apple",
    "A45E60": "Apple",
    "A4B197": "Apple",
    "A4D18C": "Apple",
    "A82066": "Apple",
    "A8667F": "Apple",
    "A886DD": "Apple",
    "A88808": "Apple",
    "A8968A": "Apple",
    "AC293A": "Apple",
    "ACFDEC": "Apple",
    "B065BD": "Apple",
    "B0CA68": "Apple",
    "B418D1": "Apple",
    "B4F0AB": "Apple",
    "B8098A": "Apple",
    "B817C2": "Apple",
    "B844D9": "Apple",
    "B8C111": "Apple",
    "B8E856": "Apple",
    "B8F6B1": "Apple",
    "BC3BAF": "Apple",
    "BC52B7": "Apple",
    "BC6778": "Apple",
    "BC92F4": "Apple",
    "C42C03": "Apple",
    "C82A14": "Apple",
    "C86F1D": "Apple",
    "C8B5B7": "Apple",
    "C8E0EB": "Apple",
    "CC088D": "Apple",
    "CC25EF": "Apple",
    "CCC760": "Apple",
    "D003DF": "Apple",
    "D02598": "Apple",
    "D023DB": "Apple",
    "D49A20": "Apple",
    "D4F46F": "Apple",
    "D89695": "Apple",
    "D8A25E": "Apple",
    "D8BB2C": "Apple",
    "DC2B2A": "Apple",
    "DC9B9C": "Apple",
    "E05F45": "Apple",
    "E0B9BA": "Apple",
    "E0C767": "Apple",
    "E0F847": "Apple",
    "E4C63D": "Apple",
    "E80688": "Apple",
    "E8040B": "Apple",
    "E8802E": "Apple",
    "E88D28": "Apple",
    "F02475": "Apple",
    "F0B479": "Apple",
    "F0C1F1": "Apple",
    "F0D1A9": "Apple",
    "F0DBE2": "Apple",
    "F0DBF8": "Apple",
    "F0F61C": "Apple",
    "F437B7": "Apple",
    "F4F15A": "Apple",
    "F8E079": "Apple",
    
    # Ubiquiti
    "00156D": "Ubiquiti",
    "0027C1": "Ubiquiti",
    "24A43C": "Ubiquiti",
    "44D9E7": "Ubiquiti",
    "68D79A": "Ubiquiti",
    "788A20": "Ubiquiti",
    "802AA8": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "DC9FDB": "Ubiquiti",
    "E063DA": "Ubiquiti",
    "FCF528": "Ubiquiti",
    "245EBE": "Ubiquiti",
    "74ACB9": "Ubiquiti",
    "B4FBE4": "Ubiquiti",
    "18E8F2": "Ubiquiti",
    
    # Fortinet
    "000977": "Fortinet",
    "00090F": "Fortinet",
    "001F9E": "Fortinet",
    "08A82B": "Fortinet",
    "70EBAF": "Fortinet",
    "90B831": "Fortinet",
    "A8F7E0": "Fortinet",
    "E8EBD3": "Fortinet",
    
    # Synology
    "0011324": "Synology",
    
    # QNAP
    "001F3B": "QNAP",
    "24-5E-BE": "QNAP",
    "245EBE": "QNAP",
    
    # Hikvision (telecamere)
    "28573C": "Hikvision",
    "44192F": "Hikvision",
    "4419B6": "Hikvision",
    "54C4BC": "Hikvision",
    "74DA38": "Hikvision",
    "8CE748": "Hikvision",
    "A0BD1D": "Hikvision",
    "C0B5CD": "Hikvision",
    "E00A00": "Hikvision",
    
    # Dahua (telecamere)
    "3C7843": "Dahua",
    "4C11BF": "Dahua",
    "9C1461": "Dahua",
    "A0BD1D": "Dahua",
    "B00C28": "Dahua",
    "D4E841": "Dahua",
    "E0AAB0": "Dahua",
    
    # Brother (stampanti)
    "00075F": "Brother",
    "001BA9": "Brother",
    "30055C": "Brother",
    "A0F4E4": "Brother",
    
    # Canon (stampanti)
    "000F44": "Canon",
    "001E8F": "Canon",
    "002483": "Canon",
    "003018": "Canon",
    "00A0C9": "Canon",
    "18C19D": "Canon",
    "2C9EFC": "Canon",
    "6C3C8C": "Canon",
    "9080FF": "Canon",
    "B87421": "Canon",
    "C869CD": "Canon",
    "E0B94D": "Canon",
    
    # Epson (stampanti)
    "0000D6": "Epson",
    "00269E": "Epson",
    "64EB8C": "Epson",
    "C8D083": "Epson",
    
    # Ricoh (stampanti)
    "0017C8": "Ricoh",
    "002678": "Ricoh",
    "4CE1B7": "Ricoh",
    "A0F453": "Ricoh",
    
    # Kyocera (stampanti)
    "006B8E": "Kyocera",
    "00C049": "Kyocera",
    "0021D8": "Kyocera",
    "54B803": "Kyocera",
    
    # Yealink (VoIP)
    "001565": "Yealink",
    "805E0C": "Yealink",
    
    # Polycom (VoIP)
    "0004F2": "Polycom",
    "0007E9": "Polycom",
    "00907A": "Polycom",
    "000413": "Polycom",
    "64167F": "Polycom",
    
    # Grandstream (VoIP)
    "000B82": "Grandstream",
    "000B46": "Grandstream",
    "C074AD": "Grandstream",
    
    # Intel
    "001111": "Intel",
    "001302": "Intel",
    "001517": "Intel",
    "0016EA": "Intel",
    "00188B": "Intel",
    "001B21": "Intel",
    "001CC0": "Intel",
    "001DE0": "Intel",
    "001E64": "Intel",
    "001E65": "Intel",
    "001E67": "Intel",
    "001F3B": "Intel",
    "001F3C": "Intel",
    "002026": "Intel",
    "002104": "Intel",
    "0021D7": "Intel",
    "0021D8": "Intel",
    "0022FA": "Intel",
    "0022FB": "Intel",
    "0024D6": "Intel",
    "0024D7": "Intel",
    "00270E": "Intel",
    "002710": "Intel",
    "0034FE": "Intel",
    "00A0C9": "Intel",
    "080027": "Intel",
    "3497F6": "Intel",
    "3C970E": "Intel",
    "3CD92B": "Intel",
    "485B39": "Intel",
    "4C3488": "Intel",
    "5001BB": "Intel",
    "6036DD": "Intel",
    "78929C": "Intel",
    "84A6C8": "Intel",
    "94659C": "Intel",
    "9C4E36": "Intel",
    "A0369F": "Intel",
    "AC7289": "Intel",
    "B4B52F": "Intel",
    "BC7737": "Intel",
    "D4258B": "Intel",
    "E8E1E1": "Intel",
    "F8B156": "Intel",
    "FC15B4": "Intel",
    
    # Realtek (NIC generici)
    "001320": "Realtek",
    "00E04C": "Realtek",
    "001FC6": "Realtek",
    "287FCF": "Realtek",
    "48E244": "Realtek",
    "526AF2": "Realtek",
    "7005B6": "Realtek",
    "7CC3A1": "Realtek",
    "8CE117": "Realtek",
    "8CFDF0": "Realtek",
    "90DE80": "Realtek",
    "A0AB1B": "Realtek",
    "D0374E": "Realtek",
    "D8EB97": "Realtek",
    "E04F43": "Realtek",
    "F8D111": "Realtek",
    
    # TP-Link
    "14CC20": "TP-Link",
    "14CF92": "TP-Link",
    "1C3BF3": "TP-Link",
    "503EAA": "TP-Link",
    "54EE75": "TP-Link",
    "6466B3": "TP-Link",
    "74DA38": "TP-Link",
    "7CC537": "TP-Link",
    "98DA1B": "TP-Link",
    "9CC9EB": "TP-Link",
    "A842A1": "TP-Link",
    "B04E26": "TP-Link",
    "C0A0BB": "TP-Link",
    "C46E1F": "TP-Link",
    "D4B910": "TP-Link",
    "E45F01": "TP-Link",
    "EC0868": "TP-Link",
    "EC888F": "TP-Link",
    "F4F26D": "TP-Link",
    "FC75D6": "TP-Link",
    
    # Netgear
    "000F66": "Netgear",
    "00146C": "Netgear",
    "0018FE": "Netgear",
    "001B2F": "Netgear",
    "001E2A": "Netgear",
    "001F33": "Netgear",
    "00223F": "Netgear",
    "002326": "Netgear",
    "00248B": "Netgear",
    "002636": "Netgear",
    "008EF2": "Netgear",
    "204E7F": "Netgear",
    "2C30AB": "Netgear",
    "3498B5": "Netgear",
    "405D5E": "Netgear",
    "44A56E": "Netgear",
    "6CB0CE": "Netgear",
    "8C3BAD": "Netgear",
    "9CC9EB": "Netgear",
    "A00460": "Netgear",
    "A42B8C": "Netgear",
    "B03956": "Netgear",
    "C43DC7": "Netgear",
    "C89E43": "Netgear",
    "CC40D0": "Netgear",
    "E03F49": "Netgear",
    "E091F5": "Netgear",
    "E4F4C6": "Netgear",
    "F87394": "Netgear",
    
    # APC (UPS)
    "00C0B7": "APC",
    "0050D8": "APC",
    
    # Xerox
    "000074": "Xerox",
    "001F0F": "Xerox",
    "002126": "Xerox",
    "0050A6": "Xerox",
    "40B837": "Xerox",
    "9C5343": "Xerox",
    "B03CA7": "Xerox",
    "F0620D": "Xerox",
}

# Mapping vendor -> tipo dispositivo suggerito
VENDOR_TO_TYPE = {
    "MikroTik": ("mikrotik", "router"),
    "Cisco": ("network", "switch"),
    "HP": ("network", "switch"),
    "Dell": ("other", "server"),
    "Lenovo": ("other", "workstation"),
    "Apple": ("other", "workstation"),
    "Ubiquiti": ("network", "ap"),
    "Fortinet": ("network", "firewall"),
    "Synology": ("linux", "nas"),
    "QNAP": ("linux", "nas"),
    "Hikvision": ("camera", "camera"),
    "Dahua": ("camera", "camera"),
    "Brother": ("printer", "printer"),
    "Canon": ("printer", "printer"),
    "Epson": ("printer", "printer"),
    "Ricoh": ("printer", "printer"),
    "Kyocera": ("printer", "printer"),
    "Xerox": ("printer", "printer"),
    "Yealink": ("voip", "phone"),
    "Polycom": ("voip", "phone"),
    "Grandstream": ("voip", "phone"),
    "VMware": ("linux", "vm"),
    "TP-Link": ("network", "switch"),
    "Netgear": ("network", "switch"),
    "APC": ("network", "ups"),
}


class MacVendorService:
    """Servizio per lookup vendor da MAC address"""
    
    def __init__(self):
        self._oui_db = OUI_DATABASE
        # Carica anche il database OUI completo se disponibile
        try:
            from .vendor_database import _OUI_DATABASE
            # Merge con database completo (ha priorità)
            for oui, vendor in _OUI_DATABASE.items():
                if isinstance(vendor, str):
                    self._oui_db[oui.replace(':', '')] = vendor
                elif isinstance(vendor, dict):
                    self._oui_db[oui.replace(':', '')] = vendor.get('vendor', '')
        except:
            pass
    
    def normalize_mac(self, mac: str) -> str:
        """Normalizza MAC address rimuovendo separatori"""
        if not mac:
            return ""
        return mac.upper().replace(":", "").replace("-", "").replace(".", "")
    
    def get_oui(self, mac: str) -> str:
        """Estrae OUI (primi 6 caratteri) dal MAC"""
        normalized = self.normalize_mac(mac)
        return normalized[:6] if len(normalized) >= 6 else ""
    
    def lookup_vendor(self, mac: str) -> Optional[str]:
        """
        Cerca il vendor dal MAC address.
        Ritorna il nome del vendor o None se non trovato.
        """
        oui = self.get_oui(mac)
        if not oui:
            return None
        
        # Prova prima formato senza due punti (database locale)
        vendor = self._oui_db.get(oui)
        if vendor:
            return vendor
        
        # Prova formato con due punti (database OUI completo)
        oui_with_colons = ':'.join([oui[i:i+2] for i in range(0, 6, 2)])
        vendor = self._oui_db.get(oui_with_colons)
        if vendor:
            return vendor
        
        # Prova anche usando vendor_database direttamente
        try:
            from .vendor_database import lookup_vendor_local
            result = lookup_vendor_local(mac)
            if result:
                return result.get('vendor')
        except:
            pass
        
        return None
    
    def lookup_vendor_with_type(self, mac: str) -> Dict[str, Any]:
        """
        Cerca vendor e suggerisce tipo dispositivo.
        
        Returns:
            Dict con vendor, device_type, category
        """
        vendor = self.lookup_vendor(mac)
        
        if vendor and vendor in VENDOR_TO_TYPE:
            device_type, category = VENDOR_TO_TYPE[vendor]
            return {
                "vendor": vendor,
                "device_type": device_type,
                "category": category,
            }
        elif vendor:
            return {
                "vendor": vendor,
                "device_type": "other",
                "category": None,
            }
        else:
            return {
                "vendor": None,
                "device_type": "other",
                "category": None,
            }
    
    def enrich_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Arricchisce un device con info vendor.
        
        Args:
            device: Dict con almeno mac_address
            
        Returns:
            Device arricchito con vendor, device_type, category
        """
        mac = device.get("mac_address", "")
        vendor_info = self.lookup_vendor_with_type(mac)
        
        device["vendor"] = vendor_info["vendor"]
        device["suggested_type"] = vendor_info["device_type"]
        device["suggested_category"] = vendor_info["category"]
        
        return device
    
    def enrich_devices(self, devices: list) -> list:
        """Arricchisce lista di devices con info vendor"""
        return [self.enrich_device(d) for d in devices]


# Singleton
_mac_vendor_service: Optional[MacVendorService] = None


def get_mac_vendor_service() -> MacVendorService:
    global _mac_vendor_service
    if _mac_vendor_service is None:
        _mac_vendor_service = MacVendorService()
    return _mac_vendor_service
