"""
Servizio per normalizzare i nomi OS rimuovendo informazioni superflue.
Es: "pve-manager/9.1.4/xxxxx" -> "Proxmox VE 9.1.4"
"""
import re
from typing import Optional


def normalize_os(
    os_name: Optional[str] = None,
    os_version: Optional[str] = None,
    os_family: Optional[str] = None,
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
) -> Optional[str]:
    """
    Normalizza il nome OS rimuovendo informazioni superflue.
    
    Args:
        os_name: Nome OS originale
        os_version: Versione OS originale
        os_family: Famiglia OS (Linux, Windows, etc.)
        manufacturer: Produttore del dispositivo (per inferire OS)
        model: Modello del dispositivo (per inferire OS)
    
    Returns:
        Stringa normalizzata o None se non determinabile
    """
    manufacturer = (manufacturer or "").lower()
    model = (model or "").upper()
    
    # Prima controlla se è un dispositivo Ubiquiti/UniFi (anche se OS è "Linux")
    if "ubiquiti" in manufacturer or "ubnt" in manufacturer or "unifi" in manufacturer:
        if os_version:
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', os_version)
            if version_match:
                return f"UniFi OS {version_match.group(1)}"
        return "UniFi OS"
    
    # Controlla il modello per pattern UniFi (USW, U6, UAP, etc.)
    if model and any(x in model for x in ["USW", "U6", "U7", "UAP", "UDM", "USG", "UCG", "UXG", "UDR"]):
        if os_version:
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', os_version)
            if version_match:
                return f"UniFi OS {version_match.group(1)}"
        return "UniFi OS"
    
    if not os_name:
        return None
    
    os_name = os_name.strip()
    os_version = (os_version or "").strip()
    
    # Proxmox VE
    if "proxmox" in os_name.lower() or "pve" in os_name.lower():
        # Cerca versione nel formato pve-manager/X.Y.Z/xxxxx
        version_match = None
        
        # Cerca in os_name
        pve_pattern = r'pve-manager/(\d+\.\d+\.\d+)'
        match = re.search(pve_pattern, os_name)
        if match:
            version_match = match.group(1)
        
        # Cerca in os_version se non trovato
        if not version_match and os_version:
            match = re.search(pve_pattern, os_version)
            if match:
                version_match = match.group(1)
            else:
                # Prova formato semplice X.Y.Z
                simple_version = re.search(r'(\d+\.\d+\.\d+)', os_version)
                if simple_version:
                    version_match = simple_version.group(1)
        
        if version_match:
            return f"Proxmox VE {version_match}"
        else:
            return "Proxmox VE"
    
    # Windows
    if "windows" in os_name.lower():
        # Rimuovi "Microsoft" e informazioni superflue
        normalized = os_name.replace("Microsoft ", "")
        
        # Rimuovi codici versione lunghi, mantieni solo nome principale
        # Es: "Windows Server 2022 Standard" -> "Windows Server 2022"
        normalized = re.sub(r'\s+(Standard|Datacenter|Enterprise|Professional|Home)', '', normalized, flags=re.IGNORECASE)
        
        # Se c'è versione separata, aggiungila
        if os_version and os_version not in normalized:
            # Estrai solo versione principale (es. "10" da "10.0.19045")
            version_main = re.search(r'^(\d+)', os_version)
            if version_main:
                normalized = f"{normalized} {version_main.group(1)}"
        
        return normalized
    
    # Linux distributions
    linux_distros = ["ubuntu", "debian", "centos", "rhel", "fedora", "suse", "arch", "alpine"]
    for distro in linux_distros:
        if distro in os_name.lower():
            # Estrai nome distribuzione e versione principale
            # Es: "Ubuntu 22.04.3 LTS (Jammy Jellyfish)" -> "Ubuntu 22.04"
            normalized = os_name
            
            # Rimuovi codename tra parentesi
            normalized = re.sub(r'\s*\([^)]+\)', '', normalized)
            
            # Rimuovi "LTS" e simili
            normalized = re.sub(r'\s+LTS\s*', ' ', normalized, flags=re.IGNORECASE)
            
            # Estrai versione principale (X.Y) se presente
            version_match = re.search(r'(\d+\.\d+)', normalized)
            if version_match:
                # Mantieni solo fino alla versione principale
                parts = normalized.split()
                result_parts = []
                for part in parts:
                    result_parts.append(part)
                    if version_match.group(1) in part:
                        break
                normalized = ' '.join(result_parts)
            
            return normalized.strip()
    
    # UniFi OS (Ubiquiti)
    if "unifi" in os_name.lower() or "ubnt" in os_name.lower() or "ubiquiti" in os_name.lower():
        if os_version:
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', os_version)
            if version_match:
                return f"UniFi OS {version_match.group(1)}"
        return "UniFi OS"
    
    # Detect Linux that's actually UniFi (common pattern: "Linux USW-xxx" or "Linux U6-xxx")
    if os_name.lower().startswith("linux "):
        device_part = os_name[6:].strip()  # Remove "Linux " prefix
        if any(x in device_part.upper() for x in ["U6", "U7", "UAP", "USW", "UDM", "USG", "NANO", "BEAM", "FLEX"]):
            if os_version:
                version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', os_version)
                if version_match:
                    return f"UniFi OS {version_match.group(1)}"
            return "UniFi OS"
    
    # RouterOS (MikroTik)
    if "routeros" in os_name.lower() or "mikrotik" in os_name.lower():
        if os_version:
            # Estrai solo versione principale
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                return f"RouterOS {version_match.group(1)}"
        return "RouterOS"
    
    # Synology DSM
    if "dsm" in os_name.lower() or "synology" in os_name.lower():
        if os_version:
            # Estrai versione principale
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                return f"DSM {version_match.group(1)}"
        return "DSM"
    
    # QNAP QTS
    if "qts" in os_name.lower() or "qnap" in os_name.lower():
        if os_version:
            version_match = re.search(r'(\d+\.\d+)', os_version)
            if version_match:
                return f"QTS {version_match.group(1)}"
        return "QTS"
    
    # Se non riconosciuto, rimuovi comunque informazioni superflue comuni
    normalized = os_name
    
    # Rimuovi codename tra parentesi
    normalized = re.sub(r'\s*\([^)]+\)', '', normalized)
    
    # Rimuovi hash/commit alla fine (es. "xxxxx" dopo versione)
    normalized = re.sub(r'/\w+$', '', normalized)
    
    # Se c'è versione separata e non è già nel nome, aggiungila
    if os_version and os_version not in normalized:
        # Estrai solo versione principale (X.Y o X.Y.Z)
        version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', os_version)
        if version_match:
            normalized = f"{normalized} {version_match.group(1)}"
    
    return normalized.strip() if normalized.strip() else os_name
