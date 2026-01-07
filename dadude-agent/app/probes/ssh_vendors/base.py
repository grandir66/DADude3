"""
DaDude Agent - SSH Vendor Base Module
Classe base e utilities comuni per tutti i vendor SSH.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable
from loguru import logger


class SSHVendorProbe(ABC):
    """
    Classe base astratta per probe SSH vendor-specific.
    
    Ogni vendor deve implementare:
    - detect(): Verifica se il device è di questo vendor
    - probe(): Esegue la scansione completa
    """
    
    # Nome del vendor (per logging)
    VENDOR_NAME: str = "Unknown"
    
    # Priorità di detection (numeri più bassi = provato prima)
    DETECTION_PRIORITY: int = 100
    
    def __init__(self, exec_cmd: Callable[[str, int], str], exec_cmd_sudo: Callable[[str, int], str]):
        """
        Args:
            exec_cmd: Funzione per eseguire comandi SSH
            exec_cmd_sudo: Funzione per eseguire comandi con sudo
        """
        self.exec_cmd = exec_cmd
        self.exec_cmd_sudo = exec_cmd_sudo
    
    @abstractmethod
    def detect(self) -> bool:
        """
        Rileva se il device è di questo vendor.
        
        Returns:
            True se il device corrisponde a questo vendor
        """
        pass
    
    @abstractmethod
    def probe(self, target: str) -> Dict[str, Any]:
        """
        Esegue la scansione completa del device.
        
        Args:
            target: IP o hostname del device
            
        Returns:
            Dict con tutte le informazioni raccolte
        """
        pass
    
    def _log_info(self, message: str):
        """Log info con prefisso vendor"""
        logger.info(f"[{self.VENDOR_NAME}] {message}")
    
    def _log_debug(self, message: str):
        """Log debug con prefisso vendor"""
        logger.debug(f"[{self.VENDOR_NAME}] {message}")
    
    def _log_warning(self, message: str):
        """Log warning con prefisso vendor"""
        logger.warning(f"[{self.VENDOR_NAME}] {message}")
    
    def _log_error(self, message: str):
        """Log error con prefisso vendor"""
        logger.error(f"[{self.VENDOR_NAME}] {message}")
    
    def _parse_key_value(self, text: str, delimiter: str = ':') -> Dict[str, str]:
        """
        Parse testo key:value in un dizionario.
        
        Args:
            text: Testo da parsare
            delimiter: Delimitatore (default ':')
            
        Returns:
            Dict con chiavi lowercase
        """
        result = {}
        for line in text.split('\n'):
            if delimiter in line:
                key, value = line.split(delimiter, 1)
                result[key.strip().lower()] = value.strip()
        return result
    
    def _parse_terse_output(self, text: str) -> List[Dict[str, str]]:
        """
        Parse output in formato terse (key=value separati da spazi).
        Usato da MikroTik e simili.
        
        Gestisce:
        - Valori quotati: name="ether1" -> name=ether1
        - Valori con spazi: name="ether 1" -> name=ether 1
        - Valori non quotati: type=ether -> type=ether
        - Valori vuoti: mac-address="" -> mac-address=""
        
        Args:
            text: Output terse da parsare
            
        Returns:
            Lista di dizionari
        """
        items = []
        for line_num, line in enumerate(text.split('\n'), 1):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('Flags'):
                continue
            
            item = {}
            i = 0
            while i < len(line):
                # Trova il prossimo '='
                eq_pos = line.find('=', i)
                if eq_pos == -1:
                    break
                
                # Estrai la chiave (tutto prima di '=')
                # La chiave non può contenere spazi
                key_start = i
                while key_start < eq_pos and line[key_start] == ' ':
                    key_start += 1
                key = line[key_start:eq_pos].strip()
                
                if not key:
                    i = eq_pos + 1
                    continue
                
                # Avanza dopo '='
                i = eq_pos + 1
                
                # Determina se il valore è quotato
                if i < len(line) and line[i] == '"':
                    # Valore quotato: trova la chiusura
                    i += 1  # Salta il quote iniziale
                    value_start = i
                    # Cerca il quote di chiusura (gestisce escape)
                    while i < len(line):
                        if line[i] == '"' and (i == value_start or line[i-1] != '\\'):
                            break
                        i += 1
                    value = line[value_start:i]
                    i += 1  # Salta il quote finale
                else:
                    # Valore non quotato: trova il prossimo spazio o fine riga
                    # Ma attenzione: alcuni valori possono contenere spazi se non quotati
                    value_start = i
                    # Per valori non quotati, prendiamo tutto fino al prossimo spazio
                    # MA solo se non inizia con un carattere speciale
                    while i < len(line) and line[i] != ' ':
                        i += 1
                    value = line[value_start:i]
                
                # Salta spazi fino al prossimo attributo
                while i < len(line) and line[i] == ' ':
                    i += 1
                
                # Salva la coppia chiave-valore solo se la chiave è valida
                # Evita chiavi che sono solo numeri (probabilmente errori di parsing)
                if key and not key.isdigit():
                    item[key] = value.strip()
            
            # Solo aggiungi item se ha almeno una chiave valida (non numerica)
            if item and any(not k.isdigit() for k in item.keys()):
                items.append(item)
        
        return items
    
    def _safe_int(self, value: Any, default: int = 0) -> int:
        """Converte value in int in modo sicuro"""
        if value is None:
            return default
        try:
            if isinstance(value, str):
                # Rimuovi suffissi comuni (K, M, G, MiB, GiB, etc.)
                value = value.strip()
                for suffix in ['GiB', 'MiB', 'KiB', 'GB', 'MB', 'KB', 'G', 'M', 'K']:
                    if value.upper().endswith(suffix.upper()):
                        multiplier = {
                            'G': 1024**3, 'GB': 1024**3, 'GIB': 1024**3,
                            'M': 1024**2, 'MB': 1024**2, 'MIB': 1024**2,
                            'K': 1024, 'KB': 1024, 'KIB': 1024,
                        }.get(suffix.upper(), 1)
                        value = value[:-len(suffix)].strip()
                        return int(float(value) * multiplier)
            return int(float(value))
        except (ValueError, TypeError):
            return default
    
    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Converte value in float in modo sicuro"""
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            return default


class VendorDetector:
    """
    Gestisce la detection automatica del vendor e l'esecuzione del probe appropriato.
    """
    
    def __init__(self, exec_cmd: Callable, exec_cmd_sudo: Callable):
        self.exec_cmd = exec_cmd
        self.exec_cmd_sudo = exec_cmd_sudo
        self._probes: List[SSHVendorProbe] = []
    
    def register_probe(self, probe_class: type):
        """Registra una classe probe"""
        probe = probe_class(self.exec_cmd, self.exec_cmd_sudo)
        self._probes.append(probe)
        # Ordina per priorità
        self._probes.sort(key=lambda p: p.DETECTION_PRIORITY)
    
    def detect_and_probe(self, target: str) -> Dict[str, Any]:
        """
        Rileva automaticamente il vendor ed esegue il probe appropriato.
        
        Args:
            target: IP o hostname
            
        Returns:
            Dict con info raccolte
        """
        for probe in self._probes:
            try:
                if probe.detect():
                    logger.info(f"Detected vendor: {probe.VENDOR_NAME} for {target}")
                    return probe.probe(target)
            except Exception as e:
                logger.debug(f"Vendor detection failed for {probe.VENDOR_NAME}: {e}")
        
        # Nessun vendor specifico rilevato, usa Linux generico
        logger.info(f"No specific vendor detected for {target}, using Linux generic")
        from .linux import LinuxProbe
        linux_probe = LinuxProbe(self.exec_cmd, self.exec_cmd_sudo)
        return linux_probe.probe(target)
