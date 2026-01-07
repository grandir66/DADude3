"""
DaDude Agent - WMI Vendor Base Module
Classe base e utilities comuni per tutti i probe WMI/WinRM.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List, Callable
from loguru import logger


class WMIVendorProbe(ABC):
    """
    Classe base astratta per probe WMI vendor-specific.
    
    Ogni tipo di Windows deve implementare:
    - detect(): Verifica se il device è di questo tipo
    - probe(): Esegue la scansione completa
    """
    
    # Nome del tipo (per logging)
    DEVICE_TYPE: str = "windows"
    
    # Priorità di detection (numeri più bassi = provato prima)
    DETECTION_PRIORITY: int = 100
    
    def __init__(self, wmi_query: Callable[[str], List[Dict]], exec_cmd: Callable[[str], str] = None):
        """
        Args:
            wmi_query: Funzione per eseguire query WMI
            exec_cmd: Funzione per eseguire comandi PowerShell (opzionale)
        """
        self.wmi_query = wmi_query
        self.exec_cmd = exec_cmd
    
    @abstractmethod
    def detect(self) -> bool:
        """
        Rileva se il device è di questo tipo.
        
        Returns:
            True se il device corrisponde a questo tipo
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
        """Log info con prefisso tipo"""
        logger.info(f"[WMI-{self.DEVICE_TYPE}] {message}")
    
    def _log_debug(self, message: str):
        """Log debug con prefisso tipo"""
        logger.debug(f"[WMI-{self.DEVICE_TYPE}] {message}")
    
    def _log_warning(self, message: str):
        """Log warning con prefisso tipo"""
        logger.warning(f"[WMI-{self.DEVICE_TYPE}] {message}")
    
    def _log_error(self, message: str):
        """Log error con prefisso tipo"""
        logger.error(f"[WMI-{self.DEVICE_TYPE}] {message}")
    
    def _safe_int(self, value: Any, default: int = 0) -> int:
        """Converte value in int in modo sicuro"""
        if value is None:
            return default
        try:
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
    
    def _bytes_to_gb(self, bytes_val: Any) -> float:
        """Converte bytes in GB"""
        return round(self._safe_float(bytes_val) / (1024**3), 2)
    
    def _bytes_to_mb(self, bytes_val: Any) -> int:
        """Converte bytes in MB"""
        return self._safe_int(self._safe_float(bytes_val) / (1024**2))
    
    def _wmi_datetime_to_str(self, wmi_datetime: str) -> str:
        """
        Converte WMI datetime (20240115123456.123456+060) in formato leggibile.
        """
        if not wmi_datetime or len(wmi_datetime) < 14:
            return wmi_datetime or ""
        try:
            year = wmi_datetime[0:4]
            month = wmi_datetime[4:6]
            day = wmi_datetime[6:8]
            hour = wmi_datetime[8:10]
            minute = wmi_datetime[10:12]
            second = wmi_datetime[12:14]
            return f"{year}-{month}-{day} {hour}:{minute}:{second}"
        except:
            return wmi_datetime
    
    def _get_first_result(self, results: List[Dict], key: str = None, default: Any = None) -> Any:
        """Ottiene il primo risultato da una query WMI"""
        if not results:
            return default
        if key:
            return results[0].get(key, default)
        return results[0]
