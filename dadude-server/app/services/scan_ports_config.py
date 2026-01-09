"""
DaDude - Scan Ports Configuration Service
Gestisce la configurazione delle porte TCP/UDP da scansionare
"""
import json
import os
from typing import Dict, Optional
from functools import lru_cache
from loguru import logger
from pathlib import Path


class ScanPortsConfig:
    """Servizio per gestire la configurazione delle porte di scansione"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Inizializza il servizio di configurazione porte.
        
        Args:
            config_path: Path al file JSON di configurazione (default: ./data/scan_ports.json)
        """
        if config_path is None:
            # Path relativo alla directory del progetto
            base_dir = Path(__file__).parent.parent.parent
            config_path = base_dir / "data" / "scan_ports.json"
        
        self.config_path = Path(config_path)
        self._cache = None
        self._ensure_config_exists()
    
    def _ensure_config_exists(self):
        """Crea il file di configurazione con valori di default se non esiste"""
        if not self.config_path.exists():
            logger.info(f"Creating default scan_ports.json at {self.config_path}")
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            
            default_config = {
                "tcp_ports": {
                    "20": "ftp-data",
                    "21": "ftp",
                    "22": "ssh",
                    "23": "telnet",
                    "25": "smtp",
                    "53": "dns",
                    "69": "tftp",
                    "80": "http",
                    "110": "pop3",
                    "111": "rpcbind",
                    "123": "ntp",
                    "135": "wmi",
                    "139": "netbios",
                    "143": "imap",
                    "161": "snmp",
                    "162": "snmp-trap",
                    "389": "ldap",
                    "443": "https",
                    "445": "smb",
                    "465": "smtps",
                    "514": "syslog",
                    "587": "smtp-submission",
                    "636": "ldaps",
                    "902": "vmware-soap",
                    "903": "vmware-vnc",
                    "993": "imaps",
                    "995": "pop3s",
                    "1433": "mssql",
                    "1494": "citrix-ica",
                    "1521": "oracle",
                    "2049": "nfs",
                    "2179": "hyper-v",
                    "2222": "ssh-alt",
                    "2375": "docker",
                    "2376": "docker-tls",
                    "2598": "citrix-ica-alt",
                    "3306": "mysql",
                    "3389": "rdp",
                    "3390": "rdp-alt",
                    "5432": "postgresql",
                    "5900": "vnc",
                    "5901": "vnc",
                    "5902": "vnc",
                    "5903": "vnc",
                    "5904": "vnc",
                    "5905": "vnc",
                    "5985": "winrm-http",
                    "5986": "winrm-https",
                    "6443": "kubernetes-api",
                    "6379": "redis",
                    "8000": "http-alt",
                    "8006": "proxmox-ve",
                    "8007": "proxmox-backup",
                    "8080": "http-proxy",
                    "8291": "mikrotik-winbox",
                    "8443": "https-alt",
                    "8728": "mikrotik-api",
                    "8888": "http-alt",
                    "9000": "sonarqube",
                    "9090": "prometheus",
                    "10250": "kubelet",
                    "1900": "ssdp",
                    "27017": "mongodb"
                },
                "udp_ports": {
                    "53": "dns",
                    "67": "dhcp-server",
                    "68": "dhcp-client",
                    "69": "tftp",
                    "123": "ntp",
                    "137": "netbios-ns",
                    "138": "netbios-dgm",
                    "161": "snmp",
                    "162": "snmp-trap",
                    "500": "ipsec-ike",
                    "1900": "ssdp",
                    "5353": "mdns"
                }
            }
            
            self._write_config(default_config)
    
    def _read_config(self) -> Dict:
        """Legge la configurazione dal file JSON"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading scan_ports.json: {e}")
            raise
    
    def _write_config(self, config: Dict):
        """Scrive la configurazione nel file JSON"""
        try:
            with open(self.config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            # Invalida cache
            self._cache = None
            logger.info(f"Scan ports configuration updated at {self.config_path}")
        except Exception as e:
            logger.error(f"Error writing scan_ports.json: {e}")
            raise
    
    def get_tcp_ports(self) -> Dict[int, str]:
        """
        Ottiene il dizionario delle porte TCP da scansionare.
        
        Returns:
            Dict con porta (int) -> nome servizio (str)
        """
        config = self._read_config()
        tcp_ports = config.get("tcp_ports", {})
        # Converti chiavi stringhe in int
        return {int(port): service for port, service in tcp_ports.items()}
    
    def get_udp_ports(self) -> Dict[int, str]:
        """
        Ottiene il dizionario delle porte UDP da scansionare.
        
        Returns:
            Dict con porta (int) -> nome servizio (str)
        """
        config = self._read_config()
        udp_ports = config.get("udp_ports", {})
        # Converti chiavi stringhe in int
        return {int(port): service for port, service in udp_ports.items()}
    
    def update_tcp_ports(self, tcp_ports: Dict[int, str]):
        """
        Aggiorna le porte TCP.
        
        Args:
            tcp_ports: Dict con porta (int) -> nome servizio (str)
        """
        config = self._read_config()
        # Converti chiavi int in stringhe per JSON
        config["tcp_ports"] = {str(port): service for port, service in tcp_ports.items()}
        self._write_config(config)
    
    def update_udp_ports(self, udp_ports: Dict[int, str]):
        """
        Aggiorna le porte UDP.
        
        Args:
            udp_ports: Dict con porta (int) -> nome servizio (str)
        """
        config = self._read_config()
        # Converti chiavi int in stringhe per JSON
        config["udp_ports"] = {str(port): service for port, service in udp_ports.items()}
        self._write_config(config)
    
    def update_all_ports(self, tcp_ports: Dict[int, str], udp_ports: Dict[int, str]):
        """
        Aggiorna sia porte TCP che UDP.
        
        Args:
            tcp_ports: Dict con porta (int) -> nome servizio (str)
            udp_ports: Dict con porta (int) -> nome servizio (str)
        """
        config = {
            "tcp_ports": {str(port): service for port, service in tcp_ports.items()},
            "udp_ports": {str(port): service for port, service in udp_ports.items()}
        }
        self._write_config(config)
    
    def get_config_dict(self) -> Dict:
        """
        Ottiene la configurazione completa come dizionario.
        
        Returns:
            Dict con "tcp_ports" e "udp_ports" (chiavi come stringhe)
        """
        return self._read_config()


# Singleton instance
_scan_ports_config_instance: Optional[ScanPortsConfig] = None


def get_scan_ports_config(config_path: Optional[str] = None) -> ScanPortsConfig:
    """
    Ottiene l'istanza singleton del servizio di configurazione porte.
    
    Args:
        config_path: Path opzionale al file di configurazione
    
    Returns:
        Istanza ScanPortsConfig
    """
    global _scan_ports_config_instance
    if _scan_ports_config_instance is None:
        _scan_ports_config_instance = ScanPortsConfig(config_path)
    return _scan_ports_config_instance
