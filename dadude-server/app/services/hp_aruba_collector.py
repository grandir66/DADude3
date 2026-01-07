"""
HP/Aruba Switch Collector - NUOVO MODULO
Raccolta configurazioni e informazioni da switch HP ProCurve/Aruba
Integra funzionalità da Script_net per backup config e info switch

Non modifica servizi esistenti
"""
import paramiko
import re
import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
from pathlib import Path


class HPArubaCollector:
    """
    Collector per switch HP ProCurve e Aruba
    Supporta backup configurazioni e raccolta informazioni dettagliate
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.timeout = self.config.get('timeout', 30)
        self.command_delay = self.config.get('command_delay', 2)

        # Regex per pulizia output ANSI
        self.ansi_escape = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]|\x1b\[\?25[hl]|'
                                       r'\[\d+;\d+[rH]|\[2K|\[1[ML]|--More--'
                                       r'|\[42D\s+\[42D')

    def test_connection(self, host: str, username: str, password: str,
                       port: int = 22) -> Dict[str, Any]:
        """
        Testa connessione SSH e recupera info base dello switch

        Returns:
            dict: {
                "success": bool,
                "system_name": str,
                "model": str,
                "firmware": str,
                "serial": str,
                "error": str (se success=False)
            }
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            # Crea shell per comandi interattivi
            shell = client.invoke_shell(term="vt100", width=160, height=1000)
            time.sleep(2)

            # Svuota buffer iniziale
            if shell.recv_ready():
                shell.recv(4096)

            # Disabilita paginazione
            self._execute_command(shell, "no page")

            # Ottieni system info
            system_output = self._execute_command(shell, "show system")
            system_info = self._parse_system_info(system_output)

            # Ottieni modello da show modules
            modules_output = self._execute_command(shell, "show modules")
            model = self._extract_model_from_modules(modules_output)

            shell.close()
            client.close()

            return {
                "success": True,
                "system_name": system_info.get("system_name", "unknown"),
                "model": model,
                "firmware": system_info.get("software_revision", "unknown"),
                "serial": system_info.get("serial_number", "unknown"),
                "system_location": system_info.get("system_location", "unknown")
            }

        except Exception as e:
            self.logger.error(f"Connection test failed for {host}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    def backup_configuration(self, host: str, username: str, password: str,
                            port: int = 22, backup_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Backup completo della configurazione running-config

        Returns:
            dict: {
                "success": bool,
                "config": str,
                "file_path": str (se backup_path fornito),
                "device_info": dict,
                "error": str (se failed)
            }
        """
        client = None
        shell = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Connecting to {host} for backup...")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            shell = client.invoke_shell(term="vt100", width=160, height=1000)
            time.sleep(2)

            # Svuota buffer
            if shell.recv_ready():
                shell.recv(4096)

            # Disabilita paginazione
            self._execute_command(shell, "no page")

            # Raccolta info device
            self.logger.info("Gathering device information...")
            system_output = self._execute_command(shell, "show system")
            system_info = self._parse_system_info(system_output)

            modules_output = self._execute_command(shell, "show modules")
            model = self._extract_model_from_modules(modules_output)

            device_info = {
                "system_name": system_info.get("system_name", "unknown"),
                "system_location": system_info.get("system_location", "unknown"),
                "model": model,
                "firmware": system_info.get("software_revision", "unknown"),
                "serial": system_info.get("serial_number", "unknown"),
                "backup_timestamp": datetime.now().isoformat()
            }

            # Backup running-config
            self.logger.info("Backing up running-config...")
            config_output = self._execute_command(shell, "show running-config", delay=3)
            clean_config = self._clean_output(config_output)

            # Riabilita paginazione
            self._execute_command(shell, "page")

            # Salva su file se richiesto
            file_path = None
            if backup_path:
                file_path = self._save_backup(
                    config=clean_config,
                    device_info=device_info,
                    backup_path=backup_path,
                    host=host
                )
                self.logger.info(f"Backup saved to: {file_path}")

            return {
                "success": True,
                "config": clean_config,
                "file_path": file_path,
                "device_info": device_info,
                "size_bytes": len(clean_config.encode('utf-8'))
            }

        except Exception as e:
            self.logger.error(f"Backup failed for {host}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if shell:
                shell.close()
            if client:
                client.close()

    def collect_switch_info(self, host: str, username: str, password: str,
                           port: int = 22) -> Dict[str, Any]:
        """
        Raccolta completa informazioni switch (interfacce, VLAN, LLDP, PoE)
        Integra funzionalità da info_complete.py

        Returns:
            dict: {
                "success": bool,
                "system_info": dict,
                "interfaces": dict,
                "vlans": dict,
                "lldp": dict,
                "poe": dict,
                "error": str (se failed)
            }
        """
        client = None
        shell = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Connecting to {host} for info collection...")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            shell = client.invoke_shell(term="vt100", width=160, height=1000)
            time.sleep(2)

            if shell.recv_ready():
                shell.recv(4096)

            # Disabilita paginazione
            self._execute_command(shell, "no page")

            # System info
            self.logger.info("Collecting system info...")
            system_output = self._execute_command(shell, "show system")
            system_info = self._parse_system_info(system_output)

            modules_output = self._execute_command(shell, "show modules")
            system_info["model"] = self._extract_model_from_modules(modules_output)

            # Interfaces
            self.logger.info("Collecting interface info...")
            intf_output = self._execute_command(shell, "show interfaces brief")
            interfaces = self._parse_interfaces_brief(intf_output)

            names_output = self._execute_command(shell, "show name")
            port_names = self._parse_port_names(names_output)

            # Merge names into interfaces
            for port, name in port_names.items():
                if port in interfaces:
                    interfaces[port]["description"] = name

            # VLAN info
            self.logger.info("Collecting VLAN info...")
            vlan_output = self._execute_command(shell, "show vlans")
            vlans = self._parse_vlans(vlan_output)

            # LLDP neighbors
            self.logger.info("Collecting LLDP info...")
            lldp_output = self._execute_command(shell, "show lldp info remote-device detail")
            lldp = self._parse_lldp(lldp_output)

            # PoE info (se supportato)
            self.logger.info("Collecting PoE info...")
            try:
                poe_output = self._execute_command(shell, "show power-over-ethernet brief")
                poe = self._parse_poe(poe_output)
            except Exception as e:
                self.logger.warning(f"PoE not supported or error: {e}")
                poe = {}

            return {
                "success": True,
                "system_info": system_info,
                "interfaces": interfaces,
                "vlans": vlans,
                "lldp": lldp,
                "poe": poe,
                "timestamp": datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Info collection failed for {host}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if shell:
                shell.close()
            if client:
                client.close()

    # ========================================================================
    # METODI PRIVATI - Utility e Parsing
    # ========================================================================

    def _execute_command(self, shell, command: str, delay: int = None) -> str:
        """Esegue comando su shell SSH gestendo paginazione"""
        if delay is None:
            delay = self.command_delay

        self.logger.debug(f"Executing: {command}")

        # Svuota buffer
        while shell.recv_ready():
            shell.recv(4096)

        shell.send(command + "\n")
        time.sleep(delay)

        output = ""
        start_time = time.time()
        max_wait = self.timeout

        while True:
            if shell.recv_ready():
                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                output += chunk

                # Gestione paginazione --More--
                if '--More--' in chunk:
                    shell.send(' ')
                    time.sleep(0.5)
                # Prompt trovato
                elif re.search(r'(^|\n)[\w\-]+#\s*$', chunk):
                    break
            else:
                if output:
                    time.sleep(1)
                    if not shell.recv_ready():
                        break
                if time.time() - start_time > max_wait:
                    self.logger.warning(f"Command timeout: {command}")
                    break

        return output

    def _clean_output(self, text: str) -> str:
        """Rimuove caratteri di controllo ANSI e prompt"""
        cleaned = self.ansi_escape.sub('', text)
        # Rimuovi prompt (es: "SW-NAME#")
        cleaned = re.sub(r'(^|\n)[\w\-]+#\s*$', '', cleaned, flags=re.MULTILINE)
        return cleaned.strip()

    def _parse_system_info(self, output: str) -> Dict[str, str]:
        """
        Estrae info da 'show system'
        System Name, System Location, Software revision, Serial Number
        """
        result = {
            "system_name": "unknown",
            "system_location": "unknown",
            "software_revision": "unknown",
            "serial_number": "unknown"
        }

        pattern = re.compile(
            r'(System Name|System Location|Software revision|Serial Number)\s*:\s*([^:]+)',
            re.IGNORECASE
        )

        for line in output.splitlines():
            for match in pattern.finditer(line):
                key = match.group(1).lower().replace(" ", "_")
                value = match.group(2).strip()
                # Taglia eventuali campi successivi sulla stessa riga
                value = re.split(r'\s{2,}', value)[0].strip()

                if key in result:
                    result[key] = value

        return result

    def _extract_model_from_modules(self, output: str) -> str:
        """Estrae modello da 'show modules'"""
        clean = self._clean_output(output)

        for line in clean.splitlines():
            if "Chassis:" in line:
                line = line.strip()
                line = line.replace("Chassis:", "").strip()
                # Rimuovi "Serial Number:" e tutto dopo
                line = re.sub(r'\s+Serial Number:.*', '', line)
                return line.strip()

        return "unknown"

    def _parse_interfaces_brief(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse 'show interfaces brief'"""
        interfaces = {}
        data_started = False

        for line in output.splitlines():
            line = line.strip()

            if not data_started:
                if '----' in line or "Port" in line:
                    data_started = True
                continue

            if not line or line.startswith("SW-"):
                continue

            # Pattern: Port | Type | Intrusion Alert | Status | Mode
            # Esempio: "1    | 100/1000T | No     | Down   | Auto"
            match = re.match(r'^(\d+(?:-?Trk\d+)?)\s*\|', line)
            if match:
                port = match.group(1)
                parts = [p.strip() for p in line.split('|')]

                if len(parts) >= 5:
                    interfaces[port] = {
                        "port": port,
                        "type": parts[1] if len(parts) > 1 else "",
                        "status": parts[3] if len(parts) > 3 else "",
                        "mode": parts[4] if len(parts) > 4 else "",
                        "is_trunk": '-Trk' in port
                    }

        return interfaces

    def _parse_port_names(self, output: str) -> Dict[str, str]:
        """Parse 'show name' per descrizioni porte"""
        names = {}
        data_started = False

        for line in output.splitlines():
            line = line.strip()

            if not data_started:
                if '----' in line:
                    data_started = True
                continue

            if not line:
                continue

            parts = line.split(None, 2)
            if len(parts) >= 3:
                port = parts[0]
                if port.replace('-', '').isdigit():
                    name = parts[2].strip()
                    if name:
                        names[port] = name

        return names

    def _parse_vlans(self, output: str) -> Dict[str, Dict[str, Any]]:
        """Parse 'show vlans'"""
        vlans = {}

        for line in output.splitlines():
            line = line.strip()

            # Pattern: VLAN_ID VLAN_NAME | Port-based
            match = re.match(r'^(\d+)\s+(\S+.*?)\s+\|\s+Port-based', line)
            if match:
                vlan_id = match.group(1).strip()
                vlan_name = match.group(2).strip()
                vlans[vlan_id] = {
                    "id": vlan_id,
                    "name": vlan_name,
                    "type": "port-based"
                }

        return vlans

    def _parse_lldp(self, output: str) -> Dict[str, Dict[str, str]]:
        """Parse 'show lldp info remote-device detail'"""
        lldp_info = {}
        current_port = None

        for line in output.splitlines():
            line = line.strip()

            if not line:
                continue

            # Local Port : XX
            if line.startswith("Local Port"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    current_port = parts[1].strip()
                    lldp_info[current_port] = {}
                continue

            # Se siamo in un blocco porta, parse key: value
            if current_port and ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                lldp_info[current_port][key] = value

        return lldp_info

    def _parse_poe(self, output: str) -> Dict[str, Dict[str, str]]:
        """Parse 'show power-over-ethernet brief'"""
        poe_info = {}

        for line in output.splitlines():
            line = line.strip()

            if not line or re.match(r'^(PoE|Port)', line) or re.match(r'^[-\s]+$', line):
                continue

            if re.match(r'^\d+', line):
                tokens = line.split()
                if len(tokens) >= 10:
                    port = tokens[0]
                    pwr_enab = tokens[1]
                    pd_pwr_draw = tokens[8] + " " + tokens[9] if len(tokens) > 9 else ""

                    poe_info[port] = {
                        "enabled": pwr_enab,
                        "power_draw": pd_pwr_draw
                    }

        return poe_info

    def _save_backup(self, config: str, device_info: Dict[str, Any],
                     backup_path: str, host: str) -> str:
        """Salva backup su file"""
        # Crea path gerarchico: backup_path/system_name/timestamp.cfg
        system_name = device_info.get("system_name", host.replace('.', '_'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_dir = Path(backup_path) / system_name
        backup_dir.mkdir(parents=True, exist_ok=True)

        file_name = f"{system_name}_{timestamp}.cfg"
        file_path = backup_dir / file_name

        # Scrivi header informativo
        header = f"""!
! HP/Aruba Switch Configuration Backup
! System Name: {device_info.get('system_name', 'unknown')}
! Model: {device_info.get('model', 'unknown')}
! Firmware: {device_info.get('firmware', 'unknown')}
! Serial: {device_info.get('serial', 'unknown')}
! Location: {device_info.get('system_location', 'unknown')}
! Backup Date: {device_info.get('backup_timestamp', 'unknown')}
! IP Address: {host}
!
"""

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(config)

        return str(file_path)
