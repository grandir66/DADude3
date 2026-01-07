"""
MikroTik Backup Collector - NUOVO MODULO
Estende funzionalità esistenti di mikrotik_service.py per backup configurazioni
Supporta backup via SSH (export) e download file binari

Non modifica mikrotik_service.py esistente
"""
import paramiko
import time
import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import re


class MikroTikBackupCollector:
    """
    Collector per backup configurazioni RouterOS MikroTik
    Supporta export testuale e backup binari
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.timeout = self.config.get('timeout', 30)
        self.sftp_enabled = self.config.get('sftp_enabled', True)

    def test_connection(self, host: str, username: str, password: str,
                       port: int = 22) -> Dict[str, Any]:
        """
        Testa connessione SSH a MikroTik e recupera info base

        Returns:
            dict: {
                "success": bool,
                "identity": str,
                "version": str,
                "board": str,
                "model": str,
                "serial": str,
                "uptime": str,
                "error": str (se failed)
            }
        """
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Testing connection to MikroTik {host}...")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            # Recupera identity
            stdin, stdout, stderr = client.exec_command('/system identity print')
            identity_output = stdout.read().decode('utf-8')

            identity = "MikroTik"
            for line in identity_output.splitlines():
                if "name:" in line:
                    identity = line.split(":", 1)[1].strip()
                    break

            # Recupera system resource
            stdin, stdout, stderr = client.exec_command('/system resource print')
            resource_output = stdout.read().decode('utf-8')

            version = "unknown"
            board = "unknown"
            uptime = "unknown"
            arch = "unknown"

            for line in resource_output.splitlines():
                if "version:" in line:
                    version = line.split(":", 1)[1].strip()
                elif "board-name:" in line:
                    board = line.split(":", 1)[1].strip()
                elif "uptime:" in line:
                    uptime = line.split(":", 1)[1].strip()
                elif "architecture-name:" in line:
                    arch = line.split(":", 1)[1].strip()

            # Recupera serial number (se disponibile)
            stdin, stdout, stderr = client.exec_command('/system routerboard print')
            routerboard_output = stdout.read().decode('utf-8')

            serial = "unknown"
            model = board  # Fallback al board-name

            for line in routerboard_output.splitlines():
                if "serial-number:" in line:
                    serial = line.split(":", 1)[1].strip()
                elif "model:" in line:
                    model = line.split(":", 1)[1].strip()

            client.close()

            return {
                "success": True,
                "identity": identity,
                "version": version,
                "board": board,
                "model": model,
                "serial": serial,
                "uptime": uptime,
                "architecture": arch
            }

        except Exception as e:
            self.logger.error(f"Connection test failed for {host}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def backup_configuration(self, host: str, username: str, password: str,
                            port: int = 22, backup_path: Optional[str] = None,
                            backup_type: str = "export") -> Dict[str, Any]:
        """
        Backup configurazione MikroTik

        Args:
            backup_type: "export" (testo), "binary" (backup binario), o "both"

        Returns:
            dict: {
                "success": bool,
                "export_config": str (se export),
                "binary_file": str (se binary),
                "file_path": str,
                "device_info": dict,
                "error": str (se failed)
            }
        """
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Connecting to MikroTik {host}:{port} for backup (SSH required)...")
            
            # Prova connessione con timeout più lungo per MikroTik
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=30  # Timeout più lungo per banner SSH
                )
            except paramiko.ssh_exception.SSHException as e:
                if "Error reading SSH protocol banner" in str(e) or "timeout" in str(e).lower():
                    error_msg = (
                        f"SSH connection failed to {host}:{port}. "
                        f"MikroTik backup requires SSH to be enabled. "
                        f"Please enable SSH service on the router or verify the SSH port is correct. "
                        f"Error: {str(e)}"
                    )
                    self.logger.error(error_msg)
                    return {
                        "success": False,
                        "error": error_msg
                    }
                raise
            except Exception as e:
                error_msg = (
                    f"Failed to connect to MikroTik {host}:{port} via SSH. "
                    f"Please verify: 1) SSH is enabled on the router, 2) SSH port is correct ({port}), "
                    f"3) Credentials are valid. Error: {str(e)}"
                )
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg
                }

            # Raccolta info device
            device_info = self._get_device_info(client)
            device_info["backup_timestamp"] = datetime.now().isoformat()

            result = {
                "success": True,
                "device_info": device_info,
                "backup_type": backup_type
            }

            # Export testuale
            if backup_type in ["export", "both"]:
                self.logger.info("Performing export backup...")
                export_config = self._export_config(client)
                result["export_config"] = export_config
                result["export_size_bytes"] = len(export_config.encode('utf-8'))

                # Salva export su file
                if backup_path:
                    export_file = self._save_export(
                        config=export_config,
                        device_info=device_info,
                        backup_path=backup_path,
                        host=host
                    )
                    result["export_file_path"] = export_file

            # Backup binario
            if backup_type in ["binary", "both"]:
                if self.sftp_enabled:
                    self.logger.info("Performing binary backup...")
                    binary_result = self._binary_backup(
                        client=client,
                        device_info=device_info,
                        backup_path=backup_path,
                        host=host
                    )
                    result.update(binary_result)
                else:
                    self.logger.warning("SFTP disabled, skipping binary backup")
                    result["binary_skipped"] = True

            return result

        except Exception as e:
            self.logger.error(f"Backup failed for {host}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def collect_device_info(self, host: str, username: str, password: str,
                           port: int = 22) -> Dict[str, Any]:
        """
        Raccolta informazioni complete dal device MikroTik
        (system, risorse, interfacce, IP, routes, etc.)

        Returns:
            dict con tutte le informazioni raccolte
        """
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Connecting to MikroTik {host} for info collection...")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            info = {
                "success": True,
                "timestamp": datetime.now().isoformat()
            }

            # System identity & resource
            info["device_info"] = self._get_device_info(client)

            # Interfacce
            self.logger.info("Collecting interfaces...")
            stdin, stdout, stderr = client.exec_command('/interface print detail without-paging')
            info["interfaces"] = self._parse_key_value_output(stdout.read().decode('utf-8'))

            # IP Addresses
            self.logger.info("Collecting IP addresses...")
            stdin, stdout, stderr = client.exec_command('/ip address print detail without-paging')
            info["ip_addresses"] = self._parse_key_value_output(stdout.read().decode('utf-8'))

            # Routes
            self.logger.info("Collecting routes...")
            stdin, stdout, stderr = client.exec_command('/ip route print detail without-paging')
            info["routes"] = self._parse_key_value_output(stdout.read().decode('utf-8'))

            # DHCP Server leases (se abilitato)
            try:
                stdin, stdout, stderr = client.exec_command('/ip dhcp-server lease print detail without-paging')
                info["dhcp_leases"] = self._parse_key_value_output(stdout.read().decode('utf-8'))
            except:
                info["dhcp_leases"] = []

            # Firewall rules count
            try:
                stdin, stdout, stderr = client.exec_command('/ip firewall filter print count-only')
                firewall_count = stdout.read().decode('utf-8').strip()
                info["firewall_rules_count"] = int(firewall_count) if firewall_count.isdigit() else 0
            except:
                info["firewall_rules_count"] = 0

            return info

        except Exception as e:
            self.logger.error(f"Info collection failed for {host}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    # ========================================================================
    # METODI PRIVATI
    # ========================================================================

    def _get_device_info(self, client: paramiko.SSHClient) -> Dict[str, Any]:
        """Recupera info base device"""
        info = {}

        # Identity
        stdin, stdout, stderr = client.exec_command('/system identity print')
        identity_output = stdout.read().decode('utf-8')
        for line in identity_output.splitlines():
            if "name:" in line:
                info["identity"] = line.split(":", 1)[1].strip()

        # Resource
        stdin, stdout, stderr = client.exec_command('/system resource print')
        resource_output = stdout.read().decode('utf-8')

        for line in resource_output.splitlines():
            if "version:" in line:
                info["version"] = line.split(":", 1)[1].strip()
            elif "board-name:" in line:
                info["board"] = line.split(":", 1)[1].strip()
            elif "uptime:" in line:
                info["uptime"] = line.split(":", 1)[1].strip()
            elif "architecture-name:" in line:
                info["architecture"] = line.split(":", 1)[1].strip()
            elif "cpu:" in line:
                info["cpu"] = line.split(":", 1)[1].strip()
            elif "total-memory:" in line:
                info["total_memory"] = line.split(":", 1)[1].strip()
            elif "free-memory:" in line:
                info["free_memory"] = line.split(":", 1)[1].strip()

        # Routerboard info
        stdin, stdout, stderr = client.exec_command('/system routerboard print')
        routerboard_output = stdout.read().decode('utf-8')

        for line in routerboard_output.splitlines():
            if "serial-number:" in line:
                info["serial"] = line.split(":", 1)[1].strip()
            elif "model:" in line:
                info["model"] = line.split(":", 1)[1].strip()
            elif "firmware:" in line:
                info["firmware"] = line.split(":", 1)[1].strip()

        return info

    def _export_config(self, client: paramiko.SSHClient) -> str:
        """Esegue /export e recupera configurazione completa"""
        # Export con verbose per commenti
        stdin, stdout, stderr = client.exec_command('/export verbose')
        time.sleep(2)  # Attendi completamento

        export_output = stdout.read().decode('utf-8', errors='ignore')

        # Pulizia output (rimuovi prompt e caratteri extra)
        lines = []
        for line in export_output.splitlines():
            # Skip linee vuote e prompt
            if line.strip() and not line.strip().startswith('['):
                lines.append(line)

        return "\n".join(lines)

    def _binary_backup(self, client: paramiko.SSHClient, device_info: Dict[str, Any],
                      backup_path: Optional[str], host: str) -> Dict[str, Any]:
        """
        Crea backup binario RouterOS e lo scarica via SFTP

        Returns:
            dict: {
                "binary_file_path": str,
                "binary_size_bytes": int,
                "binary_checksum": str
            }
        """
        result = {}

        # Nome file backup remoto
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        identity = device_info.get("identity", host.replace('.', '_'))
        remote_filename = f"backup_{identity}_{timestamp}"

        try:
            # Crea backup su MikroTik
            self.logger.info(f"Creating binary backup: {remote_filename}")
            stdin, stdout, stderr = client.exec_command(
                f'/system backup save name={remote_filename}'
            )
            time.sleep(3)  # Attendi creazione file

            # Verifica esistenza file
            stdin, stdout, stderr = client.exec_command('/file print detail')
            files_output = stdout.read().decode('utf-8')

            if remote_filename not in files_output:
                raise Exception(f"Backup file {remote_filename}.backup not created")

            # Download via SFTP
            if backup_path:
                local_path = self._download_backup_sftp(
                    client=client,
                    remote_filename=f"{remote_filename}.backup",
                    device_info=device_info,
                    backup_path=backup_path,
                    host=host
                )

                result["binary_file_path"] = local_path

                # Calcola dimensione e checksum
                local_file = Path(local_path)
                if local_file.exists():
                    result["binary_size_bytes"] = local_file.stat().st_size

                    # Checksum SHA256
                    with open(local_file, 'rb') as f:
                        file_hash = hashlib.sha256(f.read()).hexdigest()
                        result["binary_checksum"] = file_hash

                # Cleanup file remoto
                self.logger.info("Cleaning up remote backup file...")
                stdin, stdout, stderr = client.exec_command(
                    f'/file remove {remote_filename}.backup'
                )

        except Exception as e:
            self.logger.error(f"Binary backup failed: {e}")
            result["binary_error"] = str(e)

        return result

    def _download_backup_sftp(self, client: paramiko.SSHClient, remote_filename: str,
                             device_info: Dict[str, Any], backup_path: str,
                             host: str) -> str:
        """Download file backup via SFTP"""
        identity = device_info.get("identity", host.replace('.', '_'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Path locale
        backup_dir = Path(backup_path) / identity
        backup_dir.mkdir(parents=True, exist_ok=True)

        local_filename = f"{identity}_{timestamp}.backup"
        local_path = backup_dir / local_filename

        # SFTP transfer
        sftp = client.open_sftp()
        self.logger.info(f"Downloading {remote_filename} to {local_path}...")

        sftp.get(remote_filename, str(local_path))
        sftp.close()

        self.logger.info(f"Download completed: {local_path}")
        return str(local_path)

    def _save_export(self, config: str, device_info: Dict[str, Any],
                    backup_path: str, host: str) -> str:
        """Salva export testuale su file"""
        identity = device_info.get("identity", host.replace('.', '_'))
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        backup_dir = Path(backup_path) / identity
        backup_dir.mkdir(parents=True, exist_ok=True)

        file_name = f"{identity}_{timestamp}.rsc"
        file_path = backup_dir / file_name

        # Header informativo
        header = f"""# MikroTik RouterOS Configuration Export
# Identity: {device_info.get('identity', 'unknown')}
# Model: {device_info.get('model', 'unknown')}
# Version: {device_info.get('version', 'unknown')}
# Serial: {device_info.get('serial', 'unknown')}
# Board: {device_info.get('board', 'unknown')}
# Backup Date: {device_info.get('backup_timestamp', 'unknown')}
# IP Address: {host}

"""

        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write(config)

        return str(file_path)

    def _parse_key_value_output(self, output: str) -> List[Dict[str, str]]:
        """
        Parse output RouterOS in formato key-value
        Es: /interface print detail
        """
        items = []
        current_item = {}

        for line in output.splitlines():
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            # Riga vuota = fine item
            if not line and current_item:
                items.append(current_item)
                current_item = {}
                continue

            # Parse key=value o key: value
            if '=' in line:
                parts = line.split('=', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ""
                current_item[key] = value
            elif ':' in line:
                parts = line.split(':', 1)
                key = parts[0].strip()
                value = parts[1].strip() if len(parts) > 1 else ""
                current_item[key] = value

        # Aggiungi ultimo item
        if current_item:
            items.append(current_item)

        return items
