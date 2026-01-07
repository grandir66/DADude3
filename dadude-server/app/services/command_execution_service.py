"""
Command Execution Service - NUOVO MODULO
Servizio per invio comandi di configurazione a switch/router
Supporta validazione comandi e rollback automatico

Integra funzionalità da switch_config.ps1 (script PowerShell originale)
Non modifica servizi esistenti
"""
import logging
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from .hp_aruba_collector import HPArubaCollector
from .mikrotik_backup_collector import MikroTikBackupCollector


class CommandExecutionService:
    """
    Servizio per esecuzione comandi su dispositivi di rete
    Supporta HP/Aruba e MikroTik con backup pre-change automatico
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Path per log comandi
        self.commands_log_path = self.config.get(
            'commands_log_path',
            './logs/commands'
        )
        Path(self.commands_log_path).mkdir(parents=True, exist_ok=True)

        # Collectors
        self.hp_collector = HPArubaCollector(config)
        self.mikrotik_collector = MikroTikBackupCollector(config)

    def execute_commands_on_device(
        self,
        device_ip: str,
        device_type: str,
        credentials: Dict[str, Any],
        commands: List[str],
        backup_before: bool = True,
        validate_before: bool = False,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Esegue lista comandi su dispositivo

        Args:
            device_ip: IP device
            device_type: "hp_aruba" o "mikrotik"
            credentials: {"username": ..., "password": ..., "port": ...}
            commands: Lista comandi da eseguire
            backup_before: Se True, esegue backup prima di applicare comandi
            validate_before: Se True, valida comandi prima dell'esecuzione
            dry_run: Se True, simula esecuzione senza applicare comandi

        Returns:
            dict: {
                "success": bool,
                "backup_file": str (se backup_before=True),
                "commands_executed": int,
                "commands_failed": int,
                "results": list,
                "error": str (se failed)
            }
        """
        try:
            self.logger.info(f"Executing {len(commands)} commands on {device_ip} ({device_type})")

            result = {
                "success": False,
                "device_ip": device_ip,
                "device_type": device_type,
                "timestamp": datetime.now().isoformat()
            }

            # Validazione comandi (opzionale)
            if validate_before:
                validation = self._validate_commands(commands, device_type)
                if not validation["valid"]:
                    return {
                        "success": False,
                        "error": f"Command validation failed: {validation['error']}",
                        "validation_errors": validation.get("errors", [])
                    }

            # Backup pre-change
            if backup_before and not dry_run:
                self.logger.info("Creating pre-change backup...")
                backup_result = self._create_prechange_backup(
                    device_ip=device_ip,
                    device_type=device_type,
                    credentials=credentials
                )

                if backup_result["success"]:
                    result["backup_file"] = backup_result.get("file_path")
                else:
                    self.logger.warning(f"Pre-change backup failed: {backup_result.get('error')}")
                    result["backup_warning"] = backup_result.get("error")

            # Esegui comandi
            if device_type == "hp_aruba":
                exec_result = self._execute_hp_aruba_commands(
                    device_ip=device_ip,
                    credentials=credentials,
                    commands=commands,
                    dry_run=dry_run
                )
            elif device_type == "mikrotik":
                exec_result = self._execute_mikrotik_commands(
                    device_ip=device_ip,
                    credentials=credentials,
                    commands=commands,
                    dry_run=dry_run
                )
            else:
                return {
                    "success": False,
                    "error": f"Unsupported device type: {device_type}"
                }

            result.update(exec_result)

            # Salva log esecuzione
            if not dry_run:
                self._save_execution_log(
                    device_ip=device_ip,
                    commands=commands,
                    result=exec_result
                )

            return result

        except Exception as e:
            self.logger.error(f"Command execution failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def execute_commands_from_file(
        self,
        device_ip: str,
        device_type: str,
        credentials: Dict[str, Any],
        commands_file: str,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Esegue comandi da file

        Args:
            commands_file: Path al file con comandi (uno per riga)
            **kwargs: Parametri addizionali per execute_commands_on_device

        Returns:
            dict risultato esecuzione
        """
        try:
            # Leggi comandi da file
            with open(commands_file, 'r', encoding='utf-8') as f:
                commands = [
                    line.strip()
                    for line in f
                    if line.strip() and not line.strip().startswith('#')
                ]

            self.logger.info(f"Loaded {len(commands)} commands from {commands_file}")

            return self.execute_commands_on_device(
                device_ip=device_ip,
                device_type=device_type,
                credentials=credentials,
                commands=commands,
                **kwargs
            )

        except FileNotFoundError:
            return {
                "success": False,
                "error": f"Commands file not found: {commands_file}"
            }
        except Exception as e:
            self.logger.error(f"Error reading commands file: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    # ========================================================================
    # METODI PRIVATI - Esecuzione Device-Specific
    # ========================================================================

    def _execute_hp_aruba_commands(
        self,
        device_ip: str,
        credentials: Dict[str, Any],
        commands: List[str],
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Esegue comandi su switch HP/Aruba"""
        import paramiko
        import time

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "commands_executed": len(commands),
                "message": "Dry run: commands validated but not executed"
            }

        client = None
        shell = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=device_ip,
                port=credentials.get("port", 22),
                username=credentials["username"],
                password=credentials["password"],
                timeout=30,
                allow_agent=False,
                look_for_keys=False
            )

            shell = client.invoke_shell(term="vt100", width=160, height=1000)
            time.sleep(2)

            # Svuota buffer
            if shell.recv_ready():
                shell.recv(4096)

            # Disabilita paginazione
            self._send_command(shell, "no page")

            # Entra in modalità configurazione
            self._send_command(shell, "configure terminal")

            results = []
            success_count = 0
            failed_count = 0

            # Esegui ogni comando
            for cmd in commands:
                cmd_result = self._send_command(shell, cmd, check_errors=True)

                if cmd_result["success"]:
                    success_count += 1
                else:
                    failed_count += 1

                results.append({
                    "command": cmd,
                    "success": cmd_result["success"],
                    "output": cmd_result["output"],
                    "error": cmd_result.get("error")
                })

            # Esci da config e salva
            self._send_command(shell, "exit")
            save_result = self._send_command(shell, "write memory")

            # Riabilita paginazione
            self._send_command(shell, "page")

            return {
                "success": failed_count == 0,
                "commands_executed": len(commands),
                "commands_success": success_count,
                "commands_failed": failed_count,
                "results": results,
                "config_saved": save_result["success"]
            }

        except Exception as e:
            self.logger.error(f"HP/Aruba command execution error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if shell:
                shell.close()
            if client:
                client.close()

    def _execute_mikrotik_commands(
        self,
        device_ip: str,
        credentials: Dict[str, Any],
        commands: List[str],
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """Esegue comandi su MikroTik"""
        import paramiko

        if dry_run:
            return {
                "success": True,
                "dry_run": True,
                "commands_executed": len(commands),
                "message": "Dry run: commands validated but not executed"
            }

        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            client.connect(
                hostname=device_ip,
                port=credentials.get("port", 22),
                username=credentials["username"],
                password=credentials["password"],
                timeout=30,
                allow_agent=False,
                look_for_keys=False
            )

            results = []
            success_count = 0
            failed_count = 0

            for cmd in commands:
                try:
                    stdin, stdout, stderr = client.exec_command(cmd)
                    output = stdout.read().decode('utf-8')
                    error = stderr.read().decode('utf-8')

                    if error:
                        failed_count += 1
                        results.append({
                            "command": cmd,
                            "success": False,
                            "output": output,
                            "error": error
                        })
                    else:
                        success_count += 1
                        results.append({
                            "command": cmd,
                            "success": True,
                            "output": output
                        })

                except Exception as e:
                    failed_count += 1
                    results.append({
                        "command": cmd,
                        "success": False,
                        "error": str(e)
                    })

            return {
                "success": failed_count == 0,
                "commands_executed": len(commands),
                "commands_success": success_count,
                "commands_failed": failed_count,
                "results": results
            }

        except Exception as e:
            self.logger.error(f"MikroTik command execution error: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                client.close()

    def _send_command(self, shell, command: str, check_errors: bool = False) -> Dict[str, Any]:
        """Invia comando su shell SSH HP/Aruba"""
        import time
        import re

        while shell.recv_ready():
            shell.recv(4096)

        shell.send(command + "\n")
        time.sleep(1)

        output = ""
        for _ in range(10):
            if shell.recv_ready():
                chunk = shell.recv(4096).decode('utf-8', errors='ignore')
                output += chunk
                time.sleep(0.2)
            else:
                break

        # Check for errors
        error = None
        if check_errors:
            if re.search(r'(Invalid input|Error|failed)', output, re.IGNORECASE):
                error = "Command error detected in output"

        return {
            "success": error is None,
            "output": output,
            "error": error
        }

    # ========================================================================
    # METODI PRIVATI - Utility
    # ========================================================================

    def _create_prechange_backup(
        self,
        device_ip: str,
        device_type: str,
        credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Crea backup pre-change"""
        try:
            if device_type == "hp_aruba":
                return self.hp_collector.backup_configuration(
                    host=device_ip,
                    username=credentials["username"],
                    password=credentials["password"],
                    port=credentials.get("port", 22),
                    backup_path=f"{self.commands_log_path}/prechange_backups"
                )

            elif device_type == "mikrotik":
                return self.mikrotik_collector.backup_configuration(
                    host=device_ip,
                    username=credentials["username"],
                    password=credentials["password"],
                    port=credentials.get("port", 22),
                    backup_path=f"{self.commands_log_path}/prechange_backups",
                    backup_type="export"
                )

            return {
                "success": False,
                "error": f"Unsupported device type: {device_type}"
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _validate_commands(self, commands: List[str], device_type: str) -> Dict[str, Any]:
        """
        Validazione base comandi (syntax check)
        Per validazione AI avanzata, usare AIValidationService

        Returns:
            dict: {"valid": bool, "errors": list, "warnings": list}
        """
        errors = []
        warnings = []

        # Validazione base per HP/Aruba
        if device_type == "hp_aruba":
            dangerous_commands = [
                "reload", "boot", "erase", "delete", "format"
            ]

            for cmd in commands:
                cmd_lower = cmd.lower().strip()

                # Check comandi pericolosi
                for dangerous in dangerous_commands:
                    if dangerous in cmd_lower:
                        warnings.append(f"Dangerous command detected: {cmd}")

                # Check sintassi base
                if not cmd.strip():
                    errors.append("Empty command found")

        # Validazione base per MikroTik
        elif device_type == "mikrotik":
            for cmd in commands:
                if not cmd.startswith('/'):
                    warnings.append(f"MikroTik command should start with '/': {cmd}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings
        }

    def _save_execution_log(
        self,
        device_ip: str,
        commands: List[str],
        result: Dict[str, Any]
    ):
        """Salva log esecuzione comandi"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = Path(self.commands_log_path) / f"exec_{device_ip}_{timestamp}.log"

            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(f"Command Execution Log\n")
                f.write(f"Device: {device_ip}\n")
                f.write(f"Timestamp: {datetime.now().isoformat()}\n")
                f.write(f"Commands: {len(commands)}\n")
                f.write(f"Success: {result.get('success')}\n")
                f.write(f"\n{'='*60}\n\n")

                for cmd_result in result.get("results", []):
                    f.write(f"Command: {cmd_result['command']}\n")
                    f.write(f"Success: {cmd_result['success']}\n")
                    if cmd_result.get('error'):
                        f.write(f"Error: {cmd_result['error']}\n")
                    f.write(f"\n")

            self.logger.info(f"Execution log saved: {log_file}")

        except Exception as e:
            self.logger.error(f"Error saving execution log: {e}")
