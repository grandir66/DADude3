"""
Device Backup Service - NUOVO MODULO
Orchestrator centrale per backup configurazioni dispositivi
Coordina collectors HP/Aruba e MikroTik, gestisce storage e database

Non modifica servizi esistenti
"""
import os
import hashlib
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from pathlib import Path
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Import modelli esistenti e nuovi
try:
    from ..models.database import Customer, Network, Credential, DeviceAssignment
    from ..models.backup_models import (
        DeviceBackup, BackupSchedule, BackupJob, BackupTemplate
    )
    from .encryption_service import EncryptionService
except ImportError:
    # Fallback per test standalone
    pass

# Import collectors nuovi
from .hp_aruba_collector import HPArubaCollector
from .mikrotik_backup_collector import MikroTikBackupCollector
from .proxmox_backup_collector import ProxmoxBackupCollector


class DeviceBackupService:
    """
    Servizio orchestrator per backup dispositivi
    Gestisce workflow completo: identificazione device, credenziali, backup, storage
    """

    def __init__(self, db: Session, config: Dict[str, Any] = None):
        self.db = db
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

        # Path base per storage backup
        self.backup_base_path = self.config.get(
            'backup_path',
            os.getenv('BACKUP_PATH', './backups')
        )
        Path(self.backup_base_path).mkdir(parents=True, exist_ok=True)

        # Encryption service per password
        self.encryption = EncryptionService()

        # Inizializza collectors
        self.hp_collector = HPArubaCollector(config)
        self.mikrotik_collector = MikroTikBackupCollector(config)
        self.proxmox_collector = ProxmoxBackupCollector(config)

        self.logger.info(f"DeviceBackupService initialized. Backup path: {self.backup_base_path}")

    # ========================================================================
    # METODI PUBBLICI - Backup Device
    # ========================================================================

    def backup_device_by_assignment(self, device_assignment_id: str,
                                    backup_type: str = "config",
                                    triggered_by: str = "manual") -> Dict[str, Any]:
        """
        Backup di un dispositivo usando DeviceAssignment ID

        Args:
            device_assignment_id: ID dell'assegnazione device
            backup_type: "config", "binary", "both", "full"
            triggered_by: "manual", "api", "scheduler", "web_ui"

        Returns:
            dict con risultato backup e record DB creato
        """
        try:
            # Recupera device assignment
            assignment = self.db.query(DeviceAssignment).filter_by(
                id=device_assignment_id
            ).first()

            if not assignment:
                return {
                    "success": False,
                    "error": f"Device assignment {device_assignment_id} not found"
                }

            # Recupera customer e credenziali
            customer = self.db.query(Customer).filter_by(id=assignment.customer_id).first()
            if not customer:
                return {
                    "success": False,
                    "error": f"Customer {assignment.customer_id} not found"
                }

            # Identifica tipo device dal ruolo o altri metadata
            device_type = self._detect_device_type(assignment)

            # Ottieni credenziali appropriate
            credentials = self._get_device_credentials(assignment, customer, device_type)
            if not credentials:
                return {
                    "success": False,
                    "error": "No valid credentials found for device"
                }

            # Esegui backup
            backup_result = self._execute_backup(
                device_ip=assignment.dude_device_name,  # O usa IP se disponibile
                device_type=device_type,
                credentials=credentials,
                backup_type=backup_type,
                customer_code=customer.code
            )

            # Salva record in database
            if backup_result["success"]:
                backup_record = self._save_backup_record(
                    assignment=assignment,
                    customer=customer,
                    device_type=device_type,
                    backup_result=backup_result,
                    backup_type=backup_type,
                    triggered_by=triggered_by,
                    credentials=credentials
                )

                backup_result["backup_id"] = backup_record.id
                backup_result["database_record"] = True

            return backup_result

        except Exception as e:
            self.logger.error(f"Backup failed for device {device_assignment_id}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def backup_device_by_ip(self, device_ip: str, customer_id: str,
                           device_type: str = "auto",
                           backup_type: str = "config",
                           triggered_by: str = "manual",
                           credential_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Backup di un device tramite IP (anche se non assegnato)

        Args:
            device_ip: Indirizzo IP del device
            customer_id: ID cliente
            device_type: "hp_aruba", "mikrotik", "auto" (auto-detect)
            backup_type: Tipo backup
            triggered_by: Trigger source
            credential_id: ID credenziale specifica da usare (opzionale)

        Returns:
            dict con risultato backup
        """
        try:
            # Recupera customer
            customer = self.db.query(Customer).filter_by(id=customer_id).first()
            if not customer:
                return {
                    "success": False,
                    "error": f"Customer {customer_id} not found"
                }

            # Auto-detect tipo device se necessario
            if device_type == "auto":
                device_type = self._auto_detect_device_type(device_ip, customer)

            # Ottieni credenziali: priorità a credential_id se fornito
            if credential_id:
                self.logger.info(f"backup_device_by_ip: Using provided credential_id {credential_id}")
                credentials = self._get_credential_by_id(credential_id, device_type)
            else:
                self.logger.info(f"backup_device_by_ip: Using default credentials for customer {customer.id}")
                credentials = self._get_customer_default_credentials(customer, device_type)
            
            if not credentials:
                error_msg = f"No valid credentials found for device {device_ip} (type: {device_type}, credential_id: {credential_id or 'default'})"
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg
                }
            
            self.logger.info(f"backup_device_by_ip: Found credentials for {device_ip}, username: {credentials.get('username', 'N/A')}")

            # Esegui backup
            backup_result = self._execute_backup(
                device_ip=device_ip,
                device_type=device_type,
                credentials=credentials,
                backup_type=backup_type,
                customer_code=customer.code
            )

            # Salva record (senza assignment)
            if backup_result["success"]:
                backup_record = self._save_backup_record_standalone(
                    device_ip=device_ip,
                    customer=customer,
                    device_type=device_type,
                    backup_result=backup_result,
                    backup_type=backup_type,
                    triggered_by=triggered_by,
                    credentials=credentials
                )

                backup_result["backup_id"] = backup_record.id

            return backup_result

        except Exception as e:
            self.logger.error(f"Backup failed for {device_ip}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

    def backup_customer_devices(self, customer_id: str,
                               backup_type: str = "config",
                               device_type_filter: Optional[List[str]] = None,
                               triggered_by: str = "manual") -> Dict[str, Any]:
        """
        Backup di tutti i device di un cliente

        Args:
            customer_id: ID cliente
            backup_type: Tipo backup
            device_type_filter: Lista tipi device (None = tutti)
            triggered_by: Trigger source

        Returns:
            dict: {
                "success": bool,
                "job_id": str,
                "total_devices": int,
                "results": list
            }
        """
        try:
            # Crea job di backup
            job = BackupJob(
                customer_id=customer_id,
                job_type="customer_backup",
                job_scope="customer",
                status="running",
                started_at=datetime.now(),
                created_by=triggered_by
            )
            self.db.add(job)
            self.db.commit()

            # Recupera tutti i device del cliente
            query = self.db.query(DeviceAssignment).filter_by(
                customer_id=customer_id
            )

            assignments = query.all()
            job.devices_total = len(assignments)
            self.db.commit()

            results = []
            success_count = 0
            failed_count = 0

            for idx, assignment in enumerate(assignments):
                # Aggiorna progress
                job.progress_current = idx + 1
                job.progress_percent = int((idx + 1) / len(assignments) * 100)
                self.db.commit()

                # Esegui backup
                result = self.backup_device_by_assignment(
                    device_assignment_id=assignment.id,
                    backup_type=backup_type,
                    triggered_by=f"job:{job.id}"
                )

                results.append({
                    "device_id": assignment.id,
                    "device_name": assignment.dude_device_name,
                    "success": result["success"],
                    "error": result.get("error")
                })

                if result["success"]:
                    success_count += 1
                else:
                    failed_count += 1

            # Finalizza job
            job.status = "completed"
            job.completed_at = datetime.now()
            job.duration_seconds = int((job.completed_at - job.started_at).total_seconds())
            job.devices_success = success_count
            job.devices_failed = failed_count
            job.result_summary = results
            self.db.commit()

            return {
                "success": True,
                "job_id": job.id,
                "total_devices": len(assignments),
                "success_count": success_count,
                "failed_count": failed_count,
                "results": results
            }

        except Exception as e:
            self.logger.error(f"Customer backup failed: {e}", exc_info=True)
            if job:
                job.status = "failed"
                job.error_message = str(e)
                self.db.commit()

            return {
                "success": False,
                "error": str(e)
            }

    # ========================================================================
    # METODI PUBBLICI - Query Backup History
    # ========================================================================

    def get_device_backup_history(self, device_assignment_id: str,
                                  limit: int = 50) -> List[DeviceBackup]:
        """Recupera storico backup di un device"""
        return self.db.query(DeviceBackup).filter_by(
            device_assignment_id=device_assignment_id
        ).order_by(desc(DeviceBackup.created_at)).limit(limit).all()

    def get_backup_by_id(self, backup_id: str) -> Optional[DeviceBackup]:
        """Recupera backup specifico per ID"""
        return self.db.query(DeviceBackup).filter_by(id=backup_id).first()

    def get_customer_backups(self, customer_id: str, days: int = 30) -> List[DeviceBackup]:
        """Recupera backup di un cliente negli ultimi N giorni"""
        since = datetime.now() - timedelta(days=days)
        return self.db.query(DeviceBackup).filter(
            DeviceBackup.customer_id == customer_id,
            DeviceBackup.created_at >= since
        ).order_by(desc(DeviceBackup.created_at)).all()

    def cleanup_old_backups(self, customer_id: str, retention_days: int = 30) -> Dict[str, Any]:
        """
        Pulizia backup vecchi secondo retention policy

        Returns:
            dict: {
                "deleted_count": int,
                "freed_bytes": int
            }
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)

            # Query backup da eliminare
            old_backups = self.db.query(DeviceBackup).filter(
                DeviceBackup.customer_id == customer_id,
                DeviceBackup.created_at < cutoff_date
            ).all()

            deleted_count = 0
            freed_bytes = 0

            for backup in old_backups:
                # Elimina file fisico
                if backup.file_path and os.path.exists(backup.file_path):
                    file_size = os.path.getsize(backup.file_path)
                    os.remove(backup.file_path)
                    freed_bytes += file_size

                # Elimina record DB
                self.db.delete(backup)
                deleted_count += 1

            self.db.commit()

            self.logger.info(f"Cleaned up {deleted_count} old backups, freed {freed_bytes} bytes")

            return {
                "deleted_count": deleted_count,
                "freed_bytes": freed_bytes
            }

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}", exc_info=True)
            return {
                "deleted_count": 0,
                "freed_bytes": 0,
                "error": str(e)
            }

    # ========================================================================
    # METODI PRIVATI - Core Logic
    # ========================================================================

    def _execute_backup(self, device_ip: str, device_type: str,
                       credentials: Dict[str, Any], backup_type: str,
                       customer_code: str) -> Dict[str, Any]:
        """
        Esegue backup effettivo delegando al collector appropriato

        Returns:
            dict risultato backup dal collector
        """
        # Path backup specifico per cliente
        backup_path = os.path.join(
            self.backup_base_path,
            device_type,
            customer_code
        )

        # Delega al collector appropriato
        if device_type == "hp_aruba":
            return self.hp_collector.backup_configuration(
                host=device_ip,
                username=credentials["username"],
                password=credentials["password"],
                port=credentials.get("port", 22),
                backup_path=backup_path
            )

        elif device_type == "mikrotik":
            # Per MikroTik, usa porta SSH (il collector usa SSH per backup)
            ssh_port = credentials.get("port", 22)
            
            return self.mikrotik_collector.backup_configuration(
                host=device_ip,
                username=credentials["username"],
                password=credentials["password"],
                port=ssh_port,
                backup_path=backup_path,
                backup_type=backup_type
            )

        elif device_type == "proxmox":
            # Per Proxmox, usa porta SSH
            ssh_port = credentials.get("port", 22)
            
            return self.proxmox_collector.backup_configuration(
                host=device_ip,
                username=credentials["username"],
                password=credentials["password"],
                port=ssh_port,
                backup_path=backup_path,
                backup_type=backup_type
            )

        else:
            return {
                "success": False,
                "error": f"Unsupported device type: {device_type}"
            }

    def _save_backup_record(self, assignment: DeviceAssignment, customer: Customer,
                           device_type: str, backup_result: Dict[str, Any],
                           backup_type: str, triggered_by: str,
                           credentials: Dict[str, Any]) -> DeviceBackup:
        """Salva record backup nel database"""
        device_info = backup_result.get("device_info", {})

        # Calcola checksum se file presente
        checksum = None
        file_size = None
        file_path = backup_result.get("file_path") or backup_result.get("export_file_path")

        if file_path and os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()

        backup_record = DeviceBackup(
            device_assignment_id=assignment.id,
            customer_id=customer.id,
            device_ip=assignment.dude_device_name,  # TODO: usa IP effettivo se disponibile
            device_hostname=device_info.get("system_name") or device_info.get("identity"),
            device_type=device_type,
            device_model=device_info.get("model"),
            device_serial=device_info.get("serial"),
            backup_type=backup_type,
            backup_format=self._get_backup_format(device_type, backup_type),
            file_path=file_path,
            file_name=os.path.basename(file_path) if file_path else None,
            file_size=file_size,
            checksum=checksum,
            device_info=device_info,
            credential_id=credentials.get("credential_id"),
            collector_type="ssh",
            success=backup_result["success"],
            error_message=backup_result.get("error"),
            triggered_by=triggered_by,
            created_by=triggered_by
        )

        self.db.add(backup_record)
        self.db.commit()
        self.db.refresh(backup_record)

        return backup_record

    def _save_backup_record_standalone(self, device_ip: str, customer: Customer,
                                      device_type: str, backup_result: Dict[str, Any],
                                      backup_type: str, triggered_by: str,
                                      credentials: Dict[str, Any]) -> DeviceBackup:
        """Salva record backup senza assignment (device standalone)"""
        device_info = backup_result.get("device_info", {})

        checksum = None
        file_size = None
        file_path = backup_result.get("file_path") or backup_result.get("export_file_path")

        if file_path and os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            with open(file_path, 'rb') as f:
                checksum = hashlib.sha256(f.read()).hexdigest()

        backup_record = DeviceBackup(
            device_assignment_id=None,
            customer_id=customer.id,
            device_ip=device_ip,
            device_hostname=device_info.get("system_name") or device_info.get("identity"),
            device_type=device_type,
            device_model=device_info.get("model"),
            device_serial=device_info.get("serial"),
            backup_type=backup_type,
            backup_format=self._get_backup_format(device_type, backup_type),
            file_path=file_path,
            file_name=os.path.basename(file_path) if file_path else None,
            file_size=file_size,
            checksum=checksum,
            device_info=device_info,
            credential_id=credentials.get("credential_id"),
            collector_type="ssh",
            success=backup_result["success"],
            error_message=backup_result.get("error"),
            triggered_by=triggered_by,
            created_by=triggered_by
        )

        self.db.add(backup_record)
        self.db.commit()
        self.db.refresh(backup_record)

        return backup_record

    def _get_device_credentials(self, assignment: DeviceAssignment,
                                customer: Customer, device_type: str) -> Optional[Dict[str, Any]]:
        """
        Recupera credenziali appropriate per il device
        Priorità: device-specific > default customer > global
        """
        # TODO: Implementa logica credenziali specifiche per device
        # Per ora usa default customer
        return self._get_customer_default_credentials(customer, device_type)

    def _get_credential_by_id(self, credential_id: str, device_type: str) -> Optional[Dict[str, Any]]:
        """Recupera credenziale specifica per ID"""
        self.logger.info(f"_get_credential_by_id: Looking for credential {credential_id} for device_type {device_type}")
        cred = self.db.query(Credential).filter(Credential.id == credential_id).first()
        
        if not cred:
            self.logger.warning(f"_get_credential_by_id: Credential {credential_id} not found")
            return None
        
        # Verifica tipo credenziale compatibile
        if device_type == "mikrotik":
            if cred.credential_type not in ["mikrotik", "ssh", "device"]:
                self.logger.warning(f"Credential {credential_id} type {cred.credential_type} not compatible with MikroTik")
                return None
        elif device_type == "hp_aruba":
            if cred.credential_type not in ["ssh", "device"]:
                self.logger.warning(f"Credential {credential_id} type {cred.credential_type} not compatible with HP/Aruba")
                return None
        
        # Decrypt password
        try:
            password = self.encryption.decrypt(cred.password) if cred.password else None
        except:
            self.logger.warning(f"Failed to decrypt password for credential {cred.id}")
            password = None
        
        # Determina porta in base al tipo device
        # Per MikroTik: usa ssh_port se disponibile, altrimenti porta 22
        # NOTA: mikrotik_api_port è per l'API (8728), non per SSH
        if device_type == "mikrotik":
            # Per backup MikroTik serve SSH, non l'API
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22
            self.logger.info(f"_get_credential_by_id: Using SSH port {port} for MikroTik backup")
        elif device_type == "proxmox":
            # Proxmox usa SSH standard
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22
            self.logger.info(f"_get_credential_by_id: Using SSH port {port} for Proxmox backup")
        else:
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22
        
        result = {
            "credential_id": cred.id,
            "username": cred.username,
            "password": password,
            "port": port,
        }
        
        # Aggiungi campi MikroTik se disponibili
        if hasattr(cred, 'mikrotik_api_port'):
            result["mikrotik_api_port"] = cred.mikrotik_api_port
        if hasattr(cred, 'mikrotik_api_ssl'):
            result["mikrotik_api_ssl"] = cred.mikrotik_api_ssl or False
        
        return result

    def _get_customer_default_credentials(self, customer: Customer,
                                         device_type: str) -> Optional[Dict[str, Any]]:
        """Recupera credenziali di default del cliente per tipo device"""
        # Query credenziali appropriate per tipo device
        if device_type == "mikrotik":
            cred_types = ["mikrotik", "ssh", "device"]
        elif device_type == "proxmox":
            cred_types = ["ssh", "device"]  # Proxmox usa SSH standard
        else:
            cred_types = ["ssh", "device"]
        
        # Query credenziali di default per il cliente
        cred = self.db.query(Credential).filter(
            Credential.customer_id == customer.id,
            Credential.is_default == True,
            Credential.credential_type.in_(cred_types)
        ).first()

        if not cred:
            # Prova credenziali globali
            cred = self.db.query(Credential).filter(
                Credential.is_global == True,
                Credential.credential_type.in_(cred_types)
            ).first()

        if not cred:
            return None

        # Decrypt password
        try:
            password = self.encryption.decrypt(cred.password) if cred.password else None
        except:
            self.logger.warning(f"Failed to decrypt password for credential {cred.id}")
            password = None

        # Determina porta in base al tipo device
        # Per MikroTik backup serve SSH, non l'API (mikrotik_api_port è per l'API RouterOS)
        if device_type == "mikrotik":
            # Per backup MikroTik serve SSH, usa ssh_port se disponibile, altrimenti porta 22
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22
            self.logger.info(f"_get_customer_default_credentials: Using SSH port {port} for MikroTik backup")
        elif device_type == "proxmox":
            # Proxmox usa SSH standard
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22
            self.logger.info(f"_get_customer_default_credentials: Using SSH port {port} for Proxmox backup")
        else:
            port = cred.ssh_port if hasattr(cred, 'ssh_port') and cred.ssh_port else 22

        return {
            "credential_id": cred.id,
            "username": cred.username,
            "password": password,
            "port": port,
            "mikrotik_api_port": cred.mikrotik_api_port if hasattr(cred, 'mikrotik_api_port') else None,
            "mikrotik_api_ssl": cred.mikrotik_api_ssl if hasattr(cred, 'mikrotik_api_ssl') else False,
        }

    def _detect_device_type(self, assignment: DeviceAssignment) -> str:
        """Rileva tipo device da assignment metadata"""
        role = getattr(assignment, 'role', '').lower()

        # Euristiche basate su ruolo o nome
        if 'mikrotik' in role or 'router' in role:
            return "mikrotik"
        elif 'switch' in role or 'hp' in role or 'aruba' in role:
            return "hp_aruba"

        return "unknown"

    def _auto_detect_device_type(self, device_ip: str, customer: Customer) -> str:
        """Auto-detect tipo device tentando connessione"""
        # Prova MikroTik
        creds = self._get_customer_default_credentials(customer, "mikrotik")
        if creds:
            result = self.mikrotik_collector.test_connection(
                host=device_ip,
                username=creds["username"],
                password=creds["password"],
                port=creds.get("port", 22)
            )
            if result["success"]:
                return "mikrotik"

        # Prova HP/Aruba
        creds = self._get_customer_default_credentials(customer, "hp_aruba")
        if creds:
            result = self.hp_collector.test_connection(
                host=device_ip,
                username=creds["username"],
                password=creds["password"],
                port=creds.get("port", 22)
            )
            if result["success"]:
                return "hp_aruba"

        # Prova Proxmox
        creds = self._get_customer_default_credentials(customer, "proxmox")
        if creds:
            result = self.proxmox_collector.test_connection(
                host=device_ip,
                username=creds["username"],
                password=creds["password"],
                port=creds.get("port", 22)
            )
            if result["success"]:
                return "proxmox"

        return "unknown"

    def _get_backup_format(self, device_type: str, backup_type: str) -> str:
        """Determina formato file backup"""
        if device_type == "hp_aruba":
            return "cfg"
        elif device_type == "mikrotik":
            if backup_type == "binary":
                return "backup"
            else:
                return "rsc"
        return "txt"
