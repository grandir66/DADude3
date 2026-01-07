"""
Device Backup Models - NUOVO MODULO
Modelli SQLAlchemy per gestione backup configurazioni dispositivi
Non modifica i modelli esistenti in database.py
"""
from sqlalchemy import (
    Column, String, Integer, Boolean, Text, DateTime, ForeignKey,
    JSON, Index
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid


def generate_uuid():
    """Genera UUID corto a 8 caratteri (compatibile con sistema esistente)"""
    return str(uuid.uuid4())[:8]


# Importa Base dal modulo esistente per mantenere compatibilità
try:
    from .database import Base
except ImportError:
    from sqlalchemy.orm import declarative_base
    Base = declarative_base()


class DeviceBackup(Base):
    """
    Storico backup configurazioni dispositivi
    Traccia ogni backup eseguito con metadata e path del file
    """
    __tablename__ = "device_backups"

    id = Column(String(8), primary_key=True, default=generate_uuid)

    # Relazioni con entità esistenti
    device_assignment_id = Column(String(8), ForeignKey("device_assignments.id"), nullable=True)
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False, index=True)
    network_id = Column(String(8), ForeignKey("networks.id"), nullable=True)

    # Identificazione device (per device non assegnati o esterni)
    device_ip = Column(String(50), nullable=False)
    device_hostname = Column(String(255), nullable=True)
    device_type = Column(String(50), nullable=False)  # hp_aruba, mikrotik, cisco, other
    device_model = Column(String(100), nullable=True)
    device_serial = Column(String(100), nullable=True)

    # Tipo backup
    backup_type = Column(String(50), default="config")  # config, binary, full, incremental
    backup_format = Column(String(20), nullable=True)   # txt, rsc, cfg, bin

    # File storage
    file_path = Column(String(500), nullable=False)  # Path relativo in backups/
    file_name = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=True)        # Bytes
    checksum = Column(String(64), nullable=True)      # SHA256
    compressed = Column(Boolean, default=False)

    # Metadata device al momento del backup
    device_info = Column(JSON, nullable=True)  # {model, firmware, serial, uptime, etc}

    # Configurazione backup strategy
    credential_id = Column(String(8), ForeignKey("credentials.id"), nullable=True)
    collector_type = Column(String(50), nullable=True)  # ssh, api, snmp, telnet

    # Stato e risultato
    success = Column(Boolean, default=True)
    error_message = Column(Text, nullable=True)
    error_code = Column(String(50), nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Audit
    created_at = Column(DateTime, default=func.now(), index=True)
    created_by = Column(String(100), nullable=True)  # manual, scheduled, api, user:{id}
    triggered_by = Column(String(50), nullable=True)  # web_ui, api, scheduler, agent

    # Metadata aggiuntivi
    notes = Column(Text, nullable=True)
    tags = Column(JSON, nullable=True)  # ["pre-change", "monthly", "critical"]

    # Indici per query veloci
    __table_args__ = (
        Index('idx_backup_customer_date', 'customer_id', 'created_at'),
        Index('idx_backup_device_date', 'device_ip', 'created_at'),
        Index('idx_backup_type', 'device_type', 'backup_type'),
        Index('idx_backup_success', 'success'),
    )

    def __repr__(self):
        return f"<DeviceBackup {self.device_hostname or self.device_ip} @ {self.created_at}>"


class BackupSchedule(Base):
    """
    Configurazione scheduling automatico backup per cliente
    Permette schedule differenziati per tipo device o rete
    """
    __tablename__ = "backup_schedules"

    id = Column(String(8), primary_key=True, default=generate_uuid)

    # Scope dello schedule
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=False, index=True)
    network_id = Column(String(8), ForeignKey("networks.id"), nullable=True)  # NULL = tutti

    # Filtri device
    device_type_filter = Column(JSON, nullable=True)  # ["hp_aruba", "mikrotik"] o NULL = tutti
    device_role_filter = Column(JSON, nullable=True)  # ["router", "switch"] da DeviceAssignment
    device_tag_filter = Column(JSON, nullable=True)   # Tags custom

    # Configurazione schedule
    enabled = Column(Boolean, default=True)
    schedule_type = Column(String(20), default="daily")  # daily, weekly, monthly, custom
    schedule_time = Column(String(5), default="03:00")   # HH:MM formato 24h
    schedule_days = Column(JSON, nullable=True)  # [0,1,2,3,4,5,6] (0=Lunedì) per weekly
    schedule_day_of_month = Column(Integer, nullable=True)  # 1-31 per monthly

    # Cron expression per schedule custom avanzati (opzionale)
    cron_expression = Column(String(100), nullable=True)  # "0 3 * * 0" = Domenica 3:00

    # Tipi backup da eseguire
    backup_types = Column(JSON, default=lambda: ["config"])  # ["config", "binary"]

    # Retention policy
    retention_days = Column(Integer, default=30)
    retention_count = Column(Integer, nullable=True)  # Max N backup da mantenere
    retention_strategy = Column(String(20), default="time")  # time, count, both

    # Compressione
    compress_backups = Column(Boolean, default=False)
    compression_format = Column(String(10), default="gzip")  # gzip, zip, bz2

    # Notifiche
    notify_on_success = Column(Boolean, default=False)
    notify_on_failure = Column(Boolean, default=True)
    notification_emails = Column(JSON, nullable=True)  # ["admin@example.com"]
    notification_webhook = Column(String(500), nullable=True)

    # Stato esecuzione
    last_run_at = Column(DateTime, nullable=True)
    last_run_success = Column(Boolean, nullable=True)
    last_run_devices_count = Column(Integer, nullable=True)
    last_run_errors_count = Column(Integer, nullable=True)
    next_run_at = Column(DateTime, nullable=True)

    # Statistiche
    total_runs = Column(Integer, default=0)
    total_successes = Column(Integer, default=0)
    total_failures = Column(Integer, default=0)

    # Audit
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(String(100), nullable=True)

    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    # Indici
    __table_args__ = (
        Index('idx_schedule_customer', 'customer_id', 'enabled'),
        Index('idx_schedule_next_run', 'next_run_at', 'enabled'),
    )

    def __repr__(self):
        return f"<BackupSchedule {self.schedule_type} @ {self.schedule_time} for customer {self.customer_id}>"


class BackupJob(Base):
    """
    Job di backup in esecuzione
    Traccia lo stato di backup batch (es: backup di tutti i device di un cliente)
    """
    __tablename__ = "backup_jobs"

    id = Column(String(8), primary_key=True, default=generate_uuid)

    # Scope del job
    customer_id = Column(String(8), ForeignKey("customers.id"), nullable=True, index=True)
    schedule_id = Column(String(8), ForeignKey("backup_schedules.id"), nullable=True)

    # Tipo job
    job_type = Column(String(50), default="manual")  # manual, scheduled, api
    job_scope = Column(String(50), nullable=True)    # single_device, customer, network, all

    # Stato
    status = Column(String(20), default="pending")  # pending, running, completed, failed, cancelled
    progress_current = Column(Integer, default=0)
    progress_total = Column(Integer, default=0)
    progress_percent = Column(Integer, default=0)

    # Risultati
    devices_total = Column(Integer, default=0)
    devices_success = Column(Integer, default=0)
    devices_failed = Column(Integer, default=0)
    devices_skipped = Column(Integer, default=0)

    # Tempi
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)

    # Dettagli
    error_message = Column(Text, nullable=True)
    result_summary = Column(JSON, nullable=True)  # Lista device con esiti

    # Audit
    created_at = Column(DateTime, default=func.now(), index=True)
    created_by = Column(String(100), nullable=True)

    # Indici
    __table_args__ = (
        Index('idx_job_status', 'status', 'created_at'),
        Index('idx_job_customer', 'customer_id', 'status'),
    )

    def __repr__(self):
        return f"<BackupJob {self.id} ({self.status}): {self.devices_success}/{self.devices_total}>"


class BackupTemplate(Base):
    """
    Template di configurazione backup per tipo device
    Permette di configurare comandi custom e parsing per vendor specifici
    """
    __tablename__ = "backup_templates"

    id = Column(String(8), primary_key=True, default=generate_uuid)

    # Identificazione template
    name = Column(String(100), nullable=False, unique=True)
    device_type = Column(String(50), nullable=False)  # hp_aruba, mikrotik, cisco, etc
    vendor = Column(String(100), nullable=True)
    model_pattern = Column(String(200), nullable=True)  # Regex per matching modello

    # Comandi backup
    commands_config = Column(JSON, nullable=True)  # Lista comandi per config backup
    commands_binary = Column(JSON, nullable=True)  # Comandi per binary backup
    commands_pre = Column(JSON, nullable=True)     # Pre-backup (es: no page)
    commands_post = Column(JSON, nullable=True)    # Post-backup (es: cleanup)

    # Configurazione collector
    collector_type = Column(String(50), default="ssh")  # ssh, telnet, api, snmp
    connection_timeout = Column(Integer, default=30)
    command_delay = Column(Integer, default=2)  # Secondi tra comandi

    # Parsing e cleanup
    cleanup_patterns = Column(JSON, nullable=True)  # Regex da rimuovere (ANSI, prompt, etc)
    extract_info_commands = Column(JSON, nullable=True)  # Comandi per metadata

    # Metadata
    active = Column(Boolean, default=True)
    is_builtin = Column(Boolean, default=False)  # Template predefinito non modificabile
    priority = Column(Integer, default=100)  # Priorità matching (più basso = priorità maggiore)

    description = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index('idx_template_type', 'device_type', 'active'),
    )

    def __repr__(self):
        return f"<BackupTemplate {self.name} ({self.device_type})>"
