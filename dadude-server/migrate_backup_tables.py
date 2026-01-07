#!/usr/bin/env python3
"""
Database Migration Script - Device Backup Module
Crea tabelle per il modulo backup senza modificare tabelle esistenti

Usage:
    python migrate_backup_tables.py

IMPORTANTE: Eseguire SOLO dopo aver verificato che l'applicazione esistente funziona
"""
import sys
import os
from pathlib import Path

# Aggiungi app al path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from loguru import logger

# Import modelli
from app.models.database import Base as ExistingBase, init_db
from app.models.backup_models import (
    DeviceBackup,
    BackupSchedule,
    BackupJob,
    BackupTemplate
)


def check_existing_tables(engine):
    """Verifica quali tabelle esistono già"""
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    logger.info(f"Existing tables in database: {len(existing_tables)}")
    for table in existing_tables:
        logger.info(f"  - {table}")

    return existing_tables


def create_backup_tables(engine, force=False):
    """
    Crea tabelle modulo backup

    Args:
        engine: SQLAlchemy engine
        force: Se True, drop e ricrea tabelle backup (ATTENZIONE: cancella dati!)
    """
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    backup_tables = [
        "device_backups",
        "backup_schedules",
        "backup_jobs",
        "backup_templates"
    ]

    # Check quali tabelle backup esistono già
    existing_backup_tables = [t for t in backup_tables if t in existing_tables]

    if existing_backup_tables and not force:
        logger.warning(f"Some backup tables already exist: {existing_backup_tables}")
        logger.warning("Use --force to drop and recreate them (DATA WILL BE LOST!)")
        return False

    if force and existing_backup_tables:
        logger.warning(f"Dropping existing backup tables: {existing_backup_tables}")
        # Drop tabelle
        from app.models.backup_models import Base as BackupBase
        for table_name in existing_backup_tables:
            table = BackupBase.metadata.tables.get(table_name)
            if table is not None:
                table.drop(engine)
                logger.info(f"Dropped table: {table_name}")

    # Crea nuove tabelle backup
    logger.info("Creating backup module tables...")

    from app.models.backup_models import Base as BackupBase

    # Crea SOLO tabelle modulo backup (non quelle esistenti)
    tables_to_create = [
        BackupBase.metadata.tables["device_backups"],
        BackupBase.metadata.tables["backup_schedules"],
        BackupBase.metadata.tables["backup_jobs"],
        BackupBase.metadata.tables["backup_templates"]
    ]

    for table in tables_to_create:
        if table.name not in existing_tables or force:
            table.create(engine)
            logger.success(f"Created table: {table.name}")
        else:
            logger.info(f"Table {table.name} already exists, skipping")

    return True


def verify_tables(engine):
    """Verifica che tutte le tabelle backup siano state create"""
    inspector = inspect(engine)
    existing_tables = inspector.get_table_names()

    required_tables = [
        "device_backups",
        "backup_schedules",
        "backup_jobs",
        "backup_templates"
    ]

    missing_tables = [t for t in required_tables if t not in existing_tables]

    if missing_tables:
        logger.error(f"Missing tables: {missing_tables}")
        return False

    logger.success("All backup tables verified successfully!")

    # Mostra colonne per ogni tabella
    for table_name in required_tables:
        columns = inspector.get_columns(table_name)
        logger.info(f"\nTable '{table_name}' columns:")
        for col in columns:
            logger.info(f"  - {col['name']} ({col['type']})")

    return True


def seed_default_templates(engine):
    """Crea template predefiniti per HP/Aruba e MikroTik"""
    from sqlalchemy.orm import Session

    session = Session(engine)

    try:
        # Template HP/Aruba
        hp_template = BackupTemplate(
            name="HP ProCurve / Aruba Default",
            device_type="hp_aruba",
            vendor="HP/Aruba",
            commands_config=["show running-config"],
            commands_pre=["no page"],
            commands_post=["page"],
            collector_type="ssh",
            connection_timeout=30,
            command_delay=2,
            cleanup_patterns=[
                r'\x1b\[[0-9;]*[a-zA-Z]',
                r'--More--',
                r'\[42D\s+\[42D'
            ],
            extract_info_commands=[
                "show system",
                "show modules",
                "show version"
            ],
            active=True,
            is_builtin=True,
            priority=10,
            description="Template predefinito per switch HP ProCurve e Aruba"
        )

        # Template MikroTik
        mikrotik_template = BackupTemplate(
            name="MikroTik RouterOS Default",
            device_type="mikrotik",
            vendor="MikroTik",
            commands_config=["/export verbose"],
            commands_binary=["/system backup save"],
            commands_pre=[],
            commands_post=[],
            collector_type="ssh",
            connection_timeout=30,
            command_delay=2,
            extract_info_commands=[
                "/system identity print",
                "/system resource print",
                "/system routerboard print"
            ],
            active=True,
            is_builtin=True,
            priority=10,
            description="Template predefinito per router MikroTik RouterOS"
        )

        # Check se esistono già
        existing_hp = session.query(BackupTemplate).filter_by(
            name="HP ProCurve / Aruba Default"
        ).first()

        existing_mikrotik = session.query(BackupTemplate).filter_by(
            name="MikroTik RouterOS Default"
        ).first()

        if not existing_hp:
            session.add(hp_template)
            logger.info("Created HP/Aruba default template")

        if not existing_mikrotik:
            session.add(mikrotik_template)
            logger.info("Created MikroTik default template")

        session.commit()
        logger.success("Default templates seeded successfully")

    except Exception as e:
        logger.error(f"Error seeding templates: {e}")
        session.rollback()
    finally:
        session.close()


def main():
    """Main migration function"""
    import argparse

    parser = argparse.ArgumentParser(description="Migrate backup module database tables")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force drop and recreate tables (WARNING: deletes data!)"
    )
    parser.add_argument(
        "--seed-templates",
        action="store_true",
        help="Seed default backup templates"
    )
    parser.add_argument(
        "--db-url",
        type=str,
        default="sqlite:///./data/dadude.db",
        help="Database URL (default: sqlite:///./data/dadude.db)"
    )

    args = parser.parse_args()

    logger.info("="*60)
    logger.info("Device Backup Module - Database Migration")
    logger.info("="*60)

    try:
        # Get database URL
        db_url = args.db_url
        logger.info(f"Database URL: {db_url}")

        # Create engine
        engine = create_engine(db_url)

        # Check existing tables
        logger.info("\n--- Checking existing tables ---")
        existing = check_existing_tables(engine)

        # Verifica che tabelle core esistano
        required_core_tables = ["customers", "networks", "credentials", "device_assignments"]
        missing_core = [t for t in required_core_tables if t not in existing]

        if missing_core:
            logger.error(f"Missing core tables: {missing_core}")
            logger.error("Please run main application migrations first!")
            return 1

        # Create backup tables
        logger.info("\n--- Creating backup tables ---")
        success = create_backup_tables(engine, force=args.force)

        if not success and not args.force:
            logger.warning("Migration cancelled. Use --force to proceed.")
            return 1

        # Verify tables
        logger.info("\n--- Verifying tables ---")
        if not verify_tables(engine):
            logger.error("Table verification failed!")
            return 1

        # Seed templates
        if args.seed_templates:
            logger.info("\n--- Seeding default templates ---")
            seed_default_templates(engine)

        logger.info("\n" + "="*60)
        logger.success("Migration completed successfully!")
        logger.info("="*60)

        logger.info("\nNext steps:")
        logger.info("1. Restart the application")
        logger.info("2. Verify backup API endpoints: /api/v1/device-backup/...")
        logger.info("3. Test backup functionality")

        return 0

    except Exception as e:
        logger.error(f"Migration failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
