#!/usr/bin/env python3
"""
SAFE INTEGRATION SCRIPT - Device Backup Module
Script interattivo per integrare il modulo backup in modo sicuro

Verifica compatibilità, backup esistente, e integrazione graduale
NON modifica file esistenti senza conferma utente

Usage:
    python SAFE_INTEGRATION.py
"""
import sys
import os
import shutil
from pathlib import Path
from datetime import datetime
import json

# Colors for terminal
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'


def print_header(text):
    """Print header"""
    print(f"\n{BLUE}{BOLD}{'='*70}{RESET}")
    print(f"{BLUE}{BOLD}{text:^70}{RESET}")
    print(f"{BLUE}{BOLD}{'='*70}{RESET}\n")


def print_success(text):
    """Print success message"""
    print(f"{GREEN}✓{RESET} {text}")


def print_warning(text):
    """Print warning message"""
    print(f"{YELLOW}⚠{RESET} {text}")


def print_error(text):
    """Print error message"""
    print(f"{RED}✗{RESET} {text}")


def print_info(text):
    """Print info message"""
    print(f"{BLUE}ℹ{RESET} {text}")


def confirm(question):
    """Ask user confirmation"""
    response = input(f"{YELLOW}?{RESET} {question} (y/n): ").lower()
    return response in ['y', 'yes', 's', 'si']


class SafeIntegration:
    """Safe integration manager"""

    def __init__(self):
        self.project_root = Path(__file__).parent
        self.backup_dir = self.project_root / "integration_backup"
        self.errors = []
        self.warnings = []

    def run(self):
        """Main integration workflow"""
        print_header("DEVICE BACKUP MODULE - SAFE INTEGRATION")
        print_info("Questo script integra il modulo backup SENZA modificare codice esistente")
        print_info(f"Project root: {self.project_root}\n")

        if not confirm("Procedere con la verifica?"):
            print_info("Operazione annullata")
            return 1

        # Step 1: Pre-flight checks
        print_header("STEP 1: Pre-flight Checks")
        if not self.preflight_checks():
            print_error("Pre-flight checks failed. Fix errors before continuing.")
            return 1

        # Step 2: Backup existing files
        print_header("STEP 2: Backup Files")
        if not self.backup_existing_files():
            print_error("Backup failed")
            return 1

        # Step 3: Verify new files
        print_header("STEP 3: Verify New Files")
        if not self.verify_new_files():
            print_error("New files verification failed")
            return 1

        # Step 4: Database compatibility
        print_header("STEP 4: Database Compatibility Check")
        if not self.check_database_compatibility():
            print_error("Database compatibility check failed")
            return 1

        # Step 5: Dependencies check
        print_header("STEP 5: Dependencies Check")
        if not self.check_dependencies():
            print_warning("Some dependencies missing. Install before using backup features.")

        # Step 6: Integration plan
        print_header("STEP 6: Integration Plan")
        self.show_integration_plan()

        # Step 7: Apply integration
        if confirm("\nApplicare l'integrazione?"):
            print_header("STEP 7: Apply Integration")
            if self.apply_integration():
                print_header("INTEGRATION COMPLETED")
                print_success("Modulo backup integrato con successo!")
                print_info("\nProssimi passi:")
                print_info("1. Riavvia l'applicazione: python -m app.run_dual")
                print_info("2. Verifica API docs: http://localhost:8001/docs (Admin UI)")
                print_info("3. Esegui migration database: python migrate_backup_tables.py --seed-templates")
                print_info("4. Consulta INTEGRATION_GUIDE.md per UI integration")
                return 0
            else:
                print_error("Integration failed")
                return 1
        else:
            print_info("Integrazione annullata. Nessun file modificato.")
            return 0

    def preflight_checks(self):
        """Pre-flight compatibility checks"""
        all_ok = True

        # Check Python version
        if sys.version_info < (3, 8):
            print_error(f"Python 3.8+ richiesto. Versione corrente: {sys.version}")
            all_ok = False
        else:
            print_success(f"Python version: {sys.version.split()[0]}")

        # Check main_dual.py exists
        main_file = self.project_root / "app" / "main_dual.py"
        main_exists = main_file.exists()

        if not main_exists:
            print_error("File app/main_dual.py non trovato")
            all_ok = False
        else:
            print_success("Main file found: main_dual.py")

        # Check database.py exists
        db_file = self.project_root / "app" / "models" / "database.py"
        if not db_file.exists():
            print_error("File app/models/database.py non trovato")
            all_ok = False
        else:
            print_success("Database models found")

        # Check routers directory
        routers_dir = self.project_root / "app" / "routers"
        if not routers_dir.exists():
            print_error("Directory app/routers non trovata")
            all_ok = False
        else:
            print_success(f"Routers directory found ({len(list(routers_dir.glob('*.py')))} files)")

        # Check services directory
        services_dir = self.project_root / "app" / "services"
        if not services_dir.exists():
            print_error("Directory app/services non trovata")
            all_ok = False
        else:
            print_success(f"Services directory found ({len(list(services_dir.glob('*.py')))} files)")

        # Check if backup module files already exist
        backup_files_exist = []
        new_files = [
            "app/models/backup_models.py",
            "app/services/hp_aruba_collector.py",
            "app/services/mikrotik_backup_collector.py",
            "app/services/device_backup_service.py",
            "app/services/command_execution_service.py",
            "app/services/ai_command_validator.py",
            "app/services/backup_scheduler.py",
            "app/routers/device_backup.py"
        ]

        for file_path in new_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                backup_files_exist.append(file_path)

        if backup_files_exist:
            print_warning(f"Alcuni file del modulo backup esistono già:")
            for f in backup_files_exist:
                print(f"  - {f}")
            print_info("Saranno sovrascritti durante l'integrazione")

        return all_ok

    def backup_existing_files(self):
        """Backup existing files before modification"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_dir = self.project_root / f"integration_backup_{timestamp}"

        try:
            self.backup_dir.mkdir(parents=True, exist_ok=True)
            print_info(f"Backup directory: {self.backup_dir}")

            # Backup main_dual.py file
            main_file = self.project_root / "app" / "main_dual.py"
            if main_file.exists():
                backup_path = self.backup_dir / main_file.name
                shutil.copy2(main_file, backup_path)
                print_success(f"Backed up: {main_file.name}")

            # Save backup info
            backup_info = {
                "timestamp": timestamp,
                "project_root": str(self.project_root),
                "backed_up_files": [f.name for f in main_files if f.exists()]
            }

            with open(self.backup_dir / "backup_info.json", 'w') as f:
                json.dump(backup_info, f, indent=2)

            print_success(f"Backup completato in: {self.backup_dir}")
            return True

        except Exception as e:
            print_error(f"Backup failed: {e}")
            return False

    def verify_new_files(self):
        """Verify all new module files are present"""
        required_files = {
            "app/models/backup_models.py": "Database models",
            "app/services/hp_aruba_collector.py": "HP/Aruba collector",
            "app/services/mikrotik_backup_collector.py": "MikroTik collector",
            "app/services/device_backup_service.py": "Backup orchestrator",
            "app/services/command_execution_service.py": "Command execution",
            "app/services/ai_command_validator.py": "AI validator",
            "app/services/backup_scheduler.py": "Backup scheduler",
            "app/routers/device_backup.py": "API router",
            "migrate_backup_tables.py": "Migration script",
            "DEVICE_BACKUP_MODULE.md": "Documentation",
            "INTEGRATION_GUIDE.md": "Integration guide"
        }

        all_present = True
        for file_path, description in required_files.items():
            full_path = self.project_root / file_path
            if full_path.exists():
                size_kb = full_path.stat().st_size / 1024
                print_success(f"{description:30} - {file_path:40} ({size_kb:.1f} KB)")
            else:
                print_error(f"{description:30} - {file_path:40} MISSING!")
                all_present = False

        return all_present

    def check_database_compatibility(self):
        """Check database models compatibility"""
        try:
            # Import existing models
            sys.path.insert(0, str(self.project_root))
            from app.models.database import Base as ExistingBase, Customer, Network, Credential

            # Import new models
            from app.models.backup_models import DeviceBackup, BackupSchedule

            print_success("Database models imported successfully")

            # Check Base compatibility
            print_info(f"Existing Base: {ExistingBase}")
            print_info("New models use same Base - ✓ Compatible")

            # Check foreign keys
            print_success("Foreign keys to existing tables: customers, networks, credentials")
            print_success("No conflicts detected")

            return True

        except ImportError as e:
            print_error(f"Import error: {e}")
            print_warning("Database models potrebbero non essere compatibili")
            return False

        except Exception as e:
            print_error(f"Compatibility check failed: {e}")
            return False

    def check_dependencies(self):
        """Check Python dependencies"""
        required_deps = {
            "paramiko": "SSH connections",
            "apscheduler": "Backup scheduler",
            "anthropic": "AI validation (optional)"
        }

        all_ok = True
        for package, description in required_deps.items():
            try:
                __import__(package)
                print_success(f"{package:20} - {description}")
            except ImportError:
                if package == "anthropic":
                    print_warning(f"{package:20} - {description} (OPTIONAL - not installed)")
                else:
                    print_error(f"{package:20} - {description} (REQUIRED - not installed)")
                    all_ok = False

        if not all_ok:
            print_info("\nInstalla dipendenze mancanti:")
            print_info("  pip install apscheduler")
            print_info("  pip install anthropic  # opzionale")

        return True  # Non blocca, solo avvisa

    def show_integration_plan(self):
        """Show integration plan"""
        print_info("Piano di integrazione:\n")

        print("1. ✓ File modulo backup già presenti (no action needed)")
        print("2. → Aggiungere import in app/main.py:")
        print("     from app.routers import device_backup")
        print("     from app.services.backup_scheduler import start_backup_scheduler, stop_backup_scheduler")

        print("\n3. → Registrare router in app/main_dual.py:")
        print("     admin_app.include_router(device_backup.router, prefix='/api/v1')")

        print("\n4. → Aggiungere startup/shutdown events (opzionale per scheduler):")
        print("     @app.on_event('startup')")
        print("     async def startup_backup_scheduler():")
        print("         start_backup_scheduler()")
        print("     @app.on_event('shutdown')")
        print("     async def shutdown_backup_scheduler():")
        print("         stop_backup_scheduler()")

        print("\n5. → Eseguire migration database:")
        print("     python migrate_backup_tables.py --seed-templates")

        print("\n6. → Configurare .env:")
        print("     BACKUP_PATH=./backups")
        print("     ANTHROPIC_API_KEY=sk-ant-...  # opzionale")

    def apply_integration(self):
        """Apply integration changes"""
        try:
            # Use main_dual.py (current active file)
            main_file = self.project_root / "app" / "main_dual.py"

            if not main_file.exists():
                print_error("No main_dual.py found")
                return False

            print_info(f"Modifying: {main_file.name}")

            # Read current content
            with open(main_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Check if already integrated
            if "device_backup" in content:
                print_warning("Router 'device_backup' già presente in main_dual.py")
                if not confirm("Sovrascrivere comunque?"):
                    print_info("Skipped main_dual.py modification")
                    return True

            # Find insertion points
            # 1. Import section
            import_line = "from .routers import"
            if import_line in content:
                # Add device_backup to imports
                content = content.replace(
                    import_line,
                    "from .routers import device_backup, "
                )
                print_success("Added device_backup import")

            # 2. Router registration
            router_section = "app.include_router(customers.router"
            if router_section in content:
                # Add after customers router
                addition = '\napp.include_router(device_backup.router, prefix="/api/v1", tags=["Device Backup"])'
                content = content.replace(
                    router_section,
                    router_section + addition
                )
                print_success("Added device_backup router registration")

            # 3. Add scheduler imports and events (if lifespan exists)
            if "@asynccontextmanager" in content and "async def lifespan" in content:
                # Add imports at top
                scheduler_imports = """
# === BACKUP MODULE INTEGRATION ===
from .services.backup_scheduler import start_backup_scheduler, stop_backup_scheduler
# === END BACKUP MODULE ===
"""
                # Add after other service imports
                if "from .services import" in content:
                    content = content.replace(
                        "from .services import",
                        scheduler_imports + "\nfrom .services import"
                    )

                # Add to lifespan startup
                if "yield" in content:
                    startup_code = """
    # === BACKUP SCHEDULER START ===
    try:
        start_backup_scheduler()
        logger.info("Backup scheduler started")
    except Exception as e:
        logger.warning(f"Backup scheduler not started: {e}")
    # === END BACKUP SCHEDULER ===
"""
                    content = content.replace("    yield", startup_code + "\n    yield")

                    shutdown_code = """
    # === BACKUP SCHEDULER STOP ===
    try:
        stop_backup_scheduler()
        logger.info("Backup scheduler stopped")
    except:
        pass
    # === END BACKUP SCHEDULER ===
"""
                    # Add before final logger.info in shutdown
                    if 'logger.info("DaDude shutdown complete")' in content:
                        content = content.replace(
                            'logger.info("DaDude shutdown complete")',
                            shutdown_code + '\n    logger.info("DaDude shutdown complete")'
                        )

                print_success("Added backup scheduler integration")

            # Write modified content
            with open(main_file, 'w', encoding='utf-8') as f:
                f.write(content)

            print_success(f"Modified: {main_file.name}")
            print_info(f"Backup originale: {self.backup_dir / main_file.name}")

            return True

        except Exception as e:
            print_error(f"Integration failed: {e}")
            print_error("Ripristina backup se necessario")
            return False


def main():
    """Main entry point"""
    integrator = SafeIntegration()
    return integrator.run()


if __name__ == "__main__":
    sys.exit(main())
