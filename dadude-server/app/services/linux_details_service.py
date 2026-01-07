"""
Servizio per salvare dati Linux avanzati nel database
"""

from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
from loguru import logger

from ..models.inventory import LinuxDetails, InventoryDevice


def save_advanced_linux_data(
    session: Session,
    device_id: str,
    scan_data: Dict[str, Any],
) -> Optional[LinuxDetails]:
    """
    Salva dati Linux avanzati da scanner SSH avanzato nel database.
    
    Args:
        session: Database session
        device_id: ID del dispositivo
        scan_data: Dati dalla scansione avanzata
        
    Returns:
        LinuxDetails creato/aggiornato o None
    """
    try:
        # Verifica che il device esista
        device = session.query(InventoryDevice).filter(InventoryDevice.id == device_id).first()
        if not device:
            logger.error(f"Device {device_id} not found")
            return None
        
        # Prepara dati per LinuxDetails
        linux_data = {}
        
        # System info
        system_info = scan_data.get("system_info", {})
        if system_info.get("os_name"):
            linux_data["distro_name"] = system_info.get("os_name")
        if system_info.get("os_version"):
            linux_data["distro_version"] = system_info.get("os_version")
        if system_info.get("os_codename"):
            linux_data["distro_codename"] = system_info.get("os_codename")
        if system_info.get("kernel_version"):
            linux_data["kernel_version"] = system_info.get("kernel_version")
        if system_info.get("architecture"):
            linux_data["kernel_arch"] = system_info.get("architecture")
        if system_info.get("timezone"):
            linux_data["timezone"] = system_info.get("timezone")
        if system_info.get("boot_time"):
            try:
                linux_data["boot_time"] = datetime.fromisoformat(system_info["boot_time"].replace('Z', '+00:00'))
            except:
                pass
        if system_info.get("uptime_seconds"):
            linux_data["uptime_seconds"] = system_info.get("uptime_seconds")
        if system_info.get("uptime_days"):
            linux_data["uptime_days"] = system_info.get("uptime_days")
        
        # NAS specific
        if system_info.get("nas_model"):
            linux_data["nas_model"] = system_info.get("nas_model")
        if system_info.get("nas_serial"):
            linux_data["nas_serial"] = system_info.get("nas_serial")
        if system_info.get("firmware_version"):
            linux_data["firmware_version"] = system_info.get("firmware_version")
        if system_info.get("firmware_build"):
            linux_data["firmware_build"] = system_info.get("firmware_build")
        
        # IMPORTANTE: Aggiorna anche i campi base del dispositivo per il modal
        # System info -> campi base device
        if system_info.get("hostname"):
            device.hostname = system_info.get("hostname")
        if system_info.get("os_name"):
            if not device.os_family or device.os_family == "unknown":
                device.os_family = "Linux"
            if not device.os_version:
                device.os_version = system_info.get("os_version")
        if system_info.get("system_type"):
            sys_type = system_info.get("system_type", "").lower()
            if sys_type in ["synology", "qnap"]:
                if not device.device_type or device.device_type == "other":
                    device.device_type = "storage"
                if not device.category:
                    device.category = "storage"
                if not device.manufacturer:
                    device.manufacturer = "Synology" if sys_type == "synology" else "QNAP"
            elif sys_type == "proxmox":
                if not device.device_type or device.device_type == "other":
                    device.device_type = "hypervisor"
                if not device.category:
                    device.category = "hypervisor"
            elif not device.device_type or device.device_type == "other":
                device.device_type = "linux"
        if system_info.get("nas_model"):
            if not device.manufacturer:
                if system_info.get("system_type") == "synology":
                    device.manufacturer = "Synology"
                elif system_info.get("system_type") == "qnap":
                    device.manufacturer = "QNAP"
            if not device.model:
                device.model = system_info.get("nas_model")
        if system_info.get("nas_serial"):
            device.serial_number = system_info.get("nas_serial")
        if system_info.get("firmware_version"):
            device.os_version = system_info.get("firmware_version")
        
        # CPU info
        cpu_info = scan_data.get("cpu", {})
        if cpu_info.get("model"):
            device.cpu_model = cpu_info.get("model")
        if cpu_info.get("cores_physical"):
            device.cpu_cores = cpu_info.get("cores_physical")
        if cpu_info.get("cores_logical"):
            device.cpu_threads = cpu_info.get("cores_logical")
        if cpu_info.get("frequency_mhz"):
            linux_data["cpu_frequency_mhz"] = cpu_info.get("frequency_mhz")
        if cpu_info.get("cache_size"):
            linux_data["cpu_cache_size"] = cpu_info.get("cache_size")
        if cpu_info.get("usage_percent") is not None:
            linux_data["cpu_usage_percent"] = cpu_info.get("usage_percent")
        if cpu_info.get("temperature_celsius") is not None:
            linux_data["cpu_temperature_celsius"] = cpu_info.get("temperature_celsius")
        if cpu_info.get("load_1min") is not None:
            linux_data["cpu_load_1min"] = cpu_info.get("load_1min")
        if cpu_info.get("load_5min") is not None:
            linux_data["cpu_load_5min"] = cpu_info.get("load_5min")
        if cpu_info.get("load_15min") is not None:
            linux_data["cpu_load_15min"] = cpu_info.get("load_15min")
        if cpu_info.get("load_average"):
            linux_data["load_average"] = cpu_info.get("load_average")
        
        # Memory info
        memory_info = scan_data.get("memory", {})
        if memory_info.get("total_gb"):
            device.ram_total_gb = memory_info.get("total_gb")
        if memory_info.get("total_bytes"):
            linux_data["memory_available_bytes"] = memory_info.get("total_bytes")
        if memory_info.get("available_bytes"):
            linux_data["memory_available_bytes"] = memory_info.get("available_bytes")
        if memory_info.get("used_bytes"):
            linux_data["memory_used_bytes"] = memory_info.get("used_bytes")
        if memory_info.get("free_bytes"):
            linux_data["memory_free_bytes"] = memory_info.get("free_bytes")
        if memory_info.get("cached_bytes"):
            linux_data["memory_cached_bytes"] = memory_info.get("cached_bytes")
        if memory_info.get("buffers_bytes"):
            linux_data["memory_buffers_bytes"] = memory_info.get("buffers_bytes")
        if memory_info.get("usage_percent") is not None:
            linux_data["memory_usage_percent"] = memory_info.get("usage_percent")
        if memory_info.get("swap_total_bytes"):
            linux_data["swap_total_bytes"] = memory_info.get("swap_total_bytes")
        if memory_info.get("swap_used_bytes"):
            linux_data["swap_used_bytes"] = memory_info.get("swap_used_bytes")
        if memory_info.get("swap_free_bytes"):
            linux_data["swap_free_bytes"] = memory_info.get("swap_free_bytes")
        if memory_info.get("swap_usage_percent") is not None:
            linux_data["swap_usage_percent"] = memory_info.get("swap_usage_percent")
        
        # Storage data (JSON)
        storage_data = {}
        if scan_data.get("volumes"):
            storage_data["volumes"] = scan_data.get("volumes")
        if scan_data.get("raid_arrays"):
            storage_data["raid_arrays"] = scan_data.get("raid_arrays")
        if storage_data:
            linux_data["storage_data"] = storage_data
        
        # Disks data (JSON)
        if scan_data.get("disks"):
            linux_data["disks_data"] = scan_data.get("disks")
        
        # Network interfaces data (JSON)
        if scan_data.get("network_interfaces"):
            linux_data["network_interfaces_data"] = scan_data.get("network_interfaces")
        
        # Default gateway
        if scan_data.get("default_gateway"):
            linux_data["default_gateway"] = scan_data.get("default_gateway")
        
        # DNS servers
        if scan_data.get("dns_servers"):
            linux_data["dns_servers"] = scan_data.get("dns_servers")
        
        # Services data (JSON)
        if scan_data.get("services"):
            linux_data["services_data"] = scan_data.get("services")
        
        # Docker info
        docker_info = scan_data.get("docker", {})
        if docker_info:
            linux_data["docker_installed"] = True
            if docker_info.get("version"):
                linux_data["docker_version"] = docker_info.get("version")
            if docker_info.get("containers_running") is not None:
                linux_data["containers_running"] = docker_info.get("containers_running")
            if docker_info.get("containers_stopped") is not None:
                linux_data["containers_stopped"] = docker_info.get("containers_stopped")
            if docker_info.get("containers_total") is not None:
                linux_data["containers_total"] = docker_info.get("containers_total")
            if docker_info.get("images_count") is not None:
                linux_data["docker_images_count"] = docker_info.get("images_count")
        
        # VMs data (JSON) - per Proxmox
        if scan_data.get("vms"):
            linux_data["vms_data"] = scan_data.get("vms")
        
        # Crea o aggiorna LinuxDetails
        existing_ld = session.query(LinuxDetails).filter(LinuxDetails.device_id == device_id).first()
        
        if existing_ld:
            # Aggiorna campi esistenti
            for key, value in linux_data.items():
                if hasattr(existing_ld, key) and value is not None:
                    setattr(existing_ld, key, value)
            existing_ld.last_updated = datetime.now()
            logger.info(f"Updated LinuxDetails for device {device_id} with {len(linux_data)} fields")
        else:
            # Crea nuovo LinuxDetails
            if linux_data:
                from ..models.database import generate_uuid
                ld = LinuxDetails(
                    id=generate_uuid(),
                    device_id=device_id,
                    **{k: v for k, v in linux_data.items() if hasattr(LinuxDetails, k)}
                )
                session.add(ld)
                logger.info(f"Created LinuxDetails for device {device_id} with fields: {list(linux_data.keys())}")
        
        # IMPORTANTE: Assicurati che i campi base del dispositivo siano aggiornati
        # Questo è necessario per il modal che legge direttamente dal dispositivo
        session.flush()  # Assicura che le modifiche al device siano salvate
        
        return existing_ld if existing_ld else ld if linux_data else None
        
    except Exception as e:
        logger.error(f"Error saving advanced Linux data for device {device_id}: {e}", exc_info=True)
        return None

