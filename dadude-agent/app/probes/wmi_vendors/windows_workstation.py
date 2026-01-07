"""
DaDude Agent - Windows Workstation WMI Probe
Scansione Windows Client (10, 11) via WMI/WinRM.
"""
from typing import Dict, Any, List
from .base import WMIVendorProbe


class WindowsWorkstationProbe(WMIVendorProbe):
    """Probe per Windows Workstation (10, 11)"""
    
    DEVICE_TYPE = "windows_workstation"
    DETECTION_PRIORITY = 20
    
    def detect(self) -> bool:
        """Rileva se è Windows Workstation"""
        try:
            results = self.wmi_query("SELECT Caption, ProductType FROM Win32_OperatingSystem")
            if results:
                caption = results[0].get("Caption", "").lower()
                product_type = self._safe_int(results[0].get("ProductType"))
                # ProductType: 1=Workstation
                return product_type == 1 or ("windows 10" in caption or "windows 11" in caption)
            return False
        except Exception as e:
            self._log_debug(f"Detection failed: {e}")
            return False
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Windows Workstation"""
        self._log_info(f"Starting probe for {target}")
        
        info = {
            "device_type": "windows_workstation",
            "category": "workstation",
            "os_family": "Windows",
        }
        
        # OS Info
        os_info = self._get_os_info()
        if os_info:
            info.update(os_info)
        
        # Computer System
        sys_info = self._get_system_info()
        if sys_info:
            info.update(sys_info)
        
        # CPU
        cpu_info = self._get_cpu_info()
        if cpu_info:
            info.update(cpu_info)
        
        # Memory
        mem_info = self._get_memory_info()
        if mem_info:
            info.update(mem_info)
        
        # Disks
        disk_info = self._get_disk_info()
        if disk_info:
            info.update(disk_info)
        
        # Network
        net_info = self._get_network_info()
        if net_info:
            info.update(net_info)
        
        # Battery (laptop)
        battery = self._get_battery_info()
        if battery:
            info.update(battery)
        
        # Software
        software = self._get_installed_software()
        if software:
            info["software"] = software
            info["software_count"] = len(software)
        
        # Users logged in
        logged_users = self._get_logged_users()
        if logged_users:
            info["logged_in_users"] = logged_users
        
        # Security
        security = self._get_security_info()
        if security:
            info.update(security)
        
        self._log_info(f"Probe complete for {target}: hostname={info.get('hostname')}")
        return info
    
    def _get_os_info(self) -> Dict[str, Any]:
        """Ottiene info sistema operativo"""
        info = {}
        try:
            results = self.wmi_query("""
                SELECT Caption, Version, BuildNumber, OSArchitecture, 
                       InstallDate, LastBootUpTime, SerialNumber,
                       TotalVisibleMemorySize, FreePhysicalMemory
                FROM Win32_OperatingSystem
            """)
            if results:
                r = results[0]
                info["os_name"] = r.get("Caption", "Windows")
                info["os_version"] = r.get("Version", "")
                info["os_build"] = r.get("BuildNumber", "")
                info["architecture"] = r.get("OSArchitecture", "")
                info["serial_number"] = r.get("SerialNumber", "")
                info["install_date"] = self._wmi_datetime_to_str(r.get("InstallDate", ""))
                info["last_boot"] = self._wmi_datetime_to_str(r.get("LastBootUpTime", ""))
                
                total_kb = self._safe_int(r.get("TotalVisibleMemorySize"))
                free_kb = self._safe_int(r.get("FreePhysicalMemory"))
                if total_kb:
                    info["ram_total_mb"] = total_kb // 1024
                    info["ram_free_mb"] = free_kb // 1024
        except Exception as e:
            self._log_debug(f"OS info failed: {e}")
        return info
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Ottiene info sistema"""
        info = {}
        try:
            results = self.wmi_query("""
                SELECT Name, Domain, Manufacturer, Model, 
                       TotalPhysicalMemory, NumberOfProcessors
                FROM Win32_ComputerSystem
            """)
            if results:
                r = results[0]
                info["hostname"] = r.get("Name", "")
                info["domain"] = r.get("Domain", "")
                info["manufacturer"] = r.get("Manufacturer", "")
                info["model"] = r.get("Model", "")
                
                total_bytes = self._safe_int(r.get("TotalPhysicalMemory"))
                if total_bytes:
                    info["ram_total_gb"] = self._bytes_to_gb(total_bytes)
        except Exception as e:
            self._log_debug(f"System info failed: {e}")
        return info
    
    def _get_cpu_info(self) -> Dict[str, Any]:
        """Ottiene info CPU"""
        info = {}
        try:
            results = self.wmi_query("""
                SELECT Name, NumberOfCores, NumberOfLogicalProcessors,
                       MaxClockSpeed, LoadPercentage
                FROM Win32_Processor
            """)
            if results:
                r = results[0]
                info["cpu_model"] = r.get("Name", "")
                info["cpu_cores"] = self._safe_int(r.get("NumberOfCores"))
                info["cpu_threads"] = self._safe_int(r.get("NumberOfLogicalProcessors"))
                info["cpu_speed_mhz"] = self._safe_int(r.get("MaxClockSpeed"))
        except Exception as e:
            self._log_debug(f"CPU info failed: {e}")
        return info
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Ottiene info memoria"""
        info = {}
        try:
            results = self.wmi_query("SELECT Capacity FROM Win32_PhysicalMemory")
            if results:
                total_bytes = sum(self._safe_int(r.get("Capacity")) for r in results)
                info["ram_total_gb"] = self._bytes_to_gb(total_bytes)
                info["ram_modules_count"] = len(results)
        except Exception as e:
            self._log_debug(f"Memory info failed: {e}")
        return info
    
    def _get_disk_info(self) -> Dict[str, Any]:
        """Ottiene info dischi"""
        info = {}
        volumes = []
        
        try:
            vol_results = self.wmi_query("""
                SELECT DeviceID, VolumeName, Size, FreeSpace, FileSystem
                FROM Win32_LogicalDisk WHERE DriveType = 3
            """)
            total_disk = 0
            free_disk = 0
            for r in vol_results:
                size = self._safe_int(r.get("Size"))
                free = self._safe_int(r.get("FreeSpace"))
                total_disk += size
                free_disk += free
                
                volumes.append({
                    "drive_letter": r.get("DeviceID", ""),
                    "label": r.get("VolumeName", ""),
                    "size_gb": self._bytes_to_gb(size),
                    "free_gb": self._bytes_to_gb(free),
                    "filesystem": r.get("FileSystem", ""),
                })
            
            info["volumes"] = volumes
            info["disk_total_gb"] = self._bytes_to_gb(total_disk)
            info["disk_free_gb"] = self._bytes_to_gb(free_disk)
            
        except Exception as e:
            self._log_debug(f"Disk info failed: {e}")
        return info
    
    def _get_network_info(self) -> Dict[str, Any]:
        """Ottiene info rete"""
        info = {}
        interfaces = []
        
        try:
            results = self.wmi_query("""
                SELECT Description, MACAddress, IPAddress, DefaultIPGateway
                FROM Win32_NetworkAdapterConfiguration
                WHERE IPEnabled = TRUE
            """)
            for r in results:
                ip_list = r.get("IPAddress", [])
                gateway_list = r.get("DefaultIPGateway", [])
                
                iface = {
                    "name": r.get("Description", ""),
                    "mac_address": r.get("MACAddress", ""),
                    "ipv4": ip_list[0] if ip_list else "",
                    "gateway": gateway_list[0] if gateway_list else "",
                }
                interfaces.append(iface)
                
                if not info.get("primary_ip") and iface["ipv4"]:
                    info["primary_ip"] = iface["ipv4"]
                    info["primary_mac"] = iface["mac_address"]
            
            info["interfaces"] = interfaces
            
        except Exception as e:
            self._log_debug(f"Network info failed: {e}")
        return info
    
    def _get_battery_info(self) -> Dict[str, Any]:
        """Ottiene info batteria (laptop)"""
        info = {}
        try:
            results = self.wmi_query("""
                SELECT EstimatedChargeRemaining, BatteryStatus
                FROM Win32_Battery
            """)
            if results:
                r = results[0]
                info["is_laptop"] = True
                info["battery_percent"] = self._safe_int(r.get("EstimatedChargeRemaining"))
                status = self._safe_int(r.get("BatteryStatus"))
                info["battery_charging"] = status == 2
        except:
            pass  # Non è un laptop
        return info
    
    def _get_installed_software(self) -> List[Dict[str, str]]:
        """Ottiene software installato"""
        software = []
        try:
            results = self.wmi_query("""
                SELECT Name, Version, Vendor
                FROM Win32_Product
            """)
            for r in results:
                if r.get("Name"):
                    software.append({
                        "name": r.get("Name", ""),
                        "version": r.get("Version", ""),
                        "vendor": r.get("Vendor", ""),
                    })
        except Exception as e:
            self._log_debug(f"Software query failed: {e}")
        return software[:100]
    
    def _get_logged_users(self) -> List[str]:
        """Ottiene utenti loggati"""
        users = []
        try:
            results = self.wmi_query("""
                SELECT UserName FROM Win32_ComputerSystem
            """)
            if results and results[0].get("UserName"):
                users.append(results[0].get("UserName"))
        except Exception as e:
            self._log_debug(f"Logged users failed: {e}")
        return users
    
    def _get_security_info(self) -> Dict[str, Any]:
        """Ottiene info sicurezza"""
        info = {}
        try:
            # Windows Security Center
            av_results = self.wmi_query("""
                SELECT displayName, productState
                FROM AntiVirusProduct
            """, namespace="root\\SecurityCenter2")
            if av_results:
                info["antivirus_name"] = av_results[0].get("displayName", "")
                info["antivirus_status"] = "enabled"
        except:
            pass
        return info
