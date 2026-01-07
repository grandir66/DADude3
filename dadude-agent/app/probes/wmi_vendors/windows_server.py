"""
DaDude Agent - Windows Server WMI Probe
Scansione Windows Server (2012, 2016, 2019, 2022) via WMI/WinRM.
"""
from typing import Dict, Any, List
from .base import WMIVendorProbe


class WindowsServerProbe(WMIVendorProbe):
    """Probe per Windows Server"""
    
    DEVICE_TYPE = "windows_server"
    DETECTION_PRIORITY = 10
    
    def detect(self) -> bool:
        """Rileva se è Windows Server"""
        try:
            results = self.wmi_query("SELECT Caption, ProductType FROM Win32_OperatingSystem")
            if results:
                caption = results[0].get("Caption", "").lower()
                product_type = self._safe_int(results[0].get("ProductType"))
                # ProductType: 1=Workstation, 2=Domain Controller, 3=Server
                return product_type in (2, 3) or "server" in caption
            return False
        except Exception as e:
            self._log_debug(f"Detection failed: {e}")
            return False
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Windows Server"""
        self._log_info(f"Starting probe for {target}")
        
        info = {
            "device_type": "windows_server",
            "category": "server",
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
        
        # Services
        services = self._get_services()
        if services:
            info["services"] = services
            info["services_count"] = len(services)
        
        # Server Roles (Windows Server specific)
        roles = self._get_server_roles()
        if roles:
            info["server_roles"] = roles
            info["server_roles_count"] = len(roles)
        
        # Domain Info
        domain_info = self._get_domain_info()
        if domain_info:
            info.update(domain_info)
        
        # Software
        software = self._get_installed_software()
        if software:
            info["software"] = software
            info["software_count"] = len(software)
        
        # Users
        users = self._get_local_users()
        if users:
            info["local_users"] = users
        
        # Security
        security = self._get_security_info()
        if security:
            info.update(security)
        
        # Updates
        updates = self._get_pending_updates()
        if updates:
            info["pending_updates"] = updates
            info["pending_updates_count"] = len(updates)
        
        self._log_info(f"Probe complete for {target}: hostname={info.get('hostname')}, os={info.get('os_name')}")
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
                info["os_name"] = r.get("Caption", "Windows Server")
                info["os_version"] = r.get("Version", "")
                info["os_build"] = r.get("BuildNumber", "")
                info["architecture"] = r.get("OSArchitecture", "")
                info["serial_number"] = r.get("SerialNumber", "")
                info["install_date"] = self._wmi_datetime_to_str(r.get("InstallDate", ""))
                info["last_boot"] = self._wmi_datetime_to_str(r.get("LastBootUpTime", ""))
                
                # RAM da OS info (backup)
                total_kb = self._safe_int(r.get("TotalVisibleMemorySize"))
                free_kb = self._safe_int(r.get("FreePhysicalMemory"))
                if total_kb:
                    info["ram_total_mb"] = total_kb // 1024
                    info["ram_free_mb"] = free_kb // 1024
                    info["ram_usage_percent"] = round((total_kb - free_kb) / total_kb * 100, 1)
        except Exception as e:
            self._log_debug(f"OS info failed: {e}")
        return info
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Ottiene info sistema computer"""
        info = {}
        try:
            results = self.wmi_query("""
                SELECT Name, Domain, Manufacturer, Model, 
                       TotalPhysicalMemory, NumberOfProcessors,
                       NumberOfLogicalProcessors, DomainRole
                FROM Win32_ComputerSystem
            """)
            if results:
                r = results[0]
                info["hostname"] = r.get("Name", "")
                info["domain"] = r.get("Domain", "")
                info["manufacturer"] = r.get("Manufacturer", "")
                info["model"] = r.get("Model", "")
                info["cpu_sockets"] = self._safe_int(r.get("NumberOfProcessors"))
                info["cpu_logical"] = self._safe_int(r.get("NumberOfLogicalProcessors"))
                
                # DomainRole: 0=Standalone, 1=Member Workstation, 2=Standalone Server, 
                # 3=Member Server, 4=Backup DC, 5=Primary DC
                domain_role = self._safe_int(r.get("DomainRole"))
                info["domain_role"] = domain_role
                info["is_domain_controller"] = domain_role in (4, 5)
                info["is_domain_member"] = domain_role in (1, 3, 4, 5)
                
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
                info["cpu_usage_percent"] = self._safe_int(r.get("LoadPercentage"))
        except Exception as e:
            self._log_debug(f"CPU info failed: {e}")
        return info
    
    def _get_memory_info(self) -> Dict[str, Any]:
        """Ottiene info memoria"""
        info = {}
        try:
            # Moduli RAM
            results = self.wmi_query("""
                SELECT Capacity, Speed, Manufacturer, PartNumber
                FROM Win32_PhysicalMemory
            """)
            if results:
                modules = []
                total_bytes = 0
                for r in results:
                    cap = self._safe_int(r.get("Capacity"))
                    total_bytes += cap
                    modules.append({
                        "capacity_gb": self._bytes_to_gb(cap),
                        "speed_mhz": self._safe_int(r.get("Speed")),
                        "manufacturer": r.get("Manufacturer", "").strip(),
                        "part_number": r.get("PartNumber", "").strip(),
                    })
                info["ram_modules"] = modules
                info["ram_total_gb"] = self._bytes_to_gb(total_bytes)
                info["ram_modules_count"] = len(modules)
        except Exception as e:
            self._log_debug(f"Memory info failed: {e}")
        return info
    
    def _get_disk_info(self) -> Dict[str, Any]:
        """Ottiene info dischi"""
        info = {}
        disks = []
        volumes = []
        
        try:
            # Dischi fisici
            disk_results = self.wmi_query("""
                SELECT DeviceID, Model, Size, MediaType, SerialNumber
                FROM Win32_DiskDrive
            """)
            for r in disk_results:
                disks.append({
                    "device": r.get("DeviceID", ""),
                    "model": r.get("Model", ""),
                    "size_gb": self._bytes_to_gb(r.get("Size")),
                    "type": r.get("MediaType", ""),
                    "serial": r.get("SerialNumber", "").strip(),
                })
            
            # Volumi logici
            vol_results = self.wmi_query("""
                SELECT DeviceID, VolumeName, Size, FreeSpace, FileSystem, DriveType
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
                    "used_gb": self._bytes_to_gb(size - free),
                    "filesystem": r.get("FileSystem", ""),
                    "usage_percent": round((size - free) / size * 100, 1) if size > 0 else 0,
                })
            
            info["disks"] = disks
            info["disks_count"] = len(disks)
            info["volumes"] = volumes
            info["volumes_count"] = len(volumes)
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
                SELECT Description, MACAddress, IPAddress, IPSubnet,
                       DefaultIPGateway, DHCPEnabled, DNSServerSearchOrder
                FROM Win32_NetworkAdapterConfiguration
                WHERE IPEnabled = TRUE
            """)
            for r in results:
                ip_list = r.get("IPAddress", [])
                subnet_list = r.get("IPSubnet", [])
                gateway_list = r.get("DefaultIPGateway", [])
                dns_list = r.get("DNSServerSearchOrder", [])
                
                iface = {
                    "name": r.get("Description", ""),
                    "mac_address": r.get("MACAddress", ""),
                    "ipv4": ip_list[0] if ip_list else "",
                    "subnet": subnet_list[0] if subnet_list else "",
                    "gateway": gateway_list[0] if gateway_list else "",
                    "dhcp_enabled": r.get("DHCPEnabled", False),
                    "dns_servers": dns_list or [],
                }
                interfaces.append(iface)
                
                # Prima interfaccia come primaria
                if not info.get("primary_ip") and iface["ipv4"]:
                    info["primary_ip"] = iface["ipv4"]
                    info["primary_mac"] = iface["mac_address"]
                    info["default_gateway"] = iface["gateway"]
                    info["dns_servers"] = iface["dns_servers"]
            
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
            
        except Exception as e:
            self._log_debug(f"Network info failed: {e}")
        return info
    
    def _get_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi Windows"""
        services = []
        try:
            # Solo servizi in esecuzione
            results = self.wmi_query("""
                SELECT Name, DisplayName, State, StartMode, ProcessId
                FROM Win32_Service
                WHERE State = 'Running'
            """)
            for r in results:
                services.append({
                    "name": r.get("Name", ""),
                    "display_name": r.get("DisplayName", ""),
                    "status": r.get("State", ""),
                    "start_mode": r.get("StartMode", ""),
                    "pid": self._safe_int(r.get("ProcessId")),
                })
        except Exception as e:
            self._log_debug(f"Services failed: {e}")
        return services[:100]  # Limita a 100
    
    def _get_server_roles(self) -> List[Dict[str, str]]:
        """Ottiene ruoli server (Windows Server Feature)"""
        roles = []
        try:
            # Win32_ServerFeature esiste solo su Windows Server
            results = self.wmi_query("SELECT Name, ID FROM Win32_ServerFeature")
            for r in results:
                roles.append({
                    "name": r.get("Name", ""),
                    "id": str(r.get("ID", "")),
                })
        except Exception as e:
            self._log_debug(f"Server roles query failed (normal on non-Server): {e}")
        return roles
    
    def _get_domain_info(self) -> Dict[str, Any]:
        """Ottiene info dominio Active Directory"""
        info = {}
        try:
            results = self.wmi_query("SELECT Domain FROM Win32_ComputerSystem")
            if results:
                info["domain"] = results[0].get("Domain", "")
                
            # LDAP info per DC
            if info.get("is_domain_controller"):
                try:
                    # Query LDAP per info DC
                    dc_results = self.wmi_query("""
                        SELECT DomainDNSName, ForestDNSName
                        FROM Win32_NTDomain
                    """)
                    if dc_results:
                        info["domain_dns_name"] = dc_results[0].get("DomainDNSName", "")
                        info["forest_dns_name"] = dc_results[0].get("ForestDNSName", "")
                except:
                    pass
        except Exception as e:
            self._log_debug(f"Domain info failed: {e}")
        return info
    
    def _get_installed_software(self) -> List[Dict[str, str]]:
        """Ottiene software installato"""
        software = []
        try:
            results = self.wmi_query("""
                SELECT Name, Version, Vendor, InstallDate
                FROM Win32_Product
            """)
            for r in results:
                if r.get("Name"):
                    software.append({
                        "name": r.get("Name", ""),
                        "version": r.get("Version", ""),
                        "vendor": r.get("Vendor", ""),
                        "install_date": r.get("InstallDate", ""),
                    })
        except Exception as e:
            self._log_debug(f"Software query failed: {e}")
        return software[:200]  # Limita a 200
    
    def _get_local_users(self) -> List[Dict[str, Any]]:
        """Ottiene utenti locali"""
        users = []
        try:
            results = self.wmi_query("""
                SELECT Name, FullName, Disabled, LocalAccount, 
                       PasswordRequired, PasswordChangeable
                FROM Win32_UserAccount WHERE LocalAccount = TRUE
            """)
            for r in results:
                users.append({
                    "name": r.get("Name", ""),
                    "full_name": r.get("FullName", ""),
                    "disabled": r.get("Disabled", False),
                    "local_account": r.get("LocalAccount", True),
                    "password_required": r.get("PasswordRequired", False),
                })
        except Exception as e:
            self._log_debug(f"Users query failed: {e}")
        return users
    
    def _get_security_info(self) -> Dict[str, Any]:
        """Ottiene info sicurezza (antivirus, firewall)"""
        info = {}
        try:
            # Windows Security Center (potrebbe non essere disponibile su Server)
            av_results = self.wmi_query("""
                SELECT displayName, productState
                FROM AntiVirusProduct
            """, namespace="root\\SecurityCenter2")
            if av_results:
                info["antivirus_name"] = av_results[0].get("displayName", "")
                info["antivirus_status"] = "enabled"
        except:
            # Windows Defender check
            try:
                defender = self.wmi_query("""
                    SELECT AntivirusEnabled, RealTimeProtectionEnabled
                    FROM MSFT_MpComputerStatus
                """, namespace="root\\Microsoft\\Windows\\Defender")
                if defender:
                    info["antivirus_name"] = "Windows Defender"
                    info["antivirus_enabled"] = defender[0].get("AntivirusEnabled", False)
                    info["realtime_protection"] = defender[0].get("RealTimeProtectionEnabled", False)
            except:
                pass
        
        # Firewall status
        try:
            fw_results = self.wmi_query("""
                SELECT Enabled FROM MSFT_NetFirewallProfile
            """, namespace="root\\StandardCimv2")
            if fw_results:
                info["firewall_enabled"] = any(r.get("Enabled", False) for r in fw_results)
        except:
            pass
        
        return info
    
    def _get_pending_updates(self) -> List[Dict[str, str]]:
        """Ottiene aggiornamenti in sospeso"""
        updates = []
        try:
            results = self.wmi_query("""
                SELECT Title, Description, MsrcSeverity
                FROM CCM_SoftwareUpdate
                WHERE ComplianceState = 0
            """, namespace="root\\CCM\\ClientSDK")
            for r in results:
                updates.append({
                    "title": r.get("Title", ""),
                    "severity": r.get("MsrcSeverity", ""),
                })
        except:
            # SCCM non installato, normale
            pass
        return updates[:50]
