"""
DaDude Agent - WMI Probe
Scansione dettagliata dispositivi Windows via WMI/DCOM
"""
import asyncio
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor
from loguru import logger


_executor = ThreadPoolExecutor(max_workers=5)


async def probe(
    target: str,
    username: str,
    password: str,
    domain: str = "",
) -> Dict[str, Any]:
    """
    Esegue probe WMI dettagliato su un target Windows.
    
    Returns:
        Dict con info complete: OS, hardware, rete, dischi, servizi, software
    """
    loop = asyncio.get_event_loop()
    
    def connect():
        from impacket.dcerpc.v5.dcom import wmi as dcom_wmi
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        
        # Esattamente come il server: domain vuoto se non specificato
        effective_domain = domain if domain else ""
        
        logger.debug(f"WMI probe: connecting to {target} as {effective_domain}\\{username if effective_domain else username}")
        
        # Connessione DCOM - passa stringhe direttamente come fa il server
        dcom = DCOMConnection(
            target,
            username=username,
            password=password,
            domain=effective_domain
        )
        
        # Query WMI
        iInterface = dcom.CoCreateInstanceEx(
            dcom_wmi.CLSID_WbemLevel1Login,
            dcom_wmi.IID_IWbemLevel1Login
        )
        iWbemLevel1Login = dcom_wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', dcom_wmi.NULL, dcom_wmi.NULL)
        
        info = {}
        
        def get_prop(props, name, default=""):
            if name in props:
                val = props[name].get('value', default)
                if val is None:
                    return default
                # Converti bytes in string se necessario (Python 3 compatibility)
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='replace')
                    except:
                        val = str(val)
                return val
            return default
        
        def query_single(query: str) -> Dict:
            """Esegue query e ritorna primo risultato come dict"""
            try:
                result = iWbemServices.ExecQuery(query)
                item = result.Next(0xffffffff, 1)[0]
                return item.getProperties()
            except:
                return {}
        
        def query_all(query: str, limit: int = 50) -> List[Dict]:
            """Esegue query e ritorna tutti i risultati"""
            results = []
            try:
                result = iWbemServices.ExecQuery(query)
                count = 0
                while count < limit:
                    try:
                        item = result.Next(0xffffffff, 1)[0]
                        results.append(item.getProperties())
                        count += 1
                    except:
                        break
            except:
                pass
            return results
        
        # ==========================================
        # SISTEMA OPERATIVO
        # ==========================================
        props = query_single("SELECT Caption, Version, BuildNumber, OSArchitecture, SerialNumber, LastBootUpTime, InstallDate, RegisteredUser, Organization FROM Win32_OperatingSystem")
        if props:
            info["os_name"] = str(get_prop(props, "Caption"))
            info["os_version"] = str(get_prop(props, "Version"))
            info["os_build"] = str(get_prop(props, "BuildNumber"))
            info["architecture"] = str(get_prop(props, "OSArchitecture"))
            info["os_serial"] = str(get_prop(props, "SerialNumber"))
            info["last_boot"] = str(get_prop(props, "LastBootUpTime"))
            info["install_date"] = str(get_prop(props, "InstallDate"))
            info["registered_user"] = str(get_prop(props, "RegisteredUser"))
            info["organization"] = str(get_prop(props, "Organization"))
        
        # ==========================================
        # COMPUTER SYSTEM
        # ==========================================
        props = query_single("SELECT Name, Domain, Model, Manufacturer, TotalPhysicalMemory, SystemType, NumberOfProcessors, DomainRole FROM Win32_ComputerSystem")
        if props:
            info["hostname"] = str(get_prop(props, "Name"))
            info["domain"] = str(get_prop(props, "Domain"))
            info["model"] = str(get_prop(props, "Model"))
            info["manufacturer"] = str(get_prop(props, "Manufacturer"))
            info["system_type"] = str(get_prop(props, "SystemType"))
            info["processor_count"] = int(get_prop(props, "NumberOfProcessors", 0))
            
            # DomainRole: 0=Standalone Workstation, 1=Member Workstation, 2=Standalone Server, 3=Member Server, 4=Backup DC, 5=Primary DC
            domain_role = int(get_prop(props, "DomainRole", 0))
            role_names = {0: "Standalone Workstation", 1: "Member Workstation", 2: "Standalone Server", 
                         3: "Member Server", 4: "Backup Domain Controller", 5: "Primary Domain Controller"}
            info["domain_role"] = role_names.get(domain_role, "Unknown")
            info["is_domain_controller"] = domain_role >= 4
            info["is_server"] = domain_role >= 2
            
            mem = get_prop(props, "TotalPhysicalMemory")
            if mem:
                try:
                    info["ram_total_mb"] = int(mem) // (1024 * 1024)
                    info["ram_total_gb"] = round(int(mem) / (1024 ** 3), 1)
                except:
                    pass
        
        # ==========================================
        # CPU
        # ==========================================
        props = query_single("SELECT Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed, Manufacturer FROM Win32_Processor")
        if props:
            info["cpu_model"] = str(get_prop(props, "Name"))
            info["cpu_manufacturer"] = str(get_prop(props, "Manufacturer"))
            cores = get_prop(props, "NumberOfCores")
            if cores:
                info["cpu_cores"] = int(cores)
            threads = get_prop(props, "NumberOfLogicalProcessors")
            if threads:
                info["cpu_threads"] = int(threads)
            speed = get_prop(props, "MaxClockSpeed")
            if speed:
                info["cpu_speed_mhz"] = int(speed)
        
        # ==========================================
        # DISCHI (tutti i dischi fissi)
        # ==========================================
        disks = []
        total_size = 0
        total_free = 0
        for props in query_all("SELECT DeviceID, Size, FreeSpace, FileSystem, VolumeName FROM Win32_LogicalDisk WHERE DriveType=3"):
            disk = {
                "device": str(get_prop(props, "DeviceID")),
                "filesystem": str(get_prop(props, "FileSystem")),
                "label": str(get_prop(props, "VolumeName")),
            }
            size = get_prop(props, "Size")
            free = get_prop(props, "FreeSpace")
            if size:
                disk["size_gb"] = int(size) // (1024 ** 3)
                total_size += disk["size_gb"]
            if free:
                disk["free_gb"] = int(free) // (1024 ** 3)
                total_free += disk["free_gb"]
            disks.append(disk)
        
        if disks:
            info["disks"] = disks
            info["disk_total_gb"] = total_size
            info["disk_free_gb"] = total_free
        
        # ==========================================
        # BIOS / SERIAL
        # ==========================================
        props = query_single("SELECT SerialNumber, Manufacturer, SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS")
        if props:
            serial = str(get_prop(props, "SerialNumber"))
            if serial and serial not in ["To Be Filled By O.E.M.", "Default string", ""]:
                info["serial_number"] = serial
            info["bios_manufacturer"] = str(get_prop(props, "Manufacturer"))
            info["bios_version"] = str(get_prop(props, "SMBIOSBIOSVersion"))
        
        # ==========================================
        # NETWORK ADAPTERS
        # ==========================================
        adapters = []
        for props in query_all("SELECT Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True"):
            adapter = {
                "name": str(get_prop(props, "Description")),
                "mac": str(get_prop(props, "MACAddress")),
                "dhcp": bool(get_prop(props, "DHCPEnabled")),
            }
            ips = get_prop(props, "IPAddress")
            if ips:
                adapter["ips"] = list(ips) if hasattr(ips, '__iter__') and not isinstance(ips, str) else [str(ips)]
            subnet = get_prop(props, "IPSubnet")
            if subnet:
                adapter["subnets"] = list(subnet) if hasattr(subnet, '__iter__') and not isinstance(subnet, str) else [str(subnet)]
            gw = get_prop(props, "DefaultIPGateway")
            if gw:
                adapter["gateway"] = list(gw) if hasattr(gw, '__iter__') and not isinstance(gw, str) else [str(gw)]
            dns = get_prop(props, "DNSServerSearchOrder")
            if dns:
                adapter["dns"] = list(dns) if hasattr(dns, '__iter__') and not isinstance(dns, str) else [str(dns)]
            adapters.append(adapter)
        
        if adapters:
            info["network_adapters"] = adapters
        
        # ==========================================
        # MEMORIA FISICA (DIMM)
        # ==========================================
        memory_modules = []
        for props in query_all("SELECT Capacity, Speed, Manufacturer, PartNumber FROM Win32_PhysicalMemory"):
            module = {}
            cap = get_prop(props, "Capacity")
            if cap:
                module["size_gb"] = int(cap) // (1024 ** 3)
            speed = get_prop(props, "Speed")
            if speed:
                module["speed_mhz"] = int(speed)
            mfr = get_prop(props, "Manufacturer")
            if mfr:
                module["manufacturer"] = str(mfr)
            if module:
                memory_modules.append(module)
        
        if memory_modules:
            info["memory_modules"] = memory_modules
        
        # ==========================================
        # SERVER ROLES (solo Windows Server)
        # ==========================================
        if info.get("is_server"):
            roles = []
            for props in query_all("SELECT Name FROM Win32_ServerFeature WHERE ParentID=0", limit=20):
                name = str(get_prop(props, "Name"))
                if name:
                    roles.append(name)
            if roles:
                info["server_roles"] = roles
        
        # ==========================================
        # SERVIZI IMPORTANTI
        # ==========================================
        services = []
        important_services = [
            "SQL Server", "Exchange", "IIS", "Active Directory", "DNS", "DHCP",
            "Hyper-V", "Print Spooler", "Windows Update", "Remote Desktop"
        ]
        for props in query_all("SELECT Name, DisplayName, State, StartMode FROM Win32_Service WHERE State='Running'", limit=100):
            display_name = str(get_prop(props, "DisplayName"))
            # Filtra solo servizi interessanti
            if any(svc.lower() in display_name.lower() for svc in important_services):
                services.append({
                    "name": str(get_prop(props, "Name")),
                    "display_name": display_name,
                    "state": str(get_prop(props, "State")),
                    "start_mode": str(get_prop(props, "StartMode")),
                })
        
        if services:
            info["important_services"] = services
        
        # ==========================================
        # SOFTWARE INSTALLATO (top 30)
        # ==========================================
        software = []
        for props in query_all("SELECT Name, Version, Vendor FROM Win32_Product", limit=30):
            name = str(get_prop(props, "Name"))
            if name:
                software.append({
                    "name": name,
                    "version": str(get_prop(props, "Version")),
                    "vendor": str(get_prop(props, "Vendor")),
                })
        
        if software:
            info["installed_software"] = software
        
        # ==========================================
        # UTENTI LOCALI
        # ==========================================
        users = []
        for props in query_all("SELECT Name, FullName, Disabled, LocalAccount FROM Win32_UserAccount WHERE LocalAccount=True", limit=20):
            users.append({
                "name": str(get_prop(props, "Name")),
                "full_name": str(get_prop(props, "FullName")),
                "disabled": bool(get_prop(props, "Disabled")),
            })
        
        if users:
            info["local_users"] = users
        
        # ==========================================
        # ANTIVIRUS (Windows Security Center)
        # ==========================================
        try:
            iWbemSecurityServices = iWbemLevel1Login.NTLMLogin('//./root/SecurityCenter2', dcom_wmi.NULL, dcom_wmi.NULL)
            av_result = iWbemSecurityServices.ExecQuery("SELECT displayName, productState FROM AntivirusProduct")
            av_products = []
            while True:
                try:
                    item = av_result.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    av_products.append({
                        "name": str(get_prop(props, "displayName")),
                        "state": str(get_prop(props, "productState")),
                    })
                except:
                    break
            if av_products:
                info["antivirus"] = av_products
        except:
            pass
        
        dcom.disconnect()
        
        logger.info(f"WMI probe successful: {info.get('hostname')} ({info.get('os_name')}) - {len(info)} fields collected")
        return info
    
    return await loop.run_in_executor(_executor, connect)
