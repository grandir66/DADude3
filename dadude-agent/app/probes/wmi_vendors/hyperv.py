"""
DaDude Agent - Hyper-V Host WMI Probe
Scansione Hyper-V hosts via WMI/WinRM.
"""
from typing import Dict, Any, List
from .windows_server import WindowsServerProbe


class HyperVProbe(WindowsServerProbe):
    """Probe per Hyper-V Host (estende Windows Server)"""
    
    DEVICE_TYPE = "hyperv"
    DETECTION_PRIORITY = 5  # Prima di Windows Server generico
    
    def detect(self) -> bool:
        """Rileva se è Hyper-V Host"""
        try:
            # Verifica se Hyper-V è installato
            results = self.wmi_query(
                "SELECT Name FROM Msvm_VirtualSystemManagementService",
                namespace="root\\virtualization\\v2"
            )
            return bool(results)
        except Exception as e:
            self._log_debug(f"Hyper-V detection failed: {e}")
            return False
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Hyper-V Host"""
        # Prima ottieni info Windows Server base
        info = super().probe(target)
        
        # Poi aggiungi info Hyper-V specifiche
        info["device_type"] = "hyperv"
        info["category"] = "hypervisor"
        info["hypervisor_type"] = "Hyper-V"
        
        # VMs
        vms = self._get_vms()
        if vms:
            info["vms"] = vms
            info["vm_count"] = len(vms)
            info["vms_running"] = len([v for v in vms if v.get("state") == "Running"])
        
        # Virtual switches
        switches = self._get_virtual_switches()
        if switches:
            info["virtual_switches"] = switches
        
        # Storage pools
        storage = self._get_hyperv_storage()
        if storage:
            info["hyperv_storage"] = storage
        
        self._log_info(f"Hyper-V probe complete for {target}: {info.get('vm_count', 0)} VMs")
        return info
    
    def _get_vms(self) -> List[Dict[str, Any]]:
        """Ottiene lista VM"""
        vms = []
        try:
            results = self.wmi_query("""
                SELECT ElementName, EnabledState, ProcessorCount,
                       OnTimeInMilliseconds, HealthState
                FROM Msvm_ComputerSystem
                WHERE Caption = 'Virtual Machine'
            """, namespace="root\\virtualization\\v2")
            
            for r in results:
                # EnabledState: 2=Running, 3=Off, 32768=Paused, 32769=Suspended
                state_map = {
                    2: "Running",
                    3: "Off",
                    32768: "Paused",
                    32769: "Suspended",
                    32770: "Starting",
                    32771: "Snapshotting",
                    32773: "Saving",
                    32774: "Stopping",
                }
                state = state_map.get(self._safe_int(r.get("EnabledState")), "Unknown")
                
                vms.append({
                    "name": r.get("ElementName", ""),
                    "state": state,
                    "cpu_count": self._safe_int(r.get("ProcessorCount")),
                    "uptime_ms": self._safe_int(r.get("OnTimeInMilliseconds")),
                    "health": "OK" if self._safe_int(r.get("HealthState")) == 5 else "Warning",
                })
        except Exception as e:
            self._log_debug(f"VMs query failed: {e}")
        return vms
    
    def _get_virtual_switches(self) -> List[Dict[str, str]]:
        """Ottiene virtual switches"""
        switches = []
        try:
            results = self.wmi_query("""
                SELECT ElementName, Notes
                FROM Msvm_VirtualEthernetSwitch
            """, namespace="root\\virtualization\\v2")
            
            for r in results:
                switches.append({
                    "name": r.get("ElementName", ""),
                    "notes": r.get("Notes", ""),
                })
        except Exception as e:
            self._log_debug(f"Virtual switches query failed: {e}")
        return switches
    
    def _get_hyperv_storage(self) -> Dict[str, Any]:
        """Ottiene info storage Hyper-V"""
        storage = {}
        try:
            # Ottieni path VHD
            results = self.wmi_query("""
                SELECT DefaultVirtualHardDiskPath, DefaultExternalDataRoot
                FROM Msvm_VirtualSystemManagementServiceSettingData
            """, namespace="root\\virtualization\\v2")
            
            if results:
                storage["default_vhd_path"] = results[0].get("DefaultVirtualHardDiskPath", "")
                storage["default_data_root"] = results[0].get("DefaultExternalDataRoot", "")
        except Exception as e:
            self._log_debug(f"Hyper-V storage query failed: {e}")
        return storage
