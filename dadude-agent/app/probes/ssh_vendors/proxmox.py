"""
DaDude Agent - Proxmox VE SSH Probe
Scansione hypervisor Proxmox VE via SSH.
"""
from typing import Dict, Any, List
from .base import SSHVendorProbe


class ProxmoxProbe(SSHVendorProbe):
    """Probe per Proxmox VE hypervisor"""
    
    VENDOR_NAME = "Proxmox"
    DETECTION_PRIORITY = 35  # Prima di Linux generico
    
    def detect(self) -> bool:
        """Rileva Proxmox VE"""
        # Verifica file specifici Proxmox
        pve = self.exec_cmd("cat /etc/pve/version 2>/dev/null || dpkg -l pve-manager 2>/dev/null", timeout=3)
        if pve and ('pve' in pve.lower() or 'proxmox' in pve.lower()):
            return True
        
        # Verifica pvesh
        pvesh = self.exec_cmd("which pvesh 2>/dev/null", timeout=3)
        return bool(pvesh and 'pvesh' in pvesh)
    
    def probe(self, target: str) -> Dict[str, Any]:
        """Scansione completa Proxmox VE"""
        self._log_info(f"Probing Proxmox at {target}")
        
        info = {
            "device_type": "hypervisor",
            "manufacturer": "Proxmox",
            "os_name": "Proxmox VE",
            "category": "compute",
            "os_family": "Linux",
        }
        
        # Hostname
        hostname = self.exec_cmd("hostname", timeout=3)
        if hostname:
            info["hostname"] = hostname.strip()
        
        # Version
        version = self._get_pve_version()
        if version:
            info.update(version)
        
        # Hardware
        hw = self._get_hardware_info()
        if hw:
            info.update(hw)
        
        # Cluster info
        cluster = self._get_cluster_info()
        if cluster:
            info.update(cluster)
        
        # Storage
        storage = self._get_storage_info()
        if storage:
            info.update(storage)
        
        # VMs e containers
        vms = self._get_vms()
        if vms:
            info["vms"] = vms
            info["vm_count"] = len(vms)
        
        containers = self._get_containers()
        if containers:
            info["containers"] = containers
            info["container_count"] = len(containers)
        
        # Network
        interfaces = self._get_interfaces()
        if interfaces:
            info["interfaces"] = interfaces
            info["interface_count"] = len(interfaces)
        
        # Services
        services = self._get_pve_services()
        if services:
            info["services"] = services
        
        self._log_info(f"Proxmox probe complete: hostname={info.get('hostname')}, version={info.get('os_version')}")
        return info
    
    def _get_pve_version(self) -> Dict[str, Any]:
        """Ottiene versione Proxmox VE"""
        info = {}
        
        # pveversion
        pveversion = self.exec_cmd("pveversion 2>/dev/null", timeout=3)
        if pveversion:
            info["pve_full_version"] = pveversion.strip()
            # Parse: pve-manager/7.4-3/xxxxxxxx
            for part in pveversion.split('/'):
                if part and part[0].isdigit():
                    info["os_version"] = part.split('/')[0]
                    break
        
        # Kernel
        kernel = self.exec_cmd("uname -r", timeout=3)
        if kernel:
            info["kernel_version"] = kernel.strip()
        
        return info
    
    def _get_hardware_info(self) -> Dict[str, Any]:
        """Ottiene informazioni hardware"""
        info = {}
        
        # CPU
        cpu = self.exec_cmd("cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1", timeout=3)
        if cpu:
            info["cpu_model"] = cpu.split(':')[-1].strip()
        
        cpu_cores = self.exec_cmd("nproc 2>/dev/null", timeout=3)
        if cpu_cores and cpu_cores.strip().isdigit():
            info["cpu_cores"] = int(cpu_cores.strip())
        
        # CPU usage
        cpu_usage = self.exec_cmd("top -bn1 | grep 'Cpu(s)' | head -1", timeout=3)
        if cpu_usage:
            try:
                # us% user, sy% system
                for part in cpu_usage.split(','):
                    if 'id' in part.lower():
                        idle = float(part.split()[0])
                        info["cpu_usage_percent"] = round(100 - idle, 1)
                        break
            except:
                pass
        
        # RAM
        mem = self.exec_cmd("cat /proc/meminfo 2>/dev/null | grep -E '^(MemTotal|MemAvailable):'", timeout=3)
        if mem:
            for line in mem.split('\n'):
                if 'MemTotal' in line:
                    try:
                        info["ram_total_mb"] = int(line.split()[1]) // 1024
                    except:
                        pass
                elif 'MemAvailable' in line:
                    try:
                        info["ram_free_mb"] = int(line.split()[1]) // 1024
                    except:
                        pass
        
        # Calcola utilizzo RAM
        if info.get("ram_total_mb") and info.get("ram_free_mb"):
            used = info["ram_total_mb"] - info["ram_free_mb"]
            info["ram_used_mb"] = used
            info["ram_usage_percent"] = round((used / info["ram_total_mb"]) * 100, 1)
        
        # DMI
        manufacturer = self.exec_cmd_sudo("dmidecode -s system-manufacturer 2>/dev/null", timeout=5)
        if manufacturer and manufacturer.strip():
            info["hardware_manufacturer"] = manufacturer.strip()
        
        product = self.exec_cmd_sudo("dmidecode -s system-product-name 2>/dev/null", timeout=5)
        if product and product.strip():
            info["hardware_model"] = product.strip()
        
        serial = self.exec_cmd_sudo("dmidecode -s system-serial-number 2>/dev/null", timeout=5)
        if serial and serial.strip():
            info["serial_number"] = serial.strip()
        
        # Uptime
        uptime = self.exec_cmd("uptime -p 2>/dev/null || uptime", timeout=3)
        if uptime:
            info["uptime"] = uptime.strip()
        
        return info
    
    def _get_cluster_info(self) -> Dict[str, Any]:
        """Ottiene informazioni cluster Proxmox"""
        info = {}
        
        # Cluster status
        cluster = self.exec_cmd("pvecm status 2>/dev/null", timeout=5)
        if cluster and 'cluster' in cluster.lower():
            info["cluster_enabled"] = True
            
            for line in cluster.split('\n'):
                ll = line.lower().strip()
                if 'cluster name' in ll or 'name:' in ll:
                    info["cluster_name"] = line.split(':')[-1].strip() if ':' in line else ""
                elif 'quorum' in ll and ':' in line:
                    info["cluster_quorum"] = line.split(':')[-1].strip()
                elif 'nodes:' in ll:
                    try:
                        info["cluster_nodes"] = int(line.split(':')[-1].strip())
                    except:
                        pass
        else:
            info["cluster_enabled"] = False
        
        # Nodes list
        nodes = self.exec_cmd("pvesh get /nodes --output-format=json 2>/dev/null", timeout=5)
        if nodes and '[' in nodes:
            try:
                import json
                nodes_data = json.loads(nodes)
                info["nodes"] = [{
                    "name": n.get("node", ""),
                    "status": n.get("status", ""),
                    "cpu": n.get("cpu", 0),
                    "mem": n.get("mem", 0),
                    "maxmem": n.get("maxmem", 0),
                } for n in nodes_data]
            except:
                pass
        
        return info
    
    def _get_storage_info(self) -> Dict[str, Any]:
        """Ottiene informazioni storage Proxmox"""
        info = {}
        
        # Storage list via pvesh
        storage = self.exec_cmd("pvesh get /storage --output-format=json 2>/dev/null", timeout=5)
        if storage and '[' in storage:
            try:
                import json
                storage_data = json.loads(storage)
                info["storage_pools"] = [{
                    "name": s.get("storage", ""),
                    "type": s.get("type", ""),
                    "content": s.get("content", ""),
                    "enabled": s.get("disable", 0) == 0,
                } for s in storage_data]
                info["storage_pool_count"] = len(storage_data)
            except:
                pass
        
        # Storage usage
        storage_status = self.exec_cmd("pvesh get /nodes/$(hostname)/storage --output-format=json 2>/dev/null", timeout=5)
        if storage_status and '[' in storage_status:
            try:
                import json
                status_data = json.loads(storage_status)
                info["storage_usage"] = [{
                    "name": s.get("storage", ""),
                    "total": s.get("total", 0),
                    "used": s.get("used", 0),
                    "avail": s.get("avail", 0),
                    "type": s.get("type", ""),
                    "enabled": s.get("enabled", 1) == 1,
                } for s in status_data if s.get("active")]
            except:
                pass
        
        # ZFS pools
        zfs = self.exec_cmd("zpool list -H 2>/dev/null", timeout=5)
        if zfs:
            zfs_pools = []
            for line in zfs.split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 5:
                        zfs_pools.append({
                            "name": parts[0],
                            "size": parts[1],
                            "alloc": parts[2],
                            "free": parts[3],
                            "health": parts[-2] if len(parts) >= 10 else parts[4] if len(parts) >= 5 else "",
                        })
            if zfs_pools:
                info["zfs_pools"] = zfs_pools
                info["zfs_pool_count"] = len(zfs_pools)
        
        # Ceph (se presente)
        ceph = self.exec_cmd("ceph -s --format json 2>/dev/null | head -c 2000", timeout=5)
        if ceph and '{' in ceph:
            info["ceph_enabled"] = True
            try:
                import json
                ceph_data = json.loads(ceph)
                info["ceph_health"] = ceph_data.get("health", {}).get("status", "")
            except:
                pass
        
        return info
    
    def _get_vms(self) -> List[Dict[str, Any]]:
        """Ottiene lista VM"""
        vms = []
        
        # pvesh per VMs
        qemu = self.exec_cmd("pvesh get /nodes/$(hostname)/qemu --output-format=json 2>/dev/null", timeout=10)
        if qemu and '[' in qemu:
            try:
                import json
                qemu_data = json.loads(qemu)
                for vm in qemu_data:
                    vms.append({
                        "vmid": vm.get("vmid", 0),
                        "name": vm.get("name", ""),
                        "status": vm.get("status", ""),
                        "cpu": vm.get("cpus", 0),
                        "mem_mb": vm.get("maxmem", 0) // (1024 * 1024) if vm.get("maxmem") else 0,
                        "disk_gb": vm.get("maxdisk", 0) // (1024 * 1024 * 1024) if vm.get("maxdisk") else 0,
                        "type": "qemu",
                    })
            except:
                pass
        
        # Fallback: qm list
        if not vms:
            qm = self.exec_cmd("qm list 2>/dev/null | tail -n +2", timeout=5)
            if qm:
                for line in qm.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].isdigit():
                            vms.append({
                                "vmid": int(parts[0]),
                                "name": parts[1],
                                "status": parts[2],
                                "type": "qemu",
                            })
        
        return vms
    
    def _get_containers(self) -> List[Dict[str, Any]]:
        """Ottiene lista containers LXC"""
        containers = []
        
        # pvesh per LXC
        lxc = self.exec_cmd("pvesh get /nodes/$(hostname)/lxc --output-format=json 2>/dev/null", timeout=10)
        if lxc and '[' in lxc:
            try:
                import json
                lxc_data = json.loads(lxc)
                for ct in lxc_data:
                    containers.append({
                        "vmid": ct.get("vmid", 0),
                        "name": ct.get("name", ""),
                        "status": ct.get("status", ""),
                        "cpu": ct.get("cpus", 0),
                        "mem_mb": ct.get("maxmem", 0) // (1024 * 1024) if ct.get("maxmem") else 0,
                        "disk_gb": ct.get("maxdisk", 0) // (1024 * 1024 * 1024) if ct.get("maxdisk") else 0,
                        "type": "lxc",
                    })
            except:
                pass
        
        # Fallback: pct list
        if not containers:
            pct = self.exec_cmd("pct list 2>/dev/null | tail -n +2", timeout=5)
            if pct:
                for line in pct.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3 and parts[0].isdigit():
                            containers.append({
                                "vmid": int(parts[0]),
                                "status": parts[1],
                                "name": parts[2] if len(parts) > 2 else "",
                                "type": "lxc",
                            })
        
        return containers
    
    def _get_interfaces(self) -> List[Dict[str, Any]]:
        """Ottiene interfacce di rete"""
        interfaces = []
        
        output = self.exec_cmd("ip addr 2>/dev/null", timeout=5)
        if not output:
            return []
        
        current = {}
        for line in output.split('\n'):
            if line and not line.startswith(' ') and ':' in line:
                if current and current.get("name"):
                    interfaces.append(current)
                parts = line.split(':')
                if len(parts) >= 2:
                    name = parts[1].strip().split()[0]
                    current = {"name": name}
                    if 'state UP' in line:
                        current["status"] = "up"
                    elif 'state DOWN' in line:
                        current["status"] = "down"
            elif 'inet ' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        current["ipv4"] = parts[i + 1].split('/')[0]
            elif 'link/ether' in line and current:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == 'link/ether' and i + 1 < len(parts):
                        current["mac_address"] = parts[i + 1]
        
        if current and current.get("name"):
            interfaces.append(current)
        
        # Filtra loopback
        return [i for i in interfaces if not i["name"].startswith("lo")]
    
    def _get_pve_services(self) -> List[Dict[str, Any]]:
        """Ottiene servizi Proxmox"""
        services = []
        
        pve_services = [
            "pve-cluster", "pvedaemon", "pveproxy", 
            "pvestatd", "pvescheduler", "spiceproxy",
            "corosync", "pve-firewall"
        ]
        
        for svc in pve_services:
            status = self.exec_cmd(f"systemctl is-active {svc} 2>/dev/null", timeout=2)
            if status:
                services.append({
                    "name": svc,
                    "status": status.strip(),
                })
        
        return services
