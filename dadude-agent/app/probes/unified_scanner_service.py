"""
DaDude Agent - Unified Scanner Service
Servizio per scansioni multi-protocollo usando unified_scanner
"""
import asyncio
from typing import Dict, List, Optional, Any
from loguru import logger
from concurrent.futures import ThreadPoolExecutor

from .unified_scanner import (
    UnifiedScanner,
    Protocol,
    ScanResult,
    ScanStatus,
    WindowsCollector,
    LinuxSSHCollector,
    SNMPCollector,
    detect_protocol,
    result_to_dict,
)


_executor = ThreadPoolExecutor(max_workers=5)


class ResultMerger:
    """Classe per merge intelligente di risultati da più protocolli"""
    
    @staticmethod
    def merge_scan_results(results: List[ScanResult]) -> ScanResult:
        """
        Combina risultati da più protocolli eliminando duplicati
        e mantenendo dati più dettagliati
        """
        if not results:
            return ScanResult(target="", scan_status=ScanStatus.FAILED.value)
        
        if len(results) == 1:
            return results[0]
        
        # Prendi il primo risultato come base
        merged = ScanResult(
            target=results[0].target,
            scan_timestamp=results[0].scan_timestamp,
            scanner_host=results[0].scanner_host,
        )
        
        # Combina protocolli usati
        protocols_used = []
        for r in results:
            if r.protocol_used:
                protocols_used.append(r.protocol_used)
        merged.protocol_used = "+".join(set(protocols_used))
        
        # Merge system_info (preferisci dati più dettagliati)
        for r in results:
            if r.system_info:
                si = r.system_info
                if si.hostname and not merged.system_info.hostname:
                    merged.system_info.hostname = si.hostname
                if si.fqdn and not merged.system_info.fqdn:
                    merged.system_info.fqdn = si.fqdn
                if si.domain and not merged.system_info.domain:
                    merged.system_info.domain = si.domain
                if si.device_type and not merged.system_info.device_type:
                    merged.system_info.device_type = si.device_type
                if si.os_name and not merged.system_info.os_name:
                    merged.system_info.os_name = si.os_name
                if si.os_version and not merged.system_info.os_version:
                    merged.system_info.os_version = si.os_version
                if si.manufacturer and not merged.system_info.manufacturer:
                    merged.system_info.manufacturer = si.manufacturer
                if si.model and not merged.system_info.model:
                    merged.system_info.model = si.model
                if si.serial_number and not merged.system_info.serial_number:
                    merged.system_info.serial_number = si.serial_number
                if si.uptime_seconds > merged.system_info.uptime_seconds:
                    merged.system_info.uptime_seconds = si.uptime_seconds
                    merged.system_info.uptime = si.uptime
        
        # Merge CPU (preferisci dati più dettagliati)
        for r in results:
            if r.cpu and r.cpu.model:
                if not merged.cpu.model or len(r.cpu.model) > len(merged.cpu.model):
                    merged.cpu = r.cpu
        
        # Merge Memory (preferisci dati più recenti/dettagliati)
        for r in results:
            if r.memory and r.memory.total_bytes > merged.memory.total_bytes:
                merged.memory = r.memory
        
        # Merge Disks (unisci liste eliminando duplicati per device)
        disk_devices = {}
        for r in results:
            if r.disks:
                for disk in r.disks:
                    if disk.device:
                        if disk.device not in disk_devices:
                            disk_devices[disk.device] = disk
                        elif disk.size_bytes > disk_devices[disk.device].size_bytes:
                            disk_devices[disk.device] = disk
        merged.disks = list(disk_devices.values())
        
        # Merge Volumes (unisci liste eliminando duplicati per mount_point)
        volume_mounts = {}
        for r in results:
            if r.volumes:
                for vol in r.volumes:
                    mount = vol.mount_point or vol.drive_letter
                    if mount:
                        if mount not in volume_mounts:
                            volume_mounts[mount] = vol
                        elif vol.total_bytes > volume_mounts[mount].total_bytes:
                            volume_mounts[mount] = vol
        merged.volumes = list(volume_mounts.values())
        
        # Merge Network Interfaces (unisci liste eliminando duplicati per name)
        interface_names = {}
        for r in results:
            if r.network_interfaces:
                for iface in r.network_interfaces:
                    if iface.name:
                        if iface.name not in interface_names:
                            interface_names[iface.name] = iface
                        else:
                            # Merge dati interfaccia
                            existing = interface_names[iface.name]
                            if iface.ipv4_addresses:
                                existing.ipv4_addresses.extend(iface.ipv4_addresses)
                                existing.ipv4_addresses = list(set(existing.ipv4_addresses))
                            if iface.mac_address and not existing.mac_address:
                                existing.mac_address = iface.mac_address
                            if iface.speed_mbps > existing.speed_mbps:
                                existing.speed_mbps = iface.speed_mbps
        merged.network_interfaces = list(interface_names.values())
        
        # Merge Services (unisci liste eliminando duplicati per name)
        service_names = {}
        for r in results:
            if r.services:
                for svc in r.services:
                    if svc.name:
                        if svc.name not in service_names:
                            service_names[svc.name] = svc
        merged.services = list(service_names.values())
        
        # Merge Software (unisci liste eliminando duplicati per name)
        software_names = {}
        for r in results:
            if r.software:
                for sw in r.software:
                    if sw.name:
                        key = f"{sw.name}_{sw.version}"
                        if key not in software_names:
                            software_names[key] = sw
        merged.software = list(software_names.values())
        
        # Merge Users (unisci liste eliminando duplicati per username)
        user_names = {}
        for r in results:
            if r.users:
                for user in r.users:
                    if user.username:
                        if user.username not in user_names:
                            user_names[user.username] = user
        merged.users = list(user_names.values())
        
        # Merge Shares (unisci liste eliminando duplicati per name)
        share_names = {}
        for r in results:
            if r.shares:
                for share in r.shares:
                    if share.name:
                        if share.name not in share_names:
                            share_names[share.name] = share
        merged.shares = list(share_names.values())
        
        # Merge VMs (unisci liste eliminando duplicati per id)
        vm_ids = {}
        for r in results:
            if r.vms:
                for vm in r.vms:
                    if vm.id:
                        if vm.id not in vm_ids:
                            vm_ids[vm.id] = vm
        merged.vms = list(vm_ids.values())
        
        # Merge LLDP Neighbors (unisci liste)
        lldp_keys = {}
        for r in results:
            if r.lldp_neighbors:
                for neighbor in r.lldp_neighbors:
                    key = f"{neighbor.local_port}_{neighbor.remote_device}"
                    if key not in lldp_keys:
                        lldp_keys[key] = neighbor
        merged.lldp_neighbors = list(lldp_keys.values())
        
        # Merge Errors e Warnings (unisci liste)
        all_errors = set()
        all_warnings = set()
        for r in results:
            if r.errors:
                all_errors.update(r.errors)
            if r.warnings:
                all_warnings.update(r.warnings)
        merged.errors = list(all_errors)
        merged.warnings = list(all_warnings)
        
        # Determina scan_status finale
        if merged.errors and len(merged.errors) > 5:
            merged.scan_status = ScanStatus.FAILED.value
        elif merged.errors:
            merged.scan_status = ScanStatus.PARTIAL.value
        else:
            merged.scan_status = ScanStatus.SUCCESS.value
        
        # Calcola durata totale
        total_duration = sum(r.scan_duration_seconds for r in results if r.scan_duration_seconds)
        merged.scan_duration_seconds = total_duration
        
        return merged


class UnifiedScannerService:
    """Servizio per scansioni multi-protocollo"""
    
    def __init__(self, verbose: bool = False):
        self.scanner = UnifiedScanner(verbose=verbose)
        self.verbose = verbose
    
    async def scan_multi_protocol(
        self,
        target: str,
        protocols: List[str] = None,
        # SSH
        ssh_user: str = None,
        ssh_password: str = None,
        ssh_key: str = None,
        ssh_port: int = 22,
        # WinRM
        winrm_user: str = None,
        winrm_password: str = None,
        winrm_domain: str = "",
        winrm_port: int = 5985,
        winrm_ssl: bool = False,
        # SNMP
        snmp_community: str = 'public',
        snmp_port: int = 161,
        snmp_version: int = 2,
        timeout: int = 30,
    ) -> Dict[str, Any]:
        """
        Scansiona un target con multipli protocolli in parallelo
        
        Args:
            target: IP o hostname
            protocols: Lista protocolli da provare ['ssh', 'snmp', 'winrm'] o None per auto
            ... parametri specifici per protocollo
        
        Returns:
            Dict con risultati combinati e metadati
        """
        loop = asyncio.get_event_loop()
        
        # Determina protocolli se non specificati
        if not protocols or 'auto' in protocols:
            protocols = await self._detect_protocols(target, timeout)
        
        if not protocols:
            return {
                "success": False,
                "error": "Nessun protocollo disponibile per questo target",
                "target": target,
                "protocols_used": [],
            }
        
        # Esegui scansioni in parallelo
        results = []
        protocols_used = []
        
        async def scan_one(protocol_str: str) -> Optional[ScanResult]:
            try:
                protocol = Protocol(protocol_str)
                
                # Prepara parametri per questo protocollo
                if protocol == Protocol.SSH:
                    if not ssh_user:
                        return None
                    # Se ssh_key è una stringa, crea un file temporaneo
                    key_file = None
                    if ssh_key:
                        import tempfile
                        import os
                        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                            f.write(ssh_key)
                            key_file = f.name
                    
                    try:
                        result = await loop.run_in_executor(
                            _executor,
                            lambda: self.scanner.scan(
                                target=target,
                                protocol=protocol,
                                timeout=timeout,
                                ssh_user=ssh_user,
                                ssh_password=ssh_password,
                                ssh_key=key_file,  # Passa file path invece di stringa
                                ssh_port=ssh_port,
                                winrm_user=None,
                                winrm_password=None,
                                winrm_domain="",
                                winrm_port=5985,
                                winrm_ssl=False,
                                snmp_community='public',
                                snmp_port=161,
                                snmp_version=2
                            )
                        )
                        return result
                    finally:
                        # Pulisci file temporaneo
                        if key_file and os.path.exists(key_file):
                            try:
                                os.unlink(key_file)
                            except:
                                pass
                
                elif protocol == Protocol.WINRM:
                    if not winrm_user or not winrm_password:
                        return None
                    return await loop.run_in_executor(
                        _executor,
                        lambda: self.scanner.scan(
                            target=target,
                            protocol=protocol,
                            timeout=timeout,
                            ssh_user=None,
                            ssh_password=None,
                            ssh_key=None,
                            ssh_port=22,
                            winrm_user=winrm_user,
                            winrm_password=winrm_password,
                            winrm_domain=winrm_domain,
                            winrm_port=winrm_port,
                            winrm_ssl=winrm_ssl,
                            snmp_community='public',
                            snmp_port=161,
                            snmp_version=2
                        )
                    )
                
                elif protocol == Protocol.SNMP:
                    return await loop.run_in_executor(
                        _executor,
                        lambda: self.scanner.scan(
                            target=target,
                            protocol=protocol,
                            timeout=timeout,
                            ssh_user=None,
                            ssh_password=None,
                            ssh_key=None,
                            ssh_port=22,
                            winrm_user=None,
                            winrm_password=None,
                            winrm_domain="",
                            winrm_port=5985,
                            winrm_ssl=False,
                            snmp_community=snmp_community,
                            snmp_port=snmp_port,
                            snmp_version=snmp_version
                        )
                    )
                
            except Exception as e:
                logger.error(f"Error scanning {target} with {protocol_str}: {e}", exc_info=True)
                return None
        
        # Esegui tutte le scansioni in parallelo
        tasks = [scan_one(p) for p in protocols]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filtra risultati validi
        for i, result in enumerate(scan_results):
            if isinstance(result, Exception):
                logger.error(f"Scan failed for {protocols[i]}: {result}")
                continue
            if result and result.scan_status != ScanStatus.FAILED.value:
                results.append(result)
                protocols_used.append(protocols[i])
        
        if not results:
            return {
                "success": False,
                "error": "Tutte le scansioni sono fallite",
                "target": target,
                "protocols_used": protocols,
            }
        
        # Merge risultati
        merged_result = ResultMerger.merge_scan_results(results)
        
        # Converti a dict
        result_dict = result_to_dict(merged_result)
        
        return {
            "success": True,
            "target": target,
            "protocols_used": protocols_used,
            "data": result_dict,
        }
    
    async def _detect_protocols(self, target: str, timeout: int = 3) -> List[str]:
        """Rileva protocolli disponibili per un target"""
        protocols = []
        loop = asyncio.get_event_loop()
        
        # Prova WinRM (5985)
        try:
            sock = await loop.run_in_executor(
                _executor,
                lambda: self._check_port(target, 5985, timeout)
            )
            if sock:
                protocols.append("winrm")
                sock.close()
        except:
            pass
        
        # Prova SSH (22)
        try:
            sock = await loop.run_in_executor(
                _executor,
                lambda: self._check_port(target, 22, timeout)
            )
            if sock:
                protocols.append("ssh")
                sock.close()
        except:
            pass
        
        # Prova SNMP (161) - sempre disponibile per network devices
        protocols.append("snmp")
        
        return protocols
    
    def _check_port(self, host: str, port: int, timeout: int) -> Optional[Any]:
        """Verifica se una porta è aperta"""
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return sock
            sock.close()
        except:
            pass
        return None
