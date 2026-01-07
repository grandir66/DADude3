"""
DaDude - Proxmox Collector Service
Raccoglie informazioni complete da host Proxmox: host, VM, storage, backup, network
Integra logica da Proxreporter
"""
from typing import Optional, Dict, Any, List
from loguru import logger
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import re
import subprocess
import os
import urllib.request
import urllib.parse
import urllib.error
import ssl
from http.cookiejar import CookieJar
from datetime import datetime


def bytes_to_gib(value: Any) -> Optional[float]:
    """Converte byte in Gibibyte"""
    try:
        if value is None:
            return None
        return value / (1024 ** 3)
    except Exception:
        return None


def safe_round(value: Any, digits: int = 2) -> Optional[float]:
    """Arrotonda un valore numerico gestendo None"""
    try:
        if value is None:
            return None
        return round(float(value), digits)
    except Exception:
        return None


def seconds_to_human(seconds: Any) -> Optional[str]:
    """Converte secondi in formato leggibile (Xd Yh Zm Ws)"""
    try:
        if seconds is None:
            return None
        seconds = int(seconds)
        if seconds < 0:
            seconds = 0
        from datetime import timedelta
        delta = timedelta(seconds=seconds)
        days = delta.days
        hours, remainder = divmod(delta.seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if secs or not parts:
            parts.append(f"{secs}s")
        return ' '.join(parts)
    except Exception:
        return None


class ProxmoxCollector:
    """Servizio per raccogliere informazioni da Proxmox"""
    
    def __init__(self):
        self._executor = ThreadPoolExecutor(max_workers=3)
    
    async def collect_proxmox_host_info(
        self,
        device_address: str,
        credentials: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Raccoglie informazioni complete host Proxmox
        
        Args:
            device_address: IP dell'host Proxmox
            credentials: Lista credenziali (deve contenere username/password per API)
            
        Returns:
            Dict con informazioni host o None se fallisce
        """
        host_info = None
        
        for cred in credentials:
            cred_type = cred.get('type', '').lower()
            cred_id = cred.get('id', 'unknown')
            
            # Per credenziali SSH, prova prima SSH (più affidabile per Proxmox)
            # Per altre credenziali, prova prima API
            if cred_type == 'ssh':
                # Prova SSH prima
                try:
                    logger.info(f"Trying SSH for Proxmox {device_address} with cred {cred_id} (username: {cred.get('username', 'N/A')})")
                    host_info = await self._collect_host_info_ssh(device_address, cred)
                    if host_info:
                        logger.info(f"✓ Proxmox SSH collection successful for {device_address} with cred {cred_id}")
                        break
                    else:
                        logger.warning(f"Proxmox SSH returned None for {device_address} with cred {cred_id}")
                except Exception as e:
                    logger.warning(f"✗ Proxmox SSH failed for {device_address} with cred {cred_id}: {e}")
                
                # Fallback a API con credenziali SSH (solo se SSH fallisce)
                if not host_info:
                    try:
                        logger.info(f"Trying API (fallback) for Proxmox {device_address} with cred {cred_id}")
                        host_info = await self._collect_host_info_api(device_address, cred)
                        if host_info:
                            logger.info(f"✓ Proxmox API collection successful for {device_address} with cred {cred_id}")
                            break
                    except Exception as e:
                        logger.warning(f"✗ Proxmox API failed for {device_address} with cred {cred_id}: {e}")
            else:
                # Prova API prima per credenziali non-SSH
                try:
                    logger.debug(f"Trying API for Proxmox {device_address} with cred {cred_id}")
                    host_info = await self._collect_host_info_api(device_address, cred)
                    if host_info:
                        logger.info(f"Proxmox API collection successful for {device_address} with cred {cred_id}")
                        break
                except Exception as e:
                    logger.debug(f"Proxmox API failed for {device_address} with cred {cred_id}: {e}")
                
                # Fallback a SSH se disponibile
                if cred.get('username') and cred.get('password'):
                    try:
                        logger.debug(f"Trying SSH (fallback) for Proxmox {device_address} with cred {cred_id}")
                        host_info = await self._collect_host_info_ssh(device_address, cred)
                        if host_info:
                            logger.info(f"Proxmox SSH collection successful for {device_address} with cred {cred_id}")
                            break
                    except Exception as e:
                        logger.debug(f"Proxmox SSH failed for {device_address} with cred {cred_id}: {e}")
        
        if host_info:
            logger.info(f"Proxmox host info collected for {device_address}")
        else:
            logger.warning(f"Proxmox host info collection failed for {device_address} - no valid credentials or connection failed")
        
        return host_info
    
    async def collect_proxmox_vms(
        self,
        device_address: str,
        node_name: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie lista VM da host Proxmox
        
        Args:
            device_address: IP dell'host Proxmox
            node_name: Nome del nodo Proxmox
            credentials: Lista credenziali
            
        Returns:
            Lista di VM trovate
        """
        vms = []
        
        for cred in credentials:
            # Prova API
            api_success = False
            try:
                vms = await self._collect_vms_api(device_address, node_name, cred)
                if vms:
                    api_success = True
                    break
            except Exception as e:
                logger.warning(f"Proxmox API VM collection failed for {device_address}: {e}")
                # Continua a provare SSH anche se API fallisce
            
            # Fallback a SSH se API non ha funzionato
            if not api_success:
                try:
                    logger.info(f"Trying SSH fallback for VM collection on {device_address}")
                    vms = await self._collect_vms_ssh(device_address, node_name, cred)
                    if vms:
                        break
                except Exception as e:
                    logger.warning(f"Proxmox SSH VM collection failed for {device_address}: {e}")
                    continue
        
        logger.info(f"Proxmox VMs collected for {device_address}: {len(vms)} found")
        return vms
    
    async def collect_proxmox_storage(
        self,
        device_address: str,
        node_name: str,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie informazioni storage da host Proxmox
        
        Args:
            device_address: IP dell'host Proxmox
            node_name: Nome del nodo Proxmox
            credentials: Lista credenziali
            
        Returns:
            Lista di storage trovati
        """
        storage_list = []
        
        for cred in credentials:
            # Prova API
            api_success = False
            try:
                storage_list = await self._collect_storage_api(device_address, node_name, cred)
                if storage_list:
                    api_success = True
                    break
            except Exception as e:
                logger.warning(f"Proxmox API storage collection failed for {device_address}: {e}")
                # Continua a provare SSH anche se API fallisce
            
            # Fallback a SSH se API non ha funzionato
            if not api_success:
                try:
                    logger.info(f"Trying SSH fallback for storage collection on {device_address}")
                    storage_list = await self._collect_storage_ssh(device_address, node_name, cred)
                    if storage_list:
                        break
                except Exception as e:
                    logger.warning(f"Proxmox SSH storage collection failed for {device_address}: {e}")
                    continue
        
        logger.info(f"Proxmox storage collected for {device_address}: {len(storage_list)} found")
        return storage_list
    
    async def collect_proxmox_backups(
        self,
        device_address: str,
        node_name: str,
        vm_id: int,
        credentials: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie informazioni backup per una VM
        
        Args:
            device_address: IP dell'host Proxmox
            node_name: Nome del nodo Proxmox
            vm_id: ID della VM
            credentials: Lista credenziali
            
        Returns:
            Lista di backup trovati
        """
        backups = []
        
        for cred in credentials:
            try:
                backups = await self._collect_backups_api(device_address, node_name, vm_id, cred)
                if backups:
                    break
            except Exception as e:
                logger.debug(f"Proxmox backup collection failed: {e}")
                continue
        
        logger.info(f"Proxmox backups collected for VM {vm_id}: {len(backups)} found")
        return backups
    
    # ==========================================
    # API IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_host_info_api(
        self,
        address: str,
        credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Raccoglie info host via API Proxmox"""
        try:
            loop = asyncio.get_event_loop()
            host_info = await loop.run_in_executor(
                self._executor,
                self._get_host_info_api_sync,
                address,
                credentials
            )
            return host_info
        except Exception as e:
            logger.error(f"Error collecting host info via API: {e}")
            return None
    
    def _get_host_info_api_sync(
        self,
        address: str,
        credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Implementazione sincrona per API Proxmox"""
        try:
            port = credentials.get("proxmox_port", 8006)
            username = credentials.get("username", "root@pam")
            password = credentials.get("password", "")
            
            base_url = f"https://{address}:{port}/api2/json"
            ssl_context = ssl._create_unverified_context()
            auth_url = f"{base_url}/access/ticket"
            
            data = urllib.parse.urlencode({
                'username': username,
                'password': password
            }).encode('utf-8')
            
            cookie_jar = CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar),
                urllib.request.HTTPSHandler(context=ssl_context)
            )
            
            request = urllib.request.Request(auth_url, data=data, method='POST')
            response = opener.open(request, timeout=10)
            result = json.loads(response.read().decode('utf-8'))['data']
            ticket = result['ticket']
            csrf_token = result['CSRFPreventionToken']
            
            def api_get(endpoint):
                url = f"{base_url}/{endpoint}"
                req = urllib.request.Request(url)
                req.add_header('Cookie', f'PVEAuthCookie={ticket}')
                req.add_header('CSRFPreventionToken', csrf_token)
                resp = opener.open(req, timeout=10)
                return json.loads(resp.read().decode('utf-8'))['data']
            
            # Ottieni nodi
            nodes = api_get('nodes')
            if not nodes:
                return None
            
            node_name = nodes[0].get('node')
            if not node_name:
                return None
            
            # Status nodo
            node_status = api_get(f'nodes/{node_name}/status')
            if not node_status:
                return None
            
            host_info = {
                'node_name': node_name,
                'hostname': node_name,
                'status': node_status.get('status'),
                'uptime_seconds': int(node_status.get('uptime', 0)),
                'uptime_human': seconds_to_human(node_status.get('uptime')),
                'cpu_usage_percent': safe_round(float(node_status.get('cpu', 0)) * 100, 2),
                'io_delay_percent': safe_round(node_status.get('io_delay'), 2),
            }
            
            # Load average
            loadavg = node_status.get('loadavg')
            if isinstance(loadavg, (list, tuple)) and len(loadavg) >= 3:
                host_info['load_average_1m'] = safe_round(float(loadavg[0]), 2)
                host_info['load_average_5m'] = safe_round(float(loadavg[1]), 2)
                host_info['load_average_15m'] = safe_round(float(loadavg[2]), 2)
            
            # CPU info
            cpuinfo = node_status.get('cpuinfo', {})
            host_info['cpu_model'] = cpuinfo.get('model')
            host_info['cpu_cores'] = cpuinfo.get('cores')
            host_info['cpu_sockets'] = cpuinfo.get('sockets')
            host_info['cpu_threads'] = cpuinfo.get('cpus')
            host_info['cpu_total_cores'] = cpuinfo.get('cpus') or cpuinfo.get('cores')
            
            # Memory
            memory_info = node_status.get('memory', {})
            mem_total = memory_info.get('total')
            mem_used = memory_info.get('used')
            mem_free = memory_info.get('free')
            if mem_total is not None:
                host_info['memory_total_gb'] = bytes_to_gib(mem_total)
            if mem_used is not None:
                host_info['memory_used_gb'] = bytes_to_gib(mem_used)
            if mem_free is not None:
                host_info['memory_free_gb'] = bytes_to_gib(mem_free)
            if mem_total and mem_used is not None:
                host_info['memory_usage_percent'] = safe_round((mem_used / mem_total) * 100, 2)
            
            # Versione
            try:
                version_info = api_get(f'nodes/{node_name}/version')
                if version_info:
                    manager_version = version_info.get('version', '')
                    if manager_version:
                        host_info['proxmox_version'] = manager_version
                    kernel_version = version_info.get('kernel') or version_info.get('running_kernel') or version_info.get('release')
                    if kernel_version:
                        host_info['kernel_version'] = kernel_version.strip()
            except:
                pass
            
            # Subscription
            try:
                subscription_info = api_get(f'nodes/{node_name}/subscription')
                if isinstance(subscription_info, dict):
                    host_info['license_status'] = subscription_info.get('status')
                    host_info['license_message'] = subscription_info.get('message')
                    host_info['license_level'] = subscription_info.get('level')
                    host_info['subscription_type'] = subscription_info.get('type')
                    host_info['subscription_key'] = subscription_info.get('key')
            except:
                pass
            
            # Storage
            try:
                storage_list = api_get(f'nodes/{node_name}/storage')
                host_info['storage_list'] = []
                for storage in storage_list:
                    storage_info = {
                        'storage': storage.get('storage'),
                        'type': storage.get('type'),
                        'content': storage.get('content'),
                    }
                    try:
                        storage_status = api_get(f'nodes/{node_name}/storage/{storage_info["storage"]}/status')
                        if storage_status:
                            storage_info['total'] = storage_status.get('total')
                            storage_info['used'] = storage_status.get('used')
                            storage_info['available'] = storage_status.get('avail')
                    except:
                        pass
                    host_info['storage_list'].append(storage_info)
            except:
                host_info['storage_list'] = []
            
            # Network
            try:
                network_data = api_get(f'nodes/{node_name}/network')
                host_info['network_interfaces'] = network_data or []
            except:
                host_info['network_interfaces'] = []
            
            return host_info
            
        except Exception as e:
            logger.error(f"Error in API sync collection: {e}")
            return None
    
    async def _collect_vms_api(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Raccoglie VM via API Proxmox"""
        try:
            loop = asyncio.get_event_loop()
            vms = await loop.run_in_executor(
                self._executor,
                self._get_vms_api_sync,
                address,
                node_name,
                credentials
            )
            return vms or []
        except Exception as e:
            logger.error(f"Error collecting VMs via API: {e}")
            return []
    
    def _get_vms_api_sync(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Implementazione sincrona per raccolta VM via API"""
        try:
            port = credentials.get("proxmox_port", 8006)
            username = credentials.get("username", "root@pam")
            password = credentials.get("password", "")
            
            base_url = f"https://{address}:{port}/api2/json"
            ssl_context = ssl._create_unverified_context()
            auth_url = f"{base_url}/access/ticket"
            
            data = urllib.parse.urlencode({
                'username': username,
                'password': password
            }).encode('utf-8')
            
            cookie_jar = CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar),
                urllib.request.HTTPSHandler(context=ssl_context)
            )
            
            request = urllib.request.Request(auth_url, data=data, method='POST')
            response = opener.open(request, timeout=10)
            result = json.loads(response.read().decode('utf-8'))['data']
            ticket = result['ticket']
            csrf_token = result['CSRFPreventionToken']
            
            def api_get(endpoint):
                url = f"{base_url}/{endpoint}"
                req = urllib.request.Request(url)
                req.add_header('Cookie', f'PVEAuthCookie={ticket}')
                req.add_header('CSRFPreventionToken', csrf_token)
                resp = opener.open(req, timeout=10)
                return json.loads(resp.read().decode('utf-8'))['data']
            
            # Ottieni VM QEMU
            node_vms = api_get(f'nodes/{node_name}/qemu')
            vms = []
            
            for vm in node_vms:
                vmid = vm.get('vmid', 0)
                status = vm.get('status', 'unknown')
                
                vm_data = {
                    'vm_id': vmid,
                    'name': vm.get('name', f'VM-{vmid}'),
                    'status': status,
                    'type': 'qemu',
                    'cpu_cores': vm.get('maxcpu', 0),
                    'memory_mb': int(vm.get('maxmem', 0) / (1024 * 1024)) if vm.get('maxmem') else 0,
                    'disk_total_gb': bytes_to_gib(vm.get('maxdisk', 0)),
                    'template': vm.get('template', False),
                }
                
                # Configurazione VM
                try:
                    config = api_get(f'nodes/{node_name}/qemu/{vmid}/config')
                    if config:
                        vm_data['cpu_cores'] = int(config.get('cores', 1))
                        vm_data['os_type'] = config.get('ostype', '')
                        
                        # Network interfaces
                        networks = []
                        for key in config:
                            if key.startswith('net'):
                                net_info = config[key]
                                if isinstance(net_info, str):
                                    networks.append(net_info)
                        vm_data['network_interfaces'] = networks
                except:
                    pass
                
                vms.append(vm_data)
            
            # Ottieni container LXC
            try:
                node_lxcs = api_get(f'nodes/{node_name}/lxc')
                for lxc in node_lxcs:
                    vmid = lxc.get('vmid', 0)
                    status = lxc.get('status', 'unknown')
                    
                    lxc_data = {
                        'vm_id': vmid,
                        'name': lxc.get('name', f'LXC-{vmid}'),
                        'status': status,
                        'type': 'lxc',
                        'cpu_cores': lxc.get('maxcpu', 0),
                        'memory_mb': int(lxc.get('maxmem', 0) / (1024 * 1024)) if lxc.get('maxmem') else 0,
                        'disk_total_gb': bytes_to_gib(lxc.get('maxdisk', 0)),
                        'template': lxc.get('template', False),
                    }
                    
                    # Configurazione LXC
                    try:
                        config = api_get(f'nodes/{node_name}/lxc/{vmid}/config')
                        if config:
                            lxc_data['cpu_cores'] = int(config.get('cores', 1))
                            lxc_data['os_type'] = config.get('ostype', '')
                            
                            # Network interfaces
                            networks = []
                            for key in config:
                                if key.startswith('net'):
                                    net_info = config[key]
                                    if isinstance(net_info, str):
                                        networks.append(net_info)
                            lxc_data['network_interfaces'] = networks
                    except:
                        pass
                    
                    vms.append(lxc_data)
            except Exception as e:
                logger.debug(f"Failed to collect LXC containers: {e}")
            
            return vms
            
        except Exception as e:
            logger.error(f"Error in VM API sync collection: {e}")
            return []
    
    async def _collect_storage_api(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Raccoglie storage via API Proxmox"""
        try:
            loop = asyncio.get_event_loop()
            storage_list = await loop.run_in_executor(
                self._executor,
                self._get_storage_api_sync,
                address,
                node_name,
                credentials
            )
            return storage_list or []
        except Exception as e:
            logger.error(f"Error collecting storage via API: {e}")
            return []
    
    def _get_storage_api_sync(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Implementazione sincrona per raccolta storage"""
        try:
            port = credentials.get("proxmox_port", 8006)
            username = credentials.get("username", "root@pam")
            password = credentials.get("password", "")
            
            base_url = f"https://{address}:{port}/api2/json"
            ssl_context = ssl._create_unverified_context()
            auth_url = f"{base_url}/access/ticket"
            
            data = urllib.parse.urlencode({
                'username': username,
                'password': password
            }).encode('utf-8')
            
            cookie_jar = CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar),
                urllib.request.HTTPSHandler(context=ssl_context)
            )
            
            request = urllib.request.Request(auth_url, data=data, method='POST')
            response = opener.open(request, timeout=10)
            result = json.loads(response.read().decode('utf-8'))['data']
            ticket = result['ticket']
            csrf_token = result['CSRFPreventionToken']
            
            def api_get(endpoint):
                url = f"{base_url}/{endpoint}"
                req = urllib.request.Request(url)
                req.add_header('Cookie', f'PVEAuthCookie={ticket}')
                req.add_header('CSRFPreventionToken', csrf_token)
                resp = opener.open(req, timeout=10)
                return json.loads(resp.read().decode('utf-8'))['data']
            
            # Ottieni lista storage
            storage_list = api_get(f'nodes/{node_name}/storage')
            storage_info_list = []
            
            for storage in storage_list:
                storage_info = {
                    'storage': storage.get('storage'),
                    'type': storage.get('type'),
                    'content': storage.get('content', []),
                    'enabled': storage.get('enabled', 1),
                    'shared': storage.get('shared', 0),
                }
                
                # Ottieni dettagli storage
                try:
                    storage_status = api_get(f'nodes/{node_name}/storage/{storage_info["storage"]}/status')
                    if storage_status:
                        storage_info['total'] = storage_status.get('total')
                        storage_info['used'] = storage_status.get('used')
                        storage_info['available'] = storage_status.get('avail')
                        storage_info['total_gb'] = bytes_to_gib(storage_status.get('total'))
                        storage_info['used_gb'] = bytes_to_gib(storage_status.get('used'))
                        storage_info['available_gb'] = bytes_to_gib(storage_status.get('avail'))
                        if storage_info['total'] and storage_info['used']:
                            storage_info['usage_percent'] = safe_round(
                                (storage_info['used'] / storage_info['total']) * 100, 2
                            )
                except Exception as e:
                    logger.debug(f"Failed to get storage status for {storage_info['storage']}: {e}")
                
                storage_info_list.append(storage_info)
            
            return storage_info_list
            
        except Exception as e:
            logger.error(f"Error in storage API sync collection: {e}")
            return []
    
    async def _collect_backups_api(
        self,
        address: str,
        node_name: str,
        vm_id: int,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Raccoglie backup via API Proxmox"""
        # Implementazione semplificata
        return []
    
    # ==========================================
    # SSH IMPLEMENTATIONS
    # ==========================================
    
    async def _collect_host_info_ssh(
        self,
        address: str,
        credentials: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Raccoglie info host via SSH usando comandi pvesh"""
        import paramiko
        
        username = credentials.get('username')
        password = credentials.get('password')
        ssh_port = credentials.get('ssh_port', 22)
        ssh_key = credentials.get('ssh_private_key')
        
        if not username or not password:
            logger.warning(f"SSH credentials incomplete for {address}: missing username or password")
            return None
        
        try:
            # Connetti via SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Usa chiave privata se disponibile
            pkey = None
            if ssh_key:
                try:
                    from io import StringIO
                    pkey = paramiko.RSAKey.from_private_key(StringIO(ssh_key))
                except Exception as e:
                    logger.debug(f"Failed to load SSH key, using password: {e}")
            
            logger.info(f"Connecting to Proxmox {address}:{ssh_port} via SSH (user: {username})")
            client.connect(
                address,
                port=ssh_port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=30
            )
            
            def exec_cmd(cmd: str) -> Optional[str]:
                """Esegue comando SSH"""
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        return stdout.read().decode('utf-8').strip()
                    else:
                        error = stderr.read().decode('utf-8').strip()
                        logger.debug(f"Command failed: {cmd[:50]}... (exit: {exit_status}, error: {error})")
                        return None
                except Exception as e:
                    logger.debug(f"Error executing command {cmd[:50]}...: {e}")
                    return None
            
            # Ottieni nome nodo
            hostname = exec_cmd('hostname') or 'unknown'
            
            # Ottieni info nodo via pvesh
            node_info_cmd = f'pvesh get /nodes/{hostname}/status --output-format json'
            node_info_json = exec_cmd(node_info_cmd)
            
            if not node_info_json:
                logger.warning(f"Failed to get node info via pvesh for {address}")
                client.close()
                return None
            
            import json
            node_data = json.loads(node_info_json)
            
            # Ottieni versione Proxmox
            version_cmd = f'pvesh get /version --output-format json'
            version_json = exec_cmd(version_cmd)
            version_data = json.loads(version_json) if version_json else {}
            
            # Ottieni info CPU/memoria
            cpuinfo = exec_cmd('lscpu')
            meminfo = exec_cmd('grep MemTotal /proc/meminfo')
            
            # Parse CPU info
            cpu_model = None
            cpu_cores = None
            cpu_sockets = None
            cpu_threads = None
            if cpuinfo:
                for line in cpuinfo.split('\n'):
                    if 'Model name:' in line:
                        cpu_model = line.split(':', 1)[1].strip()
                    elif 'CPU(s):' in line:
                        try:
                            cpu_val = line.split(':')[1].strip()
                            # Gestisci formati come "0-31" (range) prendendo solo il primo numero
                            if '-' in cpu_val:
                                cpu_val = cpu_val.split('-')[0]
                            cpu_cores = int(cpu_val)
                        except (ValueError, IndexError):
                            pass
                    elif 'Socket(s):' in line:
                        try:
                            cpu_sockets = int(line.split(':')[1].strip())
                        except (ValueError, IndexError):
                            pass
                    elif 'Thread(s) per core:' in line:
                        try:
                            cpu_threads = int(line.split(':')[1].strip())
                        except (ValueError, IndexError):
                            pass
            
            # Parse memoria
            memory_total_gb = None
            if meminfo:
                try:
                    mem_kb = int(meminfo.split()[1])
                    memory_total_gb = round(mem_kb / 1024 / 1024, 2)
                except:
                    pass
            
            # Calcola CPU totale
            cpu_total_cores = cpu_cores
            
            # Ottieni uptime
            uptime_seconds = node_data.get('uptime', 0)
            uptime_human = seconds_to_human(uptime_seconds)
            
            # Ottieni load average
            load_avg = node_data.get('loadavg', [0, 0, 0])
            load_1m = load_avg[0] if len(load_avg) > 0 else None
            load_5m = load_avg[1] if len(load_avg) > 1 else None
            load_15m = load_avg[2] if len(load_avg) > 2 else None
            
            # Ottieni CPU usage
            cpu_usage = node_data.get('cpu', 0)
            
            # Ottieni memoria
            memory_used_gb = None
            memory_free_gb = None
            memory_usage_percent = None
            if memory_total_gb:
                mem_used = node_data.get('mem', 0) / (1024**3)  # Converti byte a GB
                memory_used_gb = round(mem_used, 2)
                memory_free_gb = round(memory_total_gb - mem_used, 2)
                memory_usage_percent = round((mem_used / memory_total_gb) * 100, 2) if memory_total_gb > 0 else None
            
            # Ottieni kernel version
            kernel_version = exec_cmd('uname -r')
            
            # Ottieni versione Proxmox
            proxmox_version = version_data.get('version', '')
            manager_version = version_data.get('release', '')
            
            # Ottieni info cluster
            cluster_name = None
            try:
                cluster_cmd = f'pvesh get /cluster/config --output-format json'
                cluster_json = exec_cmd(cluster_cmd)
                if cluster_json:
                    cluster_data = json.loads(cluster_json)
                    cluster_name = cluster_data.get('cluster', {}).get('name') if isinstance(cluster_data.get('cluster'), dict) else None
            except:
                pass
            
            # Ottieni subscription/license info (dettagliata come Proxreporter)
            license_status = None
            license_message = None
            license_level = None
            subscription_type = None
            subscription_key = None
            subscription_server_id = None
            subscription_sockets = None
            subscription_last_check = None
            subscription_next_due = None
            try:
                sub_cmd = f'pvesh get /nodes/{hostname}/subscription --output-format json'
                sub_json = exec_cmd(sub_cmd)
                if sub_json:
                    sub_data = json.loads(sub_json)
                    license_status = sub_data.get('status')
                    license_message = sub_data.get('message')
                    license_level = sub_data.get('level')
                    subscription_type = sub_data.get('productname') or sub_data.get('type')
                    subscription_key = sub_data.get('key')
                    subscription_server_id = sub_data.get('serverid')
                    subscription_sockets = sub_data.get('sockets')
                    checktime = sub_data.get('checktime') or sub_data.get('lastcheck')
                    if checktime:
                        try:
                            from datetime import datetime
                            if isinstance(checktime, (int, float)):
                                subscription_last_check = datetime.fromtimestamp(checktime).isoformat()
                            else:
                                subscription_last_check = str(checktime)
                        except:
                            subscription_last_check = str(checktime)
                    next_due = sub_data.get('nextduedate') or sub_data.get('nextdue')
                    if next_due:
                        subscription_next_due = str(next_due)
            except:
                pass
            
            # Prova anche con pvesubscription get per campi aggiuntivi
            try:
                sub_output = exec_cmd('pvesubscription get 2>/dev/null')
                if sub_output:
                    sub_data = {}
                    for line in sub_output.splitlines():
                        line = line.strip()
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip().lower().replace(' ', '_')
                            value = value.strip()
                            sub_data[key] = value
                    
                    if not license_status and sub_data.get('status'):
                        license_status = sub_data['status']
                    if not subscription_key and sub_data.get('key'):
                        subscription_key = sub_data['key']
                    if not license_level and sub_data.get('level'):
                        license_level = sub_data['level']
                    if not subscription_type and sub_data.get('productname'):
                        subscription_type = sub_data['productname']
                    if not subscription_next_due and sub_data.get('nextduedate'):
                        subscription_next_due = sub_data['nextduedate']
                    if not subscription_server_id and sub_data.get('serverid'):
                        subscription_server_id = sub_data['serverid']
                    if not subscription_sockets and sub_data.get('sockets'):
                        subscription_sockets = sub_data['sockets']
            except:
                pass
            
            # Ottieni IO delay
            io_delay_percent = node_data.get('io_delay')
            if io_delay_percent is not None:
                try:
                    io_delay_percent = round(float(io_delay_percent), 2)
                except:
                    io_delay_percent = None
            
            # Ottieni swap info da /proc/meminfo
            swap_total_gb = None
            swap_used_gb = None
            swap_free_gb = None
            swap_usage_percent = None
            try:
                meminfo_full = exec_cmd('cat /proc/meminfo')
                if meminfo_full:
                    import re
                    swap_total_match = re.search(r'SwapTotal:\s+(\d+)', meminfo_full)
                    swap_free_match = re.search(r'SwapFree:\s+(\d+)', meminfo_full)
                    if swap_total_match:
                        swap_total_kb = int(swap_total_match.group(1))
                        swap_total_gb = round(swap_total_kb / 1024 / 1024, 2)
                    if swap_free_match:
                        swap_free_kb = int(swap_free_match.group(1))
                        swap_free_gb = round(swap_free_kb / 1024 / 1024, 2)
                        if swap_total_gb:
                            swap_used_gb = round(swap_total_gb - swap_free_gb, 2)
                            if swap_total_gb > 0:
                                swap_usage_percent = round((swap_used_gb / swap_total_gb) * 100, 2)
            except:
                pass
            
            # Ottieni rootfs info
            rootfs_total_gb = None
            rootfs_used_gb = None
            rootfs_free_gb = None
            rootfs_usage_percent = None
            try:
                rootfs_output = exec_cmd('df -B1 / 2>/dev/null | tail -1')
                if rootfs_output:
                    parts = rootfs_output.split()
                    if len(parts) >= 5:
                        total = float(parts[1])
                        used = float(parts[2])
                        free = float(parts[3])
                        rootfs_total_gb = round(total / (1024 ** 3), 2)
                        rootfs_used_gb = round(used / (1024 ** 3), 2)
                        rootfs_free_gb = round(free / (1024 ** 3), 2)
                        if total > 0:
                            rootfs_usage_percent = round((used / total) * 100, 2)
            except:
                pass
            
            # Ottieni KSM sharing
            ksm_sharing_gb = None
            try:
                ksm_output = exec_cmd('cat /sys/kernel/mm/ksm/pages_sharing 2>/dev/null')
                if ksm_output:
                    pages = int(ksm_output.strip())
                    ksm_sharing_gb = round((pages * 4096) / (1024 ** 3), 2)
            except:
                pass
            
            # Ottieni repository status
            repository_status = None
            try:
                repos_cmd = f'pvesh get /nodes/{hostname}/apt/repositories --output-format json'
                repos_json = exec_cmd(repos_cmd)
                if repos_json:
                    repos_data = json.loads(repos_json)
                    repositories = []
                    if isinstance(repos_data, dict):
                        repositories = repos_data.get('repositories') or repos_data.get('data') or []
                    elif isinstance(repos_data, list):
                        repositories = repos_data
                    
                    repo_entries = []
                    for repo in repositories:
                        if not isinstance(repo, dict):
                            continue
                        name = repo.get('name') or repo.get('handle') or repo.get('description') or 'repository'
                        enabled = repo.get('enabled')
                        status = repo.get('status')
                        entry = name
                        if enabled is not None:
                            entry += f" [{'enabled' if enabled else 'disabled'}]"
                        if status:
                            entry += f" - {status}"
                        repo_entries.append(entry)
                    if repo_entries:
                        repository_status = '; '.join(repo_entries)
            except:
                pass
            
            # Ottieni boot mode
            boot_mode = None
            try:
                boot_mode_output = exec_cmd('[ -d /sys/firmware/efi ] && echo EFI || echo BIOS')
                if boot_mode_output:
                    boot_mode = boot_mode_output.strip()
                    secure_output = exec_cmd('mokutil --sb-state 2>/dev/null')
                    if secure_output and 'enabled' in secure_output.lower():
                        boot_mode += ' (Secure Boot)'
                    elif secure_output and 'disabled' in secure_output.lower():
                        boot_mode += ' (Secure Boot disabled)'
            except:
                pass
            
            # Ottieni network interfaces dettagliate
            network_interfaces = []
            try:
                network_cmd = f'pvesh get /nodes/{hostname}/network --output-format json'
                network_json = exec_cmd(network_cmd)
                if network_json:
                    network_data = json.loads(network_json)
                    if isinstance(network_data, list):
                        network_interfaces = network_data
            except:
                pass
            
            # Ottieni lista storage (solo base, dettagli vengono raccolti separatamente)
            storage_list = []
            try:
                storage_cmd = f'pvesh get /nodes/{hostname}/storage --output-format json'
                storage_json = exec_cmd(storage_cmd)
                if storage_json:
                    storage_data = json.loads(storage_json)
                    if isinstance(storage_data, list):
                        for storage in storage_data:
                            storage_list.append({
                                'storage': storage.get('storage'),
                                'type': storage.get('type'),
                                'content': storage.get('content', []),
                            })
            except:
                pass
            
            # Raccogli temperature readings
            temperature_summary = None
            temperature_highest_c = None
            try:
                sensors_json = exec_cmd('sensors -Aj 2>/dev/null')
                if sensors_json:
                    try:
                        sensors_data = json.loads(sensors_json)
                        readings = []
                        highest = None
                        for chip_name, chip_data in sensors_data.items():
                            if not isinstance(chip_data, dict):
                                continue
                            adapter = chip_data.get("Adapter") or chip_data.get("adapter")
                            for sensor_name, sensor_values in chip_data.items():
                                if not isinstance(sensor_values, dict):
                                    continue
                                for key, value in sensor_values.items():
                                    if not key.endswith("_input"):
                                        continue
                                    try:
                                        temp_val = float(value)
                                        chip = chip_name
                                        sensor = sensor_name
                                        label = f"{sensor}"
                                        if chip and chip != sensor:
                                            label = f"{chip} - {sensor}"
                                        if adapter:
                                            label = f"{label} [{adapter}]"
                                        label = f"{label}: {temp_val:.1f}°C"
                                        readings.append(label)
                                        highest = temp_val if highest is None else max(highest, temp_val)
                                    except (ValueError, TypeError):
                                        continue
                        if readings:
                            temperature_summary = readings[:20]  # Limita a 20
                            temperature_highest_c = round(highest, 1) if highest else None
                    except (json.JSONDecodeError, TypeError):
                        pass
            except:
                pass
            
            # Raccogli BIOS info
            bios_vendor = None
            bios_version = None
            bios_release_date = None
            system_manufacturer = None
            system_product = None
            system_serial = None
            board_vendor = None
            board_name = None
            try:
                sys_paths = {
                    'bios_vendor': '/sys/class/dmi/id/bios_vendor',
                    'bios_version': '/sys/class/dmi/id/bios_version',
                    'bios_release_date': '/sys/class/dmi/id/bios_date',
                    'system_manufacturer': '/sys/class/dmi/id/sys_vendor',
                    'system_product': '/sys/class/dmi/id/product_name',
                    'system_serial': '/sys/class/dmi/id/product_serial',
                    'board_vendor': '/sys/class/dmi/id/board_vendor',
                    'board_name': '/sys/class/dmi/id/board_name',
                }
                for key, path in sys_paths.items():
                    try:
                        value = exec_cmd(f'cat {path} 2>/dev/null')
                        if value:
                            value = value.strip()
                            if key == 'bios_vendor':
                                bios_vendor = value
                            elif key == 'bios_version':
                                bios_version = value
                            elif key == 'bios_release_date':
                                bios_release_date = value
                            elif key == 'system_manufacturer':
                                system_manufacturer = value
                            elif key == 'system_product':
                                system_product = value
                            elif key == 'system_serial':
                                system_serial = value
                            elif key == 'board_vendor':
                                board_vendor = value
                            elif key == 'board_name':
                                board_name = value
                    except:
                        continue
                
                # Fallback a dmidecode se necessario
                if not bios_vendor or not bios_version:
                    try:
                        dmidecode_output = exec_cmd('dmidecode -t bios 2>/dev/null')
                        if dmidecode_output:
                            import re
                            vendor_match = re.search(r'Vendor:\s*(.+)', dmidecode_output)
                            version_match = re.search(r'Version:\s*(.+)', dmidecode_output)
                            date_match = re.search(r'Release Date:\s*(.+)', dmidecode_output)
                            if vendor_match and not bios_vendor:
                                bios_vendor = vendor_match.group(1).strip()
                            if version_match and not bios_version:
                                bios_version = version_match.group(1).strip()
                            if date_match and not bios_release_date:
                                bios_release_date = date_match.group(1).strip()
                    except:
                        pass
            except:
                pass
            
            # Raccogli boot devices
            boot_devices = None
            boot_devices_details = None
            boot_entries = None
            try:
                lsblk_output = exec_cmd('lsblk --json -o NAME,TYPE,SIZE,MOUNTPOINT,MODEL,SERIAL,FSTYPE,TRAN,ROTA,RM,PARTFLAGS 2>/dev/null')
                if lsblk_output:
                    try:
                        lsblk_data = json.loads(lsblk_output)
                        devices = []
                        summaries = []
                        
                        def visit(nodes, parent_name=None):
                            for node in nodes or []:
                                name = node.get('name')
                                dev_type = node.get('type')
                                size = node.get('size')
                                model = node.get('model')
                                serial = node.get('serial')
                                mountpoint = node.get('mountpoint')
                                fstype = node.get('fstype')
                                transport = node.get('tran')
                                rotational = node.get('rota')
                                removable = node.get('rm')
                                partflags = node.get('partflags')
                                
                                entry = {
                                    'name': name,
                                    'type': dev_type,
                                    'size': size,
                                    'model': model,
                                    'serial': serial,
                                    'mountpoint': mountpoint,
                                    'fstype': fstype,
                                    'transport': transport,
                                    'rotational': rotational,
                                    'removable': removable,
                                    'parent': parent_name,
                                    'partflags': partflags,
                                }
                                
                                flags = str(partflags or '').lower()
                                entry['is_boot'] = bool(flags and any(flag in flags for flag in ('boot', 'esp', 'legacy_boot', 'bios_grub')))
                                
                                devices.append(entry)
                                
                                # Crea summary
                                boot_flag = ' (boot)' if entry['is_boot'] else ''
                                summary_parts = [name, dev_type, size]
                                if model:
                                    summary_parts.append(model)
                                if serial:
                                    summary_parts.append(serial)
                                if mountpoint:
                                    summary_parts.append(f'mnt:{mountpoint}')
                                summaries.append(' | '.join(part for part in summary_parts if part) + boot_flag)
                                
                                children = node.get('children') or node.get('children'.upper())
                                if children:
                                    visit(children, name)
                        
                        visit(lsblk_data.get('blockdevices'))
                        if devices:
                            boot_devices_details = devices
                            boot_devices = summaries[:20]  # Limita a 20
                    except (json.JSONDecodeError, TypeError):
                        pass
                
                # Raccogli boot entries EFI
                try:
                    efiboot_output = exec_cmd('efibootmgr -v 2>/dev/null')
                    if efiboot_output:
                        entries = [line.strip() for line in efiboot_output.splitlines() if line.strip()]
                        if entries:
                            boot_entries = entries[:40]  # Limita a 40
                except:
                    pass
            except:
                pass
            
            # Raccogli hardware info via lshw
            hardware_system = None
            hardware_bus = None
            hardware_memory = None
            hardware_processor = None
            hardware_storage = None
            hardware_disk = None
            hardware_volume = None
            hardware_network = None
            hardware_product = None
            try:
                lshw_output = exec_cmd('LANG=C lshw -short 2>/dev/null')
                if lshw_output:
                    import re
                    sections = {}
                    allowed_keywords = {'system', 'bus', 'memory', 'processor', 'storage', 'disk', 'volume', 'network'}
                    
                    for raw_line in lshw_output.splitlines():
                        line = raw_line.rstrip()
                        if not line or line.startswith('H/W path') or line.startswith('='):
                            continue
                        columns = re.split(r'\s{2,}', line.strip())
                        if not columns:
                            continue
                        
                        path = device = description = ''
                        clazz = ''
                        if len(columns) >= 4:
                            path, device, clazz, description = columns[0], columns[1], columns[2], ' '.join(columns[3:])
                        elif len(columns) == 3:
                            path, clazz, description = columns[0], columns[1], columns[2]
                        elif len(columns) == 2:
                            clazz, description = columns[0], columns[1]
                        else:
                            continue
                        
                        clazz = clazz.strip().lower()
                        if clazz == 'system' and not hardware_product and not path and not device:
                            hardware_product = description
                            continue
                        if clazz not in allowed_keywords:
                            continue
                        
                        entry_parts = []
                        if device:
                            entry_parts.append(device)
                        entry_parts.append(description)
                        entry = ' - '.join(part for part in entry_parts if part)
                        sections.setdefault(clazz, []).append(f'[{entry.strip()}]')
                    
                    # Limita ogni sezione a 40 entries
                    for key, entries in sections.items():
                        sections[key] = entries[:40]
                    
                    hardware_system = sections.get('system')
                    hardware_bus = sections.get('bus')
                    hardware_memory = sections.get('memory')
                    hardware_processor = sections.get('processor')
                    hardware_storage = sections.get('storage')
                    hardware_disk = sections.get('disk')
                    hardware_volume = sections.get('volume')
                    hardware_network = sections.get('network')
            except:
                pass
            
            # Raccogli PCI devices
            pci_devices = None
            try:
                lspci_output = exec_cmd('lspci 2>/dev/null')
                if lspci_output:
                    lines = [line.strip() for line in lspci_output.splitlines() if line.strip()]
                    if lines:
                        pci_devices = lines[:30]  # Limita a 30
            except:
                pass
            
            # Raccogli USB devices
            usb_devices = None
            try:
                lsusb_output = exec_cmd('lsusb 2>/dev/null')
                if lsusb_output:
                    lines = [line.strip() for line in lsusb_output.splitlines() if line.strip()]
                    if lines:
                        usb_devices = lines[:30]  # Limita a 30
            except:
                pass
            
            client.close()
            
            host_info = {
                'node_name': hostname,
                'cluster_name': cluster_name,
                'proxmox_version': proxmox_version,
                'manager_version': manager_version,
                'kernel_version': kernel_version,
                'cpu_model': cpu_model,
                'cpu_cores': cpu_cores,
                'cpu_sockets': cpu_sockets,
                'cpu_threads': cpu_threads,
                'cpu_total_cores': cpu_total_cores,
                'cpu_usage_percent': cpu_usage,
                'io_delay_percent': io_delay_percent,
                'memory_total_gb': memory_total_gb,
                'memory_used_gb': memory_used_gb,
                'memory_free_gb': memory_free_gb,
                'memory_usage_percent': memory_usage_percent,
                'ksm_sharing_gb': ksm_sharing_gb,
                'swap_total_gb': swap_total_gb,
                'swap_used_gb': swap_used_gb,
                'swap_free_gb': swap_free_gb,
                'swap_usage_percent': swap_usage_percent,
                'rootfs_total_gb': rootfs_total_gb,
                'rootfs_used_gb': rootfs_used_gb,
                'rootfs_free_gb': rootfs_free_gb,
                'rootfs_usage_percent': rootfs_usage_percent,
                'uptime_seconds': uptime_seconds,
                'uptime_human': uptime_human,
                'load_average_1m': load_1m,
                'load_average_5m': load_5m,
                'load_average_15m': load_15m,
                'license_status': license_status,
                'license_message': license_message,
                'license_level': license_level,
                'subscription_type': subscription_type,
                'subscription_key': subscription_key,
                'subscription_server_id': subscription_server_id,
                'subscription_sockets': subscription_sockets,
                'subscription_last_check': subscription_last_check,
                'subscription_next_due': subscription_next_due,
                'repository_status': repository_status,
                'boot_mode': boot_mode,
                'network_interfaces': network_interfaces,
                'storage_list': storage_list,
                'temperature_summary': temperature_summary,
                'temperature_highest_c': temperature_highest_c,
                'bios_vendor': bios_vendor,
                'bios_version': bios_version,
                'bios_release_date': bios_release_date,
                'system_manufacturer': system_manufacturer,
                'system_product': system_product,
                'system_serial': system_serial,
                'board_vendor': board_vendor,
                'board_name': board_name,
                'boot_devices': boot_devices,
                'boot_devices_details': boot_devices_details,
                'boot_entries': boot_entries,
                'hardware_system': hardware_system,
                'hardware_bus': hardware_bus,
                'hardware_memory': hardware_memory,
                'hardware_processor': hardware_processor,
                'hardware_storage': hardware_storage,
                'hardware_disk': hardware_disk,
                'hardware_volume': hardware_volume,
                'hardware_network': hardware_network,
                'hardware_product': hardware_product,
                'pci_devices': pci_devices,
                'usb_devices': usb_devices,
            }
            
            logger.info(f"Successfully collected Proxmox host info via SSH for {address}: node={hostname}")
            return host_info
            
        except Exception as e:
            logger.error(f"Error collecting Proxmox host info via SSH for {address}: {e}", exc_info=True)
            return None
    
    async def _collect_vms_ssh(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Raccoglie VM e container via SSH usando pvesh"""
        import paramiko
        
        username = credentials.get('username')
        password = credentials.get('password')
        ssh_port = credentials.get('ssh_port', 22)
        ssh_key = credentials.get('ssh_private_key')
        
        if not username or not password:
            logger.warning(f"SSH credentials incomplete for {address}: missing username or password")
            return []
        
        try:
            # Connetti via SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Usa chiave privata se disponibile
            pkey = None
            if ssh_key:
                try:
                    from io import StringIO
                    pkey = paramiko.RSAKey.from_private_key(StringIO(ssh_key))
                except Exception as e:
                    logger.debug(f"Failed to load SSH key, using password: {e}")
            
            logger.info(f"Connecting to Proxmox {address}:{ssh_port} via SSH for VM collection (user: {username})")
            client.connect(
                address,
                port=ssh_port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=30
            )
            
            def exec_cmd(cmd: str) -> Optional[str]:
                """Esegue comando SSH"""
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        return stdout.read().decode('utf-8').strip()
                    else:
                        error = stderr.read().decode('utf-8').strip()
                        logger.debug(f"Command failed: {cmd[:50]}... (exit: {exit_status}, error: {error})")
                        return None
                except Exception as e:
                    logger.debug(f"Error executing command {cmd[:50]}...: {e}")
                    return None
            
            vms = []
            
            # Raccogli VM QEMU
            qemu_cmd = f'pvesh get /nodes/{node_name}/qemu --output-format json'
            qemu_json = exec_cmd(qemu_cmd)
            
            if qemu_json:
                try:
                    import json
                    qemu_list = json.loads(qemu_json)
                    for vm in qemu_list:
                        vmid = vm.get('vmid', 0)
                        status = vm.get('status', 'unknown')
                        
                        vm_data = {
                            'vm_id': vmid,
                            'name': vm.get('name', f'VM-{vmid}'),
                            'status': status,
                            'type': 'qemu',
                            'cpu_cores': vm.get('maxcpu', 0),
                            'memory_mb': int(vm.get('maxmem', 0) / (1024 * 1024)) if vm.get('maxmem') else 0,
                            'disk_total_gb': bytes_to_gib(vm.get('maxdisk', 0)),
                            'template': vm.get('template', False),
                            'uptime': vm.get('uptime', 0),
                            'cpu_usage': vm.get('cpu', 0),
                            'mem_used': vm.get('mem', 0),
                            'netin': vm.get('netin', 0),
                            'netout': vm.get('netout', 0),
                            'diskread': vm.get('diskread', 0),
                            'diskwrite': vm.get('diskwrite', 0),
                        }
                        
                        # Ottieni configurazione VM completa (come Proxreporter)
                        config_cmd = f'pvesh get /nodes/{node_name}/qemu/{vmid}/config --output-format json'
                        config_json = exec_cmd(config_cmd)
                        if config_json:
                            try:
                                config = json.loads(config_json)
                                
                                # BIOS e Machine type
                                vm_data['bios'] = config.get('bios', 'seabios')
                                vm_data['machine'] = config.get('machine', 'pc')
                                vm_data['agent_installed'] = bool(config.get('agent'))
                                
                                # CPU dalla configurazione
                                cores = int(config.get('cores', 1))
                                sockets = int(config.get('sockets', 1))
                                vm_data['cpu_cores'] = cores
                                vm_data['cpu_sockets'] = sockets
                                vm_data['cpu_total'] = cores * sockets
                                
                                vm_data['os_type'] = config.get('ostype', '')
                                
                                # Dischi dettagliati (come Proxreporter)
                                disks = []
                                disk_details = []
                                for key in config:
                                    if key.startswith(('scsi', 'sata', 'ide', 'virtio')):
                                        # Assicurati che key sia una stringa valida
                                        if isinstance(key, str) and key:
                                            disks.append(key)
                                        disk_info = config[key]
                                        if isinstance(disk_info, str):
                                            disk_detail = {'id': key}
                                            parts = disk_info.split(',')
                                            first_part = parts[0]
                                            if ':' in first_part:
                                                storage_vol = first_part.split(':', 1)
                                                disk_detail['storage'] = storage_vol[0]
                                                if len(storage_vol) > 1:
                                                    disk_detail['volume'] = storage_vol[1]
                                            else:
                                                disk_detail['storage'] = 'N/A'
                                            
                                            for part in parts[1:]:
                                                if '=' in part:
                                                    param_name, param_value = part.split('=', 1)
                                                    if param_name == 'size':
                                                        disk_detail['size'] = param_value
                                                    elif param_name == 'media':
                                                        disk_detail['media'] = param_value
                                                    elif param_name == 'cache':
                                                        disk_detail['cache'] = param_value
                                            
                                            disk_details.append(disk_detail)
                                
                                vm_data['num_disks'] = len(disks)
                                # Limita la lunghezza di disks a 500 caratteri per il campo VARCHAR(500)
                                # Filtra solo stringhe valide prima del join
                                disks_valid = [str(d) for d in disks if d]
                                disks_str = ', '.join(disks_valid) if disks_valid else None
                                if disks_str and len(disks_str) > 500:
                                    disks_str = disks_str[:497] + '...'
                                vm_data['disks'] = disks_str
                                vm_data['disks_details'] = disk_details if disk_details else []
                                
                                # Network dettagliati (come Proxreporter)
                                networks = []
                                network_details = []
                                for key in config:
                                    if key.startswith('net'):
                                        # Assicurati che key sia una stringa valida
                                        if isinstance(key, str) and key:
                                            networks.append(key)
                                        net_info = config[key]
                                        if isinstance(net_info, str):
                                            net_detail = {'id': key}
                                            parts = net_info.split(',')
                                            first_part = parts[0] if parts else ''
                                            if '=' in first_part:
                                                model, mac = first_part.split('=', 1)
                                                net_detail['model'] = model
                                                net_detail['mac'] = mac
                                            
                                            for part in parts[1:]:
                                                if '=' in part:
                                                    k, v = part.split('=', 1)
                                                    if k == 'bridge':
                                                        net_detail['bridge'] = v
                                                    elif k == 'tag':
                                                        net_detail['vlan'] = v
                                                    elif k == 'firewall':
                                                        net_detail['firewall'] = v
                                                    elif k == 'rate':
                                                        net_detail['rate'] = v
                                            
                                            network_details.append(net_detail)
                                
                                vm_data['num_networks'] = len(networks)
                                # Limita la lunghezza di networks a 500 caratteri per il campo VARCHAR(500)
                                # Filtra solo stringhe valide prima del join
                                networks_valid = [str(n) for n in networks if n]
                                networks_str = ', '.join(networks_valid) if networks_valid else None
                                if networks_str and len(networks_str) > 500:
                                    networks_str = networks_str[:497] + '...'
                                vm_data['networks'] = networks_str
                                vm_data['network_interfaces'] = network_details if network_details else []
                            except Exception as e:
                                logger.debug(f"Failed to parse VM config for {vmid}: {e}")
                        
                        # IP Addresses via QEMU Guest Agent (solo per VM running con agent)
                        ip_addresses = []
                        if status == 'running' and vm_data.get('agent_installed'):
                            try:
                                agent_cmd = f'pvesh get /nodes/{node_name}/qemu/{vmid}/agent/network-get-interfaces --output-format json 2>/dev/null'
                                agent_json = exec_cmd(agent_cmd)
                                if agent_json:
                                    agent_info = json.loads(agent_json)
                                    result = agent_info.get('result', agent_info) if isinstance(agent_info, dict) else agent_info
                                    
                                    if isinstance(result, list):
                                        for iface in result:
                                            if not isinstance(iface, dict):
                                                continue
                                            
                                            iface_name = iface.get('name', '').lower()
                                            if iface_name in ['lo', 'loopback']:
                                                continue
                                            
                                            if 'ip-addresses' not in iface:
                                                continue
                                            
                                            ip_addrs = iface.get('ip-addresses', [])
                                            if not isinstance(ip_addrs, list):
                                                continue
                                            
                                            for ip_info in ip_addrs:
                                                if not isinstance(ip_info, dict):
                                                    continue
                                                
                                                ip = ip_info.get('ip-address', '').strip()
                                                if not ip:
                                                    continue
                                                if ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                                                    continue
                                                
                                                ip_addresses.append(ip)
                            except Exception as e:
                                logger.debug(f"Failed to get IP addresses for VM {vmid}: {e}")
                        
                        # Rimuovi duplicati
                        seen = set()
                        unique_ips = []
                        for ip in ip_addresses:
                            if ip not in seen:
                                seen.add(ip)
                                unique_ips.append(ip)
                        
                        # Limita la lunghezza di ip_addresses a 500 caratteri per il campo VARCHAR(500)
                        ip_addresses_str = '; '.join(unique_ips) if unique_ips else None
                        if ip_addresses_str and len(ip_addresses_str) > 500:
                            ip_addresses_str = ip_addresses_str[:497] + '...'
                        vm_data['ip_addresses'] = ip_addresses_str
                        
                        vms.append(vm_data)
                except Exception as e:
                    logger.warning(f"Failed to parse QEMU VM list: {e}")
            
            # Raccogli container LXC
            lxc_cmd = f'pvesh get /nodes/{node_name}/lxc --output-format json'
            lxc_json = exec_cmd(lxc_cmd)
            
            if lxc_json:
                try:
                    import json
                    lxc_list = json.loads(lxc_json)
                    for lxc in lxc_list:
                        vmid = lxc.get('vmid', 0)
                        status = lxc.get('status', 'unknown')
                        
                        lxc_data = {
                            'vm_id': vmid,
                            'name': lxc.get('name', f'LXC-{vmid}'),
                            'status': status,
                            'type': 'lxc',
                            'cpu_cores': lxc.get('maxcpu', 0),
                            'memory_mb': int(lxc.get('maxmem', 0) / (1024 * 1024)) if lxc.get('maxmem') else 0,
                            'disk_total_gb': bytes_to_gib(lxc.get('maxdisk', 0)),
                            'template': lxc.get('template', False),
                            'uptime': lxc.get('uptime', 0),
                            'cpu_usage': lxc.get('cpu', 0),
                            'mem_used': lxc.get('mem', 0),
                            'netin': lxc.get('netin', 0),
                            'netout': lxc.get('netout', 0),
                            'diskread': lxc.get('diskread', 0),
                            'diskwrite': lxc.get('diskwrite', 0),
                        }
                        
                        # Ottieni configurazione LXC completa (come Proxreporter)
                        config_cmd = f'pvesh get /nodes/{node_name}/lxc/{vmid}/config --output-format json'
                        config_json = exec_cmd(config_cmd)
                        if config_json:
                            try:
                                config = json.loads(config_json)
                                
                                lxc_data['cpu_cores'] = int(config.get('cores', lxc_data['cpu_cores']))
                                lxc_data['os_type'] = config.get('ostype', '')
                                
                                # Network dettagliati (come Proxreporter)
                                networks = []
                                network_details = []
                                for key in config:
                                    if key.startswith('net'):
                                        networks.append(key)
                                        net_info = config[key]
                                        if isinstance(net_info, str):
                                            net_detail = {'id': key}
                                            parts = net_info.split(',')
                                            first_part = parts[0] if parts else ''
                                            if '=' in first_part:
                                                model, mac = first_part.split('=', 1)
                                                net_detail['model'] = model
                                                net_detail['mac'] = mac
                                            
                                            for part in parts[1:]:
                                                if '=' in part:
                                                    k, v = part.split('=', 1)
                                                    if k == 'bridge':
                                                        net_detail['bridge'] = v
                                                    elif k == 'tag':
                                                        net_detail['vlan'] = v
                                                    elif k == 'firewall':
                                                        net_detail['firewall'] = v
                                                    elif k == 'rate':
                                                        net_detail['rate'] = v
                                            
                                            network_details.append(net_detail)
                                
                                lxc_data['num_networks'] = len(networks)
                                lxc_data['networks'] = ', '.join(networks) if networks else None
                                lxc_data['network_interfaces'] = network_details if network_details else []
                            except Exception as e:
                                logger.debug(f"Failed to parse LXC config for {vmid}: {e}")
                        
                        # IP Addresses per LXC (via network config)
                        ip_addresses = []
                        if status == 'running':
                            try:
                                # Per LXC, gli IP sono nella configurazione network
                                if config_json:
                                    config = json.loads(config_json)
                                    for key in config:
                                        if key.startswith('net'):
                                            net_info = config[key]
                                            if isinstance(net_info, str):
                                                # Cerca IP nella configurazione
                                                if 'ip=' in net_info:
                                                    for part in net_info.split(','):
                                                        if part.startswith('ip='):
                                                            ip = part.split('=')[1].split('/')[0]
                                                            if ip and not ip.startswith(('127.', '::1', 'fe80:', '169.254.')):
                                                                ip_addresses.append(ip)
                            except Exception as e:
                                logger.debug(f"Failed to get IP addresses for LXC {vmid}: {e}")
                        
                        # Rimuovi duplicati
                        seen = set()
                        unique_ips = []
                        for ip in ip_addresses:
                            if ip not in seen:
                                seen.add(ip)
                                unique_ips.append(ip)
                        
                        # Limita la lunghezza di ip_addresses a 500 caratteri per il campo VARCHAR(500)
                        ip_addresses_str = '; '.join(unique_ips) if unique_ips else None
                        if ip_addresses_str and len(ip_addresses_str) > 500:
                            ip_addresses_str = ip_addresses_str[:497] + '...'
                        lxc_data['ip_addresses'] = ip_addresses_str
                        
                        vms.append(lxc_data)
                except Exception as e:
                    logger.warning(f"Failed to parse LXC container list: {e}")
            
            client.close()
            logger.info(f"Successfully collected {len(vms)} VMs/containers via SSH for {address}")
            return vms
            
        except Exception as e:
            logger.error(f"Error collecting VMs via SSH for {address}: {e}", exc_info=True)
            return []
    
    async def _collect_storage_ssh(
        self,
        address: str,
        node_name: str,
        credentials: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Raccoglie storage via SSH usando pvesh"""
        import paramiko
        
        username = credentials.get('username')
        password = credentials.get('password')
        ssh_port = credentials.get('ssh_port', 22)
        ssh_key = credentials.get('ssh_private_key')
        
        if not username or not password:
            logger.warning(f"SSH credentials incomplete for {address}: missing username or password")
            return []
        
        try:
            # Connetti via SSH
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Usa chiave privata se disponibile
            pkey = None
            if ssh_key:
                try:
                    from io import StringIO
                    pkey = paramiko.RSAKey.from_private_key(StringIO(ssh_key))
                except Exception as e:
                    logger.debug(f"Failed to load SSH key, using password: {e}")
            
            logger.info(f"Connecting to Proxmox {address}:{ssh_port} via SSH for storage collection (user: {username})")
            client.connect(
                address,
                port=ssh_port,
                username=username,
                password=password,
                pkey=pkey,
                timeout=30
            )
            
            def exec_cmd(cmd: str) -> Optional[str]:
                """Esegue comando SSH"""
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                    exit_status = stdout.channel.recv_exit_status()
                    if exit_status == 0:
                        return stdout.read().decode('utf-8').strip()
                    else:
                        error = stderr.read().decode('utf-8').strip()
                        logger.debug(f"Command failed: {cmd[:50]}... (exit: {exit_status}, error: {error})")
                        return None
                except Exception as e:
                    logger.debug(f"Error executing command {cmd[:50]}...: {e}")
                    return None
            
            storage_list = []
            
            # Raccogli lista storage
            storage_cmd = f'pvesh get /nodes/{node_name}/storage --output-format json'
            storage_json = exec_cmd(storage_cmd)
            
            if not storage_json:
                logger.warning(f"Failed to get storage list via pvesh for {address}")
                client.close()
                return []
            
            import json
            storage_data_list = json.loads(storage_json)
            
            for storage in storage_data_list:
                storage_name = storage.get('storage')
                if not storage_name:
                    continue
                
                storage_info = {
                    'storage': storage_name,
                    'type': storage.get('type'),
                    'content': storage.get('content', []),
                    'enabled': storage.get('enabled', 1),
                    'shared': storage.get('shared', 0),
                }
                
                # Ottieni dettagli storage status
                status_cmd = f'pvesh get /nodes/{node_name}/storage/{storage_name}/status --output-format json'
                status_json = exec_cmd(status_cmd)
                
                if status_json:
                    try:
                        status_data = json.loads(status_json)
                        storage_info['total'] = status_data.get('total')
                        storage_info['used'] = status_data.get('used')
                        storage_info['available'] = status_data.get('avail')
                        storage_info['total_gb'] = bytes_to_gib(status_data.get('total'))
                        storage_info['used_gb'] = bytes_to_gib(status_data.get('used'))
                        storage_info['available_gb'] = bytes_to_gib(status_data.get('avail'))
                        if storage_info['total'] and storage_info['used']:
                            storage_info['usage_percent'] = safe_round(
                                (storage_info['used'] / storage_info['total']) * 100, 2
                            )
                    except Exception as e:
                        logger.debug(f"Failed to parse storage status for {storage_name}: {e}")
                
                storage_list.append(storage_info)
            
            client.close()
            logger.info(f"Successfully collected {len(storage_list)} storage entries via SSH for {address}")
            return storage_list
            
        except Exception as e:
            logger.error(f"Error collecting storage via SSH for {address}: {e}", exc_info=True)
            return []


# Singleton instance
_proxmox_collector: Optional[ProxmoxCollector] = None


def get_proxmox_collector() -> ProxmoxCollector:
    """Ottiene istanza singleton del collector Proxmox"""
    global _proxmox_collector
    if _proxmox_collector is None:
        _proxmox_collector = ProxmoxCollector()
    return _proxmox_collector

