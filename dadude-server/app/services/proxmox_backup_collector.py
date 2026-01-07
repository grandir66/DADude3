"""
Proxmox Backup Collector - NUOVO MODULO
Backup configurazioni Proxmox VE tramite SSH
Backup delle cartelle di configurazione critiche
"""
import paramiko
import logging
import hashlib
import tarfile
import io
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path
import os


class ProxmoxBackupCollector:
    """
    Collector per backup configurazioni Proxmox VE
    Backup delle cartelle di configurazione critiche via SSH
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.timeout = self.config.get('timeout', 30)
        
        # Cartelle e file da fare backup
        self.backup_paths = [
            '/etc/pve/',              # Configurazioni cluster, VM/CT, storage, datacenter, HA
            '/etc/vzdump.conf',       # Policy e opzioni di backup
            '/etc/network/interfaces', # Bridge, VLAN, configurazioni di rete
            '/etc/sysctl.conf',       # Tuning kernel
            '/etc/modprobe.d/',       # Moduli kernel
            '/etc/hosts',             # Identificazione nodo
            '/etc/hostname',          # Nome host
            '/etc/resolv.conf',       # DNS
            '/etc/lvm/',              # LVM/LVM-Thin (se presente)
            '/etc/multipath.conf',    # Multipath/SAN (se presente)
            '/etc/multipath/',        # Configurazioni multipath
            '/etc/cron.d/',           # Job cron personalizzati
            '/etc/cron.daily/',       # Script giornalieri
            '/etc/cron.weekly/',      # Script settimanali
            '/etc/cron.monthly/',     # Script mensili
            '/etc/aliases',           # Alias email
        ]

    def test_connection(self, host: str, username: str, password: str,
                       port: int = 22) -> Dict[str, Any]:
        """
        Testa connessione SSH a Proxmox e recupera info base

        Returns:
            dict: {
                "success": bool,
                "hostname": str,
                "version": str,
                "cluster": str,
                "error": str (se failed)
            }
        """
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Testing connection to Proxmox {host}...")
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False
            )

            # Recupera hostname
            stdin, stdout, stderr = client.exec_command('hostname')
            hostname = stdout.read().decode('utf-8').strip()

            # Recupera versione Proxmox
            stdin, stdout, stderr = client.exec_command('pveversion')
            version_output = stdout.read().decode('utf-8').strip()
            version = version_output.split('\n')[0] if version_output else "unknown"

            # Verifica se è in cluster
            cluster_name = "standalone"
            try:
                stdin, stdout, stderr = client.exec_command('cat /etc/pve/corosync.conf 2>/dev/null | grep "cluster_name" | head -1')
                cluster_output = stdout.read().decode('utf-8').strip()
                if cluster_output:
                    # Estrai nome cluster da "cluster_name: nome"
                    parts = cluster_output.split(':', 1)
                    if len(parts) > 1:
                        cluster_name = parts[1].strip()
            except:
                pass

            client.close()

            return {
                "success": True,
                "hostname": hostname,
                "version": version,
                "cluster": cluster_name,
            }

        except Exception as e:
            self.logger.error(f"Connection test failed for {host}: {e}")
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def backup_configuration(self, host: str, username: str, password: str,
                            port: int = 22, backup_path: Optional[str] = None,
                            backup_type: str = "config") -> Dict[str, Any]:
        """
        Backup configurazione Proxmox VE

        Args:
            backup_type: "config" (solo configurazioni), "full" (tutto incluso)

        Returns:
            dict: {
                "success": bool,
                "file_path": str,
                "file_size": int,
                "checksum": str,
                "device_info": dict,
                "error": str (se failed)
            }
        """
        client = None

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            self.logger.info(f"Connecting to Proxmox {host}:{port} for backup...")
            
            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=password,
                    timeout=self.timeout,
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=30
                )
            except Exception as e:
                error_msg = (
                    f"Failed to connect to Proxmox {host}:{port} via SSH. "
                    f"Please verify: 1) SSH is enabled, 2) SSH port is correct ({port}), "
                    f"3) Credentials are valid. Error: {str(e)}"
                )
                self.logger.error(error_msg)
                return {
                    "success": False,
                    "error": error_msg
                }

            # Raccolta info device
            device_info = self._get_device_info(client)
            device_info["backup_timestamp"] = datetime.now().isoformat()

            # Crea archivio tar compresso
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hostname = device_info.get("hostname", host.replace('.', '_'))
            filename = f"proxmox_{hostname}_{timestamp}.tar.gz"
            
            if backup_path:
                backup_dir = Path(backup_path) / hostname
                backup_dir.mkdir(parents=True, exist_ok=True)
                local_file_path = backup_dir / filename
            else:
                local_file_path = Path(f"/tmp/{filename}")

            # Crea archivio tar.gz locale
            self.logger.info(f"Creating backup archive: {local_file_path}")
            with tarfile.open(local_file_path, 'w:gz') as tar:
                # Aggiungi ogni path al backup
                for path in self.backup_paths:
                    try:
                        self._add_path_to_tar(client, tar, path, hostname)
                    except Exception as e:
                        self.logger.warning(f"Failed to backup {path}: {e}")
                        continue

            # Calcola checksum
            file_size = local_file_path.stat().st_size
            with open(local_file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            self.logger.info(f"Backup completed: {local_file_path} ({file_size} bytes)")

            return {
                "success": True,
                "file_path": str(local_file_path),
                "file_size": file_size,
                "checksum": file_hash,
                "device_info": device_info,
                "backup_type": backup_type,
                "filename": filename
            }

        except Exception as e:
            self.logger.error(f"Backup failed for {host}: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e)
            }

        finally:
            if client:
                try:
                    client.close()
                except:
                    pass

    def _get_device_info(self, client: paramiko.SSHClient) -> Dict[str, Any]:
        """Recupera info base device"""
        info = {}

        # Hostname
        stdin, stdout, stderr = client.exec_command('hostname')
        info["hostname"] = stdout.read().decode('utf-8').strip()

        # Versione Proxmox
        stdin, stdout, stderr = client.exec_command('pveversion')
        version_output = stdout.read().decode('utf-8').strip()
        info["version"] = version_output.split('\n')[0] if version_output else "unknown"

        # Cluster name
        info["cluster"] = "standalone"
        try:
            stdin, stdout, stderr = client.exec_command('cat /etc/pve/corosync.conf 2>/dev/null | grep "cluster_name" | head -1')
            cluster_output = stdout.read().decode('utf-8').strip()
            if cluster_output:
                parts = cluster_output.split(':', 1)
                if len(parts) > 1:
                    info["cluster"] = parts[1].strip()
        except:
            pass

        # Uptime
        try:
            stdin, stdout, stderr = client.exec_command('uptime -p')
            info["uptime"] = stdout.read().decode('utf-8').strip()
        except:
            info["uptime"] = "unknown"

        # Numero VM/CT
        try:
            stdin, stdout, stderr = client.exec_command('qm list 2>/dev/null | wc -l')
            vm_count = stdout.read().decode('utf-8').strip()
            info["vm_count"] = int(vm_count) - 1 if vm_count.isdigit() else 0  # -1 per header
            
            stdin, stdout, stderr = client.exec_command('pct list 2>/dev/null | wc -l')
            ct_count = stdout.read().decode('utf-8').strip()
            info["ct_count"] = int(ct_count) - 1 if ct_count.isdigit() else 0  # -1 per header
        except:
            info["vm_count"] = 0
            info["ct_count"] = 0

        return info

    def _add_path_to_tar(self, client: paramiko.SSHClient, tar: tarfile.TarFile, 
                        remote_path: str, hostname: str):
        """Aggiunge un path remoto all'archivio tar"""
        sftp = client.open_sftp()
        
        try:
            # Verifica se esiste
            try:
                stat = sftp.stat(remote_path)
            except IOError:
                self.logger.debug(f"Path {remote_path} does not exist, skipping")
                return

            # Se è un file
            if stat.st_mode & 0o170000 == 0o100000:  # Regular file
                with sftp.open(remote_path, 'rb') as remote_file:
                    file_data = remote_file.read()
                    tarinfo = tarfile.TarInfo(name=f"{hostname}{remote_path}")
                    tarinfo.size = len(file_data)
                    tarinfo.mtime = stat.st_mtime
                    tarinfo.mode = stat.st_mode
                    tar.addfile(tarinfo, io.BytesIO(file_data))
                    self.logger.debug(f"Added file: {remote_path}")

            # Se è una directory
            elif stat.st_mode & 0o170000 == 0o040000:  # Directory
                # Aggiungi la directory stessa
                tarinfo = tarfile.TarInfo(name=f"{hostname}{remote_path}")
                tarinfo.type = tarfile.DIRTYPE
                tarinfo.mtime = stat.st_mtime
                tarinfo.mode = stat.st_mode
                tar.addfile(tarinfo)
                
                # Ricorsivamente aggiungi contenuto
                self._add_directory_to_tar(sftp, tar, remote_path, hostname)

        finally:
            sftp.close()

    def _add_directory_to_tar(self, sftp: paramiko.SFTPClient, tar: tarfile.TarFile,
                              remote_dir: str, hostname: str):
        """Aggiunge ricorsivamente contenuto di una directory"""
        try:
            items = sftp.listdir_attr(remote_dir)
            for item in items:
                item_path = f"{remote_dir.rstrip('/')}/{item.filename}"
                
                # Skip alcuni file/directory che non servono
                if item.filename in ['.', '..', '.lock', 'lock']:
                    continue
                
                try:
                    # Se è un file
                    if item.st_mode & 0o170000 == 0o100000:
                        with sftp.open(item_path, 'rb') as remote_file:
                            file_data = remote_file.read()
                            tarinfo = tarfile.TarInfo(name=f"{hostname}{item_path}")
                            tarinfo.size = len(file_data)
                            tarinfo.mtime = item.st_mtime
                            tarinfo.mode = item.st_mode
                            tar.addfile(tarinfo, io.BytesIO(file_data))
                    
                    # Se è una directory
                    elif item.st_mode & 0o170000 == 0o040000:
                        tarinfo = tarfile.TarInfo(name=f"{hostname}{item_path}")
                        tarinfo.type = tarfile.DIRTYPE
                        tarinfo.mtime = item.st_mtime
                        tarinfo.mode = item.st_mode
                        tar.addfile(tarinfo)
                        
                        # Ricorsione
                        self._add_directory_to_tar(sftp, tar, item_path, hostname)
                except Exception as e:
                    self.logger.warning(f"Failed to add {item_path}: {e}")
                    continue
        except Exception as e:
            self.logger.warning(f"Failed to list directory {remote_dir}: {e}")

