"""
DaDude Agent - SSH Probe (Modular Version)
Scansione dispositivi via SSH con moduli vendor separati.

Ogni vendor ha il proprio modulo in ssh_vendors/ per facilitare:
- Manutenzione separata
- Test isolati
- Aggiornamenti senza impattare altri vendor
"""
import asyncio
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
from loguru import logger
from io import StringIO


_executor = ThreadPoolExecutor(max_workers=5)


async def probe(
    target: str,
    username: str,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    port: int = 22,
) -> Dict[str, Any]:
    """
    Esegue probe SSH su un target.
    Rileva automaticamente il tipo di device ed esegue il modulo vendor appropriato.
    
    Vendor supportati:
    - MikroTik RouterOS
    - Cisco IOS/IOS-XE
    - Ubiquiti EdgeOS/UniFi
    - HP Comware/ProCurve
    - Synology DSM
    - QNAP QTS
    - Proxmox VE
    - Linux generico (fallback)
    
    Returns:
        Dict con info sistema: hostname, os, cpu, ram, disco, neighbors, etc.
    """
    loop = asyncio.get_event_loop()
    
    def connect():
        import paramiko
        
        logger.debug(f"SSH probe: connecting to {target}:{port} as {username}")
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        connect_args = {
            "hostname": target,
            "port": port,
            "username": username,
            "timeout": 15,
            "allow_agent": False,
            "look_for_keys": False,
        }
        
        if private_key:
            key = paramiko.RSAKey.from_private_key(StringIO(private_key))
            connect_args["pkey"] = key
        else:
            connect_args["password"] = password
        
        client.connect(**connect_args)
        
        use_sudo = False
        
        def exec_cmd(cmd: str, timeout: int = 5, try_sudo: bool = False) -> str:
            """Esegue comando SSH con supporto per sudo automatico."""
            nonlocal use_sudo
            
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                if try_sudo and error and (
                    "permission denied" in error.lower() or 
                    "operation not permitted" in error.lower() or
                    "access denied" in error.lower()
                ):
                    sudo_cmd = f"sudo {cmd}"
                    logger.debug(f"SSH: Command failed with permission error, retrying with sudo")
                    stdin, stdout, stderr = client.exec_command(sudo_cmd, timeout=timeout)
                    sudo_output = stdout.read().decode().strip()
                    sudo_error = stderr.read().decode().strip()
                    
                    if sudo_output and not (
                        "password" in sudo_error.lower() or 
                        "sudo:" in sudo_error.lower()
                    ):
                        use_sudo = True
                        return sudo_output
                    elif "password" in sudo_error.lower():
                        logger.debug(f"SSH: sudo requires password (not available)")
                
                if error and "Permission denied" not in error.lower() and "command not found" not in error.lower():
                    logger.debug(f"SSH exec_cmd '{cmd[:50]}...' stderr: {error[:200]}")
                return output
            except Exception as e:
                logger.debug(f"SSH exec_cmd '{cmd[:50]}...' failed: {e}")
                return ""
        
        def exec_cmd_sudo(cmd: str, timeout: int = 5) -> str:
            """Esegue comando con sudo se necessario/disponibile"""
            if use_sudo:
                return exec_cmd(f"sudo {cmd}", timeout=timeout)
            return exec_cmd(cmd, timeout=timeout, try_sudo=True)
        
        # Import vendor modules
        from .ssh_vendors import (
            MikroTikProbe, CiscoProbe, UbiquitiProbe, HPProbe,
            SynologyProbe, QNAPProbe, ProxmoxProbe, LinuxProbe
        )
        
        # Lista di probe in ordine di priorità (detection)
        # Ogni probe tenta di rilevare il proprio vendor
        vendor_probes = [
            MikroTikProbe(exec_cmd, exec_cmd_sudo),
            CiscoProbe(exec_cmd, exec_cmd_sudo),
            UbiquitiProbe(exec_cmd, exec_cmd_sudo, client),
            HPProbe(exec_cmd, exec_cmd_sudo),
            ProxmoxProbe(exec_cmd, exec_cmd_sudo),
            SynologyProbe(exec_cmd, exec_cmd_sudo),
            QNAPProbe(exec_cmd, exec_cmd_sudo),
        ]
        
        # Ordina per priorità
        vendor_probes.sort(key=lambda p: p.DETECTION_PRIORITY)
        
        info = {}
        detected_vendor = None
        
        # Prova a rilevare il vendor
        for probe_instance in vendor_probes:
            try:
                if probe_instance.detect():
                    detected_vendor = probe_instance.VENDOR_NAME
                    logger.info(f"SSH probe: Detected {detected_vendor} on {target}")
                    info = probe_instance.probe(target)
                    break
            except Exception as e:
                logger.debug(f"SSH probe: {probe_instance.VENDOR_NAME} detection failed: {e}")
        
        # Fallback a Linux generico
        if not detected_vendor:
            logger.info(f"SSH probe: No specific vendor detected on {target}, using Linux generic")
            linux_probe = LinuxProbe(exec_cmd, exec_cmd_sudo)
            try:
                if linux_probe.detect():
                    info = linux_probe.probe(target)
                else:
                    # Ultimo fallback: prova comunque Linux
                    info = linux_probe.probe(target)
            except Exception as e:
                logger.error(f"SSH probe: Linux probe failed for {target}: {e}")
                info = {"error": str(e)}
        
        client.close()
        
        # Log summary
        collected_keys = [k for k in info.keys() if k not in ['address', 'mac_address', 'device_type', 'category', 'identified_by']]
        logger.info(
            f"SSH probe successful: {info.get('hostname')} ({info.get('os_name', 'Unknown')}), "
            f"vendor={detected_vendor or 'Linux'}, collected {len(collected_keys)} fields"
        )
        
        return info
    
    return await loop.run_in_executor(_executor, connect)


# ===== BACKWARD COMPATIBILITY =====
# Mantieni le funzioni helper per compatibilità con codice esistente

def _detect_ubiquiti_unifi(exec_cmd) -> bool:
    """Rileva Ubiquiti UniFi - DEPRECATED, usa UbiquitiProbe.detect()"""
    info_out = exec_cmd("info", timeout=3)
    if info_out and ("model" in info_out.lower() or "version" in info_out.lower() or "mac" in info_out.lower()):
        return True
    
    busybox = exec_cmd("busybox", timeout=3)
    if busybox and "busybox" in busybox.lower():
        board = exec_cmd("cat /etc/board.info 2>/dev/null", timeout=3)
        if board and "board" in board.lower():
            return True
    
    return False


def _probe_ubiquiti_unifi(client, target: str, exec_cmd) -> Dict[str, Any]:
    """Probe UniFi - DEPRECATED, usa UbiquitiProbe.probe()"""
    from .ssh_vendors import UbiquitiProbe
    
    def exec_cmd_sudo(cmd: str, timeout: int = 5) -> str:
        return exec_cmd(f"sudo {cmd}", timeout=timeout)
    
    probe = UbiquitiProbe(exec_cmd, exec_cmd_sudo, client)
    return probe._probe_unifi(target)


def _try_unifi_cli(client, target: str):
    """Try UniFi CLI - DEPRECATED, usa UbiquitiProbe._try_unifi_cli()"""
    from .ssh_vendors import UbiquitiProbe
    
    probe = UbiquitiProbe(lambda cmd, timeout=5: "", lambda cmd, timeout=5: "", client)
    return probe._try_unifi_cli()
