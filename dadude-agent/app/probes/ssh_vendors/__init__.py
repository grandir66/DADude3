"""
DaDude Agent - SSH Vendor Modules
Moduli separati per ogni vendor per facilitare manutenzione e test.

Struttura:
- base.py: Classe base e utilities comuni
- mikrotik.py: MikroTik RouterOS
- cisco.py: Cisco IOS/IOS-XE/NX-OS
- ubiquiti.py: Ubiquiti EdgeOS + UniFi
- hp.py: HP Comware/ProCurve
- synology.py: Synology DSM
- qnap.py: QNAP QTS
- linux.py: Linux generico
- proxmox.py: Proxmox VE
"""

from .base import SSHVendorProbe, VendorDetector
from .mikrotik import MikroTikProbe
from .cisco import CiscoProbe
from .ubiquiti import UbiquitiProbe
from .hp import HPProbe
from .synology import SynologyProbe
from .qnap import QNAPProbe
from .linux import LinuxProbe
from .proxmox import ProxmoxProbe

__all__ = [
    'SSHVendorProbe',
    'VendorDetector',
    'MikroTikProbe',
    'CiscoProbe',
    'UbiquitiProbe',
    'HPProbe',
    'SynologyProbe',
    'QNAPProbe',
    'LinuxProbe',
    'ProxmoxProbe',
]
