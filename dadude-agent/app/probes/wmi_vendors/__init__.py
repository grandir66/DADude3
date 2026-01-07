"""
DaDude Agent - WMI/WinRM Vendor Modules
Moduli separati per ogni tipo di Windows per facilitare manutenzione e test.

Struttura:
- base.py: Classe base e utilities comuni
- windows_server.py: Windows Server (2016, 2019, 2022)
- windows_workstation.py: Windows Client (10, 11)
- hyperv.py: Hyper-V hosts
"""

from .base import WMIVendorProbe
from .windows_server import WindowsServerProbe
from .windows_workstation import WindowsWorkstationProbe
from .hyperv import HyperVProbe

__all__ = [
    'WMIVendorProbe',
    'WindowsServerProbe',
    'WindowsWorkstationProbe',
    'HyperVProbe',
]
