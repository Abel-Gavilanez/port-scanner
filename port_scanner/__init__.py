"""Escaner de puertos TCP asincrono.

API publica minima:

    from port_scanner import PortScanner
    report = await PortScanner().scan("127.0.0.1", 1, 1024)
"""

from .models import PortResult, PortState, ScanReport
from .scanner import PortScanner, PortScannerError

__all__ = [
    "PortScanner",
    "PortScannerError",
    "PortResult",
    "PortState",
    "ScanReport",
]

__version__ = "1.0.0"
