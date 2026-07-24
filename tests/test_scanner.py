"""Pruebas unitarias basicas del PortScanner.

Se usan servidores TCP efimeros levantados en localhost para no depender
de red externa ni de puertos reales del sistema."""

import asyncio
import socket

import pytest

from port_scanner.models import PortState
from port_scanner.scanner import PortScanner, PortScannerError


def _free_port() -> int:
    """Pide al SO un puerto libre para evitar colisiones entre tests."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _close_immediately(reader, writer):
    """Handler de servidor de prueba: acepta y cierra la conexion al toque."""
    writer.close()
    await writer.wait_closed()


@pytest.mark.asyncio
async def test_detects_open_port():
    port = _free_port()
    server = await asyncio.start_server(_close_immediately, "127.0.0.1", port)
    async with server:
        scanner = PortScanner(timeout=0.5)
        report = await scanner.scan("127.0.0.1", port, port)

    assert len(report.results) == 1
    assert report.results[0].state is PortState.OPEN


@pytest.mark.asyncio
async def test_detects_closed_port():
    port = _free_port()  # nadie escucha aqui
    scanner = PortScanner(timeout=0.5)
    report = await scanner.scan("127.0.0.1", port, port)

    # En Linux, un puerto sin oyente suele devolver RST -> CLOSED.
    # En Windows, dependiendo del firewall, la conexion puede no responder
    # nada y expirar por timeout -> FILTERED. Ambos son resultados
    # correctos del escaner; lo unico incorrecto seria marcarlo OPEN.
    
    assert report.results[0].state in (PortState.CLOSED, PortState.FILTERED)


@pytest.mark.asyncio
async def test_invalid_host_raises():
    scanner = PortScanner(timeout=0.5)
    with pytest.raises(PortScannerError):
        await scanner.scan("host-que-no-existe.invalid", 1, 1)


def test_invalid_port_range_raises():
    scanner = PortScanner()
    with pytest.raises(ValueError):
        asyncio.run(scanner.scan("127.0.0.1", 100, 1))  # fin < inicio
