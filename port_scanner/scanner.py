"""Nucleo del escaner de puertos, implementado sobre asyncio.

Se eligio asyncio por encima de threads o multiprocessing porque escanear
puertos es un problema I/O-bound (la mayor parte del tiempo se espera
respuesta de red, no se consume CPU). Con asyncio se pueden manejar miles
de conexiones concurrentes con una sola hebra, sin el overhead de memoria
y contexto que implican los threads del modulo `threading`.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from datetime import datetime, timezone

from .known_ports import lookup_service
from .models import PortResult, PortState, ScanReport

logger = logging.getLogger(__name__)


class PortScannerError(Exception):
    """Error de dominio para fallos del escaner (host invalido, etc.)."""


class PortScanner:
    """Escanea un rango de puertos TCP de un host de forma concurrente.

    Parameters
    ----------
    concurrency:
        Numero maximo de conexiones simultaneas. Un semaforo asyncio limita
        esto para no agotar file descriptors ni saturar la red local.
    timeout:
        Segundos a esperar por intento de conexion antes de marcar el
        puerto como filtrado.
    grab_banners:
        Si es True, intenta leer los primeros bytes que el servicio envia
        al conectar (util para identificar version de software).
    """

    def __init__(
        self,
        concurrency: int = 500,
        timeout: float = 1.0,
        grab_banners: bool = False,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency debe ser >= 1")
        if timeout <= 0:
            raise ValueError("timeout debe ser > 0")

        self.concurrency = concurrency
        self.timeout = timeout
        self.grab_banners = grab_banners
        self._semaphore = asyncio.Semaphore(concurrency)

    @staticmethod
    def resolve_host(target: str) -> str:
        """Resuelve un hostname a IPv4. Lanza PortScannerError si falla."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as exc:
            raise PortScannerError(f"No se pudo resolver el host: {target}") from exc

    async def _grab_banner(self, ip: str, port: int) -> str | None:
        """Intenta leer un banner corto del servicio. Falla en silencio."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=self.timeout
            )
            try:
                data = await asyncio.wait_for(reader.read(128), timeout=self.timeout)
                return data.decode(errors="replace").strip() or None
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None

    async def _scan_one(self, ip: str, port: int) -> PortResult:
        """Escanea un unico puerto respetando el limite de concurrencia."""
        async with self._semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()

                banner = await self._grab_banner(ip, port) if self.grab_banners else None
                return PortResult(
                    port=port,
                    state=PortState.OPEN,
                    service=lookup_service(port),
                    banner=banner,
                )
            except asyncio.TimeoutError:
                return PortResult(port=port, state=PortState.FILTERED)
            except ConnectionRefusedError:
                return PortResult(port=port, state=PortState.CLOSED)
            except OSError as exc:
                logger.debug("Error de socket en puerto %s: %s", port, exc)
                return PortResult(port=port, state=PortState.CLOSED)

    async def scan(
        self,
        target: str,
        start_port: int,
        end_port: int,
        on_progress: callable | None = None,
    ) -> ScanReport:
        """Escanea el rango [start_port, end_port] (inclusive) en `target`.

        `on_progress`, si se provee, se llama con (completados, total) tras
        cada puerto resuelto -- pensado para actualizar una barra de progreso
        sin acoplar este modulo a ninguna libreria de UI concreta.
        """
        if not (0 <= start_port <= end_port <= 65535):
            raise ValueError("Rango de puertos invalido (0-65535)")

        ip = self.resolve_host(target)
        started_at = datetime.now(timezone.utc)

        ports = range(start_port, end_port + 1)
        total = len(ports)
        completed = 0
        results: list[PortResult] = []

        tasks = [asyncio.create_task(self._scan_one(ip, p)) for p in ports]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            completed += 1
            if on_progress:
                on_progress(completed, total)

        results.sort(key=lambda r: r.port)

        return ScanReport(
            target=target,
            resolved_ip=ip,
            port_range=(start_port, end_port),
            started_at=started_at,
            finished_at=datetime.now(timezone.utc),
            results=results,
        )
