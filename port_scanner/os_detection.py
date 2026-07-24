"""Deteccion heuristica de sistema operativo mediante TTL (Time To Live).

Estrategia (la misma idea de fondo que usa nmap en su modo simplificado):

1. Se envia un ping ICMP al host objetivo usando el comando `ping` del
   sistema operativo (no requiere sockets crudos ni privilegios de
   administrador, a diferencia de un escaneo de flags TCP personalizados).
2. Se extrae el TTL de la respuesta.
3. Como el TTL disminuye en 1 por cada salto de red (router) que el
   paquete atraviesa, se estima el TTL *inicial* redondeando el valor
   observado hacia arriba, al techo tipico mas cercano (64, 128, 255).
4. Se compara ese techo estimado contra una tabla de sistemas operativos
   conocidos por usar ese valor de salida.

Limitaciones importantes (indicarlas es parte de hacer esto bien):
- Es una heuristica, no una deteccion certera. Nmap real cruza muchas
  mas senales (ventana TCP, opciones, orden de flags, etc.).
- Firewalls que bloquean ICMP hacen que esto no arroje resultado.
- Redes con NAT o VPNs pueden alterar el TTL observado.
"""

from __future__ import annotations

import asyncio
import platform
import re
import subprocess
from dataclasses import dataclass

# TTL inicial tipico por familia de SO. Los valores reales que se observan
# son siempre <= al inicial, porque decrecen con cada salto de red.
_TTL_CEILINGS: dict[int, str] = {
    64: "Linux / Unix / macOS",
    128: "Windows",
    255: "Equipo de red (router/switch, ej. Cisco)",
}

_TTL_PATTERN = re.compile(r"ttl[=:]\s*(\d+)", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class OsGuess:
    """Resultado de la estimacion de SO. Todos los campos son None si el
    host no respondio al ping (comun cuando ICMP esta bloqueado)."""

    observed_ttl: int | None
    estimated_initial_ttl: int | None
    guessed_os: str | None

    @property
    def summary(self) -> str:
        if self.guessed_os is None:
            return "Desconocido (sin respuesta ICMP o TTL atipico)"
        return f"{self.guessed_os} (TTL observado: {self.observed_ttl}, estimado inicial: {self.estimated_initial_ttl})"


def _estimate_os_from_ttl(ttl: int) -> OsGuess:
    for ceiling in sorted(_TTL_CEILINGS):
        if ttl <= ceiling:
            return OsGuess(ttl, ceiling, _TTL_CEILINGS[ceiling])
    return OsGuess(ttl, None, None)


def _build_ping_command(host: str) -> list[str]:
    """Arma el comando de ping segun el SO donde CORRE el escaner (no el objetivo)."""
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", "1000", host]
    return ["ping", "-c", "1", "-W", "1", host]


def _run_ping_blocking(command: list[str], timeout: float) -> str:
    """Ejecuta el ping de forma bloqueante (pensado para correr en un hilo aparte).

    Se usa `subprocess.run` en vez de `asyncio.create_subprocess_exec` a
    proposito: en Windows, el subprocess transport del Proactor event loop
    de asyncio tiene un bug conocido de limpieza (genera un
    `PytestUnraisableExceptionWarning` / `ValueError: I/O operation on
    closed pipe` benigno pero molesto al cerrar el event loop). Usando
    `subprocess.run` dentro de un hilo (`asyncio.to_thread`) evitamos ese
    problema por completo, en cualquier sistema operativo.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


async def detect_os_by_ttl(host: str, timeout: float = 2.0) -> OsGuess:
    """Hace ping al host y estima su familia de SO a partir del TTL de la respuesta."""
    command = _build_ping_command(host)
    stdout = await asyncio.to_thread(_run_ping_blocking, command, timeout)

    match = _TTL_PATTERN.search(stdout)
    if not match:
        return OsGuess(None, None, None)

    return _estimate_os_from_ttl(int(match.group(1)))