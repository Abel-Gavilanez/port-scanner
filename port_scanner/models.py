"""Modelos de datos usados en todo el paquete."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class PortState(str, Enum):
    """Estado posible de un puerto escaneado."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"  # timeout / sin respuesta -> probablemente filtrado por firewall


@dataclass(frozen=True, slots=True)
class PortResult:
    """Resultado del escaneo de un unico puerto."""

    port: int
    state: PortState
    service: str | None = None
    banner: str | None = None


@dataclass(slots=True)
class ScanReport:
    """Resumen completo de una sesion de escaneo, listo para exportar o imprimir."""

    target: str
    resolved_ip: str
    port_range: tuple[int, int]
    started_at: datetime
    finished_at: datetime | None = None
    results: list[PortResult] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def open_ports(self) -> list[PortResult]:
        return [r for r in self.results if r.state is PortState.OPEN]

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "port_range": list(self.port_range),
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "open_ports_count": len(self.open_ports),
            "results": [
                {
                    "port": r.port,
                    "state": r.state.value,
                    "service": r.service,
                    "banner": r.banner,
                }
                for r in self.results
            ],
        }
