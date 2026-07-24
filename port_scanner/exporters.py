"""Exportadores de ScanReport a distintos formatos."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

from .models import ScanReport


def to_json(report: ScanReport, path: str | Path | None = None) -> str:
    """Serializa el reporte a JSON. Si `path` se indica, tambien lo escribe a disco."""
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if path is not None:
        Path(path).write_text(payload, encoding="utf-8")
    return payload


def to_csv(report: ScanReport, path: str | Path) -> None:
    """Escribe los resultados a un archivo CSV (uno por puerto)."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["port", "state", "service", "banner"])
        for r in report.results:
            writer.writerow([r.port, r.state.value, r.service or "", r.banner or ""])


def print_human_readable(report: ScanReport, show_all: bool = False) -> None:
    """Imprime el reporte en un formato legible por humanos en stdout."""
    print("=" * 56)
    print(f"  Objetivo:   {report.target} ({report.resolved_ip})")
    print(f"  Rango:      {report.port_range[0]}-{report.port_range[1]}")
    print(f"  Duracion:   {report.duration_seconds:.2f}s")
    if report.os_guess is not None:
        print(f"  SO estimado: {report.os_guess.summary}")
    print("=" * 56)

    rows = report.results if show_all else report.open_ports
    if not rows:
        print("\nNo se encontraron puertos abiertos en el rango especificado.")
        return

    print(f"\n{'PUERTO':<10}{'ESTADO':<12}{'SERVICIO':<15}BANNER")
    for r in rows:
        banner = (r.banner or "")[:40]
        print(f"{r.port:<10}{r.state.value:<12}{(r.service or '-'):<15}{banner}")

    print(f"\n{len(report.open_ports)} puerto(s) abierto(s) de {len(report.results)} escaneados.")


def print_progress(completed: int, total: int) -> None:
    """Callback de progreso simple para usar con PortScanner.scan(on_progress=...)."""
    pct = (completed / total) * 100 if total else 100
    sys.stdout.write(f"\r[*] Progreso: {completed}/{total} ({pct:5.1f}%)")
    sys.stdout.flush()
    if completed == total:
        sys.stdout.write("\n")