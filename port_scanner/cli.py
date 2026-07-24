"""Interfaz de linea de comandos del escaner."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from .exporters import print_human_readable, print_progress, to_csv, to_json
from .scanner import PortScanner, PortScannerError


def _parse_port_range(value: str) -> tuple[int, int]:
    """Valida y parsea un rango 'inicio-fin' pasado por CLI."""
    try:
        start_str, end_str = value.split("-", maxsplit=1)
        start, end = int(start_str), int(end_str)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"'{value}' no es un rango valido. Usa el formato inicio-fin, p. ej. 1-1024"
        )
    if not (0 <= start <= end <= 65535):
        raise argparse.ArgumentTypeError("El rango debe estar entre 0 y 65535 (inicio <= fin)")
    return start, end


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description=(
            "Escaner de puertos TCP asincrono. "
            "Uso exclusivo en sistemas propios o con autorizacion explicita."
        ),
    )
    parser.add_argument("target", help="IP o hostname a escanear")
    parser.add_argument(
        "-p", "--ports", type=_parse_port_range, default=(1, 1024),
        metavar="INICIO-FIN", help="Rango de puertos (default: 1-1024)"
    )
    parser.add_argument(
        "-c", "--concurrency", type=int, default=500,
        help="Conexiones concurrentes maximas (default: 500)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Timeout por conexion en segundos (default: 1.0)"
    )
    parser.add_argument(
        "--banners", action="store_true",
        help="Intenta capturar el banner de cada servicio detectado (mas lento)"
    )
    parser.add_argument(
        "--detect-os", action="store_true",
        help="Estima el SO del objetivo mediante el TTL de un ping ICMP (heuristico)"
    )
    parser.add_argument(
        "--all", action="store_true", dest="show_all",
        help="Muestra tambien puertos cerrados/filtrados, no solo abiertos"
    )
    parser.add_argument("--json", metavar="ARCHIVO", help="Exporta el resultado a JSON")
    parser.add_argument("--csv", metavar="ARCHIVO", help="Exporta el resultado a CSV")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Activa logging detallado (debug)"
    )
    return parser


async def _run(args: argparse.Namespace) -> int:
    scanner = PortScanner(
        concurrency=args.concurrency,
        timeout=args.timeout,
        grab_banners=args.banners,
        detect_os=args.detect_os,
    )
    try:
        report = await scanner.scan(
            args.target, args.ports[0], args.ports[1], on_progress=print_progress
        )
    except PortScannerError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1

    print()  # separa la barra de progreso del reporte
    print_human_readable(report, show_all=args.show_all)

    if args.json:
        to_json(report, args.json)
        print(f"\n[+] Resultado exportado a {args.json}")
    if args.csv:
        to_csv(report, args.csv)
        print(f"[+] Resultado exportado a {args.csv}")

    return 0


def main() -> None:
    args = build_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    try:
        exit_code = asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario", file=sys.stderr)
        exit_code = 130
    sys.exit(exit_code)


if __name__ == "__main__":
    main()