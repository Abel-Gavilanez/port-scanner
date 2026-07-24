"""Pruebas unitarias del modulo de deteccion de SO por TTL."""

import pytest

from port_scanner.os_detection import OsGuess, _estimate_os_from_ttl, detect_os_by_ttl


@pytest.mark.parametrize(
    "observed_ttl,expected_os",
    [
        (64, "Linux / Unix / macOS"),
        (60, "Linux / Unix / macOS"),  # unos saltos de red por debajo de 64
        (128, "Windows"),
        (120, "Windows"),  # unos saltos de red por debajo de 128
        (255, "Equipo de red (router/switch, ej. Cisco)"),
    ],
)
def test_estimate_os_from_ttl(observed_ttl, expected_os):
    guess = _estimate_os_from_ttl(observed_ttl)
    assert guess.guessed_os == expected_os


def test_estimate_os_from_ttl_out_of_range():
    # Un TTL mayor a 255 no deberia ocurrir nunca en la practica (es el
    # maximo del campo en IPv4), pero el codigo no debe reventar si pasa.
    guess = _estimate_os_from_ttl(300)
    assert guess.guessed_os is None


@pytest.mark.asyncio
async def test_detect_os_by_ttl_against_localhost():
    guess = await detect_os_by_ttl("127.0.0.1", timeout=2.0)
    # No afirmamos un SO especifico (depende de donde corran los tests),
    # solo que el ping a localhost SIEMPRE debe responder con algun TTL.
    assert guess.observed_ttl is not None


@pytest.mark.asyncio
async def test_detect_os_by_ttl_unreachable_host():
    # Una IP de red privada casi con certeza sin host detras -> sin respuesta.
    guess = await detect_os_by_ttl("10.255.255.1", timeout=0.5)
    assert guess.observed_ttl is None
    assert guess.guessed_os is None


def test_os_guess_summary_unknown():
    guess = OsGuess(None, None, None)
    assert "Desconocido" in guess.summary


def test_os_guess_summary_known():
    guess = OsGuess(observed_ttl=64, estimated_initial_ttl=64, guessed_os="Linux / Unix / macOS")
    assert "Linux" in guess.summary
    assert "64" in guess.summary