# Port Scanner
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Tests](https://github.com/Abel-Gavilanez/port-scanner/actions/workflows/tests.yml/badge.svg)

Escáner de puertos TCP asíncrono, escrito en Python puro (sin dependencias
externas para el núcleo). Proyecto educativo para practicar sockets,
`asyncio` y diseño de herramientas de línea de comandos en el contexto de
ciberseguridad.

> ⚠️ **Uso ético únicamente.** Escanea solo sistemas de tu propiedad o para
> los que tengas autorización explícita por escrito. Escanear redes ajenas
> sin permiso puede constituir un delito según la legislación de tu país
> (en Ecuador, por ejemplo, bajo el COIP – delitos informáticos).

## Características

- **Concurrencia con `asyncio`** en vez de threads: miles de puertos se
  escanean con una sola hebra, usando un semáforo para limitar conexiones
  simultáneas.
- **Detección de servicio** contra una tabla de puertos conocidos.
- **Banner grabbing opcional** (`--banners`): intenta leer lo que el
  servicio responde al conectar, útil para identificar versiones.
- **Exportación** a JSON y CSV para integrarlo en otros flujos o reportes.
- **Arquitectura en capas**: modelos, lógica de escaneo, exportadores y CLI
  están separados, cada uno con una única responsabilidad.
- **Pruebas unitarias** con `pytest` y `pytest-asyncio`.

## Instalación

```bash
git clone https://github.com/Abel-Gavilanez/port-scanner.git
cd port-scanner
pip install -e ".[dev]"
```

## Uso

```bash
# Escaneo básico (puertos 1-1024 por defecto)
python run_scanner.py 127.0.0.1

# Rango personalizado y más concurrencia
python run_scanner.py scanme.nmap.org -p 1-1000 -c 300

# Con banner grabbing y exportación
python run_scanner.py 127.0.0.1 -p 1-1024 --banners --json resultado.json --csv resultado.csv

# Instalado como comando (tras pip install -e .)
port-scanner 127.0.0.1 -p 1-500
```
### Ejemplo de salida

<img width="953" height="272" alt="image" src="https://github.com/user-attachments/assets/022c8b02-9359-48bd-8613-864ad4694389" />


### Opciones principales

| Flag             | Descripción                                         | Default |
|------------------|------------------------------------------------------|---------|
| `-p, --ports`    | Rango de puertos `inicio-fin`                        | `1-1024`|
| `-c, --concurrency` | Conexiones concurrentes máximas                    | `500`   |
| `--timeout`      | Timeout por conexión (segundos)                       | `1.0`   |
| `--banners`      | Captura el banner del servicio (más lento)            | off     |
| `--all`          | Muestra también puertos cerrados/filtrados            | off     |
| `--json ARCHIVO` | Exporta resultados a JSON                             | -       |
| `--csv ARCHIVO`  | Exporta resultados a CSV                              | -       |
| `-v, --verbose`  | Logging detallado (debug)                             | off     |

## Estructura del proyecto

```
port_scanner_pro/
├── port_scanner/
│   ├── __init__.py       # API pública del paquete
│   ├── models.py         # PortResult, ScanReport, PortState (dataclasses/enum)
│   ├── known_ports.py    # Tabla de puertos comunes
│   ├── scanner.py        # Lógica de escaneo asíncrona (PortScanner)
│   ├── exporters.py      # Salida human-readable, JSON y CSV
│   └── cli.py            # argparse + entry point
├── tests/
│   └── test_scanner.py
├── run_scanner.py         # Punto de entrada directo
├── pyproject.toml
└── README.md
```

## Por qué asyncio y no threads

Escanear puertos es un problema **I/O-bound**: la mayor parte del tiempo
se pasa esperando respuesta de red, no usando CPU. `asyncio` permite manejar
miles de conexiones concurrentes con una sola hebra y mucho menos overhead
de memoria que `threading`, que es la alternativa típica en scripts más
sencillos.

## Ejecutar pruebas

```bash
pytest tests/ -v
```

## Posibles mejoras futuras

- Escaneo UDP (requiere una estrategia distinta, ya que UDP no tiene
  handshake de conexión).
- Detección de versión de servicio más sofisticada (fingerprinting tipo
  `nmap -sV`, comparando banners contra firmas conocidas).
- Modo de salida `--quiet` para integrarse en pipelines/scripts.
- Rate limiting configurable para evitar saturar redes sensibles.

## Licencia

[MIT](LICENSE) — libre para usar con fines educativos.
