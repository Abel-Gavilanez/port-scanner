"""Tabla estatica de puertos comunes y su servicio asociado.

No pretende ser exhaustiva (para eso existe /etc/services o la lista de IANA);
solo cubre los servicios que mas se ven en escaneos tipicos de practica.
"""

WELL_KNOWN_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    27017: "MongoDB",
}


def lookup_service(port: int) -> str | None:
    """Devuelve el nombre de servicio conocido para un puerto, si existe."""
    return WELL_KNOWN_PORTS.get(port)
