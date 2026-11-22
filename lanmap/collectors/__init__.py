"""Сборщики улик. Все только читают: никаких паролей, записи настроек и эксплойтов.

Каждый сборщик получает ScanContext и работает только в пределах локальной подсети.
"""
from __future__ import annotations

import ipaddress
import urllib.parse
from dataclasses import dataclass

USER_AGENT = "LanMap/0.0 (local read-only inventory)"

HTTP = {"http": 80, "https": 443}  # схема → порт по умолчанию


def url_target(url, schemes: dict[str, int] = HTTP) -> tuple[str, int] | None:
    """Хост и порт из адреса, который прислало устройство (SSDP LOCATION, WS-Discovery XAddrs, ответы SOAP).
    Кривой адрес («http://[»), чужая схема, порт не число или вне 1–65535 — None: такая запись пропускается,
    а не обрывает сбор."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        return None
    try:
        parts = urllib.parse.urlsplit(url.strip())
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in schemes or not host:
        return None
    if port is None:
        port = schemes[scheme]
    if not 1 <= port <= 65535:
        return None
    return host, port


@dataclass
class ScanContext:
    local_ip: str
    network: str
    gateway: str | None
    if_index: int
    local_mac: str | None = None

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.network)

    def in_scope(self, host: str | None) -> bool:
        """Адрес внутри сканируемой подсети. Имена и чужие адреса не допускаются."""
        if not host:
            return False
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return False
        return ip in self.net and ip not in (self.net.network_address, self.net.broadcast_address)

    def url_in_scope(self, url, schemes: dict[str, int] = HTTP) -> tuple[str, int] | None:
        """url_target, и хост — внутри сканируемой подсети. Иначе None."""
        target = url_target(url, schemes)
        return target if target and self.in_scope(target[0]) else None

    def hosts(self) -> list[str]:
        return [str(ip) for ip in self.net.hosts()]
