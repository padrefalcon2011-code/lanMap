"""Сборщики улик. Все только читают: никаких паролей, записи настроек и эксплойтов.

Каждый сборщик получает ScanContext и работает только в пределах локальной подсети.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

USER_AGENT = "LanMap/0.0 (local read-only inventory)"


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

    def hosts(self) -> list[str]:
        return [str(ip) for ip in self.net.hosts()]
