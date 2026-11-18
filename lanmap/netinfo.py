"""Автоопределение локальных сетей компьютера (Windows) и прав администратора.

Ничего не прописано: интерфейс, адрес, маска, шлюз и собственный MAC берутся из системы.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import socket
import subprocess
from dataclasses import asdict, dataclass, field

from lanmap.util import norm_mac

# Больше этого числа адресов без явного разрешения не сканируем (защита от /16).
MAX_HOSTS_DEFAULT = 1022

_PS_INTERFACES = r"""
Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    ifIndex = $_.InterfaceIndex
    alias = $_.InterfaceAlias
    desc = $_.InterfaceDescription
    status = [string]$_.NetAdapter.Status
    mac = $_.NetAdapter.MacAddress
    hardware = [bool]$_.NetAdapter.HardwareInterface
    ipv4 = @($_.IPv4Address | ForEach-Object { [pscustomobject]@{ ip = $_.IPAddress; prefix = [int]$_.PrefixLength } })
    gateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
  }
} | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass
class LocalNet:
    if_index: int
    alias: str
    description: str
    local_ip: str
    prefix: int
    network: str
    gateway: str | None
    mac: str | None
    hardware: bool
    up: bool
    reasons_skipped: list[str] = field(default_factory=list)

    @property
    def net(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.network)

    @property
    def default_choice(self) -> bool:
        return not self.reasons_skipped

    def to_dict(self) -> dict:
        return asdict(self)


def run_powershell(script: str, timeout: int = 60) -> str:
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "[Console]::OutputEncoding=[Text.Encoding]::UTF8;" + script],
        capture_output=True, timeout=timeout,
    )
    return proc.stdout.decode("utf-8", "replace").strip()


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def list_networks() -> list[LocalNet]:
    """Все IPv4-сети на интерфейсах компьютера. Подходящие для среза — без reasons_skipped."""
    raw = run_powershell(_PS_INTERFACES)
    try:
        items = _as_list(json.loads(raw)) if raw else []
    except json.JSONDecodeError:
        items = []
    result: list[LocalNet] = []
    for item in items:
        gateways = [g for g in _as_list(item.get("gateway")) if g and g != "0.0.0.0"]
        for addr in _as_list(item.get("ipv4")):
            ip, prefix = addr.get("ip"), addr.get("prefix")
            if not ip or prefix is None:
                continue
            iface = ipaddress.ip_interface(f"{ip}/{prefix}")
            gw = next((g for g in gateways if ipaddress.ip_address(g) in iface.network), None)
            net = LocalNet(
                if_index=int(item.get("ifIndex")),
                alias=item.get("alias") or "",
                description=item.get("desc") or "",
                local_ip=ip,
                prefix=int(prefix),
                network=str(iface.network),
                gateway=gw,
                mac=norm_mac(item.get("mac")),
                hardware=bool(item.get("hardware")),
                up=(item.get("status") == "Up"),
            )
            reasons = net.reasons_skipped
            if not net.up:
                reasons.append("интерфейс отключён")
            if iface.ip.is_link_local:
                reasons.append("адрес APIPA 169.254.x.x — нет связи с сетью")
            elif not iface.ip.is_private:
                reasons.append("не частная сеть")
            if not net.hardware:
                reasons.append("виртуальный адаптер (Hyper-V, VPN и т. п.)")
            if not gw:
                reasons.append("нет шлюза по умолчанию")
            result.append(net)
    return result


def host_count(network: str) -> int:
    return max(ipaddress.ip_network(network).num_addresses - 2, 1)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def hostname() -> str:
    return socket.gethostname()
