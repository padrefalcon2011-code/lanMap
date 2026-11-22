"""Календарь наблюдений: когда устройство попадало в срезы — по последним HISTORY_LIMIT срезам той же сети.

Берутся только завершённые срезы этой же сети (snapshot.finished, snapshot.network_diff) с уже собранным
devices.json — старые срезы не пересобираются. Устройства сопоставляются с текущими тем же каскадом, что и
блок изменений (changes.match: ключ, серийник, MAC, адрес). Срезы делаются нерегулярно: пустой день —
это «не было замера», а не «не было устройства».
"""
from __future__ import annotations

from pathlib import Path

from lanmap import changes
from lanmap import snapshot as snap_mod
from lanmap.util import read_json

HISTORY_LIMIT = 30


def _older(snapshot: Path, limit: int) -> list[Path]:
    """Завершённые срезы той же сети, раньше этого, с devices.json → от старых к новым, не больше limit."""
    snapshot = Path(snapshot)
    me, mine = snap_mod.order_key(snapshot), snap_mod.network_id(snapshot)
    parent = snapshot.parent
    if not parent.is_dir():
        return []
    out = []
    for p in sorted((p for p in parent.iterdir() if p.is_dir() and snap_mod.is_snapshot_name(p.name)
                     and snap_mod.order_key(p) < me), key=snap_mod.order_key, reverse=True):
        m = snap_mod.meta(p)
        if (p / "devices.json").is_file() and snap_mod.finished(p, m) and not snap_mod.network_diff(
                mine, snap_mod.network_id(p, m)):
            out.append(p)
            if len(out) >= limit:
                break
    return out[::-1]


def observe(snapshot: Path, devices: list[dict], limit: int = HISTORY_LIMIT) -> dict:
    """→ {"snapshots": [дата срезов, старые → новые, последний — этот], "by_key": {ключ: {...}}}.

    У устройства: marks — по срезу «1» в сети, «0» известно, но не в сети, «·» не было; first — дата первого
    появления, last_alive — последнего раза в сети, seen — в скольких срезах было."""
    snaps = _older(snapshot, limit - 1)
    started = [(snap_mod.meta(p).get("started") or p.name)[:16] for p in snaps]
    started.append(((snap_mod.meta(snapshot).get("started")) or Path(snapshot).name)[:16])
    marks = {d["key"]: [] for d in devices}
    for p in snaps:
        try:
            old = (read_json(p / "devices.json", {}) or {}).get("devices") or []
        except ValueError:
            old = []
        pairs, _gone, _new = changes.match(old, devices)
        here = {new["key"]: old_dev for old_dev, new in pairs}
        for d in devices:
            o = here.get(d["key"])
            marks[d["key"]].append("·" if o is None else ("1" if o.get("alive") else "0"))
    out = {}
    for d in devices:
        row = marks[d["key"]] + ["1" if d.get("alive") else "0"]
        seen = [i for i, x in enumerate(row) if x != "·"]
        alive = [i for i, x in enumerate(row) if x == "1"]
        out[d["key"]] = {"marks": "".join(row), "seen": len(seen),
                         "first": started[seen[0]] if seen else None,
                         "last_alive": started[alive[-1]] if alive else None}
    return {"snapshots": started, "by_key": out}
