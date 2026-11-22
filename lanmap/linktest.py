"""Минутный тест связи: серии ping до устройства и до роутера одновременно — где теряются ответы.

Только чтение: ICMP-эхо раз в секунду, только адреса своей подсети. Две серии рядом показывают, на каком
участке беда: теряется уже до роутера — дело в связи этого компьютера (Wi-Fi, кабель) или в самом роутере;
до роутера чисто, а до устройства нет — участок до устройства (далеко от точки доступа, спит, перегружено).
Серия показывает наблюдения с этого компьютера и не измеряет скорость передачи данных.
"""
from __future__ import annotations

import concurrent.futures
import statistics
import time

SECONDS = 60
INTERVAL = 1.0
TIMEOUT_MS = 900
LOSS_BAD = 0.05     # больше 5 % потерь — плохо
SLOW_MS = 50        # медиана выше — устройство отвечает медленно (для домашней сети)


def series_stats(rtts: list[int | None]) -> dict:
    """Серия (мс или None — нет ответа) → отправлено, потеряно, медиана, худший ответ."""
    got = [r for r in rtts if r is not None]
    return {"sent": len(rtts), "lost": len(rtts) - len(got),
            "median": round(statistics.median(got), 1) if got else None, "max": max(got) if got else None}


def verdict(target: dict, gateway: dict | None) -> tuple[str, str]:
    """→ (уровень good|warn|crit, вывод человеческим языком)."""
    def loss(s):
        return s["lost"] / s["sent"] if s and s["sent"] else 0.0
    if target["sent"] and target["lost"] == target["sent"]:
        if gateway and loss(gateway) < 1:
            return "crit", "устройство не ответило ни разу, а роутер отвечает: оно выключено, спит или не отвечает на ping"
        return "crit", "ответов нет совсем: проверь связь этого компьютера"
    if gateway and loss(gateway) > LOSS_BAD:
        return "crit", "ответы теряются уже до роутера: дело в связи этого компьютера (Wi-Fi, кабель) или в роутере"
    if loss(target) > LOSS_BAD:
        return "warn", ("до роутера чисто, а до устройства ответы теряются: устройство далеко от точки доступа, "
                        "засыпает или перегружено")
    if (target["median"] or 0) > SLOW_MS:
        return "warn", "ответы доходят, но медленно: слабый Wi-Fi или устройство в режиме экономии"
    return "good", "связь в порядке: потерь почти нет, ответы быстрые"


def run(ip: str, gateway: str | None, seconds: int = SECONDS, echo=None, on_tick=None, sleep=time.sleep) -> dict:
    """Серии ping раз в INTERVAL секунд. gateway=None или совпал с ip — одна серия.

    echo(ip) → мс или None; on_tick(прогресс) — для страницы. → {"ip", "gateway", "target", "gw", "level", "text"}."""
    if echo is None:
        from lanmap.collectors import live
        echo = lambda a: live.icmp_rtt(a, TIMEOUT_MS)  # noqa: E731
    gw = gateway if gateway and gateway != ip else None
    rows: dict[str, list] = {"target": [], "gw": []}
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for i in range(seconds):
            t0 = time.monotonic()
            futs = {"target": pool.submit(echo, ip)}
            if gw:
                futs["gw"] = pool.submit(echo, gw)
            for name, f in futs.items():
                try:
                    rows[name].append(f.result())
                except Exception:
                    rows[name].append(None)
            if on_tick:
                on_tick({"done": i + 1, "total": seconds, "target": series_stats(rows["target"]),
                         "gw": series_stats(rows["gw"]) if gw else None})
            if i < seconds - 1:
                sleep(max(0.0, INTERVAL - (time.monotonic() - t0)))
    target = series_stats(rows["target"])
    gw_stats = series_stats(rows["gw"]) if gw else None
    level, text = verdict(target, gw_stats)
    return {"ip": ip, "gateway": gw, "target": target, "gw": gw_stats, "level": level, "text": text}


def line(name: str, s: dict | None) -> str:
    if not s:
        return ""
    med = f'{s["median"]:g} мс' if s["median"] is not None else "—"
    return f'{name}: медиана {med}, потеряно {s["lost"]} из {s["sent"]}' + (f', худший {s["max"]} мс' if s["max"] else "")
