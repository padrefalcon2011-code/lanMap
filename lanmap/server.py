"""Локальный веб-интерфейс: отчёт последнего среза с кнопками вместо команд.

Слушает только петлевой адрес этого компьютера. Вход — по одноразовому токену из ссылки, которую печатает
`python -m lanmap serve`: токен меняется при каждом запуске, браузер запоминает его в cookie этого порта.
Кнопки пишут только в data/ (реестр, отметки находок и чек-листа) и запускают срез; на устройствах сети
ничего не меняется.
"""
from __future__ import annotations

import hmac
import json
import secrets
import threading
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from lanmap import ops

LOOPBACK = "127.0.0.1"
DEFAULT_PORT = 7480  # вне диапазонов, которые Windows часто резервирует под Hyper-V (8000–9500)
MAX_BODY = 64 * 1024


class Watcher:
    """«Найти устройство»: фоновый опрос раз в INTERVAL секунд, пока страница спрашивает состояние.
    Закрыли вкладку — через IDLE_STOP секунд опрос останавливается сам."""

    INTERVAL = 2.0
    IDLE_STOP = 20.0

    def __init__(self, setup=None):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.last_poll = time.monotonic()
        self.status, self.error, self.router_note = "starting", None, None
        self.presence = None
        self._setup = setup or _live_setup
        threading.Thread(target=self._run, daemon=True, name="lanmap-watch").start()

    def touch(self) -> None:
        self.last_poll = time.monotonic()

    @property
    def alive(self) -> bool:
        return self.status in ("starting", "running") and not self.stop.is_set()

    def state(self) -> dict:
        with self.lock:
            out = {"status": self.status, "error": self.error, "router": self.router_note, "now": time.time(),
                   "interval": self.INTERVAL}
            if self.presence:
                out.update(self.presence.state())
            return out

    def _run(self) -> None:
        live = None
        try:
            live = self._setup()
            with self.lock:
                self.presence, self.router_note, self.status = live["presence"], live.get("router_note"), "running"
            name_new = live.get("name_new") or (lambda ip, mac: "Новое устройство")
            cycle, clients = 0, None
            while not self.stop.is_set() and time.monotonic() - self.last_poll < self.IDLE_STOP:
                t0 = time.monotonic()
                ping = live["sweep"](live["targets"](cycle))
                if live.get("router"):
                    try:
                        clients = live["router"]()
                        note = None
                    except Exception as exc:  # один сбой роутера не должен «гасить» все телефоны: берём прошлый список
                        note = f"роутер не ответил: {exc}"
                    with self.lock:
                        self.router_note = note
                with self.lock:
                    self.presence.update(ping, clients, time.time(), name_new)
                cycle += 1
                self.stop.wait(max(0.2, self.INTERVAL - (time.monotonic() - t0)))
        except BaseException as exc:  # показать в интерфейсе, а не уронить поток молча
            with self.lock:
                self.error = str(exc) or exc.__class__.__name__
        finally:
            with self.lock:
                self.status = "stopped"
            if live and live.get("close"):
                live["close"]()


def _live_setup() -> dict:
    """Настоящий опрос: своя подсеть, устройства последнего среза, роутер — если подключён."""
    from lanmap import oui, routers
    from lanmap.collectors import ScanContext, discovery, live
    net = ops.pick_network()
    ctx = ScanContext(local_ip=net.local_ip, network=net.network, gateway=net.gateway, if_index=net.if_index,
                      local_mac=net.mac)
    try:
        devices = ops.latest()[1].get("devices", [])
    except ops.OpError:
        devices = []
    poll, note = routers.presence(ctx.gateway) if ctx.gateway else (None, "шлюз не найден")
    prober = live.Prober(ctx)
    hosts = [ip for ip in ctx.hosts() if ip != ctx.local_ip]
    presence = live.Presence(devices, ctx.local_ip,
                             mac_of=lambda ip: discovery._send_arp((ip, ctx.local_ip)).get("mac"))

    def targets(cycle: int) -> list[str]:
        # /24 — вся подсеть каждый цикл; большая сеть — знакомые адреса, а вся подсеть раз в 10 циклов
        if len(hosts) <= 256 or cycle % 10 == 0:
            return hosts
        return presence.known_ips()

    def name_new(ip, mac) -> str:
        vendor = oui.short_vendor(oui.lookup(mac)) if mac else None
        return f"Новое: {vendor}" if vendor else "Новое устройство"

    return {"presence": presence, "sweep": lambda ips: prober.sweep(ips, set(presence.by_ip)), "targets": targets, "router": poll,
            "router_note": None if poll else note, "name_new": name_new, "close": prober.close}


class Job:
    """Фоновое действие с ходом для страницы (скачать базу IEEE, собрать паспорт роутера): одно за раз."""

    def __init__(self):
        self.lock = threading.Lock()
        self.data = {"running": False, "error": None, "result": None}

    def status(self) -> dict:
        with self.lock:
            return dict(self.data)

    def start(self, fn) -> bool:
        with self.lock:
            if self.data["running"]:
                return False
            self.data = {"running": True, "error": None, "result": None, "started": time.time()}
        threading.Thread(target=self._run, args=(fn,), daemon=True, name="lanmap-job").start()
        return True

    def update(self, **kw) -> None:
        """Ход долгого действия — страница видит его при опросе (тест связи)."""
        with self.lock:
            self.data.update(kw)

    def _run(self, fn) -> None:
        try:
            out = {"result": fn()}
        except ops.OpError as exc:
            out = {"error": str(exc)}
        except BaseException as exc:  # показать в интерфейсе, а не уронить поток молча
            out = {"error": f"Ошибка LanMap: {exc or exc.__class__.__name__}"}
        with self.lock:
            self.data.update(out, running=False)


class State:
    """Состояние сервера: токен, замок на запись в data/, ход среза, «Найти устройство»."""

    def __init__(self, token: str, live_setup=None):
        self.token = token
        self.live_setup = live_setup
        self.watcher: Watcher | None = None
        self.watch_lock = threading.Lock()
        self.write_lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.scan = {"running": False, "stages": [], "error": None, "snapshot": None}
        self.jobs = {"oui": Job(), "probe": Job(), "link": Job()}

    def scan_status(self) -> dict:
        with self.scan_lock:
            s = dict(self.scan)
            s["stages"] = list(s["stages"])
            return s

    def start_scan(self) -> bool:
        with self.scan_lock:
            if self.scan["running"]:
                return False
            self.scan = {"running": True, "stages": [], "error": None, "snapshot": None, "started": time.time()}
        threading.Thread(target=self._scan, daemon=True, name="lanmap-scan").start()
        return True

    def start_watch(self) -> Watcher:
        with self.watch_lock:
            if self.watcher is None or not self.watcher.alive:
                self.watcher = Watcher(self.live_setup)
            self.watcher.touch()
            return self.watcher

    def watch_state(self) -> dict:
        with self.watch_lock:
            w = self.watcher
        if w is None:
            return {"status": "stopped"}
        w.touch()
        return w.state()

    def stop_watch(self) -> None:
        with self.watch_lock:
            if self.watcher:
                self.watcher.stop.set()

    def oui_update(self) -> dict:
        with self.write_lock:
            return ops.oui_update()

    def _step(self, text: str) -> None:
        with self.scan_lock:
            self.scan["stages"].append(text)

    def _scan(self) -> None:
        from lanmap.build import build
        from lanmap.scan import run_scan
        try:
            net = ops.pick_network()
            snap = run_scan(net, on_step=self._step)
            self._step("Опознание и отчёт")
            with self.write_lock:
                build(snap)
            result = {"snapshot": snap.name}
        except BaseException as exc:  # срез в фоне: любую ошибку показать в интерфейсе, а не уронить поток молча
            result = {"error": str(exc) or exc.__class__.__name__}
        with self.scan_lock:
            self.scan.update(result, running=False)


def _report_path() -> Path | None:
    """Отчёт последнего собранного среза — того же, в который пишут кнопки (ops.latest)."""
    from lanmap.scan import latest_snapshot
    snap = latest_snapshot(complete=True)
    return snap / "report.html" if snap and (snap / "report.html").exists() else None


class Handler(BaseHTTPRequestHandler):
    server_version = "LanMap"
    state: State  # задаётся в make_server

    # --- проверки ---------------------------------------------------------------------------

    def _host_ok(self) -> bool:
        """Защита от DNS-rebinding: чужой сайт, подменивший свой адрес на петлевой, придёт с чужим Host."""
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"{LOOPBACK}:{port}", f"localhost:{port}")

    def _cookie_name(self) -> str:
        return f"lanmap_{self.server.server_address[1]}"

    def _cookie_ok(self) -> bool:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            return False
        morsel = jar.get(self._cookie_name())
        return bool(morsel) and hmac.compare_digest(morsel.value, self.state.token)

    def _header_ok(self) -> bool:
        """Запросы API несут токен в своём заголовке: чужая страница так не может без разрешения CORS."""
        return hmac.compare_digest(self.headers.get("X-LanMap-Token", ""), self.state.token)

    # --- ответы -----------------------------------------------------------------------------

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code: int, data: dict) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _text(self, code: int, text: str) -> None:
        self._send(code, text.encode("utf-8"), "text/plain; charset=utf-8")

    def log_message(self, fmt: str, *args) -> None:
        # Стандартный журнал печатает строку запроса целиком — вместе с токеном из ссылки. Печатаем без неё.
        if args and isinstance(args[0], str) and " " in args[0]:
            parts = args[0].split(" ")
            args = (f"{parts[0]} {urlsplit(parts[1]).path}",) + args[1:]
        super().log_message(fmt, *args)

    # --- маршруты ---------------------------------------------------------------------------

    def do_OPTIONS(self) -> None:  # предзапрос CORS: не разрешаем никому
        self._text(403, "forbidden")

    def do_GET(self) -> None:
        if not self._host_ok():
            return self._text(403, "Неверный адрес. Открой ссылку, которую напечатал python -m lanmap serve.")
        url = urlsplit(self.path)
        if url.path == "/":
            given = parse_qs(url.query).get("t", [""])[0]
            if given:
                if not hmac.compare_digest(given, self.state.token):
                    return self._text(403, "Ссылка устарела: открой новую из окна python -m lanmap serve.")
                cookie = f"{self._cookie_name()}={self.state.token}; Path=/; HttpOnly; SameSite=Strict"
                return self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
            if not self._cookie_ok():
                return self._text(403, "Нет доступа. Открой ссылку, которую напечатал python -m lanmap serve.")
            return self._page()
        if url.path.startswith("/api/"):
            if not self._header_ok():
                return self._json(403, {"error": "нет доступа"})
            if url.path == "/api/scan":
                return self._json(200, self.state.scan_status())
            if url.path == "/api/watch":
                return self._json(200, self.state.watch_state())
            if url.path == "/api/oui":
                return self._json(200, {**ops.oui_status(), **self.state.jobs["oui"].status()})
            if url.path == "/api/probe":
                return self._json(200, self.state.jobs["probe"].status())
            if url.path == "/api/link":
                return self._json(200, self.state.jobs["link"].status())
            if url.path == "/api/router":
                try:
                    return self._json(200, ops.router_status())
                except ops.OpError as exc:
                    return self._json(400, {"error": str(exc)})
            return self._json(404, {"error": "не найдено"})
        self._text(404, "не найдено")

    def _page(self) -> None:
        path = _report_path()
        if path:
            html = path.read_text("utf-8")
        else:
            from lanmap.report import empty_page
            html = empty_page()
        boot = f"<script>window.LANMAP={json.dumps({'token': self.state.token})};</script>"
        html = html.replace("<head>", "<head>" + boot, 1) if "<head>" in html else boot + html
        self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        if not self._host_ok() or not self._header_ok():
            return self._json(403, {"error": "нет доступа"})
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            return self._json(415, {"error": "нужен JSON"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = -1
        if not 0 <= size <= MAX_BODY:
            return self._json(413, {"error": "слишком большой запрос"})
        try:
            body = json.loads(self.rfile.read(size) or b"{}")
        except ValueError:
            return self._json(400, {"error": "испорченный JSON"})
        if not isinstance(body, dict):
            return self._json(400, {"error": "нужен объект JSON"})
        route = urlsplit(self.path).path
        if route == "/api/shutdown":
            if self.state.scan_status()["running"]:
                return self._json(409, {"error": "Идёт срез — выключить можно, когда он закончится"})
            self.state.stop_watch()
            self._json(200, {"ok": True})
            # Остановить сервер из его же обработчика можно только из другого потока
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return None
        if route == "/api/scan":
            started = self.state.start_scan()
            return self._json(202 if started else 409, self.state.scan_status())
        if route == "/api/watch":
            if body.get("stop"):
                self.state.stop_watch()
                return self._json(200, {"status": "stopping"})
            return self._json(202, self.state.start_watch().state())
        if route in ("/api/oui", "/api/probe"):
            if self.state.scan_status()["running"]:
                return self._json(409, {"error": "Идёт срез — подожди, пока он закончится"})
            job = self.state.jobs[route[5:]]
            started = job.start(self.state.oui_update if route == "/api/oui" else ops.router_probe)
            return self._json(202 if started else 409, job.status())
        if route == "/api/router/login":
            return self._router_login(body)
        if route == "/api/router/forget":
            try:
                removed = ops.router_forget()
            except ops.OpError as exc:
                return self._json(400, {"error": str(exc)})
            except OSError as exc:
                return self._json(500, {"error": f"Ошибка LanMap: {exc}"})
            self.state.stop_watch()  # «Найти устройство» перезапустится уже без роутера
            return self._json(200, {"ok": True, "removed": removed})
        if route.startswith("/api/camera/"):
            return self._camera(route[len("/api/camera/"):], body)
        if route == "/api/launch":
            return self._launch(body)
        if route == "/api/ai/check":
            return self._ai_check(body)
        if route == "/api/link":  # минутный тест связи: только ICMP, отчёт не пересобирает
            job = self.state.jobs["link"]
            try:
                ip = self._str(body, "ip")
                ops.link_target(ip)  # проверка адреса заранее: ошибка — сразу, а не в фоне
            except ops.OpError as exc:
                return self._json(400, {"error": str(exc)})
            started = job.start(lambda: ops.link_test(ip, on_tick=lambda p: job.update(progress=p)))
            if started:
                job.update(ip=ip)
            return self._json(202 if started else 409, job.status())
        if route == "/api/ipcheck":  # только читает сеть, отчёт не пересобирает
            try:
                return self._json(200, {"ok": True, **ops.ip_check(self._str(body, "ip"))})
            except ops.OpError as exc:
                return self._json(400, {"error": str(exc)})
            except Exception as exc:
                return self._json(500, {"error": f"Ошибка LanMap ({exc.__class__.__name__})"})
        action = {"/api/sign": self._sign, "/api/finding": self._finding, "/api/check": self._check,
                  "/api/recheck": self._recheck, "/api/ai/apply": self._ai_apply}.get(route)
        if not action:
            return self._json(404, {"error": "не найдено"})
        if self.state.scan_status()["running"]:
            return self._json(409, {"error": "Идёт срез — отметку можно сделать, когда он закончится"})
        try:
            with self.state.write_lock:
                result = action(body)
                ops.rebuild()
        except ops.OpError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:  # иначе соединение просто рвётся, и страница решит, что сервер закрыт
            return self._json(500, {"error": f"Ошибка LanMap: {exc}"})
        self._json(200, {"ok": True, **result})

    def _router_login(self, body: dict) -> None:
        """Пароль из формы проверяется входом в роутер и уходит в диспетчер учётных данных Windows. Он не
        пишется в журнал (тела запросов не журналируются), не возвращается и не попадает в текст ошибки."""
        user, password = body.get("user"), body.get("password")
        if not isinstance(user, str) or not isinstance(password, str) or not user.strip() or not password                 or len(user) > 200 or len(password) > 500:
            return self._json(400, {"error": "Нужны логин и пароль"})
        try:
            saved = ops.router_login(user.strip(), password)
        except ops.OpError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:  # текст ошибки не показываем: мало ли что в нём окажется
            return self._json(500, {"error": f"Ошибка LanMap при входе в роутер ({exc.__class__.__name__})"})
        self.state.stop_watch()  # «Найти устройство» перезапустится уже с роутером
        try:
            reads = ops.router_test(saved["host"])
        except Exception:
            reads = []
        return self._json(200, {"ok": True, **saved, "reads": reads})

    def _camera(self, what: str, body: dict) -> None:
        """Стоп-кадр: только чтение, без пересборки отчёта. Кадр живёт только в ответе (base64 в JSON), на диск
        не пишется. Пароль из формы — как у роутера: в диспетчер учётных данных, не в ответ и не в ошибку."""
        import base64
        try:
            key = self._str(body, "key")
            if what == "snapshot":
                image = ops.camera_snapshot(key)
                return self._json(200, {"ok": True, "image": base64.b64encode(image).decode()})
            if what == "login":
                user, password = body.get("user"), body.get("password")
                if not isinstance(user, str) or not isinstance(password, str) or not user.strip() or not password                         or len(user) > 200 or len(password) > 500:
                    return self._json(400, {"error": "Нужны логин и пароль"})
                saved, image = ops.camera_login(key, user.strip(), password)
                return self._json(200, {"ok": True, "login": saved["login"], "image": base64.b64encode(image).decode()})
            if what == "forget":
                return self._json(200, {"ok": True, "removed": ops.camera_forget(key)})
        except ops.OpError as exc:
            return self._json(400, {"error": str(exc), "need_login": isinstance(exc, ops.NeedLogin)})
        except Exception as exc:  # текст ошибки не показываем: в нём мог оказаться адрес кадра
            return self._json(500, {"error": f"Ошибка LanMap при работе с камерой ({exc.__class__.__name__})"})
        return self._json(404, {"error": "не найдено"})

    def _launch(self, body: dict) -> None:
        """Запуск программы из карточки (lanmap/launch.py). Со страницы — только ключ устройства и имя действия;
        адрес, порт и команду сервер берёт из последнего среза. Отчёт не пересобирается."""
        from lanmap import launch
        try:
            key, action = self._str(body, "key"), self._str(body, "action")
            if action not in launch.ACTIONS:
                return self._json(400, {"error": "Неизвестное действие"})
            result = ops.launch(key, action, ack=body.get("ack") is True)
        except ops.OpError as exc:
            return self._json(400, {"error": str(exc), "url": getattr(exc, "url", None),
                                    "need_ack": bool(getattr(exc, "need_ack", False))})
        except Exception as exc:  # текст ошибки не показываем: в нём мог оказаться адрес потока
            return self._json(500, {"error": f"Ошибка LanMap при запуске ({exc.__class__.__name__})"})
        return self._json(200, {"ok": True, **result})

    def _ai_check(self, body: dict) -> None:
        """«Разобрать с ИИ»: проверить вставленный ответ ИИ и показать, что будет записано. Ничего не пишет."""
        try:
            answer = body.get("answer")
            if not isinstance(answer, str):
                raise ops.OpError("Нет ответа ИИ")
            return self._json(200, {"ok": True, **ops.ai_check(self._str(body, "key"), answer)})
        except ops.OpError as exc:
            return self._json(400, {"error": str(exc)})
        except Exception as exc:
            return self._json(500, {"error": f"Ошибка LanMap ({exc.__class__.__name__})"})

    def _ai_apply(self, body: dict) -> dict:
        """Подтверждение владельца: ответ проверяется заново, ключ — со страницы, не из ответа."""
        answer = body.get("answer")
        if not isinstance(answer, str):
            raise ops.OpError("Нет ответа ИИ")
        done = ops.ai_apply(self._str(body, "key"), answer, to_registry=body.get("registry") is True,
                            save_rule=body.get("rule") is True)
        return {"key": done["key"], "rule": done["rule"], "registry": bool(done["registry"])}

    @staticmethod
    def _str(body: dict, name: str, required: bool = True) -> str | None:
        value = body.get(name)
        if value is None and not required:
            return None
        if not isinstance(value, str) or (required and not value.strip()) or len(value) > 500:
            raise ops.OpError(f"Поле {name}: нужна строка до 500 символов")
        return value.strip()

    def _sign(self, body: dict) -> dict:
        fields = body.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise ops.OpError("Нет полей для подписи")
        clean = {k: self._str(fields, k) if fields[k] != "" else "" for k in fields}
        key, entry = ops.sign(self._str(body, "key"), clean)
        w = self.state.watcher
        if w and w.presence:
            with w.lock:
                w.presence.rename(key, entry.get("name"))
        return {"key": key, "name": entry.get("name")}

    def _finding(self, body: dict) -> dict:
        found = ops.set_finding(self._str(body, "check"), self._str(body, "key"), self._str(body, "status"),
                                self._str(body, "reason", required=False))
        return {"count": len(found)}

    def _recheck(self, body: dict) -> dict:
        """Перепроверка находки по сети (только чтение, своя подсеть): несколько секунд."""
        done = ops.recheck(self._str(body, "check"), self._str(body, "key"))
        return {"results": [{"result": r["result"], "detail": r["detail"]} for r in done]}

    def _check(self, body: dict) -> dict:
        entry = ops.set_check(self._str(body, "code"), self._str(body, "status"), self._str(body, "note", required=False))
        return {"status": entry["status"]}


class Server(ThreadingHTTPServer):
    # В Windows SO_REUSEADDR позволяет занять порт, который уже слушает другая программа, — не нужно
    allow_reuse_address = False
    daemon_threads = True
    state: State


def make_server(port: int = DEFAULT_PORT, token: str | None = None, live_setup=None) -> Server:
    """Сервер на петлевом адресе. Если порт занят — любой свободный. live_setup — подмена опроса в тестах."""
    state = State(token or secrets.token_urlsafe(24), live_setup)
    handler = type("LanMapHandler", (Handler,), {"state": state})
    try:
        httpd = Server((LOOPBACK, port), handler)
    except OSError:
        httpd = Server((LOOPBACK, 0), handler)
    httpd.state = state
    return httpd


def url_for(httpd: Server) -> str:
    return f"http://{LOOPBACK}:{httpd.server_address[1]}/?t={httpd.state.token}"
