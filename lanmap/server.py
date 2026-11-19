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


class State:
    """Состояние сервера: токен, замок на запись в data/, ход среза."""

    def __init__(self, token: str):
        self.token = token
        self.write_lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.scan = {"running": False, "stages": [], "error": None, "snapshot": None}

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


EMPTY_PAGE = """<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>LanMap</title>
<style>body{font:16px system-ui,sans-serif;background:#f3f4f6;color:#1b1f27;display:grid;place-items:center;height:100vh;margin:0}
button{font:inherit;padding:10px 20px;border-radius:10px;border:0;background:#2a78d6;color:#fff;cursor:pointer}
@media (prefers-color-scheme:dark){body{background:#131518;color:#e8eaed}}</style></head>
<body><div><p>Срезов ещё нет.</p><button id="go">Сделать первый срез</button><p id="st"></p></div>
<script>const L=window.LANMAP,st=document.getElementById('st');
async function poll(){const r=await fetch('/api/scan',{headers:{'X-LanMap-Token':L.token}});const j=await r.json();
 st.textContent=j.error||j.stages.slice(-1)[0]||'';if(j.running)setTimeout(poll,1500);else if(!j.error)location.reload();}
document.getElementById('go').onclick=async()=>{await fetch('/api/scan',{method:'POST',
 headers:{'Content-Type':'application/json','X-LanMap-Token':L.token},body:'{}'});poll();};</script></body></html>"""


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
        if url.path == "/api/scan":
            if not self._header_ok():
                return self._json(403, {"error": "нет доступа"})
            return self._json(200, self.state.scan_status())
        self._text(404, "не найдено")

    def _page(self) -> None:
        path = _report_path()
        html = path.read_text("utf-8") if path else EMPTY_PAGE
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
        if route == "/api/scan":
            started = self.state.start_scan()
            return self._json(202 if started else 409, self.state.scan_status())
        action = {"/api/sign": self._sign, "/api/finding": self._finding, "/api/check": self._check}.get(route)
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
        return {"key": key, "name": entry.get("name")}

    def _finding(self, body: dict) -> dict:
        found = ops.set_finding(self._str(body, "check"), self._str(body, "key"), self._str(body, "status"),
                                self._str(body, "reason", required=False))
        return {"count": len(found)}

    def _check(self, body: dict) -> dict:
        entry = ops.set_check(self._str(body, "code"), self._str(body, "status"), self._str(body, "note", required=False))
        return {"status": entry["status"]}


class Server(ThreadingHTTPServer):
    # В Windows SO_REUSEADDR позволяет занять порт, который уже слушает другая программа, — не нужно
    allow_reuse_address = False
    daemon_threads = True
    state: State


def make_server(port: int = DEFAULT_PORT, token: str | None = None) -> Server:
    """Сервер на петлевом адресе. Если порт занят — любой свободный."""
    state = State(token or secrets.token_urlsafe(24))
    handler = type("LanMapHandler", (Handler,), {"state": state})
    try:
        httpd = Server((LOOPBACK, port), handler)
    except OSError:
        httpd = Server((LOOPBACK, 0), handler)
    httpd.state = state
    return httpd


def url_for(httpd: Server) -> str:
    return f"http://{LOOPBACK}:{httpd.server_address[1]}/?t={httpd.state.token}"
