"""Значок Windows и уведомления LanMap без внешних библиотек."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
import hashlib
import os
import queue
import threading
import webbrowser
from contextlib import ExitStack, contextmanager

from lanmap import monitor, server
from lanmap.util import UserError

WM_TRAY = 0x8001
WM_DESTROY = 0x0002
WM_CANCELMODE = 0x001F
WM_CONTEXTMENU = 0x007B
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
NIN_KEYSELECT = 0x0401
NIN_BALLOONUSERCLICK = 0x0405
NIM_ADD, NIM_MODIFY, NIM_DELETE, NIM_SETFOCUS, NIM_SETVERSION = range(5)
NIF_MESSAGE, NIF_ICON, NIF_TIP, NIF_INFO = 1, 2, 4, 16
CMD_REPORT, CMD_JOURNAL, CMD_PAUSE, CMD_QUIT = range(1, 5)

WNDPROC = c.WINFUNCTYPE(c.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)


class WindowClass(c.Structure):
    _fields_ = [("style", w.UINT), ("callback", WNDPROC), ("cls_extra", c.c_int), ("wnd_extra", c.c_int),
                ("instance", w.HINSTANCE), ("icon", w.HICON), ("cursor", w.HANDLE), ("background", w.HBRUSH),
                ("menu", w.LPCWSTR), ("name", w.LPCWSTR)]


class NotifyIcon(c.Structure):
    _fields_ = [("size", w.DWORD), ("window", w.HWND), ("id", w.UINT), ("flags", w.UINT),
                ("callback_message", w.UINT), ("icon", w.HICON), ("tip", w.WCHAR * 128),
                ("state", w.DWORD), ("state_mask", w.DWORD), ("text", w.WCHAR * 256),
                ("version", w.UINT), ("title", w.WCHAR * 64), ("info_flags", w.DWORD),
                ("guid", c.c_ubyte * 16), ("balloon_icon", w.HICON)]


def _bind(dll, name, result, *parameters):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, parameters
    return fn


_user = c.WinDLL("user32", use_last_error=True)
_kernel = c.WinDLL("kernel32", use_last_error=True)
_notify_icon = _bind(c.WinDLL("shell32", use_last_error=True), "Shell_NotifyIconW", w.BOOL,
                     w.DWORD, c.POINTER(NotifyIcon))
_create_mutex = _bind(_kernel, "CreateMutexW", w.HANDLE, c.c_void_p, w.BOOL, w.LPCWSTR)
_close_handle = _bind(_kernel, "CloseHandle", w.BOOL, w.HANDLE)
_module = _bind(_kernel, "GetModuleHandleW", w.HMODULE, w.LPCWSTR)
_register_class = _bind(_user, "RegisterClassW", w.ATOM, c.POINTER(WindowClass))
_unregister_class = _bind(_user, "UnregisterClassW", w.BOOL, w.LPCWSTR, w.HINSTANCE)
_create_window = _bind(_user, "CreateWindowExW", w.HWND, w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
                       c.c_int, c.c_int, c.c_int, c.c_int, w.HWND, w.HMENU, w.HINSTANCE, c.c_void_p)
_destroy_window = _bind(_user, "DestroyWindow", w.BOOL, w.HWND)
_default = _bind(_user, "DefWindowProcW", c.c_ssize_t, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
_register_message = _bind(_user, "RegisterWindowMessageW", w.UINT, w.LPCWSTR)
_allow_message = _bind(_user, "ChangeWindowMessageFilterEx", w.BOOL, w.HWND, w.UINT, w.DWORD, c.c_void_p)
_load_icon = _bind(_user, "LoadIconW", w.HICON, w.HINSTANCE, c.c_void_p)
_peek = _bind(_user, "PeekMessageW", w.BOOL, c.POINTER(w.MSG), w.HWND, w.UINT, w.UINT, w.UINT)
_translate = _bind(_user, "TranslateMessage", w.BOOL, c.POINTER(w.MSG))
_dispatch = _bind(_user, "DispatchMessageW", c.c_ssize_t, c.POINTER(w.MSG))
_menu = _bind(_user, "CreatePopupMenu", w.HMENU)
_destroy_menu = _bind(_user, "DestroyMenu", w.BOOL, w.HMENU)
_append = _bind(_user, "AppendMenuW", w.BOOL, w.HMENU, w.UINT, c.c_size_t, w.LPCWSTR)
_track = _bind(_user, "TrackPopupMenu", w.BOOL, w.HMENU, w.UINT, c.c_int, c.c_int, c.c_int, w.HWND, c.c_void_p)
_cursor = _bind(_user, "GetCursorPos", w.BOOL, c.POINTER(w.POINT))
_foreground = _bind(_user, "SetForegroundWindow", w.BOOL, w.HWND)
_post = _bind(_user, "PostMessageW", w.BOOL, w.HWND, w.UINT, w.WPARAM, w.LPARAM)
_message_box = _bind(_user, "MessageBoxW", c.c_int, w.HWND, w.LPCWSTR, w.LPCWSTR, w.UINT)


@contextmanager
def _single_instance(path):
    digest = hashlib.sha256(os.path.normcase(str(path.resolve())).encode()).hexdigest()[:24]
    mutex = _create_mutex(None, False, f"Local\\LanMap-Tray-{digest}")
    if not mutex:
        raise c.WinError(c.get_last_error())
    try:
        if c.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            raise UserError("Присмотр LanMap для этой папки данных уже запущен")
        yield
    finally:
        _close_handle(mutex)


class Tray:
    def __init__(self, httpd):
        self.httpd = httpd
        self.watcher = monitor.Monitor(self.notify)
        self.messages = queue.SimpleQueue()
        self.events = queue.SimpleQueue()
        self.stopped = threading.Event()
        self.ready = threading.Event()
        self.error = None
        self.hwnd = None
        self.thread = threading.Thread(target=self._run, daemon=True, name="lanmap-tray")
        self.current_event = None
        self.taskbar_created = _register_message("TaskbarCreated")
        self.callback = WNDPROC(self._window_message)

    def _window_message(self, hwnd, message, wp, lp):
        if message == WM_TRAY:
            self.messages.put(lp)
            return 0
        if message == self.taskbar_created:
            self.messages.put(self.taskbar_created)
            return 0
        if message == WM_DESTROY:
            self.stopped.set()
            return 0
        return _default(hwnd, message, wp, lp)

    def _add_icon(self) -> bool:
        self.icon.flags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        if not _notify_icon(NIM_ADD, c.byref(self.icon)):
            return False
        self.icon.version = 3  # NOTIFYICON_VERSION: события клавиатуры, lParam — код события.
        _notify_icon(NIM_SETVERSION, c.byref(self.icon))
        return True

    def _open(self, journal=False, event_id=None):
        webbrowser.open(server.url_for(self.httpd, "/monitor" if journal else "/", event_id))

    def notify(self, events: list[dict]) -> None:
        self.events.put(events)

    def _announce(self, events):
        self.icon.flags = NIF_INFO
        # В системном уведомлении только вид события. Детали видны в защищённом журнале.
        if len(events) == 1:
            self.current_event = events[0]["id"]
            self.icon.title = monitor.TITLES[events[0]["kind"]]
        else:
            self.current_event = None
            self.icon.title = f"События в сети · {len(events)}"
        self.icon.text = "Открыть журнал LanMap"
        self.icon.info_flags = 1  # NIIF_INFO
        _notify_icon(NIM_MODIFY, c.byref(self.icon))

    def _popup(self):
        menu = _menu()
        if not menu:
            raise c.WinError(c.get_last_error())
        try:
            paused = self.watcher.status()["paused"]
            _append(menu, 0, CMD_REPORT, "Открыть LanMap")
            _append(menu, 0, CMD_JOURNAL, "Журнал присмотра")
            _append(menu, 0, CMD_PAUSE, "Продолжить присмотр" if paused else "Пауза")
            _append(menu, 0x800, 0, None)  # MF_SEPARATOR
            _append(menu, 0, CMD_QUIT, "Выйти")
            point = w.POINT()
            _cursor(c.byref(point))
            _foreground(self.icon.window)
            choice = _track(menu, 0x102, point.x, point.y, 0, self.icon.window, None)
            _post(self.icon.window, 0, 0, 0)
        finally:
            _destroy_menu(menu)
            _notify_icon(NIM_SETFOCUS, c.byref(self.icon))
        if choice in (CMD_REPORT, CMD_JOURNAL):
            self._open(journal=choice == CMD_JOURNAL)
        elif choice == CMD_PAUSE:
            try:
                self.watcher.settings({"paused": not paused})
            except (UserError, OSError) as exc:
                _message_box(self.icon.window, str(exc), "LanMap", 0x30)
        elif choice == CMD_QUIT:
            if not self.httpd.state.prepare_shutdown():
                _message_box(self.icon.window, "Идёт срез. Дождись его окончания.", "LanMap", 0x40)
            else:
                self.httpd.shutdown()
                self.close()

    def _loop(self):
        message = w.MSG()
        while not self.stopped.is_set():
            while _peek(c.byref(message), None, 0, 0, 1):  # PM_REMOVE
                _translate(c.byref(message))
                _dispatch(c.byref(message))
            while not self.messages.empty():
                action = self.messages.get_nowait()
                if action in (WM_LBUTTONUP, NIN_KEYSELECT):
                    self._open()
                elif action in (WM_RBUTTONUP, WM_CONTEXTMENU):
                    self._popup()
                elif action == NIN_BALLOONUSERCLICK:
                    self._open(journal=True, event_id=self.current_event)
                elif action == self.taskbar_created:
                    self._add_icon()
            if not self.events.empty():
                self._announce(self.events.get_nowait())
            self.stopped.wait(0.1)

    def start(self):
        self.thread.start()

    def wait_ready(self):
        if not self.ready.wait(10):
            self.close()
            raise UserError("Windows не успела добавить значок LanMap. Попробуй ещё раз.")
        if self.error:
            raise UserError(self.error)
        if self.stopped.is_set():
            raise UserError("LanMap завершает работу")

    def close(self):
        self.stopped.set()
        self.watcher.close()
        if self.hwnd:
            _post(self.hwnd, WM_CANCELMODE, 0, 0)
        if threading.current_thread() is not self.thread and self.thread.is_alive():
            self.thread.join(2)

    def _run(self):
        try:
            self._run_window()
        except Exception as exc:
            self.error = str(exc) if isinstance(exc, (UserError, OSError)) else f"Ошибка трея ({type(exc).__name__})"
        finally:
            self.close()
            self.ready.set()

    def _run_window(self):
        with _single_instance(self.watcher.path), ExitStack() as cleanup:
            instance = _module(None)
            klass = WindowClass(callback=self.callback, instance=instance, name="LanMapTray")
            if not _register_class(c.byref(klass)):
                raise c.WinError(c.get_last_error())
            cleanup.callback(_unregister_class, klass.name, instance)
            hwnd = _create_window(0, klass.name, "LanMap", 0, 0, 0, 0, 0, None, None, instance, None)
            if not hwnd:
                raise c.WinError(c.get_last_error())
            self.hwnd = hwnd
            cleanup.callback(_destroy_window, hwnd)
            cleanup.callback(setattr, self, "hwnd", None)
            _allow_message(hwnd, self.taskbar_created, 1, None)  # Explorer может быть без повышения прав.
            _allow_message(hwnd, WM_TRAY, 1, None)
            self.icon = NotifyIcon(size=c.sizeof(NotifyIcon), window=hwnd, id=1, callback_message=WM_TRAY,
                                   icon=_load_icon(None, 32512), tip="LanMap · Присмотр за сетью")
            if not self._add_icon():
                raise UserError("Не удалось добавить значок LanMap в область уведомлений Windows.")
            cleanup.callback(_notify_icon, NIM_DELETE, c.byref(self.icon))
            if self.stopped.is_set():
                return
            threading.Thread(target=self.watcher.run, daemon=True, name="lanmap-monitor").start()
            self.httpd.state.monitor = self.watcher
            cleanup.callback(setattr, self.httpd.state, "monitor", None)
            self.ready.set()
            self._loop()
