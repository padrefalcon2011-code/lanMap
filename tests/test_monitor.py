"""Присмотр: первое появление, возвращение и защищённый переход из уведомления."""
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, Request, build_opener

from lanmap import monitor, netinfo, server
from lanmap.util import read_json, write_json

GATEWAY = "00:00:5E:00:53:01"
MAC = "00:00:5E:00:53:02"
OTHER = "00:00:5E:00:53:03"
NET = ("192.0.2.0/24", GATEWAY)
OWNER = {"devices": {MAC: {"name": "Принтер <тест>", "confirmed": True}}}
CLIENT = {"mac": MAC, "ip": "192.0.2.2", "active": True}


class ObservationsTest(unittest.TestCase):
    def test_quiet_start_and_signed_new_device_only_once(self):
        state = monitor._initial()
        start = 1000000
        empty = lambda _: None
        self.assertEqual(monitor.observe(state, NET, "router", [{"mac": OTHER}], start, OWNER, empty), [])
        events = monitor.observe(state, NET, "router", [CLIENT], start + 120, OWNER, empty)
        self.assertEqual([(e["kind"], e["name"]) for e in events], [("new", "Принтер <тест>")])
        changed_ip = {**CLIENT, "ip": "192.0.2.25"}
        self.assertEqual(monitor.observe(state, NET, "router", [changed_ip], start + 240, OWNER, empty), [])
        other_net = (NET[0], "00:00:5E:00:53:04")
        self.assertEqual(monitor.observe(state, other_net, "router", [CLIENT], start + 360, OWNER, empty), [])
        self.assertEqual(len(state["networks"]), 2)

    def test_return_requires_negative_observation_and_threshold(self):
        state = monitor._initial()
        start = 1000000
        known = lambda _: {MAC: {"seen": start, "source": None}}
        observe = lambda clients, at, source="router": monitor.observe(state, NET, source, clients, at, OWNER, known)
        end = start + 30 * monitor.DAY
        self.assertEqual(observe([CLIENT], start), [])
        self.assertEqual(observe([CLIENT], end), [])  # компьютер пропустил опросы
        self.assertEqual([e["kind"] for e in state["events"]], ["gap"])
        self.assertEqual(observe([], end + 120, "local"), [])  # роутер видит больше, чем ping
        self.assertEqual(observe([CLIENT], end + 20 * monitor.DAY), [])
        last = end + 20 * monitor.DAY
        observe([], last + 120)
        self.assertEqual(observe([CLIENT], last + 240), [])
        last += 240
        observe([], last + 120)
        events = observe([CLIENT], last + 14 * monitor.DAY)
        self.assertEqual([(e["kind"], e["seen"]) for e in events], [("return", last)])
        self.assertEqual(observe([CLIENT], last + 14 * monitor.DAY + 120), [])

    def test_latest_snapshot_is_seed_and_different_gateway_is_skipped(self):
        with tempfile.TemporaryDirectory() as directory, patch("lanmap.scan.snapshots_dir", return_value=Path(directory)):
            from lanmap.snapshot import CORE_RAW
            for day, gateway in ((1, GATEWAY), (2, OTHER)):
                path = Path(directory) / f"2026-01-0{day}_090000"
                write_json(path / "meta.json", {"finished": f"2026-01-0{day}T09:05:00+00:00",
                                               "interface": {"network": NET[0], "gateway": "192.0.2.1"}})
                for name in CORE_RAW:
                    value = [{"ip": "192.0.2.1", "mac": gateway}] if name == "arp.json" else []
                    write_json(path / "raw" / name, value)
                write_json(path / "devices.json", {"devices": [{"mac": MAC if day == 1 else OTHER, "alive": True}]})
            self.assertEqual(set(monitor.baseline(NET)), {MAC})

    def test_poller_uses_only_active_router_clients_and_reuses_session(self):
        net = netinfo.LocalNet(5, "Тест", "Тест", "192.0.2.4", 24, NET[0], "192.0.2.1", OTHER, True, True)
        poll = monitor.Poller()
        rows = [CLIENT, {"mac": OTHER, "active": True}, {"mac": GATEWAY, "active": False}]
        with (patch("lanmap.ops.pick_network", return_value=net),
              patch("lanmap.collectors.discovery.arp_query", return_value=[{"mac": GATEWAY}]),
              patch("lanmap.routers.presence", return_value=(lambda: rows, None)) as presence):
            self.assertEqual(poll(), (NET, "router", [CLIENT]))
            self.assertEqual(poll(), (NET, "router", [CLIENT]))
            presence.assert_called_once_with(net.gateway)

    def test_local_fallback_checks_only_ping_replies_for_mac(self):
        net = netinfo.LocalNet(5, "Тест", "Тест", "192.0.2.4", 24, NET[0], "192.0.2.1", OTHER, True, True)
        replies = {CLIENT["ip"]: True, "192.0.2.3": False}
        with (patch("lanmap.ops.pick_network", return_value=net),
              patch("lanmap.collectors.discovery.arp_query", side_effect=[[{"mac": GATEWAY}], [CLIENT]]) as arp,
              patch("lanmap.routers.presence", return_value=(None, "нет входа")),
              patch("lanmap.collectors.live.Prober") as prober):
            prober.return_value.sweep.return_value = replies
            self.assertEqual(monitor.Poller()(), (NET, "local", [CLIENT]))
            self.assertEqual(arp.call_args.args[1], [CLIENT["ip"]])
            prober.return_value.close.assert_called_once()


class MonitorServerTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Трей Windows")
    def test_tray_starts_only_after_authorized_button_request(self):
        httpd = server.make_server(0, token="test-button")
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        browser = build_opener(HTTPCookieProcessor())
        url = server.url_for(httpd)
        origin = url.split("/?")[0]
        try:
            with patch("lanmap.server._report_path", return_value=None), patch.object(httpd.state, "start_tray") as start:
                with browser.open(url, timeout=3) as response:
                    self.assertIn("Свернуть в трей", response.read().decode())
                self.assertIsNone(httpd.state.monitor)
                headers = {"Content-Type": "application/json"}
                with self.assertRaises(HTTPError) as error:
                    browser.open(Request(origin + "/api/tray", b"{}", headers), timeout=3)
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
                start.assert_not_called()
                headers["X-LanMap-Token"] = "test-button"
                with browser.open(Request(origin + "/api/tray", b"{}", headers), timeout=3) as response:
                    self.assertEqual(response.status, 200)
                start.assert_called_once_with(httpd)
        finally:
            httpd.shutdown()
            thread.join(3)
            httpd.server_close()

    def test_event_link_requires_cookie_and_settings_require_header(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor.json"
            received = []
            watcher = monitor.Monitor(received.extend, poll=lambda: (NET, "router", [CLIENT]), path=path)
            with patch("lanmap.registry.load", return_value=OWNER):
                # Пустой готовый срез — исходная точка. Первое устройство должно вызвать уведомление.
                state = monitor._initial()
                state["networks"]["|".join(NET)] = {}
                write_json(path, state)
                watcher._tick()
            self.assertEqual(len(received), 1)
            self.assertEqual(read_json(path)["events"], received)
            restarted = monitor.Monitor(received.extend, poll=lambda: (NET, "router", [CLIENT]), path=path)
            with patch("lanmap.registry.load", return_value=OWNER):
                restarted._tick()
            self.assertEqual(len(received), 1)
            httpd = server.make_server(0, token="test-tray")
            httpd.state.monitor = restarted
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                url = server.url_for(httpd, "/monitor", received[0]["id"])
                browser = build_opener(HTTPCookieProcessor())
                with self.assertRaises(HTTPError) as error:
                    browser.open(url.split("?")[0], timeout=3)
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
                with browser.open(url, timeout=3) as reply:
                    self.assertTrue(reply.url.endswith("/monitor?e=1"))
                    page = reply.read().decode()
                self.assertIn('id="event-1" open', page)
                self.assertIn("Принтер &lt;тест&gt;", page)
                api = url.split("/monitor?")[0] + "/api/monitor"
                body = json.dumps({"return_days": 30, "paused": True}).encode()
                headers = {"Content-Type": "application/json"}
                with self.assertRaises(HTTPError) as error:
                    browser.open(Request(api, body, headers), timeout=3)
                self.assertEqual(error.exception.code, 403)
                error.exception.close()
                headers["X-LanMap-Token"] = "test-tray"
                with browser.open(Request(api, body, headers), timeout=3) as reply:
                    self.assertEqual(reply.status, 200)
                self.assertEqual(restarted.status()["return_days"], 30)
                self.assertTrue(restarted.status()["paused"])
                self.assertEqual(restarted.status()["events"][-1]["kind"], "gap")
            finally:
                httpd.shutdown()
                thread.join(3)
                httpd.server_close()
