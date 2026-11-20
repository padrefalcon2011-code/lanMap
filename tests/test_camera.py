"""Стоп-кадр по ONVIF: только разрешённые действия, пароль только владельца и только своей камере.
Адреса — RFC 5737, MAC — диапазон документации."""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import tempfile
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest import mock

if "LANMAP_DATA" not in os.environ:
    _TMP = tempfile.TemporaryDirectory()
    os.environ["LANMAP_DATA"] = _TMP.name

from lanmap import ops  # noqa: E402
from lanmap.collectors import ScanContext, onvif  # noqa: E402

CTX = ScanContext(local_ip="192.0.2.30", network="192.0.2.0/24", gateway="192.0.2.1", if_index=1)
IP = "192.0.2.15"
MAC = "00:00:5E:00:53:0C"
OTHER = "00:00:5E:00:53:0B"
JPEG = b"\xff\xd8\xff\xe0" + b"\0" * 64
CAM_PW = "camleak1"     # пароль, который камера сама вписала в адрес кадра
OWNER_PW = "owner-pw"   # пароль, сохранённый владельцем


def soap(inner: str) -> bytes:
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            f'xmlns:tt="http://www.onvif.org/ver10/schema" xmlns:trt="{onvif.MEDIA_NS}" xmlns:tds="{onvif.DEVICE_NS}">'
            f'<s:Body>{inner}</s:Body></s:Envelope>').encode()


FAULT = soap('<s:Fault><s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>ter:NotAuthorized</s:Value>'
             '</s:Subcode></s:Code></s:Fault>')


class FakeCamera:
    """Камера в духе Xiongmai: часы сбиты на час, адреса в ответах — чужие, пароль в адресе кадра."""

    def __init__(self, image=JPEG, fetch_status=200, auth_fault=False, uri=None):
        self.image, self.fetch_status, self.auth_fault = image, fetch_status, auth_fault
        self.uri = uri or f"http://198.51.100.7/webcapture.jpg?command=snap&channel=0&user=admin&password={CAM_PW}"
        self.clock = dt.datetime(2020, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        self.posts: list[tuple[str, str, bytes]] = []
        self.fetched: list[tuple[str, str, str]] = []

    def poster(self, url, body, headers):
        action = next(a for a in onvif.READ_ONLY_ACTIONS if f"<{a} " in body.decode())
        self.posts.append((url, action, body))
        if self.auth_fault and action != "GetSystemDateAndTime":
            return 400, FAULT
        if action == "GetSystemDateAndTime":
            c = self.clock
            return 200, soap(f'<tds:GetSystemDateAndTimeResponse><tds:SystemDateAndTime><tt:UTCDateTime>'
                             f'<tt:Time><tt:Hour>{c.hour}</tt:Hour><tt:Minute>{c.minute}</tt:Minute><tt:Second>{c.second}</tt:Second></tt:Time>'
                             f'<tt:Date><tt:Year>{c.year}</tt:Year><tt:Month>{c.month}</tt:Month><tt:Day>{c.day}</tt:Day></tt:Date>'
                             f'</tt:UTCDateTime></tds:SystemDateAndTime></tds:GetSystemDateAndTimeResponse>')
        if action == "GetCapabilities":
            return 200, soap('<tds:GetCapabilitiesResponse><tds:Capabilities><tt:Media>'
                             '<tt:XAddr>http://192.0.2.99:8899/onvif/media_service</tt:XAddr>'
                             '</tt:Media></tds:Capabilities></tds:GetCapabilitiesResponse>')
        if action == "GetProfiles":
            return 200, soap('<trt:GetProfilesResponse><trt:Profiles token="000"/><trt:Profiles token="001"/></trt:GetProfilesResponse>')
        return 200, soap(f'<trt:GetSnapshotUriResponse><trt:MediaUri><tt:Uri>{self.uri.replace("&", "&amp;")}</tt:Uri>'
                         f'</trt:MediaUri></trt:GetSnapshotUriResponse>')

    def fetcher(self, url, user, password, limit):
        self.fetched.append((url, user, password))
        return self.fetch_status, self.image


def camera(fake: FakeCamera, user="viewer", password=OWNER_PW) -> onvif.Camera:
    return onvif.Camera(CTX, IP, "http://192.0.2.10:8899/onvif/device_service", user, password,
                        fake.poster, fake.fetcher)


class OnvifTest(unittest.TestCase):
    def test_only_read_actions(self):
        for action in ("SetSystemDateAndTime", "SystemReboot", "CreateUsers", "SetUser", "SetNetworkInterfaces"):
            with self.assertRaises(PermissionError):
                onvif.envelope(action)

    def test_digest(self):
        nonce, when = b"0123456789abcdef", dt.datetime(2020, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
        head = onvif.security_header("u<x", "pw", when, nonce)
        want = base64.b64encode(hashlib.sha1(nonce + b"2020-01-02T03:04:05Z" + b"pw").digest()).decode()
        self.assertIn(want, head)
        self.assertIn("u&lt;x", head)          # логин экранирован
        self.assertNotIn(">pw<", head)         # пароль открытым текстом не уходит
        self.assertIn("PasswordDigest", head)

    def test_snapshot_xiongmai(self):
        fake = FakeCamera()
        self.assertEqual(camera(fake).snapshot(), JPEG)
        self.assertTrue({a for _, a, _ in fake.posts} <= set(onvif.READ_ONLY_ACTIONS))
        # Все запросы — только на проверенный адрес, а не на те, что назвала камера
        self.assertEqual({urllib.parse.urlsplit(u).hostname for u, _, _ in fake.posts}, {IP})
        url, user, password = fake.fetched[0]
        parts = urllib.parse.urlsplit(url)
        self.assertEqual(parts.hostname, IP)
        q = dict(urllib.parse.parse_qsl(parts.query))
        self.assertEqual((q["user"], q["password"], q["command"]), ("viewer", OWNER_PW, "snap"))
        self.assertNotIn(CAM_PW, url)  # пароль, выданный камерой, не используется
        # Подпись — по часам камеры
        signed = next(b for _, a, b in fake.posts if a == "GetProfiles").decode()
        self.assertIn("<Created", signed)
        self.assertIn("2020-01-02T03:0", signed)

    def test_not_jpeg_is_refused(self):
        fake = FakeCamera(image=b"<html><script>alert(1)</script></html>")
        with self.assertRaises(onvif.AuthError) as cm:
            camera(fake).snapshot()
        self.assertNotIn(OWNER_PW, str(cm.exception))
        self.assertNotIn("webcapture", str(cm.exception))

    def test_auth_fault(self):
        with self.assertRaises(onvif.AuthError):
            camera(FakeCamera(auth_fault=True)).snapshot()
        with self.assertRaises(onvif.AuthError):
            camera(FakeCamera(fetch_status=401)).snapshot()

    def test_errors_hide_snapshot_url(self):
        """Ошибка урлиба несёт адрес кадра (а в нём пароль владельца) — наружу идёт только имя класса."""
        fake = FakeCamera()
        def boom(url, user, password, limit):
            raise ValueError(url)
        fake.fetcher = boom
        with self.assertRaises(onvif.OnvifError) as cm:
            camera(fake).snapshot()
        self.assertNotIn(OWNER_PW, str(cm.exception))
        self.assertNotIn("webcapture", str(cm.exception))

    def test_failed_authentication_fault(self):
        fake = FakeCamera(auth_fault=True)
        global FAULT
        saved, FAULT = FAULT, FAULT.replace(b"ter:NotAuthorized", b"wsse:FailedAuthentication")
        try:
            with self.assertRaises(onvif.AuthError):
                camera(fake).snapshot()
        finally:
            FAULT = saved

    def test_bad_uri_scheme(self):
        with self.assertRaises(onvif.OnvifError) as cm:
            camera(FakeCamera(uri="file:///C:/Windows/win.ini")).snapshot()
        self.assertNotIn("win.ini", str(cm.exception))

    def test_out_of_scope_camera(self):
        with self.assertRaises(onvif.OnvifError):
            onvif.Camera(CTX, "198.51.100.7", "http://198.51.100.7/onvif/device_service", "u", "p")

    def test_leaks_password(self):
        self.assertTrue(onvif.leaks_password("http://192.0.2.10/webcapture.jpg?user=admin&password=x"))
        self.assertFalse(onvif.leaks_password("http://192.0.2.10/webcapture.jpg?user=admin&password="))
        self.assertFalse(onvif.leaks_password("http://192.0.2.10/snap.jpg"))


class CameraOpsTest(unittest.TestCase):
    NET = SimpleNamespace(local_ip="192.0.2.30", network="192.0.2.0/24", gateway="192.0.2.1", if_index=1, mac=None)

    def dev(self, key=MAC, ips=("192.0.2.10", IP)):
        return {"key": key, "mac": MAC, "ips": list(ips), "title": "камера",
                "facts": {"onvif": {"anonymous": True}, "ports": [554, 8899],
                          "onvif_urls": {ip: f"http://{ip}:8899/onvif/device_service" for ip in ips}}}

    def probes(self, macs, serials=None):
        return SimpleNamespace(mac=lambda ip: macs.get(ip),
                               onvif=lambda url: {"fields": {"SerialNumber": (serials or {}).get(
                                   urllib.parse.urlsplit(url).hostname)}})

    def snap(self, dev, macs, serials=None, fake=None):
        fake = fake or FakeCamera()
        with mock.patch.object(ops, "pick_network", return_value=self.NET):
            return ops._camera_snap(dev, "viewer", OWNER_PW, probes=self.probes(macs, serials),
                                    poster=fake.poster, fetcher=fake.fetcher), fake

    def test_shared_factory_address(self):
        """.10 занят другой камерой — пароль уходит только на адрес, где ARP даёт MAC этой камеры."""
        image, fake = self.snap(self.dev(), {"192.0.2.10": OTHER, IP: MAC})
        self.assertEqual(image, JPEG)
        self.assertEqual({urllib.parse.urlsplit(u).hostname for u, _, _ in fake.posts}, {IP})

    def test_wrong_device_gets_no_password(self):
        fake = FakeCamera()
        with self.assertRaises(ops.OpError) as cm:
            self.snap(self.dev(), {"192.0.2.10": OTHER, IP: OTHER}, fake=fake)
        self.assertIn("другое устройство", str(cm.exception))
        self.assertEqual(fake.posts, [])
        with self.assertRaises(ops.OpError):
            self.snap(self.dev(), {}, fake=fake)  # не ответила
        self.assertEqual(fake.posts, [])

    def test_mac_twin_checks_serial(self):
        dev = self.dev(key=f"{MAC}#SN-B", ips=("192.0.2.10",))
        fake = FakeCamera()
        with self.assertRaises(ops.OpError):
            self.snap(dev, {"192.0.2.10": MAC}, {"192.0.2.10": "SN-A"}, fake=fake)
        self.assertEqual(fake.posts, [])
        image, _ = self.snap(dev, {"192.0.2.10": MAC}, {"192.0.2.10": "SN-B"})
        self.assertEqual(image, JPEG)

    def test_auth_error_asks_login(self):
        with self.assertRaises(ops.NeedLogin) as cm:
            self.snap(self.dev(), {IP: MAC}, fake=FakeCamera(image=b"bad password"))
        self.assertNotIn(OWNER_PW, str(cm.exception))


if __name__ == "__main__":
    unittest.main()
