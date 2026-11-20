"""Запуск программ из карточки: белый список, команда только из модели среза, без shell и без паролей.
Адреса — RFC 5737, MAC — диапазон документации."""
from __future__ import annotations

import os
import tempfile
import unittest
import urllib.parse
from types import SimpleNamespace
from unittest import mock

if "LANMAP_DATA" not in os.environ:
    _TMP = tempfile.TemporaryDirectory()
    os.environ["LANMAP_DATA"] = _TMP.name

from lanmap import actions, launch, ops  # noqa: E402
from lanmap.collectors import ScanContext, onvif  # noqa: E402
try:  # discover -s tests кладёт в sys.path саму папку tests; встроенный Python не видит пакет tests
    from test_camera import CAM_PW, FakeCamera, soap  # noqa: E402
except ImportError:
    from tests.test_camera import CAM_PW, FakeCamera, soap  # noqa: E402

CTX = ScanContext(local_ip="192.0.2.30", network="192.0.2.0/24", gateway="192.0.2.1", if_index=1)
IP = "192.0.2.15"
MAC = "00:00:5E:00:53:0C"
TOOLS = launch.Tools(ssh=r"C:\W\ssh.exe", telnet=r"C:\W\telnet.exe", wt=r"C:\U\wt.exe", vlc=r"C:\P\vlc.exe",
                     explorer=r"C:\W\explorer.exe", mstsc=r"C:\W\mstsc.exe")
# Имена приходят из сети: в командную строку они попадать не должны (у Windows Terminal «;» — разделитель команд)
EVIL = 'x" ; calc.exe & del'


def dev(ports=(22,), ips=(IP,), mac=MAC, dev_type="computer", **extra):
    return {"key": mac, "mac": mac, "ips": list(ips), "title": EVIL, "subtitle": EVIL,
            "services": [{"port": p} for p in ports], "identity": {"type": dev_type, "model": EVIL},
            "router": {"hostname": EVIL}, **extra}


def plan(d, action, **kw):
    kw.setdefault("tools", TOOLS)
    return launch.plan(d, action, ctx=CTX, **kw)


class ActionsTest(unittest.TestCase):
    def test_launch_ids(self):
        d = dev(ports=(22, 23, 445, 554, 3389))
        self.assertEqual(sorted(launch.available(d)), ["rdp", "smb", "ssh", "telnet", "vlc", "wol"])
        self.assertEqual(launch.available(d)["vlc"]["port"], 554)
        self.assertEqual(sorted(launch.available(dev(ports=(80,), dev_type="camera"))), [])

    def test_wol_only_real_mac(self):
        self.assertIn("wol", launch.available(dev(ports=(), dev_type="nas")))
        self.assertNotIn("wol", launch.available(dev(ports=(), dev_type="tv")))
        self.assertNotIn("wol", launch.available(dev(mac="02:00:5E:00:53:0C")))  # частный MAC
        self.assertIn("wol", launch.available(dev(ips=())))  # спящее устройство без адреса — как раз его и будить
        self.assertEqual([a["kind"] for a in actions.build(dev(ips=())) if a.get("launch") == "wol"], ["launch"])


class PlanTest(unittest.TestCase):
    def test_whitelist(self):
        with self.assertRaises(launch.LaunchError):
            plan(dev(), "cmd")
        with self.assertRaises(launch.LaunchError):  # порта 3389 в срезе не было
            plan(dev(ports=(22,)), "rdp")

    def test_ssh(self):
        p = plan(dev(), "ssh")
        self.assertEqual(p.argv, [TOOLS.wt, "new-tab", "--title", f"SSH {IP}", TOOLS.ssh, IP])
        p = plan(dev(), "ssh", tools=launch.Tools(ssh=TOOLS.ssh))
        self.assertEqual((p.argv, p.console), ([TOOLS.ssh, IP], True))
        with self.assertRaises(launch.LaunchError):
            plan(dev(), "ssh", tools=launch.Tools())

    def test_only_ip_from_device(self):
        """В argv — только пути программ и проверенный IP: ни имён, ни модели, ни строк со страницы."""
        d = dev(ports=(22, 23, 445, 3389, 554))
        for action in ("ssh", "smb", "rdp", "telnet", "vlc"):
            argv = plan(d, action, ack=True).argv
            self.assertIsInstance(argv, list)
            self.assertFalse(any(EVIL in a or "calc" in a for a in argv), action)
            self.assertTrue(any(IP in a for a in argv), action)
        self.assertEqual(plan(d, "smb").argv, [TOOLS.explorer, f"\\\\{IP}"])
        self.assertEqual(plan(d, "rdp").argv, [TOOLS.mstsc, f"/v:{IP}"])

    def test_ip_must_be_local(self):
        for ips in (("198.51.100.4",), ("192.0.2.255",), ("192.0.2.1; calc",), ("fe80::1",), ()):
            with self.assertRaises(launch.LaunchError, msg=ips):
                plan(dev(ips=ips), "ssh")
        # первый адрес чужой, второй свой — берётся свой
        self.assertEqual(plan(dev(ips=("198.51.100.4", IP)), "ssh").argv[-1], IP)

    def test_telnet_needs_ack(self):
        with self.assertRaises(launch.LaunchError) as cm:
            plan(dev(ports=(23,)), "telnet")
        self.assertIn("открытым текстом", str(cm.exception))
        self.assertEqual(plan(dev(ports=(23,)), "telnet", ack=True).argv, [TOOLS.telnet, IP])
        with self.assertRaises(launch.LaunchError):
            plan(dev(ports=(23,)), "telnet", ack=True, tools=launch.Tools())

    def test_vlc(self):
        seen = []

        def stream(d, ip, port):
            seen.append((ip, port))
            return f"rtsp://{ip}:{port}/live", "пояснение"
        p = plan(dev(ports=(8554,), dev_type="camera"), "vlc", stream=stream)
        self.assertEqual((p.argv, seen), ([TOOLS.vlc, f"rtsp://{IP}:8554/live"], [(IP, 8554)]))
        self.assertIn("пояснение", p.message)
        with self.assertRaises(launch.LaunchError) as cm:  # VLC нет — адрес для копирования
            plan(dev(ports=(554,), dev_type="camera"), "vlc", tools=launch.Tools())
        self.assertEqual(cm.exception.url, f"rtsp://{IP}:554/")

    def test_wol(self):
        p = plan(dev(ports=(445,)), "wol")
        mac = bytes.fromhex(MAC.replace(":", ""))
        self.assertEqual(p.packet, b"\xff" * 6 + mac * 16)
        self.assertEqual(len(p.packet), 102)
        self.assertEqual((p.target, p.source), (("192.0.2.255", 9), "192.0.2.30"))  # своя подсеть, не 255.255.255.255
        sent = []
        launch.execute(p, send=lambda *a: sent.append(a))
        self.assertEqual(sent, [(p.packet, ("192.0.2.255", 9), "192.0.2.30")])
        with self.assertRaises(launch.LaunchError):
            launch.magic_packet("01:00:5E:00:00:01")

    def test_execute(self):
        calls = []
        msg = launch.execute(plan(dev(), "ssh"), popen=lambda argv, console: calls.append((argv, console)))
        self.assertEqual(calls[0][0][-1], IP)
        self.assertIn(IP, msg)

        def boom(argv, console):
            raise FileNotFoundError(2, "нет", argv[0])
        with self.assertRaises(launch.LaunchError):
            launch.execute(plan(dev(), "ssh"), popen=boom)

    def test_popen_no_shell(self):
        with mock.patch("subprocess.Popen") as popen:
            launch._popen(["a.exe", IP], True)
        args, kw = popen.call_args
        self.assertEqual(args[0], ["a.exe", IP])
        self.assertIs(kw["shell"], False)


class StreamUriTest(unittest.TestCase):
    def test_strip_creds(self):
        cases = {
            "rtsp://198.51.100.7:554/user=admin&password=s3cr3t&channel=1&stream=0.sdp?real_stream":
                f"rtsp://{IP}:554/user=&password=&channel=1&stream=0.sdp?real_stream",
            "rtsp://198.51.100.7/user=admin_password=ab_cd_channel=1_stream=0.sdp":
                f"rtsp://{IP}/user=_password=_channel=1_stream=0.sdp",
            "rtsp://admin:s3cr3t@198.51.100.7/Streaming/Channels/101": f"rtsp://{IP}/Streaming/Channels/101",
            "rtsp://198.51.100.7:8554/live?usr=a&pwd=s3cr3t&ch=1": f"rtsp://{IP}:8554/live?usr=&pwd=&ch=1",
        }
        for uri, want in cases.items():
            got, had = onvif.rtsp_without_creds(uri, IP)
            self.assertEqual(got, want)
            self.assertTrue(had)
            self.assertNotIn("s3cr3t", got)
            self.assertNotIn("ab_cd", got)
        for pw, tail in (("ab?cd", "cd"), ("ab#cd", "cd"), ("a&b", "&b&")):
            got, had = onvif.rtsp_without_creds(
                f"rtsp://198.51.100.7:554/user=admin&password={pw}&channel=1&stream=0.sdp?real_stream", IP)
            self.assertTrue(had)
            self.assertNotIn(tail, got, pw)
            self.assertTrue(got.startswith(f"rtsp://{IP}:554/user=&password="), got)
        self.assertEqual(onvif.rtsp_without_creds("rtsp://198.51.100.7/live/ch0", IP), (f"rtsp://{IP}/live/ch0", False))
        self.assertEqual(onvif.rtsp_without_creds(f"rtsp://h/user=&password=&channel=1", IP)[1], False)
        for bad in ("http://198.51.100.7/x", "file:///c:/x", "rtsp://h:99999/x", ""):
            self.assertIsNone(onvif.rtsp_without_creds(bad, IP))

    def test_get_stream_uri_allowed(self):
        self.assertIn(b"GetStreamUri", onvif.envelope("GetStreamUri"))
        self.assertEqual(len(onvif.READ_ONLY_ACTIONS), 5)

    def test_stream_uri_from_camera(self):
        class StreamCam(FakeCamera):
            def poster(self, url, body, headers):
                if b"<GetStreamUri " in body:
                    self.posts.append((url, "GetStreamUri", body))
                    uri = f"rtsp://198.51.100.7:554/user=admin&amp;password={CAM_PW}&amp;channel=1&amp;stream=0.sdp"
                    return 200, soap(f"<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{uri}</tt:Uri></trt:MediaUri>"
                                     "</trt:GetStreamUriResponse>")
                return super().poster(url, body, headers)
        fake = StreamCam()
        cam = onvif.Camera(CTX, IP, "http://192.0.2.10:8899/onvif/device_service", "", "", fake.poster)
        url, had = cam.stream_uri(auth=False)
        self.assertEqual(url, f"rtsp://{IP}:554/user=&password=&channel=1&stream=0.sdp")
        self.assertTrue(had)
        self.assertNotIn(CAM_PW, url)
        self.assertEqual({urllib.parse.urlsplit(u).hostname for u, _, _ in fake.posts}, {IP})
        sent = [a for _, a, _ in fake.posts]
        self.assertEqual(sent[-1], "GetStreamUri")
        body = fake.posts[-1][2].decode()
        self.assertIn("<ProfileToken>000</ProfileToken>", body)  # токен из GetProfiles, не угаданный
        self.assertIn("RTP-Unicast", body)


class OpsLaunchTest(unittest.TestCase):
    def run_op(self, d, action, **kw):
        kw.setdefault("tools", TOOLS)
        with mock.patch.object(ops, "latest", return_value=(None, {"devices": [d]})):
            return ops.launch(d["key"], action, ctx=CTX, **kw)

    def test_launch(self):
        calls = []
        out = self.run_op(dev(), "ssh", popen=lambda argv, console: calls.append(argv))
        self.assertEqual(calls[0][-1], IP)
        self.assertIn("SSH", out["message"])

    def test_errors(self):
        with self.assertRaises(ops.OpError) as cm:
            self.run_op(dev(ports=(23,)), "telnet", popen=self.fail)
        self.assertTrue(cm.exception.need_ack)
        with self.assertRaises(ops.OpError) as cm:
            self.run_op(dev(ports=(554,), dev_type="camera"), "vlc", tools=launch.Tools(), stream=lambda d, ip, p: (
                f"rtsp://{ip}:{p}/x", ""))
        self.assertEqual(cm.exception.url, f"rtsp://{IP}:554/x")
        with mock.patch.object(ops, "latest", return_value=(None, {"devices": []})):
            with self.assertRaises(ops.OpError):
                ops.launch(MAC, "ssh", ctx=CTX, tools=TOOLS)

    def test_stream_url_without_onvif(self):
        url, note = ops._stream_url(dev(ports=(554,)), IP, 554)
        self.assertEqual(url, f"rtsp://{IP}:554/")

    def test_stream_url_camera_silent(self):
        d = dev(ports=(554,), dev_type="camera", facts={"onvif": {"anonymous": True}})
        with mock.patch.object(ops, "_camera_address", side_effect=ops.OpError("не ответила")):
            self.assertEqual(ops._stream_url(d, IP, 554)[0], f"rtsp://{IP}:554/")


if __name__ == "__main__":
    unittest.main()
