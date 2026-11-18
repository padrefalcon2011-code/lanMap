"""Тесты LanMap. Только адреса из документационных диапазонов (RFC 5737) и выдуманные MAC."""
from __future__ import annotations

import os
import re
import struct
import tempfile
import unittest
from pathlib import Path

TMP = tempfile.TemporaryDirectory()
os.environ["LANMAP_DATA"] = TMP.name  # тесты не трогают настоящий data/

from lanmap import devices, identify, registry  # noqa: E402
from lanmap.collectors import ScanContext, dnswire  # noqa: E402
from lanmap.util import PACKAGE_DIR, is_private_mac, norm_mac, write_json  # noqa: E402

NET = "192.0.2.0/24"
MAC_A = "02:00:5E:00:00:0A"   # локально назначенный (как частный MAC)
MAC_B = "00:00:5E:00:53:0B"   # диапазон IANA для документации
MAC_C = "00:00:5E:00:53:0C"


def device(**facts) -> dict:
    base = {"ports": [], "mdns_services": [], "mdns_txt": {}, "upnp": {}, "onvif": {}, "http": [], "tls": [],
            "rtsp": [], "ssdp_server": [], "wsd_types": [], "oui": None, "private_mac": False}
    base.update(facts)
    return {"key": MAC_B, "mac": MAC_B, "ips": ["192.0.2.10"], "is_local": False, "is_gateway": False,
            "facts": base, "services": [], "evidence": []}


class UtilTest(unittest.TestCase):
    def test_norm_mac(self):
        self.assertEqual(norm_mac("00-00-5e-00-53-0b"), MAC_B)
        self.assertIsNone(norm_mac("FF-FF-FF-FF-FF-FF"))
        self.assertIsNone(norm_mac("01-00-5E-00-00-FB"))  # групповой
        self.assertIsNone(norm_mac(""))

    def test_private_mac(self):
        self.assertTrue(is_private_mac(MAC_A))
        self.assertFalse(is_private_mac(MAC_B))

    def test_scope(self):
        ctx = ScanContext(local_ip="192.0.2.5", network=NET, gateway="192.0.2.1", if_index=1)
        self.assertTrue(ctx.in_scope("192.0.2.77"))
        self.assertFalse(ctx.in_scope("198.51.100.7"))
        self.assertFalse(ctx.in_scope("192.0.2.255"))
        self.assertFalse(ctx.in_scope("example.com"))


class DnsTest(unittest.TestCase):
    def test_roundtrip(self):
        name = dnswire.encode_name("cam._http._tcp.local")
        target = dnswire.encode_name("cam.local")
        srv = struct.pack("!HHH", 0, 0, 80) + target
        txt = bytes([5]) + b"md=X1"
        a = bytes([192, 0, 2, 9])
        pkt = struct.pack("!6H", 0, 0x8400, 0, 3, 0, 0)
        pkt += name + struct.pack("!HHIH", 33, 1, 120, len(srv)) + srv
        pkt += name + struct.pack("!HHIH", 16, 1, 120, len(txt)) + txt
        pkt += target + struct.pack("!HHIH", 1, 1, 120, 4) + a
        recs = dnswire.parse_records(pkt)
        self.assertEqual(recs[0]["value"], {"port": 80, "target": "cam.local"})
        self.assertEqual(recs[1]["value"], ["md=X1"])
        self.assertEqual(recs[2]["value"], "192.0.2.9")


class IdentifyTest(unittest.TestCase):
    def test_xiongmai_by_ports(self):
        r = identify.resolve(device(ports=[80, 554, 8899, 34567]))
        self.assertEqual(r["type"], "camera")
        self.assertEqual(r["vendor"], "Xiongmai (XM)")
        self.assertGreaterEqual(r["confidence"], 3)

    def test_onvif_placeholder_vendor_ignored(self):
        r = identify.resolve(device(ports=[554, 8899, 34567],
                                    onvif={"Manufacturer": "H264", "Model": "TESTCAM-1", "FirmwareVersion": "1.0"}))
        self.assertEqual(r["vendor"], "Xiongmai (XM)")
        self.assertEqual(r["model"], "TESTCAM-1")
        self.assertEqual(r["confidence"], 4)

    def test_printer_from_mdns(self):
        r = identify.resolve(device(mdns_services=["_ipp._tcp"], mdns_txt={"ty": "Test Printer 100", "usb_mfg": "TESTCO"}))
        self.assertEqual(r["type"], "printer")
        self.assertEqual(r["model"], "Test Printer 100")

    def test_private_mac_without_ports_is_weak_phone(self):
        d = device(private_mac=True)
        r = identify.resolve(d)
        self.assertEqual(r["type"], "phone")
        self.assertEqual(r["confidence"], 1)

    def test_unknown(self):
        r = identify.resolve(device(ports=[12345]))
        self.assertEqual(r["type"], "unknown")
        self.assertEqual(r["confidence"], 0)

    def test_confirmed_registry_wins(self):
        r = identify.resolve(device(ports=[34567, 554]), {"name": "Камера у ворот", "type": "camera", "confirmed": True})
        self.assertEqual(r["name"], "Камера у ворот")
        self.assertEqual(r["confidence"], 4)

    def test_draft_registry_does_not_override(self):
        r = identify.resolve(device(ports=[62078]), {"type": "nas", "confirmed": False, "source": "codex-x"})
        self.assertEqual(r["type"], "phone")

    def test_all_rule_conditions_known(self):
        d = device()
        for rule in identify.load_rules():
            identify.rule_matches(rule, d)  # не должно бросать «неизвестное условие»


class DevicesTest(unittest.TestCase):
    def _snapshot(self, onvif_serials: tuple[str, str]) -> Path:
        snap = Path(tempfile.mkdtemp(dir=TMP.name))
        raw = snap / "raw"
        write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "gateway": "192.0.2.1", "mac": MAC_C},
                                        "hostname": "TESTPC"})
        write_json(raw / "neighbors.json", [{"ip": "192.0.2.10", "mac": MAC_B, "state": "Reachable"},
                                            {"ip": "192.0.2.11", "mac": MAC_B, "state": "Reachable"}])
        write_json(raw / "ping.json", {"192.0.2.10": {"alive": True, "ttl": 64}, "192.0.2.11": {"alive": True, "ttl": 64}})
        write_json(raw / "ports.json", {"open": {"192.0.2.10": [554, 34567], "192.0.2.11": [554, 34567]}})
        write_json(raw / "onvif.json", [
            {"ip": "192.0.2.10", "fields": {"Model": "M1", "SerialNumber": onvif_serials[0]}},
            {"ip": "192.0.2.11", "fields": {"Model": "M1", "SerialNumber": onvif_serials[1]}}])
        return snap

    def test_one_mac_two_ips_same_device(self):
        devs = devices.build(self._snapshot(("S1", "S1")))
        cams = [d for d in devs if d["mac"] == MAC_B]
        self.assertEqual(len(cams), 1)
        self.assertEqual(cams[0]["ips"], ["192.0.2.10", "192.0.2.11"])

    def test_duplicate_mac_split_by_serial(self):
        devs = devices.build(self._snapshot(("S1", "S2")))
        cams = [d for d in devs if d["mac"] == MAC_B]
        self.assertEqual(len(cams), 2)
        self.assertTrue(all(d["duplicate_mac"] for d in cams))

    def test_local_computer_named(self):
        devs = devices.build(self._snapshot(("S1", "S1")))
        me = next(d for d in devs if d["is_local"])
        self.assertEqual(me["facts"]["netbios"]["computer"], "TESTPC")


class RegistryTest(unittest.TestCase):
    def test_sign_and_alias(self):
        data = {"version": 1, "devices": {}}
        registry.sign(data, MAC_B.replace(":", "-").lower(), {"name": "NAS", "trust": "own"})
        data["devices"][MAC_B]["also_macs"] = [MAC_C]
        self.assertTrue(data["devices"][MAC_B]["confirmed"])
        self.assertEqual(registry.aliases(data), {MAC_C: MAC_B})
        with self.assertRaises(ValueError):
            registry.sign(data, MAC_B, {"trust": "maybe"})


class NoNetworkSpecificsTest(unittest.TestCase):
    """Жёсткое правило: в коде нет IP и MAC конкретной сети."""

    PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
    MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")

    def test_package_has_no_private_addresses(self):
        for path in PACKAGE_DIR.rglob("*"):
            if path.suffix not in (".py", ".json", ".html", ".txt"):
                continue
            text = path.read_text("utf-8").replace("AA:BB:CC:DD:EE:FF", "")  # шаблон в подсказках
            self.assertIsNone(self.PRIVATE_IP.search(text), f"частный IP в {path}")
            self.assertIsNone(self.MAC.search(text), f"MAC-адрес в {path}")


if __name__ == "__main__":
    unittest.main()
