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
from lanmap.util import PACKAGE_DIR, is_private_mac, norm_mac, read_json, write_json  # noqa: E402

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

    def test_bridge_label_goes_to_dhcp_owner(self):
        # Камера за мостом: роутер видит один MAC с двумя адресами и подписывает оба одинаково.
        # Подпись — владельцу MAC (адрес получен по DHCP), а не устройству за мостом.
        snap = self._snapshot(("S1", "S2"))
        host = {"mac": MAC_B.lower(), "name": "Камера у ворот", "registered": True, "active": True}
        write_json(snap / "raw" / "router.json", {"kind": "keenetic", "data": {"hotspot": {"host": [
            {**host, "ip": "192.0.2.11"}, {**host, "ip": "192.0.2.10", "dhcp": {"expires": 100}}]}}})
        cams = {d["ips"][0]: d for d in devices.build(snap) if d["mac"] == MAC_B}
        self.assertTrue(all(d["duplicate_mac"] for d in cams.values()))
        self.assertEqual(cams["192.0.2.10"]["router"]["label"], "Камера у ворот")
        self.assertIsNone(cams["192.0.2.11"]["router"]["label"])
        self.assertEqual(cams["192.0.2.11"]["router"]["ip"], "192.0.2.11")

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

    def test_twin_found_by_ip_when_key_changes(self):
        data = {"version": 1, "devices": {}}
        registry.sign(data, f"{MAC_B}#S1", {"name": "Камера у ворот"}, ips=["192.0.2.10"])
        # Ключ сменился (другой MAC моста, другой серийник) — подпись находится по адресу
        self.assertEqual(registry.entry_by_ip(data, ["192.0.2.10"])[0], f"{MAC_B}#S1")
        self.assertIsNone(registry.entry_by_ip(data, ["192.0.2.10"], exclude={f"{MAC_B}#S1"}))
        # Подписать под новым ключом — дополняется прежняя запись, а не появляется вторая с тем же адресом
        registry.sign(data, f"{MAC_C}#S2", {"place": "ворота"}, ips=["192.0.2.10"])
        self.assertEqual(list(data["devices"]), [f"{MAC_B}#S1"])
        self.assertEqual(data["devices"][f"{MAC_B}#S1"]["place"], "ворота")
        registry.sign(data, f"{MAC_C}#S3", {"name": "Другая"}, ips=["192.0.2.11"])
        data["devices"][f"{MAC_C}#S3"]["ips"].append("192.0.2.10")
        self.assertIsNone(registry.entry_by_ip(data, ["192.0.2.10"]))  # неоднозначно — не угадываем


class RouterTest(unittest.TestCase):
    def test_clean_label(self):
        from lanmap.routers.keenetic import clean_label
        self.assertEqual(clean_label("TESTPC - Home network - 2026-01-02 03:04"), "TESTPC")
        self.assertIsNone(clean_label("02:00:5e:00:00:0a - Home network - 2026-01-02 03:04"))
        self.assertEqual(clean_label("Камера у ворот"), "Камера у ворот")

    def test_probe_anonymize(self):
        from lanmap.routers.probe import anonymize
        text = anonymize("Location: http://192.0.2.1/ mac 00-00-5E-00-53-0B uuid:12345678-1234-1234-1234-123456789abc "
                         "service:WANCommonInterfaceConfig:1 sid=Ab3dEf6hIj9kLm2nOp5qRs8tUv1")
        self.assertNotIn("192.0.2.1", text)
        self.assertNotIn("00-00-5E", text)
        self.assertIn("<uuid>", text)
        self.assertIn("WANCommonInterfaceConfig", text)
        self.assertIn("<token>", text)

    def test_normalize_and_merge(self):
        from lanmap.routers import keenetic
        raw = {"kind": "keenetic", "data": {
            "version": {"model": "Test (KN-0000)", "title": "1.0"},
            "interfaces": {"WifiMaster1": {"channel": 36}},
            "hotspot": {"host": [
                {"mac": MAC_B.lower(), "ip": "192.0.2.10", "name": "Камера у ворот", "registered": True, "active": True,
                 "port": 2, "speed": 100, "interface": {"name": "Home"}},
                {"mac": MAC_A.lower(), "ip": "192.0.2.20", "name": "Телефон", "registered": True, "active": True,
                 "ap": "WifiMaster1/AccessPoint0", "ssid": "TEST", "rssi": -50, "interface": {"name": "Home"}},
                {"mac": MAC_C.lower(), "ip": "192.0.2.30", "registered": False, "active": False}]},
            "upnp_redirects": {"entry": [{"protocol": "tcp", "port": 50000, "to-address": "192.0.2.10", "to-port": 80}]}}}
        n = keenetic.normalize(raw)
        self.assertEqual(n["clients"][1]["band"], "5 ГГц")
        self.assertEqual(n["clients"][0]["link"], "wired")
        self.assertEqual(len(n["forwards"]), 1)
        snap = Path(tempfile.mkdtemp(dir=TMP.name))
        write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "gateway": "192.0.2.1"}})
        write_json(snap / "raw" / "neighbors.json", [{"ip": "192.0.2.10", "mac": MAC_B, "state": "Reachable"}])
        write_json(snap / "raw" / "router.json", raw)
        devs = {d["mac"]: d for d in devices.build(snap)}
        self.assertEqual(devs[MAC_B]["router"]["label"], "Камера у ворот")
        self.assertTrue(devs[MAC_A]["router_only"] and devs[MAC_A]["alive"])
        self.assertFalse(devs[MAC_C]["alive"])
        r = identify.resolve(devs[MAC_B])
        self.assertEqual(r["name"], "Камера у ворот")


def mdev(key, ips, alive=True, ports=(), mac=None, router_only=False, private=False, firmware=None, serial=None,
         label=None):
    """Устройство в форме модели devices.json — для сравнения срезов."""
    mac = mac if mac is not None else key.partition("#")[0]
    return {"key": key, "mac": mac, "ips": list(ips), "alive": alive, "router_only": router_only,
            "private_mac": private, "services": [{"port": p, "name": None} for p in ports],
            "facts": {"onvif": {"SerialNumber": serial} if serial else {}, "upnp": {}},
            "identity": {"firmware": firmware, "name": None}, "router": {"label": label} if label else None,
            "title": key, "subtitle": ""}


def model(devs, router=None, name="2026-01-01_000000"):
    return {"snapshot": name, "meta": {"started": "2026-01-01T00:00:00"}, "router": router, "devices": devs}


class ChangesTest(unittest.TestCase):
    TESTED = {22, 23, 80, 443}

    def cmp(self, old, new):
        from lanmap import changes
        return changes.compare(old, new, self.TESTED, self.TESTED)

    def test_new_gone_ip_ports(self):
        old = model([mdev(MAC_B, ["192.0.2.10"], ports=[80, 443]), mdev(MAC_C, ["192.0.2.12"])])
        new = model([mdev(MAC_B, ["192.0.2.11"], ports=[23, 80]), mdev("00:00:5E:00:53:0D", ["192.0.2.13"])])
        c = self.cmp(old, new)
        self.assertEqual([d["key"] for d in c["new"]], ["00:00:5E:00:53:0D"])
        self.assertEqual([d["key"] for d in c["gone"]], [MAC_C])
        whats = {x["what"]: x for x in c["by_key"][MAC_B]}
        self.assertIn("ip", whats)
        self.assertEqual(whats["port_open"]["port"], 23)
        self.assertEqual(whats["port_closed"]["port"], 443)

    def test_no_closed_ports_when_silent(self):
        old = model([mdev(MAC_B, ["192.0.2.10"], ports=[80, 443])])
        new = model([mdev(MAC_B, ["192.0.2.10"], alive=False)])
        c = self.cmp(old, new)
        whats = [x["what"] for x in c["by_key"][MAC_B]]
        self.assertEqual(whats, ["offline"])
        self.assertEqual(c["changed"], [])

    def test_phone_closed_ports_ignored_opened_kept(self):
        old = model([mdev(MAC_B, ["192.0.2.10"], ports=[80, 443])])
        new = model([mdev(MAC_B, ["192.0.2.10"], ports=[22])])
        new["devices"][0]["identity"]["type"] = "phone"
        whats = [x["what"] for x in self.cmp(old, new)["by_key"][MAC_B]]
        self.assertEqual(whats, ["port_open"])

    def test_untested_port_is_not_opened(self):
        from lanmap import changes
        old = model([mdev(MAC_B, ["192.0.2.10"], ports=[80])])
        new = model([mdev(MAC_B, ["192.0.2.10"], ports=[80, 8080])])
        c = changes.compare(old, new, {80}, {80, 8080})
        self.assertEqual(c["changed"], [])
        self.assertTrue(c["notes"])

    def test_baseline_without_router_is_not_new(self):
        fw = {"kind": "upnp", "protocol": "tcp", "port": 5000, "to_ip": "192.0.2.10", "to_port": 5000}
        old = model([mdev(MAC_B, ["192.0.2.10"])])
        new = model([mdev(MAC_B, ["192.0.2.10"]), mdev(MAC_C, ["192.0.2.12"], alive=False, router_only=True)],
                    router={"forwards": [fw], "firmware": "1"})
        c = self.cmp(old, new)
        self.assertEqual(c["new"], [])
        self.assertEqual(c["forwards_added"], [])
        self.assertEqual(c["first_seen_router"], {"devices": 1, "forwards": 1})
        # А с данными роутера в обоих срезах новый проброс виден
        old2 = model(old["devices"], router={"forwards": [], "firmware": "1"})
        self.assertEqual(len(self.cmp(old2, new)["forwards_added"]), 1)

    def test_private_macs_counted_not_listed(self):
        old = model([mdev(MAC_A, ["192.0.2.20"], private=True)])
        new = model([mdev("02:00:5E:00:00:0E", ["192.0.2.21"], private=True)])
        c = self.cmp(old, new)
        self.assertEqual((c["new"], c["gone"]), ([], []))
        self.assertEqual(c["private"], {"new": 1, "gone": 1})

    def test_serial_match_when_mac_part_changes(self):
        old = model([mdev(f"{MAC_B}#SN1", ["192.0.2.10"], serial="SN1", firmware="1.0")])
        new = model([mdev(f"{MAC_C}#SN1", ["192.0.2.10"], serial="SN1", firmware="1.1")])
        c = self.cmp(old, new)
        self.assertEqual((c["new"], c["gone"]), ([], []))
        self.assertEqual([x["what"] for x in c["changed"][0]["items"]], ["firmware"])

    def test_other_serial_is_not_firmware_change(self):
        old = model([mdev(MAC_B, ["192.0.2.10"], serial="SN1", firmware="1.0")])
        new = model([mdev(MAC_B, ["192.0.2.10"], serial="SN2", firmware="2.0")])
        c = self.cmp(old, new)
        self.assertEqual([x["what"] for x in c["changed"][0]["items"]], ["serial"])

    def test_previous_snapshot_and_report(self):
        from lanmap import changes
        from lanmap.report import _changes
        base = Path(tempfile.mkdtemp(dir=TMP.name))
        for name in ("2026-01-01_100000", "2026-01-02_100000", "2026-01-03_100000"):
            write_json(base / name / "meta.json", {})
        self.assertEqual(changes.previous_snapshot(base / "2026-01-02_100000").name, "2026-01-01_100000")
        self.assertIsNone(changes.previous_snapshot(base / "2026-01-01_100000"))
        new = model([mdev(MAC_B, ["192.0.2.10"])])
        c = self.cmp(model([]), new)
        self.assertIn("Новые устройства", _changes({**new, "changes": c}))

    def test_render_smoke(self):
        """Отчёт собирается в обоих вариантах: с роутером и изменениями, без роутера и без прошлого среза."""
        from lanmap.report import render

        def rdev(key, ip, dev_type, alive=True, ports=(), router=None):
            d = mdev(key, [ip], alive=alive, ports=ports)
            d["identity"] = {"type": dev_type, "type_label": dev_type, "group": "Камеры" if alive else
                             "Сейчас не в сети (известны роутеру)", "vendor": "Test", "model": "X1", "firmware": "1.0",
                             "os": None, "name": None, "confidence": 3, "chosen": {}, "rules": [], "conflicts": [],
                             "notes": []}
            d.update(is_local=False, is_gateway=False, duplicate_mac=False, evidence=[], registry=None, router=router,
                     actions=[{"kind": "copy", "label": "IP", "value": ip}], subtitle="Камера")
            return d

        fw = {"kind": "upnp", "protocol": "tcp", "port": 5000, "to_ip": "192.0.2.10", "to_port": 5000}
        cam = rdev(MAC_B, "192.0.2.10", "camera", ports=[23, 80],
                   router={"active": True, "link": "wifi", "rssi": -75, "band": "2.4 ГГц"})
        off = rdev(MAC_C, "192.0.2.12", "phone", alive=False, router={"active": False})
        base = model([mdev(MAC_B, ["192.0.2.11"], ports=[80])], router={"forwards": [], "firmware": "1"})
        full = model([cam, off], router={"forwards": [fw], "firmware": "1", "clients": [], "model": "R"})
        full["changes"] = self.cmp(base, full)
        full["meta"].update(admin=True, interface={"network": NET})
        from lanmap import security
        snap = Path(tempfile.mkdtemp(dir=TMP.name))
        full["security"] = security.evaluate(full, snap, self.TESTED, {})
        page = render(full)
        for text in ("Открыто из интернета", "Изменения", "+23", "d-" + MAC_B, "wifi1", "Безопасность",
                     "sec-TELNET_OPEN", "sec-UPNP_PORT_MAPPINGS", "находок безопасности", "Что может сломаться"):
            self.assertIn(text, page)
        bare = model([rdev(MAC_B, "192.0.2.10", "camera")])
        self.assertIn("Сеть", render(bare))


def sdev(key, ip, dev_type, ports=(), alive=True, gateway=False, local=False, facts=None, vendor=None):
    """Устройство модели для проверок безопасности."""
    d = mdev(key, [ip], alive=alive, ports=ports)
    d["facts"].update(facts or {})
    d["identity"] = {"type": dev_type, "vendor": vendor, "firmware": None, "name": None}
    d.update(is_gateway=gateway, is_local=local)
    return d


class SecurityTest(unittest.TestCase):
    TESTED = {23, 80, 111, 2049, 5555, 34567}

    def snap(self, onvif=True, smb=True) -> Path:
        base = Path(tempfile.mkdtemp(dir=TMP.name)) / "2026-01-02_100000"
        (base / "raw").mkdir(parents=True)
        if onvif:
            write_json(base / "raw" / "onvif.json", [])
        if smb:
            write_json(base / "raw" / "smb.json", [])
        return base

    def net(self, router=None, cam_ports=(80, 34567), router_ports=(23, 80), cam_alive=True, started="2026-01-02T10:00:00"):
        devs = [
            sdev(MAC_B, "192.0.2.1", "router", ports=router_ports, gateway=True, vendor="Keenetic"),
            sdev(MAC_C, "192.0.2.10", "camera", ports=cam_ports, alive=cam_alive,
                 facts={"onvif": {"anonymous": True, "Model": "X1"}}),
            sdev("00:00:5E:00:53:0D", "192.0.2.20", "nas", ports=[80, 111, 2049], vendor="Synology",
                 facts={"smb": {"status": "0x0", "dialect": "0x311", "signing_enabled": True, "signing_required": False}}),
            sdev("00:00:5E:00:53:0E", "192.0.2.30", "computer", ports=[445], local=True,
                 facts={"smb": {"status": "0x0", "signing_required": False}}),
        ]
        m = model(devs, router=router)
        m["meta"]["started"] = started
        return m

    def run_checks(self, m, statuses=None, **kw):
        from lanmap import security
        m["security"] = security.evaluate(m, self.snap(**kw), self.TESTED, statuses or {})
        return m["security"]

    def ids(self, sec):
        return sorted((f["id"], f["ips"][0]) for f in sec["findings"])

    def test_findings_and_priorities(self):
        sec = self.run_checks(self.net())
        found = self.ids(sec)
        self.assertIn(("TELNET_OPEN", "192.0.2.1"), found)
        self.assertIn(("CAMERA_XM_PORT", "192.0.2.10"), found)
        self.assertIn(("CAMERA_ONVIF_ANON", "192.0.2.10"), found)
        self.assertIn(("NAS_EXTRA_SERVICES", "192.0.2.20"), found)
        self.assertIn(("SMB_SIGNING", "192.0.2.20"), found)
        self.assertNotIn(("SMB_SIGNING", "192.0.2.30"), found)  # этот компьютер не проверяем по сети
        telnet = next(f for f in sec["findings"] if f["id"] == "TELNET_OPEN")
        self.assertEqual(telnet["priority"], 1)  # Telnet на роутере — срочно
        self.assertFalse(sec["evaluated"]["UPNP_PORT_MAPPINGS"])  # нет данных роутера — не «чисто», а «нечем проверить»
        self.assertIn("UPNP_PORT_MAPPINGS", sec["skipped"])

    def test_upnp_needs_router(self):
        fw = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": 5000}
        sec = self.run_checks(self.net(router={"forwards": [fw, {**fw, "kind": "static"}]}))
        upnp = [f for f in sec["findings"] if f["id"] == "UPNP_PORT_MAPPINGS"]
        self.assertEqual(len(upnp), 1)
        self.assertEqual(upnp[0]["key"], "00:00:5E:00:53:0D")
        self.assertTrue(upnp[0]["router_based"])

    def test_card_lists_every_device_with_own_steps(self):
        """Карточка перечисляет все устройства; у каждого своя инструкция: под производителя или общая."""
        import re as _re
        from lanmap import report
        fw = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": 5000}
        m = self.net(router={"forwards": [fw, {**fw, "port": 50001, "to_ip": "192.0.2.10", "to_port": 80}]})
        self.run_checks(m)
        html_ = report._security(m)
        card = _re.search(r'<article[^>]*id="sec-UPNP_PORT_MAPPINGS".*?</article>', html_, _re.S).group(0)
        rows = _re.findall(r'<details class="drow.*?</details>', card, _re.S)
        self.assertEqual(len(rows), 2)
        nas = next(r for r in rows if "192.0.2.20" in r)
        cam = next(r for r in rows if "192.0.2.10" in r)
        self.assertIn("Конфигурация маршрутизатора", nas)      # путь Synology — только у NAS
        self.assertNotIn("Конфигурация маршрутизатора", cam)
        self.assertIn("Автонастройка роутера", cam)           # у неизвестного — общая инструкция
        self.assertIn("общая инструкция", cam)                 # и значок честно говорит, что она общая
        self.assertNotIn("общая инструкция", nas)
        # Модуля роутера (kind) нет — марку берём у шлюза: подсказка Keenetic у обоих
        self.assertIn("набор компонентов", nas)
        self.assertIn("набор компонентов", cam)
        self.assertIn("2 двери", card)                         # число пробросов на стрелке схемы
        self.assertEqual(report.plural(5, ("дверь", "двери", "дверей")), "5 дверей")
        self.assertEqual(report.plural(21, ("дверь", "двери", "дверей")), "21 дверь")

    def test_missing_raw_is_not_clean(self):
        sec = self.run_checks(self.net(), onvif=False, smb=False)
        self.assertFalse(sec["evaluated"]["CAMERA_ONVIF_ANON"])
        self.assertFalse(sec["evaluated"]["SMB_SIGNING"])

    def test_statuses_and_regress(self):
        from lanmap import security
        u = security.uid("TELNET_OPEN", MAC_B)
        sec = self.run_checks(self.net(), {u: {"status": "fixed", "updated": "2026-01-01T00:00:00"}})
        self.assertEqual(next(f for f in sec["findings"] if f["uid"] == u)["status"], "regress")
        sec = self.run_checks(self.net(started="2025-12-31T00:00:00"), {u: {"status": "fixed", "updated": "2026-01-01T00:00:00"}})
        self.assertEqual(next(f for f in sec["findings"] if f["uid"] == u)["status"], "fixed_pending")
        sec = self.run_checks(self.net(), {u: {"status": "accepted", "updated": "2026-01-01T00:00:00"}})
        self.assertNotIn(u, [f["uid"] for f in security.open_findings(sec)])
        # Статус живёт в data/findings.json
        security.set_status("TELNET_OPEN", MAC_B, "accepted", "нужен для скрипта")
        self.assertEqual(security.load_statuses()[u]["status"], "accepted")
        security.set_status("TELNET_OPEN", MAC_B, "open")
        self.assertNotIn(u, security.load_statuses())
        with self.assertRaises(ValueError):
            security.set_status("NO_SUCH", MAC_B, "open")

    def test_findings_diff(self):
        from lanmap import changes
        old, new = self.net(), self.net(router_ports=(80,), cam_ports=(80,), cam_alive=True)
        self.run_checks(old)
        self.run_checks(new)
        c = changes.compare(old, new, self.TESTED, self.TESTED)
        gone = sorted(f["id"] for f in c["findings_removed"])
        self.assertEqual(gone, ["CAMERA_XM_PORT", "TELNET_OPEN"])
        self.assertEqual(c["findings_added"], [])
        # Камера не ответила — её находка не «исправлена», а просто не проверена
        new2 = self.net(router_ports=(80,), cam_alive=False)
        self.run_checks(new2)
        c2 = changes.compare(old, new2, self.TESTED, self.TESTED)
        self.assertEqual(sorted(f["id"] for f in c2["findings_removed"]), ["TELNET_OPEN"])
        # Обратно: Telnet открылся — новая находка и значок на плитке
        c3 = changes.compare(new, old, self.TESTED, self.TESTED)
        self.assertIn("TELNET_OPEN", [f["id"] for f in c3["findings_added"]])
        self.assertIn("finding", [x["what"] for x in c3["by_key"][MAC_B]])

    def test_first_check_is_not_new(self):
        from lanmap import changes
        old = self.net()
        self.run_checks(old, onvif=False)
        new = self.net()
        self.run_checks(new)
        c = changes.compare(old, new, self.TESTED, self.TESTED)
        self.assertNotIn("CAMERA_ONVIF_ANON", [f["id"] for f in c["findings_added"]])
        self.assertTrue(any("нечем было проверить" in n for n in c["notes"]))


IGD_DESC = """<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
<serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<controlURL>/ctl/L3F</controlURL></service></serviceList>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
<deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
<serviceList>
<service><serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</serviceType><controlURL>/ctl/PPP</controlURL></service>
<service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><controlURL>/ctl/IPConn</controlURL></service>
</serviceList></device></deviceList></device></deviceList></device></root>"""


class StatusCascadeTest(unittest.TestCase):
    """Отметки владельца не теряются, когда ключ камеры (MAC#серийник) плавает."""
    M1, M2 = "00:00:5E:00:53:21", "00:00:5E:00:53:22"

    def match(self, keys, statuses):
        from lanmap import security
        return security._match_statuses("CAMERA_ONVIF_ANON", keys, statuses)

    def test_moved_by_ip(self):
        saved = {f"CAMERA_ONVIF_ANON|{self.M1}#S1": {"status": "accepted", "ips": ["192.0.2.10"]}}
        got = self.match([(f"{self.M2}#S2", ["192.0.2.10"]), (f"{self.M2}#S3", ["192.0.2.11"])], saved)
        self.assertEqual(got, [(f"CAMERA_ONVIF_ANON|{self.M1}#S1", "ip"), (None, None)])

    def test_ip_before_serial(self):
        # Серийник S1 «перескочил» на другую камеру — адрес главнее
        saved = {f"CAMERA_ONVIF_ANON|{self.M1}#S1": {"status": "accepted", "ips": ["192.0.2.10"]}}
        got = self.match([(f"{self.M1}#S1", ["192.0.2.11"]), (self.M1, ["192.0.2.10"])], saved)
        self.assertEqual(got[0], (f"CAMERA_ONVIF_ANON|{self.M1}#S1", None))  # точный ключ — первым делом
        self.assertEqual(got[1], (None, None))  # одна отметка — одной находке

    def test_shared_mac_is_ambiguous(self):
        saved = {f"CAMERA_ONVIF_ANON|{self.M1}#S9": {"status": "accepted"}}  # старая запись без адресов
        got = self.match([(f"{self.M1}#S1", ["192.0.2.10"]), (f"{self.M1}#S2", ["192.0.2.11"])], saved)
        self.assertEqual(got, [(None, None), (None, None)])  # MAC у двух находок — не угадываем

    def test_set_status_replaces_moved_mark(self):
        from lanmap import security
        old = f"{self.M1}#S1"
        security.set_status("CAMERA_ONVIF_ANON", old, "accepted", "тест", ips=["192.0.2.10"])
        new = f"{self.M2}#S2"
        (su, via), = self.match([(new, ["192.0.2.10"])], security.load_statuses())
        self.assertEqual((su, via), (security.uid("CAMERA_ONVIF_ANON", old), "ip"))
        security.set_status("CAMERA_ONVIF_ANON", new, "open", replace=su)  # снять отметку, найденную по адресу
        self.assertEqual(self.match([(new, ["192.0.2.10"])], security.load_statuses()), [(None, None)])
        entry = security.set_status("CAMERA_ONVIF_ANON", new, "accepted", ips=["192.0.2.10"])
        self.assertEqual((entry["mac"], entry["serial"], entry["ips"]), (self.M2, "S2", ["192.0.2.10"]))
        security.set_status("CAMERA_ONVIF_ANON", new, "open")


class ChecklistTest(unittest.TestCase):
    """Чек-лист E1–E9: четыре исхода и «был X, стал Y»."""

    def net(self, router=None):
        cam = sdev(MAC_C, "192.0.2.10", "camera")
        nas = sdev("00:00:5E:00:53:0D", "192.0.2.20", "nas")
        pc = sdev("00:00:5E:00:53:0E", "192.0.2.30", "computer", local=True)
        gw = sdev(MAC_B, "192.0.2.1", "router", gateway=True)
        for d, conf in ((cam, 3), (nas, 4), (pc, 4), (gw, 4)):
            d["identity"]["confidence"] = conf
        return model([gw, cam, nas, pc], router=router)

    def items(self, m, marks=None):
        from lanmap import checklist
        return {c["id"]: c for c in checklist.evaluate(m, marks or {})["criteria"]}

    def test_without_router_and_checks(self):
        c = self.items(self.net())
        self.assertEqual(c["E1"]["status"], "ok")
        for code in ("E2", "E3", "E4", "E9"):
            self.assertEqual(c[code]["status"], "unknown", code)  # нечем проверить — не «выполнен»
        self.assertEqual(c["E6"]["status"], "owner")
        self.assertEqual(self.items(self.net(), {"E8": {"status": "done"}})["E8"]["status"], "ok")

    def test_e1_router_label_counts(self):
        m = self.net()
        m["devices"][1]["identity"]["confidence"] = 1
        self.assertEqual(self.items(m)["E1"]["status"], "fail")
        self.assertEqual(self.items(m)["E1"]["devices"][0]["key"], MAC_C)
        m["devices"][1]["router"] = {"label": "Камера у ворот"}  # подписано в роутере — засчитывается
        self.assertEqual(self.items(m)["E1"]["status"], "ok")

    def test_findings_based(self):
        from lanmap import security
        m = self.net(router={"forwards": [], "reservations": []})
        m["devices"][0]["services"] = [{"port": 23, "name": None}]
        m["security"] = security.evaluate(m, SecurityTest().snap(), {23}, {})
        c = self.items(m)
        self.assertEqual(c["E4"]["status"], "fail")
        self.assertEqual(c["E4"]["findings"][0]["id"], "TELNET_OPEN")
        self.assertEqual(c["E2"]["status"], "ok")  # роутер прочитан, пробросов нет
        # Telnet оставлен осознанно — критерий не мешает
        m["security"] = security.evaluate(m, SecurityTest().snap(), {23},
                                          {security.uid("TELNET_OPEN", MAC_B): {"status": "accepted"}})
        self.assertEqual(self.items(m)["E4"]["status"], "ok")

    def test_static_forward_is_e2(self):
        from lanmap import security
        fw = {"kind": "static", "protocol": "udp", "port": 51820, "to_ip": "192.0.2.20", "to_port": 51820}
        m = self.net(router={"forwards": [fw], "reservations": []})
        m["security"] = security.evaluate(m, SecurityTest().snap(), set(), {})
        self.assertEqual([f["id"] for f in m["security"]["findings"]], ["STATIC_PORT_FORWARD"])
        self.assertEqual(self.items(m)["E2"]["status"], "fail")
        m["security"] = security.evaluate(m, SecurityTest().snap(), set(), {
            security.uid("STATIC_PORT_FORWARD", "00:00:5E:00:53:0D"): {"status": "accepted", "reason": "VPN"}})
        self.assertEqual(self.items(m)["E2"]["status"], "ok")

    def test_e3_segments_and_e9_reservations(self):
        m = self.net(router={"forwards": [], "reservations": [{"mac": "00:00:5e:00:53:0d", "ip": "192.0.2.20"}]})
        for d, seg in zip(m["devices"], ("Home", "Home", "Home", "Home")):
            d["router"] = {"segment": seg}
        c = self.items(m)
        self.assertEqual((c["E3"]["status"], c["E3"]["likely"]), ("fail", True))
        self.assertEqual(c["E3"]["devices"][0]["key"], MAC_C)
        self.assertEqual((c["E9"]["status"], c["E9"]["done"], c["E9"]["total"]), ("fail", 1, 2))  # камера без резервации
        m["devices"][1]["router"]["segment"] = "Guest"
        m["router"]["reservations"].append({"mac": MAC_C.lower(), "ip": "192.0.2.10"})
        c = self.items(m)
        self.assertEqual(c["E3"]["status"], "ok")
        self.assertEqual(c["E9"]["status"], "ok")
        m["router"]["reservations"] = None  # модуль роутера резервации не читает
        self.assertEqual(self.items(m)["E9"]["status"], "unknown")

    def test_compare(self):
        from lanmap import checklist

        def cl(**st):
            items = [{"id": k, "status": v} for k, v in st.items()]
            return {"criteria": items, "score": sum(1 for v in st.values() if v == "ok")}
        d = checklist.compare(cl(E1="fail", E2="ok", E3="unknown", E4="ok"), cl(E1="ok", E2="fail", E3="ok", E4="unknown"))
        self.assertEqual((d["better"], d["worse"]), (["E1"], ["E2"]))  # E3 и E4 нечем было проверить — не изменение
        self.assertEqual((d["old"], d["new"]), (2, 2))

    def test_keenetic_reservations(self):
        from lanmap.routers import keenetic
        base = {"kind": "keenetic", "data": {"version": {}}, "errors": {}}
        self.assertIsNone(keenetic.normalize(base)["reservations"])  # старый срез: не читали
        base["data"]["dhcp_hosts"] = [{"mac": MAC_B, "ip": "192.0.2.10"}]
        self.assertEqual(keenetic.normalize(base)["reservations"], [{"mac": MAC_B.lower(), "ip": "192.0.2.10"}])

    def test_set_mark(self):
        from lanmap import checklist
        checklist.set_mark("e8", "done", "восстановил файл")
        self.assertEqual(checklist.load_marks()["E8"]["note"], "восстановил файл")
        with self.assertRaises(ValueError):
            checklist.set_mark("E4", "done")  # проверяется по срезу
        checklist.set_mark("E8", "open")
        self.assertNotIn("E8", checklist.load_marks())


def soap_ok(**fields) -> bytes:
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:R xmlns:u="urn:x">{inner}</u:R></s:Body></s:Envelope>').encode()


def soap_fault(code: str, text: str) -> bytes:
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>'
            f'<faultstring>UPnPError</faultstring><detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">'
            f'<errorCode>{code}</errorCode><errorDescription>{text}</errorDescription></UPnPError></detail>'
            f'</s:Fault></s:Body></s:Envelope>').encode()


class FakeGateway:
    """Выдуманный шлюз IGD: отвечает на SOAP без сети и запоминает действия."""

    def __init__(self, entries, external="8.8.8.8", fail_at=None):  # публичный адрес (адреса RFC 5737 Python считает частными)
        self.entries, self.external, self.fail_at, self.actions = entries, external, fail_at, []

    def __call__(self, url, data, headers):
        action = headers["SOAPAction"].strip('"').split("#")[1]
        self.actions.append(action)
        if action == "GetExternalIPAddress":
            return 200, soap_ok(NewExternalIPAddress=self.external)
        index = int(re.search(rb"<NewPortMappingIndex>(\d+)<", data)[1])
        if index == self.fail_at:
            return 500, soap_fault("501", "ActionFailed")
        if index >= len(self.entries):
            return 500, soap_fault("713", "SpecifiedArrayIndexInvalid")
        return 200, soap_ok(**self.entries[index])


def igd_entry(port, to_ip, to_port, proto="TCP", enabled="1"):
    return {"NewRemoteHost": "", "NewExternalPort": port, "NewProtocol": proto, "NewInternalPort": to_port,
            "NewInternalClient": to_ip, "NewEnabled": enabled, "NewPortMappingDescription": "app",
            "NewLeaseDuration": 0}


class IgdTest(unittest.TestCase):
    CTX = ScanContext(local_ip="192.0.2.50", network="192.0.2.0/24", gateway="192.0.2.1", if_index=0)
    DESC = [{"url": "http://192.0.2.1:1900/rootDesc.xml", "ip": "192.0.2.1", "body": IGD_DESC}]

    def test_services_from_nested_description(self):
        from lanmap.collectors import igd
        svcs = igd.wan_services(IGD_DESC, "http://192.0.2.1:1900/rootDesc.xml")
        self.assertEqual([s["service"].split(":")[-2] for s in svcs], ["WANIPConnection", "WANPPPConnection"])
        self.assertEqual(svcs[0]["control_url"], "http://192.0.2.1:1900/ctl/IPConn")  # относительный → абсолютный

    def test_only_read_actions(self):
        from lanmap.collectors import igd
        for action in ("AddPortMapping", "DeletePortMapping", "SetConnectionType", "ForceTermination"):
            with self.assertRaises(PermissionError):
                igd.envelope("urn:schemas-upnp-org:service:WANIPConnection:1", action)

    def test_full_list_and_normalize(self):
        from lanmap.collectors import igd
        gw = FakeGateway([igd_entry(50000, "192.0.2.20", 5000), igd_entry(50001, "192.0.2.21", 80, enabled="0")])
        raw = igd.collect(self.CTX, self.DESC, post=gw)
        g = raw["gateways"][0]
        self.assertTrue(g["complete"])
        self.assertEqual(g["termination"]["code"], "713")
        self.assertEqual(set(gw.actions), igd.READ_ONLY_ACTIONS)
        n = igd.normalize(raw)
        self.assertEqual(n["forwards"], [{"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20",
                                          "to_port": 5000, "description": "app", "source": "igd"}])  # выключенная — пропущена
        self.assertEqual(n["external_scope"], "public")

    def test_broken_list_is_not_complete(self):
        from lanmap.collectors import igd
        raw = igd.collect(self.CTX, self.DESC, post=FakeGateway([igd_entry(50000, "192.0.2.20", 5000)] * 3, fail_at=1))
        self.assertFalse(raw["gateways"][0]["complete"])
        self.assertFalse(igd.normalize(raw)["complete"])

    def test_control_url_outside_subnet_is_skipped(self):
        from lanmap.collectors import igd
        body = IGD_DESC.replace("<root xmlns=\"urn:schemas-upnp-org:device-1-0\">",
                                "<root xmlns=\"urn:schemas-upnp-org:device-1-0\"><URLBase>http://198.51.100.9/</URLBase>")
        gw = FakeGateway([])
        self.assertEqual(igd.collect(self.CTX, [{**self.DESC[0], "body": body}], post=gw), {"gateways": []})
        self.assertEqual(gw.actions, [])

    def test_external_scope(self):
        from lanmap.collectors import igd
        self.assertEqual(igd.external_scope("100.64.1.2"), "cgnat")
        self.assertEqual(igd.external_scope("198.51.100.4"), "private")  # служебные адреса Python считает частными
        self.assertEqual(igd.external_scope("203.0.113.300"), None)
        self.assertEqual(igd.external_scope("0.0.0.0"), None)
        self.assertEqual(igd.external_scope("8.8.8.8"), "public")

    def igd_model(self, entries, external="8.8.8.8", fail_at=None, router=None):
        from lanmap.collectors import igd
        t = SecurityTest()
        m = t.net(router=router)
        m["igd"] = igd.normalize(igd.collect(self.CTX, self.DESC, post=FakeGateway(entries, external, fail_at)))
        return t, m

    def test_upnp_check_without_router(self):
        t, m = self.igd_model([igd_entry(50000, "192.0.2.20", 5000)])
        sec = t.run_checks(m)
        self.assertTrue(sec["evaluated"]["UPNP_PORT_MAPPINGS"])
        f = next(f for f in sec["findings"] if f["id"] == "UPNP_PORT_MAPPINGS")
        self.assertEqual((f["ips"][0], f["confidence"], f["priority"]), ("192.0.2.20", "confirmed", 1))
        # За NAT провайдера — «вероятно», и карточка объясняет почему
        t, m = self.igd_model([igd_entry(50000, "192.0.2.20", 5000)], external="100.64.1.2")
        sec = t.run_checks(m)
        nat = next(f for f in sec["findings"] if f["id"] == "UPNP_PORT_MAPPINGS")
        self.assertEqual((nat["confidence"], nat["priority"]), ("likely", 2))
        from lanmap import report
        self.assertIn("CGNAT", report._security(m))
        # Список прочитан не до конца — не «чисто», а «нечем проверить»
        t, m = self.igd_model([igd_entry(50000, "192.0.2.20", 5000)] * 3, fail_at=1)
        self.assertFalse(t.run_checks(m)["evaluated"]["UPNP_PORT_MAPPINGS"])

    def test_router_and_igd_do_not_duplicate(self):
        from lanmap import forwards
        fw = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": "5000"}
        _, m = self.igd_model([igd_entry(50000, "192.0.2.20", 5000), igd_entry(50002, "192.0.2.20", 22)],
                              router={"forwards": [fw]})
        self.assertEqual(len(forwards.merged(m)), 2)
        self.assertEqual(forwards.merged(m)[0], fw)  # запись роутера главнее

    def test_compare_router_vs_igd_only(self):
        from lanmap import changes
        upnp = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": 5000}
        static = {"kind": "static", "protocol": "tcp", "port": 443, "to_ip": "192.0.2.20", "to_port": 443}
        old = SecurityTest().net(router={"forwards": [upnp, static]})
        _, new = self.igd_model([igd_entry(50000, "192.0.2.20", 5000), igd_entry(50003, "192.0.2.21", 80)])
        c = changes.compare(old, new)
        self.assertEqual(c["forwards_removed"], [])  # статический не «закрылся»: его просто не видно без роутера
        self.assertEqual([f["port"] for f in c["forwards_added"]], [50003])
        self.assertTrue(any("UPnP-пробросы сравнены" in n for n in c["notes"]))


class ServerTest(unittest.TestCase):
    """Локальный веб-интерфейс: доступ только с токеном и с петлевого адреса, кнопки пишут отметки."""

    @classmethod
    def setUpClass(cls):
        import threading
        from lanmap import server
        from lanmap.build import build
        snap = Path(TMP.name) / "snapshots" / "2026-01-01_000000"
        raw = snap / "raw"
        write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "gateway": "192.0.2.1", "mac": MAC_C,
                                                      "network": NET}, "hostname": "TESTPC", "admin": True})
        write_json(raw / "neighbors.json", [{"ip": "192.0.2.10", "mac": MAC_B, "state": "Reachable"}])
        write_json(raw / "ping.json", {"192.0.2.10": {"alive": True, "ttl": 64}})
        write_json(raw / "ports.json", {"tested": [23, 80], "open": {"192.0.2.10": [23]}})
        cls.snap = snap
        cls.model = build(snap)
        cls.httpd = server.make_server(0, token="test-token")
        cls.httpd.RequestHandlerClass.log_message = lambda *a: None
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def req(self, method, path, body=None, headers=None, host=None):
        import http.client
        import json
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Host": host or f"127.0.0.1:{self.port}"}
        hdrs.update(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs.setdefault("Content-Type", "application/json")
        conn.request(method, path, body=data, headers=hdrs)
        r = conn.getresponse()
        out = r.status, dict(r.getheaders()), r.read().decode("utf-8")
        conn.close()
        return out

    def api(self, path, body, token="test-token"):
        import json
        code, _, text = self.req("POST", path, body, {"X-LanMap-Token": token})
        return code, json.loads(text)

    def test_page_needs_token_and_host(self):
        self.assertEqual(self.req("GET", "/")[0], 403)
        self.assertEqual(self.req("GET", "/?t=wrong")[0], 403)
        self.assertEqual(self.req("GET", "/?t=test-token", host="evil.example:80")[0], 403)
        code, headers, _ = self.req("GET", "/?t=test-token")
        self.assertEqual(code, 303)
        cookie = headers["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        code, _, page = self.req("GET", "/", headers={"Cookie": cookie})
        self.assertEqual(code, 200)
        self.assertIn('window.LANMAP={"token": "test-token"}', page)
        self.assertIn("data-finding=", page)
        self.assertNotIn("test-token", (self.snap / "report.html").read_text("utf-8"))  # файл отчёта без токена
        self.assertEqual(self.req("GET", "/", headers={"Cookie": cookie}, host="evil.example")[0], 403)

    def test_api_needs_header_token(self):
        self.assertEqual(self.api("/api/check", {"code": "E8", "status": "done"}, token="")[0], 403)
        self.assertEqual(self.api("/api/check", {"code": "E8", "status": "done"}, token="wrong")[0], 403)
        code, _, _ = self.req("POST", "/api/check", {"code": "E8", "status": "done"},
                              {"X-LanMap-Token": "test-token"}, host="evil.example")
        self.assertEqual(code, 403)
        self.assertEqual(self.req("OPTIONS", "/api/check")[0], 403)
        code, _, _ = self.req("POST", "/api/check", {"code": "E8"},
                              {"X-LanMap-Token": "test-token", "Content-Type": "text/plain"})
        self.assertEqual(code, 415)

    def test_buttons_write_marks(self):
        from lanmap import checklist, registry, security
        code, out = self.api("/api/check", {"code": "E8", "status": "done", "note": "восстановил файл"})
        self.assertEqual((code, out["status"]), (200, "done"))
        self.assertEqual(checklist.load_marks()["E8"]["note"], "восстановил файл")
        self.assertEqual(self.api("/api/check", {"code": "E2", "status": "done"})[0], 400)

        found = [f for f in self.model["security"]["findings"] if f["id"] == "TELNET_OPEN"]
        self.assertTrue(found)
        code, out = self.api("/api/finding", {"check": "TELNET_OPEN", "key": found[0]["key"], "status": "accepted",
                                              "reason": "так надо"})
        self.assertEqual(code, 200)
        saved = security.load_statuses()[security.uid("TELNET_OPEN", found[0]["key"])]
        self.assertEqual((saved["status"], saved["reason"], saved["ips"]), ("accepted", "так надо", ["192.0.2.10"]))

        code, out = self.api("/api/sign", {"key": MAC_B, "fields": {"name": "Тестовая камера", "place": ""}})
        self.assertEqual((code, out["name"]), (200, "Тестовая камера"))
        self.assertTrue(registry.load()["devices"][MAC_B]["confirmed"])
        self.assertEqual(self.api("/api/sign", {"key": MAC_B, "fields": {"confirmed": "1"}})[0], 400)
        self.assertEqual(self.api("/api/sign", {"key": "не MAC", "fields": {"name": "x"}})[0], 400)
        model = read_json(self.snap / "devices.json")  # отчёт пересобран
        self.assertEqual(next(d for d in model["devices"] if d["key"] == MAC_B)["title"], "Тестовая камера")


class NoNetworkSpecificsTest(unittest.TestCase):
    def test_no_control_characters(self):
        for path in list(PACKAGE_DIR.rglob("*.py")) + list(PACKAGE_DIR.rglob("*.json")):
            bad = re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", path.read_text("utf-8"))
            self.assertIsNone(bad, f"управляющий символ в {path}")

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
