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


def finish_snapshot(snap: Path, **meta) -> Path:
    """Тестовый срез как завершённый: finished в meta.json и пустые основные сырые файлы, которых нет."""
    from lanmap import snapshot
    m = {**(read_json(snap / "meta.json", {}) or {}), "finished": "2026-01-01T00:00:00", **meta}
    write_json(snap / "meta.json", m)
    for name in snapshot.CORE_RAW:
        if not (snap / "raw" / name).exists():
            write_json(snap / "raw" / name, {} if name in ("ping.json", "ports.json") else [])
    return snap


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


class CertTest(unittest.TestCase):
    """Сертификат разбирается через временный файл внутри data/, а не в %TEMP%."""
    DER = "MIIBqDCCAU6gAwIBAgIUbIS2ptlrkWgBh3ClIrih8X5T2MIwCgYIKoZIzj0EAwIwGTEXMBUGA1UEAwwOZGV2aWNlLmV4YW1wbGUwHhcNMjYxMTIyMDM1NjQyWhcNMzYxMTE5MDM1NjQyWjAZMRcwFQYDVQQDDA5kZXZpY2UuZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABI3QkMx4nRUKjmVfMcUWiPQ89/Mls577LJ3cmlG5GjAZDDpBHp4NRyRQwbWsaMRz7952Q5JGlrDTPWAGm7t+i3+jdDByMB0GA1UdDgQWBBTh23VqasWq55s55yvtAMFMNEwyeTAfBgNVHSMEGDAWgBTh23VqasWq55s55yvtAMFMNEwyeTAPBgNVHRMBAf8EBTADAQH/MB8GA1UdEQQYMBaCDmRldmljZS5leGFtcGxlhwTAAAIFMAoGCCqGSM49BAMCA0gAMEUCIQDend63LpifNvNZpWf3LS/Yz1Rucm3G2pJ3doLa3tZLkAIgSgC8Y2iL1BcigHnL4rdUDVBMyCbJYsbeGosPDQkFrxo="

    def test_decode_in_data_dir(self):
        import base64
        from unittest import mock
        from lanmap.collectors import tcp
        from lanmap.util import data_dir
        made = []
        real = tempfile.mkstemp
        with mock.patch.object(tcp.tempfile, "mkstemp", lambda **kw: made.append(kw["dir"]) or real(**kw)):
            info = tcp._decode_cert(base64.b64decode(self.DER))
        self.assertEqual(info["subject"].get("commonName"), "device.example")
        self.assertIn("192.0.2.5", info["san"])
        self.assertTrue(info["not_after"])
        self.assertEqual(Path(made[0]), data_dir() / tcp.CERT_TMP)
        self.assertEqual(list((data_dir() / tcp.CERT_TMP).glob("*.pem")), [])
        # Удалить не вышло — сказано в ответе, а следующий срез подметает остатки
        with mock.patch.object(tcp.os, "unlink", side_effect=PermissionError):
            info = tcp._decode_cert(base64.b64decode(self.DER))
        self.assertIn("PermissionError", info["temp_left"])
        self.assertEqual(tcp.sweep_cert_tmp(), [])
        self.assertEqual(list((data_dir() / tcp.CERT_TMP).glob("*.pem")), [])


class ExternalBuildTest(unittest.TestCase):
    def test_external_snapshot_is_only_read(self):
        """build по срезу вне каталога данных: его папка не трогается, отчёт — в data/external."""
        from lanmap.build import build, output_dir
        from lanmap.util import data_dir
        with tempfile.TemporaryDirectory() as outside:
            snap = Path(outside) / "2026-01-03_000000"
            write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "network": "192.0.2.0/24"}})
            write_json(snap / "raw" / "ping.json", {"192.0.2.10": {"alive": True}})
            before = sorted(p.relative_to(snap) for p in snap.rglob("*"))
            build(snap)
            self.assertEqual(sorted(p.relative_to(snap) for p in snap.rglob("*")), before)
            out = data_dir() / "external" / snap.name
            self.assertEqual(output_dir(snap), out.resolve())
            self.assertTrue((out / "report.html").exists() and (out / "devices.json").exists())
        inside = data_dir() / "snapshots" / "2026-01-03_000001"
        self.assertEqual(output_dir(inside), inside.resolve())


class SnapshotCheckTest(unittest.TestCase):
    def test_report_says_interrupted_or_changed(self):
        """build по прерванному или изменённому срезу собирается, но «О срезе» говорит об этом."""
        from lanmap import snapshot
        from lanmap.build import build
        from lanmap.report import _about
        snap = Path(tempfile.mkdtemp(dir=TMP.name)) / "2026-01-04_000000"
        write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "network": "192.0.2.0/24"}, "admin": True})
        write_json(snap / "raw" / "ping.json", {"192.0.2.10": {"alive": True}})
        model = build(snap)
        self.assertIn("Срез прерван", _about(model))
        finish_snapshot(snap)
        m = read_json(snap / "meta.json")
        write_json(snap / "meta.json", {**m, "manifest": snapshot.manifest(snap),
                                        "warnings": ["не удалось удалить временные файлы сертификатов в data/tmp-cert: 1"]})
        model = build(snap)
        self.assertTrue(model["snapshot_check"]["ok"])
        self.assertNotIn("manifest", model["meta"])
        self.assertNotIn("Срез прерван", _about(model))
        self.assertIn("временные файлы сертификатов", _about(model))
        write_json(snap / "raw" / "ping.json", {})
        about = _about(build(snap))
        self.assertIn("изменены после съёмки: ping.json", about)
        self.assertIn("проверка неполная", about)


class ScanPassportTest(unittest.TestCase):
    """run_scan на подставной сети: сбой необязательного этапа не обрывает срез, а пишется в паспорт."""

    def run_scan(self, **broken):
        from unittest import mock
        from lanmap import netinfo, routers, scan
        from lanmap.collectors import discovery, igd, protocols, tcp, windows
        from lanmap.collectors import onvif as onvif_mod
        net = netinfo.LocalNet(if_index=1, alias="test", description="", local_ip="192.0.2.5", prefix=29,
                               network="192.0.2.0/29", gateway="192.0.2.1", mac=MAC_C, hardware=True, up=True)
        own = Path(tempfile.mkdtemp(dir=TMP.name))

        async def ports_and_probes(ctx, targets, progress):
            return {"192.0.2.2": [445], "192.0.2.3": [445]}, []

        def smb(ctx, ip):
            if ip == "192.0.2.3":
                raise TimeoutError("нет ответа")
            return {"dialect": "0x311"}

        def boom(*a, **kw):
            raise OSError("сбой")

        patches = [
            mock.patch.object(netinfo, "is_admin", lambda: True),
            mock.patch.object(netinfo, "hostname", lambda: "TESTPC"),
            mock.patch.object(discovery, "multicast", lambda ctx: {"mdns": [], "ssdp": [], "errors": []}),
            mock.patch.object(discovery, "ws_discovery", lambda ctx: []),
            mock.patch.object(discovery, "ping_sweep", lambda ctx: {"192.0.2.2": {"alive": True},
                                                                    "192.0.2.3": {"alive": True}}),
            mock.patch.object(discovery, "neighbor_table", lambda ctx: []),
            mock.patch.object(discovery, "arp_query", lambda ctx, ips: [{"ip": i, "mac": MAC_B} for i in ips]),
            mock.patch.object(scan, "_ports_and_probes", ports_and_probes),
            mock.patch.object(routers, "collect", lambda host: {"host": host, "kind": None, "skipped": "нет модуля"}),
            mock.patch.object(protocols, "reverse_dns", lambda ip: (ip, None)),
            mock.patch.object(protocols, "gateway_ptr", lambda ctx, ip: (ip, [])),
            mock.patch.object(protocols, "netbios_status", lambda ctx, ip: None),
            mock.patch.object(protocols, "smb_probe", smb),
            mock.patch.object(protocols, "onvif_targets", lambda ctx, wsd, ports: []),
            mock.patch.object(protocols, "upnp_descriptions", boom if broken.get("upnp") else lambda ctx, s: []),
            mock.patch.object(igd, "collect", lambda ctx, upnp: {"gateways": []}),
            mock.patch.object(onvif_mod, "snapshot_leak", boom),
            mock.patch.object(windows, "collect", lambda: {"platform": "windows", "smb1_client": False}),
            mock.patch.object(tcp, "sweep_cert_tmp", lambda: []),
            mock.patch.object(scan, "snapshots_dir", lambda: own),  # не трогать общий тестовый каталог срезов
        ]
        for x in patches:
            x.start()
        try:
            return scan.run_scan(net, ports=[445], quiet=True)
        finally:
            for x in patches:
                x.stop()

    def test_optional_failures_are_recorded(self):
        from lanmap import snapshot
        snap = self.run_scan(upnp=True)
        meta = read_json(snap / "meta.json")
        self.assertTrue(snapshot.finished(snap) and snapshot.verify(snap)["ok"])
        self.assertIn("raw/smb.json", meta["manifest"])
        by = {x["id"]: x for x in meta["passport"]}
        self.assertEqual(by["smb"]["status"], "partial")
        self.assertIn("опрошено 1 из 2", by["smb"]["detail"])
        self.assertEqual(by["upnp"]["status"], "error")
        self.assertFalse((snap / "raw" / "upnp.json").exists())  # проверки UPnP скажут «нечем проверить»
        self.assertEqual(by["router"]["status"], "skipped")
        self.assertEqual(by["igd"]["status"], "ok")
        self.assertEqual(len(read_json(snap / "raw" / "smb.json")), 1)

    def test_report_shows_passport(self):
        from lanmap.build import build
        from lanmap.report import _about
        about = _about(build(self.run_scan(upnp=True)))
        self.assertIn("UPnP-описания", about)
        self.assertIn("Не все этапы среза прошли", about)
        # Роутер без модуля уже сказан своей плашкой — в счёт неполноты второй раз не идёт
        self.assertEqual(about.count("Данные роутера недоступны"), 1)
        self.assertNotIn("Роутер (пропущен)", about)


class CertExpiryTest(unittest.TestCase):
    def snap(self, not_after):
        snap = Path(tempfile.mkdtemp(dir=TMP.name)) / "2026-01-05_000000"
        write_json(snap / "meta.json", {"interface": {"local_ip": "192.0.2.5", "network": "192.0.2.0/24"},
                                        "started": "2025-12-20T00:00:00"})
        write_json(snap / "raw" / "ping.json", {"192.0.2.10": {"alive": True}})
        write_json(snap / "raw" / "neighbors.json", [{"ip": "192.0.2.10", "mac": MAC_B}])
        write_json(snap / "raw" / "ports.json", {"tested": [443], "open": {"192.0.2.10": [443]}})
        write_json(snap / "raw" / "probes.json", [{
            "ip": "192.0.2.10", "port": 443, "kind": "http", "tls_version": "TLSv1.3",
            "response": "HTTP/1.1 200 OK\r\n\r\n",
            "cert": {"subject": {"commonName": "device.example"}, "not_after": not_after}}])
        return finish_snapshot(snap)

    def test_days_and_report(self):
        """Дни до конца сертификата — на дату среза; меньше 30 — значок у плитки и у порта, истёк — красный."""
        from lanmap import devices
        from lanmap.build import make_model
        from lanmap.report import _detail, _flags
        self.assertEqual(devices.cert_days("Jan  1 00:00:00 2026 GMT", "2025-12-20T00:00:00"), 12)
        self.assertIsNone(devices.cert_days("не дата", "2025-12-20T00:00:00"))
        dev = make_model(self.snap("Jan  1 00:00:00 2026 GMT"))["devices"][0]
        svc = next(s for s in dev["services"] if s["port"] == 443)
        self.assertEqual(svc["cert"]["days"], 12)
        self.assertIn("certw", _detail(dev))
        self.assertIn("сертификат HTTPS до 01.01.2026 (12 дн. на момент среза)", _flags(dev))
        old = make_model(self.snap("Dec  1 00:00:00 2025 GMT"))["devices"][0]
        self.assertIn('flag crit', _flags(old))
        self.assertIn("истёк", _detail(old))
        far = make_model(self.snap("Jan  1 00:00:00 2030 GMT"))["devices"][0]
        self.assertNotIn("certw", _detail(far))
        self.assertNotIn("сертификат HTTPS", _flags(far))


class StaleReportTest(unittest.TestCase):
    def test_age_chip_and_threshold(self):
        """Возраст среза считает страница при открытии: в шапке — дата среза, в «О срезе» — порог владельца."""
        from lanmap.build import build
        from lanmap.report import STALE_DAYS, render
        snap = finish_snapshot(Path(tempfile.mkdtemp(dir=TMP.name)) / "2026-01-06_000000",
                               started="2026-01-06T10:00:00+03:00", interface={"network": "192.0.2.0/24"})
        page = render(build(snap))
        self.assertIn('id="age" data-started="2026-01-06T10:00:00+03:00" hidden', page)
        self.assertIn(f'<option value="{STALE_DAYS}" selected>', page)
        self.assertIn("store.get('stale')", page)


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
            finish_snapshot(base / name)
        self.assertEqual(changes.previous_snapshot(base / "2026-01-02_100000").name, "2026-01-01_100000")
        self.assertIsNone(changes.previous_snapshot(base / "2026-01-01_100000"))
        new = model([mdev(MAC_B, ["192.0.2.10"])])
        c = self.cmp(model([]), new)
        self.assertIn("Новые устройства", _changes({**new, "changes": c}))

    def test_baseline_skips_broken_and_foreign(self):
        """База сравнения — только завершённый, целый срез той же сети; номера …_2 < …_10."""
        from lanmap import changes, snapshot
        base = Path(tempfile.mkdtemp(dir=TMP.name))
        net = {"interface": {"network": "192.0.2.0/24"}}
        good = finish_snapshot(base / "2026-01-01_100000", **net)
        snap = finish_snapshot(base / "2026-01-05_100000", **net)
        self.assertEqual(changes.previous_snapshot(snap), good)
        # Прерванный (нет finished), чужая сеть, файл изменён после съёмки — пропускаются
        write_json(base / "2026-01-02_100000" / "meta.json", net)
        finish_snapshot(base / "2026-01-03_100000", interface={"network": "198.51.100.0/24"})
        damaged = finish_snapshot(base / "2026-01-04_100000", **net)
        m = read_json(damaged / "meta.json")
        write_json(damaged / "meta.json", {**m, "manifest": snapshot.manifest(damaged)})
        self.assertEqual(changes.previous_snapshot(snap), damaged)
        write_json(damaged / "raw" / "ping.json", {"192.0.2.9": {"alive": True}})
        self.assertEqual(snapshot.verify(damaged)["changed"], ["raw/ping.json"])
        self.assertEqual(changes.previous_snapshot(snap), good)
        # Без основного файла — тоже не срез
        (good / "raw" / "arp.json").unlink()
        self.assertIsNone(changes.previous_snapshot(snap))
        self.assertLess(snapshot.order_key(base / "2026-01-01_100000_2"), snapshot.order_key(base / "2026-01-01_100000_10"))

    def test_latest_ignores_rebuilt_interrupted(self):
        """Прерванный срез, пересобранный вручную (devices.json есть, finished нет), не считается последним."""
        from unittest import mock
        from lanmap import scan
        base = Path(tempfile.mkdtemp(dir=TMP.name))
        done = finish_snapshot(base / "2026-01-01_100000")
        write_json(done / "devices.json", {})
        broken = base / "2026-01-02_100000"
        write_json(broken / "meta.json", {})
        write_json(broken / "devices.json", {})
        with mock.patch.object(scan, "snapshots_dir", lambda: base):
            self.assertEqual(scan.latest_snapshot(), done)
            self.assertEqual(scan.latest_snapshot(complete=True), done)

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
                     "sec-TELNET_OPEN", "sec-UPNP_PORT_MAPPINGS", 'data-kpi="security"', "Что может сломаться",
                     'class="alert p1"', 'data-quick="find"', 'data-find="1"', "О срезе"):
            self.assertIn(text, page)
        bare = model([rdev(MAC_B, "192.0.2.10", "camera")])
        self.assertIn("Сеть", render(bare))


class MapTest(unittest.TestCase):
    """Карта сети: место устройства по данным роутера, разметка дерева, вид по умолчанию."""

    def dev(self, n, router=None, alive=True, gateway=False):
        d = mdev(f"00:00:5E:00:53:{n:02X}", [f"192.0.2.{n}"], alive=alive)
        d["identity"] = {"type": "camera", "type_label": "Камера", "group": "Камеры", "vendor": None, "model": None,
                         "firmware": None, "os": None, "name": None, "confidence": 3, "chosen": {}, "rules": [],
                         "conflicts": [], "notes": []}
        d.update(is_local=False, is_gateway=gateway, duplicate_mac=False, evidence=[], registry=None, router=router,
                 actions=[], subtitle="")
        return d

    def test_slot(self):
        from lanmap.report import map_slot
        self.assertEqual(map_slot(self.dev(1, gateway=True)), "gw")
        self.assertEqual(map_slot(self.dev(2, {"segment": "Home", "link": "wired", "port": "6"}, alive=False)), "off")
        self.assertEqual(map_slot(self.dev(3)), "scan")  # роутер о нём не знает
        self.assertEqual(map_slot(self.dev(4, {"segment": "Home", "link": "wired", "port": 6})), "seg|Home|wired|6")
        self.assertEqual(map_slot(self.dev(5, {"segment": "Guest", "link": "wifi", "band": "5 ГГц"})),
                         "seg|Guest|wifi|5 ГГц")
        # роутер не отметил связь активной, но знает точку доступа — это Wi-Fi
        self.assertEqual(map_slot(self.dev(6, {"segment": "Home", "band": "5 ГГц", "ap": "W1/AP0"})),
                         "seg|Home|wifi|5 ГГц")
        self.assertEqual(map_slot(self.dev(7, {"segment": "Home"})), "seg|Home|other|")
        self.assertEqual(map_slot(self.dev(8, {"segment": "A|B", "link": "wired"})), "seg|A/B|wired|?")

    def test_render(self):
        from lanmap.report import render
        wired = [self.dev(n, {"segment": "Home", "link": "wired", "port": "6", "active": True}) for n in (10, 11, 12)]
        guest = self.dev(20, {"segment": "Guest", "link": "wifi", "band": "5 ГГц", "active": True})
        devs = [self.dev(1, gateway=True), *wired, guest, self.dev(30), self.dev(40, alive=False)]
        fw = {"kind": "upnp", "protocol": "tcp", "port": 8080, "to_ip": "192.0.2.10", "to_port": 80}
        page = render(model(devs, router={"forwards": [fw], "clients": []}))
        self.assertIn('<main data-map="1">', page)
        self.assertIn('data-view="map"', page)
        for slot in ("gw", "seg|Home|wired|6", "seg|Guest|wifi|5 ГГц", "scan", "off"):
            self.assertGreaterEqual(page.count(f'data-slot="{slot}"'), 2, slot)  # место на карте и плитка
        self.assertIn("коммутатор или ретранслятор", page)  # три устройства за портом 6
        self.assertIn("Гостевая сеть", page)
        self.assertIn(f'class="mdoor" data-goto="{wired[0]["key"]}"', page)  # дверь из интернета ведёт к плитке
        bare = render(model([self.dev(3), self.dev(4)]))  # без роутера карты нет: остаются плитки и список
        self.assertIn('<main data-map="0">', bare)
        self.assertNotIn('data-view="map"', bare)
        self.assertNotIn('id="mapv"', bare)


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

    def test_failed_forward_read_is_not_clean(self):
        """Роутер ответил, но секция пробросов не прочиталась — «нечем проверить», а не «чисто»."""
        from lanmap import forwards
        from lanmap.routers import keenetic
        raw = {"kind": "keenetic", "data": {"version": {}, "static_nat": []},
               "errors": {"upnp_redirects": "show/upnp/redirect: HTTP 500"}}
        router = keenetic.normalize(raw)
        self.assertEqual(router["forward_kinds"], ["static"])
        sec = self.run_checks(self.net(router=router))
        self.assertFalse(sec["evaluated"]["UPNP_PORT_MAPPINGS"])
        self.assertTrue(sec["evaluated"]["STATIC_PORT_FORWARD"])
        # IGD, прочитанный до конца, закрывает дыру в UPnP
        self.assertTrue(forwards.upnp_known({"router": router, "igd": {"complete": True}}))
        self.assertEqual(forwards.known_kinds({"router": router}), {"static"})

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

    def test_keenetic_no_redirects(self):
        """Клиент Keenetic не идёт по переадресации: запрос не уходит с адреса шлюза."""
        import http.server
        import threading
        from lanmap.routers import keenetic
        hits = []

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                hits.append(self.path)
                if self.path.startswith("/elsewhere"):
                    self.send_response(401)
                    self.send_header("X-NDM-Challenge", "x")
                    self.send_header("X-NDM-Realm", "r")
                    self.end_headers()
                    return
                self.send_response(302)
                self.send_header("Location", "/elsewhere" + self.path)
                self.end_headers()

        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            host = f"127.0.0.1:{srv.server_address[1]}"
            self.assertIsNone(keenetic.is_keenetic(host, timeout=2))
            client = keenetic.KeeneticClient(host, timeout=2)
            with self.assertRaises(keenetic.KeeneticError):
                client.get("show/version")
            with self.assertRaises(keenetic.KeeneticError):
                client.login("admin", "x")
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(hits, ["/auth", "/rci/show/version", "/auth"])

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
        cls.snap = finish_snapshot(snap)
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

    def test_launch_route(self):
        """Запуск: со страницы только ключ и действие; Telnet — сначала предупреждение; ничего не запускается."""
        from types import SimpleNamespace
        from unittest import mock
        from lanmap import launch, ops
        net = SimpleNamespace(local_ip="192.0.2.5", network=NET, gateway="192.0.2.1", if_index=1, mac=None)
        with mock.patch.object(ops, "pick_network", return_value=net), \
                mock.patch.object(launch, "_popen", side_effect=AssertionError("запуска быть не должно")):
            code, out = self.api("/api/launch", {"key": MAC_B, "action": "telnet"})
            self.assertEqual((code, out["need_ack"]), (400, True))
            self.assertIn("открытым текстом", out["error"])
            self.assertEqual(self.api("/api/launch", {"key": MAC_B, "action": "cmd /c calc"})[0], 400)
            self.assertEqual(self.api("/api/launch", {"key": MAC_B, "action": "rdp"})[0], 400)  # 3389 не открыт
            self.assertEqual(self.api("/api/launch", {"key": "192.0.2.99", "action": "telnet"})[0], 400)
            self.assertEqual(self.api("/api/launch", {"key": MAC_B, "action": "telnet"}, token="")[0], 403)
        page = (self.snap / "report.html").read_text("utf-8")
        self.assertIn("data-launch=", page)

    def test_ai_routes(self):
        """«Разобрать с ИИ»: мусор — 400, во время среза запись не идёт (409); в отчёте кнопка и шаблон промта."""
        code, out = self.api("/api/ai/check", {"key": MAC_B, "answer": "просто текст"})
        self.assertEqual(code, 400)
        self.assertIn("JSON", out["error"])
        self.assertEqual(self.api("/api/ai/check", {"key": MAC_B})[0], 400)
        state = self.httpd.state
        state.scan["running"] = True
        try:
            self.assertEqual(self.api("/api/ai/apply", {"key": MAC_B, "answer": "{}", "registry": True})[0], 409)
        finally:
            state.scan["running"] = False
        page = (self.snap / "report.html").read_text("utf-8")
        self.assertIn('id="aiprompt"', page)
        self.assertIn("data-ai=", page)

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

    def test_shutdown_button_stops_server(self):
        import threading
        from lanmap import server
        httpd = server.make_server(0, token="t2")
        httpd.RequestHandlerClass.log_message = lambda *a: None
        loop = threading.Thread(target=httpd.serve_forever, daemon=True)
        loop.start()
        old_port, self.port = self.port, httpd.server_address[1]
        try:
            self.assertEqual(self.api("/api/shutdown", {}, token="wrong")[0], 403)
            self.assertTrue(loop.is_alive())
            self.assertEqual(self.api("/api/shutdown", {}, token="t2")[0], 200)
            loop.join(5)
            self.assertFalse(loop.is_alive())  # serve_forever вернулся — serve завершится, окно закроется
        finally:
            self.port = old_port
            httpd.server_close()

    def test_interrupted_scan_is_ignored(self):
        """Прерванный срез (папка только с meta.json) не забирает ни страницу, ни отметки."""
        import shutil
        broken = self.snap.parent / "2026-01-02_000000"
        write_json(broken / "meta.json", {"interface": {}})
        try:
            self.assertEqual(self.api("/api/check", {"code": "E6", "status": "done"})[0], 200)
            self.assertFalse((broken / "devices.json").exists())
            self.assertEqual(read_json(self.snap / "devices.json")["snapshot"], self.snap.name)
            from lanmap import server
            self.assertEqual(server._report_path(), self.snap / "report.html")
        finally:
            shutil.rmtree(broken)


class PresenceTest(unittest.TestCase):
    """«Найти устройство»: кто в сети по ping и роутеру, события погасло / появилось / новое."""

    def presence(self):
        from lanmap.collectors.live import Presence
        devs = [
            {"key": MAC_A, "mac": MAC_A, "ips": ["192.0.2.20"], "title": "Телефон"},
            {"key": MAC_B + "#S1", "mac": MAC_B, "ips": ["192.0.2.10"], "title": "Камера 1", "duplicate_mac": True},
            {"key": MAC_B + "#S2", "mac": MAC_B, "ips": ["192.0.2.11"], "title": "Камера 2", "duplicate_mac": True},
            {"key": MAC_C, "mac": MAC_C, "ips": ["192.0.2.1"], "title": "Роутер", "is_gateway": True},
        ]
        return Presence(devs, "192.0.2.5", mac_of=lambda ip: "00:00:5E:00:53:99")

    @staticmethod
    def alive(p, key):
        return next(d for d in p.state()["devices"] if d["key"] == key)["alive"]

    def test_new_device_share(self):
        """Новое устройство (нет в срезе): «Помочь опознать» из роутера и OUI, без адресов и подписей."""
        p = self.presence()
        new_mac = "00:00:5E:00:53:44"
        router = [{"mac": new_mac, "ip": "192.0.2.44", "active": True, "hostname": "roborock-vacuum-a15",
                   "label": "Пылесос-Маши", "ssid": "SSID-Секрет", "link": "wifi", "band": "2,4 ГГц"}]
        p.update({}, router, 1.0)
        devs = {d["key"]: d for d in p.state()["devices"]}
        data = devs[new_mac]["share"]
        self.assertNotIn("share", devs[MAC_A])  # у устройств из среза — данные из плитки отчёта
        body = data["lanmap"] + data["text"]
        for s in ("192.0.2.44", "00:00:5E:00:53:44", "Пылесос-Маши", "SSID-Секрет", "roborock"):
            self.assertNotIn(s, body)
        self.assertIn("порты и службы ещё не опрошены", body)
        self.assertIn("Wi-Fi 2,4 ГГц", body)
        self.assertIn("roborock-vacuum-a15", data["names"])
        self.assertNotIn("Пылесос", data["names"])

    def test_router_decides_for_silent_phone_ping_for_cameras(self):
        p = self.presence()
        ping = {"192.0.2.1": True, "192.0.2.10": True, "192.0.2.11": True, "192.0.2.20": False}
        router = [{"mac": MAC_A, "ip": "192.0.2.20", "active": True},
                  {"mac": MAC_B, "ip": "192.0.2.10", "active": True}]
        self.assertEqual(p.update(ping, router, 1.0), [])  # первый цикл — точка отсчёта, без событий
        self.assertTrue(self.alive(p, MAC_A))               # на ping молчит, но роутер видит
        # телефон выключил Wi-Fi: роутер погасил — событие «погасло»
        router = [dict(router[0], active=False), router[1]]
        events = p.update(ping, router, 2.0)
        self.assertEqual([(e["key"], e["kind"]) for e in events], [(MAC_A, "gone")])
        # камера 2 за мостом выключена: MAC моста у роутера активен, но решает ping (после двух промахов)
        off = dict(ping, **{"192.0.2.11": False})
        self.assertEqual(p.update(off, router, 3.0), [])
        events = p.update(off, router, 4.0)
        self.assertEqual([(e["key"], e["kind"]) for e in events], [(MAC_B + "#S2", "gone")])
        self.assertTrue(self.alive(p, MAC_B + "#S1"))
        events = p.update(ping, router, 5.0)
        self.assertIn((MAC_B + "#S2", "back"), [(e["key"], e["kind"]) for e in events])

    def test_new_address_and_gateway(self):
        p = self.presence()
        ping = {"192.0.2.1": True, "192.0.2.10": True, "192.0.2.11": True}
        p.update(ping, None, 1.0)
        events = p.update(dict(ping, **{"192.0.2.30": True}), None, 2.0)
        self.assertEqual([(e["key"], e["kind"]) for e in events], [("00:00:5E:00:53:99", "new")])
        # шлюз — не кандидат: его пропажа не попадает в ленту событий
        down = dict(ping, **{"192.0.2.1": False, "192.0.2.30": True})
        p.update(down, None, 3.0)
        self.assertEqual(p.update(down, None, 4.0), [])
        self.assertFalse(self.alive(p, MAC_C))

    def test_stale_router_address_does_not_light_other_tile(self):
        """Роутер помнит старый адрес выключенного устройства; этот адрес теперь у другого — плитки не путаются."""
        p = self.presence()
        router = [{"mac": MAC_A, "ip": "192.0.2.20", "active": False},              # телефон выключен, адрес старый
                  {"mac": "00:00:5E:00:53:77", "ip": "192.0.2.20", "active": True}]  # адрес теперь у другого
        ping = {"192.0.2.1": True, "192.0.2.10": True, "192.0.2.11": True, "192.0.2.20": True}
        p.update(ping, router, 1.0)
        self.assertFalse(self.alive(p, MAC_A))
        self.assertTrue(self.alive(p, "00:00:5E:00:53:77"))
        p.rename("00:00:5E:00:53:77", "Часы")
        self.assertEqual(next(d for d in p.state()["devices"] if d["key"] == "00:00:5E:00:53:77")["title"], "Часы")

    def test_dozing_watch_does_not_flap_but_steady_camera_goes_dark(self):
        from lanmap.collectors.live import Presence
        watch, cam = "00:00:5E:00:53:21", "00:00:5E:00:53:22"
        p = Presence([{"key": cam, "mac": cam, "ips": ["192.0.2.22"], "title": "Камера"}])
        router = [{"mac": watch, "ip": "192.0.2.21", "active": True}, {"mac": cam, "ip": "192.0.2.22", "active": True}]
        events = []
        # часы: роутер видит всё время, ping через раз; камера отвечает стабильно
        for i, w in enumerate([False, False, True, False, False, False, True, True, False, False]):
            events += p.update({"192.0.2.21": w, "192.0.2.22": True}, router, float(i))
        self.assertEqual(events, [])
        self.assertTrue(self.alive(p, watch))
        # камеру выключили, роутер ещё считает её активной — гаснет по ping после трёх промахов
        off = {"192.0.2.21": False, "192.0.2.22": False}
        events = p.update(off, router, 20.0) + p.update(off, router, 21.0)
        self.assertEqual(events, [])
        events = p.update(off, router, 22.0)
        self.assertEqual([(e["key"], e["kind"]) for e in events], [(cam, "gone")])

    def test_router_hiccup_keeps_last_clients(self):
        """Один сбой роутера не «гасит» телефоны, которые решает роутер."""
        import time
        from lanmap import server
        from lanmap.collectors.live import Presence
        calls = []
        pres = Presence([{"key": MAC_A, "mac": MAC_A, "ips": ["192.0.2.20"], "title": "Т"}])

        def router():
            calls.append(1)
            if len(calls) % 2 == 0:
                raise OSError("timeout")
            return [{"mac": MAC_A, "ip": "192.0.2.20", "active": True}]

        def setup():
            return {"presence": pres, "targets": lambda c: ["192.0.2.20"], "sweep": lambda ips: {"192.0.2.20": False},
                    "router": router}

        old = (server.Watcher.INTERVAL, server.Watcher.IDLE_STOP)
        server.Watcher.INTERVAL, server.Watcher.IDLE_STOP = 0.02, 1.0  # цикл не короче 0,2 с
        try:
            w = server.Watcher(setup)
            for _ in range(60):
                if w.status == "stopped":
                    break
                time.sleep(0.05)
        finally:
            server.Watcher.INTERVAL, server.Watcher.IDLE_STOP = old
        self.assertGreater(len(calls), 3)
        self.assertEqual(pres.events, [])
        self.assertTrue(self.alive(pres, MAC_A))

    def test_watch_endpoints_and_auto_stop(self):
        import json
        import threading
        import time
        from lanmap import server
        from lanmap.collectors.live import Presence
        sweeps = []

        def setup():
            pres = Presence([{"key": MAC_A, "mac": MAC_A, "ips": ["192.0.2.20"], "title": "Т"}])
            return {"presence": pres, "targets": lambda cycle: ["192.0.2.20"],
                    "sweep": lambda ips: sweeps.append(ips) or {"192.0.2.20": True}}

        old = (server.Watcher.INTERVAL, server.Watcher.IDLE_STOP)
        server.Watcher.INTERVAL, server.Watcher.IDLE_STOP = 0.05, 0.5
        httpd = server.make_server(0, token="t", live_setup=setup)
        httpd.RequestHandlerClass.log_message = lambda *a: None
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            import http.client
            port = httpd.server_address[1]

            def call(method, body=None, token="t", host=None):
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                hdrs = {"Host": host or f"127.0.0.1:{port}", "X-LanMap-Token": token, "Content-Type": "application/json"}
                conn.request(method, "/api/watch", body=json.dumps(body) if body is not None else None, headers=hdrs)
                r = conn.getresponse()
                raw = r.read()
                out = r.status, (json.loads(raw) if raw.startswith(b"{") else {})
                conn.close()
                return out

            self.assertEqual(call("POST", {}, token="bad")[0], 403)
            self.assertEqual(call("GET", host="evil.example")[0], 403)
            self.assertEqual(call("POST", {})[0], 202)
            for _ in range(50):
                code, st = call("GET")
                if st.get("devices") and st["devices"][0]["alive"]:
                    break
                time.sleep(0.05)
            self.assertTrue(st["devices"][0]["alive"])
            w = httpd.state.watcher
            for _ in range(60):  # никто не спрашивает — опрос сам останавливается
                if w.status == "stopped":
                    break
                time.sleep(0.05)
            self.assertEqual(w.status, "stopped")
            n = len(sweeps)
            time.sleep(0.2)
            self.assertEqual(len(sweeps), n)
        finally:
            server.Watcher.INTERVAL, server.Watcher.IDLE_STOP = old
            httpd.shutdown()
            httpd.server_close()


class PortableTest(unittest.TestCase):
    """Переносимость: где лежат данные и база производителей из зеркала Wireshark."""

    def test_data_next_to_program_unless_program_files(self):
        from unittest import mock
        from lanmap import util
        with tempfile.TemporaryDirectory() as tmp:
            root, local = Path(tmp) / "Мои программы" / "LanMap", Path(tmp) / "Local"
            root.mkdir(parents=True)
            env = {"LOCALAPPDATA": str(local), "ProgramFiles": str(Path(tmp) / "PF"), "ProgramW6432": "",
                   "ProgramFiles(x86)": "", "windir": str(Path(tmp) / "Win")}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(util._choose(root), root / "data")  # переносится вместе с папкой
                pf = Path(tmp) / "PF" / "LanMap"
                pf.mkdir(parents=True)
                # в Program Files — всегда LOCALAPPDATA, даже если права администратора позволили бы писать
                self.assertEqual(util._choose(pf), local / "LanMap" / "data")
                self.assertFalse((pf / "data").exists())
                with mock.patch.object(Path, "write_bytes", side_effect=PermissionError("только чтение")):
                    self.assertEqual(util._choose(root), local / "LanMap" / "data")

    def test_lanmap_data_env_wins(self):
        from lanmap import util
        self.assertEqual(util.data_dir(), Path(TMP.name))

    def test_wireshark_manuf_to_ieee_format(self):
        from lanmap import oui
        manuf = ("# comment\n00:00:5E           \tICANN       \tICANN, IANA Department\n"
                 "00:00:0C\tCisco\n00:1B:C5:00:00/36\tSmall       \tSmall Block Inc.\n")
        table = dict(oui._LINE.findall(oui.from_manuf(manuf)))
        self.assertEqual(table, {"00005E": "ICANN, IANA Department", "00000C": "Cisco"})

    def test_oui_update_falls_back_when_ieee_sends_a_stub(self):
        from unittest import mock
        from lanmap import oui
        manuf = "".join(f"00:{i // 256:02X}:{i % 256:02X}\tV{i}\tVendor {i} Ltd\n" for i in range(1500))
        pages = {oui.IEEE_URL: b"<html>Please enable JavaScript</html>", oui.MIRROR_URL: manuf.encode()}
        with mock.patch.object(oui, "_download", side_effect=pages.__getitem__):
            path, count = oui.update()
        self.assertEqual(count, 1500)
        self.assertEqual(oui.lookup(MAC_B), "Vendor 94 Ltd")  # 00:00:5E → 0x5E = 94
        path.unlink()
        oui._table.cache_clear()


class FakeRouterModule:
    """Модуль роутера без сети: пароль «right» подходит, остальные нет."""
    READS = {"clients": "show/ip/hotspot", "forwards": "show/upnp/redirect"}

    @staticmethod
    def credential_target(host):
        return f"router:{host}"

    @staticmethod
    def check_login(host, user, password):
        if password != "right":
            raise ValueError("неверный логин или пароль")

    @staticmethod
    def collect(host):
        return {"data": {"clients": [1, 2]}, "errors": {"forwards": "HTTP 403"}}


class SetupApiTest(unittest.TestCase):
    """Кнопки настройки веб-интерфейса: база производителей, вход в роутер, паспорт. Без сети и без настоящего
    диспетчера учётных данных: модуль роутера, шлюз и credentials подменены."""

    def setUp(self):
        import threading
        from unittest import mock
        from lanmap import server
        self.saved = {}
        patches = [
            mock.patch("lanmap.ops.gateway", return_value="192.0.2.1"),
            mock.patch("lanmap.ops._router_module", return_value=(FakeRouterModule, ("fake", "Fake Router 1"))),
            mock.patch("lanmap.credentials.save", side_effect=lambda t, u, p, comment="": self.saved.update({t: (u, p)})),
            mock.patch("lanmap.credentials.load", side_effect=lambda t: self.saved.get(t)),
            mock.patch("lanmap.credentials.delete", side_effect=lambda t: self.saved.pop(t, None) is not None),
            mock.patch("lanmap.ops.oui_update", return_value={"count": 12345}),
            mock.patch("lanmap.ops.router_probe", return_value="### Паспорт роутера\n- порты: 80"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.httpd = server.make_server(0, token="setup-token")
        self.httpd.RequestHandlerClass.log_message = lambda *a: None
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def call(self, method, path, body=None, token="setup-token"):
        import http.client
        import json
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        hdrs = {"Host": f"127.0.0.1:{self.port}", "X-LanMap-Token": token}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            hdrs["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=hdrs)
        r = conn.getresponse()
        text = r.read().decode("utf-8")
        conn.close()
        return r.status, json.loads(text), text

    def wait_job(self, path):
        import time
        for _ in range(100):
            code, j, _ = self.call("GET", path)
            if not j.get("running"):
                return j
            time.sleep(0.02)
        self.fail("фоновое действие не закончилось")

    def test_router_login_saves_password_but_never_returns_it(self):
        self.assertEqual(self.call("POST", "/api/router/login", {"user": "ro", "password": "right"}, token="x")[0], 403)
        code, j, _ = self.call("GET", "/api/router")
        self.assertEqual((code, j["kind"], j["login"]), (200, "fake", None))
        code, j, text = self.call("POST", "/api/router/login", {"user": "ro", "password": "wrong-secret"})
        self.assertEqual(code, 400)
        self.assertNotIn("wrong-secret", text)
        self.assertEqual(self.saved, {})
        code, j, text = self.call("POST", "/api/router/login", {"user": " ro ", "password": "right"})
        self.assertEqual(code, 200)
        self.assertNotIn('"right"', text)
        self.assertEqual(self.saved, {"router:192.0.2.1": ("ro", "right")})
        self.assertEqual([(r["name"], r["ok"]) for r in j["reads"]], [("clients", True), ("forwards", False)])
        self.assertEqual(self.call("GET", "/api/router")[1]["login"], "ro")
        self.assertEqual(self.call("POST", "/api/router/login", {"user": "ro"})[0], 400)
        code, j, _ = self.call("POST", "/api/router/forget", {})
        self.assertEqual((code, j["removed"], self.saved), (200, True, {}))

    def test_oui_and_probe_run_in_background(self):
        code, j, _ = self.call("POST", "/api/oui", {})
        self.assertIn(code, (202, 409))
        self.assertEqual(self.wait_job("/api/oui")["result"], {"count": 12345})
        self.assertEqual(self.call("POST", "/api/probe", {})[0], 202)
        self.assertIn("Паспорт роутера", self.wait_job("/api/probe")["result"])

    def test_first_run_page_has_setup(self):
        import http.client
        from unittest import mock
        with mock.patch("lanmap.server._report_path", return_value=None):
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
            conn.request("GET", "/", headers={"Host": f"127.0.0.1:{self.port}",
                                              "Cookie": f"lanmap_{self.port}=setup-token"})
            page = conn.getresponse().read().decode("utf-8")
            conn.close()
        self.assertIn('window.LANMAP={"token": "setup-token"}', page)
        self.assertIn("lanmapSetup.mount", page)
        self.assertIn("Сделать первый срез", page)


class ShareTest(unittest.TestCase):
    """«Помочь опознать»: в тексте для публичной заявки нет ничего личного, а улики для правила есть."""

    SECRETS = ("192.0.2.77", "198.51.100.9", "00:00:5E:00:53:7A", "00-00-5E-00-53-7B", "СекретноеИмя", "Комната-Маши",
               "SSID-Секрет", "SN-SECRET-1", "UDN-SECRET-2", "HW-SECRET-3", "fn-secret", "deviceid-secret",
               "note-secret", "cn-secret.example", "san-secret", "netbios-secret", "dns-secret", "rdns-secret",
               "mdnsinst-secret", "body-secret", "location-secret", "dhcp-secret", "mdnshost-secret", "ap-secret",
               "registry-secret", "evidence-secret", "12345678-1234-1234-1234-123456789abc")

    def dev(self):
        d = device(
            ports=[80, 554], oui="Test Vendor GmbH", ttl=64, mdns_services=["_ipp._tcp"],
            mdns_txt={"ty": "Printer X100", "fn": "fn-secret", "deviceid": "deviceid-secret", "note": "note-secret"},
            mdns_hosts=["mdnshost-secret.local"], mdns_instances=["mdnsinst-secret"],
            upnp={"manufacturer": ["TestCorp"], "modelName": ["X100"], "friendlyName": ["СекретноеИмя"],
                  "serialNumber": ["SN-SECRET-1"], "UDN": ["uuid:12345678-1234-1234-1234-123456789abc"],
                  "presentationURL": ["http://192.0.2.77/"], "UDN2": ["UDN-SECRET-2"]},
            onvif={"Manufacturer": "CamCo", "Model": "AB123_C45DE67-FG_8M", "SerialNumber": "SN-SECRET-1",
                   "HardwareId": "HW-SECRET-3"},
            http=[{"port": 80, "tls": False, "status": "HTTP/1.1 200 OK", "server": "lighttpd", "title": "Web UI",
                   "realm": "", "body": "body-secret 192.0.2.77", "location": "http://192.0.2.77/location-secret"}],
            tls=[{"port": 443, "subject": {"commonName": "cn-secret.example", "organizationName": "TestCorp"},
                  "san": ["san-secret"], "issuer": {}}],
            rtsp=["Server 1.0"], banners=[{"port": 3306, "text": "\x05E� Host '198.51.100.9' denied"}],
            netbios={"computer": "netbios-secret"}, dns=["dns-secret"], router_names=["rdns-secret"],
            router={"label": "Комната-Маши", "hostname": "dhcp-secret", "ssid": "SSID-Секрет", "ap": "ap-secret",
                    "link": "wifi", "band": "5 ГГц", "mac": "00-00-5E-00-53-7B", "ip": "192.0.2.77"})
        d["ips"] = ["192.0.2.77"]
        d["mac"] = d["key"] = "00:00:5E:00:53:7A"
        d["router"] = d["facts"]["router"]
        d["registry"] = {"name": "registry-secret", "owner": "registry-secret", "type": "tv", "vendor": "registry-secret",
                         "model": "registry-secret", "confirmed": True}
        d["evidence"] = [{"source": "router", "text": "evidence-secret"}]
        d["identity"] = {"type": "printer", "type_label": "Принтер", "confidence_label": "высокая", "vendor": "TestCorp",
                         "model": "X100", "name": "СекретноеИмя", "rules": ["printer-mdns"],
                         "chosen": {"name": {"value": "СекретноеИмя", "why": "fn-secret"}}}
        return d

    def test_no_secrets(self):
        from lanmap import share
        p = share.payload(self.dev())
        body = p["text"] + "\n" + p["lanmap"]
        for s in self.SECRETS:
            self.assertNotIn(s.lower(), body.lower(), s)
        for s in ("LanMap ", "TestCorp", "X100", "Test Vendor", "80, 554", "_ipp._tcp", "ty=Printer X100",
                  "lighttpd", "«Web UI»", "организация TestCorp", "Model=AB123_C45DE67-FG_8M", "Wi-Fi 5 ГГц",
                  "TTL: 64", "Host '<ip>' denied"):
            self.assertIn(s, body)
        self.assertNotRegex(body, r"[\x00-\x08\x0b-\x1f�]")

    def test_verdict_is_lanmap_own(self):
        """В заявку идёт догадка программы, не подпись владельца; модель из DHCP-имени — только под галочкой."""
        from lanmap import share
        d = device(oui="TP-Link Systems Inc", router={"hostname": "RE450-secret", "link": "wifi"})
        d["router"] = d["facts"]["router"]
        d["registry"] = {"type": "tv", "model": "registry-secret", "confirmed": True}
        ident = identify.resolve(d, None)
        self.assertEqual(ident["model"], "RE450-secret")  # правило tplink-extender берёт модель из DHCP-имени
        p = share.payload(d)
        self.assertNotIn("RE450", p["text"])
        self.assertNotIn("registry-secret", p["text"])
        self.assertIn("TP-Link", p["text"])
        self.assertIn("tplink-extender", p["text"])
        self.assertNotIn("Телевизор", p["lanmap"])
        self.assertIn("RE450-secret", p["names"])

    def test_names_opt_in(self):
        """Имя, которое устройство сообщает само (DHCP, mDNS), — отдельно, под галочкой; подпись владельца — никогда."""
        from lanmap import share
        p = share.payload(self.dev())
        self.assertIn("dhcp-secret", p["names"])
        self.assertIn("mdnshost-secret", p["names"])
        self.assertNotIn(".local", p["names"])
        for s in ("Комната-Маши", "netbios-secret", "СекретноеИмя"):
            self.assertNotIn(s, p["names"])
        bare = device()
        bare["identity"] = {}
        self.assertEqual(share.payload(bare)["names"], "")
        self.assertIn("улик почти нет", share.payload(bare)["text"])

    def test_button_in_report(self):
        import html as html_mod
        import json
        from lanmap.report import _detail
        d = self.dev()
        d["identity"].update(group="Принтеры", confidence=3, chosen={}, conflicts=[], notes=[], firmware=None, os=None)
        d.update(services=[], actions=[], title="t")
        page = _detail(d)
        m = re.search(r'data-share="([^"]*)"', page)
        self.assertIsNotNone(m)
        data = json.loads(html_mod.unescape(m.group(1)))
        self.assertEqual(set(data), {"lanmap", "text", "names"})
        for s in self.SECRETS:
            self.assertNotIn(s.lower(), (data["lanmap"] + data["text"]).lower(), s)


class AskAiTest(unittest.TestCase):
    """«Спросить ИИ»: весь отчёт без адресов, имён и подписей, но со связями между устройствами."""

    SECRETS = ("192.0.2.1", "192.0.2.20", "192.0.2.21", "198.51.100.30", "203.0.113.5", "00:00:5E:00:53:01",
               "00:00:5E:00:53:20", "00:00:5E:00:53:21", "00-00-5E-00-53-99", "Камера-у-Маши", "dhcp-secret",
               "SSID-Секрет", "Сегмент-Секрет", "pc-secret", "registry-secret", "reason-secret", "note-secret",
               "static-desc-secret", "alias-secret", "netbios-secret", "fn-secret", "SN-SECRET")

    def mk(self, key, ip, dev_type, label, ports=(), gateway=False, facts=None, router=None):
        d = mdev(key, [ip], ports=ports)
        d["services"] = [{"port": p, "name": "Telnet" if p == 23 else None} for p in ports]
        d["facts"].update({"ports": list(ports), "mdns_services": [], "mdns_txt": {}, "http": [], "tls": [],
                           "rtsp": [], "ssdp_server": [], "wsd_types": [], "oui": None, "private_mac": False},
                          **(facts or {}))
        d["router"] = d["facts"]["router"] = {"label": label, "hostname": "dhcp-secret", "ssid": "SSID-Секрет",
                                              "segment": "Сегмент-Секрет", "link": "wifi", "band": "2,4 ГГц",
                                              "mac": key, "ip": ip, **(router or {})}
        d["identity"] = {"type": dev_type, "type_label": identify.TYPES[dev_type], "vendor": "TestCorp",
                         "model": "Z9", "firmware": "1.2", "name": label, "confidence": 4, "chosen": {},
                         "group": identify.GROUPS[dev_type]}
        d.update(is_gateway=gateway, is_local=False, duplicate_mac=False, title=label, subtitle=label,
                 registry={"name": "registry-secret", "owner": "registry-secret", "confirmed": True}, evidence=[])
        return d

    def model(self):
        from lanmap import checklist, security
        gw = self.mk("00:00:5E:00:53:01", "192.0.2.1", "router", "Роутер-registry-secret", ports=[80], gateway=True)
        cam = self.mk("00:00:5E:00:53:20", "192.0.2.20", "camera", "Камера-у-Маши", ports=[23, 80],
                      facts={"netbios": {"computer": "netbios-secret"}, "mdns_txt": {"fn": "fn-secret"},
                             "onvif": {"SerialNumber": "SN-SECRET"}})
        pc = self.mk("00:00:5E:00:53:21", "192.0.2.21", "computer", "pc-secret")
        m = model([gw, cam, pc], router={"kind": "keenetic", "model": "Test", "firmware": "5.0", "clients": [],
                                         "reservations": [], "forwards": [
            {"kind": "static", "protocol": "tcp", "port": 8080, "to_ip": "192.0.2.20", "to_port": 80,
             "description": "static-desc-secret"},
            {"kind": "upnp", "protocol": "tcp", "port": 5000, "to_ip": "192.0.2.21", "to_port": 5000,
             "description": "dhcp-secret 192.0.2.21"},
            {"kind": "upnp", "protocol": "udp", "port": 9, "to_ip": "198.51.100.30", "to_port": 9}]})
        m["meta"].update(hostname="pc-secret", ports_tested=100,
                         interface={"prefix": 24, "local_ip": "192.0.2.21", "mac": "00-00-5E-00-53-99",
                                    "alias": "alias-secret", "description": "alias-secret", "gateway": "192.0.2.1"})
        m["igd"] = {"external_scope": "public", "gateways": [{"ip": "192.0.2.1", "external_ip": "203.0.113.5"}]}
        snap = Path(tempfile.mkdtemp(dir=TMP.name))
        m["security"] = security.evaluate(m, snap, {23, 80}, {})
        for f in m["security"]["findings"]:
            f["reason"] = "reason-secret"
        m["checklist"] = checklist.evaluate(m, {"E6": {"status": "done", "note": "note-secret"}})
        return m

    def test_no_secrets_and_links_kept(self):
        from lanmap import askai
        text = askai.text(self.model())
        for s in self.SECRETS:
            self.assertNotIn(s.lower(), text.lower(), s)
        self.assertIsNone(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        self.assertIsNone(re.search(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b", text))
        self.assertIn("- У1 — Роутер", text)                      # шлюз первым
        self.assertIn("→ У2:80", text)                              # проброс на камеру…
        self.assertIn("У2 (Камера TestCorp Z9): порт 23", text)      # …и находка на ней же — та же метка
        self.assertIn("→ У3:5000, описание «<имя> У3»", text)       # имя и адрес в описании UPnP заменены
        self.assertIn("→ неизвестный адрес:9", text)
        self.assertIn("сеть A", text)
        self.assertIn("Помоги мне разобраться", text.split("##")[0])  # вступление — просьба к ИИ
        self.assertIn("пробросы видны из интернета", text)
        self.assertIn("Порядок в сети", text)

    def test_minimal_model(self):
        from lanmap import askai
        text = askai.text(model([]))
        self.assertIn("Устройства в сети: 0", text)
        self.assertIn("проверки безопасности в срезе нет", text)

    def test_button_in_report(self):
        from lanmap.report import render
        m = self.model()
        for d in m["devices"]:
            d["actions"] = []
            d["identity"].update(conflicts=[], notes=[], rules=[], os=None)
        page = render(m)
        self.assertIn('id="askai" data-askai="', page)


def smb1_reply(words: int, index: int, status: int = 0) -> bytes:
    """Ответ сервера на согласование SMB1 (заголовок + число слов + номер диалекта)."""
    smb = (b"\xffSMB" + bytes([0x72]) + struct.pack("<I", status) + bytes([0x88]) + b"\x01\xc8" + b"\0" * 12
           + struct.pack("<HHHH", 0, 0xFEFF, 0, 0) + bytes([words]) + struct.pack("<H", index) + b"\0" * 4)
    return struct.pack("!I", len(smb)) + smb


class Smb1Test(unittest.TestCase):
    def test_parse_reply(self):
        from lanmap.collectors import protocols
        self.assertEqual(protocols.parse_smb1_reply(smb1_reply(17, 0))[0], True)
        self.assertEqual(protocols.parse_smb1_reply(smb1_reply(1, 0xFFFF))[0], False)  # «ни один диалект не подошёл»
        self.assertEqual(protocols.parse_smb1_reply(b"")[0], False)                     # оборвал соединение
        self.assertEqual(protocols.parse_smb1_reply(b"\0\0\0\x40\xfeSMB" + b"\0" * 60)[0], False)
        req = protocols.smb1_request()
        self.assertEqual(req[4:9], b"\xffSMB\x72")
        self.assertIn(b"NT LM 0.12", req)
        self.assertNotIn(b"SMB 2", req)  # SMB2 не предлагаем: иначе сервер ответит по SMB2

    def net(self, windows):
        devs = [sdev("00:00:5E:00:53:0D", "192.0.2.20", "nas", ports=[445], vendor="D-Link", facts={"smb1": True}),
                sdev("00:00:5E:00:53:0E", "192.0.2.30", "computer", ports=[445], local=True, facts={"smb1": False}),
                sdev("00:00:5E:00:53:0F", "192.0.2.40", "nas", ports=[445], facts={"smb1": False})]
        m = model(devs)
        m["windows"] = windows
        return m

    def test_detect(self):
        from lanmap import security
        snap = SecurityTest.snap(SecurityTest())
        sec = security.evaluate(self.net(None), snap, None, {})
        self.assertFalse(sec["evaluated"]["SMB1_ENABLED"])  # срез без проверки SMB1 — не «чисто»
        sec = security.evaluate(self.net({"platform": "windows", "smb1_client": True}), snap, None, {})
        found = {f["ips"][0]: f for f in sec["findings"] if f["id"] == "SMB1_ENABLED"}
        self.assertEqual(sorted(found), ["192.0.2.20", "192.0.2.30"])
        self.assertEqual(found["192.0.2.20"]["priority"], 2)  # сервер SMB1
        self.assertEqual(found["192.0.2.30"]["priority"], 3)  # только клиент на этом компьютере
        steps, exact, _ = security.device_steps(security.BY_ID["SMB1_ENABLED"], found["192.0.2.30"])
        self.assertTrue(exact)
        self.assertTrue(any("SMB 1.0/CIFS" in s for s in steps))  # инструкция под Windows
        steps, exact, _ = security.device_steps(security.BY_ID["SMB1_ENABLED"], found["192.0.2.20"])
        self.assertFalse(exact)
        sec = security.evaluate(self.net({"platform": "windows", "smb1_client": False}), snap, None, {})
        self.assertEqual([f["ips"][0] for f in sec["findings"] if f["id"] == "SMB1_ENABLED"], ["192.0.2.20"])

    def test_windows_client(self):
        from lanmap.collectors import windows
        self.assertTrue(windows.smb1_client(2))
        self.assertFalse(windows.smb1_client(4))     # служба отключена
        self.assertFalse(windows.smb1_client(None))  # компонент удалён


class FakeProbes:
    """Подставная сеть для перепроверки: ARP, порты, ping, SMB, роутер."""

    def __init__(self, macs=None, ports=None, ping=False, smb=None, router=None):
        self.macs, self.ports, self.alive, self.smb_reply, self.router_raw = macs or {}, ports or {}, ping, smb, router
        self.asked: list = []

    def mac(self, ip):
        return self.macs.get(ip)

    def tcp(self, ip, port):
        self.asked.append((ip, port))
        return self.ports.get(port, "silent")

    def ping(self, ip):
        return self.alive

    def smb(self, ip):
        return self.smb_reply or {"smb1": None}

    def windows(self):
        return {"platform": "windows", "smb1_client": False}

    def onvif(self, url):
        return {"error": "timeout"}

    def router(self):
        return self.router_raw

    def igd(self, descriptions):
        return {"gateways": []}


class RecheckTest(unittest.TestCase):
    CTX = ScanContext(local_ip="192.0.2.30", network=NET, gateway="192.0.2.1", if_index=1)

    def setUp(self):
        from lanmap import security
        write_json(security.statuses_path(), {})
        self.snap = SecurityTest.snap(SecurityTest())
        self.m = SecurityTest.net(SecurityTest())
        self.m["windows"] = {"platform": "windows", "smb1_client": False}
        self.m["security"] = security.evaluate(self.m, self.snap, SecurityTest.TESTED, {})

    def finding(self, check_id):
        return next(f for f in self.m["security"]["findings"] if f["id"] == check_id)

    def run_rc(self, check_id, probes):
        from lanmap import recheck
        return recheck.run(check_id, self.finding(check_id), self.m, self.snap, self.CTX, probes)

    def test_port_present_gone_offline(self):
        on_link = {"192.0.2.10": MAC_C}
        self.assertEqual(self.run_rc("CAMERA_XM_PORT", FakeProbes(on_link, {34567: "open"}))["result"], "present")
        self.assertEqual(self.run_rc("CAMERA_XM_PORT", FakeProbes(on_link, {34567: "closed"}))["result"], "gone")
        # Не ответило ни на ARP, ни на порт, ни на ping — выключено, а не исправлено
        self.assertEqual(self.run_rc("CAMERA_XM_PORT", FakeProbes())["result"], "unknown")
        # ARP молчит, но порт ответил отказом — устройство на связи
        self.assertEqual(self.run_rc("CAMERA_XM_PORT", FakeProbes({}, {34567: "closed"}))["result"], "gone")
        # Ping отвечает, а порт молчит — это не закрытие (сбой или DROP): unknown с пометкой silent
        res = self.run_rc("CAMERA_XM_PORT", FakeProbes({}, {}, ping=True))
        self.assertEqual((res["result"], res.get("silent")), ("unknown", True))
        res = self.run_rc("CAMERA_XM_PORT", FakeProbes(on_link))
        self.assertEqual((res["result"], res.get("silent")), ("unknown", True))
        # Выключенное устройство серию не копит
        self.assertNotIn("silent", self.run_rc("CAMERA_XM_PORT", FakeProbes()))

    def test_nas_only_own_ports_decide(self):
        """У хранилища решают порты самой находки: остальные лишние могут молчать всегда (файрвол)."""
        from lanmap import recheck
        f = {"id": "NAS_EXTRA_SERVICES", "key": MAC_C, "ips": ["192.0.2.10"], "ports": [3306]}
        dev = next(d for d in self.m["devices"] if d["key"] == MAC_C)
        dev["identity"] = {**dev.get("identity", {}), "type": "nas"}
        on_link = {"192.0.2.10": MAC_C}
        res = recheck.run("NAS_EXTRA_SERVICES", f, self.m, self.snap, self.CTX, FakeProbes(on_link, {3306: "closed"}))
        self.assertEqual(res["result"], "gone")
        res = recheck.run("NAS_EXTRA_SERVICES", f, self.m, self.snap, self.CTX, FakeProbes(on_link, {2049: "closed"}))
        self.assertEqual((res["result"], res.get("silent")), ("unknown", True))

    def test_silent_streak(self):
        """Порт молчит у живого устройства: gone только после серии перепроверок с паузой."""
        from lanmap import ops, security
        from unittest import mock
        clock = iter(f"2030-01-01T10:{m:02d}:00" for m in (0, 1, 6, 12, 13, 20, 30))
        snap_meta = {"started": "2030-01-01T09:00:00"}
        self.m["meta"] = {**self.m.get("meta", {}), **snap_meta}
        silent = FakeProbes({"192.0.2.10": MAC_C})
        u = security.uid("CAMERA_XM_PORT", MAC_C)

        def go(probes):
            with mock.patch.object(security, "now_iso", lambda: next(clock)),                  mock.patch.object(ops, "latest", lambda: (self.snap, self.m)),                  mock.patch.object(ops, "pick_network", lambda: mock.Mock(
                     local_ip=self.CTX.local_ip, network=self.CTX.network, gateway=self.CTX.gateway, if_index=1,
                     mac=None)):
                return ops.recheck("CAMERA_XM_PORT", "192.0.2.10", probes)[0]

        self.assertEqual(go(silent)["result"], "unknown")                      # 10:00 — 1 из 3
        r = go(silent)                                                         # 10:01 — рано, не считается
        self.assertEqual((r["result"], security.load_statuses()[u]["checked"]["silent"]), ("unknown", 1))
        self.assertIn("повтори не раньше", r["detail"])
        self.assertEqual(go(silent)["result"], "unknown")                      # 10:06 — 2 из 3
        r = go(silent)                                                         # 10:12 — 3 из 3
        self.assertEqual(r["result"], "gone")
        self.assertEqual(security.load_statuses()[u]["status"], "fixed")
        # Порт открылся — находка на месте, серия сброшена
        self.assertEqual(go(FakeProbes({"192.0.2.10": MAC_C}, {34567: "open"}))["result"], "present")  # 10:13
        self.assertNotIn("silent", security.load_statuses()[u]["checked"])
        self.assertEqual(go(silent)["result"], "unknown")                      # 10:20 — снова 1 из 3
        self.assertEqual(security.load_statuses()[u]["checked"]["silent"], 1)
        # Серия до нового среза не в счёт
        self.m["meta"]["started"] = "2030-01-01T10:25:00"
        go(silent)                                                             # 10:30
        self.assertEqual(security.load_statuses()[u]["checked"]["silent"], 1)

    def test_address_taken_by_other(self):
        res = self.run_rc("CAMERA_XM_PORT", FakeProbes({"192.0.2.10": MAC_B}, {34567: "closed"}))
        self.assertEqual(res["result"], "unknown")

    def test_shared_address_picks_own_mac(self):
        """Заводской адрес на несколько камер: перепроверяем по тому адресу, где отвечает этот MAC."""
        cam = next(d for d in self.m["devices"] if d["key"] == MAC_C)
        cam["ips"] = ["192.0.2.10", "192.0.2.15"]
        f = self.finding("CAMERA_XM_PORT")
        f["ips"] = cam["ips"]
        from lanmap import recheck
        probes = FakeProbes({"192.0.2.10": MAC_B, "192.0.2.15": MAC_C}, {34567: "closed"})
        self.assertEqual(recheck.run("CAMERA_XM_PORT", f, self.m, self.snap, self.CTX, probes)["result"], "gone")
        self.assertEqual(probes.asked, [("192.0.2.15", 34567)])

    def test_out_of_scope_is_not_probed(self):
        from lanmap import recheck
        f = {**self.finding("CAMERA_XM_PORT"), "ips": ["198.51.100.7"]}
        probes = FakeProbes({}, {34567: "closed"})
        self.assertEqual(recheck.run("CAMERA_XM_PORT", f, self.m, self.snap, self.CTX, probes)["result"], "unknown")
        self.assertEqual(probes.asked, [])

    def test_smb_signing(self):
        nas = {"192.0.2.20": "00:00:5E:00:53:0D"}
        weak = {"status": "0x0", "dialect": "0x311", "signing_required": False, "smb1": False}
        self.assertEqual(self.run_rc("SMB_SIGNING", FakeProbes(nas, smb=weak))["result"], "present")
        self.assertEqual(self.run_rc("SMB_SIGNING", FakeProbes(nas, smb={**weak, "signing_required": True}))["result"],
                         "gone")

    def test_forwards_from_router(self):
        from lanmap import security
        fw = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": 5000}
        self.m["router"] = {"forwards": [fw]}
        self.m["security"] = security.evaluate(self.m, self.snap, SecurityTest.TESTED, {})
        f = self.finding("UPNP_PORT_MAPPINGS")
        from lanmap import recheck
        from unittest import mock
        with mock.patch("lanmap.routers.normalize", side_effect=lambda raw: raw):
            still = recheck.run("UPNP_PORT_MAPPINGS", f, self.m, self.snap, self.CTX, FakeProbes(router={"forwards": [fw]}))
            gone = recheck.run("UPNP_PORT_MAPPINGS", f, self.m, self.snap, self.CTX, FakeProbes(router={"forwards": []}))
            unknown = recheck.run("UPNP_PORT_MAPPINGS", f, self.m, self.snap, self.CTX, FakeProbes(router=None))
        self.assertEqual((still["result"], gone["result"], unknown["result"]), ("present", "gone", "unknown"))

    def test_silence_is_not_fixed(self):
        """Устройство на связи (ARP), но проверяемая служба промолчала — «нечем проверить», а не «исчезла»."""
        from lanmap import recheck, security
        nas = {"192.0.2.20": "00:00:5E:00:53:0D"}
        self.assertEqual(self.run_rc("SMB_SIGNING", FakeProbes(nas, smb={"error": "timeout", "smb1": None}))["result"],
                         "unknown")
        self.assertEqual(self.run_rc("SMB_SIGNING", FakeProbes(nas, smb={"smb1": False, "port_closed": True}))["result"],
                         "gone")
        cam = {"192.0.2.10": MAC_C}
        self.assertEqual(self.run_rc("CAMERA_ONVIF_ANON", FakeProbes(cam))["result"], "unknown")  # ONVIF: тайм-аут
        # Этот компьютер: SMB1 к себе не ответил, клиент выключен — всё равно не «исчезла»
        f = {"id": "SMB1_ENABLED", "key": "00:00:5E:00:53:0E", "ips": ["192.0.2.30"], "port": 445}
        res = recheck.run("SMB1_ENABLED", f, self.m, self.snap, self.CTX, FakeProbes(smb={"smb1": None}))
        self.assertEqual(res["result"], "unknown")
        res = recheck.run("SMB1_ENABLED", f, self.m, self.snap, self.CTX, FakeProbes(smb={"smb1": False}))
        self.assertEqual(res["result"], "gone")
        # ADB только по объявлению mDNS: порт 5555 тут ни при чём
        adb = {"id": "ADB_EXPOSED", "key": MAC_C, "ips": ["192.0.2.10"]}
        res = recheck.run("ADB_EXPOSED", adb, self.m, self.snap, self.CTX, FakeProbes(cam, {5555: "closed"}))
        self.assertEqual(res["result"], "unknown")
        # Обрезанный ответ SMB1 — не «SMB1 нет»
        from lanmap.collectors import protocols
        self.assertIsNone(protocols.parse_smb1_reply(smb1_reply(17, 0)[:30])[0])
        self.assertIn("SMB1_ENABLED", security.BY_ID)

    def test_router_partial_or_other_network(self):
        from lanmap import recheck, security
        from unittest import mock
        fw = {"kind": "upnp", "protocol": "tcp", "port": 50000, "to_ip": "192.0.2.20", "to_port": 5000}
        self.m["router"] = {"forwards": [fw]}
        self.m["security"] = security.evaluate(self.m, self.snap, SecurityTest.TESTED, {})
        f = self.finding("UPNP_PORT_MAPPINGS")
        with mock.patch("lanmap.routers.normalize", side_effect=lambda raw: raw):
            partial = FakeProbes(router={"forwards": [], "errors": {"upnp_redirects": "HTTP 500"}})
            self.assertEqual(recheck.run("UPNP_PORT_MAPPINGS", f, self.m, self.snap, self.CTX, partial)["result"],
                             "unknown")
            other = FakeProbes({"192.0.2.1": MAC_C}, router={"forwards": []})  # у шлюза чужой MAC
            self.assertEqual(recheck.run("UPNP_PORT_MAPPINGS", f, self.m, self.snap, self.CTX, other)["result"],
                             "unknown")
        self.m["meta"]["interface"] = {"network": "198.51.100.0/24"}
        res = recheck.run("CAMERA_XM_PORT", self.finding("CAMERA_XM_PORT"), self.m, self.snap, self.CTX,
                          FakeProbes({"192.0.2.10": MAC_C}, {34567: "closed"}))
        self.assertEqual(res["result"], "unknown")

    def test_record_and_effective(self):
        from lanmap import security
        key = MAC_C
        u = security.uid("CAMERA_XM_PORT", key)
        # Исчезла → «исправлена», и перепроверка это подтверждает, пока срез старше перепроверки
        security.record_recheck("CAMERA_XM_PORT", key, "gone", "порт закрыт", ips=["192.0.2.10"])
        saved = security.load_statuses()[u]
        self.assertEqual(saved["status"], "fixed")
        self.assertEqual(security._effective(saved, "2000-01-01T00:00:00")["status"], "fixed_verified")
        self.assertIn("fixed_verified", security.QUIET_STATUSES)  # подтверждённая не считается открытой
        # Новый срез после перепроверки снова видит находку — вернулась
        self.assertEqual(security._effective(saved, "2999-01-01T00:00:00")["status"], "regress")
        # На месте при отметке «исправлена» — отметка снимается
        security.set_status("CAMERA_XM_PORT", key, "fixed")
        security.record_recheck("CAMERA_XM_PORT", key, "present", "порт открыт")
        saved = security.load_statuses()[u]
        self.assertEqual(saved["status"], "open")
        eff = security._effective(saved, "2000-01-01T00:00:00")
        self.assertEqual((eff["status"], eff["checked"]["result"]), ("open", "present"))
        # «Принята осознанно» перепроверка не трогает
        security.set_status("CAMERA_XM_PORT", key, "accepted", "так надо")
        security.record_recheck("CAMERA_XM_PORT", key, "gone", "порт закрыт")
        self.assertEqual(security.load_statuses()[u]["status"], "accepted")

    def test_report_chip_and_button(self):
        from lanmap import report, security
        security.record_recheck("CAMERA_XM_PORT", MAC_C, "present", "порт 34567 открыт", ips=["192.0.2.10"])
        self.m["security"] = security.evaluate(self.m, self.snap, SecurityTest.TESTED)
        html_ = report._security(self.m)
        self.assertIn("finding recheck CAMERA_XM_PORT", html_)
        self.assertIn("на месте", html_)
        self.assertIn('&quot;recheck&quot;: true', html_)


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
