"""TCP: проверка открытых портов и снятие баннеров (HTTP, TLS, RTSP, SSH...). Только чтение."""
from __future__ import annotations

import asyncio
import hashlib
import os
import ssl
import tempfile
from pathlib import Path

from lanmap.collectors import USER_AGENT, ScanContext
from lanmap.ports import BANNER_PORTS, RTSP_PORTS, SILENT_PORTS, TLS_PORTS
from lanmap.util import data_dir


async def tcp_open(ctx: ScanContext, ip: str, port: int, sem: asyncio.Semaphore, timeout: float = 0.6) -> int | None:
    async with sem:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, local_addr=(ctx.local_ip, 0)), timeout)
        except Exception:
            return None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port


async def scan_host(ctx: ScanContext, ip: str, ports: list[int], sem: asyncio.Semaphore,
                    timeout: float = 0.6) -> list[int]:
    found = await asyncio.gather(*(tcp_open(ctx, ip, p, sem, timeout) for p in ports))
    return sorted(p for p in found if p)


CERT_TMP = "tmp-cert"


def _cert_tmp_dir() -> Path:
    """Папка для временных PEM внутри data/: в сертификате имена и адреса, в %TEMP% им не место.

    Остатки прошлых запусков (если удаление тогда не удалось) убираются здесь же."""
    path = data_dir() / CERT_TMP
    path.mkdir(parents=True, exist_ok=True)
    return path


def _decode_cert(der: bytes) -> dict:
    """Разбор сертификата средствами стандартной библиотеки (через временный PEM-файл в data/).

    Из памяти stdlib сертификат не разбирает. Файл не удалился — в ответе поле temp_left с его именем."""
    info: dict = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        fd, path = tempfile.mkstemp(suffix=".pem", prefix="cert-", dir=_cert_tmp_dir())
    except OSError as exc:
        info["error"] = f"нет места для временного файла: {exc.__class__.__name__}"
        return info
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(ssl.DER_cert_to_PEM_cert(der))
        decoded = ssl._ssl._test_decode_cert(path)  # noqa: SLF001 — в stdlib нет публичного аналога
        flat = lambda seq: {k: v for rdn in seq for (k, v) in rdn}  # noqa: E731
        info["subject"] = flat(decoded.get("subject", ()))
        info["issuer"] = flat(decoded.get("issuer", ()))
        info["not_after"] = decoded.get("notAfter")
        info["san"] = [v for _k, v in decoded.get("subjectAltName", ())]
    except Exception as exc:
        info["error"] = str(exc)
    finally:
        try:
            os.unlink(path)
        except OSError as exc:
            info["temp_left"] = f"{CERT_TMP}/{Path(path).name}: {exc.__class__.__name__}"
    return info


def sweep_cert_tmp() -> list[str]:
    """Удалить временные PEM, оставшиеся от прошлых срезов → имена тех, что удалить не вышло."""
    left = []
    path = data_dir() / CERT_TMP
    for f in path.glob("cert-*.pem") if path.is_dir() else []:
        try:
            f.unlink()
        except OSError:
            left.append(f.name)
    return left


async def probe(ctx: ScanContext, ip: str, port: int, sem: asyncio.Semaphore) -> dict:
    """Одно «рукопожатие» с открытым портом: что служба о себе говорит."""
    async with sem:
        out: dict = {"ip": ip, "port": port}
        use_tls = port in TLS_PORTS
        try:
            context = None
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                try:
                    context.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=context, server_hostname=ip if context else None,
                                        local_addr=(ctx.local_ip, 0)), 3)
            if context:
                tls = writer.get_extra_info("ssl_object")
                out["tls_version"] = tls.version()
                der = tls.getpeercert(binary_form=True)
                if der:
                    out["cert"] = _decode_cert(der)
            if port in BANNER_PORTS:
                out["kind"] = "banner"
                try:
                    data = await asyncio.wait_for(reader.read(4096), 2)
                except asyncio.TimeoutError:
                    data = b""
            elif port in RTSP_PORTS:
                out["kind"] = "rtsp"
                writer.write(f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {USER_AGENT}\r\n\r\n".encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), 2)
            elif port in SILENT_PORTS:
                out["kind"] = "banner"
                try:
                    data = await asyncio.wait_for(reader.read(2048), 0.7)
                except asyncio.TimeoutError:
                    data = b""
            else:
                out["kind"] = "http"
                writer.write(
                    (f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: {USER_AGENT}\r\n"
                     "Accept: text/html,*/*\r\nConnection: close\r\n\r\n").encode())
                await writer.drain()
                data = b""
                try:
                    while len(data) < 65536:
                        chunk = await asyncio.wait_for(reader.read(16384), 2.5)
                        if not chunk:
                            break
                        data += chunk
                except asyncio.TimeoutError:
                    pass
            out["response"] = data.decode("utf-8", "replace")[:20000]
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except Exception:
                pass
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
        return out
