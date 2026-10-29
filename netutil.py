#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ابزارهای مشترک شبکه برای یک دور پایش.

یک context گواهی، ترجیح IPv4، کوئری DNS روی UDP، و کش single-flight
تا فازهای همزمان یک هدف را دو بار نزنند. کش‌ها با clear_caches()
در شروع هر دور خالی می‌شوند.
"""

import json
import random
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

# سقف اتصال همزمان. فازها موازی‌اند، ولی بیشتر از این تعداد سوکت باز
# تایم‌اوت کاذب می‌سازد.
_NET_SLOTS = threading.BoundedSemaphore(48)
_STATE_LOCK = threading.Lock()
_CACHE = {}
_INFLIGHT = {}

_SSL_CONTEXT = None


class _Box:
    def __init__(self, value):
        self.value = value


class NetworkSlot:
    """جا را برای یک اتصال شبکه نگه می‌دارد. تو در تو صدا زده نشود."""

    def __enter__(self):
        _NET_SLOTS.acquire()
        return self

    def __exit__(self, exc_type, exc, tb):
        _NET_SLOTS.release()
        return False


def ssl_context():
    """یک context بدون راستی‌آزمایی گواهی برای کل پروسه."""
    global _SSL_CONTEXT
    if _SSL_CONTEXT is not None:
        return _SSL_CONTEXT
    with _STATE_LOCK:
        if _SSL_CONTEXT is None:
            try:
                ctx = ssl._create_unverified_context()
            except Exception:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            _SSL_CONTEXT = ctx
    return _SSL_CONTEXT


def close_quietly(sock):
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


# getaddrinfo پیش‌فرض ممکن است اول AAAA را امتحان کند و روی IPv6 خاموش چند ثانیه معطل بماند.
_ORIG_GETADDRINFO = socket.getaddrinfo


def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family in (0, socket.AF_UNSPEC):
        family = socket.AF_INET
    return _ORIG_GETADDRINFO(host, port, family, type, proto, flags)


def install_ipv4_preference():
    if socket.getaddrinfo is not _ipv4_getaddrinfo:
        socket.getaddrinfo = _ipv4_getaddrinfo


install_ipv4_preference()


def clear_caches():
    """نتایج دور قبل را دور بریز. فقط وقتی هیچ پروبی در جریان نیست صدا زده شود."""
    with _STATE_LOCK:
        _CACHE.clear()


def cached_call(key, fn):
    """fn را برای هر کلید یک بار اجرا کن. صداهای همزمان همان نتیجه را می‌گیرند."""
    with _STATE_LOCK:
        box = _CACHE.get(key)
        if box is not None:
            return box.value
        slot = _INFLIGHT.get(key)
        if slot is None:
            slot = {"event": threading.Event(), "box": None, "error": None}
            _INFLIGHT[key] = slot
            leader = True
        else:
            leader = False
    if not leader:
        slot["event"].wait()
        if slot["error"] is not None:
            raise slot["error"]
        return slot["box"].value
    try:
        value = fn()
        box = _Box(value)
        slot["box"] = box
        with _STATE_LOCK:
            _CACHE[key] = box
        return value
    except BaseException as exc:
        slot["error"] = exc
        raise
    finally:
        slot["event"].set()
        with _STATE_LOCK:
            _INFLIGHT.pop(key, None)


def cache_put(key, value):
    with _STATE_LOCK:
        _CACHE[key] = _Box(value)


def build_dns_query(domain, qtype=1):
    """بستهٔ پرسش DNS استاندارد (یک سؤال، RD=1). شناسه را هم برمی‌گرداند."""
    tid = random.randint(1, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    ascii_name = domain.strip(".").encode("idna").decode("ascii")
    qname = b"".join(
        bytes([len(label)]) + label.encode("ascii")
        for label in ascii_name.split(".")
        if label
    ) + b"\x00"
    return tid, header + qname + struct.pack(">HH", qtype, 1)


def _skip_dns_name(packet, offset):
    while offset < len(packet):
        length = packet[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length
    return offset


def parse_dns_a(packet, expected_id):
    """آدرس‌های A را از پاسخ DNS بیرون بکش. پاسخ نامعتبر لیست خالی است."""
    if len(packet) < 12:
        return []
    tid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", packet[:12])
    if expected_id is not None and tid != expected_id:
        return []
    if flags & 0x000F:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(packet, offset)
        offset += 4
    ips = []
    for _ in range(ancount):
        if offset >= len(packet):
            break
        offset = _skip_dns_name(packet, offset)
        if offset + 10 > len(packet):
            break
        rtype, _, _, rdlen = struct.unpack(">HHIH", packet[offset:offset + 10])
        offset += 10
        rdata = packet[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and len(rdata) == 4:
            ips.append(".".join(str(b) for b in rdata))
    return ips


def _system_nameservers():
    servers = []
    if sys.platform.startswith("win"):
        return servers
    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                    servers.append(parts[1])
    except OSError:
        return []
    return servers


def query_dns_udp(domain, server, timeout=1.0, port=53):
    """یک پرسش A روی UDP. خطا و تایم‌اوت به لیست خالی تبدیل می‌شود."""
    try:
        tid, packet = build_dns_query(domain)
    except Exception:
        return []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        with NetworkSlot():
            sock.sendto(packet, (server, port))
            data, _ = sock.recvfrom(2048)
        return parse_dns_a(data, tid)
    except Exception:
        return []
    finally:
        close_quietly(sock)


def _getaddrinfo_v4(domain, timeout):
    result = {}

    def work():
        try:
            infos = _ORIG_GETADDRINFO(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            seen = []
            for item in infos:
                ip = item[4][0]
                if ip not in seen:
                    seen.append(ip)
            result["ips"] = seen
        except Exception:
            result["ips"] = []

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(timeout)
    return result.get("ips", [])


def resolve_system(domain, timeout=2.0):
    """رزولوشن از DNS سیستم. اول resolv.conf با تایم‌اوت، بعد getaddrinfo."""
    for server in _system_nameservers():
        ips = query_dns_udp(domain, server, timeout=timeout)
        if ips:
            return ips
    return _getaddrinfo_v4(domain, timeout)


def resolve_a(domain, server=None, timeout=1.0, port=53):
    """
    رکوردهای A. server=None یعنی DNS سیستم.
    نتیجهٔ هر (سرور، دامنه) تا clear_caches یک بار گرفته می‌شود.
    """
    name = domain.strip(".").lower()
    key = ("dns", server or "@system", name)

    def work():
        if server:
            return query_dns_udp(name, server, timeout=timeout, port=port)
        return resolve_system(name, timeout=max(timeout, 1.0))

    return list(cached_call(key, work))


_HTTP_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    )
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = None
_OPENER_LOCK = threading.Lock()


def _opener():
    global _OPENER
    if _OPENER is not None:
        return _OPENER
    with _OPENER_LOCK:
        if _OPENER is None:
            _OPENER = urllib.request.build_opener(
                _NoRedirect,
                urllib.request.HTTPSHandler(context=ssl_context()),
            )
    return _OPENER


def classify_http_status(code):
    """
    کدی که یعنی به سرور رسیده‌ایم، حتی اگر صفحه را تحویل ندهد.
    401 و 403 و 429 فیلتر نیستند؛ هندشیک تمام شده است.
    """
    if code in (200, 204, 301, 302, 303, 307, 308):
        return True, "باز (Available)"
    if code in (401, 403, 429):
        return True, f"باز (HTTP {code}، سرور پاسخ داد)"
    return False, f"خطا (HTTP {code})"


def _http_failure(url, exc):
    reason = str(getattr(exc, "reason", exc))
    low = reason.lower()
    name = type(exc).__name__
    if "timed out" in low or "timeout" in low or isinstance(exc, (TimeoutError, socket.timeout)):
        return {
            "url": url,
            "ok": False,
            "code": "TIMEOUT",
            "latency": None,
            "status": "تایم‌اوت اتصال (Connect Timeout)",
            "error": name,
        }
    if "handshake" in low:
        return {
            "url": url,
            "ok": False,
            "code": "TLS_TIMEOUT",
            "latency": None,
            "status": "تایم‌اوت TLS (فیلترینگ SNI / Throttling)",
            "error": name,
        }
    if "reset" in low or "refused" in low or isinstance(exc, ConnectionResetError):
        return {
            "url": url,
            "ok": False,
            "code": "RST_REFUSED",
            "latency": None,
            "status": "کانکشن ریست/فیلتر (Connection Reset/Blocked)",
            "error": name,
        }
    if "nodename" in low or "name resolution" in low or "getaddrinfo" in low or isinstance(exc, socket.gaierror):
        return {
            "url": url,
            "ok": False,
            "code": "DNS_FAIL",
            "latency": None,
            "status": "خطای DNS (دامنه یافت نشد)",
            "error": name,
        }
    if "ssl" in low or "certificate" in low:
        return {
            "url": url,
            "ok": False,
            "code": "SSL_ERR",
            "latency": None,
            "status": "خطای SSL (احتمال شنود یا مسدودسازی)",
            "error": name,
        }
    return {
        "url": url,
        "ok": False,
        "code": "CONN_ERR",
        "latency": None,
        "status": f"خطای اتصال ({reason[:40]})",
        "error": name,
    }


def _probe_http_once(url, timeout):
    """GET تا هدر. بدنه خوانده نمی‌شود تا ۱۳۲ سایت صفحهٔ کامل نگیرند."""
    req = urllib.request.Request(url, headers=_HTTP_HEADERS, method="GET")
    started = time.perf_counter()
    try:
        with NetworkSlot():
            response = _opener().open(req, timeout=timeout)
            try:
                code = response.getcode()
                latency = round((time.perf_counter() - started) * 1000, 1)
            finally:
                close_quietly(response)
        ok, status = classify_http_status(code)
        return {
            "url": url,
            "ok": ok,
            "code": code,
            "latency": latency,
            "status": status,
            "error": None if ok else status,
        }
    except urllib.error.HTTPError as exc:
        latency = round((time.perf_counter() - started) * 1000, 1)
        close_quietly(exc)
        ok, status = classify_http_status(exc.code)
        return {
            "url": url,
            "ok": ok,
            "code": exc.code,
            "latency": latency,
            "status": status,
            "error": None if ok else status,
        }
    except Exception as exc:
        return _http_failure(url, exc)


def probe_http(url, timeout=4):
    """دسترسی HTTP یک URL، با کش و single-flight در طول دور."""
    key = ("http", url)

    def work():
        return _probe_http_once(url, timeout)

    return dict(cached_call(key, work))


def doh_lookup(url, timeout=2.5):
    """
    یک درخواست DNS-over-HTTPS. بدنه کوچک JSON است و خوانده می‌شود.
    همان URL در ریشه‌یابی و بنچمارک DoH یک بار زده می‌شود.
    """
    key = ("doh", url)

    def work():
        return _doh_once(url, timeout)

    result = dict(cached_call(key, work))
    result["ips"] = list(result.get("ips") or [])
    return result


def _doh_once(url, timeout):
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/dns-json", "User-Agent": _HTTP_HEADERS["User-Agent"]},
    )
    started = time.perf_counter()
    try:
        with NetworkSlot():
            response = urllib.request.urlopen(req, timeout=timeout, context=ssl_context())
        try:
            latency = round((time.perf_counter() - started) * 1000, 1)
            code = response.getcode()
            payload = json.loads(response.read().decode("utf-8"))
        finally:
            close_quietly(response)
        answers = payload.get("Answer") or []
        ips = [item["data"].strip() for item in answers if item.get("type") == 1 and item.get("data")]
        ok = code == 200 and bool(ips)
        if ok:
            detail = f"پاسخ معتبر DoH دریافت شد ({latency}ms)"
            status = "DOH_ACCESSIBLE"
        elif code == 200:
            detail = "پاسخ DoH بدون رکورد A"
            status = "DOH_EMPTY"
        else:
            detail = f"HTTP {code}"
            status = f"HTTP_{code}"
        return {
            "ok": ok,
            "ips": ips,
            "latency_ms": latency,
            "status": status,
            "detail": detail,
        }
    except Exception as exc:
        message = str(exc).lower()
        if "timed out" in message or "timeout" in message:
            status = "DOH_TIMEOUT"
            detail = "تایم‌اوت استعلام DoH (فیلترینگ و دراپ پکت‌ها)"
        elif "refused" in message:
            status = "DOH_REFUSED"
            detail = "رد اتصال DoH"
        else:
            status = type(exc).__name__
            detail = f"عدم امکان اتصال به DoH ({status})"
        return {
            "ok": False,
            "ips": [],
            "latency_ms": None,
            "status": status,
            "detail": detail,
        }


def quic_initial_packet():
    """پکت QUIC Initial با نسخهٔ نامعتبر و طول ۱۲۰۰ بایت (RFC 9000)."""
    dcid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    scid = b"\x11\x12\x13\x14\x15\x16\x17\x18"
    header = bytes([0xC0, 0x1A, 0x2A, 0x3A, 0x4A, len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return header + b"\x00" * (1200 - len(header))


def probe_udp_quic(host, port=443, timeout=2.5):
    """
    یک پروب UDP/QUIC. نتیجهٔ (میزبان، پورت) بین بنچمارک QUIC و پروتکل‌های UDP مشترک است.
    error یکی از None، timeout، refused یا نام استثناست.
    """
    key = ("udp-quic", str(host), int(port))

    def work():
        return _udp_quic_once(host, port, timeout)

    return dict(cached_call(key, work))


def _udp_quic_once(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    started = time.perf_counter()
    try:
        sock.settimeout(timeout)
        ip = host if _is_ipv4(host) else (resolve_a(host, timeout=timeout) or [None])[0]
        if not ip:
            return {
                "ok": False,
                "latency_ms": None,
                "bytes_received": 0,
                "error": "dns",
            }
        with NetworkSlot():
            sock.sendto(quic_initial_packet(), (ip, port))
            data, _ = sock.recvfrom(2048)
        return {
            "ok": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "bytes_received": len(data),
            "error": None,
        }
    except socket.timeout:
        return {"ok": False, "latency_ms": None, "bytes_received": 0, "error": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "latency_ms": None, "bytes_received": 0, "error": "refused"}
    except Exception as exc:
        return {"ok": False, "latency_ms": None, "bytes_received": 0, "error": type(exc).__name__}
    finally:
        close_quietly(sock)


def _is_ipv4(value):
    parts = str(value).split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def tcp_cache_key(host, port):
    return ("tcp", str(host), int(port))


def note_tcp_open(host, port, latency_ms):
    """اگر اتصال TCP همین الان برقرار شده، پروب بعدی همان آدرس را تکرار نکند."""
    cache_put(tcp_cache_key(host, port), {
        "ok": True,
        "latency_ms": latency_ms,
        "error": None,
    })


def probe_tcp(host, port=443, timeout=2.5):
    key = tcp_cache_key(host, port)

    def work():
        return _tcp_once(host, port, timeout)

    return dict(cached_call(key, work))


def _tcp_once(host, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    started = time.perf_counter()
    try:
        sock.settimeout(timeout)
        ip = host if _is_ipv4(host) else (resolve_a(host, timeout=timeout) or [None])[0]
        if not ip:
            return {"ok": False, "latency_ms": None, "error": "dns"}
        with NetworkSlot():
            sock.connect((ip, port))
        return {
            "ok": True,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
            "error": None,
        }
    except ConnectionResetError:
        return {"ok": False, "latency_ms": None, "error": "reset"}
    except (socket.timeout, TimeoutError):
        return {"ok": False, "latency_ms": None, "error": "timeout"}
    except Exception as exc:
        return {"ok": False, "latency_ms": None, "error": type(exc).__name__}
    finally:
        close_quietly(sock)
