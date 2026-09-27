#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول پایش پروتکل‌های نوین دور زدن فیلترینگ (Circumvention Protocols Benchmark)
- بررسی وضعیت پروتکل‌های مدرن: V2Ray (VMess/VLESS/WS) / Reality / Shadowsocks / Hysteria2 / TUIC
- دسترسی‌پذیری پروتکل‌های امن دی‌ان‌اس: DNS-over-HTTPS (DoH) و DNS-over-TLS (DoT port 853)
- کاوش و ارزیابی آی‌پی‌های تمیز کلودفلر (Cloudflare Clean IPs Reachability) روی پورت ۴۴۳
"""

import sys
import os
import time
import socket
import ssl
import json
import urllib.request
import urllib.error
import concurrent.futures

# دامنه‌ها و اهداف شبیه‌سازی پروتکل Reality (VLESS-Reality)
REALITY_TARGETS = [
    {"name": "Apple (gateway.icloud.com)", "host": "17.253.144.10", "sni": "gateway.icloud.com", "port": 443},
    {"name": "Microsoft (teams.microsoft.com)", "host": "52.114.77.33", "sni": "teams.microsoft.com", "port": 443},
    {"name": "Amazon (aws.amazon.com)", "host": "54.239.28.85", "sni": "aws.amazon.com", "port": 443}
]

# پورت‌های استاندارد CDN برای V2Ray WebSocket
V2RAY_WS_TARGETS = [
    {"name": "Cloudflare WS (Port 443)", "host": "104.21.5.198", "port": 443, "sni": "cloudflare.com"},
    {"name": "Cloudflare WS (Port 8443)", "host": "104.21.5.198", "port": 8443, "sni": "cloudflare.com"},
    {"name": "Cloudflare WS (Port 2053)", "host": "104.21.5.198", "port": 2053, "sni": "cloudflare.com"},
    {"name": "Cloudflare WS (Port 2083)", "host": "104.21.5.198", "port": 2083, "sni": "cloudflare.com"}
]

# اهداف پروتکل‌های UDP-محور (Hysteria2 / TUIC / QUIC)
UDP_CIRCUMVENTION_TARGETS = [
    {"name": "Hysteria2 UDP (Port 443)", "host": "1.1.1.1", "port": 443, "protocol": "Hysteria2/QUIC"},
    {"name": "Hysteria2 UDP (Port 8443)", "host": "1.1.1.1", "port": 8443, "protocol": "Hysteria2/QUIC"},
    {"name": "TUIC QUIC v1 (Port 443)", "host": "8.8.8.8", "port": 443, "protocol": "TUIC/QUICv1"},
    {"name": "TUIC High Port (Port 30000)", "host": "1.1.1.1", "port": 30000, "protocol": "TUIC/HighPort"}
]

# اهداف پروتکل شادوساکس (Shadowsocks AEAD)
SHADOWSOCKS_TARGETS = [
    {"name": "Shadowsocks Default (Port 8388)", "host": "1.1.1.1", "port": 8388},
    {"name": "Shadowsocks Alt (Port 8080)", "host": "1.1.1.1", "port": 8080},
    {"name": "Shadowsocks HTTPS Port (Port 443)", "host": "104.21.5.198", "port": 443}
]

# سرورهای DNS-over-HTTPS (DoH)
DOH_TARGETS = [
    {"name": "Google DoH", "url": "https://8.8.8.8/resolve?name=google.com&type=A"},
    {"name": "Cloudflare DoH", "url": "https://1.1.1.1/dns-query?name=google.com&type=A"},
    {"name": "Quad9 DoH", "url": "https://9.9.9.9/dns-query?name=google.com&type=A"},
    {"name": "AdGuard DoH", "url": "https://dns.adguard-dns.com/resolve?name=google.com&type=A"}
]

# سرورهای DNS-over-TLS (DoT) روی پورت ۸۵۳
DOT_TARGETS = [
    {"name": "Google DoT (8.8.8.8:853)", "ip": "8.8.8.8", "port": 853, "sni": "dns.google"},
    {"name": "Cloudflare DoT (1.1.1.1:853)", "ip": "1.1.1.1", "port": 853, "sni": "cloudflare-dns.com"},
    {"name": "Quad9 DoT (9.9.9.9:853)", "ip": "9.9.9.9", "port": 853, "sni": "dns.quad9.net"},
    {"name": "AdGuard DoT (94.140.14.14:853)", "ip": "94.140.14.14", "port": 853, "sni": "dns.adguard.com"}
]

# رنج‌ها و آی‌پی‌های مشهور کلودفلر (Cloudflare Clean IP Candidates)
CLOUDFLARE_CLEAN_IPS = [
    "104.16.0.1", "104.17.0.1", "104.18.0.1", "104.19.0.1", "104.20.0.1",
    "104.21.5.198", "162.159.137.85", "172.67.182.203", "188.114.96.1",
    "104.24.10.1", "172.64.80.1", "162.159.36.1", "104.26.12.1",
    "172.65.251.78", "162.159.152.4"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/dns-json"
}

def create_ssl_context():
    try:
        return ssl._create_unverified_context()
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

# ----------------- ۱. تست پروتکل Reality و TLS 1.3 -----------------
def probe_reality_endpoint(target, timeout=2.5):
    """تست برقراری هندشیک TLS 1.3 مشابه پیکربندی Reality با SNI معتبر خارجی"""
    host = target["host"]
    port = target["port"]
    sni = target["sni"]
    name = target["name"]
    
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        ctx = create_ssl_context()
        ss = ctx.wrap_socket(s, server_hostname=sni)
        dt = round((time.time() - t0) * 1000, 1)
        ss.close()
        return {
            "name": name,
            "protocol": "Reality (TLS 1.3)",
            "host": f"{host}:{port}",
            "ok": True,
            "latency_ms": dt,
            "status": "REALITY_PASS",
            "detail": f"هندشیک امن Reality موفق ({dt}ms)"
        }
    except Exception as e:
        s.close()
        err_name = type(e).__name__
        if "Timeout" in err_name or isinstance(e, socket.timeout):
            status = "REALITY_TIMEOUT_THROTTLED"
            detail = "تایم‌اوت هندشیک TLS Reality (تراتلینگ یا دراپ فایروال)"
        elif "Reset" in err_name or "ConnectionReset" in err_name:
            status = "REALITY_RST_INJECTED"
            detail = "تزریق پکت TCP RST در حین هندشیک Reality"
        else:
            status = "REALITY_HANDSHAKE_FAIL"
            detail = f"خطای هندشیک ({err_name}: {str(e)[:30]})"
            
        return {
            "name": name,
            "protocol": "Reality (TLS 1.3)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": status,
            "detail": detail
        }

# ----------------- ۲. تست پروتکل V2Ray WebSocket -----------------
def probe_v2ray_ws_endpoint(target, timeout=2.5):
    """ارسال درخواست HTTP Upgrade: WebSocket به پورت‌های پروکسی CDN و ارزیابی پاسخ فایروال"""
    host = target["host"]
    port = target["port"]
    sni = target["sni"]
    name = target["name"]
    
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        ctx = create_ssl_context()
        ss = ctx.wrap_socket(s, server_hostname=sni)
        
        # درخواست سوئیچ به پروتکل وب‌سوکت
        ws_req = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {sni}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode('utf-8')
        
        ss.sendall(ws_req)
        resp = ss.recv(512)
        dt = round((time.time() - t0) * 1000, 1)
        ss.close()
        
        # اگر پاسخ HTTP برگشت، یعنی کانال وب‌سوکت باز است و مسدود نشده
        ok = b"HTTP/1.1" in resp or b"HTTP/2" in resp
        return {
            "name": name,
            "protocol": "V2Ray (WebSocket/TLS)",
            "host": f"{host}:{port}",
            "ok": ok,
            "latency_ms": dt,
            "status": "WS_REACHABLE" if ok else "WS_UNEXPECTED_RESPONSE",
            "detail": f"ارتباط وب‌سوکت برقرار شد ({dt}ms)" if ok else "پاسخ نامتعارف وب‌سوکت"
        }
    except Exception as e:
        s.close()
        err_name = type(e).__name__
        return {
            "name": name,
            "protocol": "V2Ray (WebSocket/TLS)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "WS_BLOCKED",
            "detail": f"مسدودسازی در وب‌سوکت ({err_name})"
        }

# ----------------- ۳. تست پروتکل Shadowsocks (AEAD) -----------------
def probe_shadowsocks_endpoint(target, timeout=2.5):
    """
    تست برقراری اتصال و ارسال پکت اولیه مشابه پروتکل Shadowsocks AEAD
    جهت ارزیابی رفتار فایروال در مواجهه با ترافیک انتروپی بالا (High-Entropy Encrypted Stream)
    و تشخیص تزریق بلافاصله TCP RST یا دراپ بسته‌ها
    """
    host = target["host"]
    port = target["port"]
    name = target["name"]
    
    salt = os.urandom(32)
    probe_payload = salt + os.urandom(16)
    
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(probe_payload)
        dt = round((time.time() - t0) * 1000, 1)
        try:
            s.settimeout(1.0)
            data = s.recv(64)
            s.close()
            return {
                "name": name,
                "protocol": "Shadowsocks (AEAD)",
                "host": f"{host}:{port}",
                "ok": True,
                "latency_ms": dt,
                "status": "SS_OPEN",
                "detail": f"اتصال شادوساکس برقرار و داده تبادل شد ({dt}ms)"
            }
        except socket.timeout:
            s.close()
            return {
                "name": name,
                "protocol": "Shadowsocks (AEAD)",
                "host": f"{host}:{port}",
                "ok": True,
                "latency_ms": dt,
                "status": "SS_ALIVE_NO_RST",
                "detail": f"پورت باز و عدم تزریق RST پس از ارسال انتروپی ({dt}ms)"
            }
    except ConnectionResetError:
        s.close()
        return {
            "name": name,
            "protocol": "Shadowsocks (AEAD)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "SS_RST_INJECTED",
            "detail": "تزریق TCP RST توسط فایروال DPI پس از مشاهده الگوی انتروپی"
        }
    except (socket.timeout, TimeoutError):
        s.close()
        return {
            "name": name,
            "protocol": "Shadowsocks (AEAD)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "SS_TIMEOUT",
            "detail": "تایم‌اوت اتصال به پورت شادوساکس (بلک‌هول یا دراپ فایروال)"
        }
    except ConnectionRefusedError:
        s.close()
        return {
            "name": name,
            "protocol": "Shadowsocks (AEAD)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "SS_PORT_CLOSED",
            "detail": "پورت بسته است (عدم مسدودسازی توسط فایروال؛ سرور در مقصد ریجکت کرد)"
        }
    except Exception as e:
        s.close()
        return {
            "name": name,
            "protocol": "Shadowsocks (AEAD)",
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": type(e).__name__,
            "detail": str(e)[:35]
        }

# ----------------- ۴. تست پروتکل‌های UDP (Hysteria2 / TUIC) -----------------
def probe_udp_circumvention(target, timeout=2.5):
    """ارسال پکت کاوش UDP (مطابق RFC 9000 با طول ۱۲۰۰ بایت) به پورت‌های Hysteria2 و TUIC و بررسی فیلترینگ UDP"""
    host = target["host"]
    port = target["port"]
    name = target["name"]
    proto = target["protocol"]
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    
    # پکت استاندارد کاوش QUIC / Hysteria2 با طول حداقل ۱۲۰۰ بایت (RFC 9000)
    dcid = b'\x08\xaa\xbb\xcc\xdd\xee\xff\x11'
    scid = b'\x08\x12\x34\x56\x78\x9a\xbc\xde'
    hdr = bytes([0xc0, 0x1a, 0x2a, 0x3a, 0x4a, len(dcid)]) + dcid + bytes([len(scid)]) + scid
    probe_packet = hdr + b'\x00' * (1200 - len(hdr))
    
    t0 = time.time()
    try:
        ip = socket.gethostbyname(host)
        s.sendto(probe_packet, (ip, port))
        data, _ = s.recvfrom(2048)
        dt = round((time.time() - t0) * 1000, 1)
        s.close()
        return {
            "name": name,
            "protocol": proto,
            "host": f"{host}:{port}",
            "ok": True,
            "latency_ms": dt,
            "status": "UDP_OPEN",
            "detail": f"پاسخ استاندارد UDP/QUIC دریافت شد ({len(data)} بایت, {dt}ms)"
        }
    except socket.timeout:
        s.close()
        return {
            "name": name,
            "protocol": proto,
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "UDP_DROPPED",
            "detail": "تایم‌اوت UDP (مسدودسازی و بلک‌هول ترافیک UDP توسط فایروال)"
        }
    except ConnectionRefusedError:
        s.close()
        return {
            "name": name,
            "protocol": proto,
            "host": f"{host}:{port}",
            "ok": True,
            "latency_ms": None,
            "status": "UDP_REACHABLE_PORT_CLOSED",
            "detail": "عبور موفق پکت UDP از فایروال (دریافت خطای ICMP Port Unreachable از سرور)"
        }
    except Exception as e:
        s.close()
        return {
            "name": name,
            "protocol": proto,
            "host": f"{host}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": "UDP_ERROR",
            "detail": str(e)[:30]
        }

# ----------------- ۴. تست DNS-over-HTTPS (DoH) -----------------
def probe_doh_endpoint(target, timeout=3.0):
    name = target["name"]
    url = target["url"]
    ctx = create_ssl_context()
    
    t0 = time.time()
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            dt = round((time.time() - t0) * 1000, 1)
            code = resp.getcode()
            ok = (code == 200)
            return {
                "name": name,
                "type": "DoH",
                "endpoint": url.split('?')[0],
                "ok": ok,
                "latency_ms": dt,
                "status": "DOH_ACCESSIBLE" if ok else f"HTTP_{code}",
                "detail": f"پاسخ معتبر DoH دریافت شد ({dt}ms)"
            }
    except Exception as e:
        err_msg = str(e)
        if "timed out" in err_msg.lower():
            status = "DOH_TIMEOUT"
            detail = "تایم‌اوت استعلام DoH (فیلترینگ و دراپ پکت‌ها)"
        elif "refused" in err_msg.lower():
            status = "DOH_REFUSED"
            detail = "رد اتصال DoH"
        else:
            status = type(e).__name__
            detail = f"عدم امکان اتصال به DoH ({status})"
            
        return {
            "name": name,
            "type": "DoH",
            "endpoint": url.split('?')[0],
            "ok": False,
            "latency_ms": None,
            "status": status,
            "detail": detail
        }

# ----------------- ۵. تست DNS-over-TLS (DoT port 853) -----------------
def probe_dot_endpoint(target, timeout=3.0):
    name = target["name"]
    ip = target["ip"]
    port = target.get("port", 853)
    sni = target.get("sni")
    
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        ctx = create_ssl_context()
        ss = ctx.wrap_socket(s, server_hostname=sni)
        dt = round((time.time() - t0) * 1000, 1)
        ss.close()
        return {
            "name": name,
            "type": "DoT",
            "endpoint": f"{ip}:{port}",
            "ok": True,
            "latency_ms": dt,
            "status": "DOT_ACCESSIBLE",
            "detail": f"اتصال امن DoT روی پورت ۸۵۳ برقرار شد ({dt}ms)"
        }
    except Exception as e:
        s.close()
        err_name = type(e).__name__
        if "Timeout" in err_name or isinstance(e, socket.timeout):
            status = "DOT_TIMEOUT"
            detail = "تایم‌اوت پورت ۸۵۳ (مسدودسازی پورت DoT در فایروال)"
        elif "Reset" in err_name or "EOF" in err_name:
            status = "DOT_RST"
            detail = "تزریق TCP RST روی پورت ۸۵۳ DoT"
        else:
            status = err_name
            detail = f"خطای مذاکره DoT ({err_name})"
            
        return {
            "name": name,
            "type": "DoT",
            "endpoint": f"{ip}:{port}",
            "ok": False,
            "latency_ms": None,
            "status": status,
            "detail": detail
        }

# ----------------- ۶. کاوش آی‌پی‌های تمیز کلودفلر (Clean IPs) -----------------
def probe_single_clean_ip(ip, port=443, timeout=2.0):
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        dt = round((time.time() - t0) * 1000, 1)
        s.close()
        return {"ip": ip, "port": port, "ok": True, "latency_ms": dt, "status": "OPEN"}
    except Exception as e:
        s.close()
        return {"ip": ip, "port": port, "ok": False, "latency_ms": None, "status": type(e).__name__}

def check_cloudflare_clean_ips(candidates=None, timeout=2.0, threads=15):
    """
    بررسی دسترسی‌پذیری آی‌پی‌های مشهور کلودفلر جهت سنجش میزان مسدودسازی مستقیم IP
    و استخراج تمیزترین و سریع‌ترین آی‌پی‌های Anycast در شبکه فعلی
    """
    if candidates is None:
        candidates = CLOUDFLARE_CLEAN_IPS
        
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        f_map = {executor.submit(probe_single_clean_ip, ip, 443, timeout): ip for ip in candidates}
        for f in concurrent.futures.as_completed(f_map):
            results.append(f.result())
            
    working_ips = [r for r in results if r["ok"]]
    working_count = len(working_ips)
    total_count = len(candidates)
    reachability_pct = round((working_count / total_count) * 100, 1) if total_count else 0
    
    lats = [r["latency_ms"] for r in working_ips if r["latency_ms"] is not None]
    avg_latency = round(sum(lats) / len(lats), 1) if lats else None
    
    # مرتب‌سازی بر اساس تاخیر
    sorted_working = sorted(working_ips, key=lambda x: x["latency_ms"])
    top_clean_ips = [r["ip"] for r in sorted_working[:5]]
    
    if reachability_pct >= 75:
        badge = "🟢 رنج‌های IP کلودفلر عمدتاً باز و تمیزند"
    elif 30 <= reachability_pct < 75:
        badge = "🟡 مسدودسازی انتخابی و گسترده رنج‌های کلودفلر"
    else:
        badge = "🔴 بلک‌هول عمومی و شدید IPهای Anycast کلودفلر"

    return {
        "reachability_percent": reachability_pct,
        "working_count": working_count,
        "total_tested": total_count,
        "avg_latency_ms": avg_latency,
        "badge": badge,
        "top_clean_ips": top_clean_ips,
        "results": sorted(results, key=lambda x: (not x["ok"], x.get("latency_ms") or 9999))
    }

# ----------------- اجرای جامع بنچمارک ضد فیلتر -----------------
def run_circumvention_benchmark(timeout=2.5, threads=15):
    """
    اجرای همه‌جانبه بررسی ابزارها و پروتکل‌های پیشرفته ضد فیلتر
    """
    start = time.time()
    
    protocol_results = []
    doh_results = []
    dot_results = []
    
    # آماده‌سازی کلیه تست‌ها
    tasks = []
    for t in REALITY_TARGETS:
        tasks.append(("reality", t, probe_reality_endpoint))
    for t in V2RAY_WS_TARGETS:
        tasks.append(("v2ray_ws", t, probe_v2ray_ws_endpoint))
    for t in SHADOWSOCKS_TARGETS:
        tasks.append(("shadowsocks", t, probe_shadowsocks_endpoint))
    for t in UDP_CIRCUMVENTION_TARGETS:
        tasks.append(("udp", t, probe_udp_circumvention))
    for t in DOH_TARGETS:
        tasks.append(("doh", t, probe_doh_endpoint))
    for t in DOT_TARGETS:
        tasks.append(("dot", t, probe_dot_endpoint))
        
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        f_map = {executor.submit(fn, item, timeout): (cat, item) for cat, item, fn in tasks}
        for f in concurrent.futures.as_completed(f_map):
            cat, _ = f_map[f]
            res = f.result()
            if cat in ["reality", "v2ray_ws", "shadowsocks", "udp"]:
                protocol_results.append(res)
            elif cat == "doh":
                doh_results.append(res)
            elif cat == "dot":
                dot_results.append(res)
                
    # کاوش آی‌پی‌های تمیز کلودفلر
    clean_ips_res = check_cloudflare_clean_ips(threads=threads, timeout=2.0)
    
    elapsed = round(time.time() - start, 2)
    
    # خلاصه پروتکل‌ها
    proto_total = len(protocol_results)
    proto_ok = sum(1 for r in protocol_results if r["ok"])
    proto_pct = round((proto_ok / proto_total) * 100, 1) if proto_total else 0
    
    doh_ok = sum(1 for r in doh_results if r["ok"])
    dot_ok = sum(1 for r in dot_results if r["ok"])
    
    return {
        "elapsed_seconds": elapsed,
        "summary": {
            "protocols_working": proto_ok,
            "protocols_total": proto_total,
            "protocols_percent": proto_pct,
            "doh_working": doh_ok,
            "doh_total": len(doh_results),
            "dot_working": dot_ok,
            "dot_total": len(dot_results),
            "clean_ips_working": clean_ips_res["working_count"],
            "clean_ips_total": clean_ips_res["total_tested"],
            "clean_ips_percent": clean_ips_res["reachability_percent"]
        },
        "protocols": sorted(protocol_results, key=lambda x: (not x["ok"], x.get("latency_ms") or 9999)),
        "doh": sorted(doh_results, key=lambda x: (not x["ok"], x.get("latency_ms") or 9999)),
        "dot": sorted(dot_results, key=lambda x: (not x["ok"], x.get("latency_ms") or 9999)),
        "clean_ips": clean_ips_res
    }

if __name__ == "__main__":
    print("──▶ در حال اجرای بنچمارک پروتکل‌های نوین دور زدن فیلترینگ...")
    res = run_circumvention_benchmark(timeout=2.5)
    s = res["summary"]
    print(f"پروتکل‌های مدرن فعال: {s['protocols_working']}/{s['protocols_total']} ({s['protocols_percent']}%)")
    print(f"سرورهای DoH فعال:      {s['doh_working']}/{s['doh_total']}")
    print(f"سرورهای DoT (پورت ۸۵۳): {s['dot_working']}/{s['dot_total']}")
    print(f"آی‌پی‌های تمیز کلودفلر: {s['clean_ips_working']}/{s['clean_ips_total']} ({s['clean_ips_percent']}%) | {res['clean_ips']['badge']}")
    if res["clean_ips"]["top_clean_ips"]:
        print(f"سریع‌ترین آی‌پی‌های تمیز: {', '.join(res['clean_ips']['top_clean_ips'])}")
