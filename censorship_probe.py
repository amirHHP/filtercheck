#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول تفکیک لایه‌ای فیلترینگ و ریشه‌یابی تکنیکال (Censorship Root-Cause Analysis)
- بررسی آلودگی و دستکاری DNS (DNS Poisoning & Spoofing Detection)
- تفکیک مسدودسازی بر اساس SNI در برابر مسدودسازی مستقیم IP (SNI vs IP Blocking)
- تفکیک تزریق پکت TCP RST در برابر دراپ خاموش و تایم‌اوت (TCP RST vs Silent Drop/Blackhole)
- بررسی وضعیت مسدودسازی UDP/QUIC (HTTP/3) در مقایسه با TCP (HTTP/1.1 & HTTP/2)
"""

import socket
import ssl
import time
import os
import subprocess
import json
import urllib.request
import urllib.parse
import concurrent.futures

# دامنه‌های تستی برای ارزیابی رفتاری UDP/QUIC در برابر TCP
QUIC_TEST_TARGETS = [
    {"name": "Google DNS (8.8.8.8)", "host": "8.8.8.8", "port": 443},
    {"name": "Cloudflare DNS (1.1.1.1)", "host": "1.1.1.1", "port": 443},
    {"name": "Cloudflare CDN", "host": "cloudflare.com", "port": 443},
    {"name": "Google Web (google.com)", "host": "google.com", "port": 443},
    {"name": "Aparat / Domestic", "host": "aparat.com", "port": 443},
    {"name": "Sotoon / Domestic", "host": "sotoon.ir", "port": 443}
]

# آی‌پی‌های مشهور دستکاری/تزریق DNS در ایران
KNOWN_SPOOFED_IPS = {
    "10.10.34.34", "10.10.34.35", "10.10.34.36", "10.10.34.37",
    "127.0.0.1", "0.0.0.0"
}

def is_rfc1918_private_ip(ip_str):
    """بررسی اینکه آیا آی‌پی جزو آدرس‌های خصوصی/لوکال شبکه است یا خیر"""
    if not ip_str:
        return False
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    try:
        p0, p1 = int(parts[0]), int(parts[1])
        if p0 == 10:
            return True
        if p0 == 172 and 16 <= p1 <= 31:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if p0 == 127 or p0 == 0:
            return True
    except ValueError:
        return False
    return False

def resolve_domain_local(domain, timeout=2):
    """رزولوشن دامنه از طریق DNS سیستم / محلی"""
    try:
        res = subprocess.run(
            ['dig', '+time=1', '+tries=1', '+short', domain],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        out = res.stdout.strip()
        if res.returncode == 0 and out:
            ips = [line.strip() for line in out.split('\n') if line.strip() and not line.startswith(';')]
            # فیلتر کردن رکوردهای CNAME و برداشتن اولین آی‌پی
            valid_ips = [ip for ip in ips if any(c.isdigit() for c in ip.split('.'))]
            return valid_ips
    except Exception:
        pass
        
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET)
        return list(set(item[4][0] for item in infos))
    except Exception:
        return []

def query_trusted_doh(domain, timeout=2.5):
    """استعلام رکورد A دامنه از طریق DNS-over-HTTPS مطمئن (Google 8.8.8.8 یا Cloudflare)"""
    endpoints = [
        f"https://8.8.8.8/resolve?name={domain}&type=A",
        f"https://1.1.1.1/dns-query?name={domain}&type=A",
        f"https://1.0.0.1/dns-query?name={domain}&type=A"
    ]
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for ep in endpoints:
        try:
            req = urllib.request.Request(
                ep,
                headers={"Accept": "application/dns-json", "User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                if resp.getcode() == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    answers = payload.get("Answer", [])
                    ips = [a["data"].strip() for a in answers if a.get("type") == 1]
                    if ips:
                        return ips
        except Exception:
            continue
    return []

def detect_dns_poisoning(domain, timeout=2.0, check_doh=True):
    """
    بررسی سلامت پاسخ DNS و تشخیص آلودگی (DNS Poisoning / Spoofing)
    با مقایسه پاسخ DNS سیستم با سرورهای DoH بین‌المللی مطمئن (Google 8.8.8.8 / Cloudflare)
    """
    local_ips = resolve_domain_local(domain, timeout=timeout)
    
    # استعلام پاسخ معتبر جهانی از DoH در صورت درخواست
    doh_ips = query_trusted_doh(domain, timeout=timeout + 0.5) if check_doh else []
    
    # حالت ۱: دریافت نکردن پاسخ محلی (NXDOMAIN یا تایم‌اوت)
    if not local_ips:
        if doh_ips:
            # سرور مطمئن جهانی دامنه را می‌شناسد اما DNS محلی هیچ پاسخی نمی‌دهد یا NXDOMAIN تزریق کرده است!
            return {
                "poisoned": True,
                "status": "DNS_TAMPERED_NXDOMAIN",
                "message": f"تزریق NXDOMAIN / حذف پاسخ DNS محلی (در حالی که در DoH جهانی معتبر است: {doh_ips[0]})",
                "local_ips": [],
                "doh_ips": doh_ips,
                "ips": []
            }
        return {
            "poisoned": False,
            "status": "NXDOMAIN_OR_TIMEOUT",
            "message": "عدم دریافت پاسخ DNS (تایم‌اوت یا دامنه نامعتبر)",
            "local_ips": [],
            "doh_ips": doh_ips,
            "ips": []
        }
        
    # حالت ۲: بررسی آی‌پی‌های مشهور فیلترینگ ایران و رنج‌های لوکال/RFC1918
    for ip in local_ips:
        if ip in KNOWN_SPOOFED_IPS or is_rfc1918_private_ip(ip):
            return {
                "poisoned": True,
                "status": "DNS_POISONED_IRAN_INJECTION",
                "message": f"تزریق پاسخ جعلی DNS به آدرس مسدود/لوکال پیوندها ({ip})",
                "spoofed_ip": ip,
                "local_ips": local_ips,
                "doh_ips": doh_ips,
                "ips": local_ips
            }

    # حالت ۳: بررسی عدم تطابق فاحش آی‌پی محلی با پاسخ DoH مطمئن (DNS Divergence / Hijacking)
    if doh_ips and local_ips:
        # شناسایی رنج‌های مشهور CDNهای جهانی
        known_cdn_prefixes = (
            '142.250.', '142.251.', '172.217.', '172.253.', '192.178.', '216.58.', '74.125.',  # Google
            '104.', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.', '162.159.', '188.114.',  # Cloudflare
            '151.101.', '199.232.',  # Fastly
            '23.', '104.', '184.', '2.', '96.',  # Akamai
            '52.', '54.', '13.', '99.84.', '99.86.', '143.204.', '18.',  # AWS / CloudFront
            '20.', '40.', '51.'  # Microsoft / Azure
        )
        local_is_cdn = any(ip.startswith(known_cdn_prefixes) for ip in local_ips)
        doh_is_cdn = any(ip.startswith(known_cdn_prefixes) for ip in doh_ips)
        
        # اگر هر دو در رنج CDN هستند، این تفاوت ناشی از Anycast/GeoDNS طبیعی است نه آلودگی
        if not (local_is_cdn and doh_is_cdn):
            local_subnets = {'.'.join(ip.split('.')[:2]) for ip in local_ips if '.' in ip}
            doh_subnets = {'.'.join(ip.split('.')[:2]) for ip in doh_ips if '.' in ip}
            if not (set(local_ips) & set(doh_ips)) and not (local_subnets & doh_subnets):
                # اعتبارسنجی قطعی: تست اتصال TLS به آی‌پی محلی با نام دامنه مورد نظر
                # اگر سرور گواهی معتبر تحویل دهد، قطعا سرور واقعی و GeoDNS است نه آلودگی
                try:
                    s_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_test.settimeout(1.5)
                    s_test.connect((local_ips[0], 443))
                    c_test = ssl.create_default_context()
                    c_test.check_hostname = False
                    c_test.verify_mode = ssl.CERT_NONE
                    s_wrap = c_test.wrap_socket(s_test, server_hostname=domain)
                    cert = s_wrap.getpeercert(binary_form=True)
                    s_wrap.close()
                    if cert:
                        return {
                            "poisoned": False,
                            "status": "CLEAN_OR_CDN",
                            "message": f"پاسخ DNS معتبر است (تایید هویت سرور {local_ips[0]} با TLS)",
                            "local_ips": local_ips,
                            "doh_ips": doh_ips,
                            "ips": local_ips
                        }
                except Exception:
                    pass

                return {
                    "poisoned": True,
                    "status": "DNS_POISONED_DIVERGENT",
                    "message": f"انحراف مشکوک پاسخ DNS محلی ({local_ips[0]}) در برابر آی‌پی واقعی جهانی ({doh_ips[0]})",
                    "spoofed_ip": local_ips[0],
                    "local_ips": local_ips,
                    "doh_ips": doh_ips,
                    "ips": local_ips
                }
            
    return {
        "poisoned": False,
        "status": "CLEAN_OR_CDN",
        "message": "پاسخ DNS معتبر به نظر می‌رسد",
        "local_ips": local_ips,
        "doh_ips": doh_ips,
        "ips": local_ips
    }

def probe_sni_vs_ip(domain, target_ip=None, port=443, timeout=3.0):
    """
    تفکیک دقیق فیلترینگ بر مبنای SNI در برابر مسدودسازی مستقیم IP یا پروتکل TCP:
    ۱. تست اتصال TCP خالص بدون TLS
    ۲. تست هندشیک TLS با ارسال SNI واقعی
    ۳. تست هندشیک TLS بدون ارسال SNI یا با SNI بی‌خطر (مانند ساب‌دامین لوکال یا خالی)
    """
    if not target_ip:
        ips = resolve_domain_local(domain, timeout=2)
        if not ips:
            return {
                "mechanism": "DNS_RESOLUTION_FAILED",
                "tcp_ok": False,
                "tls_sni_ok": False,
                "detail": "عدم امکان اتصال به دلیل عدم رزولوشن DNS"
            }
        target_ip = ips[0]
        
    # بررسی اگر آی‌پی تزریقی باشد
    if target_ip in KNOWN_SPOOFED_IPS or is_rfc1918_private_ip(target_ip):
        return {
            "mechanism": "DNS_POISONING",
            "tcp_ok": False,
            "tls_sni_ok": False,
            "target_ip": target_ip,
            "detail": f"آلودگی DNS: هدایت به آی‌پی جعلی {target_ip}"
        }

    # ۱. تست اتصال TCP
    tcp_ok = False
    tcp_lat = None
    tcp_error = None
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((target_ip, port))
        tcp_lat = round((time.time() - t0) * 1000, 1)
        tcp_ok = True
        s.close()
    except ConnectionResetError:
        tcp_error = "TCP_RST"
        s.close()
    except (socket.timeout, TimeoutError):
        tcp_error = "TCP_TIMEOUT"
        s.close()
    except Exception as e:
        tcp_error = type(e).__name__
        s.close()

    if not tcp_ok:
        # اتصال TCP قبل از ارسال SNI شکست خورد (مسدودسازی مستقیم IP یا پورت)
        if tcp_error == "TCP_RST":
            return {
                "mechanism": "IP_BLOCKED_RST",
                "tcp_ok": False,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "detail": f"مسدودسازی در لایه TCP با ارسال بلافاصله TCP RST به {target_ip}:{port}"
            }
        else:
            return {
                "mechanism": "IP_BLOCKED_TIMEOUT",
                "tcp_ok": False,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "detail": f"دراپ خاموش / بلک‌هول پکت‌های TCP SYN به {target_ip}:{port} (تایم‌اوت)"
            }

    # ۲. تست هندشیک TLS با ارسال SNI
    tls_sni_ok = False
    tls_sni_lat = None
    tls_sni_error = None
    t0 = time.time()
    s_tls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_tls.settimeout(timeout)
    try:
        s_tls.connect((target_ip, port))
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(s_tls, server_hostname=domain)
        tls_sni_lat = round((time.time() - t0) * 1000, 1)
        tls_sni_ok = True
        ss.close()
    except ssl.SSLEOFError:
        tls_sni_error = "TLS_SNI_RST_EOF"
        s_tls.close()
    except ConnectionResetError:
        tls_sni_error = "TLS_SNI_RST"
        s_tls.close()
    except (socket.timeout, TimeoutError):
        tls_sni_error = "TLS_SNI_TIMEOUT"
        s_tls.close()
    except Exception as e:
        tls_sni_error = type(e).__name__
        s_tls.close()

    if tls_sni_ok:
        return {
            "mechanism": "ACCESSIBLE_TLS",
            "tcp_ok": True,
            "tls_sni_ok": True,
            "target_ip": target_ip,
            "tcp_latency_ms": tcp_lat,
            "tls_latency_ms": tls_sni_lat,
            "detail": f"اتصال امن TLS با موفقیت و بدون فیلترینگ SNI برقرار شد ({tls_sni_lat}ms)"
        }

    # ۳. هندشیک با SNI شکست خورده است. اکنون تست بدون SNI را انجام می‌دهیم تا مطمئن شویم فیلترینگ روی SNI است
    tls_nosni_ok = False
    tls_nosni_error = None
    s_nosni = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_nosni.settimeout(timeout)
    try:
        s_nosni.connect((target_ip, port))
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        # ارسال بدون server_hostname
        ss2 = ctx2.wrap_socket(s_nosni, server_hostname=None)
        tls_nosni_ok = True
        ss2.close()
    except Exception as e:
        tls_nosni_error = type(e).__name__
        s_nosni.close()

    # ریشه‌یابی بر اساس تفکیک دقیق رفتار با و بدون SNI
    if tls_nosni_ok:
        # اتصال بدون SNI موفق بوده اما با نام دامنه مسدود شده است -> قطعی‌ترین نشانه فیلترینگ SNI
        if "RST" in str(tls_sni_error) or "EOF" in str(tls_sni_error):
            return {
                "mechanism": "SNI_FILTERED_RST",
                "tcp_ok": True,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "tls_nosni_ok": True,
                "detail": f"فیلترینگ هوشمند SNI با تزریق TCP RST پس از مشاهده نام دامنه '{domain}' در ClientHello"
            }
        else:
            return {
                "mechanism": "SNI_FILTERED_THROTTLED",
                "tcp_ok": True,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "tls_nosni_ok": True,
                "detail": f"دراپ پکت یا تراتلینگ عمیق TLS ClientHello هنگام ارسال SNI دامنه '{domain}' (Timeout)"
            }
    else:
        # هم با SNI و هم بدون SNI شکست خورده است
        if "RST" in str(tls_sni_error) or "EOF" in str(tls_sni_error):
            return {
                "mechanism": "SNI_FILTERED_RST",
                "tcp_ok": True,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "tls_nosni_ok": False,
                "detail": f"تزریق TCP RST در لایه TLS Handshake (خطا: {tls_sni_error})"
            }
        elif "TIMEOUT" in str(tls_sni_error):
            return {
                "mechanism": "SNI_FILTERED_THROTTLED",
                "tcp_ok": True,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "tls_nosni_ok": False,
                "detail": f"تایم‌اوت TLS ClientHello به {target_ip}:{port} (فیلترینگ یا تراتلینگ عمیق)"
            }
        else:
            return {
                "mechanism": "TLS_HANDSHAKE_ERROR",
                "tcp_ok": True,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "tls_nosni_ok": False,
                "detail": f"خطا در پروتکل امنیتی TLS ({tls_sni_error})"
            }

def make_rfc9000_quic_probe():
    """
    تولید پکت کاوش استاندارد QUIC Initial / Version Negotiation مطابق با بند ۱۴.۱ از RFC 9000
    سایز پکت الزاماً باید حداقل ۱۲۰۰ بایت باشد، در غیر این صورت سرورهای استاندارد طبق مشخصات RFC آن را دراپ می‌کنند.
    """
    dcid = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    scid = b'\x11\x12\x13\x14\x15\x16\x17\x18'
    # 0xc0 = Long Header (0x80) | Fixed Bit (0x40)
    # نسخه 0x1a2a3a4a: نسخه نامعتبر جهت وادار کردن سرور استاندارد به پاسخ Version Negotiation
    hdr = bytes([0xc0, 0x1a, 0x2a, 0x3a, 0x4a, len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return hdr + b'\x00' * (1200 - len(hdr))

def probe_udp_quic_single(host, port=443, timeout=2.5):
    """
    تست دسترسی به UDP/QUIC (HTTP/3) روی پورت ۴۴۳
    ارسال پکت استاندارد کاوش QUIC Initial / Version Negotiation (RFC 9000)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    
    quic_probe = make_rfc9000_quic_probe()

    t0 = time.time()
    try:
        ip = socket.gethostbyname(host)
        s.sendto(quic_probe, (ip, port))
        data, addr = s.recvfrom(2048)
        dt = round((time.time() - t0) * 1000, 1)
        s.close()
        return {
            "ok": True,
            "status": "UDP_REACHABLE",
            "latency_ms": dt,
            "bytes_received": len(data),
            "detail": f"پاسخ استاندارد UDP/QUIC دریافت شد ({len(data)} بایت, {dt}ms)"
        }
    except socket.timeout:
        s.close()
        return {
            "ok": False,
            "status": "UDP_TIMEOUT_BLOCKED",
            "latency_ms": None,
            "detail": "تایم‌اوت UDP (مسدودسازی ترافیک UDP پورت ۴۴۳ / QUIC توسط فایروال)"
        }
    except ConnectionRefusedError:
        s.close()
        return {
            "ok": False,
            "status": "UDP_PORT_UNREACHABLE",
            "latency_ms": None,
            "detail": "دریافت خطای ICMP Port Unreachable (پورت پکت را نمی‌پذیرد)"
        }
    except Exception as e:
        s.close()
        return {
            "ok": False,
            "status": "UDP_ERROR",
            "latency_ms": None,
            "detail": f"خطا در ارسال UDP ({type(e).__name__}: {str(e)[:30]})"
        }

def probe_tcp_port_single(host, port=443, timeout=2.5):
    """تست اتصال TCP متناظر برای مقایسه مستقیم رفتار TCP در برابر UDP"""
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        ip = socket.gethostbyname(host)
        s.connect((ip, port))
        dt = round((time.time() - t0) * 1000, 1)
        s.close()
        return {
            "ok": True,
            "status": "TCP_CONNECTED",
            "latency_ms": dt,
            "detail": f"اتصال TCP در {dt}ms برقرار شد"
        }
    except ConnectionResetError:
        s.close()
        return {"ok": False, "status": "TCP_RST", "latency_ms": None, "detail": "دریافت TCP RST"}
    except (socket.timeout, TimeoutError):
        s.close()
        return {"ok": False, "status": "TCP_TIMEOUT", "latency_ms": None, "detail": "تایم‌اوت اتصال TCP"}
    except Exception as e:
        s.close()
        return {"ok": False, "status": "TCP_ERROR", "latency_ms": None, "detail": str(e)[:30]}

def run_quic_vs_tcp_benchmark(targets=None, timeout=2.5):
    """
    بررسی تطبیقی UDP/QUIC (HTTP/3) در مقایسه با TCP (HTTP/1.1 & HTTP/2)
    جهت تعیین اینکه آیا پروتکل مدرن HTTP/3 در شبکه مسدود است یا خیر
    """
    if targets is None:
        targets = QUIC_TEST_TARGETS

    def _probe_single_target(t):
        host = t["host"]
        port = t.get("port", 443)
        name = t["name"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as sub_exec:
            f_udp = sub_exec.submit(probe_udp_quic_single, host, port, timeout)
            f_tcp = sub_exec.submit(probe_tcp_port_single, host, port, timeout)
            udp_res = f_udp.result()
            tcp_res = f_tcp.result()
        return {
            "name": name,
            "host": host,
            "port": port,
            "udp_quic": udp_res,
            "tcp": tcp_res
        }

    results = []
    quic_working = 0
    tcp_working = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as executor:
        f_list = [executor.submit(_probe_single_target, t) for t in targets]
        for f in concurrent.futures.as_completed(f_list):
            res = f.result()
            results.append(res)
            if res["udp_quic"]["ok"]:
                quic_working += 1
            if res["tcp"]["ok"]:
                tcp_working += 1

    # تحلیل وضعیت مسدودسازی UDP
    if tcp_working > 0 and quic_working == 0:
        quic_status = "QUIC_SYSTEMATICALLY_BLOCKED"
        quic_badge = "🔴 مسدودسازی کامل پروتکل UDP / HTTP/3"
        quic_summary = "ارتباطات TCP 443 برقرار می‌شوند اما کلیه پکت‌های UDP 443 مسدود یا بلک‌هول هستند."
    elif quic_working < tcp_working:
        quic_status = "QUIC_PARTIALLY_BLOCKED"
        quic_badge = "🟡 فیلترینگ انتخابی یا اختلال شدید روی UDP/QUIC"
        quic_summary = "پروتکل UDP تنها به برخی مقاصد اجازه عبور دارد و ترافیک بین‌المللی HTTP/3 دچار اختلال است."
    else:
        quic_status = "QUIC_AVAILABLE"
        quic_badge = "🟢 پروتکل UDP و HTTP/3 در دسترس"
        quic_summary = "محدودیت ویژه‌ای روی ترافیک UDP پورت ۴۴۳ مشاهده نشد."

    return {
        "status": quic_status,
        "badge": quic_badge,
        "summary": quic_summary,
        "quic_working": quic_working,
        "tcp_working": tcp_working,
        "total_targets": len(targets),
        "results": results
    }

def analyze_target_censorship(url, timeout=3.0):
    """
    ریشه‌یابی و تفکیک لایه‌ای کامل سانسور برای یک آدرس وب
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.hostname or url
    port = parsed.port or (443 if parsed.scheme == 'https' or not parsed.scheme else 80)
    
    # مرحله ۱: بررسی وضعیت DNS
    dns_analysis = detect_dns_poisoning(domain, timeout=2)
    
    if dns_analysis["poisoned"]:
        sni_analysis = None
        detail = dns_analysis["message"]
        # اگر آی‌پی واقعی جهانی در DoH وجود دارد، لایه دوم (وضعیت SNI روی آی‌پی واقعی) را نیز می‌سنجیم
        if dns_analysis.get("doh_ips"):
            real_ip = dns_analysis["doh_ips"][0]
            sni_analysis = probe_sni_vs_ip(domain, target_ip=real_ip, port=port, timeout=timeout)
            m = sni_analysis.get("mechanism")
            if m in ["SNI_FILTERED_RST", "SNI_FILTERED_THROTTLED"]:
                detail += f" | لایه دوم: فیلترینگ SNI نیز روی آی‌پی واقعی ({real_ip}) اعمال می‌شود"
            elif m in ["IP_BLOCKED_RST", "IP_BLOCKED_TIMEOUT"]:
                detail += f" | لایه دوم: مسدودسازی مستقیم IP واقعی ({real_ip})"
            elif m == "ACCESSIBLE_TLS":
                detail += f" | نکته: تنها لایه DNS آلوده است؛ با فعال‌سازی DoH یا تغییر DNS سایت باز می‌شود"

        return {
            "url": url,
            "domain": domain,
            "primary_cause": "DNS_POISONING",
            "cause_title": "آلودگی و تزریق DNS",
            "mechanism": "DNS_POISONED",
            "detail": detail,
            "dns_info": dns_analysis,
            "sni_info": sni_analysis
        }

    # مرحله ۲: تفکیک SNI در برابر IP
    target_ip = dns_analysis["ips"][0] if dns_analysis["ips"] else None
    sni_analysis = probe_sni_vs_ip(domain, target_ip=target_ip, port=port, timeout=timeout)
    
    mechanism = sni_analysis.get("mechanism", "UNKNOWN")
    
    cause_mapping = {
        "SNI_FILTERED_RST": ("SNI_BLOCK", "فیلترینگ SNI (تزریق TCP RST)"),
        "SNI_FILTERED_THROTTLED": ("THROTTLING", "تراتلینگ و دراپ TLS ClientHello (Throttling)"),
        "IP_BLOCKED_RST": ("IP_BLOCK", "مسدودسازی IP (تزریق RST در SYN)"),
        "IP_BLOCKED_TIMEOUT": ("IP_BLOCK", "مسدودسازی IP (تایم‌اوت / بلک‌هول)"),
        "DNS_POISONING": ("DNS_POISONING", "آلودگی DNS"),
        "ACCESSIBLE_TLS": ("NONE", "بدون مسدودسازی (سالم)"),
        "TLS_HANDSHAKE_ERROR": ("TLS_ERROR", "خطای پروتکل امنیتی TLS"),
        "DNS_RESOLUTION_FAILED": ("DNS_FAIL", "عدم رزولوشن DNS")
    }
    
    cause_code, cause_title = cause_mapping.get(mechanism, ("UNKNOWN", "نامشخص"))
    
    return {
        "url": url,
        "domain": domain,
        "primary_cause": cause_code,
        "cause_title": cause_title,
        "mechanism": mechanism,
        "detail": sni_analysis.get("detail", ""),
        "dns_info": dns_analysis,
        "sni_info": sni_analysis
    }

def batch_censorship_analysis(urls, timeout=3.0, threads=15):
    """
    اجرای تحلیل ریشه‌ای فیلترینگ برای دسته‌ای از آدرس‌های اینترنتی
    و تهیه آمار سهم هر مکانیزم فیلترینگ
    """
    results = []
    breakdown = {
        "SNI_BLOCK": 0,
        "IP_BLOCK": 0,
        "DNS_POISONING": 0,
        "THROTTLING": 0,
        "TLS_ERROR": 0,
        "NONE": 0,
        "OTHER": 0
    }
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        f_map = {executor.submit(analyze_target_censorship, u, timeout): u for u in urls}
        for f in concurrent.futures.as_completed(f_map):
            res = f.result()
            results.append(res)
            c = res.get("primary_cause", "OTHER")
            if c in breakdown:
                breakdown[c] += 1
            else:
                breakdown["OTHER"] += 1
                
    return {
        "total": len(urls),
        "breakdown": breakdown,
        "results": sorted(results, key=lambda x: (x["primary_cause"] == "NONE", x["primary_cause"], x["domain"]))
    }

if __name__ == "__main__":
    print("──▶ تست تشخیص DNS Poisoning برای twitter.com و google.com:")
    print("twitter.com:", detect_dns_poisoning("twitter.com"))
    print("google.com :", detect_dns_poisoning("google.com"))
    
    print("\n──▶ تست تفکیک SNI vs IP برای twitter.com و speed.cloudflare.com:")
    print("twitter.com:", analyze_target_censorship("https://twitter.com"))
    print("cloudflare :", analyze_target_censorship("https://speed.cloudflare.com"))
    
    print("\n──▶ تست تطبیقی UDP/QUIC (HTTP/3) در مقایسه با TCP:")
    quic_res = run_quic_vs_tcp_benchmark()
    print(f"نتیجه HTTP/3: {quic_res['badge']}")
    print(f"UDP فعال: {quic_res['quic_working']}/{quic_res['total_targets']} | TCP فعال: {quic_res['tcp_working']}/{quic_res['total_targets']}")
