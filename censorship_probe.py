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
import urllib.parse
import concurrent.futures

import netutil

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
    """رزولوشن دامنه از DNS سیستم. نتیجه در طول دور کش می‌شود."""
    return netutil.resolve_a(domain, timeout=timeout)


DOH_TEMPLATES = (
    "https://8.8.8.8/resolve?name={domain}&type=A",
    "https://1.1.1.1/dns-query?name={domain}&type=A",
    "https://1.0.0.1/dns-query?name={domain}&type=A",
)


def _sticky_doh_template(timeout):
    """یک بار در هر دور اندپوینت زندهٔ DoH را انتخاب کن، نه برای هر دامنه."""
    def choose():
        def probe(template):
            url = template.format(domain="google.com")
            result = netutil.doh_lookup(url, timeout=timeout)
            return template if result.get("ips") else None

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(DOH_TEMPLATES)) as executor:
            futures = [executor.submit(probe, template) for template in DOH_TEMPLATES]
            chosen = None
            for future in concurrent.futures.as_completed(futures):
                found = future.result()
                if found and chosen is None:
                    chosen = found
            return chosen

    return netutil.cached_call("doh-sticky-template", choose)


def query_trusted_doh(domain, timeout=2.5):
    """رکورد A از DoH. اندپوینت مرده برای دامنه‌های بعدی دوباره امتحان نمی‌شود."""
    name = domain.strip(".").lower()

    def load():
        try:
            ascii_name = name.encode("idna").decode("ascii")
        except Exception:
            return []
        template = _sticky_doh_template(min(timeout, 2.0))
        if not template:
            return []
        url = template.format(domain=ascii_name)
        return netutil.doh_lookup(url, timeout=timeout).get("ips") or []

    return list(netutil.cached_call(("doh-a", name), load))

# پیشوند حداقل /۱۶. پیشوند یک‌اکتتی بخش بزرگی از اینترنت را CDN جا می‌زند.
_CDN_PREFIXES = (
    "142.250.", "142.251.", "172.217.", "172.253.", "192.178.", "216.58.", "74.125.",
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.", "104.22.",
    "104.23.", "104.24.", "104.25.", "104.26.", "104.27.", "104.28.", "104.29.",
    "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.", "172.70.", "172.71.",
    "162.159.", "188.114.",
    "151.101.", "199.232.",
)


def _is_known_cdn_ip(ip):
    return isinstance(ip, str) and ip.startswith(_CDN_PREFIXES)


def both_on_known_cdn(local_ips, doh_ips):
    """True فقط وقتی هر دو پاسخ روی پیشوند مشخص یک CDN شناخته‌شده باشند."""
    return any(_is_known_cdn_ip(ip) for ip in local_ips) and any(_is_known_cdn_ip(ip) for ip in doh_ips)


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
        # اگر هر دو در رنج مشخص CDN هستند، تفاوت ناشی از Anycast/GeoDNS است نه آلودگی.
        # پیشوندهای یک‌اکتتی (مثل 2. یا 104.) عمداً CDN حساب نمی‌شوند.
        if not both_on_known_cdn(local_ips, doh_ips):
            local_subnets = {'.'.join(ip.split('.')[:2]) for ip in local_ips if '.' in ip}
            doh_subnets = {'.'.join(ip.split('.')[:2]) for ip in doh_ips if '.' in ip}
            if not (set(local_ips) & set(doh_ips)) and not (local_subnets & doh_subnets):
                # اعتبارسنجی قطعی: تست اتصال TLS به آی‌پی محلی با نام دامنه مورد نظر
                # اگر سرور گواهی معتبر تحویل دهد، قطعا سرور واقعی و GeoDNS است نه آلودگی
                s_test = None
                s_wrap = None
                try:
                    s_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s_test.settimeout(1.5)
                    with netutil.NetworkSlot():
                        s_test.connect((local_ips[0], 443))
                        s_wrap = netutil.ssl_context().wrap_socket(s_test, server_hostname=domain)
                        cert = s_wrap.getpeercert(binary_form=True)
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
                finally:
                    netutil.close_quietly(s_wrap)
                    if s_wrap is None:
                        netutil.close_quietly(s_test)

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

    def tls_attempt(server_hostname):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        wrapped = None
        try:
            sock.settimeout(timeout)
            started = time.perf_counter()
            with netutil.NetworkSlot():
                sock.connect((target_ip, port))
                wrapped = netutil.ssl_context().wrap_socket(sock, server_hostname=server_hostname)
            return True, round((time.perf_counter() - started) * 1000, 1), None
        except ssl.SSLEOFError:
            return False, None, "TLS_SNI_RST_EOF"
        except ConnectionResetError:
            return False, None, "TLS_SNI_RST"
        except (socket.timeout, TimeoutError):
            return False, None, "TLS_SNI_TIMEOUT"
        except Exception as exc:
            return False, None, type(exc).__name__
        finally:
            netutil.close_quietly(wrapped)
            if wrapped is None:
                netutil.close_quietly(sock)

    # ۱. تست اتصال TCP. نتیجه برای آی‌پی‌های تکراری همین دور کش می‌شود.
    tcp = netutil.probe_tcp(target_ip, port, timeout)
    tcp_lat = tcp.get("latency_ms")
    if not tcp["ok"]:
        if tcp.get("error") == "reset":
            return {
                "mechanism": "IP_BLOCKED_RST",
                "tcp_ok": False,
                "tls_sni_ok": False,
                "target_ip": target_ip,
                "detail": f"مسدودسازی در لایه TCP با ارسال بلافاصله TCP RST به {target_ip}:{port}"
            }
        return {
            "mechanism": "IP_BLOCKED_TIMEOUT",
            "tcp_ok": False,
            "tls_sni_ok": False,
            "target_ip": target_ip,
            "detail": f"دراپ خاموش / بلک‌هول پکت‌های TCP SYN به {target_ip}:{port} (تایم‌اوت)"
        }

    # ۲. تست هندشیک TLS با ارسال SNI
    tls_sni_ok, tls_sni_lat, tls_sni_error = tls_attempt(domain)

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

    # ۳. هندشیک با SNI شکست خورده است. تست بدون SNI نشان می‌دهد فیلتر روی نام دامنه است یا نه.
    tls_nosni_ok, _, _tls_nosni_error = tls_attempt(None)

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
    """پکت QUIC Initial با طول ۱۲۰۰ بایت (RFC 9000)."""
    return netutil.quic_initial_packet()

def probe_udp_quic_single(host, port=443, timeout=2.5):
    """UDP/QUIC روی پورت داده‌شده. نتیجه با بنچمارک پروتکل‌های UDP مشترک است."""
    result = netutil.probe_udp_quic(host, port, timeout)
    if result["error"] is None and result["ok"]:
        return {
            "ok": True,
            "status": "UDP_REACHABLE",
            "latency_ms": result["latency_ms"],
            "bytes_received": result["bytes_received"],
            "detail": f"پاسخ استاندارد UDP/QUIC دریافت شد ({result['bytes_received']} بایت, {result['latency_ms']}ms)"
        }
    if result["error"] == "timeout":
        return {
            "ok": False,
            "status": "UDP_TIMEOUT_BLOCKED",
            "latency_ms": None,
            "detail": "تایم‌اوت UDP (مسدودسازی ترافیک UDP پورت ۴۴۳ / QUIC توسط فایروال)"
        }
    if result["error"] == "refused":
        return {
            "ok": False,
            "status": "UDP_PORT_UNREACHABLE",
            "latency_ms": None,
            "detail": "دریافت خطای ICMP Port Unreachable (پورت پکت را نمی‌پذیرد)"
        }
    return {
        "ok": False,
        "status": "UDP_ERROR",
        "latency_ms": None,
        "detail": f"خطا در ارسال UDP ({result['error']})"
    }

def probe_tcp_port_single(host, port=443, timeout=2.5):
    """تست اتصال TCP متناظر برای مقایسه مستقیم رفتار TCP در برابر UDP"""
    result = netutil.probe_tcp(host, port, timeout)
    if result["ok"]:
        return {
            "ok": True,
            "status": "TCP_CONNECTED",
            "latency_ms": result["latency_ms"],
            "detail": f"اتصال TCP در {result['latency_ms']}ms برقرار شد"
        }
    if result["error"] == "reset":
        return {"ok": False, "status": "TCP_RST", "latency_ms": None, "detail": "دریافت TCP RST"}
    if result["error"] == "timeout":
        return {"ok": False, "status": "TCP_TIMEOUT", "latency_ms": None, "detail": "تایم‌اوت اتصال TCP"}
    return {"ok": False, "status": "TCP_ERROR", "latency_ms": None, "detail": str(result["error"])[:30]}

def run_quic_vs_tcp_benchmark(targets=None, timeout=2.5):
    """
    بررسی تطبیقی UDP/QUIC (HTTP/3) در مقایسه با TCP (HTTP/1.1 & HTTP/2)
    جهت تعیین اینکه آیا پروتکل مدرن HTTP/3 در شبکه مسدود است یا خیر
    """
    if targets is None:
        targets = QUIC_TEST_TARGETS

    results = []
    quic_working = 0
    tcp_working = 0
    workers = max(1, len(targets) * 2)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        jobs = []
        for target in targets:
            host = target["host"]
            port = target.get("port", 443)
            jobs.append((
                target,
                executor.submit(probe_udp_quic_single, host, port, timeout),
                executor.submit(probe_tcp_port_single, host, port, timeout),
            ))
        for target, fut_udp, fut_tcp in jobs:
            res = {
                "name": target["name"],
                "host": target["host"],
                "port": target.get("port", 443),
                "udp_quic": fut_udp.result(),
                "tcp": fut_tcp.result(),
            }
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
