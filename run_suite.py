#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اجرای جامع و یکپارچه پایش وضعیت اینترنت، فیلترینگ و کیفیت شبکه
۱. تفکیک هویت شبکه و شاخص اینترنت ملی (Network Identity & Intranet Index)
۲. دسترسی و فیلترینگ وب‌سایت‌ها و دسته‌بندی‌ها (Web Accessibility)
۳. ریشه‌یابی تکنیکال سانسور (Censorship Root-Cause: DNS / SNI / IP / QUIC)
۴. سنجش کیفیت، پایداری و افت خط (QoS: Ping, Jitter, Packet Loss, Speed Throttling, Traceroute)
۵. پایش پروتکل‌های نوین دور زدن فیلترینگ و آی‌پی‌های تمیز کلودفلر (Circumvention & Clean IPs)
۶. پاسخ‌دهی سرورهای DNS داخلی و APIهای ابزارهای ضد فیلتر
۷. تولید خودکار گزارش‌های JSON، Markdown و داشبورد تعاملی HTML (dashboard.html)
۸. پشتیبانی از پایش پیوسته با آرگومان --watch
"""

import os
import sys
import time
import json
import socket
import ssl
import subprocess
import argparse
import concurrent.futures
from datetime import datetime

# ۱. ایمپورت ماژول‌های پروژه
try:
    from filtercheck import CATEGORIZED_SITES, SITES_TO_CHECK, URL_TO_CATEGORY, check_site, create_ssl_context
except ImportError:
    print("[!] ماژول filtercheck.py یافت نشد.")
    sys.exit(1)

try:
    from check import VPN_TARGETS, test_vpn_endpoint
except ImportError:
    print("[!] ماژول check.py یافت نشد.")
    sys.exit(1)

try:
    from network_identity import get_network_identity, check_intranet_index
except ImportError:
    print("[!] ماژول network_identity.py یافت نشد.")
    sys.exit(1)

try:
    from censorship_probe import batch_censorship_analysis, run_quic_vs_tcp_benchmark
except ImportError:
    print("[!] ماژول censorship_probe.py یافت نشد.")
    sys.exit(1)

try:
    from qos_metrics import run_qos_benchmark
except ImportError:
    print("[!] ماژول qos_metrics.py یافت نشد.")
    sys.exit(1)

try:
    from circumvention_benchmark import run_circumvention_benchmark
except ImportError:
    print("[!] ماژول circumvention_benchmark.py یافت نشد.")
    sys.exit(1)

try:
    from dashboard_generator import generate_html_dashboard
except ImportError:
    print("[!] ماژول dashboard_generator.py یافت نشد.")
    sys.exit(1)

# لیست DNSهای داخلی
DNS_SERVERS = [
    '185.161.112.33', '185.161.112.34', '185.51.200.10', '185.231.182.126',
    '46.224.1.42', '194.225.62.80', '213.176.123.5', '91.99.101.12',
    '185.187.84.15', '37.156.145.229', '185.97.117.187', '185.113.59.253',
    '80.191.40.41', '194.225.73.141', '91.245.229.1', '185.51.200.50',
    '37.156.145.21', '217.218.155.155', '2.189.44.44', '2.188.21.131',
    '2.188.21.132', '81.91.144.116', '2.188.21.130', '92.119.56.162',
    '194.225.152.12'
]

DNS_TEST_DOMAINS = ['sotoon.ir', 'google.com', 'github.com']

# کدهای رنگ ANSI
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

def check_single_dns(dns_ip, domains=DNS_TEST_DOMAINS, timeout=2):
    resolved = {}
    all_ok = True
    for dom in domains:
        try:
            res = subprocess.run(
                ['dig', '+time=1', '+tries=1', '+short', dom, f'@{dns_ip}'],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = res.stdout.strip()
            if res.returncode == 0 and output:
                resolved[dom] = output.split('\n')[0]
            else:
                resolved[dom] = None
                all_ok = False
        except Exception:
            resolved[dom] = None
            all_ok = False
            
    return {
        "ip": dns_ip,
        "ok": all_ok,
        "resolved": resolved
    }

def run_dns_checks(threads=15):
    start = time.time()
    results = []
    working_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_single_dns, dns): dns for dns in DNS_SERVERS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            results.append(res)
            if res["ok"]:
                working_count += 1
                
    elapsed = round(time.time() - start, 2)
    return {
        "total": len(DNS_SERVERS),
        "working": working_count,
        "elapsed_seconds": elapsed,
        "results": sorted(results, key=lambda x: (not x["ok"], x["ip"]))
    }

def run_vpn_checks(timeout=3, threads=15):
    start = time.time()
    results = []
    working_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(test_vpn_endpoint, t['name'], t['url'], timeout): t
            for t in VPN_TARGETS
        }
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                success, latency, extra = future.result()
                results.append({
                    "name": target["name"],
                    "url": target["url"],
                    "ok": success,
                    "latency": round(latency, 1) if latency else None,
                    "info": extra
                })
                if success:
                    working_count += 1
            except Exception as e:
                results.append({
                    "name": target["name"],
                    "url": target["url"],
                    "ok": False,
                    "latency": None,
                    "info": str(e)
                })
                
    elapsed = round(time.time() - start, 2)
    return {
        "total": len(VPN_TARGETS),
        "working": working_count,
        "elapsed_seconds": elapsed,
        "results": sorted(results, key=lambda x: (not x["ok"], x.get("latency") or 9999, x["name"]))
    }

def run_web_checks(threads=30, timeout=3.5):
    start = time.time()
    results = []
    accessible_count = 0
    latencies = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_site, url, timeout): url for url in SITES_TO_CHECK}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            res["category"] = URL_TO_CATEGORY.get(res["url"], "متفرقه")
            results.append(res)
            if res.get("ok"):
                accessible_count += 1
                if res.get("latency"):
                    latencies.append(res["latency"])
                    
    elapsed = round(time.time() - start, 2)
    avg_lat = round(sum(latencies) / len(latencies), 1) if latencies else None
    
    cat_summary = {}
    for cat_name, cat_urls in CATEGORIZED_SITES.items():
        cat_results = [r for r in results if r["url"] in cat_urls]
        c_acc = sum(1 for r in cat_results if r.get("ok"))
        c_tot = len(cat_results)
        c_pct = round((c_acc / c_tot) * 100, 1) if c_tot else 0
        c_lats = [r["latency"] for r in cat_results if r.get("latency")]
        c_avg_lat = round(sum(c_lats) / len(c_lats), 1) if c_lats else None
        cat_summary[cat_name] = {
            "total": c_tot,
            "accessible": c_acc,
            "blocked": c_tot - c_acc,
            "percent": c_pct,
            "avg_latency": c_avg_lat
        }
        
    return {
        "total": len(SITES_TO_CHECK),
        "accessible": accessible_count,
        "blocked": len(SITES_TO_CHECK) - accessible_count,
        "accessible_percent": round((accessible_count / len(SITES_TO_CHECK)) * 100, 1),
        "avg_latency_ms": avg_lat,
        "elapsed_seconds": elapsed,
        "categories": cat_summary,
        "results": sorted(results, key=lambda x: (not x.get("ok"), x.get("category", ""), x["url"]))
    }

def calculate_holistic_health_score(web_data, dns_data, vpn_data, intranet_data, qos_data, circ_data):
    """
    محاسبه نمره سلامت کلنگار اینترنت بین ۰ تا ۱۰۰ با در نظر گرفتن:
    - دسترسی وب (وزن ۳۵٪)
    - پروتکل‌های ضد فیلتر و آی‌پی‌های تمیز (وزن ۲۵٪)
    - پاسخ‌دهی سرورهای DNS (وزن ۱۵٪)
    - کیفیت خط، پکت‌لاس و جیتر (وزن ۱۵٪)
    - شاخص عدم قرنطینه در اینترنت ملی (وزن ۱۰٪)
    """
    web_score = web_data.get("accessible_percent", 0)
    dns_score = (dns_data["working"] / dns_data["total"]) * 100 if dns_data.get("total") else 0
    
    circ_summary = circ_data.get("summary", {})
    circ_score = circ_summary.get("clean_ips_percent", 50) * 0.5 + circ_summary.get("protocols_percent", 50) * 0.5
    
    # ارزیابی کیفیت خط: کسر امتیاز به نسبت پکت‌لاس و جیتر
    intl_stability = qos_data.get("stability", {}).get("international", {})
    loss = intl_stability.get("avg_packet_loss_pct", 0) or 0
    jitter = intl_stability.get("avg_jitter_ms", 50) or 50
    qos_score = max(0, min(100, 100 - (loss * 2.0) - (max(0, jitter - 30) * 0.3)))
    
    # شاخص اینترنت ملی: در حالت قفل کامل اینترنت ملی نمره باید به صفر نزدیک شود
    intra_mode = intranet_data.get("mode", "NORMAL")
    if intra_mode == "INTRANET_LOCKDOWN":
        intranet_score = 0
    elif intra_mode == "HEAVY_CENSORSHIP":
        intranet_score = 40
    elif intra_mode == "MODERATE_CENSORSHIP":
        intranet_score = 75
    else:
        intranet_score = 100
        
    overall = round(
        (web_score * 0.35) + 
        (circ_score * 0.25) + 
        (dns_score * 0.15) + 
        (qos_score * 0.15) + 
        (intranet_score * 0.10),
        1
    )
    
    if intra_mode == "INTRANET_LOCKDOWN":
        badge = "🔴 وضعیت اضطراری اینترنت ملی (National Intranet Lockdown)"
    elif overall >= 80:
        badge = "🟢 اینترنت عادی و پایدار / بدون اختلال عمده"
    elif 50 <= overall < 80:
        badge = "🟡 فیلترینگ گسترده و اختلالات پروتکلی / تراتلینگ فعال"
    else:
        badge = "🔴 اختلال بسیار شدید، کندی حاد و مسدودسازی سراسری"

    return {
        "score": overall,
        "badge": badge,
        "web_score": web_score,
        "circ_score": round(circ_score, 1),
        "dns_score": round(dns_score, 1),
        "qos_score": round(qos_score, 1),
        "intranet_score": intranet_score
    }

def generate_unified_markdown(data):
    h = data["health"]
    net = data.get("network_identity", {})
    intra = data.get("intranet_index", {})
    w = data["web"]
    d = data["dns"]
    v = data["vpn"]
    qos = data.get("qos", {})
    stab = qos.get("stability", {})
    thrott = qos.get("throttling", {})
    trace = qos.get("traceroute", {})
    censor = data.get("censorship_analysis", {})
    circ = data.get("circumvention", {})
    circ_sum = circ.get("summary", {})
    
    md = [
        f"# 📡 گزارش جامع پایش وضعیت اینترنت ({data['timestamp']})",
        "",
        f"### شاخص کل سلامت اینترنت: **{h['score']}/100** — {h['badge']}",
        "",
        "> [!NOTE]",
        f"> **اپراتور (ISP):** `{net.get('isp', 'نامشخص')}` | **ASN:** `{net.get('asn', '-')}` | **آی‌پی:** `{net.get('ip', '-')}` | **مکان:** `{net.get('city', '')}, {net.get('country', '')}`",
        f"> **شاخص اینترنت ملی:** نسبت دسترسی `{intra.get('ratio', 1.0)}x` ({intra.get('badge', '-')})",
        "",
        "---",
        "",
        "## 📊 ۱. کارت‌های شاخص عملکرد و کیفیت",
        "| شاخص ارزیابی شده | درصد / مقدار | وضعیت سنجش | جزئیات تکمیلی |",
        "| :--- | :---: | :---: | :--- |",
        f"| **دسترسی به وب‌سایت‌های خارجی** | `{w['accessible_percent']}%` | {w['accessible']}/{w['total']} سایت | میانگین تاخیر: {w.get('avg_latency_ms', '-')}ms |",
        f"| **آی‌پی‌های تمیز کلودفلر (Port 443)** | `{circ_sum.get('clean_ips_percent', 0)}%` | {circ_sum.get('clean_ips_working', 0)}/{circ_sum.get('clean_ips_total', 0)} آی‌پی | سریع‌ترین: {', '.join(circ.get('clean_ips', {}).get('top_clean_ips', [])[:3])} |",
        f"| **پروتکل‌های مدرن ضد فیلتر** | `{circ_sum.get('protocols_percent', 0)}%` | {circ_sum.get('protocols_working', 0)}/{circ_sum.get('protocols_total', 0)} پروتکل | وضعیت Reality و V2Ray |",
        f"| **دی‌ان‌اس امن (DoH / DoT)** | `DoH: {circ_sum.get('doh_working', 0)}/4` | `DoT: {circ_sum.get('dot_working', 0)}/4` | پورت ۸۵۳ و استعلام رمزنگاری‌شده |",
        f"| **پایداری خط، پکت‌لاس و جیتر** | `{stab.get('international', {}).get('avg_jitter_ms', 0)}ms Jitter` | پکت‌لاس: {stab.get('international', {}).get('avg_packet_loss_pct', 0)}% | {stab.get('stability_badge', '-')} |",
        f"| **پهنای باند و تراتلینگ CDN** | `{thrott.get('international_avg_mbps', 0)} Mbps` | داخلی: {thrott.get('domestic_avg_mbps', 0)} Mbps | {thrott.get('badge', '-')} |",
        f"| **مسیر Traceroute به گیت‌وی** | `{trace.get('total_hops_inspected', 0)} هاپ` | {trace.get('status_badge', '-')} | {trace.get('diagnosis', '-')} |",
        "",
        "---",
        "",
        "## 🛡️ ۲. ریشه‌یابی علل فیلترینگ (Censorship Root-Cause Breakdown)",
        "| نوع مکانیزم فیلترینگ | تعداد موارد شناسایی شده | سهم از کل | رفتار مشاهده شده |",
        "| :--- | :---: | :---: | :--- |"
    ]
    
    bd = censor.get("breakdown", {})
    tot_c = censor.get("total", 1) or 1
    md.extend([
        f"| **فیلترینگ هوشمند SNI** | `{bd.get('SNI_BLOCK', 0)}` | {round((bd.get('SNI_BLOCK', 0)/tot_c)*100, 1)}% | تزریق TCP RST هنگام ارسال نام دامنه در ClientHello |",
        f"| **تراتلینگ و دراپ کلاینت‌هلو** | `{bd.get('THROTTLING', 0)}` | {round((bd.get('THROTTLING', 0)/tot_c)*100, 1)}% | دراپ پکت، تایم‌اوت یا تراتلینگ عمدی ارتباط TLS |",
        f"| **مسدودسازی مستقیم IP** | `{bd.get('IP_BLOCK', 0)}` | {round((bd.get('IP_BLOCK', 0)/tot_c)*100, 1)}% | قطع اتصال در لایه TCP SYN قبل از ارسال نام دامنه |",
        f"| **آلودگی و تزریق DNS** | `{bd.get('DNS_POISONING', 0)}` | {round((bd.get('DNS_POISONING', 0)/tot_c)*100, 1)}% | هدایت به رنج‌های لوکال/پیوندها یا تزریق NXDOMAIN جعلی |",
        f"| **سالم و بدون فیلتر** | `{bd.get('NONE', 0)}` | {round((bd.get('NONE', 0)/tot_c)*100, 1)}% | برقراری کامل هندشیک TLS |",
        "",
        "---",
        "",
        "## 🌐 ۳. وضعیت دسترسی به تفکیک دسته‌بندی‌ها",
        "| دسته‌بندی | در دسترس | کل | درصد دسترسی | میانگین تاخیر (ms) |",
        "| :--- | :---: | :---: | :---: | :---: |"
    ])
    
    for cat_name, cs in w["categories"].items():
        avg_l = f"{cs['avg_latency']} ms" if cs['avg_latency'] else "-"
        md.append(f"| {cat_name} | {cs['accessible']} | {cs['total']} | {cs['percent']}% | {avg_l} |")
        
    md.extend([
        "",
        "---",
        "",
        "## ❌ ۴. نمونه سایت‌های مسدود شده یا دارای اختلال شدید",
        "| آدرس وب‌سایت | دسته‌بندی | وضعیت مشاهده شده |",
        "| :--- | :--- | :--- |"
    ])
    
    blocked = [r for r in w["results"] if not r.get("ok")]
    for item in blocked[:20]:
        md.append(f"| `{item['url']}` | {item.get('category', '-')} | {item['status']} |")
        
    md.append("")
    return "\n".join(md)

def run_suite_step(output_dir="reports", threads=25, timeout=3.5):
    """
    اجرای یک دور کامل پایش همه‌جانبه وضعیت اینترنت
    """
    now = datetime.now()
    t_readable = now.strftime("%Y-%m-%d %H:%M:%S")
    t_id = now.strftime("%Y%m%d_%H%M%S")
    total_start = time.time()
    
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}   🚀 شروع پایش همه‌جانبه وضعیت اینترنت، فیلترینگ و کیفیت شبکه  {RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"زمان اجرا: {t_readable}\n")
    
    # فاز ۱: هویت شبکه و شاخص اینترنت ملی
    print(f"{BOLD}{CYAN}──▶ فاز ۱: شناسایی هویت شبکه و سنجش شاخص اینترنت ملی...{RESET}")
    net_id = get_network_identity(timeout=3)
    print(f"    اپراتور: {BOLD}{net_id['isp']}{RESET} | ASN: {net_id['asn']} | IP: {net_id['ip']} | موقعیت: {net_id['city']}, {net_id['country']}")
    intranet_idx = check_intranet_index(timeout=3, threads=12)
    print(f"    وضعیت شبکه ملی: {intranet_idx['badge']} (نسبت: {intranet_idx['ratio']}x)")
    
    # فاز ۲: دسترسی وب‌سایت‌ها
    print(f"\n{BOLD}{CYAN}──▶ فاز ۲: پایش دسترسی به {len(SITES_TO_CHECK)} سایت و سرویس کلیدی...{RESET}")
    web_res = run_web_checks(threads=threads, timeout=timeout)
    print(f"    سایت‌های در دسترس: {GREEN}{web_res['accessible']}/{web_res['total']}{RESET} ({web_res['accessible_percent']}%) | میانگین تاخیر: {web_res['avg_latency_ms']}ms")
    
    # فاز ۳: ریشه‌یابی تکنیکال فیلترینگ
    print(f"\n{BOLD}{CYAN}──▶ فاز ۳: ریشه‌یابی لایه‌ای فیلترینگ (SNI vs IP vs DNS vs QUIC)...{RESET}")
    # انتخاب نمونه سایت‌های مسدود شده برای ریشه‌یابی دقیق
    blocked_urls = [r["url"] for r in web_res["results"] if not r.get("ok")]
    target_urls_to_probe = blocked_urls[:20] if blocked_urls else SITES_TO_CHECK[:15]
    censor_analysis = batch_censorship_analysis(target_urls_to_probe, timeout=2.5, threads=12)
    bd = censor_analysis["breakdown"]
    print(f"    تفکیک سانسور: فیلترینگ SNI: {RED}{bd['SNI_BLOCK']}{RESET} | تراتلینگ: {YELLOW}{bd.get('THROTTLING', 0)}{RESET} | مسدودسازی IP: {YELLOW}{bd['IP_BLOCK']}{RESET} | آلودگی DNS: {BLUE}{bd['DNS_POISONING']}{RESET}")
    quic_res = run_quic_vs_tcp_benchmark(timeout=2.0)
    print(f"    وضعیت پروتکل UDP/QUIC (HTTP/3): {quic_res['badge']}")
    
    # فاز ۴: سنجش کیفیت، پایداری و افت خط
    print(f"\n{BOLD}{CYAN}──▶ فاز ۴: سنجش کیفیت خط (Ping, Jitter, Packet Loss, Speed & Traceroute)...{RESET}")
    qos_res = run_qos_benchmark(ping_count=3, speed_timeout=5.0)
    stab = qos_res["stability"]
    thrott = qos_res["throttling"]
    trace = qos_res["traceroute"]
    print(f"    پایداری خط: {stab['stability_badge']}")
    print(f"    پکت‌لاس بین‌الملل: {stab['international']['avg_packet_loss_pct']}% | جیتر بین‌الملل: {stab['international']['avg_jitter_ms']}ms")
    print(f"    پهنای باند خارجی: {thrott['international_avg_mbps']} Mbps | داخلی: {thrott['domestic_avg_mbps']} Mbps | {thrott['badge']}")
    print(f"    مسیر Traceroute: {trace.get('status_badge', 'نامشخص')} ({trace.get('total_hops_inspected', 0)} هاپ)")
    
    # فاز ۵: بنچمارک پروتکل‌های نوین ضد فیلتر و آی‌پی‌های تمیز
    print(f"\n{BOLD}{CYAN}──▶ فاز ۵: بررسی پروتکل‌های ضد فیلتر (Reality / V2Ray / Hysteria / Clean IPs)...{RESET}")
    circ_res = run_circumvention_benchmark(timeout=2.5, threads=12)
    c_sum = circ_res["summary"]
    print(f"    پروتکل‌های مدرن فعال: {GREEN}{c_sum['protocols_working']}/{c_sum['protocols_total']}{RESET} ({c_sum['protocols_percent']}%)")
    print(f"    دی‌ان‌اس امن: DoH ({c_sum['doh_working']}/4) | DoT پورت ۸۵۳ ({c_sum['dot_working']}/4)")
    print(f"    آی‌پی‌های تمیز کلودفلر: {GREEN}{c_sum['clean_ips_working']}/{c_sum['clean_ips_total']}{RESET} ({c_sum['clean_ips_percent']}%)")
    
    # فاز ۶: دی‌ان‌اس‌های داخلی و APIهای VPN
    print(f"\n{BOLD}{CYAN}──▶ فاز ۶: بررسی سرورهای DNS داخلی و APIهای ضد فیلتر...{RESET}")
    dns_res = run_dns_checks(threads=15)
    vpn_res = run_vpn_checks(timeout=3, threads=15)
    print(f"    سرورهای DNS سالم: {dns_res['working']}/{dns_res['total']} | سرویس‌های VPN باز: {vpn_res['working']}/{vpn_res['total']}")
    
    total_elapsed = round(time.time() - total_start, 2)
    
    # محاسبه نمره جامع سلامت
    health = calculate_holistic_health_score(web_res, dns_res, vpn_res, intranet_idx, qos_res, circ_res)
    
    report_data = {
        "timestamp": t_readable,
        "timestamp_id": t_id,
        "total_elapsed_seconds": total_elapsed,
        "health": health,
        "network_identity": net_id,
        "intranet_index": intranet_idx,
        "web": web_res,
        "dns": dns_res,
        "vpn": vpn_res,
        "qos": qos_res,
        "circumvention": circ_res,
        "censorship_analysis": censor_analysis,
        "quic_benchmark": quic_res,
        "categories": web_res["categories"],
        "results": web_res["results"],
        "summary": {
            "total": web_res["total"],
            "accessible": web_res["accessible"],
            "blocked": web_res["blocked"],
            "accessible_percent": web_res["accessible_percent"],
            "avg_latency_ms": web_res["avg_latency_ms"],
            "isp": net_id["isp"],
            "asn": net_id["asn"],
            "ip": net_id["ip"]
        }
    }
    
    # ذخیره فایل‌ها در پوشه reports
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, f"report_{t_id}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
        
    latest_json = os.path.join(output_dir, "latest.json")
    with open(latest_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
        
    md_content = generate_unified_markdown(report_data)
    md_path = os.path.join(output_dir, f"report_{t_id}.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    latest_md = os.path.join(output_dir, "latest.md")
    with open(latest_md, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    # تولید داشبورد تعاملی HTML
    dashboard_path = os.path.join(output_dir, "dashboard.html")
    generate_html_dashboard(report_data, dashboard_path)
    # همچنین ذخیره یک نسخه با تایم‌استمپ برای آرشیو
    hist_dash = os.path.join(output_dir, f"dashboard_{t_id}.html")
    generate_html_dashboard(report_data, hist_dash)
    
    print(f"\n{BOLD}{GREEN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{GREEN}                 خلاصه وضعیت نهایی و سلامت اینترنت            {RESET}")
    print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"اپراتور و موقعیت:     {net_id['isp']} ({net_id['asn']}) | {net_id['city']}, {net_id['country']}")
    print(f"نمره سلامت اینترنت:   {BOLD}{health['score']}/100{RESET} ({health['badge']})")
    print(f"شاخص اینترنت ملی:     {intranet_idx['ratio']}x ({intranet_idx['badge']})")
    print(f"دسترسی وب‌سایت‌ها:      {web_res['accessible']}/{web_res['total']} ({web_res['accessible_percent']}%) | میانگین تاخیر: {web_res['avg_latency_ms']}ms")
    print(f"کیفیت و تراتلینگ:     جیتر: {stab['international']['avg_jitter_ms']}ms | پکت‌لاس: {stab['international']['avg_packet_loss_pct']}% | سرعت خارجی: {thrott['international_avg_mbps']} Mbps")
    print(f"آی‌پی‌های تمیز کلودفلر: {c_sum['clean_ips_working']}/{c_sum['clean_ips_total']} ({c_sum['clean_ips_percent']}%) | پروتکل‌های نوین: {c_sum['protocols_working']}/{c_sum['protocols_total']}")
    print(f"زمان کل پایش:         {total_elapsed} ثانیه")
    print(f"\n[💾] گزارش‌ها و داشبورد ذخیره شدند:")
    print(f"  • داشبورد تعاملی HTML: {BOLD}{dashboard_path}{RESET}")
    print(f"  • گزارش JSON:          {latest_json}")
    print(f"  • گزارش Markdown:      {latest_md}")
    print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════════{RESET}\n")
    
    return report_data

def main():
    parser = argparse.ArgumentParser(description="اجرای یکپارچه و جامع پایش اینترنت و تولید داشبورد بصری")
    parser.add_argument("--output-dir", default="reports", help="مسیر ذخیره گزارش‌ها")
    parser.add_argument("--threads", type=int, default=25, help="تعداد تردها")
    parser.add_argument("--timeout", type=float, default=3.5, help="تایم‌اوت هر تست")
    parser.add_argument("--compare", action="store_true", help="مقایسه خودکار با گزارش قبلی پس از اتمام")
    parser.add_argument("--watch", type=int, default=None, help="پایش پیوسته با فاصله زمانی مشخص به ثانیه (حالت Daemon/Watch)")
    args = parser.parse_args()

    # حالت ۱: پایش پیوسته مداوم (--watch)
    if args.watch is not None:
        interval = max(5, args.watch)
        print(f"\n[🔄] حالت پایش مداوم (Watch Mode) فعال شد. فاصله هر دور: {interval} ثانیه")
        print(f"[i] برای توقف برنامه کلیدهای Ctrl+C را فشار دهید.")
        
        prev_report = None
        # بارگذاری آخرین گزارش برای مقایسه اولیه در صورت وجود
        latest_file = os.path.join(args.output_dir, "latest.json")
        if os.path.exists(latest_file):
            try:
                with open(latest_file, "r", encoding="utf-8") as f:
                    prev_report = json.load(f)
            except Exception:
                prev_report = None
                
        iter_count = 0
        try:
            while True:
                iter_count += 1
                print(f"\n{BOLD}{YELLOW}══════════════════════════════════════════════════════════════{RESET}")
                print(f"{BOLD}{YELLOW}          دور پایش #{iter_count} — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}          {RESET}")
                print(f"{BOLD}{YELLOW}══════════════════════════════════════════════════════════════{RESET}")
                
                curr_report = run_suite_step(output_dir=args.output_dir, threads=args.threads, timeout=args.timeout)
                
                if prev_report:
                    try:
                        from compare_reports import compare_reports, print_comparison
                        diff = compare_reports(prev_report, curr_report)
                        print_comparison(diff)
                    except Exception as e:
                        print(f"[!] خطا در مقایسه گزارش‌ها: {e}")
                        
                prev_report = curr_report
                print(f"[⏳] در حال استراحت به مدت {interval} ثانیه تا آغاز دور بعدی پایش...")
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n[🛑] پایش مداوم توسط کاربر متوقف شد.")
            sys.exit(0)
            
    # حالت ۲: اجرای تکی عادی
    else:
        # بارگذاری گزارش قبلی در صورت نیاز به مقایسه
        prev_report = None
        if args.compare:
            latest_file = os.path.join(args.output_dir, "latest.json")
            if os.path.exists(latest_file):
                try:
                    with open(latest_file, "r", encoding="utf-8") as f:
                        prev_report = json.load(f)
                except Exception:
                    prev_report = None
                    
        curr_report = run_suite_step(output_dir=args.output_dir, threads=args.threads, timeout=args.timeout)
        
        if args.compare and prev_report:
            try:
                from compare_reports import compare_reports, print_comparison
                diff = compare_reports(prev_report, curr_report)
                print_comparison(diff)
            except Exception as e:
                print(f"[!] خطا در اجرای مقایسه: {e}")

if __name__ == "__main__":
    main()
