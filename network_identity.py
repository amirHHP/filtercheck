#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول تفکیک هویت شبکه و شاخص اینترنت ملی (Network Identity & Intranet Index)
- شناسایی خودکار IP عمومی، نام اپراتور (ISP)، ASN، شهر و کشور
- ارزیابی شاخص دسترسی شبکه ملی در مقایسه با اینترنت بین‌الملل (Intranet vs Internet Ratio)
- تشخیص وضعیت اینترنت ملی (National Intranet Lockdown Mode)
"""

import time
import json
import urllib.request
import concurrent.futures

import netutil

# لیست سرویس‌های مرجع داخلی برای سنجش پایداری شبکه ملی
DOMESTIC_BENCHMARK_SERVICES = [
    {"name": "دیجی‌کالا (Digikala)", "url": "https://www.digikala.com"},
    {"name": "آپارات (Aparat)", "url": "https://www.aparat.com"},
    {"name": "شیپور (Sheypoor)", "url": "https://www.sheypoor.com"},
    {"name": "دیوار (Divar)", "url": "https://divar.ir"},
    {"name": "کافه بازار (CafeBazaar)", "url": "https://cafebazaar.ir"},
    {"name": "ترب (Torob)", "url": "https://torob.com"},
    {"name": "ورزش سه (Varzesh3)", "url": "https://www.varzesh3.com"},
    {"name": "عصر ایران (AsrIran)", "url": "https://www.asriran.com"},
    {"name": "باما (Bama)", "url": "https://bama.ir"},
    {"name": "بانک ملی ایران", "url": "https://bmi.ir"},
    {"name": "بانک ملت", "url": "https://bankmellat.ir"},
    {"name": "بانک تجارت", "url": "https://tejaratbank.ir"},
    {"name": "ابر ستون (Sotoon)", "url": "https://sotoon.ir"},
    {"name": "ابر آروان (ArvanCloud)", "url": "https://arvancloud.ir"},
    {"name": "آسیاتک (Asiatech)", "url": "https://asiatech.ir"},
    {"name": "شاتل (Shatel)", "url": "https://shatel.ir"},
    {"name": "همراه اول (MCI)", "url": "https://mci.ir"},
    {"name": "ایرانسل (Irancell)", "url": "https://irancell.ir"},
    {"name": "پیام‌رسان بله (Bale)", "url": "https://bale.ai"},
    {"name": "روبیکا (Rubika)", "url": "https://rubika.ir"}
]

# لیست سرویس‌های مرجع بین‌المللی برای محاسبه نسبت اینترنت ملی به بین‌الملل
INTERNATIONAL_BENCHMARK_SERVICES = [
    {"name": "Google", "url": "https://www.google.com"},
    {"name": "Wikipedia", "url": "https://www.wikipedia.org"},
    {"name": "GitHub", "url": "https://github.com"},
    {"name": "Microsoft", "url": "https://www.microsoft.com"},
    {"name": "Apple", "url": "https://www.apple.com"},
    {"name": "Cloudflare", "url": "https://www.cloudflare.com"},
    {"name": "Amazon", "url": "https://www.amazon.com"},
    {"name": "StackOverflow", "url": "https://stackoverflow.com"},
    {"name": "Python.org", "url": "https://www.python.org"},
    {"name": "Ubuntu", "url": "https://www.ubuntu.com"},
    {"name": "X / Twitter", "url": "https://x.com"},
    {"name": "YouTube", "url": "https://www.youtube.com"},
    {"name": "Instagram", "url": "https://www.instagram.com"},
    {"name": "Telegram", "url": "https://telegram.org"},
    {"name": "WhatsApp", "url": "https://www.whatsapp.com"},
    {"name": "Reddit", "url": "https://www.reddit.com"},
    {"name": "OpenAI / ChatGPT", "url": "https://chatgpt.com"},
    {"name": "Anthropic / Claude", "url": "https://claude.ai"},
    {"name": "BBC", "url": "https://www.bbc.com"},
    {"name": "Spotify", "url": "https://www.spotify.com"}
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

def identify_iranian_isp(raw_isp, raw_org, raw_as):
    """تشخیص و استانداردسازی نام اپراتور ایرانی بر اساس نام و AS Number"""
    text = f"{raw_isp} {raw_org} {raw_as}".lower()
    
    if "mci" in text or "mobile telecommunication company of iran" in text or "as197207" in text:
        return "همراه اول (MCI)", "AS197207"
    if "mtn" in text or "irancell" in text or "as44244" in text:
        return "ایرانسل (MTN Irancell)", "AS44244"
    if "shatel" in text or "as31549" in text:
        return "شاتل (Shatel)", "AS31549"
    if "tci" in text or "telecommunication company of iran" in text or "mokhaberat" in text or "as58224" in text:
        return "مخابرات ایران (TCI)", "AS58224"
    if "sotoon" in text or "as208004" in text:
        return "ابر ستون (Sotoon)", "AS208004"
    if "afranet" in text or "as25184" in text:
        return "افرانیک / افرانت (Afranet)", "AS25184"
    if "asiatech" in text or "as43754" in text:
        return "آسیاتک (Asiatech)", "AS43754"
    if "rightel" in text or "as57218" in text:
        return "رایتل (Rightel)", "AS57218"
    if "mobinnet" in text or "as50810" in text:
        return "مبین‌نت (Mobinnet)", "AS50810"
    if "respina" in text or "as42337" in text:
        return "رسپینا (Respina)", "AS42337"
    if "arvan" in text or "as202468" in text:
        return "ابر آروان (ArvanCloud)", "AS202468"
    if "hiweb" in text or "dadeh gostar" in text or "as44237" in text:
        return "های‌وب (HiWeb)", "AS44237"
    if "fanava" in text or "as41881" in text:
        return "فناوا (Fanava)", "AS41881"
    if "zitel" in text or "as206065" in text:
        return "زیتل (Zitel)", "AS206065"
    if "tic" in text or "infrastructure" in text or "as12880" in text:
        return "شرکت ارتباطات زیرساخت (TIC)", "AS12880"
        
    # در صورت عدم تطابق با موارد معروف
    isp_display = raw_isp or raw_org or "ناشناس"
    asn_display = raw_as.split()[0] if raw_as else "نامشخص"
    return isp_display, asn_display

def get_network_identity(timeout=3):
    """
    استخراج مشخصات اتصال فعلی (IP عمومی، اپراتور، ASN، شهر و کشور)
    با مکانیزم تلاش متوالی بر روی چندین سرویس بدون نیاز به کلید API
    """
    ctx = netutil.ssl_context()
    endpoints = [
        ("http://ip-api.com/json/", "ip-api"),
        ("https://freeipapi.com/api/json", "freeipapi"),
        ("https://ipwho.is/", "ipwhois"),
        ("https://api.myip.com", "myip")
    ]
    
    for url, service_type in endpoints:
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                if response.getcode() == 200:
                    payload = json.loads(response.read().decode("utf-8"))
                    
                    if service_type == "ip-api" and payload.get("status") == "success":
                        raw_isp = payload.get("isp", "")
                        raw_org = payload.get("org", "")
                        raw_as = payload.get("as", "")
                        friendly_isp, friendly_asn = identify_iranian_isp(raw_isp, raw_org, raw_as)
                        return {
                            "ok": True,
                            "ip": payload.get("query"),
                            "country": payload.get("country"),
                            "country_code": payload.get("countryCode"),
                            "city": payload.get("city"),
                            "isp": friendly_isp,
                            "raw_isp": raw_isp,
                            "asn": friendly_asn,
                            "org": raw_org,
                            "provider_service": "ip-api"
                        }
                    elif service_type == "freeipapi":
                        raw_isp = payload.get("asnName", "")
                        raw_as = f"AS{payload.get('asn', '')}"
                        friendly_isp, friendly_asn = identify_iranian_isp(raw_isp, "", raw_as)
                        return {
                            "ok": True,
                            "ip": payload.get("ipAddress"),
                            "country": payload.get("countryName"),
                            "country_code": payload.get("countryCode"),
                            "city": payload.get("cityName"),
                            "isp": friendly_isp,
                            "raw_isp": raw_isp,
                            "asn": friendly_asn,
                            "org": raw_isp,
                            "provider_service": "freeipapi"
                        }
                    elif service_type == "ipwhois" and payload.get("success"):
                        conn = payload.get("connection", {})
                        raw_isp = conn.get("isp", "")
                        raw_org = conn.get("org", "")
                        raw_as = f"AS{conn.get('asn', '')}"
                        friendly_isp, friendly_asn = identify_iranian_isp(raw_isp, raw_org, raw_as)
                        return {
                            "ok": True,
                            "ip": payload.get("ip"),
                            "country": payload.get("country"),
                            "country_code": payload.get("country_code"),
                            "city": payload.get("city"),
                            "isp": friendly_isp,
                            "raw_isp": raw_isp,
                            "asn": friendly_asn,
                            "org": raw_org,
                            "provider_service": "ipwhois"
                        }
        except Exception:
            continue
            
    # در صورت عدم دسترسی به هیچ‌یک
    return {
        "ok": False,
        "ip": "نامشخص",
        "country": "نامشخص",
        "country_code": "IR",
        "city": "نامشخص",
        "isp": "اپراتور نامشخص (محدودیت دسترسی به API هویت)",
        "raw_isp": "",
        "asn": "نامشخص",
        "org": "",
        "provider_service": "none"
    }

def probe_benchmark_url(item, timeout=3):
    """همان کش HTTP چک وب‌سایت‌ها، تا دامنهٔ مشترک در یک دور دو بار گرفته نشود."""
    probed = netutil.probe_http(item["url"], timeout=timeout)
    return {
        "name": item["name"],
        "url": item["url"],
        "ok": probed["ok"],
        "code": probed["code"],
        "latency_ms": probed["latency"],
        "error": None if probed["ok"] else probed["status"],
    }

def check_intranet_index(timeout=3, threads=15):
    """
    بررسی نسبت دسترسی شبکه ملی (Domestic) به بین‌الملل (International)
    و تشخیص وضعیت اینترنت ملی (Intranet Lockdown Mode)
    """
    start = time.time()
    
    domestic_results = []
    intl_results = []
    
    # تست همزمان تمام سرویس‌های داخلی و بین‌المللی
    all_targets = [("dom", item) for item in DOMESTIC_BENCHMARK_SERVICES] + [("intl", item) for item in INTERNATIONAL_BENCHMARK_SERVICES]
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        f_map = {executor.submit(probe_benchmark_url, item, timeout): (scope, item) for scope, item in all_targets}
        for f in concurrent.futures.as_completed(f_map):
            scope, _ = f_map[f]
            res = f.result()
            if scope == "dom":
                domestic_results.append(res)
            else:
                intl_results.append(res)
            
    d_total = len(domestic_results)
    d_ok = sum(1 for r in domestic_results if r["ok"])
    d_pct = round((d_ok / d_total) * 100, 1) if d_total else 0
    d_lats = [r["latency_ms"] for r in domestic_results if r["latency_ms"]]
    d_avg_lat = round(sum(d_lats) / len(d_lats), 1) if d_lats else None
    
    i_total = len(intl_results)
    i_ok = sum(1 for r in intl_results if r["ok"])
    i_pct = round((i_ok / i_total) * 100, 1) if i_total else 0
    i_lats = [r["latency_ms"] for r in intl_results if r["latency_ms"]]
    i_avg_lat = round(sum(i_lats) / len(i_lats), 1) if i_lats else None
    
    # محاسبه نسبت دسترسی داخلی به خارجی
    ratio = round(d_pct / i_pct, 2) if i_pct > 0 else 99.0
    
    # تعیین وضعیت شبکه بر اساس نسبت‌ها
    if d_pct >= 75 and i_pct <= 20:
        mode = "INTRANET_LOCKDOWN"
        badge = "🔴 وضعیت اضطراری اینترنت ملی (National Intranet Lockdown)"
        description = "ارتباط با شبکه بین‌الملل تقریباً به طور کامل قطع شده است؛ سرویس‌های داخلی فعال‌اند."
    elif d_pct >= 75 and i_pct < 60:
        mode = "HEAVY_CENSORSHIP"
        badge = "🟡 فیلترینگ گسترده و تفکیک شدید ترافیک داخلی/خارجی"
        description = "سایت‌های داخلی با سرعت و کیفیت بالا باز می‌شوند، اما دسترسی خارجی به شدت فیلتر و مختل است."
    elif i_pct >= 60 and i_pct < 85:
        mode = "MODERATE_CENSORSHIP"
        badge = "🟢 فیلترینگ متداول / وضعیت پایدار داخلی"
        description = "دسترسی به وب خارجی در حد متوسط بوده و فیلترینگ روی پلتفرم‌های پرمخاطب متمرکز است."
    elif i_pct >= 85:
        mode = "NORMAL"
        badge = "🟢 وضعیت عادی بین‌الملل و داخلی"
        description = "دسترسی مطلوب به عموم سرویس‌های بین‌المللی و داخلی بدون اختلال گسترده."
    else:
        mode = "OUTAGE"
        badge = "⚫ اختلال عمومی شبکه محلی / قطعی گسترده"
        description = "حتی سرویس‌های داخلی نیز با اختلال و قطعی روبه‌رو هستند (مشکل ISP یا لینک محلی)."
        
    elapsed = round(time.time() - start, 2)
    
    return {
        "elapsed_seconds": elapsed,
        "mode": mode,
        "badge": badge,
        "description": description,
        "ratio": ratio,
        "domestic": {
            "total": d_total,
            "working": d_ok,
            "percent": d_pct,
            "avg_latency_ms": d_avg_lat,
            "results": sorted(domestic_results, key=lambda x: (not x["ok"], x["name"]))
        },
        "international": {
            "total": i_total,
            "working": i_ok,
            "percent": i_pct,
            "avg_latency_ms": i_avg_lat,
            "results": sorted(intl_results, key=lambda x: (not x["ok"], x["name"]))
        }
    }

if __name__ == "__main__":
    print("──▶ در حال دریافت هویت شبکه...")
    net = get_network_identity()
    print(f"IP: {net['ip']} | ISP: {net['isp']} | ASN: {net['asn']} | City: {net['city']}, {net['country']}")
    
    print("\n──▶ در حال ارزیابی شاخص اینترنت ملی (Intranet Index)...")
    idx = check_intranet_index(timeout=3, threads=10)
    print(f"وضعیت: {idx['badge']}")
    print(f"داخلی: {idx['domestic']['working']}/{idx['domestic']['total']} ({idx['domestic']['percent']}%)")
    print(f"خارجی: {idx['international']['working']}/{idx['international']['total']} ({idx['international']['percent']}%)")
    print(f"نسبت دسترسی: {idx['ratio']}x")
