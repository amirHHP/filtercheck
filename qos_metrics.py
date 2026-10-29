#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول سنجش کیفیت، پایداری و افت خط (QoS & Performance Metrics)
- محاسبه نرخ افت پکت (Packet Loss) و جیتر (Jitter) برای مقاصد داخلی و بین‌الملل
- ارزیابی تراتلینگ و محدودسازی عمدی پهنای باند بین‌الملل (Bandwidth Throttling Probe)
- پیمایش هاپ‌های مسیریابی (Traceroute / Routing Hop Inspection) جهت تشخیص نقطه دقیق قطعی
"""

import sys
import re
import time
import subprocess
import urllib.request
import concurrent.futures

import netutil

DOMESTIC_PING_TARGETS = [
    {"name": "آپارات (Aparat)", "host": "aparat.com"},
    {"name": "دیجی‌کالا (Digikala)", "host": "digikala.com"},
    {"name": "ابر ستون (Sotoon)", "host": "sotoon.ir"},
    {"name": "دی‌ان‌اس شکن (Shecan)", "host": "178.22.122.100"}
]

INTERNATIONAL_PING_TARGETS = [
    {"name": "Cloudflare DNS (1.1.1.1)", "host": "1.1.1.1"},
    {"name": "Google DNS (8.8.8.8)", "host": "8.8.8.8"},
    {"name": "Quad9 DNS (9.9.9.9)", "host": "9.9.9.9"},
    {"name": "Wikimedia Global CDN", "host": "wikimedia.org"}
]

# یک نمونهٔ ۲ مگابایتی، نه صفحهٔ HTML. دانلودها پشت‌سرهم‌اند تا Mbps بین جریان‌ها تقسیم نشود.
WARMUP_BYTES = 256 * 1024
MEASURE_BYTES = 2 * 1024 * 1024
MIN_MEASURED_BYTES = 256 * 1024
SPEED_SAMPLE_BYTES = WARMUP_BYTES + MEASURE_BYTES

SPEED_DOMESTIC_TARGETS = [
    {"name": "شاتل (فایل معیار)", "url": "http://speedtest.shatel.ir/speedtest/random4000x4000.jpg"},
    {"name": "مخابرات (فایل معیار)", "url": "http://speedtest.tci.ir/speedtest/random4000x4000.jpg"},
    {"name": "آروان (آینه اوبونتو)", "url": "https://mirror.arvancloud.ir/ubuntu-releases/24.04.1/ubuntu-24.04.1-desktop-amd64.iso"},
]

SPEED_INTERNATIONAL_TARGETS = [
    {"name": "Cloudflare (۲ مگابایت)", "url": f"https://speed.cloudflare.com/__down?bytes={SPEED_SAMPLE_BYTES}"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
}

def bytes_to_mbps(num_bytes, seconds):
    """مگابیت بر ثانیه از روی بایت و مدت. مدت صفر یعنی نمونه‌ای در دست نیست."""
    if not seconds or seconds <= 0 or not num_bytes:
        return 0.0
    return round((num_bytes * 8) / (seconds * 1_000_000), 2)


def probe_ping_target(target, count=4, timeout=4.0):
    """
    اجرای پینگ چندتایی به یک هاست و استخراج RTT، نرخ پکت‌لاس و محاسبه جیتر (Jitter)
    """
    name = target["name"]
    host = target["host"]
    
    # تعیین پارامترهای پینگ بر مبنای سیستم‌عامل
    is_mac = sys.platform == 'darwin'
    is_win = sys.platform.startswith('win')
    if is_win:
        cmd = ['ping', '-n', str(count), '-w', '1000', host]
    elif is_mac:
        cmd = ['ping', '-c', str(count), '-W', '1000', host]
    else:
        cmd = ['ping', '-c', str(count), '-W', '1', host]
    
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + (count * 1.0))
        out = res.stdout
        
        # استخراج زمان‌های میلی‌ثانیه‌ای هر پکت: time=XX.X ms
        times = [float(t) for t in re.findall(r'time=([\d\.]+)\s*ms', out)]
        
        # استخراج پکت لاس: XX% packet loss
        loss_match = re.search(r'([\d\.]+)%\s*packet loss', out)
        if loss_match:
            packet_loss = float(loss_match.group(1))
        else:
            packet_loss = 0.0 if (times and len(times) == count) else 100.0
            
        # محاسبه جیتر (میانگین تفاضل مطلق پکت‌های متوالی: Mean Deviation / RFC 3550 style)
        jitter = 0.0
        if len(times) > 1:
            diffs = [abs(times[i] - times[i-1]) for i in range(1, len(times))]
            jitter = round(sum(diffs) / len(diffs), 1)
            
        avg_rtt = round(sum(times) / len(times), 1) if times else None
        min_rtt = round(min(times), 1) if times else None
        max_rtt = round(max(times), 1) if times else None
        
        return {
            "name": name,
            "host": host,
            "ok": len(times) > 0,
            "transmitted": count,
            "received": len(times),
            "packet_loss_pct": packet_loss,
            "avg_rtt_ms": avg_rtt,
            "min_rtt_ms": min_rtt,
            "max_rtt_ms": max_rtt,
            "jitter_ms": jitter,
            "samples": times
        }
    except Exception as e:
        return {
            "name": name,
            "host": host,
            "ok": False,
            "transmitted": count,
            "received": 0,
            "packet_loss_pct": 100.0,
            "avg_rtt_ms": None,
            "min_rtt_ms": None,
            "max_rtt_ms": None,
            "jitter_ms": None,
            "error": str(e)
        }

def measure_ping_and_jitter(count=4, timeout=4.0, threads=8):
    """
    سنجش پایداری خط، افت پکت و جیتر به صورت موازی برای اهداف داخلی و بین‌الملل
    """
    all_targets = [("domestic", t) for t in DOMESTIC_PING_TARGETS] + [("international", t) for t in INTERNATIONAL_PING_TARGETS]
    domestic_results = []
    intl_results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        f_map = {executor.submit(probe_ping_target, t, count, timeout): (scope, t) for scope, t in all_targets}
        for f in concurrent.futures.as_completed(f_map):
            scope, _ = f_map[f]
            res = f.result()
            if scope == "domestic":
                domestic_results.append(res)
            else:
                intl_results.append(res)
                
    # تجمیع نتایج داخلی
    d_lats = [r["avg_rtt_ms"] for r in domestic_results if r["avg_rtt_ms"] is not None]
    d_jitters = [r["jitter_ms"] for r in domestic_results if r["jitter_ms"] is not None]
    d_losses = [r["packet_loss_pct"] for r in domestic_results if "packet_loss_pct" in r]
    
    dom_summary = {
        "avg_latency_ms": round(sum(d_lats) / len(d_lats), 1) if d_lats else None,
        "avg_jitter_ms": round(sum(d_jitters) / len(d_jitters), 1) if d_jitters else None,
        "avg_packet_loss_pct": round(sum(d_losses) / len(d_losses), 1) if d_losses else 0.0,
        "healthy_count": sum(1 for r in domestic_results if r["ok"]),
        "total_targets": len(domestic_results),
        "results": sorted(domestic_results, key=lambda x: (not x["ok"], x.get("avg_rtt_ms") or 9999))
    }

    # تجمیع نتایج بین‌الملل
    i_lats = [r["avg_rtt_ms"] for r in intl_results if r["avg_rtt_ms"] is not None]
    i_jitters = [r["jitter_ms"] for r in intl_results if r["jitter_ms"] is not None]
    i_losses = [r["packet_loss_pct"] for r in intl_results if "packet_loss_pct" in r]
    
    intl_summary = {
        "avg_latency_ms": round(sum(i_lats) / len(i_lats), 1) if i_lats else None,
        "avg_jitter_ms": round(sum(i_jitters) / len(i_jitters), 1) if i_jitters else None,
        "avg_packet_loss_pct": round(sum(i_losses) / len(i_losses), 1) if i_losses else 0.0,
        "healthy_count": sum(1 for r in intl_results if r["ok"]),
        "total_targets": len(intl_results),
        "results": sorted(intl_results, key=lambda x: (not x["ok"], x.get("avg_rtt_ms") or 9999))
    }

    # ارزیابی پایداری کلی
    jitter_val = intl_summary["avg_jitter_ms"] or 0
    loss_val = intl_summary["avg_packet_loss_pct"] or 0
    if loss_val >= 40:
        stability_badge = "🔴 پکت‌لاس بسیار بالا و ناپایداری حاد (Severe Packet Loss)"
        stability_status = "CRITICAL_LOSS"
    elif jitter_val >= 100 or loss_val >= 15:
        stability_badge = "🟡 جیتر شدید و نوسان پکت (High Jitter / Route Instability)"
        stability_status = "UNSTABLE"
    elif jitter_val >= 40 or loss_val >= 5:
        stability_badge = "🟡 نوسان نسبی و تاخیر متغیر (Moderate Jitter)"
        stability_status = "MODERATE"
    else:
        stability_badge = "🟢 خط پایدار و کم‌نوسان (Low Jitter & Healthy Line)"
        stability_status = "STABLE"

    return {
        "stability_status": stability_status,
        "stability_badge": stability_badge,
        "domestic": dom_summary,
        "international": intl_summary
    }

def _sample_result(name, url, ok, measured, elapsed, error):
    size_kb = round(measured / 1024, 1) if measured else 0.0
    speed_mbps = bytes_to_mbps(measured, elapsed) if ok else 0.0
    speed_kb_s = round(size_kb / elapsed, 1) if ok and elapsed else 0.0
    return {
        "name": name,
        "url": url,
        "ok": ok,
        "size_kb": size_kb,
        "duration_seconds": round(elapsed, 2) if elapsed else 0.0,
        "speed_kb_s": speed_kb_s,
        "speed_mbps": speed_mbps,
        "error": error,
    }


def probe_download_speed(target, timeout=20.0):
    """
    ۲۵۶ کیلوبایت اول دور ریخته می‌شود (گرم‌کردن همان اتصال).
    سرعت از ۲ مگابایت بعدی همان سوکت حساب می‌شود، نه از صفحهٔ HTML.
    """
    name = target["name"]
    url = target["url"]
    headers = dict(HEADERS)
    headers["Range"] = f"bytes=0-{SPEED_SAMPLE_BYTES - 1}"
    req = urllib.request.Request(url, headers=headers)
    response = None
    wall = time.perf_counter()
    try:
        with netutil.NetworkSlot():
            response = urllib.request.urlopen(req, timeout=timeout, context=netutil.ssl_context())
            warmup_left = WARMUP_BYTES
            measured = 0
            started = None
            try:
                while measured < MEASURE_BYTES:
                    if time.perf_counter() - wall > timeout:
                        break
                    if warmup_left:
                        chunk = response.read(min(65536, warmup_left))
                    else:
                        chunk = response.read(min(65536, MEASURE_BYTES - measured))
                    if not chunk:
                        break
                    if warmup_left:
                        if len(chunk) < warmup_left:
                            warmup_left -= len(chunk)
                            continue
                        spill = chunk[warmup_left:]
                        warmup_left = 0
                        started = time.perf_counter()
                        measured += len(spill)
                        continue
                    if started is None:
                        started = time.perf_counter()
                    measured += len(chunk)
            except Exception:
                if measured < MIN_MEASURED_BYTES:
                    raise
            elapsed = (time.perf_counter() - started) if started else 0.0
        ok = measured >= MIN_MEASURED_BYTES and elapsed > 0
        return _sample_result(name, url, ok, measured, elapsed, None if ok else "SHORT_SAMPLE")
    except Exception as exc:
        message = str(exc).lower()
        if "timed out" in message or "timeout" in message:
            err_type = "TIMEOUT_THROTTLED"
        elif "reset" in message or "eof" in message:
            err_type = "RST_BLOCKED"
        else:
            err_type = type(exc).__name__
        return _sample_result(name, url, False, 0, time.perf_counter() - wall, err_type)
    finally:
        netutil.close_quietly(response)


def _first_speed_sample(targets, timeout):
    """اولین فایلی که به‌اندازهٔ کافی بایت بدهد. بقیه فقط وقتی قبلی ناکافی باشد امتحان می‌شوند."""
    attempts = []
    for target in targets:
        result = probe_download_speed(target, timeout=timeout)
        attempts.append(result)
        if result["ok"]:
            break
    return attempts


def _chosen_mbps(attempts):
    good = [item["speed_mbps"] for item in attempts if item["ok"]]
    return good[0] if good else 0.0


def measure_bandwidth_throttling(timeout=20.0, threads=1):
    """
    مقایسهٔ یک دانلود داخلی با یک دانلود خارجی، پشت‌سرهم.
    threads نادیده گرفته می‌شود؛ دانلود همزمان عدد Mbps را تقسیم می‌کند.
    """
    del threads
    domestic_results = _first_speed_sample(SPEED_DOMESTIC_TARGETS, timeout)
    intl_results = _first_speed_sample(SPEED_INTERNATIONAL_TARGETS, timeout)
    avg_d_speed = _chosen_mbps(domestic_results)
    avg_i_speed = _chosen_mbps(intl_results)
    d_ok = any(item["ok"] for item in domestic_results)
    i_ok = any(item["ok"] for item in intl_results)

    if d_ok and not i_ok:
        throttling_status = "HEAVY_THROTTLING_DETECTED"
        throttling_badge = "🔴 محدودسازی و تراتلینگ شدید پهنای باند بین‌الملل (Intl Speed Throttled)"
        throttling_summary = f"دانلود معیار خارجی کامل نشد. داخلی: {avg_d_speed} Mbps."
    elif not d_ok or not i_ok:
        throttling_status = "INCONCLUSIVE"
        throttling_badge = "⚫ سنجش سرعت کامل نشد"
        throttling_summary = "فایل معیار داخلی یا خارجی به‌اندازهٔ کافی دریافت نشد؛ مقایسهٔ تراتلینگ ممکن نیست."
    elif avg_d_speed > 5.0 and avg_i_speed < 0.8:
        throttling_status = "HEAVY_THROTTLING_DETECTED"
        throttling_badge = "🔴 محدودسازی و تراتلینگ شدید پهنای باند بین‌الملل (Intl Speed Throttled)"
        throttling_summary = f"ترافیک CDN خارجی خفه شده است (بین‌الملل: {avg_i_speed} Mbps در برابر داخلی: {avg_d_speed} Mbps)."
    elif avg_i_speed < 2.0 and avg_d_speed >= 8.0:
        throttling_status = "MODERATE_THROTTLING"
        throttling_badge = "🟡 تراتلینگ محسوس سرعت ارتباطات خارجی (Noticeable Throttling)"
        throttling_summary = f"سرعت CDN خارجی محدودتر از توان خط است (بین‌الملل: {avg_i_speed} Mbps | داخلی: {avg_d_speed} Mbps)."
    else:
        throttling_status = "NORMAL_SPEED"
        throttling_badge = "🟢 سرعت تبادل اطلاعات مناسب و بدون تراتلینگ حاد"
        throttling_summary = f"سرعت بین‌الملل ({avg_i_speed} Mbps) در تناسب قابل قبولی با ترافیک داخلی ({avg_d_speed} Mbps) است."

    return {
        "status": throttling_status,
        "badge": throttling_badge,
        "summary": throttling_summary,
        "domestic_avg_mbps": avg_d_speed,
        "international_avg_mbps": avg_i_speed,
        "domestic": domestic_results,
        "international": intl_results,
    }

def run_traceroute_hop_inspection(target="1.1.1.1", max_hops=14, timeout=16):
    """
    بازرسی مسیر هاپ‌های ارتباطی (Traceroute) برای تعیین دقیق نقطه افت یا فیلترینگ:
    - هاپ‌های محلی / مودم (LAN)
    - هسته شبکه اپراتور (Local ISP Core)
    - درگاه ملی زیرساخت (TIC / AS12880 Gateway)
    - مسیرهای بین‌الملل (International Transit)
    """
    is_mac = sys.platform == 'darwin'
    is_win = sys.platform.startswith('win')
    if is_win:
        cmd = ['tracert', '-d', '-h', str(max_hops), '-w', '1000', target]
    elif is_mac:
        cmd = ['traceroute', '-I', '-q', '1', '-m', str(max_hops), '-w', '1', target]
    else:
        cmd = ['traceroute', '-q', '1', '-m', str(max_hops), '-w', '1', target]
    
    out = ""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if res.returncode != 0 and is_mac:
            cmd = ['traceroute', '-q', '1', '-m', str(max_hops), '-w', '1', target]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = res.stdout.strip()
    except subprocess.TimeoutExpired as e:
        # بازیابی خروجی هاپ‌های طی شده تا لحظه وقوع تایم‌اوت
        raw_out = e.stdout or ""
        if isinstance(raw_out, bytes):
            out = raw_out.decode('utf-8', errors='replace').strip()
        else:
            out = str(raw_out).strip()
    except Exception as e:
        return {
            "target": target,
            "reached_target": False,
            "status_code": "EXEC_ERROR",
            "status_badge": "⚫ خطای Traceroute",
            "diagnosis": f"خطا در اجرای Traceroute: {str(e)}",
            "total_hops_inspected": 0,
            "drop_hop": None,
            "last_valid_hop": None,
            "hops": []
        }

    if not out:
        return {
            "target": target,
            "reached_target": False,
            "status_code": "EXEC_ERROR",
            "status_badge": "⚫ بدون پاسخ Traceroute",
            "diagnosis": "هیچ خروجی از Traceroute دریافت نشد.",
            "total_hops_inspected": 0,
            "drop_hop": None,
            "last_valid_hop": None,
            "hops": []
        }

    lines = out.split('\n')
    hops = []
    drop_hop = None
    last_valid_hop = None
    reached_target = False

    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if not parts or not parts[0].isdigit():
            continue
            
        hop_num = int(parts[0])
        
        # در صورت دراپ در این هاپ
        if '*' in line and len(parts) <= 3:
            hops.append({
                "hop": hop_num,
                "ip": None,
                "rtt_ms": None,
                "category": "DROPPED_HOP",
                "status": "DROP"
            })
            if not drop_hop:
                drop_hop = hop_num
            continue
            
        ip_match = re.search(r'\(([\d\.]+)\)', line)
        time_match = re.search(r'([\d\.]+)\s*ms', line)
        ip = ip_match.group(1) if ip_match else (parts[1] if '.' in parts[1] else None)
        rtt = float(time_match.group(1)) if time_match else None
        
        if not ip:
            continue
            
        # رده‌بندی هاپ
        if ip.startswith(('192.168.', '10.189.', '10.0.', '172.16.', '127.')):
            cat = "LAN_ROUTER"
            cat_desc = "مودم / روتر محلی کاربر"
        elif ip.startswith(('79.175.', '172.19.', '172.26.', '172.28.', '5.200.', '5.201.', '185.161.')):
            cat = "LOCAL_ISP_CORE"
            cat_desc = "هسته شبکه اپراتور اینترنت (ISP Core)"
        elif ip.startswith(('10.202.', '10.10.', '217.11.', '62.60.', '178.252.', '10.201.')):
            cat = "TIC_NATIONAL_GATEWAY"
            cat_desc = "درگاه فیلترینگ و مرز شرکت ارتباطات زیرساخت (TIC AS12880)"
        else:
            cat = "INTERNATIONAL_TRANSIT"
            cat_desc = "شبکه ترانزیت بین‌الملل (Tier-1 Transit)"
            
        if ip == target:
            reached_target = True
            
        hop_info = {
            "hop": hop_num,
            "ip": ip,
            "rtt_ms": rtt,
            "category": cat,
            "desc": cat_desc,
            "status": "OK"
        }
        hops.append(hop_info)
        last_valid_hop = hop_info

    # تحلیل نقطه افت مسیر
    if reached_target:
        diagnosis = f"مسیر تا مقصد نهایی ({target}) کاملاً باز و بدون قطعی است ({len(hops)} هاپ)."
        status_code = "ROUTING_HEALTHY"
        status_badge = "🟢 روتینگ سالم تا مقصد"
    elif last_valid_hop:
        l_cat = last_valid_hop["category"]
        l_hop = last_valid_hop["hop"]
        l_ip = last_valid_hop["ip"]
        if l_cat == "TIC_NATIONAL_GATEWAY":
            diagnosis = f"قطعی در لایه مرز زیرساخت (TIC AS12880) در هاپ {l_hop} ({l_ip}) رخ داده است. فایروال ملی پکت‌ها را متوقف می‌کند."
            status_code = "TIC_GATEWAY_DROP"
            status_badge = "🔴 قطعی در گیت‌وی خروجی زیرساخت (TIC)"
        elif l_cat == "LOCAL_ISP_CORE":
            diagnosis = f"پکت‌ها از شبکه داخلی اپراتور ({last_valid_hop['desc']}) خارج نشده و در هاپ {l_hop} متوقف شده‌اند."
            status_code = "LOCAL_ISP_DROP"
            status_badge = "🟡 قطعی در شبکه اپراتور محلی (ISP)"
        elif l_cat == "LAN_ROUTER":
            diagnosis = f"ارتباط حتی از روتر یا مودم لوکال کاربر (هاپ {l_hop}) عبور نکرده است."
            status_code = "LAN_DROP"
            status_badge = "⚫ قطعی ارتباط مودم و شبکه محلی"
        else:
            diagnosis = f"ارتباط وارد ترانزیت بین‌الملل شده اما در هاپ {l_hop} ({l_ip}) به مقصد نرسیده است."
            status_code = "UPSTREAM_TRANSIT_DROP"
            status_badge = "🟡 اختلال در ترانزیت بالادستی اینترنت"
    else:
        diagnosis = "عدم دریافت هیچ پاسخی از هاپ‌های مسیر."
        status_code = "FULL_TIMEOUT"
        status_badge = "⚫ بدون پاسخ مسیر (Full Timeout)"

    return {
        "target": target,
        "reached_target": reached_target,
        "status_code": status_code,
        "status_badge": status_badge,
        "diagnosis": diagnosis,
        "total_hops_inspected": len(hops),
        "drop_hop": drop_hop,
        "last_valid_hop": last_valid_hop,
        "hops": hops
    }

def run_qos_benchmark(ping_count=10, speed_timeout=20.0, traceroute_target="1.1.1.1", include_speed=True):
    """
    پینگ و traceroute همزمان‌اند. تست سرعت بعد از آن‌هاست تا لوله را اشغال نکند.
    include_speed=False برای وقتی است که سرعت را ارکستراتور، جدا از بقیهٔ پروب‌ها اجرا می‌کند.
    """
    start = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        ping_future = executor.submit(measure_ping_and_jitter, ping_count, 4.0)
        trace_future = executor.submit(
            run_traceroute_hop_inspection, traceroute_target, 14, 12
        )
        ping_res = ping_future.result()
        trace_res = trace_future.result()

    speed_res = measure_bandwidth_throttling(timeout=speed_timeout) if include_speed else None
    elapsed = round(time.time() - start, 2)
    result = {
        "elapsed_seconds": elapsed,
        "stability": ping_res,
        "traceroute": trace_res,
    }
    if speed_res is not None:
        result["throttling"] = speed_res
    return result

if __name__ == "__main__":
    print("──▶ تست پینگ، پکت‌لاس و جیتر:")
    p = measure_ping_and_jitter(count=10)
    print(f"وضعیت خط: {p['stability_badge']}")
    print(f"داخلی -> تاخیر: {p['domestic']['avg_latency_ms']}ms | جیتر: {p['domestic']['avg_jitter_ms']}ms | لاس: {p['domestic']['avg_packet_loss_pct']}%")
    print(f"خارجی -> تاخیر: {p['international']['avg_latency_ms']}ms | جیتر: {p['international']['avg_jitter_ms']}ms | لاس: {p['international']['avg_packet_loss_pct']}%")
    
    print("\n──▶ تست سنجش سرعت و تراتلینگ پهنای باند:")
    s = measure_bandwidth_throttling(timeout=20.0)
    print(f"وضعیت تراتلینگ: {s['badge']}")
    print(f"سرعت داخلی: {s['domestic_avg_mbps']} Mbps | سرعت خارجی: {s['international_avg_mbps']} Mbps")
    
    print("\n──▶ تست بازرسی هاپ‌های مسیر به 1.1.1.1:")
    tr = run_traceroute_hop_inspection("1.1.1.1", max_hops=12)
    print(f"تشخیص روتینگ: {tr['status_badge']}")
    print(f"توضیحات: {tr['diagnosis']}")
