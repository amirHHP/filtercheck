#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
بررسی جامع وضعیت دسترسی، فیلترینگ و سلامت اینترنت بین‌الملل
"""

import sys
import os
import time
import json
import argparse
import concurrent.futures
from datetime import datetime

import netutil

CATEGORIZED_SITES = {
    "موتورهای جستجو و دانشنامه‌ها": [
        "https://www.google.com", "https://www.bing.com", "https://www.yahoo.com", "https://www.wikipedia.org",
        "https://www.britannica.com", "https://www.dictionary.com", "https://www.thesaurus.com",
        "https://www.timeanddate.com", "https://www.weather.com", "https://www.accuweather.com",
        "https://www.imdb.com", "https://lineageos.org/"
    ],
    "دنیای متن‌باز و لینوکس": [
        "https://www.ubuntu.com", "https://www.debian.org", "https://www.centos.org",
        "https://www.linux.org", "https://www.kernel.org", "https://www.freebsd.org",
        "https://www.openbsd.org", "https://www.archlinux.org", "https://www.fedoraproject.org", "https://www.opensuse.org"
    ],
    "زبان‌های برنامه‌نویسی و تکنولوژی": [
        "https://www.python.org", "https://www.php.net", "https://www.rust-lang.org",
        "https://www.ruby-lang.org", "https://go.dev", "https://www.java.com",
        "https://www.scala-lang.org", "https://www.perl.org", "https://www.lua.org", "https://www.haskell.org"
    ],
    "سازمان‌های استاندارد و علمی": [
        "https://www.w3.org", "https://www.ieee.org", "https://www.acm.org",
        "https://www.icann.org", "https://www.iana.org", "https://www.ietf.org",
        "https://www.iso.org", "https://www.cern.ch", "https://www.nasa.gov", "https://www.esa.int"
    ],
    "ابزارها و نرم‌افزارهای کاربردی": [
        "https://www.blender.org", "https://www.gimp.org", "https://www.videolan.org",
        "https://www.libreoffice.org", "https://www.inkscape.org", "https://www.audacityteam.org",
        "https://www.virtualbox.org", "https://www.wireshark.org", "https://www.filezilla-project.org", "https://www.7-zip.org"
    ],
    "دانشگاه‌های معتبر جهانی": [
        "https://www.mit.edu", "https://www.stanford.edu", "https://www.harvard.edu",
        "https://www.caltech.edu", "https://www.cam.ac.uk", "https://www.ox.ac.uk",
        "https://www.princeton.edu", "https://www.yale.edu", "https://www.columbia.edu", "https://www.cornell.edu"
    ],
    "پایگاه‌های داده و سرورها": [
        "https://www.mysql.com", "https://www.postgresql.org", "https://www.mariadb.org",
        "https://www.sqlite.org", "https://www.redis.io", "https://www.mongodb.com",
        "https://www.apache.org", "https://www.nginx.org", "https://www.lighttpd.net", "https://www.haproxy.org"
    ],
    "شرکت‌های سخت‌افزاری و الکترونیکی": [
        "https://www.asus.com", "https://www.msi.com", "https://www.gigabyte.com",
        "https://www.lenovo.com", "https://www.samsung.com", "https://www.sony.com",
        "https://www.lg.com", "https://www.panasonic.com", "https://www.philips.com", "https://www.bosch.com"
    ],
    "فریم‌ورک‌ها و مدیریت محتوا": [
        "https://react.dev", "https://vuejs.org", "https://angular.io",
        "https://jquery.com", "https://bootstrap.com", "https://wordpress.org",
        "https://joomla.org", "https://drupal.org", "https://moodle.org", "https://magento.com"
    ],
    "بازی‌سازی و گرافیک": [
        "https://unity.com", "https://www.unrealengine.com", "https://godotengine.org",
        "https://www.khronos.org", "https://www.opengl.org", "https://vulkan.org",
        "https://www.nintendo.com", "https://www.playstation.com", "https://www.xbox.com", "https://www.ea.com"
    ],
    "ابزارهای هوش مصنوعی و مدل‌های زبانی (AI & LLMs)": [
        "https://chatgpt.com", "https://api.openai.com", "https://claude.ai", "https://api.anthropic.com",
        "https://gemini.google.com", "https://aistudio.google.com", "https://huggingface.co", "https://www.perplexity.ai",
        "https://replicate.com", "https://mistral.ai", "https://cohere.com", "https://www.together.ai",
        "https://platform.openai.com", "https://discord.com"
    ],
    "زیردامنه‌های کاربردی و زیرساختی گوگل": [
        "https://mail.google.com", "https://drive.google.com", "https://docs.google.com", "https://meet.google.com",
        "https://calendar.google.com", "https://cloud.google.com", "https://console.cloud.google.com",
        "https://developers.google.com", "https://fonts.googleapis.com", "https://ajax.googleapis.com",
        "https://analytics.google.com", "https://play.google.com", "https://developer.android.com",
        "https://translate.google.com", "https://scholar.google.com", "https://colab.research.google.com"
    ]
}

# لیست تخت برای سازگاری با کدهای قبلی
SITES_TO_CHECK = [url for category_sites in CATEGORIZED_SITES.values() for url in category_sites]

# ایجاد دیکشنری معکوس برای یافتن سریع دسته‌بندی هر سایت
URL_TO_CATEGORY = {}
for cat, urls in CATEGORIZED_SITES.items():
    for u in urls:
        URL_TO_CATEGORY[u] = cat

def create_ssl_context():
    return netutil.ssl_context()

def check_site(url, timeout=4):
    """فقط تا هدر HTTP. ۴۰۱ و ۴۰۳ و ۴۲۹ یعنی سرور پاسخ داده و فیلتر نیست."""
    return netutil.probe_http(url, timeout=timeout)

def save_report(report_data, output_dir="reports"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = report_data["timestamp_id"]
    
    # ذخیره فایل JSON
    json_filename = f"filtercheck_{timestamp_str}.json"
    json_path = os.path.join(output_dir, json_filename)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
        
    # ذخیره فایل latest.json
    latest_json_path = os.path.join(output_dir, "latest_filtercheck.json")
    with open(latest_json_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, ensure_ascii=False, indent=2)
        
    # تولید و ذخیره فایل Markdown
    md_filename = f"filtercheck_{timestamp_str}.md"
    md_path = os.path.join(output_dir, md_filename)
    md_content = generate_markdown_report(report_data)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    latest_md_path = os.path.join(output_dir, "latest_filtercheck.md")
    with open(latest_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    return json_path, md_path

def generate_markdown_report(report_data):
    s = report_data["summary"]
    lines = [
        f"# گزارش پایش دسترسی و فیلترینگ اینترنت ({report_data['timestamp']})",
        "",
        "## 📊 خلاصه وضعیت کلی",
        f"- **زمان ثبت:** {report_data['timestamp']}",
        f"- **کل سرویس‌های بررسی شده:** {s['total']}",
        f"- **سایت‌های در دسترس (سبز):** {s['accessible']} ({s['accessible_percent']}%)",
        f"- **سایت‌های مسدود / خطادار / فیلتر:** {s['blocked']} ({s['blocked_percent']}%)",
        f"- **میانگین تاخیر (Latency):** {s.get('avg_latency_ms', 'N/A')} میلی‌ثانیه",
        f"- **وضعیت کیفی اینترنت:** {s['status_verdict']}",
        "",
        "---",
        "",
        "## 📁 وضعیت بر اساس دسته‌بندی‌ها",
        "| دسته‌بندی | در دسترس | کل | درصد دسترسی | میانگین تاخیر (ms) |",
        "| :--- | :---: | :---: | :---: | :---: |"
    ]
    
    for cat_name, cat_stats in report_data["categories"].items():
        avg_lat = f"{cat_stats['avg_latency']} ms" if cat_stats['avg_latency'] else "N/A"
        lines.append(f"| {cat_name} | {cat_stats['accessible']} | {cat_stats['total']} | {cat_stats['percent']}% | {avg_lat} |")
        
    lines.extend([
        "",
        "---",
        "",
        "## ❌ سایت‌های مسدود شده یا خطادار",
        "| آدرس وب‌سایت | دسته‌بندی | علت / نوع مسدودسازی | کد |",
        "| :--- | :--- | :--- | :---: |"
    ])
    
    for item in report_data["results"]:
        if not item.get("ok"):
            lines.append(f"| `{item['url']}` | {item.get('category', '-')} | {item['status']} | {item['code']} |")
            
    lines.extend([
        "",
        "---",
        "",
        "## ✅ سایت‌های در دسترس و پرسرعت",
        "| آدرس وب‌سایت | دسته‌بندی | تاخیر (ms) | وضعیت HTTP |",
        "| :--- | :--- | :---: | :---: |"
    ])
    
    # 20 سایت سریع اول
    working_sites = [r for r in report_data["results"] if r.get("ok") and r.get("latency")]
    working_sites.sort(key=lambda x: x["latency"])
    for item in working_sites[:25]:
        lines.append(f"| `{item['url']}` | {item.get('category', '-')} | {item['latency']} ms | {item['code']} |")
        
    lines.append("")
    return "\n".join(lines)

def run_tests(threads=25, timeout=4):
    print(f"در حال بررسی وضعیت دسترسی به {len(SITES_TO_CHECK)} سایت و سرویس بین‌المللی...")
    print(f"تعداد پردازشگر همزمان: {threads} | تایم‌اوت: {timeout} ثانیه | موتور ارتباط: urllib (بدون دانلود بدنه)")
    print("-" * 65)
    
    results = []
    accessible_count = 0
    blocked_count = 0
    start_time = time.time()
    latencies = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(check_site, url, timeout): url for url in SITES_TO_CHECK}
        
        for future in concurrent.futures.as_completed(future_to_url):
            res = future.result()
            res["category"] = URL_TO_CATEGORY.get(res["url"], "متفرقه")
            results.append(res)
            status_text = res["status"]
            
            if res.get("ok"):
                lat_str = f"({res['latency']}ms)" if res.get("latency") else ""
                print(f"[✅] {res['url']:<38} -> {status_text} {lat_str}")
                accessible_count += 1
                if res.get("latency"):
                    latencies.append(res["latency"])
            else:
                print(f"[❌] {res['url']:<38} -> {status_text}")
                blocked_count += 1

    end_time = time.time()
    elapsed = round(end_time - start_time, 2)
    
    avg_latency = round(sum(latencies) / len(latencies), 1) if latencies else None
    accessible_pct = round((accessible_count / len(SITES_TO_CHECK)) * 100, 1)
    blocked_pct = round((blocked_count / len(SITES_TO_CHECK)) * 100, 1)
    
    if accessible_pct >= 85:
        verdict = "🟢 اینترنت بین‌الملل پایدار و بدون اختلال عمده است."
    elif 50 <= accessible_pct < 85:
        verdict = "🟡 اختلال محسوس در روتینگ، پکت‌لاس، یا فیلترینگ گسترده پروتکل‌ها وجود دارد."
    else:
        verdict = "🔴 اختلال بسیار شدید، قطعی ارتباطات بین‌الملل یا اینترنت ملی (Intranet)."

    # تفکیک بر اساس دسته‌بندی
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

    now = datetime.now()
    timestamp_readable = now.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_id = now.strftime("%Y%m%d_%H%M%S")
    
    report_data = {
        "timestamp": timestamp_readable,
        "timestamp_id": timestamp_id,
        "elapsed_seconds": elapsed,
        "summary": {
            "total": len(SITES_TO_CHECK),
            "accessible": accessible_count,
            "blocked": blocked_count,
            "accessible_percent": accessible_pct,
            "blocked_percent": blocked_pct,
            "avg_latency_ms": avg_latency,
            "status_verdict": verdict
        },
        "categories": cat_summary,
        "results": sorted(results, key=lambda x: (not x.get("ok"), x.get("category", ""), x["url"]))
    }
    
    print("\n" + "=" * 65)
    print("خلاصه گزارش دسترسی:")
    print(f"کل سایت‌ها: {len(SITES_TO_CHECK)}")
    print(f"سایت‌های در دسترس: {accessible_count} ({accessible_pct}%)")
    print(f"سایت‌های مسدود/خطادار: {blocked_count} ({blocked_pct}%)")
    if avg_latency:
        print(f"میانگین تاخیر سرورهای باز: {avg_latency} میلی‌ثانیه")
    print(f"زمان کل اجرای تست: {elapsed} ثانیه")
    print(f"\nوضعیت کلی: {verdict}")
    
    return report_data

def main():
    parser = argparse.ArgumentParser(description="بررسی وضعیت فیلترینگ و دسترسی به اینترنت")
    parser.add_argument("--threads", type=int, default=25, help="تعداد تردها (پیش‌فرض 25)")
    parser.add_argument("--timeout", type=int, default=4, help="تایم‌اوت هر تست بر حسب ثانیه (پیش‌فرض 4)")
    parser.add_argument("--output-dir", default="reports", help="مسیر ذخیره گزارش‌ها (پیش‌فرض reports)")
    parser.add_argument("--no-save", action="store_true", help="عدم ذخیره گزارش روی دیسک")
    args = parser.parse_args()
    
    report = run_tests(threads=args.threads, timeout=args.timeout)
    
    if not args.no_save:
        json_path, md_path = save_report(report, output_dir=args.output_dir)
        print(f"\n[💾] گزارش با موفقیت ذخیره شد:")
        print(f"  • JSON: {json_path}")
        print(f"  • Markdown: {md_path}")
        print(f"  • آخرین نسخه: {os.path.join(args.output_dir, 'latest_filtercheck.json')}")

if __name__ == "__main__":
    main()