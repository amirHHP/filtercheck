#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ابزار مقایسه دو گزارش پایش وضعیت اینترنت (Diff & Trend Analyzer)
پشتیبانی از مقایسه نمره سلامت، هویت شبکه، شاخص اینترنت ملی، کیفیت خط (QoS)،
مکانیزم‌های فیلترینگ و ابزارهای دور زدن فیلترینگ

Usage:
    python3 compare_reports.py                          # مقایسه خودکار دو گزارش آخر
    python3 compare_reports.py report1.json report2.json # مقایسه دو فایل مشخص
    python3 compare_reports.py --json                   # خروجی ساختاریافته JSON
"""

import sys
import os
import json
import glob
import argparse

# رنگ‌های ترمینال ANSI
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

def load_report(filepath):
    if not os.path.exists(filepath):
        print(f"{RED}[!] فایل گزارش پیدا نشد: {filepath}{RESET}")
        sys.exit(1)
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def find_latest_two_reports(reports_dir="reports"):
    # جستجوی تمام گزارش‌های دارای تایم‌استمپ (report_*.json یا filtercheck_*.json)
    files = glob.glob(os.path.join(reports_dir, "*_*.json"))
    files = [f for f in files if "latest" not in os.path.basename(f)]
    files.sort(key=os.path.getmtime, reverse=True)
    
    if len(files) < 2:
        return files[0] if len(files) == 1 else None, None
    return files[1], files[0]  # قدیمی‌تر اول، جدیدتر دوم

def compare_reports(old_report, new_report, verbose=False):
    t_old = old_report.get("timestamp", "قدیمی")
    t_new = new_report.get("timestamp", "جدید")
    
    s_old = old_report.get("summary", {})
    s_new = new_report.get("summary", {})
    
    # مقایسه هویت شبکه
    net_old = old_report.get("network_identity", {})
    net_new = new_report.get("network_identity", {})
    isp_changed = False
    old_isp = net_old.get("isp") or s_old.get("isp", "ناشناس")
    new_isp = net_new.get("isp") or s_new.get("isp", "ناشناس")
    old_ip = net_old.get("ip") or s_old.get("ip", "-")
    new_ip = net_new.get("ip") or s_new.get("ip", "-")
    if old_isp != new_isp or old_ip != new_ip:
        isp_changed = True
        
    # مقایسه نمره سلامت
    h_old = old_report.get("health", {})
    h_new = new_report.get("health", {})
    score_old = h_old.get("score")
    score_new = h_new.get("score")
    score_diff = round(score_new - score_old, 1) if (score_old is not None and score_new is not None) else None

    # خلاصه دسترسی وب
    acc_old = s_old.get("accessible", 0)
    acc_new = s_new.get("accessible", 0)
    tot_old = s_old.get("total", 0)
    tot_new = s_new.get("total", 0)
    
    pct_old = s_old.get("accessible_percent", 0)
    pct_new = s_new.get("accessible_percent", 0)
    pct_diff = round(pct_new - pct_old, 1)
    
    lat_old = s_old.get("avg_latency_ms")
    lat_new = s_new.get("avg_latency_ms")
    lat_diff = round(lat_new - lat_old, 1) if (lat_old and lat_new) else None

    # دیکشنری نتایج وب بر اساس URL
    old_results = {r["url"]: r for r in old_report.get("results", []) if "url" in r}
    new_results = {r["url"]: r for r in new_report.get("results", []) if "url" in r}
    
    newly_blocked = []
    newly_recovered = []
    latency_improved = []
    latency_degraded = []
    
    all_urls = sorted(list(set(old_results.keys()) | set(new_results.keys())))
    
    for url in all_urls:
        r_old = old_results.get(url)
        r_new = new_results.get(url)
        
        if not r_old or not r_new:
            continue
            
        old_ok = r_old.get("ok", False)
        new_ok = r_new.get("ok", False)
        cat = r_new.get("category", r_old.get("category", "متفرقه"))
        
        if old_ok and not new_ok:
            newly_blocked.append({
                "url": url,
                "category": cat,
                "old_latency": r_old.get("latency"),
                "new_status": r_new.get("status")
            })
        elif not old_ok and new_ok:
            newly_recovered.append({
                "url": url,
                "category": cat,
                "new_latency": r_new.get("latency"),
                "old_status": r_old.get("status")
            })
        elif old_ok and new_ok:
            l_old = r_old.get("latency")
            l_new = r_new.get("latency")
            if l_old and l_new:
                diff = round(l_new - l_old, 1)
                if diff > 100 or (diff > 50 and diff / l_old > 0.3):
                    latency_degraded.append({"url": url, "category": cat, "old": l_old, "new": l_new, "diff": diff})
                elif diff < -100 or (diff < -50 and abs(diff) / l_old > 0.3):
                    latency_improved.append({"url": url, "category": cat, "old": l_old, "new": l_new, "diff": diff})

    # مقایسه دسته‌بندی‌ها
    cat_diffs = {}
    cats_old = old_report.get("categories", {})
    cats_new = new_report.get("categories", {})
    all_cats = sorted(list(set(cats_old.keys()) | set(cats_new.keys())))
    for cat in all_cats:
        co = cats_old.get(cat, {})
        cn = cats_new.get(cat, {})
        cat_diffs[cat] = {
            "old_pct": co.get("percent", 0),
            "new_pct": cn.get("percent", 0),
            "diff_pct": round(cn.get("percent", 0) - co.get("percent", 0), 1),
            "old_acc": co.get("accessible", 0),
            "new_acc": cn.get("accessible", 0),
            "total": cn.get("total", co.get("total", 0))
        }

    # مقایسه شاخص اینترنت ملی
    intra_old = old_report.get("intranet_index", {})
    intra_new = new_report.get("intranet_index", {})
    intranet_diff = None
    if intra_old or intra_new:
        intranet_diff = {
            "old_ratio": intra_old.get("ratio"),
            "new_ratio": intra_new.get("ratio"),
            "old_mode": intra_old.get("badge", "-"),
            "new_mode": intra_new.get("badge", "-")
        }

    # مقایسه کیفیت خط (QoS)
    qos_diff = None
    qos_old = old_report.get("qos", {})
    qos_new = new_report.get("qos", {})
    if qos_old or qos_new:
        s_old_intl = qos_old.get("stability", {}).get("international", {})
        s_new_intl = qos_new.get("stability", {}).get("international", {})
        th_old = qos_old.get("throttling", {})
        th_new = qos_new.get("throttling", {})
        
        qos_diff = {
            "old_loss_pct": s_old_intl.get("avg_packet_loss_pct"),
            "new_loss_pct": s_new_intl.get("avg_packet_loss_pct"),
            "old_jitter_ms": s_old_intl.get("avg_jitter_ms"),
            "new_jitter_ms": s_new_intl.get("avg_jitter_ms"),
            "old_speed_mbps": th_old.get("international_avg_mbps"),
            "new_speed_mbps": th_new.get("international_avg_mbps")
        }

    # مقایسه پروتکل‌های ضد فیلتر و آی‌پی‌های تمیز
    circ_diff = None
    circ_old = old_report.get("circumvention", {})
    circ_new = new_report.get("circumvention", {})
    if circ_old or circ_new:
        cs_old = circ_old.get("summary", {})
        cs_new = circ_new.get("summary", {})
        circ_diff = {
            "old_clean_ips_pct": cs_old.get("clean_ips_percent"),
            "new_clean_ips_pct": cs_new.get("clean_ips_percent"),
            "old_protocols_working": cs_old.get("protocols_working"),
            "new_protocols_working": cs_new.get("protocols_working")
        }

    # مقایسه تفکیک علل فیلترینگ (SNI vs IP vs DNS vs Throttling)
    censor_diff = None
    c_old = old_report.get("censorship_analysis", {}).get("breakdown")
    c_new = new_report.get("censorship_analysis", {}).get("breakdown")
    if c_old or c_new:
        c_old = c_old or {}
        c_new = c_new or {}
        censor_diff = {
            "old_sni": c_old.get("SNI_BLOCK", 0),
            "new_sni": c_new.get("SNI_BLOCK", 0),
            "old_ip": c_old.get("IP_BLOCK", 0),
            "new_ip": c_new.get("IP_BLOCK", 0),
            "old_dns": c_old.get("DNS_POISONING", 0),
            "new_dns": c_new.get("DNS_POISONING", 0),
            "old_throttling": c_old.get("THROTTLING", 0),
            "new_throttling": c_new.get("THROTTLING", 0)
        }

    # مقایسه VPNها
    vpn_comparison = None
    if "vpn" in old_report and "vpn" in new_report:
        v_old = {t["name"]: t for t in old_report["vpn"].get("results", []) if "name" in t}
        v_new = {t["name"]: t for t in new_report["vpn"].get("results", []) if "name" in t}
        v_newly_blocked = []
        v_newly_working = []
        for name in sorted(list(set(v_old.keys()) | set(v_new.keys()))):
            vo = v_old.get(name, {}).get("ok", False)
            vn = v_new.get(name, {}).get("ok", False)
            if vo and not vn:
                v_newly_blocked.append(name)
            elif not vo and vn:
                v_newly_working.append(name)
        vpn_comparison = {
            "old_working": old_report["vpn"].get("working", 0),
            "new_working": new_report["vpn"].get("working", 0),
            "newly_blocked": v_newly_blocked,
            "newly_working": v_newly_working
        }

    return {
        "timestamp_old": t_old,
        "timestamp_new": t_new,
        "identity": {
            "isp_changed": isp_changed,
            "old_isp": old_isp,
            "new_isp": new_isp,
            "old_ip": old_ip,
            "new_ip": new_ip
        },
        "health": {
            "old_score": score_old,
            "new_score": score_new,
            "diff_score": score_diff,
            "old_badge": h_old.get("badge", ""),
            "new_badge": h_new.get("badge", "")
        },
        "summary": {
            "old_accessible": acc_old,
            "new_accessible": acc_new,
            "old_total": tot_old,
            "new_total": tot_new,
            "old_pct": pct_old,
            "new_pct": pct_new,
            "diff_pct": pct_diff,
            "old_latency": lat_old,
            "new_latency": lat_new,
            "diff_latency": lat_diff
        },
        "intranet_diff": intranet_diff,
        "qos_diff": qos_diff,
        "circumvention_diff": circ_diff,
        "censor_diff": censor_diff,
        "newly_blocked": newly_blocked,
        "newly_recovered": newly_recovered,
        "latency_degraded": latency_degraded,
        "latency_improved": latency_improved,
        "category_diffs": cat_diffs,
        "vpn_comparison": vpn_comparison
    }

def print_comparison(comp):
    s = comp["summary"]
    h = comp["health"]
    ident = comp["identity"]
    t_old = comp["timestamp_old"]
    t_new = comp["timestamp_new"]
    
    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"{BOLD}{CYAN}            گزارش مقایسه‌ای وضعیت اینترنت (Diff Report)         {RESET}")
    print(f"{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}")
    print(f"گزارش پایه (قبل):   {YELLOW}{t_old}{RESET}")
    print(f"گزارش جدید (بعد):   {GREEN}{t_new}{RESET}\n")
    
    # هشدار تغییر شبکه یا اپراتور
    if ident["isp_changed"]:
        print(f"{BOLD}{YELLOW}⚠️ هشدار تغییر شبکه / اپراتور اینترنت:{RESET}")
        print(f"  • اپراتور: {ident['old_isp']}  ───▶  {BOLD}{ident['new_isp']}{RESET}")
        print(f"  • آی‌پی:   {ident['old_ip']}  ───▶  {ident['new_ip']}\n")

    # تغییر نمره سلامت
    if h["new_score"] is not None and h["old_score"] is not None:
        diff_s = h["diff_score"]
        if diff_s > 0:
            s_color = GREEN
            s_sign = f"+{diff_s} ↗️ (بهبود وضعیت سلامت اینترنت)"
        elif diff_s < 0:
            s_color = RED
            s_sign = f"{diff_s} ↘️ (افت سلامت و افزایش اختلال)"
        else:
            s_color = YELLOW
            s_sign = "0.0 (بدون تغییر)"
        print(f"{BOLD}🎯 نمره کل سلامت اینترنت:{RESET} {h['old_score']}  ───▶  {s_color}{BOLD}{h['new_score']}/100  [{s_sign}]{RESET}")
        if h['old_badge'] != h['new_badge']:
            print(f"  • وضعیت قبلی: {h['old_badge']}")
            print(f"  • وضعیت جدید: {h['new_badge']}")
        print("")

    # تغییر درصد دسترسی
    if s["diff_pct"] > 0:
        pct_color = GREEN
        pct_sign = f"+{s['diff_pct']}% ↗️ (بهبود دسترسی)"
    elif s["diff_pct"] < 0:
        pct_color = RED
        pct_sign = f"{s['diff_pct']}% ↘️ (افزایش مسدودسازی)"
    else:
        pct_color = YELLOW
        pct_sign = "0.0% (بدون تغییر کلی)"
        
    print(f"{BOLD}📊 تغییرات دسترسی به وب‌سایت‌ها:{RESET}")
    print(f"  • تعداد در دسترس:  {s['old_accessible']} سایت  ───▶  {BOLD}{s['new_accessible']}{RESET} سایت")
    print(f"  • درصد در دسترس:   {s['old_pct']}%  ───▶  {pct_color}{BOLD}{s['new_pct']}%  [{pct_sign}]{RESET}")
    
    if s["diff_latency"] is not None:
        if s["diff_latency"] < 0:
            lat_str = f"{GREEN}{s['diff_latency']}ms (بهبود پینگ){RESET}"
        elif s["diff_latency"] > 0:
            lat_str = f"{RED}+{s['diff_latency']}ms (افزایش پینگ/کندی){RESET}"
        else:
            lat_str = "بدون تغییر"
        print(f"  • میانگین تاخیر:    {s['old_latency']}ms  ───▶  {s['new_latency']}ms  [{lat_str}]")

    # مقایسه شاخص اینترنت ملی
    intra = comp.get("intranet_diff")
    if intra and intra.get("new_ratio") is not None:
        print(f"\n{BOLD}🏛️ شاخص اینترنت ملی (Intranet Ratio):{RESET}")
        if intra.get("old_ratio") is not None:
            print(f"  • نسبت دسترسی داخلی/خارجی: {intra['old_ratio']}x  ───▶  {BOLD}{intra['new_ratio']}x{RESET}")
        else:
            print(f"  • نسبت دسترسی داخلی/خارجی: {BOLD}{intra['new_ratio']}x{RESET} (جدید)")
        if intra.get("old_mode") != intra.get("new_mode"):
            print(f"  • تغییر وضعیت: {intra.get('old_mode', '-')}  ───▶  {intra.get('new_mode', '-')}")

    # مقایسه کیفیت خط و QoS
    qos = comp.get("qos_diff")
    if qos and any(v is not None for v in [qos.get("new_loss_pct"), qos.get("new_jitter_ms"), qos.get("new_speed_mbps")]):
        print(f"\n{BOLD}⚡ تغییرات پایداری خط و پهنای باند:{RESET}")
        if qos.get("old_loss_pct") is not None and qos.get("new_loss_pct") is not None:
            print(f"  • پکت‌لاس بین‌الملل: {qos['old_loss_pct']}%  ───▶  {qos['new_loss_pct']}%")
        elif qos.get("new_loss_pct") is not None:
            print(f"  • پکت‌لاس بین‌الملل: {qos['new_loss_pct']}% (جدید)")
            
        if qos.get("old_jitter_ms") is not None and qos.get("new_jitter_ms") is not None:
            print(f"  • جیتر بین‌الملل:   {qos['old_jitter_ms']}ms  ───▶  {qos['new_jitter_ms']}ms")
        elif qos.get("new_jitter_ms") is not None:
            print(f"  • جیتر بین‌الملل:   {qos['new_jitter_ms']}ms (جدید)")
            
        if qos.get("old_speed_mbps") is not None and qos.get("new_speed_mbps") is not None:
            print(f"  • پهنای باند خارجی: {qos['old_speed_mbps']} Mbps  ───▶  {qos['new_speed_mbps']} Mbps")
        elif qos.get("new_speed_mbps") is not None:
            print(f"  • پهنای باند خارجی: {qos['new_speed_mbps']} Mbps (جدید)")

    # مقایسه پروتکل‌های ضد فیلتر و آی‌پی‌های تمیز
    circ = comp.get("circumvention_diff")
    if circ and any(v is not None for v in [circ.get("new_clean_ips_pct"), circ.get("new_protocols_working")]):
        print(f"\n{BOLD}🛡️ آی‌پی‌های تمیز کلودفلر و پروتکل‌های ضد فیلتر:{RESET}")
        if circ.get("old_clean_ips_pct") is not None and circ.get("new_clean_ips_pct") is not None:
            print(f"  • دسترسی به IPهای تمیز: {circ['old_clean_ips_pct']}%  ───▶  {circ['new_clean_ips_pct']}%")
        elif circ.get("new_clean_ips_pct") is not None:
            print(f"  • دسترسی به IPهای تمیز: {circ['new_clean_ips_pct']}% (جدید)")
            
        if circ.get("old_protocols_working") is not None and circ.get("new_protocols_working") is not None:
            print(f"  • پروتکل‌های فعال:       {circ['old_protocols_working']}  ───▶  {circ['new_protocols_working']}")
        elif circ.get("new_protocols_working") is not None:
            print(f"  • پروتکل‌های فعال:       {circ['new_protocols_working']} (جدید)")

    # مقایسه تفکیک علل فیلترینگ
    cd = comp.get("censor_diff")
    if cd and any(cd.values()):
        print(f"\n{BOLD}🔍 تغییرات تفکیک علل فیلترینگ (SNI vs IP vs DNS vs Throttling):{RESET}")
        print(f"  • فیلترینگ SNI:  {cd['old_sni']}  ───▶  {cd['new_sni']}")
        print(f"  • مسدودسازی IP:   {cd['old_ip']}  ───▶  {cd['new_ip']}")
        print(f"  • آلودگی DNS:    {cd['old_dns']}  ───▶  {cd['new_dns']}")
        print(f"  • تراتلینگ TLS:   {cd['old_throttling']}  ───▶  {cd['new_throttling']}")

    print("-" * 62)
    
    # سایت‌های تازه مسدود شده
    nb = comp["newly_blocked"]
    if nb:
        print(f"\n{RED}{BOLD}🚨 سایت‌های تازه مسدود شده (Newly Blocked) [{len(nb)}]:{RESET}")
        for item in nb:
            print(f"  ❌ {item['url']:<36} [{item['category']}] -> {item['new_status']}")
    else:
        print(f"\n{GREEN}[✓] هیچ سایت جدیدی مسدود نشده است.{RESET}")

    # سایت‌های تازه آزاد شده
    nr = comp["newly_recovered"]
    if nr:
        print(f"\n{GREEN}{BOLD}🎉 سایت‌های تازه آزاد شده / رفع اختلال (Recovered) [{len(nr)}]:{RESET}")
        for item in nr:
            lat_s = f"({item['new_latency']}ms)" if item.get('new_latency') else ""
            print(f"  ✅ {item['url']:<36} [{item['category']}] -> باز شد {lat_s}")
    else:
        print(f"{BLUE}[i] هیچ سایت جدیدی از وضعیت مسدود به باز تغییر نکرده است.{RESET}")

    # تغییرات کیفیت و کندی
    if comp["latency_degraded"]:
        print(f"\n{YELLOW}{BOLD}⚠️ سایت‌هایی که به شدت کند شده‌اند (+100ms یا +30%):{RESET}")
        for item in comp["latency_degraded"][:8]:
            print(f"  ⏱️ {item['url']:<32} {item['old']}ms -> {item['new']}ms (+{item['diff']}ms)")
            
    if comp["latency_improved"]:
        print(f"\n{GREEN}{BOLD}⚡ سایت‌هایی که تاخیر آن‌ها بهتر شده است:{RESET}")
        for item in comp["latency_improved"][:8]:
            print(f"  🚀 {item['url']:<32} {item['old']}ms -> {item['new']}ms ({item['diff']}ms)")

    # مقایسه VPNها
    vc = comp.get("vpn_comparison")
    if vc:
        print(f"\n{BOLD}🛡️ وضعیت ابزارهای ضد فیلتر و APIهای VPN:{RESET}")
        print(f"  • سرویس‌های فعال: {vc['old_working']}  ───▶  {BOLD}{vc['new_working']}{RESET}")
        if vc["newly_blocked"]:
            print(f"  • {RED}سرویس‌های تازه قطع شده: {', '.join(vc['newly_blocked'])}{RESET}")
        if vc["newly_working"]:
            print(f"  • {GREEN}سرویس‌های تازه وصل شده: {', '.join(vc['newly_working'])}{RESET}")

    print(f"\n{BOLD}{CYAN}══════════════════════════════════════════════════════════════{RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="مقایسه دو گزارش از وضعیت اینترنت")
    parser.add_argument("report_old", nargs="?", default=None, help="مسیر فایل گزارش اول (قدیمی‌تر)")
    parser.add_argument("report_new", nargs="?", default=None, help="مسیر فایل گزارش دوم (جدیدتر)")
    parser.add_argument("--dir", default="reports", help="پوشه گزارش‌ها برای مقایسه خودکار (پیش‌فرض reports)")
    parser.add_argument("--json", action="store_true", help="خروجی به فرمت JSON")
    args = parser.parse_args()

    old_file = args.report_old
    new_file = args.report_new

    if not old_file or not new_file:
        old_f, new_f = find_latest_two_reports(args.dir)
        if not old_f or not new_f:
            print(f"{RED}[!] حداقل دو فایل گزارش برای مقایسه در پوشه '{args.dir}' پیدا نشد.{RESET}")
            sys.exit(1)
        old_file, new_file = old_f, new_f
        print(f"[i] مقایسه خودکار دو گزارش آخر:")
        print(f"    قدیمی: {old_file}")
        print(f"    جدید:  {new_file}")

    rep_old = load_report(old_file)
    rep_new = load_report(new_file)

    comp = compare_reports(rep_old, rep_new)

    if args.json:
        print(json.dumps(comp, ensure_ascii=False, indent=2))
    else:
        print_comparison(comp)

if __name__ == "__main__":
    main()
