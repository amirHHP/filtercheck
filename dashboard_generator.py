#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ماژول تولید داشبورد بصری تعاملی (Interactive HTML Dashboard Generator)
تولید گزارش تک‌فایلی، مدرن، ریسپانسیو و مستقل `reports/dashboard.html` با نمودارهای بصری،
گیج نمره سلامت اینترنت، ماتریس دسترسی دسته‌بندی‌ها، نمودار مقایسه تاخیر و پینگ،
تفکیک علل ریشه‌ای فیلترینگ (SNI vs IP vs DNS vs Throttling) و جدول تعاملی کلیه سرویس‌ها.
"""

import os
import json
from datetime import datetime

def generate_html_dashboard(report_data, output_path="reports/dashboard.html"):
    """
    تولید فایل HTML خودکفا (Standalone) بر اساس داده‌های گزارش جامع
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    timestamp = report_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    health = report_data.get("health", {})
    health_score = health.get("score", 0)
    health_badge = health.get("badge", "نامشخص")
    
    net = report_data.get("network_identity", {})
    ip = net.get("ip", "نامشخص")
    isp = net.get("isp", "ناشناس")
    asn = net.get("asn", "ناشناس")
    city = net.get("city", "")
    country = net.get("country", "Iran")
    location_str = f"{city}، {country}" if city else country
    
    intranet = report_data.get("intranet_index", {})
    intra_mode = intranet.get("badge", "عادی")
    intra_ratio = intranet.get("ratio", 1.0)
    dom_pct = intranet.get("domestic", {}).get("percent", 100)
    intl_pct = intranet.get("international", {}).get("percent", 50)
    
    web = report_data.get("web", {})
    web_total = web.get("total", 0)
    web_acc = web.get("accessible", 0)
    web_pct = web.get("accessible_percent", 0)
    web_avg_lat = web.get("avg_latency_ms", 0) or 0
    categories = web.get("categories", {})
    
    dns = report_data.get("dns", {})
    dns_working = dns.get("working", 0)
    dns_total = dns.get("total", 0)
    
    vpn = report_data.get("vpn", {})
    vpn_working = vpn.get("working", 0)
    vpn_total = vpn.get("total", 0)
    
    qos = report_data.get("qos", {})
    stability = qos.get("stability", {})
    throttling = qos.get("throttling", {})
    traceroute = qos.get("traceroute", {})
    
    dom_ping = stability.get("domestic", {})
    intl_ping = stability.get("international", {})
    intl_jitter = intl_ping.get("avg_jitter_ms", 0) or 0
    intl_loss = intl_ping.get("avg_packet_loss_pct", 0) or 0
    dom_ping_lat = dom_ping.get("avg_latency_ms", 0) or 0
    intl_ping_lat = intl_ping.get("avg_latency_ms", 0) or 0
    
    dom_speed = throttling.get("domestic_avg_mbps", 0) or 0
    intl_speed = throttling.get("international_avg_mbps", 0) or 0
    throttling_badge = throttling.get("badge", "عادی")
    
    circumvention = report_data.get("circumvention", {})
    circ_summary = circumvention.get("summary", {})
    clean_ips = circumvention.get("clean_ips", {})
    clean_ip_pct = clean_ips.get("reachability_percent", 0) or 0
    
    censorship = report_data.get("censorship_analysis", {})
    breakdown = censorship.get("breakdown", {
        "SNI_BLOCK": 0,
        "IP_BLOCK": 0,
        "DNS_POISONING": 0,
        "THROTTLING": 0,
        "TLS_ERROR": 0,
        "NONE": 0,
        "OTHER": 0
    })
    
    # اگر در برک‌داون قبلی فیلد تراتلینگ نبود اما تراتلینگ گزارش شده، احتساب شود
    throttling_count = breakdown.get("THROTTLING", 0)
    if throttling_count == 0 and "THROTTLED" in throttling.get("status", ""):
        throttling_count = sum(1 for r in throttling.get("international", []) if not r.get("ok"))
        breakdown["THROTTLING"] = throttling_count
    
    quic_res = report_data.get("quic_benchmark", {})
    quic_badge = quic_res.get("badge", "نامشخص")
    
    results = report_data.get("results", [])
    
    # داده‌های ماتریس دسته‌بندی
    cat_labels = list(categories.keys())
    cat_pcts = [categories[c].get("percent", 0) for c in cat_labels]
    cat_lats = [categories[c].get("avg_latency") or 0 for c in cat_labels]

    # تعیین رنگ و وضعیت نمره سلامت
    if health_score >= 80:
        score_color = "#10b981"
        score_badge_class = "badge-success"
    elif health_score >= 50:
        score_color = "#f59e0b"
        score_badge_class = "badge-warn"
    else:
        score_color = "#ef4444"
        score_badge_class = "badge-fail"

    # داده‌های جدول تعاملی
    table_data = []
    for r in results:
        table_data.append({
            "url": r.get("url", ""),
            "category": r.get("category", "متفرقه"),
            "status": "در دسترس" if r.get("ok") else "مسدود / خطا",
            "ok": bool(r.get("ok")),
            "code": r.get("code") or "-",
            "latency": r.get("latency") or 0,
            "error": r.get("status", "")
        })

    # هاپ‌های مسیر Traceroute
    trace_hops = traceroute.get("hops", [])

    # آماده‌سازی کارت‌های ماتریس دسته‌بندی
    category_cards_html = []
    for cat_name in cat_labels:
        c_info = categories.get(cat_name, {})
        pct = c_info.get("percent", 0)
        tot = c_info.get("total", 0)
        acc = c_info.get("accessible", 0)
        blk = c_info.get("blocked", 0)
        avg_l = c_info.get("avg_latency")
        lat_text = f"{avg_l}ms" if avg_l else "-"
        
        if pct >= 80:
            bar_color = "#10b981"
            status_dot = "🟢"
        elif pct >= 40:
            bar_color = "#f59e0b"
            status_dot = "🟡"
        else:
            bar_color = "#ef4444"
            status_dot = "🔴"
            
        category_cards_html.append(f"""
        <div class="matrix-card">
            <div class="matrix-card-header">
                <span class="matrix-title">{status_dot} {cat_name}</span>
                <span class="matrix-pct" style="color: {bar_color};">{pct}%</span>
            </div>
            <div class="progress-bar-bg">
                <div class="progress-bar-fill" style="width: {pct}%; background-color: {bar_color};"></div>
            </div>
            <div class="matrix-meta">
                <span>سالم: <strong>{acc}</strong> / {tot}</span>
                <span>تاخیر: <strong>{lat_text}</strong></span>
            </div>
        </div>
        """)
    matrix_html = "\n".join(category_cards_html)

    # مقایسه تاخیر: لیست داده‌ها برای نمودار تاخیر
    latency_chart_labels = ["پینگ داخلی (میانگین)", "پینگ خارجی (میانگین)"] + [c for c in cat_labels[:6]]
    latency_chart_values = [dom_ping_lat, intl_ping_lat] + [cat_lats[i] for i in range(min(6, len(cat_lats)))]

    # HTML هاپ‌های Traceroute
    trace_hops_html = []
    for h in trace_hops:
        h_num = h.get("hop", "?")
        h_ip = h.get("ip") or "* * *"
        h_rtt = f"{h.get('rtt_ms')} ms" if h.get('rtt_ms') else "-"
        h_status = h.get("status", "DROP")
        h_cat = h.get("category", "")
        h_desc = h.get("desc", "دراپ پکت یا فیلتر")
        
        is_ok = h_status == "OK"
        dot_class = "hop-dot-success" if is_ok else "hop-dot-fail"
        badge_class = "badge-success" if is_ok else "badge-fail"
        
        trace_hops_html.append(f"""
        <div class="hop-item">
            <div class="hop-number">#{h_num}</div>
            <div class="hop-dot {dot_class}"></div>
            <div class="hop-info">
                <div class="hop-ip monospace">{h_ip}</div>
                <div class="hop-desc">{h_desc}</div>
            </div>
            <div class="hop-rtt monospace">{h_rtt}</div>
            <div class="hop-badge"><span class="badge-pill {badge_class}">{h_status}</span></div>
        </div>
        """)
    hops_rendered = "\n".join(trace_hops_html) if trace_hops_html else "<div class='no-data'>هاپی ثبت نشد.</div>"

    # آماده‌سازی پروتکل‌های نوین دور زدن فیلترینگ
    circ_protocols = circumvention.get("protocols", [])
    circ_html = []
    for p in circ_protocols:
        p_ok = p.get("ok", False)
        p_badge = "badge-success" if p_ok else "badge-fail"
        p_status = p.get("status", "-")
        p_lat = f"{p.get('latency_ms')} ms" if p.get('latency_ms') else "-"
        circ_html.append(f"""
        <div class="list-item">
            <div>
                <strong>{p.get('name', '')}</strong>
                <div style="font-size: 11px; color: var(--text-muted); font-family: monospace;">{p.get('host', '')}</div>
            </div>
            <div style="display: flex; gap: 8px; align-items: center;">
                <span class="monospace">{p_lat}</span>
                <span class="badge-pill {p_badge}">{p_status}</span>
            </div>
        </div>
        """)
    circ_rendered = "\n".join(circ_html) if circ_html else "<div class='no-data'>داده‌ای موجود نیست.</div>"

    html_content = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبورد جامع پایش و سلامت اینترنت | {timestamp}</title>
    <!-- بارگذاری قلم وزین وزیرمتن و فونت سیستم به عنوان پشتیبان کامل آفلاین -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {{
            --bg-base: #0b0f19;
            --bg-surface: #111827;
            --bg-card: #1f2937;
            --bg-card-hover: #283548;
            --border-color: #374151;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --text-muted: #6b7280;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-amber: #f59e0b;
            --accent-blue: #3b82f6;
            --accent-cyan: #06b6d4;
            --accent-purple: #8b5cf6;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Vazirmatn', -apple-system, BlinkMacSystemFont, "Segoe UI", Tahoma, sans-serif;
            background-color: var(--bg-base);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 24px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .monospace {{
            font-family: 'JetBrains Mono', Consolas, Monaco, monospace;
            direction: ltr;
            display: inline-block;
        }}

        /* Header & Identity */
        header {{
            background: linear-gradient(180deg, rgba(31, 41, 55, 0.7) 0%, rgba(17, 24, 39, 0.9) 100%);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px 32px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            backdrop-filter: blur(10px);
        }}
        .header-title h1 {{
            font-size: 26px;
            font-weight: 800;
            display: flex;
            align-items: center;
            gap: 12px;
            background: linear-gradient(90deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{
            color: var(--text-secondary);
            font-size: 14px;
            margin-top: 4px;
        }}
        .identity-badge-group {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .id-badge {{
            background: rgba(31, 41, 55, 0.8);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 8px 14px;
            font-size: 13px;
        }}
        .id-badge span.label {{
            color: var(--text-muted);
            margin-left: 6px;
        }}
        .id-badge span.value {{
            color: var(--text-primary);
            font-weight: 600;
        }}

        /* KPI Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 18px 20px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            transition: transform 0.2s, border-color 0.2s;
        }}
        .kpi-card:hover {{
            transform: translateY(-2px);
            border-color: var(--accent-blue);
        }}
        .kpi-title {{
            font-size: 13px;
            color: var(--text-secondary);
            font-weight: 600;
        }}
        .kpi-value {{
            font-size: 26px;
            font-weight: 800;
            margin: 8px 0;
            font-family: 'JetBrains Mono', monospace;
        }}
        .kpi-sub {{
            font-size: 12px;
            color: var(--text-muted);
        }}

        /* Overview: Health Score & Category Matrix */
        .overview-section {{
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        @media (max-width: 1024px) {{
            .overview-section {{
                grid-template-columns: 1fr;
            }}
        }}
        .health-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }}
        .radial-gauge {{
            position: relative;
            width: 170px;
            height: 170px;
            margin: 14px 0;
        }}
        .radial-gauge svg {{
            transform: rotate(-90deg);
        }}
        .radial-gauge circle {{
            fill: none;
            stroke-width: 14;
        }}
        .gauge-bg {{
            stroke: #1f2937;
        }}
        .gauge-bar {{
            stroke: {score_color};
            stroke-dasharray: 440;
            stroke-dashoffset: {round(440 - (440 * (health_score / 100)), 1)};
            stroke-linecap: round;
            transition: stroke-dashoffset 1s ease-in-out;
        }}
        .gauge-text {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-family: 'JetBrains Mono', monospace;
            font-size: 36px;
            font-weight: 900;
            color: var(--text-primary);
        }}
        .health-badge {{
            background: rgba(31, 41, 55, 0.9);
            border: 1px solid {score_color};
            color: {score_color};
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 700;
            margin-top: 8px;
        }}

        /* Category Matrix Grid */
        .category-matrix-container {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
        }}
        .category-matrix-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .category-matrix-header h3 {{
            font-size: 16px;
            font-weight: 700;
        }}
        .matrix-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
            gap: 12px;
            max-height: 380px;
            overflow-y: auto;
            padding-left: 6px;
        }}
        .matrix-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px 14px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .matrix-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            font-weight: 600;
        }}
        .matrix-title {{
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 170px;
        }}
        .matrix-pct {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
        }}
        .progress-bar-bg {{
            background: #374151;
            height: 6px;
            border-radius: 3px;
            overflow: hidden;
        }}
        .progress-bar-fill {{
            height: 100%;
            border-radius: 3px;
        }}
        .matrix-meta {{
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-muted);
        }}

        /* Charts Row */
        .charts-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }}
        @media (max-width: 900px) {{
            .charts-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        .chart-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            display: flex;
            flex-direction: column;
        }}
        .chart-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
        }}
        .chart-header h3 {{
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        .chart-container {{
            position: relative;
            height: 270px;
            width: 100%;
        }}

        /* Pure CSS / SVG Fallback Bars (Active when offline or Chart.js fails) */
        .fallback-chart {{
            display: none;
            flex-direction: column;
            gap: 12px;
            padding: 10px 0;
        }}
        .fallback-bar-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 12px;
        }}
        .fallback-bar-label {{
            width: 140px;
            text-align: right;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .fallback-bar-track {{
            flex: 1;
            background: #374151;
            height: 14px;
            border-radius: 7px;
            overflow: hidden;
        }}
        .fallback-bar-val {{
            height: 100%;
            border-radius: 7px;
            background: var(--accent-blue);
        }}
        .fallback-bar-num {{
            width: 60px;
            font-family: 'JetBrains Mono', monospace;
            text-align: left;
        }}

        /* Protocols & Routing Grid */
        .info-panels-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
            margin-bottom: 24px;
        }}
        .panel-card {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 22px;
            max-height: 420px;
            overflow-y: auto;
        }}
        .panel-card h3 {{
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .list-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 12px;
            border-radius: 8px;
            background: rgba(31, 41, 55, 0.5);
            margin-bottom: 8px;
            font-size: 13px;
        }}
        .badge-pill {{
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            font-family: 'JetBrains Mono', monospace;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .badge-fail {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.4); }}
        .badge-warn {{ background: rgba(245, 158, 11, 0.2); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.4); }}

        /* Traceroute Hop Items */
        .hop-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 10px;
            border-radius: 8px;
            background: rgba(31, 41, 55, 0.4);
            margin-bottom: 6px;
            font-size: 12px;
        }}
        .hop-number {{
            width: 24px;
            font-weight: 700;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}
        .hop-dot {{
            width: 10px;
            height: 10px;
            border-radius: 50%;
        }}
        .hop-dot-success {{ background: var(--accent-green); box-shadow: 0 0 6px var(--accent-green); }}
        .hop-dot-fail {{ background: var(--accent-red); box-shadow: 0 0 6px var(--accent-red); }}
        .hop-info {{
            flex: 1;
        }}
        .hop-ip {{
            font-weight: 600;
            color: var(--text-primary);
        }}
        .hop-desc {{
            font-size: 11px;
            color: var(--text-muted);
        }}
        .hop-rtt {{
            font-size: 11px;
            color: var(--accent-cyan);
            margin-left: 8px;
        }}

        /* Interactive Table */
        .table-section {{
            background: var(--bg-surface);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
        }}
        .table-controls {{
            display: flex;
            flex-wrap: wrap;
            gap: 14px;
            margin-bottom: 20px;
            align-items: center;
            justify-content: space-between;
        }}
        .search-box {{
            flex: 1;
            min-width: 250px;
            position: relative;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 10px 16px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 14px;
        }}
        .search-box input:focus {{
            outline: none;
            border-color: var(--accent-blue);
        }}
        .filter-select {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 10px 16px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 13px;
        }}
        .table-responsive {{
            overflow-x: auto;
            max-height: 520px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            text-align: right;
        }}
        th, td {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: var(--bg-card);
            color: var(--text-secondary);
            font-weight: 700;
            position: sticky;
            top: 0;
            z-index: 2;
        }}
        tr:hover td {{
            background: var(--bg-card-hover);
        }}
        .no-data {{
            padding: 24px;
            text-align: center;
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="header-title">
                <h1>📡 داشبورد پایش سلامت و کیفیت اینترنت</h1>
                <p>گزارش وضعیت دسترسی، علل ریشه‌ای فیلترینگ، کیفیت خط (QoS) و ابزارهای ضد فیلتر • {timestamp}</p>
            </div>
            <div class="identity-badge-group">
                <div class="id-badge"><span class="label">اپراتور:</span><span class="value">{isp}</span></div>
                <div class="id-badge"><span class="label">ASN:</span><span class="value monospace">{asn}</span></div>
                <div class="id-badge"><span class="label">IP عمومی:</span><span class="value monospace">{ip}</span></div>
                <div class="id-badge"><span class="label">موقعیت:</span><span class="value">{location_str}</span></div>
            </div>
        </header>

        <!-- KPI Grid -->
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">نمره سلامت اینترنت</div>
                <div class="kpi-value" style="color: {score_color};">{health_score} <span style="font-size: 16px; color: var(--text-muted);">/ 100</span></div>
                <div class="kpi-sub">{health_badge}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">دسترسی به وب‌سایت‌های بین‌الملل</div>
                <div class="kpi-value" style="color: var(--accent-blue);">{web_pct}%</div>
                <div class="kpi-sub">{web_acc} سالم از مجموع {web_total} سایت</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">شاخص اینترنت ملی (Intranet Ratio)</div>
                <div class="kpi-value" style="color: var(--accent-purple);">{intra_ratio}x</div>
                <div class="kpi-sub">{intra_mode}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">کیفیت خط و پکت‌لاس بین‌الملل</div>
                <div class="kpi-value" style="color: var(--accent-amber);">{intl_loss}%</div>
                <div class="kpi-sub">جیتر: {intl_jitter} ms | {stability.get("stability_badge", "عادی")}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">پهنای باند خارجی (Speed Throttling)</div>
                <div class="kpi-value" style="color: var(--accent-cyan);">{intl_speed} <span style="font-size: 14px;">Mbps</span></div>
                <div class="kpi-sub">داخلی: {dom_speed} Mbps | {throttling_badge}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">آی‌پی‌های تمیز کلودفلر (Port 443)</div>
                <div class="kpi-value" style="color: var(--accent-green);">{clean_ip_pct}%</div>
                <div class="kpi-sub">{clean_ips.get("working_count", 0)}/{clean_ips.get("total_tested", 0)} آی‌پی در دسترس</div>
            </div>
        </div>

        <!-- Overview Section: Health Gauge + Category Availability Matrix -->
        <div class="overview-section">
            <!-- Health Gauge -->
            <div class="health-card">
                <div class="kpi-title" style="margin-bottom: 4px;">شاخص کل سلامت شبکه</div>
                <div class="radial-gauge">
                    <svg width="170" height="170">
                        <circle class="gauge-bg" cx="85" cy="85" r="70"></circle>
                        <circle class="gauge-bar" cx="85" cy="85" r="70"></circle>
                    </svg>
                    <div class="gauge-text">{health_score}</div>
                </div>
                <div class="health-badge">{health_badge}</div>
                <div style="font-size: 12px; color: var(--text-muted); margin-top: 14px; text-align: right; width: 100%; line-height: 1.8;">
                    <div>• دسترسی وب: <strong>{health.get('web_score', 0)}%</strong></div>
                    <div>• کیفیت و جیتر: <strong>{health.get('qos_score', 0)}/100</strong></div>
                    <div>• پروتکل‌های دور زدن: <strong>{health.get('circ_score', 0)}%</strong></div>
                    <div>• دی‌ان‌اس سالم: <strong>{health.get('dns_score', 0)}%</strong></div>
                </div>
            </div>

            <!-- Category Availability Matrix -->
            <div class="category-matrix-container">
                <div class="category-matrix-header">
                    <h3>🏛️ ماتریس دسترسی به دسته‌بندی‌های وب (Category Availability Matrix)</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">{len(cat_labels)} دسته‌بندی پایش شده</span>
                </div>
                <div class="matrix-grid">
                    {matrix_html}
                </div>
            </div>
        </div>

        <!-- Charts Grid: Latency Comparison & Censorship Mechanisms -->
        <div class="charts-grid">
            <!-- Latency Comparison Bar Chart -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3>⏱️ مقایسه تاخیر و پینگ (Latency Comparison Bar Chart)</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">میلی‌ثانیه (ms)</span>
                </div>
                <div class="chart-container">
                    <canvas id="latencyChart"></canvas>
                </div>
                <!-- Pure CSS Fallback for Latency -->
                <div id="latencyFallback" class="fallback-chart">
                    {"".join(f'<div class="fallback-bar-item"><div class="fallback-bar-label">{lbl}</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, int((val/2500)*100))}%;"></div></div><div class="fallback-bar-num">{val}ms</div></div>' for lbl, val in zip(latency_chart_labels, latency_chart_values))}
                </div>
            </div>

            <!-- Censorship Mechanisms Breakdown (SNI vs IP vs DNS vs Throttling) -->
            <div class="chart-card">
                <div class="chart-header">
                    <h3>🛡️ تفکیک علل ریشه‌ای فیلترینگ (SNI vs IP vs DNS vs Throttling)</h3>
                    <span style="font-size: 12px; color: var(--text-muted);">سهم مکانیزم‌ها</span>
                </div>
                <div class="chart-container">
                    <canvas id="censorshipChart"></canvas>
                </div>
                <!-- Pure CSS Fallback for Censorship Breakdown -->
                <div id="censorshipFallback" class="fallback-chart">
                    <div class="fallback-bar-item"><div class="fallback-bar-label">فیلترینگ SNI</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, breakdown.get('SNI_BLOCK',0)*5)}%; background: #ef4444;"></div></div><div class="fallback-bar-num">{breakdown.get('SNI_BLOCK',0)}</div></div>
                    <div class="fallback-bar-item"><div class="fallback-bar-label">مسدودسازی مستقیم IP</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, breakdown.get('IP_BLOCK',0)*5)}%; background: #f97316;"></div></div><div class="fallback-bar-num">{breakdown.get('IP_BLOCK',0)}</div></div>
                    <div class="fallback-bar-item"><div class="fallback-bar-label">آلودگی DNS</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, breakdown.get('DNS_POISONING',0)*5)}%; background: #8b5cf6;"></div></div><div class="fallback-bar-num">{breakdown.get('DNS_POISONING',0)}</div></div>
                    <div class="fallback-bar-item"><div class="fallback-bar-label">تراتلینگ و دراپ کلاینت‌هلو</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, breakdown.get('THROTTLING',0)*5)}%; background: #f59e0b;"></div></div><div class="fallback-bar-num">{breakdown.get('THROTTLING',0)}</div></div>
                    <div class="fallback-bar-item"><div class="fallback-bar-label">سالم و بدون فیلتر</div><div class="fallback-bar-track"><div class="fallback-bar-val" style="width: {min(100, breakdown.get('NONE',0)*5)}%; background: #10b981;"></div></div><div class="fallback-bar-num">{breakdown.get('NONE',0)}</div></div>
                </div>
            </div>
        </div>

        <!-- Protocols & Routing Grid -->
        <div class="info-panels-grid">
            <!-- Modern Circumvention Protocols Benchmark -->
            <div class="panel-card">
                <h3>🚀 پروتکل‌های نوین ضد فیلتر و دور زدن سانسور</h3>
                <div style="font-size: 12px; color: var(--text-muted); margin-bottom: 12px;">
                    پروتکل‌های فعال: <strong>{circ_summary.get('protocols_working', 0)} / {circ_summary.get('protocols_total', 0)}</strong> ({circ_summary.get('protocols_percent', 0)}%)
                </div>
                {circ_rendered}
            </div>

            <!-- DNS Security (DoH / DoT) & QUIC/HTTP3 Status -->
            <div class="panel-card">
                <h3>🔒 پروتکل‌های امن دی‌ان‌اس و UDP/HTTP-3</h3>
                <div class="list-item">
                    <div><strong>دی‌ان‌اس امن DoH</strong><div style="font-size: 11px; color: var(--text-muted);">DNS-over-HTTPS (443)</div></div>
                    <div><span class="badge-pill {'badge-success' if circ_summary.get('doh_working',0)>0 else 'badge-fail'}">{circ_summary.get('doh_working', 0)} / {circ_summary.get('doh_total', 4)} فعال</span></div>
                </div>
                <div class="list-item">
                    <div><strong>دی‌ان‌اس امن DoT</strong><div style="font-size: 11px; color: var(--text-muted);">DNS-over-TLS (Port 853)</div></div>
                    <div><span class="badge-pill {'badge-success' if circ_summary.get('dot_working',0)>0 else 'badge-fail'}">{circ_summary.get('dot_working', 0)} / {circ_summary.get('dot_total', 4)} فعال</span></div>
                </div>
                <div class="list-item">
                    <div><strong>وضعیت پروتکل UDP/QUIC</strong><div style="font-size: 11px; color: var(--text-muted);">HTTP/3 Transport (UDP 443)</div></div>
                    <div><span class="badge-pill {'badge-success' if quic_res.get('quic_working',0)>0 else 'badge-fail'}">{quic_res.get('quic_working',0)}/{quic_res.get('total_targets',6)} UDP</span></div>
                </div>
                <div class="list-item">
                    <div><strong>سرورهای DNS داخلی</strong><div style="font-size: 11px; color: var(--text-muted);">پاسخ‌دهی به رکوردهای خارجی</div></div>
                    <div><span class="badge-pill badge-success">{dns_working} / {dns_total} سالم</span></div>
                </div>
                <div class="list-item">
                    <div><strong>اندپوینت‌های عمومی VPN</strong><div style="font-size: 11px; color: var(--text-muted);">دسترسی به APIهای اتصال</div></div>
                    <div><span class="badge-pill badge-success">{vpn_working} / {vpn_total} باز</span></div>
                </div>
            </div>

            <!-- Traceroute Hop Inspection -->
            <div class="panel-card">
                <h3>🔍 بازرسی هاپ‌های مسیریابی (Traceroute Hop Inspection)</h3>
                <div style="font-size: 12px; margin-bottom: 12px; color: var(--text-secondary);">
                    {traceroute.get("status_badge", "روتینگ")} — {traceroute.get("diagnosis", "")}
                </div>
                <div style="max-height: 280px; overflow-y: auto;">
                    {hops_rendered}
                </div>
            </div>
        </div>

        <!-- Interactive Table of All Tested Services -->
        <div class="table-section">
            <div class="table-controls">
                <div class="search-box">
                    <input type="text" id="searchInput" placeholder="🔍 جستجو در نام دامنه، دسته‌بندی یا خطای مشاهده شده..." onkeyup="filterTable()">
                </div>
                <div style="display: flex; gap: 10px;">
                    <select id="statusFilter" class="filter-select" onchange="filterTable()">
                        <option value="ALL">همه وضعیت‌ها</option>
                        <option value="OK">فقط در دسترس (✅)</option>
                        <option value="BLOCKED">فقط مسدود / دارای خطا (❌)</option>
                    </select>
                    <select id="categoryFilter" class="filter-select" onchange="filterTable()">
                        <option value="ALL">همه دسته‌بندی‌ها ({len(cat_labels)})</option>
                        {"".join(f'<option value="{c}">{c}</option>' for c in cat_labels)}
                    </select>
                </div>
            </div>

            <div class="table-responsive">
                <table id="servicesTable">
                    <thead>
                        <tr>
                            <th>آدرس وب‌سایت</th>
                            <th>دسته‌بندی</th>
                            <th>وضعیت دسترسی</th>
                            <th>کد HTTP</th>
                            <th>تاخیر (ms)</th>
                            <th>جزئیات خطای مشاهده شده</th>
                        </tr>
                    </thead>
                    <tbody id="tableBody">
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Script for Dynamic Charts & Table Filtering -->
    <script>
        const tableData = {json.dumps(table_data, ensure_ascii=False)};
        
        function renderTable(data) {{
            const tbody = document.getElementById('tableBody');
            tbody.innerHTML = '';
            
            if (data.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">موردی با این مشخصات یافت نشد.</td></tr>';
                return;
            }}
            
            data.forEach(item => {{
                const tr = document.createElement('tr');
                const statusBadge = item.ok 
                    ? '<span class="badge-pill badge-success">✅ در دسترس</span>' 
                    : '<span class="badge-pill badge-fail">❌ مسدود / خطا</span>';
                    
                const latStr = item.latency ? `<span class="monospace">${{item.latency}} ms</span>` : '-';
                
                tr.innerHTML = `
                    <td class="monospace"><strong>${{item.url}}</strong></td>
                    <td>${{item.category}}</td>
                    <td>${{statusBadge}}</td>
                    <td class="monospace">${{item.code}}</td>
                    <td>${{latStr}}</td>
                    <td style="color: var(--text-muted); font-size: 12px;">${{item.error}}</td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterTable() {{
            const query = document.getElementById('searchInput').value.toLowerCase().trim();
            const statusVal = document.getElementById('statusFilter').value;
            const catVal = document.getElementById('categoryFilter').value;
            
            const filtered = tableData.filter(item => {{
                const matchQuery = item.url.toLowerCase().includes(query) || 
                                   item.category.toLowerCase().includes(query) ||
                                   item.error.toLowerCase().includes(query);
                
                let matchStatus = true;
                if (statusVal === 'OK') matchStatus = item.ok;
                if (statusVal === 'BLOCKED') matchStatus = !item.ok;
                
                let matchCat = true;
                if (catVal !== 'ALL') matchCat = (item.category === catVal);
                
                return matchQuery && matchStatus && matchCat;
            }});
            
            renderTable(filtered);
        }}

        // مقداردهی اولیه جدول
        renderTable(tableData);

        // تلاش برای رسم نمودارها با Chart.js و فعال‌سازی Fallback در صورت آفلاین بودن یا فیلتر بودن CDN
        try {{
            if (typeof Chart === 'undefined') {{
                throw new Error("Chart.js is not loaded (offline or CDN blocked)");
            }}

            // ۱. نمودار مقایسه تاخیر (Latency Comparison Bar Chart)
            const ctxLat = document.getElementById('latencyChart').getContext('2d');
            new Chart(ctxLat, {{
                type: 'bar',
                data: {{
                    labels: {json.dumps(latency_chart_labels, ensure_ascii=False)},
                    datasets: [{{
                        label: 'تاخیر (میلی‌ثانیه)',
                        data: {json.dumps(latency_chart_values)},
                        backgroundColor: [
                            'rgba(16, 185, 129, 0.7)',
                            'rgba(245, 158, 11, 0.7)',
                            'rgba(59, 130, 246, 0.7)',
                            'rgba(139, 92, 246, 0.7)',
                            'rgba(6, 182, 212, 0.7)',
                            'rgba(236, 72, 153, 0.7)',
                            'rgba(99, 102, 241, 0.7)',
                            'rgba(20, 184, 166, 0.7)'
                        ],
                        borderColor: '#374151',
                        borderWidth: 1,
                        borderRadius: 6
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {{
                        y: {{
                            beginAtZero: true,
                            ticks: {{ color: '#9ca3af' }},
                            grid: {{ color: '#374151' }}
                        }},
                        x: {{
                            ticks: {{ color: '#9ca3af', font: {{ family: 'Vazirmatn' }} }},
                            grid: {{ display: false }}
                        }}
                    }},
                    plugins: {{
                        legend: {{ display: false }}
                    }}
                }}
            }});

            // ۲. نمودار تفکیک علل ریشه‌ای فیلترینگ (SNI vs IP vs DNS vs Throttling)
            const ctxCensor = document.getElementById('censorshipChart').getContext('2d');
            new Chart(ctxCensor, {{
                type: 'doughnut',
                data: {{
                    labels: ['فیلترینگ SNI', 'مسدودسازی مستقیم IP', 'آلودگی DNS', 'تراتلینگ / دراپ کلاینت‌هلو', 'خطای TLS', 'سالم و بدون فیلتر'],
                    datasets: [{{
                        data: [
                            {breakdown.get("SNI_BLOCK", 0)},
                            {breakdown.get("IP_BLOCK", 0)},
                            {breakdown.get("DNS_POISONING", 0)},
                            {breakdown.get("THROTTLING", 0)},
                            {breakdown.get("TLS_ERROR", 0)},
                            {breakdown.get("NONE", 0)}
                        ],
                        backgroundColor: ['#ef4444', '#f97316', '#8b5cf6', '#f59e0b', '#06b6d4', '#10b981'],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {{
                        legend: {{
                            position: 'right',
                            labels: {{ color: '#f3f4f6', font: {{ family: 'Vazirmatn' }} }}
                        }}
                    }}
                }}
            }});
        }} catch(e) {{
            console.log("Chart.js fallback activated:", e);
            // نمایش نمودارهای خالص CSS/SVG در صورت عدم دسترسی به اینترنت یا CDN
            document.querySelectorAll('.chart-container').forEach(c => c.style.display = 'none');
            document.getElementById('latencyFallback').style.display = 'flex';
            document.getElementById('censorshipFallback').style.display = 'flex';
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return output_path

if __name__ == "__main__":
    latest_json = "reports/latest.json"
    if os.path.exists(latest_json):
        with open(latest_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = generate_html_dashboard(data, "reports/dashboard.html")
        print(f"[✓] داشبورد با موفقیت تولید شد: {out}")
    else:
        print("[!] فایل reports/latest.json یافت نشد.")
