#!/usr/bin/env python3
import socket
import ssl
import time

import netutil
import urllib.request
import urllib.error
import concurrent.futures
import json
import sys
import argparse
import os
import threading
import base64
import re
from urllib.parse import urlparse

# ANSI terminal colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Enable ANSI colors on Windows Command Prompt / PowerShell
if sys.platform == 'win32':
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11) # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            mode.value |= 0x0004 # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            kernel32.SetConsoleMode(handle, mode)
    except Exception:
        # Fallback to no colors if it fails
        GREEN = RED = YELLOW = BLUE = MAGENTA = CYAN = RESET = BOLD = ""

def create_ssl_context():
    return netutil.ssl_context()

# GitHub raw URLs (including public proxy list and V2Ray subscription lists)
LIST_URLS = {
    'all': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/all-proxies.txt',
    'http': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt',
    'https': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt',
    'socks4': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt',
    'socks5': 'https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt',
    
    # User-added sources
    'ebrasha_v2ray': 'https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/V2Ray-Config-By-EbraSha-All-Type.txt',
    'barry_far_v2ray': 'https://raw.githubusercontent.com/barry-far/V2ray-Config/main/Sub1.txt',
    'roosterkid_socks5': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt',
    'roosterkid_https': 'https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt',
    'v2ray_sub': 'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/V2RAY_SUB/main/v2ray_configs_no1.txt',
    'slipnet_sub': 'https://raw.githubusercontent.com/V2RAYCONFIGSPOOL/SLIPNET_SUB/main/slipnet_no1.txt',
    'yawstar_proxy_hunter': 'https://raw.githubusercontent.com/YawStar/Proxy-Hunter/main/configs/proxy_configs.txt',
    '3inker_v2ray': 'https://raw.githubusercontent.com/3inker/v2ray-subscription/main/subs/all_not_ru.txt',
}

# User-provided VPN API endpoints list
VPN_TARGETS = [
    # --- گزینه‌های موجود در لیست شما ---
    {"name": "Cloudflare WARP (API)", "type": "HTTP", "url": "https://api.cloudflareclient.com"},
    {"name": "Proton VPN (Auth API)", "type": "HTTP", "url": "https://api.protonvpn.ch"},
    {"name": "Windscribe VPN (API)", "type": "HTTP", "url": "https://api.windscribe.com"},
    {"name": "Lantern VPN (Website)", "type": "HTTP", "url": "https://getlantern.org"},
    {"name": "Psiphon (Bootstrap)", "type": "HTTP", "url": "https://psiphon3.com"},
    {"name": "Tor Project (Bridge API)", "type": "HTTP", "url": "https://bridges.torproject.org"},

    # --- سرویس‌های فریمیم و رایگان معروف دیگر (زیرساخت و API) ---
    {"name": "Geph VPN (Binder API)", "type": "HTTP", "url": "https://binder.geph.io"},
    {"name": "Riseup VPN (Leap API)", "type": "HTTP", "url": "https://api.black.riseup.net"},
    {"name": "CalyxVPN (API)", "type": "HTTP", "url": "https://api.calyx.net"},
    {"name": "TunnelBear (API)", "type": "HTTP", "url": "https://api.tunnelbear.com"},
    {"name": "Speedify (Master Server)", "type": "HTTP", "url": "https://api.speedify.com"},
    {"name": "Hide.me VPN (API)", "type": "HTTP", "url": "https://api.hide.me"},
    {"name": "AdGuard VPN (API)", "type": "HTTP", "url": "https://api.adguard-vpn.com"},
    {"name": "Hotspot Shield (Auth)", "type": "HTTP", "url": "https://api.hotspotshield.com"},
    
    # --- ابزارهای شبکه اختصاصی و مش (دارای پلن رایگان قوی) ---
    {"name": "Tailscale (Control Plane)", "type": "HTTP", "url": "https://controlplane.tailscale.com"},
    {"name": "ZeroTier (Central API)", "type": "HTTP", "url": "https://my.zerotier.com"},

    # --- نقاط بررسی کمکی برای ابزارهای ضد فیلتر ---
    {"name": "Tor Network (Status Check)", "type": "HTTP", "url": "https://check.torproject.org"},
    {"name": "NewNode (Website/CDN)", "type": "HTTP", "url": "https://newnode.com"},
    {"name": "Ultrasurf (Bootstrap)", "type": "HTTP", "url": "https://ultrasurf.us"},

    # --- گزینه‌های جدید در تصاویر شما ---
    {"name": "Outline VPN (Website)", "type": "HTTP", "url": "https://getoutline.org"},
    {"name": "Streisand VPN (GitHub)", "type": "HTTP", "url": "https://raw.githubusercontent.com/StreisandConnect/Streisand/master/README.md"},
    {"name": "OpenVPN (Website)", "type": "HTTP", "url": "https://openvpn.net"},
    {"name": "VPN Super (Website)", "type": "HTTP", "url": "https://vpnsuper.co"},
    {"name": "Ostrich VPN (Website)", "type": "HTTP", "url": "https://ostrichvpn.net"},
    {"name": "Npv Tunnel (Website)", "type": "HTTP", "url": "https://vonmatrix.com"},
    {"name": "RostamVPN (Website)", "type": "HTTP", "url": "https://rostam.app"},
    {"name": "Wirevpn (Website)", "type": "HTTP", "url": "https://wirevpn.com"},
    {"name": "VMP VPN (Website)", "type": "HTTP", "url": "https://vpnmasterpro.com"},
    {"name": "VPN Unlimited (Website)", "type": "HTTP", "url": "https://www.vpnunlimited.com"},
    {"name": "VPN 360 (Website)", "type": "HTTP", "url": "https://www.vpn360.com"},
    {"name": "Turbo VPN (Website)", "type": "HTTP", "url": "https://turbovpn.com"},
    {"name": "Betternet (Website)", "type": "HTTP", "url": "https://www.betternet.co"},
    {"name": "Free VPN by FreeVPN.org (Website)", "type": "HTTP", "url": "https://freevpnapp.org"},
    {"name": "vpnify (Website)", "type": "HTTP", "url": "https://vpnifyapp.com"},
    {"name": "JumpJumpVPN (Website)", "type": "HTTP", "url": "https://jumpjump.io"},
    {"name": "X-VPN (Website)", "type": "HTTP", "url": "https://xvpn.io"},
    {"name": "CyberGhost (API)", "type": "HTTP", "url": "https://api.cyberghostvpn.com"},
    {"name": "VPNProxyMaster (Website)", "type": "HTTP", "url": "https://vpnproxymaster.com"},
    {"name": "PlatoVPN (Website)", "type": "HTTP", "url": "https://platovpn.com"},
    {"name": "PotatoVPN (Website)", "type": "HTTP", "url": "https://potatovpn.com"}
]

# VPN Gate API list endpoint
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"

# Threading locks and stats
stats_lock = threading.Lock()
checked_count = 0
working_count = 0
working_proxies = []
working_ovpn_servers = []
servers_to_test = []
start_time = 0

def draw_banner():
    banner = f"""
{CYAN}{BOLD}┌────────────────────────────────────────────────────────┐
│               🛡️  CONNECTIVITY INTEGRATED CHECKER        │
│          Proxies, VPN App APIs & VPN Gate OVPN         │
└────────────────────────────────────────────────────────┘{RESET}
"""
    print(banner)

def parse_target_url(url):
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    port = parsed.port
    path = parsed.path if parsed.path else '/'
    if parsed.query:
        path += '?' + parsed.query
        
    if not port:
        port = 443 if scheme == 'https' else 80
        
    use_ssl = (scheme == 'https')
    return host, port, path, use_ssl

def get_http_status(http_response):
    lines = http_response.split('\r\n')
    if lines and len(lines) > 0:
        return lines[0]
    return "Unknown Status"

def get_http_body(http_response):
    parts = http_response.split('\r\n\r\n', 1)
    if len(parts) > 1:
        return parts[1]
    parts = http_response.split('\n\n', 1)
    if len(parts) > 1:
        return parts[1]
    return http_response

# SOCKS5 Handshake & Check
def check_socks5(proxy_ip, proxy_port, host, port, path, use_ssl, timeout):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_ip, proxy_port))
        
        # Greeting
        s.sendall(b'\x05\x01\x00')
        resp = s.recv(2)
        if resp != b'\x05\x00':
            return False, 0, "SOCKS5 greeting failed"
            
        # Connect: Version 5, CONNECT (0x01), Reserved, ATYP Domain name (0x03)
        host_bytes = host.encode('ascii')
        port_bytes = port.to_bytes(2, 'big')
        payload = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + port_bytes
        s.sendall(payload)
        
        resp2 = s.recv(10)
        if not resp2 or resp2[0] != 5 or resp2[1] != 0:
            return False, 0, "SOCKS5 connection rejected"
            
        if use_ssl:
            context = create_ssl_context()
            s = context.wrap_socket(s, server_hostname=host)
            
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        resp_data = b""
        while len(resp_data) < 2048:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_data += chunk
            
        if b"HTTP/" in resp_data:
            latency = (time.time() - start) * 1000
            return True, latency, resp_data.decode('utf-8', errors='ignore')
        return False, 0, "No HTTP header in response"
    except ssl.SSLError as e:
        return False, 0, f"SSL Error: {e}"
    except socket.timeout:
        return False, 0, "Connection Timeout"
    except Exception as e:
        return False, 0, str(e)
    finally:
        try:
            s.close()
        except:
            pass

# SOCKS4 Handshake & Check
def check_socks4(proxy_ip, proxy_port, host, port, path, use_ssl, timeout):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_ip, proxy_port))
        
        # SOCKS4a request
        port_bytes = port.to_bytes(2, 'big')
        host_bytes = host.encode('ascii')
        payload = b'\x04\x01' + port_bytes + b'\x00\x00\x00\x01\x00' + host_bytes + b'\x00'
        s.sendall(payload)
        
        resp = s.recv(8)
        if not resp or resp[0] != 0 or resp[1] != 0x5a:
            return False, 0, "SOCKS4 connection rejected"
            
        if use_ssl:
            context = create_ssl_context()
            s = context.wrap_socket(s, server_hostname=host)
            
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        resp_data = b""
        while len(resp_data) < 2048:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_data += chunk
            
        if b"HTTP/" in resp_data:
            latency = (time.time() - start) * 1000
            return True, latency, resp_data.decode('utf-8', errors='ignore')
        return False, 0, "No HTTP header in response"
    except ssl.SSLError as e:
        return False, 0, f"SSL Error: {e}"
    except socket.timeout:
        return False, 0, "Connection Timeout"
    except Exception as e:
        return False, 0, str(e)
    finally:
        try:
            s.close()
        except:
            pass

# HTTP Check
def check_http(proxy_ip, proxy_port, host, port, path, timeout):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_ip, proxy_port))
        
        req = f"GET http://{host}:{port}{path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        resp_data = b""
        while len(resp_data) < 2048:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_data += chunk
            
        if b"HTTP/" in resp_data:
            latency = (time.time() - start) * 1000
            return True, latency, resp_data.decode('utf-8', errors='ignore')
        return False, 0, "No HTTP header in response"
    except socket.timeout:
        return False, 0, "Connection Timeout"
    except Exception as e:
        return False, 0, str(e)
    finally:
        try:
            s.close()
        except:
            pass

# HTTP CONNECT Check (for HTTPS over HTTP Proxy)
def check_http_connect(proxy_ip, proxy_port, host, port, path, use_ssl, timeout):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((proxy_ip, proxy_port))
        
        req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = s.recv(1)
            if not chunk:
                break
            resp += chunk
            if len(resp) > 4096:
                break
                
        if b"200" not in resp.split(b"\r\n")[0]:
            return False, 0, "CONNECT tunnel denied"
            
        if use_ssl:
            context = create_ssl_context()
            s = context.wrap_socket(s, server_hostname=host)
            
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        resp_data = b""
        while len(resp_data) < 2048:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_data += chunk
            
        if b"HTTP/" in resp_data:
            latency = (time.time() - start) * 1000
            return True, latency, resp_data.decode('utf-8', errors='ignore')
        return False, 0, "No HTTP header in response"
    except ssl.SSLError as e:
        return False, 0, f"SSL Error: {e}"
    except socket.timeout:
        return False, 0, "Connection Timeout"
    except Exception as e:
        return False, 0, str(e)
    finally:
        try:
            s.close()
        except:
            pass

def test_tcp_port(ip, port, timeout=3):
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        latency = (time.time() - start) * 1000
        return True, latency, "HTTP/1.1 200 OK\r\n\r\nTCP Port Connection Succeeded"
    except Exception as e:
        return False, 0, str(e)
    finally:
        s.close()

def test_proxy(proxy, target_url, timeout=5):
    protocol = proxy['protocol'].lower()
    ip = proxy['ip']
    port = proxy['port']
    
    host, target_port, path, use_ssl = parse_target_url(target_url)
    
    success = False
    latency = 0
    resp = ""
    
    if protocol == 'socks5':
        success, latency, resp = check_socks5(ip, port, host, target_port, path, use_ssl, timeout)
    elif protocol == 'socks4':
        success, latency, resp = check_socks4(ip, port, host, target_port, path, use_ssl, timeout)
    elif protocol == 'http':
        if use_ssl:
            success, latency, resp = check_http_connect(ip, port, host, target_port, path, use_ssl, timeout)
        else:
            success, latency, resp = check_http(ip, port, host, target_port, path, timeout)
    elif protocol == 'https':
        success, latency, resp = check_http_connect(ip, port, host, target_port, path, use_ssl, timeout)
    elif protocol in ('vmess', 'vless', 'ss', 'trojan', 'tuic', 'hysteria', 'hysteria2'):
        return test_tcp_port(ip, port, timeout)
    else:
        return False, 0, f"Unsupported protocol: {protocol}"

    if success:
        # Parse status code
        try:
            status_line = get_http_status(resp)
            status_parts = status_line.split()
            if len(status_parts) >= 2:
                status_code = int(status_parts[1])
            else:
                status_code = 0
        except:
            status_code = 0
            
        if status_code not in (200, 204, 301, 302, 307, 308):
            return False, 0, f"HTTP Error Status: {status_line}"
            
        if "ip-api.com" in target_url:
            body = get_http_body(resp)
            try:
                data = json.loads(body)
                if not isinstance(data, dict) or ('query' not in data and 'status' not in data):
                    return False, 0, "Invalid ip-api response format"
            except Exception as e:
                return False, 0, f"Failed to parse JSON response: {str(e)}"
                
        if "ipify.org" in target_url:
            body = get_http_body(resp)
            try:
                data = json.loads(body)
                if not isinstance(data, dict) or 'ip' not in data:
                    return False, 0, "Invalid ipify response format"
            except Exception as e:
                return False, 0, f"Failed to parse JSON response: {str(e)}"
                
        if "cloudflare.com" in target_url or "1.1.1.1" in target_url:
            body = get_http_body(resp)
            if "visit_scheme=" not in body or "ip=" not in body:
                return False, 0, "Invalid Cloudflare trace response format"
                
        return True, latency, resp
        
    return False, 0, resp

def parse_proxy_line(line, default_protocol=None):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    try:
        if line.startswith('vmess://'):
            b64_data = line[8:]
            b64_data += '=' * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode('utf-8', errors='ignore')
            data = json.loads(decoded)
            host = data.get('add')
            port = data.get('port')
            if host and port:
                return {'protocol': 'vmess', 'ip': host, 'port': int(port)}
        elif any(line.startswith(p) for p in ['vless://', 'ss://', 'trojan://', 'tuic://', 'hysteria2://', 'hysteria://']):
            parsed = urlparse(line)
            host = parsed.hostname
            port = parsed.port
            if host and port:
                return {'protocol': parsed.scheme.lower(), 'ip': host, 'port': int(port)}
            # Fallback to basic parsing for custom formats
            protocol, rest = line.split("://", 1)
            if '#' in rest:
                rest = rest.split('#', 1)[0]
            if '@' in rest:
                rest = rest.split('@', 1)[1]
            if ':' in rest:
                ip, port = rest.split(':', 1)
                if '/' in port:
                    port = port.split('/', 1)[0]
                if '?' in port:
                    port = port.split('?', 1)[0]
                return {'protocol': protocol.lower(), 'ip': ip, 'port': int(port)}
        elif "://" in line:
            protocol, rest = line.split("://", 1)
            if ":" in rest:
                ip, port = rest.split(":", 1)
                return {'protocol': protocol.lower(), 'ip': ip, 'port': int(port)}
        else:
            if ":" in line:
                ip, port = line.split(":", 1)
                return {'protocol': default_protocol or 'http', 'ip': ip, 'port': int(port)}
    except:
        pass
    return None

def load_working_proxies():
    proxies = []
    if os.path.exists('working_proxies.txt'):
        try:
            with open('working_proxies.txt', 'r') as f:
                for line in f:
                    p = parse_proxy_line(line)
                    if p:
                        proxies.append(p)
        except Exception:
            pass
    return proxies

# Socket-level HTTP GET over a proxy
def socket_get_via_proxy(proxy, url, timeout=6):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path if parsed.path else '/'
    if parsed.query:
        path += '?' + parsed.query
        
    use_ssl = (parsed.scheme == 'https')
    proxy_ip = proxy['ip']
    proxy_port = proxy['port']
    protocol = proxy['protocol'].lower()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((proxy_ip, proxy_port))
        
        # Check if host is raw IP
        try:
            ip_bytes = socket.inet_aton(host)
            is_ip = True
        except:
            is_ip = False
            ip_bytes = None
            
        host_bytes = host.encode('ascii')
        port_bytes = port.to_bytes(2, 'big')
        
        # SOCKS5 Handshake
        if protocol == 'socks5':
            s.sendall(b'\x05\x01\x00')
            if s.recv(2) != b'\x05\x00':
                return None
            if is_ip:
                payload = b'\x05\x01\x00\x01' + ip_bytes + port_bytes
            else:
                payload = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + port_bytes
            s.sendall(payload)
            resp2 = s.recv(10)
            if not resp2 or resp2[0] != 5 or resp2[1] != 0:
                return None
                
        # SOCKS4 Handshake
        elif protocol == 'socks4':
            if is_ip:
                payload = b'\x04\x01' + port_bytes + ip_bytes + b'\x00'
            else:
                payload = b'\x04\x01' + port_bytes + b'\x00\x00\x00\x01\x00' + host_bytes + b'\x00'
            s.sendall(payload)
            resp = s.recv(8)
            if not resp or resp[0] != 0 or resp[1] != 0x5a:
                return None
                
        # HTTP CONNECT Handshake
        elif protocol in ('http', 'https'):
            req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: keep-alive\r\n\r\n"
            s.sendall(req.encode('utf-8'))
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(1)
                if not chunk:
                    break
                resp += chunk
            if b"200" not in resp.split(b"\r\n")[0]:
                return None
        
        if use_ssl:
            context = create_ssl_context()
            s = context.wrap_socket(s, server_hostname=host)
            
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        response_bytes = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            response_bytes += chunk
            # Protect against huge pages
            if len(response_bytes) > 8 * 1024 * 1024:
                break
            
        parts = response_bytes.split(b"\r\n\r\n", 1)
        if len(parts) > 1:
            return parts[1].decode('utf-8', errors='ignore')
        return response_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None
    finally:
        s.close()

# Socket-level direct HTTP GET to prevent urllib connection read hangs
def socket_get_direct(url, timeout=6):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    path = parsed.path if parsed.path else '/'
    if parsed.query:
        path += '?' + parsed.query
        
    use_ssl = (parsed.scheme == 'https')
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        if use_ssl:
            context = create_ssl_context()
            s = context.wrap_socket(s, server_hostname=host)
            
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode('utf-8'))
        
        response_bytes = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            response_bytes += chunk
            if len(response_bytes) > 8 * 1024 * 1024:
                break
                
        parts = response_bytes.split(b"\r\n\r\n", 1)
        if len(parts) > 1:
            return parts[1].decode('utf-8', errors='ignore')
        return response_bytes.decode('utf-8', errors='ignore')
    except Exception:
        return None
    finally:
        s.close()

# Worker function to download CSV from a single mirror
def fetch_from_mirror(mirror_url, working_proxies, timeout=4):
    if working_proxies:
        for p in working_proxies:
            try:
                content = socket_get_via_proxy(p, mirror_url, timeout=timeout)
                if content and "*vpn_servers" in content:
                    return content
            except:
                pass
                
    try:
        content = socket_get_direct(mirror_url, timeout=timeout)
        if content and "*vpn_servers" in content:
            return content
    except:
        pass
        
    return None

# Self-healing fetch of VPN Gate list using mirror discovery
def fetch_vpngate_csv():
    working_proxies = load_working_proxies()
    
    # 1. Try official API via working proxies first (prevents DNS hang on blocked domains)
    if working_proxies:
        for p in working_proxies:
            print(f"{YELLOW}[*] Attempting official API download via proxy {p['protocol'].upper()} {p['ip']}:{p['port']}...{RESET}")
            content = socket_get_via_proxy(p, VPNGATE_API_URL, timeout=4)
            if content and "*vpn_servers" in content:
                print(f"{GREEN}[✓] Downloaded VPN Gate list via proxy.{RESET}")
                return content
                
    # 2. Try official API directly as a fallback
    print(f"{YELLOW}[*] Downloading VPN Gate server list from official URL directly...{RESET}")
    content = socket_get_direct(VPNGATE_API_URL, timeout=4)
    if content and "*vpn_servers" in content:
        print(f"{GREEN}[✓] Downloaded VPN Gate list directly.{RESET}")
        return content
                
    # 3. If official fails, fetch mirror sites directory to discover active volunteer mirrors
    print(f"{YELLOW}[!] Official API blocked. Fetching active mirror sites list...{RESET}")
    sites_url = "https://www.vpngate.net/en/sites.aspx"
    sites_html = None
    
    if working_proxies:
        for p in working_proxies:
            print(f"{YELLOW}[*] Fetching mirror sites directory via proxy {p['protocol'].upper()} {p['ip']}:{p['port']}...{RESET}")
            sites_html = socket_get_via_proxy(p, sites_url, timeout=4)
            if sites_html:
                break
                
    if not sites_html:
        print(f"{YELLOW}[*] Fetching mirror sites directory directly...{RESET}")
        sites_html = socket_get_direct(sites_url, timeout=4)
                
    mirrors = []
    if sites_html:
        found = re.findall(r'http://[0-9a-zA-Z\.\-]+:[0-9]+', sites_html)
        seen = set()
        for url in found:
            url_clean = url.lower().strip()
            if url_clean not in seen:
                seen.add(url_clean)
                mirrors.append(url)
                
    if mirrors:
        print(f"{GREEN}[✓] Discovered {len(mirrors)} active volunteer mirror URLs.{RESET}")
        print(f"{YELLOW}[*] Downloading VPN Gate CSV from mirrors in parallel...{RESET}")
        
        mirrors_to_try = mirrors[:15]
        csv_data = None
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(mirrors_to_try))
        futures = {
            executor.submit(fetch_from_mirror, f"{m}/api/iphone/", working_proxies, 4): m 
            for m in mirrors_to_try
        }
        
        for future in concurrent.futures.as_completed(futures):
            try:
                res = future.result()
                if res:
                    csv_data = res
                    executor.shutdown(wait=False, cancel_futures=True)
                    print(f"{GREEN}[✓] Successfully downloaded VPN Gate list from mirror!{RESET}")
                    return csv_data
            except:
                pass
                
        executor.shutdown(wait=False)
        print(f"{RED}[✗] Failed to download CSV from all active mirrors.{RESET}")
    else:
        print(f"{RED}[✗] Could not discover any active VPN Gate mirror sites.{RESET}")
        
    return None

def parse_vpngate_csv(csv_text):
    servers = []
    lines = csv_text.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith('*') or line.startswith('#'):
            continue
        parts = line.split(',')
        if len(parts) >= 11:
            try:
                # OpenVPN Config Base64 is always the last field in the CSV row
                config_b64 = parts[-1]
                config_data = base64.b64decode(config_b64).decode('utf-8', errors='ignore')
                
                port = 1194
                proto = 'udp'
                
                for conf_line in config_data.splitlines():
                    conf_line = conf_line.strip()
                    if conf_line.startswith('remote '):
                         conf_parts = conf_line.split()
                         if len(conf_parts) >= 3:
                             port = int(conf_parts[2])
                    elif conf_line.startswith('proto '):
                         conf_parts = conf_line.split()
                         if len(conf_parts) >= 2:
                             proto = conf_parts[1].lower()
                             
                # Robustly find country_short and country_long
                country_short = "US"
                country_long = "United States"
                for i in range(5, len(parts) - 2):
                    p = parts[i].strip()
                    if len(p) == 2 and p.isupper() and p.isalpha():
                        country_short = p
                        country_long = ",".join(parts[5:i])
                        break
                        
                servers.append({
                    'hostname': parts[0],
                    'ip': parts[1],
                    'country': country_long,
                    'country_short': country_short,
                    'ping': parts[3],
                    'speed': parts[4],
                    'port': port,
                    'proto': proto,
                    'config_data': config_data
                })
            except:
                pass
    return servers

def test_openvpn_udp(ip, port, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        session_id = os.urandom(8)
        packet = b'\x38' + session_id + b'\x00\x00\x00\x00\x00'
        s.sendto(packet, (ip, port))
        
        data, addr = s.recvfrom(1024)
        if len(data) >= 14 and (data[0] & 0xF8) == 0x40:
            return True
    except:
        pass
    finally:
        s.close()
    return False

def test_openvpn_tcp(ip, port, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        session_id = os.urandom(8)
        packet = b'\x00\x0e\x38' + session_id + b'\x00\x00\x00\x00\x00'
        s.sendall(packet)
        
        len_bytes = s.recv(2)
        if len_bytes == 2:
            resp_len = int.from_bytes(len_bytes, 'big')
            if 0 < resp_len < 1024:
                data = s.recv(resp_len)
                if len(data) >= 14 and (data[0] & 0xF8) == 0x40:
                    return True
    except:
        pass
    finally:
        s.close()
    return False

def download_proxies(choice):
    url = LIST_URLS.get(choice)
    if not url:
        return []
    
    print(f"{YELLOW}[*] Downloading proxy list from GitHub ({choice})...{RESET}")
    try:
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            content_bytes = response.read()
            
        try:
            # Check if content is base64 encoded
            decoded_bytes = base64.b64decode(content_bytes)
            decoded_text = decoded_bytes.decode('utf-8', errors='ignore')
            if any(marker in decoded_text for marker in ['vmess://', 'vless://', 'ss://', 'trojan://', 'socks5://', 'socks4://', 'http://', 'https://', ':']):
                content = decoded_text
            else:
                content = content_bytes.decode('utf-8', errors='ignore')
        except Exception:
            content = content_bytes.decode('utf-8', errors='ignore')
            
        raw_lines = content.splitlines()
        proxies = []
        default_protocol = None if choice in ('all', 'roosterkid_socks5', 'roosterkid_https', 'ebrasha_v2ray', 'barry_far_v2ray', 'v2ray_sub', 'slipnet_sub', 'yawstar_proxy_hunter', '3inker_v2ray') else choice
        
        for line in raw_lines:
            p = parse_proxy_line(line, default_protocol)
            if p:
                proxies.append(p)
                
        print(f"{GREEN}[✓] Downloaded {len(proxies)} proxies.{RESET}")
        return proxies
    except urllib.error.URLError as e:
        print(f"{RED}[✗] Network error downloading list: {e.reason}{RESET}")
        return []
    except Exception as e:
        print(f"{RED}[✗] Failed to download list: {e}{RESET}")
        return []

def draw_progress_bar(checked, total, working):
    percent = (checked / total) * 100 if total > 0 else 0
    bar_length = 30
    filled = int(bar_length * checked // total) if total > 0 else 0
    bar = "█" * filled + "-" * (bar_length - filled)
    
    elapsed = time.time() - start_time
    rate = checked / elapsed if elapsed > 0 else 0
    
    sys.stdout.write(
        f"\r{BLUE}[{bar}]{RESET} Checked: {checked}/{total} ({percent:.1f}%) | "
        f"{GREEN}Working: {working}{RESET} | "
        f"{YELLOW}Speed: {rate:.1f} p/s{RESET}"
    )
    sys.stdout.flush()

def proxy_worker(proxy, target_url, timeout, all_proxies_to_test):
    global checked_count, working_count
    
    latencies = []
    successes = 0
    resp_str = ""
    
    # Run 3 consecutive probes to test stability
    for i in range(3):
        success, latency, r_str = test_proxy(proxy, target_url, timeout)
        if not success:
            break
        successes += 1
        latencies.append(latency)
        resp_str = r_str
        if i < 2:
            time.sleep(0.15)  # Short pause between probes to check stability
            
    with stats_lock:
        checked_count += 1
        if successes == 3:  # Only accept 100% stable proxies
            working_count += 1
            avg_latency = sum(latencies) / len(latencies)
            # Jitter: Standard deviation of latencies
            jitter = (sum((l - avg_latency) ** 2 for l in latencies) / len(latencies)) ** 0.5
            
            status_line = get_http_status(resp_str)
            country = "Unknown"
            isp = "Unknown"
            
            exit_ip = proxy['ip']
            if "ip-api.com" in target_url:
                body = get_http_body(resp_str)
                try:
                    data = json.loads(body)
                    country = data.get('country', 'Unknown')
                    isp = data.get('isp', 'Unknown')
                except:
                    pass
            elif "cloudflare.com" in target_url or "1.1.1.1" in target_url:
                body = get_http_body(resp_str)
                for line in body.splitlines():
                    if line.startswith("ip="):
                        exit_ip = line.split("=", 1)[1].strip()
                        break
            
            result = {
                'protocol': proxy['protocol'],
                'ip': proxy['ip'],
                'exit_ip': exit_ip,
                'port': proxy['port'],
                'latency': avg_latency,
                'jitter': jitter,
                'status': status_line,
                'country': country,
                'isp': isp
            }
            working_proxies.append(result)
            
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(
                f"{GREEN}[✓] {proxy['protocol'].upper()} {proxy['ip']}:{proxy['port']} "
                f"({country}) - Avg: {avg_latency:.1f}ms, Jitter: {jitter:.1f}ms | {status_line}{RESET}"
            )
            
        draw_progress_bar(checked_count, len(all_proxies_to_test), working_count)

def get_ip_geocode_direct(ip, timeout=3):
    try:
        url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode('utf-8'))
            if data.get('status') == 'success':
                return data.get('country', 'Unknown'), data.get('isp', 'Unknown')
    except:
        pass
    return "Unknown", "Unknown"

def run_proxy_check(proxy_type='all', target_url='http://cloudflare.com/cdn-cgi/trace', threads=80, timeout=4, output_file='working_proxies.txt'):
    global start_time, checked_count, working_count, working_proxies
    
    checked_count = 0
    working_count = 0
    working_proxies = []
    
    all_proxies_to_test = download_proxies(proxy_type)
    if not all_proxies_to_test:
        print(f"{RED}[✗] No proxies downloaded to test.{RESET}\n")
        return
        
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│               TESTING PUBLIC PROXIES         │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Target endpoint: {BOLD}{target_url}{RESET}")
    print(f"Concurrency:     {BOLD}{threads} threads (Multi-Probe: 3 checks per proxy){RESET}")
    print(f"Timeout:         {BOLD}{timeout}s{RESET}\n")
    
    start_time = time.time()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(proxy_worker, p, target_url, timeout, all_proxies_to_test): p 
                for p in all_proxies_to_test
            }
            for future in concurrent.futures.as_completed(futures):
                pass
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Proxy check cancelled by user.{RESET}")
        
    print("\n")
    elapsed_total = time.time() - start_time
    
    print(f"{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│                 PROXY SUMMARY                │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Total Proxies Checked: {checked_count}")
    print(f"Working Stable Proxies: {GREEN}{working_count}{RESET} (100% Success Rate)")
    print(f"Total Time Elapsed:    {elapsed_total:.2f} seconds")
    
    if working_proxies:
        # Sort by total cost: average latency + jitter (penalizing highly unstable latency)
        working_proxies.sort(key=lambda x: x['latency'] + x['jitter'])
        
        # Parallel geolocation resolve for top 15 working proxies
        top_wp = working_proxies[:15]
        def resolve_wp(wp):
            if wp['country'] == 'Unknown':
                c, i = get_ip_geocode_direct(wp.get('exit_ip', wp['ip']))
                wp['country'] = c
                wp['isp'] = i
                
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(top_wp) or 1) as executor:
            executor.map(resolve_wp, top_wp)
            
        print(f"\n{BOLD}{CYAN}Top 15 Most Stable & Fastest Working Proxies (3/3 Probes):{RESET}")
        print(f"{BOLD}{'Protocol':<10} {'IP Address':<18} {'Port':<8} {'Avg Latency':<12} {'Jitter':<10} {'Country':<15} {'ISP':<20}{RESET}")
        print("-" * 97)
        for wp in top_wp:
            country = wp['country'][:13] if len(wp['country']) > 13 else wp['country']
            isp = wp['isp'][:18] if len(wp['isp']) > 18 else wp['isp']
            print(f"{wp['protocol'].upper():<10} {wp['ip']:<18} {wp['port']:<8} {wp['latency']:>6.1f}ms      {wp['jitter']:>6.1f}ms    {country:<15} {isp:<20}")
            
        try:
            with open(output_file, 'w') as f:
                for wp in working_proxies:
                    f.write(f"{wp['protocol']}://{wp['ip']}:{wp['port']}\n")
            print(f"\n{GREEN}[✓] Saved all working proxies to {BOLD}{output_file}{RESET}\n")
        except Exception as e:
            print(f"\n{RED}[✗] Failed to save working proxies to {output_file}: {e}{RESET}\n")
    else:
        print(f"\n{RED}[✗] No working proxies found on your internet connection.{RESET}\n")

# HTTP Target Check for VPN APIs (Option 4)
def test_vpn_endpoint(name, url, timeout=4):
    start = time.time()
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            _ = response.read(1)
        latency = (time.time() - start) * 1000
        return True, latency, f"HTTP {response.getcode()}"
    except urllib.error.HTTPError as e:
        latency = (time.time() - start) * 1000
        return True, latency, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, 0, f"Unreachable ({e.reason})"
    except socket.timeout:
        return False, 0, "Timeout"
    except Exception as e:
        return False, 0, str(e)

def run_vpn_api_check(timeout=4):
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│       TESTING FREE VPN APP BACKEND APIs      │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Testing {len(VPN_TARGETS)} endpoints directly on your internet connection...\n")
    
    print(f"{BOLD}{'VPN App / Service':<30} {'Status':<15} {'Latency':<12} {'Response Info':<30}{RESET}")
    print("-" * 88)
    
    working = 0
    start = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(test_vpn_endpoint, t['name'], t['url'], timeout): t 
            for t in VPN_TARGETS
        }
        
        for future in concurrent.futures.as_completed(futures):
            target = futures[future]
            try:
                success, latency, extra = future.result()
                if success:
                    working += 1
                    status_str = f"{GREEN}Accessible{RESET}"
                    latency_str = f"{latency:.1f}ms"
                else:
                    status_str = f"{RED}Blocked{RESET}"
                    latency_str = "N/A"
                    
                print(f"{target['name']:<30} {status_str:<15} {latency_str:<12} {extra:<30}")
            except Exception as e:
                print(f"{target['name']:<30} {RED}Error{RESET:<15} N/A          {e}")
                
    elapsed = time.time() - start
    print(f"\n{BOLD}VPN App API Check Finished in {elapsed:.2f}s | Working APIs: {GREEN}{working}/{len(VPN_TARGETS)}{RESET}\n")

# Draw Progress for VPN Gate Scan
def draw_vpngate_progress(checked, total, working):
    percent = (checked / total) * 100 if total > 0 else 0
    bar_length = 30
    filled = int(bar_length * checked // total) if total > 0 else 0
    bar = "█" * filled + "-" * (bar_length - filled)
    
    elapsed = time.time() - start_time
    rate = checked / elapsed if elapsed > 0 else 0
    
    sys.stdout.write(
        f"\r{BLUE}[{bar}]{RESET} Checked: {checked}/{total} ({percent:.1f}%) | "
        f"{GREEN}Working: {working}{RESET} | "
        f"{YELLOW}Speed: {rate:.1f} s/s{RESET}"
    )
    sys.stdout.flush()

# VPN Gate check worker
def vpngate_worker(server, timeout):
    global checked_count, working_count
    
    ip = server['ip']
    port = server['port']
    proto = server['proto']
    
    start = time.time()
    if proto == 'tcp':
        success = test_openvpn_tcp(ip, port, timeout)
    else:
        success = test_openvpn_udp(ip, port, timeout)
        
    latency = (time.time() - start) * 1000
    
    with stats_lock:
        checked_count += 1
        if success:
            working_count += 1
            server['latency'] = latency
            working_ovpn_servers.append(server)
            
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(
                f"{GREEN}[✓] OpenVPN {proto.upper()} {ip}:{port} "
                f"({server['country_short']}) is working! Latency: {latency:.1f}ms{RESET}"
            )
            
        draw_vpngate_progress(checked_count, len(servers_to_test), working_count)

# Run Check on VPN Gate (Option 2)
def run_vpngate_check(threads=50, timeout=3, max_check=120, local_file=None):
    global checked_count, working_count, start_time, servers_to_test, working_ovpn_servers
    
    checked_count = 0
    working_count = 0
    working_ovpn_servers = []
    
    csv_data = None
    if local_file:
        print(f"{YELLOW}[*] Loading VPN Gate database from local file: {BOLD}{local_file}{RESET}")
        try:
            with open(local_file, 'r', encoding='utf-8', errors='ignore') as f:
                csv_data = f.read()
            print(f"{GREEN}[✓] Loaded local database file successfully.{RESET}")
        except Exception as e:
            print(f"{RED}[✗] Failed to read local file {local_file}: {e}{RESET}")
            
    # Auto-detect vpngate.csv in current directory if no file was specified
    if not csv_data and not local_file and os.path.exists('vpngate.csv'):
        print(f"{YELLOW}[*] Found local 'vpngate.csv' database. Loading offline...{RESET}")
        try:
            with open('vpngate.csv', 'r', encoding='utf-8', errors='ignore') as f:
                csv_data = f.read()
            print(f"{GREEN}[✓] Loaded 'vpngate.csv' successfully.{RESET}")
        except Exception as e:
            print(f"{RED}[!] Found local 'vpngate.csv' but failed to read it: {e}. Trying live download...{RESET}")
            
    # Fallback to fetching over network if offline data is not available
    if not csv_data:
        csv_data = fetch_vpngate_csv()
        
    if not csv_data:
        print(f"{RED}[✗] Could not obtain VPN Gate database (no local file, and live download failed). Skipping scan.{RESET}\n")
        return
        
    servers = parse_vpngate_csv(csv_data)
    if not servers:
        print(f"{RED}[✗] VPN Gate database parse failed (no servers found).{RESET}\n")
        return
        
    print(f"{GREEN}[✓] Successfully parsed {len(servers)} servers from VPN Gate.{RESET}")
    
    servers_to_test = servers[:max_check]
    
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│         TESTING VPN GATE OPENVPN SERVERS     │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Testing the top {len(servers_to_test)} servers on your connection (using {threads} threads)...")
    print(f"Sending real OpenVPN hard reset handshake packets (TCP & UDP) to verify service...\n")
    
    start_time = time.time()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(vpngate_worker, s, timeout): s 
                for s in servers_to_test
            }
            for future in concurrent.futures.as_completed(futures):
                pass
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] VPN Gate scan cancelled by user.{RESET}")
        
    print("\n")
    elapsed = time.time() - start_time
    
    print(f"{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│               VPN GATE SUMMARY               │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Total OVPN Servers Checked: {checked_count}")
    print(f"Working OVPN Servers:      {GREEN}{working_count}{RESET}")
    print(f"Total Time Elapsed:        {elapsed:.2f} seconds")
    
    if working_ovpn_servers:
        working_ovpn_servers.sort(key=lambda x: x.get('latency', 9999))
        
        print(f"\n{BOLD}{CYAN}Working OpenVPN Servers (Top 15):{RESET}")
        print(f"{BOLD}{'Proto':<6} {'IP Address':<18} {'Port':<6} {'Latency':<10} {'Country':<15} {'Speed (Mbps)':<12}{RESET}")
        print("-" * 75)
        for s in working_ovpn_servers[:15]:
            speed_mbps = float(s['speed']) / 1000000 if s['speed'].isdigit() else 0
            print(f"{s['proto'].upper():<6} {s['ip']:<18} {s['port']:<6} {s['latency']:>6.1f}ms   {s['country'][:13]:<15} {speed_mbps:>6.1f} Mbps")
            
        config_dir = 'working_ovpn_configs'
        os.makedirs(config_dir, exist_ok=True)
        
        saved_count = 0
        for i, s in enumerate(working_ovpn_servers):
            filename = f"vpngate_{s['country_short']}_{s['proto']}_{s['ip']}_{s['port']}.ovpn"
            filepath = os.path.join(config_dir, filename)
            try:
                with open(filepath, 'w') as f:
                    f.write(s['config_data'])
                saved_count += 1
            except:
                pass
                
        print(f"\n{GREEN}[✓] Saved {saved_count} working .ovpn profiles in folder: {BOLD}{config_dir}/{RESET}")
        print(f"    You can import these configs into OpenVPN Connect / Tunnelblick to use them.\n")
    else:
        print(f"\n{RED}[✗] No working OpenVPN servers found on your internet connection.{RESET}\n")

def main():
    parser = argparse.ArgumentParser(description="Unified Proxy & VPN Connectivity Checker")
    parser.add_argument('--mode', choices=['all', 'vpn', 'vpngate', 'proxy'], default=None, help="Check mode (all, vpn, vpngate, proxy)")
    parser.add_argument('--type', choices=list(LIST_URLS.keys()), default='all', help=f"Proxy list type (choices: {', '.join(LIST_URLS.keys())})")
    parser.add_argument('--target', default='http://cloudflare.com/cdn-cgi/trace', help="Target URL for proxy checks (default: http://cloudflare.com/cdn-cgi/trace)")
    parser.add_argument('--threads', type=int, default=80, help="Concurrency threads for proxy checks (default: 80)")
    parser.add_argument('--timeout', type=int, default=4, help="Timeout in seconds for proxy checks (default: 4)")
    parser.add_argument('--output', default='working_proxies.txt', help="Output file name for working proxies (default: working_proxies.txt)")
    parser.add_argument('--vpn-timeout', type=int, default=4, help="Timeout in seconds for VPN app checks (default: 4)")
    parser.add_argument('--vpngate-threads', type=int, default=50, help="Threads for VPN Gate checking (default: 50)")
    parser.add_argument('--vpngate-limit', type=int, default=120, help="Max VPN Gate servers to check (default: 120)")
    parser.add_argument('--vpngate-timeout', type=int, default=3, help="Connection timeout in seconds for VPN Gate (default: 3)")
    parser.add_argument('--vpngate-file', default=None, help="Path to local VPN Gate CSV file (offline mode)")
    args = parser.parse_args()
    
    draw_banner()
    
    mode = args.mode
    if not mode:
        print(f"{BOLD}Select check mode:{RESET}")
        print(" [1] Check Free VPN App APIs (WARP, Proton, Windscribe, etc.)")
        print(" [2] Check VPN Gate OpenVPN Servers (uses local vpngate.csv if present, or downloads)")
        print(" [3] Check Public Proxies (downloads from GitHub & checks protocols)")
        print(" [4] Check All three modes")
        print(" [5] Exit")
        try:
            choice = input(f"{BOLD}Enter choice [1-5] (default 4): {RESET}").strip()
            if choice == '1':
                mode = 'vpn'
            elif choice == '2':
                mode = 'vpngate'
            elif choice == '3':
                mode = 'proxy'
            elif choice == '5':
                print("Exiting.")
                sys.exit(0)
            else:
                mode = 'all'
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)
            
    if mode in ('vpn', 'all'):
        run_vpn_api_check(timeout=args.vpn_timeout)
        
    if mode in ('vpngate', 'all'):
        run_vpngate_check(
            threads=args.vpngate_threads,
            timeout=args.vpngate_timeout,
            max_check=args.vpngate_limit,
            local_file=args.vpngate_file
        )
        
    if mode in ('proxy', 'all'):
        run_proxy_check(
            proxy_type=args.type,
            target_url=args.target,
            threads=args.threads,
            timeout=args.timeout,
            output_file=args.output
        )

if __name__ == '__main__':
    main()
