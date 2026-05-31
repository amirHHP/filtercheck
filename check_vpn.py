#!/usr/bin/env python3
import socket
import ssl
import time
import urllib.request
import urllib.error
import concurrent.futures
import json
import sys
import argparse
import os
import base64
import threading
import re
import subprocess
import tempfile
import shutil
from urllib.parse import urlparse

# Set default socket timeout globally to prevent any hanging connections
socket.setdefaulttimeout(4.0)

# ANSI terminal colors
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

# User-provided VPN API endpoints list
VPN_TARGETS = [
    {"name": "Cloudflare WARP (API)", "type": "HTTP", "url": "https://api.cloudflareclient.com"},
    {"name": "Proton VPN (Auth API)", "type": "HTTP", "url": "https://api.protonvpn.ch"},
    {"name": "Windscribe VPN (API)", "type": "HTTP", "url": "https://api.windscribe.com"},
    {"name": "Lantern VPN (Website)", "type": "HTTP", "url": "https://getlantern.org"},
    {"name": "Psiphon (Bootstrap)", "type": "HTTP", "url": "https://psiphon3.com"},
    {"name": "Tor Project (Bridge API)", "type": "HTTP", "url": "https://bridges.torproject.org"},
    {"name": "Geph VPN (Binder API)", "type": "HTTP", "url": "https://binder.geph.io"},
    {"name": "Riseup VPN (Leap API)", "type": "HTTP", "url": "https://api.black.riseup.net"},
    {"name": "CalyxVPN (API)", "type": "HTTP", "url": "https://api.calyx.net"},
    {"name": "TunnelBear (API)", "type": "HTTP", "url": "https://api.tunnelbear.com"},
    {"name": "Speedify (Master Server)", "type": "HTTP", "url": "https://api.speedify.com"},
    {"name": "Hide.me VPN (API)", "type": "HTTP", "url": "https://api.hide.me"},
    {"name": "AdGuard VPN (API)", "type": "HTTP", "url": "https://api.adguard-vpn.com"},
    {"name": "Hotspot Shield (Auth)", "type": "HTTP", "url": "https://api.hotspotshield.com"},
    {"name": "Tailscale (Control Plane)", "type": "HTTP", "url": "https://controlplane.tailscale.com"},
    {"name": "ZeroTier (Central API)", "type": "HTTP", "url": "https://my.zerotier.com"},
    {"name": "Tor Network (Status Check)", "type": "HTTP", "url": "https://check.torproject.org"},
    {"name": "NewNode (Website/CDN)", "type": "HTTP", "url": "https://newnode.com"},
    {"name": "Ultrasurf (Bootstrap)", "type": "HTTP", "url": "https://ultrasurf.us"},
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
    {"name": "PotatoVPN (Website)", "type": "HTTP", "url": "https://soft.potatovpn.io/"}
]

# VPN Gate API list endpoint
VPNGATE_API_URL = "http://www.vpngate.net/api/iphone/"

# Concurrency & stats tracking
stats_lock = threading.Lock()
checked_count = 0
working_count = 0
working_ovpn_servers = []
deep_verified_servers = []  # Servers that passed full TLS key negotiation
start_time = 0

def find_openvpn_binary():
    """Locate the openvpn binary on the system."""
    # Common paths
    candidates = [
        '/opt/homebrew/sbin/openvpn',
        '/usr/local/sbin/openvpn',
        '/usr/sbin/openvpn',
        '/usr/local/bin/openvpn',
        '/usr/bin/openvpn',
    ]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    # Try shutil.which as fallback
    found = shutil.which('openvpn')
    return found

def generate_alt_proto_config(config_data, target_proto):
    """Rewrite an .ovpn config to use a different protocol (udp<->tcp)."""
    lines = config_data.splitlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith('proto '):
            new_lines.append(f'proto {target_proto}')
        else:
            new_lines.append(line)
    return '\n'.join(new_lines)

def deep_test_openvpn(config_data, openvpn_bin, timeout=20):
    """
    Run actual openvpn binary with a config to test full TLS handshake.
    Returns a dict with test results:
      - 'initial_packet': True if server responded to initial hard reset
      - 'cert_verified': True if TLS certificate chain was verified
      - 'key_negotiated': True if TLS key negotiation succeeded
      - 'connected': True if tunnel was fully established (INITIALIZATION SEQUENCE COMPLETED)
      - 'error': error message if any
      - 'cert_cn': Common Name from server certificate
      - 'elapsed': time taken in seconds
    """
    result = {
        'initial_packet': False,
        'cert_verified': False,
        'key_negotiated': False,
        'connected': False,
        'error': None,
        'cert_cn': None,
        'elapsed': 0,
    }
    
    # Write config to a temp file
    tmp_dir = tempfile.mkdtemp(prefix='ovpn_test_')
    config_path = os.path.join(tmp_dir, 'test.ovpn')
    try:
        with open(config_path, 'w') as f:
            f.write(config_data)
        
        # Build openvpn command:
        # --dev null --dev-type tun: don't create real tun device (no root needed)
        # --route-noexec --ifconfig-noexec: don't modify routing table
        # --connect-timeout: limit initial connection time
        # --hand-window: limit TLS handshake time
        # --verb 3: verbose enough to see TLS details
        # --connect-retry-max 1: don't retry on failure
        # --tls-exit: exit after TLS error instead of retrying
        cmd = [
            openvpn_bin,
            '--config', config_path,
            '--dev', 'null',
            '--dev-type', 'tun',
            '--route-noexec',
            '--ifconfig-noexec',
            '--connect-timeout', str(timeout),
            '--hand-window', str(timeout),
            '--verb', '3',
            '--connect-retry-max', '1',
            '--tls-exit',
        ]
        
        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 5,  # extra 5s buffer for process cleanup
            )
            output = proc.stdout + proc.stderr
        except subprocess.TimeoutExpired as e:
            output = ''
            if e.stdout:
                output += e.stdout if isinstance(e.stdout, str) else e.stdout.decode('utf-8', errors='ignore')
            if e.stderr:
                output += e.stderr if isinstance(e.stderr, str) else e.stderr.decode('utf-8', errors='ignore')
            result['error'] = 'Process timeout'
        
        result['elapsed'] = time.time() - start
        
        # Parse output for each stage
        if 'TLS: Initial packet from' in output:
            result['initial_packet'] = True
            
        if 'VERIFY OK: depth=0' in output:
            result['cert_verified'] = True
            # Extract CN
            for line in output.splitlines():
                if 'VERIFY OK: depth=0' in line and 'CN=' in line:
                    cn_part = line.split('CN=')[-1].strip()
                    result['cert_cn'] = cn_part
                    break
        
        # Key negotiation success indicators
        if 'Control Channel:' in output or 'Data Channel:' in output:
            result['key_negotiated'] = True
            
        # Full connection
        if 'Initialization Sequence Completed' in output:
            result['connected'] = True
            result['key_negotiated'] = True  # implied
            
        # Detect specific errors
        if 'TLS key negotiation failed' in output:
            result['error'] = 'TLS key negotiation timeout (DPI block likely)'
        elif 'TLS Error: TLS handshake failed' in output:
            result['error'] = 'TLS handshake failed'
        elif 'Connection refused' in output:
            result['error'] = 'Connection refused'
        elif 'Network is unreachable' in output:
            result['error'] = 'Network unreachable'
        elif not result['error']:
            if not result['initial_packet']:
                result['error'] = 'No response from server'
    
    except Exception as e:
        result['error'] = str(e)
    finally:
        # Cleanup temp files
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except:
            pass
    
    return result

def draw_banner():
    banner = f"""
{MAGENTA}{BOLD}┌────────────────────────────────────────────────────────┐
│                 🛡️  VPN CONNECTIVITY CHECKER             │
│          Testing App APIs & VPN Gate OVPN Servers      │
└────────────────────────────────────────────────────────┘{RESET}
"""
    print(banner)

# Helper to parse proxies in protocol://ip:port format
def parse_proxy_line(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    try:
        if "://" in line:
            protocol, rest = line.split("://", 1)
            if ":" in rest:
                ip, port = rest.split(":", 1)
                return {'protocol': protocol.lower(), 'ip': ip, 'port': int(port)}
        else:
            if ":" in line:
                ip, port = line.split(":", 1)
                return {'protocol': 'http', 'ip': ip, 'port': int(port)}
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
            context = ssl.create_default_context()
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
            context = ssl.create_default_context()
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
    # Try via proxies first (prevents DNS resolution hang for the mirror domain if it is blocked)
    if working_proxies:
        for p in working_proxies:
            try:
                content = socket_get_via_proxy(p, mirror_url, timeout=timeout)
                if content and "*vpn_servers" in content:
                    return content
            except:
                pass
                
    # Try direct as fallback
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
    
    # Try sites.aspx via proxy first
    if working_proxies:
        for p in working_proxies:
            print(f"{YELLOW}[*] Fetching mirror sites directory via proxy {p['protocol'].upper()} {p['ip']}:{p['port']}...{RESET}")
            sites_html = socket_get_via_proxy(p, sites_url, timeout=4)
            if sites_html:
                break
                
    # Try sites.aspx directly as a fallback
    if not sites_html:
        print(f"{YELLOW}[*] Fetching mirror sites directory directly...{RESET}")
        sites_html = socket_get_direct(sites_url, timeout=4)
                
    mirrors = []
    if sites_html:
        # Regex to find http://<host>:<port> mirror links
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
        
        # Limit to top 15 mirrors
        mirrors_to_try = mirrors[:15]
        
        csv_data = None
        # Non-blocking ThreadPoolExecutor: returns instantly on the first success
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
                    # Shutdown in background immediately without blocking current return
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

# Parse CSV data from VPN Gate API
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
                
                # Default ports & protocol
                port = 1194
                proto = 'udp'
                
                # Parse server IP, port, and protocol from configuration details
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

# OpenVPN Handshake over UDP
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

# OpenVPN Handshake over TCP
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

# HTTP Target Check (For Option 4)
def test_http_endpoint(name, url, timeout=4):
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

# Run Check on App APIs (Option 4)
def run_app_api_check(timeout=4):
    print(f"{CYAN}{BOLD}┌──────────────────────────────────────────────┐")
    print(f"│       TESTING FREE VPN APP BACKEND APIs      │")
    print(f"└──────────────────────────────────────────────┘{RESET}")
    print(f"Testing {len(VPN_TARGETS)} endpoints directly on your internet connection...\n")
    
    print(f"{BOLD}{'VPN App / Service':<30} {'Status':<15} {'Latency':<12} {'Response Info':<30}{RESET}")
    print("-" * 88)
    
    working = 0
    start = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(test_http_endpoint, t['name'], t['url'], timeout): t 
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
    print(f"\n{BOLD}App Check Finished in {elapsed:.2f}s | Working APIs: {GREEN}{working}/{len(VPN_TARGETS)}{RESET}\n")

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

# VPN Gate check worker (Phase 1: fast packet scan)
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
            
            # Clear progress and print working server
            sys.stdout.write("\r" + " " * 80 + "\r")
            print(
                f"{GREEN}[✓] OpenVPN {proto.upper()} {ip}:{port} "
                f"({server['country_short']}) port open! Latency: {latency:.1f}ms{RESET}"
            )
            
        draw_vpngate_progress(checked_count, len(servers_to_test), working_count)

# Phase 2: Deep test worker using openvpn binary
def deep_test_worker(server, openvpn_bin, timeout):
    ip = server['ip']
    port = server['port']
    proto = server['proto']
    config_data = server['config_data']
    country = server.get('country_short', '??')
    
    results = []
    
    # Test 1: Original protocol (as in config)
    sys.stdout.write("\r" + " " * 100 + "\r")
    print(f"{YELLOW}  [→] Deep testing {proto.upper()} {ip}:{port} ({country})...{RESET}")
    
    r1 = deep_test_openvpn(config_data, openvpn_bin, timeout=timeout)
    r1['proto'] = proto
    r1['ip'] = ip
    r1['port'] = port
    results.append(r1)
    
    # Print result for this protocol
    _print_deep_result(server, r1)
    
    # Test 2: Alternate protocol (if original was UDP, try TCP and vice versa)
    alt_proto = 'tcp' if proto == 'udp' else 'udp'
    alt_config = generate_alt_proto_config(config_data, alt_proto)
    
    sys.stdout.write("\r" + " " * 100 + "\r")
    print(f"{YELLOW}  [→] Deep testing {alt_proto.upper()} {ip}:{port} ({country})...{RESET}")
    
    r2 = deep_test_openvpn(alt_config, openvpn_bin, timeout=timeout)
    r2['proto'] = alt_proto
    r2['ip'] = ip
    r2['port'] = port
    results.append(r2)
    
    _print_deep_result(server, r2)
    
    # Determine best result
    for r in results:
        if r['connected'] or r['key_negotiated']:
            with stats_lock:
                entry = dict(server)
                entry['deep_result'] = r
                entry['deep_proto'] = r['proto']
                if r['connected']:
                    entry['deep_status'] = 'CONNECTED'
                else:
                    entry['deep_status'] = 'KEY_OK'
                deep_verified_servers.append(entry)
            return  # only need the best one
    
    # If cert verified on either, still note it (but NOT as verified)
    for r in results:
        if r['cert_verified']:
            with stats_lock:
                entry = dict(server)
                entry['deep_result'] = r
                entry['deep_proto'] = r['proto']
                entry['deep_status'] = 'CERT_ONLY'
                deep_verified_servers.append(entry)
            return

def _print_deep_result(server, r):
    ip = r['ip']
    port = r['port']
    proto = r['proto']
    country = server.get('country_short', '??')
    
    pkt = f"{GREEN}✓{RESET}" if r['initial_packet'] else f"{RED}✗{RESET}"
    cert = f"{GREEN}✓{RESET}" if r['cert_verified'] else f"{RED}✗{RESET}"
    key = f"{GREEN}✓{RESET}" if r['key_negotiated'] else f"{RED}✗{RESET}"
    conn = f"{GREEN}✓{RESET}" if r['connected'] else f"{RED}✗{RESET}"
    
    if r['connected']:
        status = f"{GREEN}{BOLD}FULLY CONNECTED{RESET}"
    elif r['key_negotiated']:
        status = f"{GREEN}Key Negotiated{RESET}"
    elif r['cert_verified']:
        status = f"{YELLOW}Cert OK, Key Failed{RESET}"
    elif r['initial_packet']:
        status = f"{RED}Packet OK, TLS Failed{RESET}"
    else:
        status = f"{RED}No Response{RESET}"
    
    cn = f" CN={r['cert_cn']}" if r['cert_cn'] else ""
    err = f" | {r['error']}" if r['error'] and not r['connected'] else ""
    
    print(
        f"    {proto.upper()} {ip}:{port} ({country}) "
        f"[Pkt:{pkt} Cert:{cert} Key:{key} Conn:{conn}] "
        f"→ {status}{cn}{err} ({r['elapsed']:.1f}s)"
    )

# Run Check on VPN Gate (Option 1)
def run_vpngate_check(threads=40, timeout=3, max_check=100, local_file=None, deep_timeout=20):
    global checked_count, working_count, start_time, servers_to_test, deep_verified_servers
    
    checked_count = 0
    working_count = 0
    working_ovpn_servers.clear()
    deep_verified_servers.clear()
    
    # Detect openvpn binary for Phase 2
    openvpn_bin = find_openvpn_binary()
    
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
            
    # Fallback to network download
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
    if openvpn_bin:
        print(f"{GREEN}[✓] Found openvpn binary: {openvpn_bin}{RESET}")
    else:
        print(f"{YELLOW}[!] openvpn binary not found. Phase 2 deep test will be skipped.{RESET}")
        print(f"{YELLOW}    Install OpenVPN to enable full TLS handshake verification.{RESET}")
    
    servers_to_test = servers[:max_check]
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 1: Fast packet scan
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────────────┐")
    print(f"│   PHASE 1: FAST PORT SCAN (OpenVPN Packet Test)     │")
    print(f"└──────────────────────────────────────────────────────┘{RESET}")
    print(f"Testing {len(servers_to_test)} servers with quick handshake packet ({threads} threads, {timeout}s timeout)...")
    print(f"This finds servers with {BOLD}open ports{RESET} that respond to OpenVPN packets.\n")
    
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
        print(f"\n\n{RED}[!] Phase 1 scan cancelled by user.{RESET}")
        
    print("\n")
    phase1_elapsed = time.time() - start_time
    
    print(f"{CYAN}{BOLD}── Phase 1 Results ──{RESET}")
    print(f"Servers Checked: {checked_count} | Ports Open: {GREEN}{working_count}{RESET} | Time: {phase1_elapsed:.1f}s")
    
    if working_ovpn_servers:
        working_ovpn_servers.sort(key=lambda x: x.get('latency', 9999))
        
        print(f"\n{BOLD}{'Proto':<6} {'IP Address':<18} {'Port':<6} {'Latency':<10} {'Country':<15} {'Speed (Mbps)':<12}{RESET}")
        print("-" * 75)
        for s in working_ovpn_servers[:15]:
            speed_mbps = float(s['speed']) / 1000000 if s['speed'].isdigit() else 0
            print(f"{s['proto'].upper():<6} {s['ip']:<18} {s['port']:<6} {s['latency']:>6.1f}ms   {s['country'][:13]:<15} {speed_mbps:>6.1f} Mbps")
    else:
        print(f"\n{RED}[✗] No servers with open ports found. Phase 2 skipped.{RESET}\n")
        return
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 2: Deep TLS handshake test using openvpn binary
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    if not openvpn_bin:
        # Save configs from Phase 1 only
        _save_working_configs(working_ovpn_servers, 'working_ovpn_configs')
        return
    
    phase2_candidates = list(working_ovpn_servers)  # copy
    
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────────────┐")
    print(f"│   PHASE 2: DEEP TLS TEST (Full OpenVPN Handshake)   │")
    print(f"└──────────────────────────────────────────────────────┘{RESET}")
    print(f"Testing {len(phase2_candidates)} servers with real openvpn binary ({deep_timeout}s timeout per protocol)...")
    print(f"Each server tested on BOTH {BOLD}UDP{RESET} and {BOLD}TCP{RESET} protocols.")
    print(f"Checks: Packet → Certificate → Key Negotiation → Full Connection\n")
    
    phase2_start = time.time()
    
    # Run deep tests with limited concurrency (each spawns openvpn process)
    deep_threads = min(5, len(phase2_candidates))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=deep_threads) as executor:
            futures = {
                executor.submit(deep_test_worker, s, openvpn_bin, deep_timeout): s
                for s in phase2_candidates
            }
            for future in concurrent.futures.as_completed(futures):
                pass
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Phase 2 cancelled by user.{RESET}")
    
    phase2_elapsed = time.time() - phase2_start
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINAL SUMMARY
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    total_elapsed = time.time() - start_time
    
    print(f"\n{CYAN}{BOLD}┌──────────────────────────────────────────────────────┐")
    print(f"│                FINAL VPN GATE SUMMARY                │")
    print(f"└──────────────────────────────────────────────────────┘{RESET}")
    print(f"Phase 1 (Port Scan):    {checked_count} checked, {GREEN}{working_count} open{RESET} ({phase1_elapsed:.1f}s)")
    
    connected = [s for s in deep_verified_servers if s.get('deep_status') == 'CONNECTED']
    key_ok = [s for s in deep_verified_servers if s.get('deep_status') == 'KEY_OK']
    cert_only = [s for s in deep_verified_servers if s.get('deep_status') == 'CERT_ONLY']
    
    print(f"Phase 2 (Deep Test):    {len(phase2_candidates)} tested ({phase2_elapsed:.1f}s)")
    print(f"  Fully Connected:      {GREEN}{BOLD}{len(connected)}{RESET}")
    print(f"  Key Negotiated:       {GREEN}{len(key_ok)}{RESET}")
    print(f"  Cert Only (blocked):  {YELLOW}{len(cert_only)}{RESET}")
    print(f"Total Time:             {total_elapsed:.1f}s")
    
    # Save configs: prioritize connected > key_ok > cert_only > phase1_only
    config_dir = 'working_ovpn_configs'
    os.makedirs(config_dir, exist_ok=True)
    
    # Clear old configs
    for f in os.listdir(config_dir):
        if f.startswith('vpngate_') and f.endswith('.ovpn'):
            try:
                os.remove(os.path.join(config_dir, f))
            except:
                pass
    
    if connected or key_ok:
        best_servers = connected + key_ok
        print(f"\n{BOLD}{GREEN}Usable OpenVPN Servers:{RESET}")
        print(f"{BOLD}{'Status':<16} {'Proto':<6} {'IP Address':<18} {'Port':<6} {'Country':<12} {'Speed (Mbps)':<12}{RESET}")
        print("-" * 75)
        saved_count = 0
        for s in best_servers:
            speed_mbps = float(s['speed']) / 1000000 if s['speed'].isdigit() else 0
            deep_proto = s.get('deep_proto', s['proto'])
            status_str = f"{GREEN}CONNECTED{RESET}" if s['deep_status'] == 'CONNECTED' else f"{CYAN}KEY OK{RESET}"
            print(f"{status_str:<16} {deep_proto.upper():<6} {s['ip']:<18} {s['port']:<6} {s['country'][:10]:<12} {speed_mbps:>6.1f} Mbps")
            
            # Save config (with the working protocol)
            config_to_save = s['config_data']
            if deep_proto != s['proto']:
                config_to_save = generate_alt_proto_config(s['config_data'], deep_proto)
            
            filename = f"vpngate_{s['country_short']}_{deep_proto}_{s['ip']}_{s['port']}.ovpn"
            filepath = os.path.join(config_dir, filename)
            try:
                with open(filepath, 'w') as f:
                    f.write(config_to_save)
                saved_count += 1
            except:
                pass
        
        print(f"\n{GREEN}[✓] Saved {saved_count} verified .ovpn profiles in: {BOLD}{config_dir}/{RESET}")
        print(f"    These configs passed full TLS handshake and should work in OpenVPN Connect.")
    elif cert_only:
        print(f"\n{YELLOW}[!] All servers passed certificate verification but TLS key negotiation failed.{RESET}")
        print(f"    This typically means your ISP's DPI is blocking OpenVPN after the TLS handshake.")
        print(f"    Suggestions:")
        print(f"    • Try obfuscated VPN protocols (e.g., Geph, Psiphon, Tor with bridges)")
        print(f"    • Use VPN over HTTPS/Websocket tunneling")
        print(f"    • Try Shadowsocks or V2Ray protocols instead")
        # Still save phase 1 configs as reference
        _save_working_configs(working_ovpn_servers, config_dir)
    else:
        print(f"\n{RED}[✗] No servers passed deep TLS testing.{RESET}")
        _save_working_configs(working_ovpn_servers, config_dir)

def _save_working_configs(servers, config_dir):
    """Save .ovpn config files for servers that passed Phase 1 port scan."""
    os.makedirs(config_dir, exist_ok=True)
    saved_count = 0
    for s in servers:
        filename = f"vpngate_{s['country_short']}_{s['proto']}_{s['ip']}_{s['port']}.ovpn"
        filepath = os.path.join(config_dir, filename)
        try:
            with open(filepath, 'w') as f:
                f.write(s['config_data'])
            saved_count += 1
        except:
            pass
    if saved_count:
        print(f"\n{GREEN}[✓] Saved {saved_count} .ovpn profiles (port-scan only) in: {BOLD}{config_dir}/{RESET}")
        print(f"    Note: These passed port scan only, not full TLS verification.")

def main():
    parser = argparse.ArgumentParser(description="VPN Gate OpenVPN Scanner & App API Connectivity Check")
    parser.add_argument('--mode', choices=['all', 'apps', 'vpngate'], default=None, help="Check mode")
    parser.add_argument('--threads', type=int, default=50, help="Threads for Phase 1 VPN Gate checking (default: 50)")
    parser.add_argument('--limit', type=int, default=120, help="Max VPN Gate servers to check (default: 120)")
    parser.add_argument('--timeout', type=int, default=3, help="Phase 1 connection timeout in seconds (default: 3)")
    parser.add_argument('--deep-timeout', type=int, default=20, help="Phase 2 deep test timeout per protocol (default: 20)")
    parser.add_argument('--vpngate-file', default=None, help="Path to local VPN Gate CSV file (offline mode)")
    args = parser.parse_args()
    
    draw_banner()
    
    mode = args.mode
    if not mode:
        print(f"{BOLD}Select check mode:{RESET}")
        print(" [1] Check Free VPN App APIs (Proton, Windscribe, WARP, Tor, etc.)")
        print(" [2] Check VPN Gate OpenVPN Servers (2-Phase: Port Scan + Deep TLS Test)")
        print(" [3] Check Both")
        try:
            choice = input(f"{BOLD}Enter choice [1-3] (default 3): {RESET}").strip()
            if choice == '1':
                mode = 'apps'
            elif choice == '2':
                mode = 'vpngate'
            else:
                mode = 'all'
        except KeyboardInterrupt:
            print("\nExiting.")
            sys.exit(0)
            
    if mode in ('apps', 'all'):
        run_app_api_check(timeout=4)
        
    if mode in ('vpngate', 'all'):
        run_vpngate_check(
            threads=args.threads,
            timeout=args.timeout,
            max_check=args.limit,
            local_file=args.vpngate_file,
            deep_timeout=args.deep_timeout,
        )

if __name__ == '__main__':
    main()
