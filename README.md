# Proxy Connectivity Checker

A multi-threaded, high-performance, zero-dependency Python script to verify the connectivity, latency, and anonymity of free proxies from the [free-proxy-list](https://github.com/iplocate/free-proxy-list) repository.

## Features

- **Multi-threaded**: Processes thousands of proxies concurrently using Python's thread pool.
- **Zero Dependencies**: Built entirely using Python's standard library (no need to `pip install` any third-party library).
- **Comprehensive Protocol Support**: Implements low-level socket handshakes for **HTTP**, **HTTPS (CONNECT)**, **SOCKS4**, and **SOCKS5**.
- **Flexible Targets**: Test proxies against Cloudflare connectivity, Google bypass capability, GeoIP location resolution, or custom URLs.
- **GeoIP Lookup & Anonymity Verification**: Automatically resolves country, city, and ISP for working proxies when checking against `ip-api.com`.
- **Live Terminal UI**: Shows real-time progress bar, speed (proxies/sec), and working count.
- **Auto-Save**: Saves verified working proxies sorted by latency to a file (default `working_proxies.txt`).

## How to Run

1. Run the script:
   ```bash
   python3 check.py
   ```

2. The script will prompt you to:
   - Select proxy list type to download (All, HTTP, HTTPS, SOCKS4, SOCKS5).
   - Select the target URL to test connectivity (Cloudflare, GeoIP, Google, or Custom URL).

### Command Line Options

You can also run the checker directly from the command line with options:

```bash
# Check SOCKS5 proxies against Google with 100 threads and 3 seconds timeout
python3 check.py --type socks5 --target https://www.google.com/ --threads 100 --timeout 3 --output working_socks5.txt

# Check HTTP proxies with default settings
python3 check.py --type http
```

### Options Reference
- `--type`: `all`, `http`, `https`, `socks4`, `socks5` (default: asks interactively)
- `--target`: URL to check connectivity (default: asks interactively)
- `--threads`: Number of concurrent threads (default: `80`)
- `--timeout`: Timeout in seconds for each proxy connection (default: `4`)
- `--output`: File name to save working proxies to (default: `working_proxies.txt`)