import netutil

dnss = [
    "185.161.112.33",
    "185.161.112.34",
    "185.51.200.10",
    "185.231.182.126",
    "46.224.1.42",
    "194.225.62.80",
    "213.176.123.5",
    "91.99.101.12",
    "185.187.84.15",
    "37.156.145.229",
    "185.97.117.187",
    "185.113.59.253",
    "80.191.40.41",
    "194.225.73.141",
    "91.245.229.1",
    "185.51.200.50",
    "37.156.145.21",
    "217.218.155.155",
    "2.189.44.44",
    "2.188.21.131",
    "2.188.21.132",
    "81.91.144.116",
    "2.188.21.130",
    "92.119.56.162",
    "194.225.152.12",
]

domains = ["sotoon.ir", "google.com", "github.com"]
working_dnss = []

netutil.clear_caches()

for dns in dnss:
    print(f"Checking DNS {dns}:")
    all_ok = True
    for domain in domains:
        print(f"  A {domain} @{dns} -> ", end="", flush=True)
        ips = netutil.resolve_a(domain, server=dns, timeout=1.0)
        if ips:
            print(f"OK ({ips[0]})")
        else:
            print("Failed")
            all_ok = False

    if all_ok:
        working_dnss.append(dns)
    print()

print("====================================")
print("Working DNS servers (resolved all 3):")
print("====================================")
for dns in working_dnss:
    print(dns)
