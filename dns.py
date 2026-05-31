import os
import subprocess

dnss = [
'185.161.112.33',
'185.161.112.34',
'185.51.200.10',
'185.231.182.126',
'46.224.1.42',
'194.225.62.80',
'213.176.123.5',
'91.99.101.12',
'185.187.84.15',
'37.156.145.229',
'185.97.117.187',
'185.113.59.253',
'80.191.40.41',
'194.225.73.141',
'91.245.229.1',
'185.51.200.50',
'37.156.145.21',
'217.218.155.155',
'2.189.44.44',
'2.188.21.131',
'2.188.21.132',
'81.91.144.116',
'2.188.21.130',
'92.119.56.162',
'194.225.152.12',
]

domains = ['sotoon.ir', 'google.com', 'github.com']
working_dnss = []

for dns in dnss:
    print(f"Checking DNS {dns}:")
    all_ok = True
    for domain in domains:
        print(f"  dig +time=1 +short {domain} @{dns} -> ", end="", flush=True)
        try:
            res = subprocess.run(
                ['dig', '+time=1', '+tries=1', '+short', domain, f'@{dns}'],
                capture_output=True,
                text=True,
                timeout=2
            )
            output = res.stdout.strip()
            if res.returncode == 0 and output:
                first_line = output.split('\n')[0]
                print(f"OK ({first_line})")
            else:
                print("Failed")
                all_ok = False
        except Exception as e:
            print(f"Failed ({str(e)})")
            all_ok = False
    
    if all_ok:
        working_dnss.append(dns)
    print()

print("====================================")
print("Working DNS servers (resolved all 3):")
print("====================================")
for dns in working_dnss:
    print(dns)

