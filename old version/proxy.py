import requests
import concurrent.futures

# تنظیمات
TARGET_URL = "https://www.google.com"
TIMEOUT = 7 
THREADS = 100 

def check_proxy(proxy):
    # سعی می‌کنیم هم به عنوان SOCKS5 و هم HTTP تست کنیم
    protocols = [f"socks5://{proxy}", f"http://{proxy}"]
    
    for proto in protocols:
        proxy_dict = {"http": proto, "https": proto}
        try:
            # تست اتصال
            response = requests.get(TARGET_URL, proxies=proxy_dict, timeout=TIMEOUT)
            if response.status_code == 200:
                ping = round(response.elapsed.total_seconds() * 1000)
                return proxy, ping, proto
        except Exception:
            continue
    return None

def main():
    input_file = "proxies.txt"
    
    try:
        with open(input_file, "r") as f:
            proxies = [line.strip() for line in f if line.strip() and ":" in line]
    except Exception as e:
        print(f"خطا در خواندن فایل: {e}")
        return

    if not proxies:
        print("لیست پروکسی‌ها خالی است یا فرمت صحیح (IP:Port) ندارد.")
        return

    print(f"شروع تست {len(proxies)} پروکسی... (لطفاً صبور باشید)")

    valid_count = 0
    with open("valid_proxies.txt", "w") as f_out:
        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            future_to_proxy = {executor.submit(check_proxy, p): p for p in proxies}
            
            for future in concurrent.futures.as_completed(future_to_proxy):
                result = future.result()
                if result:
                    p_url, ping, proto = result
                    valid_count += 1
                    print(f"[OK] {proto} | Ping: {ping}ms")
                    f_out.write(f"{proto}\n")

    print("-" * 30)
    print(f"پایان! {valid_count} پروکسی سالم پیدا و ذخیره شدند.")

if __name__ == "__main__":
    main()