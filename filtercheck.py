import requests
import concurrent.futures
import time

SITES_TO_CHECK = [
    # --- موتورهای جستجو و دانشنامه‌ها ---
    "https://www.google.com", "https://www.bing.com", "https://www.yahoo.com", "https://www.wikipedia.org",
    "https://www.britannica.com", "https://www.dictionary.com", "https://www.thesaurus.com",
    "https://www.timeanddate.com", "https://www.weather.com", "https://www.accuweather.com", "https://www.imdb.com", "https://lineageos.org/", ""
    # --- دنیای متن‌باز و لینوکس ---
    "https://www.ubuntu.com", "https://www.debian.org", "https://www.centos.org",
    "https://www.linux.org", "https://www.kernel.org", "https://www.freebsd.org",
    "https://www.openbsd.org", "https://www.archlinux.org", "https://www.fedoraproject.org", "https://www.opensuse.org",
    # --- زبان‌های برنامه‌نویسی و تکنولوژی ---
    "https://www.python.org", "https://www.php.net", "https://www.rust-lang.org",
    "https://www.ruby-lang.org", "https://go.dev", "https://www.java.com",
    "https://www.scala-lang.org", "https://www.perl.org", "https://www.lua.org", "https://www.haskell.org",
    # --- سازمان‌های استاندارد و علمی ---
    "https://www.w3.org", "https://www.ieee.org", "https://www.acm.org",
    "https://www.icann.org", "https://www.iana.org", "https://www.ietf.org",
    "https://www.iso.org", "https://www.cern.ch", "https://www.nasa.gov", "https://www.esa.int",
    # --- ابزارها و نرم‌افزارهای کاربردی ---
    "https://www.blender.org", "https://www.gimp.org", "https://www.videolan.org",
    "https://www.libreoffice.org", "https://www.inkscape.org", "https://www.audacityteam.org",
    "https://www.virtualbox.org", "https://www.wireshark.org", "https://www.filezilla-project.org", "https://www.7-zip.org",
    # --- دانشگاه‌های معتبر جهانی ---
    "https://www.mit.edu", "https://www.stanford.edu", "https://www.harvard.edu",
    "https://www.caltech.edu", "https://www.cam.ac.uk", "https://www.ox.ac.uk",
    "https://www.princeton.edu", "https://www.yale.edu", "https://www.columbia.edu", "https://www.cornell.edu",
    # --- پایگاه‌های داده و سرورها ---
    "https://www.mysql.com", "https://www.postgresql.org", "https://www.mariadb.org",
    "https://www.sqlite.org", "https://www.redis.io", "https://www.mongodb.com",
    "https://www.apache.org", "https://www.nginx.org", "https://www.lighttpd.net", "https://www.haproxy.org",
    # --- شرکت‌های سخت‌افزاری و الکترونیکی ---
    "https://www.asus.com", "https://www.msi.com", "https://www.gigabyte.com",
    "https://www.lenovo.com", "https://www.samsung.com", "https://www.sony.com",
    "https://www.lg.com", "https://www.panasonic.com", "https://www.philips.com", "https://www.bosch.com",
    # --- فریم‌ورک‌ها و مدیریت محتوا ---
    "https://react.dev", "https://vuejs.org", "https://angular.io",
    "https://jquery.com", "https://bootstrap.com", "https://wordpress.org",
    "https://joomla.org", "https://drupal.org", "https://moodle.org", "https://magento.com",
    # --- بازی‌سازی و گرافیک ---
    "https://unity.com", "https://www.unrealengine.com", "https://godotengine.org",
    "https://www.khronos.org", "https://www.opengl.org", "https://vulkan.org",
    "https://www.nintendo.com", "https://www.playstation.com", "https://www.xbox.com", "https://www.ea.com"
    # --- ابزارهای هوش مصنوعی و مدل‌های زبانی (LLMs & AI) ---
    "https://chatgpt.com",               # OpenAI ChatGPT
    "https://api.openai.com",            # OpenAI API
    "https://claude.ai",                 # Anthropic Claude
    "https://api.anthropic.com",         # Anthropic API
    "https://gemini.google.com",         # Google Gemini
    "https://aistudio.google.com",       # Google AI Studio
    "https://huggingface.co",            # Hugging Face
    "https://www.perplexity.ai",         # Perplexity
    "https://replicate.com",             # Replicate
    "https://mistral.ai",                # Mistral AI
    "https://cohere.com",                # Cohere
    "https://www.together.ai",           # Together AI
    "https://platform.openai.com",       # OpenAI Platform
    "https://discord.com",               # Discord (Midjourney/Bots)

    # --- زیردامنه‌های کاربردی و زیرساختی گوگل (Google Ecosystem) ---
    "https://mail.google.com",           # Gmail
    "https://drive.google.com",          # Google Drive
    "https://docs.google.com",           # Google Docs
    "https://meet.google.com",           # Google Meet
    "https://calendar.google.com",       # Google Calendar
    "https://cloud.google.com",          # Google Cloud
    "https://console.cloud.google.com",  # Google Cloud Console
    "https://developers.google.com",     # Google Developers
    "https://fonts.googleapis.com",      # Google Fonts (CDN)
    "https://ajax.googleapis.com",       # Google Hosted Libraries (CDN)
    "https://analytics.google.com",      # Google Analytics
    "https://play.google.com",           # Google Play
    "https://developer.android.com",     # Android Developers
    "https://translate.google.com",      # Google Translate
    "https://scholar.google.com",        # Google Scholar
    "https://colab.research.google.com"  # Google Colab
]

# تنظیم تایم‌اوت: 3 ثانیه برای اتصال (Connect)، 5 ثانیه برای دریافت پاسخ (Read)
TIMEOUT = (3, 5) 
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
}

def check_site(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
        if response.status_code in [200, 301, 302, 303, 307, 308]:
            return {"url": url, "status": "باز (Available)", "code": response.status_code}
        else:
            return {"url": url, "status": f"خطا (HTTP {response.status_code})", "code": response.status_code}
            
    except requests.exceptions.ReadTimeout:
        return {"url": url, "status": "تایم‌اوت دریافت (Read Timeout)", "code": "N/A"}
    except requests.exceptions.ConnectTimeout:
        return {"url": url, "status": "تایم‌اوت اتصال (Connect Blocked/Dropped)", "code": "N/A"}
    except requests.exceptions.SSLError:
        return {"url": url, "status": "خطای SSL (احتمال شنود یا مسدودسازی)", "code": "N/A"}
    except requests.exceptions.ConnectionError:
        return {"url": url, "status": "کانکشن ریست/فیلتر (Connection Error)", "code": "N/A"}
    except Exception as e:
        return {"url": url, "status": "خطای ناشناخته", "code": "N/A"}

def main():
    print(f"در حال بررسی وضعیت دسترسی به {len(SITES_TO_CHECK)} سایت...")
    print("-" * 60)
    
    accessible_count = 0
    blocked_count = 0
    start_time = time.time()
    
    # استفاده از as_completed برای چاپ در لحظه نتایج
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        # ارسال کارها به تردها
        future_to_url = {executor.submit(check_site, url): url for url in SITES_TO_CHECK}
        
        # هر سایتی که زودتر جواب داد (یا تایم‌اوت شد) را همان لحظه پردازش و چاپ کن
        for future in concurrent.futures.as_completed(future_to_url):
            res = future.result()
            status_text = res["status"]
            
            if "باز" in status_text:
                print(f"[✅] {res['url']:<35} -> {status_text}")
                accessible_count += 1
            else:
                print(f"[❌] {res['url']:<35} -> {status_text}")
                blocked_count += 1

    end_time = time.time()
    
    print("\n" + "=" * 60)
    print("خلاصه گزارش:")
    print(f"کل سایت‌ها: {len(SITES_TO_CHECK)}")
    print(f"سایت‌های در دسترس: {accessible_count}")
    print(f"سایت‌های مسدود/خطادار/تایم‌اوت: {blocked_count}")
    print(f"زمان اجرای تست: {round(end_time - start_time, 2)} ثانیه")
    
    if accessible_count >= 90:
        print("\nوضعیت کلی: 🟢 اینترنت بین‌الملل پایدار و بدون اختلال است.")
    elif 50 <= accessible_count < 90:
        print("\nوضعیت کلی: 🟡 اختلال نسبی در روتینگ یا پکت‌لاس وجود دارد.")
    else:
        print("\nوضعیت کلی: 🔴 اختلال شدید، قطعی ارتباطات بین‌الملل یا اینترنت ملی (Intranet).")

if __name__ == "__main__":
    main()