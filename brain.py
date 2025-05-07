  import re
from urllib.parse import urlparse

# Example blacklist (you can expand this or load from a file)
blacklist = [
    "malicious.com",
    "phishingsite.net",
    "badlogin.ru"
]

shorteners = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"
]

def is_ip(url):
    try:
        host = urlparse(url).netloc
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
    except:
        return False

def uses_shortener(url):
    try:
        domain = urlparse(url).netloc
        return domain.lower() in shorteners
    except:
        return False

def is_blacklisted(url):
    for bad in blacklist:
        if bad in url:
            return True
    return False

def suspicious_url(url):
    warnings = []

    if len(url) > 75:
        warnings.append("⚠️ URL is very long")

    if '@' in url:
        warnings.append("⚠️ URL contains '@' symbol")

    if '-' in urlparse(url).netloc:
        warnings.append("⚠️ Domain contains '-'")

    if url.count('.') > 5:
        warnings.append("⚠️ URL contains many dots")

    if is_ip(url):
        warnings.append("⚠️ URL uses IP instead of domain")

    if uses_shortener(url):
        warnings.append("⚠️ URL uses a known URL shortener")

    if is_blacklisted(url):
        warnings.append("❌ URL is in the blacklist")

    return warnings

def scan_url(url):
    print(f"\n🔎 Scanning URL: {url}")
    issues = suspicious_url(url)
    if issues:
        for issue in issues:
            print(issue)
        print("🚨 Potential phishing link detected!")
    else:
        print("✅ URL looks safe (no basic flags raised)")

# Sample test
if __name__ == "__main__":
    while True:
        url = input("\nEnter a URL to scan (or 'exit'): ").strip()
        if url.lower() == "exit":
            break
        scan_url(url)
