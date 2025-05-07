import re


# Optional: Add your VirusTotal API Key here
VT_API_KEY = ''  # Add your key or leave blank to skip VirusTotal scan

# List of suspicious keywords often used in phishing URLs
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'account', 'update', 'secure', 'webscr', 'banking',
    'confirm', 'wp-admin', 'admin', 'ebayisapi', 'signin'
]

# Common URL shortening services
SHORTENING_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 't.co'
]

def is_shortened(url):
    return any(service in url for service in SHORTENING_SERVICES)

def contains_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

def has_ip_address(url):
    ip_pattern = r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}'
    return re.match(ip_pattern, url) is not None

def check_with_virustotal(url):
    if not VT_API_KEY:
        return "Skipped (API key not provided)"
    
    vt_url = "https://www.virustotal.com/api/v3/urls"
    try:
        # URL needs to be encoded in base64 without padding for VT v3 API
        response = requests.post(vt_url, headers={
            "x-apikey": VT_API_KEY
        }, data={"url": url})

        if response.status_code == 200:
            data_id = response.json()['data']['id']
            result = requests.get(f"{vt_url}/{data_id}", headers={"x-apikey": VT_API_KEY})
            stats = result.json()['data']['attributes']['last_analysis_stats']
            return f"VirusTotal Scan: Malicious={stats['malicious']}, Suspicious={stats['suspicious']}"
        else:
            return "VirusTotal query failed."
    except Exception as e:
        return f"Error querying VirusTotal: {e}"

def scan_url(url):
    print(f"\nScanning URL: {url}")
    issues = []

    if has_ip_address(url):
        issues.append("⚠️ Uses IP address instead of domain")

    if is_shortened(url):
        issues.append("⚠️ Uses a known URL shortener")

    if contains_suspicious_keywords(url):
        issues.append("⚠️ Contains phishing-related keywords")

    vt_result = check_with_virustotal(url)
    print("✔️ Basic checks done.")
    
    # Print results
    if issues:
        print("Phishing Indicators Detected:")
        for issue in issues:
            print(" -", issue)
    else:
        print("✅ No basic phishing indicators found.")

    print("🔍", vt_result)

# Example usage
if __name__ == "__main__":
    test_url = input("Enter a URL to scan: ")
    scan_url(test_url)
