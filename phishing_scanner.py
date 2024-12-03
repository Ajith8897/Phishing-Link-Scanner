import re
#regular expression for validating web browsers http or htpps
import requests
#if http requests to check url wheather having ssl or not
from urllib.parse import urlparse
#parse means url break down to domains,subdomains,path
PHISHING_BLACKLIST = [
    "example-phishing.com",
    "malicious-site.net"
]
#if any url match this domains its is in high risk and detected as malicious software
def is_blacklisted(url):
    """Check if URL is in the blacklist."""
    domain = urlparse(url).netloc
    return domain in PHISHING_BLACKLIST
#if any domain part of url and if any domain is extracted it will in blacklist
def has_suspicious_features(url):
    

    if len(url) >70:
        return False
#if more then 75 characters it will suspicious feature
   
    if "@" in url:
        return True
#some of them will use @ for fake urls

    domain_parts = urlparse(url).netloc.split(".")
    if len(domain_parts) > 3:
        return True
    
    #The url splits like domain subdomain example com


    if not url.startswith("https://"):
        return True
#if any url is not start with https .it will expand the url

    suspicious_keywords = ["verify", "secure", "update","http"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return True
#These words are used mainly in phising links
    return False
#if we dont find any words like keywords it will goes to false

def check_ssl_certificate(url):
    
    try:
        response = requests.get(url, timeout=5)
        return response.url.startswith("https://")
    except Exception:
        return False
#it will check if legitimate then browser side will check wheather request have ssl certifiacte or not 
def phishing_link_scanner(url):
   
    print(f"Scanning URL: {url}")

    if is_blacklisted(url):
        return "High Risk: URL found in blacklist!"
    #if url is black list shown in blacklist

    if has_suspicious_features(url):
        return "Moderate Risk: URL contains suspicious features."

    if not check_ssl_certificate(url):
        return "Low Risk: URL does not have a valid SSL certificate."

    return "Safe: No phishing characteristics detected."


if __name__ == "__main__":
    print("=== BrainWave Matrix Solutions Assignment===")
    print("Enter a URL Wheather it is Suspicious or Genuie :")
    while True:
        url = input("Enter a URL: ").strip()
        if url.lower() == "exit":
            print("Exiting the scanner. Stay safe online!")
            break
        if not re.match(r'^https?://', url):
            print("Invalid URL format. Please start with 'http://' or 'https://'")
            continue

        result = phishing_link_scanner(url)
        print(f"Scan Result of url: {result}")
        print("-" * 40)