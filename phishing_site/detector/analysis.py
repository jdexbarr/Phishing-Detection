import re
from bs4 import BeautifulSoup
import tldextract


URL_RE = re.compile(r'https?://[^\s\'">]+', re.IGNORECASE)
EMAIL_RE = re.compile(r'https?://\d{1,3}(?:\.\d{1,3}){3}', re.IGNORECASE)

SUSPICIOUS_TLDS = {
    "tk", "pw", "cf", "ga", "gq", "ml", "xyz", "top", "club", "online", "site", "website",
}
URGENT_WORDS = {
    "verify your account",
    "login to your account",
    "suspend",
    "update your information", 
    "security alert", 
    "confirm your identity",
    "urgent", 
    "update your payment", 
    "account locked", 
    "unauthorized access", 
    "password expired",
    "suspended",
    "verify identity", 
    "account verification", 
    "limited time", 
    "action required",
    "within 24 hours",
}

def extract_urls_from_html(html_content):

    links = []
    soup = BeautifulSoup(html_content, 'html.parser')

    for a in soup.find_all('a', href=True):
        links.append(a['href'])
    
    for j in URL_RE.findall(html_content):
        links.append(j)

    return list(set(links))


def analyze_threats(email_content, sender_name=None, sender_email=None):
    threats = []

    lower_text = email_content.lower()

    links = extract_urls_from_html(email_content)
    suspicious_links = []
    for url in links:
        features = {}

        features["has_ip"] = bool(EMAIL_RE.search(url))
        tx = tldextract.extract(url)
        tld = tx.suffix.lower()
        features["suspicious_tld"] = tld in SUSPICIOUS_TLDS
        features["long_url"] = len(url) > 100


        score = sum(int(v) for v in features.values())
        if score >= 1:
            suspicious_links.append(url)
    
    if suspicious_links:
        threats.append({
            "type": "suspicious_links detected",
            "details": suspicious_links,
        })

    for phrase in URGENT_WORDS:
        if phrase in lower_text:
            threats.append({
                "type": "urgent_language detected",
                "details": [phrase],
            })
            break

    BRANDS = ["paypal", "bank of america", "wells fargo", "chase", "amazon", "google", "microsoft", "apple"]
    brand_hit = [i for i in BRANDS if i in lower_text]
    if brand_hit:
        threats.append({
            "type": "Possible impersonationd detected",
            "details": brand_hit,
        })
    
    return threats

