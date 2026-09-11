import re
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", "tiny.cc"}
SUSPICIOUS_TLDS = {".xyz", ".top", ".work", ".click", ".gq", ".fit", ".monster", ".tk", ".ml", ".cf", ".ga", ".club", ".vip", ".cam"}
BRAND_KEYWORDS = {"paypal", "bank", "amazon", "apple", "microsoft", "google", "netflix", "wellsfargo", "chase", "binance"}
LOGIN_PATHS = {"login", "signin", "verify", "account", "update", "banking", "secure", "auth", "credential", "checkout"}

IP_REGEX = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

def analyze_url(url_str: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    findings = []
    indicators = []
    
    parse_target = url_str if "://" in url_str else f"http://{url_str}"
    
    try:
        parsed = urlparse(parse_target)
        host = parsed.netloc.split(":")[0].lower() if parsed.netloc else ""
        path = parsed.path.lower()
        scheme = parsed.scheme.lower()
        
        if scheme == "http":
            findings.append("URL uses unencrypted HTTP protocol instead of HTTPS.")
            
        if IP_REGEX.match(host):
            findings.append(f"Host uses raw IP address ('{host}') rather than a registered domain name.")
            
        if host in SHORTENER_DOMAINS:
            findings.append("URL uses a domain shortener service which hides the true destination.")
            
        subdomains = host.split(".")
        if len(subdomains) >= 4:
            findings.append(f"Excessive subdomains detected ({len(subdomains)-2} subdomains), often used in phishing links.")
            
        for tld in SUSPICIOUS_TLDS:
            if host.endswith(tld):
                findings.append(f"Domain uses high-risk top-level domain ('{tld}').")
                break
                
        if len(host) > 30:
            findings.append("Unusually long domain name.")
            
        if "@" in url_str:
            findings.append("URL contains '@' symbol, which can mask the true destination host.")
            
        if "xn--" in host or "%" in url_str:
            findings.append("URL contains encoded or punycode characters (potential homograph attack).")
            
        for brand in BRAND_KEYWORDS:
            if brand in url_str.lower() and not host.endswith(f"{brand}.com") and not host.endswith(f"{brand}.org"):
                findings.append(f"URL references brand '{brand}' outside of the official brand domain.")
                break
                
        for keyword in LOGIN_PATHS:
            if keyword in path:
                findings.append(f"URL path contains credential/login target term '{keyword}'.")
                break

    except Exception:
        findings.append("Malformed URL structure.")

    if findings:
        indicators.append({
            "name": "suspicious_url",
            "description": "Structural URL heuristics flagged suspicious patterns",
            "weight": 20
        })

    return indicators, findings
