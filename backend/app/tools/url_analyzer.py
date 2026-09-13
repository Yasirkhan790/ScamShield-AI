import ipaddress
import re
from urllib.parse import urlparse

from app.models.analysis import Indicator

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
}

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "security",
    "account",
    "password",
    "wallet",
    "payment",
    "update",
    "confirm",
    "unlock",
    "suspend",
    "bank",
}

KNOWN_BRANDS = {
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "netflix",
}


def normalize_url(raw_url: str) -> tuple[str, bool]:
    value = raw_url.strip()
    explicit_scheme = re.match(r"^([a-z][a-z0-9+.-]*):\/\/", value, re.IGNORECASE)
    if explicit_scheme and explicit_scheme.group(1).lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    has_scheme = bool(re.match(r"^https?://", value, re.IGNORECASE))
    if not has_scheme:
        value = f"http://{value}"
    return value, has_scheme


def _base_domain_label(host: str) -> str:
    labels = [part for part in host.lower().strip(".").split(".") if part]
    if len(labels) < 2:
        return labels[0] if labels else ""
    return labels[-2]


def _is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(raw_url: str) -> tuple[str, str, bool, list[Indicator]]:
    normalized_url, had_scheme = normalize_url(raw_url)
    parsed = urlparse(normalized_url)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported")

    host = (parsed.hostname or "").lower().strip(".")
    if not host:
        raise ValueError("Enter a valid URL with a hostname")

    uses_https = parsed.scheme.lower() == "https"
    indicators: list[Indicator] = []

    def add(code: str, name: str, description: str, severity: str, weight: int) -> None:
        if not any(item.code == code for item in indicators):
            indicators.append(
                Indicator(
                    code=code,
                    name=name,
                    description=description,
                    severity=severity,
                    weight=weight,
                )
            )

    if not had_scheme:
        add(
            "missing_scheme",
            "Missing URL scheme",
            "The submitted address did not specify HTTP or HTTPS, so ScamShield treated it as HTTP for local analysis.",
            "low",
            5,
        )

    if not uses_https:
        add(
            "no_https",
            "No HTTPS",
            "The URL does not use HTTPS. This is a security signal, but it does not by itself prove maliciousness.",
            "medium",
            10,
        )

    if _is_ip_address(host):
        add(
            "ip_address_host",
            "IP-address URL",
            "The URL uses an IP address instead of a normal domain name, a pattern sometimes used to obscure destination identity.",
            "high",
            20,
        )

    labels = [part for part in host.split(".") if part]
    if len(labels) >= 5:
        add(
            "excessive_subdomains",
            "Excessive subdomains",
            "The hostname contains many subdomain levels, which can make the true destination harder to notice.",
            "medium",
            10,
        )

    if parsed.username or parsed.password or "@" in raw_url.split("/", 3)[-1].split("?")[0]:
        add(
            "userinfo_obfuscation",
            "User-info obfuscation",
            "The URL contains user-info style syntax that can make the visible address misleading.",
            "high",
            20,
        )

    if "xn--" in host:
        add(
            "punycode_domain",
            "Punycode domain",
            "The hostname uses Punycode. Internationalized domains can be legitimate, but look-alike domains also use this technique.",
            "medium",
            15,
        )

    if "%" in parsed.path or "%" in parsed.query or host.count("-") >= 4:
        add(
            "unusual_characters",
            "Unusual URL characters",
            "The URL contains encoded or unusually repetitive characters that reduce readability.",
            "medium",
            10,
        )

    searchable = f"{host}{parsed.path}?{parsed.query}".lower()
    matched_keywords = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in searchable)
    if matched_keywords:
        shown = ", ".join(matched_keywords[:4])
        add(
            "suspicious_keywords",
            "Sensitive-action keywords",
            f"The URL contains terms such as {shown}, which are common in account and credential workflows and deserve verification.",
            "medium",
            15,
        )

    if host in URL_SHORTENERS or any(host.endswith(f".{item}") for item in URL_SHORTENERS):
        add(
            "url_shortener",
            "URL shortening service",
            "The destination is hidden behind a shortening service, so the final domain is not visible from the submitted URL.",
            "medium",
            20,
        )

    if len(normalized_url) > 120:
        add(
            "long_url",
            "Unusually long URL",
            "The URL is long enough to make its destination and parameters harder to inspect manually.",
            "low",
            10,
        )

    base_label = _base_domain_label(host)
    host_labels = set(labels[:-2] if len(labels) >= 2 else labels)
    path_tokens = set(re.findall(r"[a-z0-9]+", parsed.path.lower()))
    brand_mentions = (host_labels | path_tokens) & KNOWN_BRANDS
    mismatched_brands = sorted(brand for brand in brand_mentions if brand not in base_label)
    if mismatched_brands:
        add(
            "domain_mismatch",
            "Possible domain mismatch",
            f"The URL mentions {', '.join(mismatched_brands[:2])} outside the apparent base domain. This can imitate a trusted brand without using its real domain.",
            "high",
            25,
        )

    if parsed.port and parsed.port not in {80, 443}:
        add(
            "unusual_port",
            "Unusual network port",
            f"The URL specifies port {parsed.port}, which is uncommon for ordinary public web links.",
            "low",
            5,
        )

    return normalized_url, host, uses_https, indicators
