from urllib.parse import urlsplit, urlunsplit
import ipaddress
import re

# Well-known established global authority domains
TOP_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "wikipedia.org", "apple.com", "microsoft.com",
    "github.com", "amazon.com", "netflix.com", "reddit.com", "stackoverflow.com",
    "yahoo.com", "bing.com", "live.com", "office.com", "openai.com",
    "zoom.us", "dropbox.com", "spotify.com", "adobe.com", "pinterest.com",
    "cnn.com", "nytimes.com", "bbc.com", "theguardian.com", "forbes.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "paypal.com", "citi.com",
    "walmart.com", "target.com", "ebay.com", "craigslist.org", "etsy.com",
    "imdb.com", "twitch.tv", "medium.com", "quora.com", "whatsapp.com",
    "telegram.org", "discord.com", "slack.com", "gitlab.com", "bitbucket.org",
    "cloudflare.com", "mozilla.org", "w3.org", "python.org", "apache.org"
}

# TLDs heavily correlated with disposable/abusive phishing campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "buzz", "click", "fit",
    "surf", "work", "icu", "cam", "loan", "bar", "rest", "monster", "link",
    "country", "kim", "science", "party", "gdn", "mom", "rodeo", "vip"
}

# Free application hosting / tunneling domains frequently abused for phishing forms
FREE_HOSTS = {
    "firebaseapp.com", "web.app", "weeblysite.com", "weebly.com", "wixsite.com",
    "repl.co", "glitch.me", "000webhostapp.com", "pages.dev", "workers.dev",
    "pantheonsite.io", "ngrok.io", "ngrok-free.app", "loca.lt", "serveo.net",
    "duckdns.org", "herokuapp.com", "sites.google.com", "forms.gle"
}

# High-profile brand targets commonly spoofed
BRAND_MAP = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "appleid": "apple.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "bankofamerica": "bankofamerica.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "steam": "steampowered.com",
    "discord": "discord.com",
    "binance": "binance.com",
    "coinbase": "coinbase.com",
    "metamask": "metamask.io",
    "walmart": "walmart.com",
    "ebay": "ebay.com",
    "dhl": "dhl.com",
    "ups": "ups.com",
    "usps": "usps.com",
    "github": "github.com",
}


def extract_registered_domain(host: str) -> str:
    """Extract the effective registered domain (SLD + TLD) from a hostname."""
    if not host:
        return ""
    host = host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]

    parts = host.split(".")
    if len(parts) >= 2:
        # Multi-part TLDs (e.g. co.uk, com.au, org.uk, ac.in)
        if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "edu", "gov", "ac") and len(parts[-1]) <= 3:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return host


def normalize_for_model(value: str) -> str:
    """Normalize URL formatting consistently for both training and inference."""
    value = str(value).strip()

    if not value:
        return ""

    if not value.lower().startswith(("http://", "https://")):
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.lower()

        if scheme not in ("http", "https") or not parsed.hostname:
            return value.lower()

        hostname = parsed.hostname.lower()

        # Canonicalize leading www. to avoid artificial bias between www and non-www
        if hostname.startswith("www."):
            hostname = hostname[4:]

        try:
            port = parsed.port
        except ValueError:
            return value.lower()

        netloc = hostname
        if port is not None and not (
            (scheme == "https" and port == 443)
            or (scheme == "http" and port == 80)
        ):
            netloc = f"{hostname}:{port}"

        path = parsed.path or "/"

        return urlunsplit(
            (scheme, netloc, path, parsed.query, "")
        )

    except (ValueError, TypeError):
        return value.lower()


def analyze_security_signals(raw_url: str, host: str) -> dict:
    """Run comprehensive security heuristic analysis on URL and host."""
    parsed = urlsplit(raw_url)
    reg_domain = extract_registered_domain(host)
    findings = []
    heuristic_risk = 0.0

    # 1. IP Address host check
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
        findings.append({
            "name": "Raw IP Address Host",
            "detail": "Destination is an IP address rather than a registered domain name.",
            "severity": "high",
        })
        heuristic_risk += 0.50
    except ValueError:
        pass

    # 2. Punycode / IDN homograph attack check
    if any(label.startswith("xn--") for label in host.split(".")):
        findings.append({
            "name": "Punycode / Homograph Warning",
            "detail": "Hostname contains internationalized Punycode labels commonly used for lookalike spoofing.",
            "severity": "high",
        })
        heuristic_risk += 0.45

    # 3. Transport security
    if parsed.scheme.lower() == "http":
        findings.append({
            "name": "Unencrypted HTTP Scheme",
            "detail": "Connection is unencrypted. Legitimate services requesting credentials require TLS/HTTPS.",
            "severity": "medium",
        })
        heuristic_risk += 0.15

    # 4. TLD risk evaluation
    tld = host.split(".")[-1].lower() if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append({
            "name": f"High-Risk TLD (.{tld})",
            "detail": f"The top-level domain .{tld} is statistically overrepresented in disposable phishing campaigns.",
            "severity": "high",
        })
        heuristic_risk += 0.40

    # 5. Free hosting / public app deployment abuse
    is_free_host = any(reg_domain == fh or host.endswith("." + fh) for fh in FREE_HOSTS)
    if is_free_host:
        findings.append({
            "name": "Free Application Hosting Service",
            "detail": f"Hosted on {reg_domain}, a public hosting platform commonly abused for short-lived phishing forms.",
            "severity": "high",
        })
        heuristic_risk += 0.40

    # 6. Brand spoofing / Impersonation detection
    brand_matched = None
    for brand, official_domain in BRAND_MAP.items():
        if brand in host:
            if reg_domain != official_domain and not host.endswith("." + official_domain):
                brand_matched = brand
                findings.append({
                    "name": f"Brand Impersonation Target: {brand.upper()}",
                    "detail": f'Hostname contains brand keyword "{brand}", but the registered destination domain is "{reg_domain}", not official domain "{official_domain}".',
                    "severity": "critical",
                })
                heuristic_risk += 0.65
                break

    # 7. Deceptive multi-level subdomain trick (e.g. paypal.com.attacker.com)
    labels = host.split(".")
    if len(labels) >= 4 and not is_free_host:
        for brand, official_domain in BRAND_MAP.items():
            if any(l == brand for l in labels[:-2]) and reg_domain != official_domain:
                findings.append({
                    "name": "Deceptive Subdomain Spoofing",
                    "detail": f'Subdomain hierarchy embeds target "{brand}" before root destination domain "{reg_domain}".',
                    "severity": "critical",
                })
                heuristic_risk += 0.50
                break

    # 8. Excessive hostname hyphens (e.g. login-verify-account-security-update.com)
    hyphen_count = host.count("-")
    if hyphen_count >= 3:
        findings.append({
            "name": "Excessive Hostname Hyphens",
            "detail": f"Hostname contains {hyphen_count} hyphens, a frequent tactic in spoofed domain registration.",
            "severity": "medium",
        })
        heuristic_risk += 0.20

    # 9. Credential / authentication harvesting keywords
    sensitive_kw = re.findall(
        r"(?:login|signin|verify|verification|account|banking|security|update|recover|wallet|confirm|credential|password)",
        parsed.path.lower() + " " + parsed.query.lower()
    )
    if sensitive_kw:
        unique_kw = sorted(set(sensitive_kw))
        if is_free_host or heuristic_risk > 0.2 or brand_matched:
            findings.append({
                "name": "Credential Harvesting Signals",
                "detail": f"URL path or query includes sensitive target keywords: {', '.join(unique_kw)}.",
                "severity": "high",
            })
            heuristic_risk += 0.25

    # 10. Check for verified top authority domains
    is_top_authority = (reg_domain in TOP_DOMAINS) and not is_free_host and not is_ip
    if is_top_authority:
        findings.append({
            "name": "Verified Top Authority Domain",
            "detail": f'Destination resolves to official domain "{reg_domain}", a globally recognized authority domain.',
            "severity": "clean",
        })

    # If no negative findings, add clean signal
    if not any(f["severity"] in ("medium", "high", "critical") for f in findings):
        findings.append({
            "name": "Standard Domain Structure",
            "detail": "No explicit deceptive structural markers or spoofing indicators detected in the URL syntax.",
            "severity": "clean",
        })

    return {
        "findings": findings,
        "heuristic_risk": min(1.0, heuristic_risk),
        "is_top_authority": is_top_authority,
        "reg_domain": reg_domain,
    }
