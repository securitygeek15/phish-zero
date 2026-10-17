from urllib.parse import urlsplit, urlunsplit
from collections import Counter
import ipaddress
import math
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


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a given text string."""
    if not text or len(text) <= 1:
        return 0.0
    counts = Counter(text)
    length = len(text)
    ent = -sum((c / length) * math.log2(c / length) for c in counts.values())
    return round(max(0.0, ent), 2)


def dissect_url(raw_url: str, host: str, security_analysis: dict) -> list:
    """Decompose a URL into semantic, risk-scored interactive tokens."""
    parsed = urlsplit(raw_url)
    reg_domain = security_analysis.get("reg_domain", host)
    is_top_authority = security_analysis.get("is_top_authority", False)

    tokens = []

    # 1. Scheme
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    tokens.append({
        "type": "scheme",
        "label": "SCHEME",
        "value": f"{scheme}://",
        "raw": scheme,
        "severity": "clean" if scheme == "https" else "medium",
        "entropy": calculate_entropy(scheme),
        "length": len(scheme),
        "explanation": "Encrypted TLS transport layer." if scheme == "https" else "Unencrypted plain-text HTTP transport. Vulnerable to interception.",
        "tag": "TLS-ENCRYPTED" if scheme == "https" else "NO-ENCRYPTION"
    })

    # 2. Host segments: Subdomain vs Apex vs TLD
    host_clean = host.lower().strip(".")
    if host_clean.startswith("www."):
        host_clean = host_clean[4:]

    subdomain = ""
    if reg_domain in host_clean and len(host_clean) > len(reg_domain):
        subdomain = host_clean[:-(len(reg_domain) + 1)]

    reg_parts = reg_domain.split(".")
    if len(reg_parts) >= 2:
        if len(reg_parts) >= 3 and reg_parts[-2] in ("co", "com", "org", "net", "edu", "gov", "ac") and len(reg_parts[-1]) <= 3:
            tld = ".".join(reg_parts[-2:])
            apex_name = ".".join(reg_parts[:-2])
        else:
            tld = reg_parts[-1]
            apex_name = ".".join(reg_parts[:-1])
    else:
        apex_name = reg_domain
        tld = ""

    # Subdomain token
    if subdomain:
        sub_sev = "clean"
        sub_tag = "SUBDOMAIN"
        sub_exp = f"Subdomain prefix '{subdomain}' routes to primary host."
        for brand, official in BRAND_MAP.items():
            if brand in subdomain.lower() and reg_domain != official:
                sub_sev = "critical"
                sub_tag = "DECEPTIVE-BRAND"
                sub_exp = f"Deceptive subdomain trick: embeds brand '{brand}' before actual destination '{reg_domain}'."
                break
        tokens.append({
            "type": "subdomain",
            "label": "SUBDOMAIN",
            "value": f"{subdomain}.",
            "raw": subdomain,
            "severity": sub_sev,
            "entropy": calculate_entropy(subdomain),
            "length": len(subdomain),
            "explanation": sub_exp,
            "tag": sub_tag
        })

    # Apex Domain Name
    apex_sev = "clean" if is_top_authority else "info"
    apex_tag = "APEX-HOST"
    apex_exp = f"Registered apex destination domain '{reg_domain}'."
    for brand, official in BRAND_MAP.items():
        if brand in apex_name.lower():
            if reg_domain != official:
                apex_sev = "critical"
                apex_tag = "BRAND-SPOOF"
                apex_exp = f"Brand impersonation alert: mentions '{brand}' but root registry is '{reg_domain}', not authentic '{official}'."
                break
    if apex_name.count("-") >= 3:
        if apex_sev != "critical":
            apex_sev = "medium"
            apex_tag = "HYPHEN-STUFFING"
            apex_exp = f"Unusual hyphen density ({apex_name.count('-')} hyphens) in domain name."

    tokens.append({
        "type": "domain",
        "label": "APEX DOMAIN",
        "value": apex_name,
        "raw": apex_name,
        "severity": apex_sev,
        "entropy": calculate_entropy(apex_name),
        "length": len(apex_name),
        "explanation": apex_exp,
        "tag": apex_tag
    })

    # TLD
    if tld:
        tld_sev = "high" if tld in SUSPICIOUS_TLDS else "clean"
        tld_tag = "HIGH-RISK-TLD" if tld in SUSPICIOUS_TLDS else "STANDARD-TLD"
        tld_exp = f"High-risk TLD (.{tld}): statistically associated with burner phishing campaigns." if tld in SUSPICIOUS_TLDS else f"Standard top-level domain zone (.{tld})."
        tokens.append({
            "type": "tld",
            "label": "TLD",
            "value": f".{tld}",
            "raw": tld,
            "severity": tld_sev,
            "entropy": calculate_entropy(tld),
            "length": len(tld) + 1,
            "explanation": tld_exp,
            "tag": tld_tag
        })

    # Port (if non-standard)
    if parsed.port and not ((scheme == "https" and parsed.port == 443) or (scheme == "http" and parsed.port == 80)):
        tokens.append({
            "type": "port",
            "label": "PORT",
            "value": f":{parsed.port}",
            "raw": str(parsed.port),
            "severity": "medium",
            "entropy": calculate_entropy(str(parsed.port)),
            "length": len(str(parsed.port)) + 1,
            "explanation": f"Non-standard destination port {parsed.port}. May bypass security gateways or run ad-hoc services.",
            "tag": "NON-STANDARD-PORT"
        })

    # Path
    path_str = parsed.path or "/"
    path_sev = "clean"
    path_tag = "ENDPOINT"
    path_exp = f"Resource path endpoint '{path_str}'."
    sensitive_kw = [kw for kw in ["login", "signin", "verify", "verification", "account", "banking", "security", "update", "recover", "wallet", "confirm", "credential", "password"] if kw in path_str.lower()]
    if sensitive_kw:
        if not is_top_authority or apex_sev == "critical":
            path_sev = "high"
            path_tag = "CREDENTIAL-TARGET"
            path_exp = f"Endpoint targets authentication credentials: {', '.join(sensitive_kw)}."
        else:
            path_sev = "info"
            path_tag = "AUTH-PATH"
            path_exp = f"Authentic platform authentication path: {', '.join(sensitive_kw)}."

    tokens.append({
        "type": "path",
        "label": "PATH",
        "value": path_str,
        "raw": path_str,
        "severity": path_sev,
        "entropy": calculate_entropy(path_str),
        "length": len(path_str),
        "explanation": path_exp,
        "tag": path_tag
    })

    # Query
    if parsed.query:
        q_str = f"?{parsed.query}"
        q_sev = "clean"
        q_tag = "QUERY-PARAMS"
        q_exp = f"Query parameters payload ({len(parsed.query)} chars)."
        if any(kw in parsed.query.lower() for kw in ["login", "token", "auth", "session", "user", "pwd"]):
            q_sev = "medium" if not is_top_authority else "info"
            q_tag = "SENSITIVE-QUERY"
            q_exp = "Query parameters contain authentication or session identifier variables."
        tokens.append({
            "type": "query",
            "label": "QUERY",
            "value": q_str,
            "raw": parsed.query,
            "severity": q_sev,
            "entropy": calculate_entropy(parsed.query),
            "length": len(q_str),
            "explanation": q_exp,
            "tag": q_tag
        })

    return tokens


def compute_graph_data(raw_url: str, host: str, security_analysis: dict, ml_score: float) -> dict:
    """Generate risk surface vectors and topological routing graph data."""
    parsed = urlsplit(raw_url)
    reg_domain = security_analysis.get("reg_domain", host)
    is_top_authority = security_analysis.get("is_top_authority", False)

    # 1. Lexical Anomaly (0-100)
    ent_netloc = calculate_entropy(parsed.netloc)
    length_penalty = min(30.0, max(0.0, (len(raw_url) - 50) * 0.4))
    lexical_score = min(100.0, round(ml_score * 0.6 + length_penalty + (ent_netloc * 7.0), 1))
    if is_top_authority:
        lexical_score = min(lexical_score * 0.2, 12.0)

    # 2. Structural Deception (0-100)
    hyphen_count = host.count("-")
    dot_count = host.count(".")
    struct_score = 0.0
    if hyphen_count >= 3:
        struct_score += 40.0
    elif hyphen_count >= 1:
        struct_score += 15.0
    if dot_count >= 4:
        struct_score += 35.0
    elif dot_count >= 3:
        struct_score += 15.0
    if parsed.port and not ((parsed.scheme == "https" and parsed.port == 443) or (parsed.scheme == "http" and parsed.port == 80)):
        struct_score += 25.0
    try:
        ipaddress.ip_address(host.strip("[]"))
        struct_score += 65.0
    except ValueError:
        pass
    if is_top_authority:
        struct_score = 5.0
    struct_score = min(100.0, round(struct_score, 1))

    # 3. Brand Impersonation (0-100)
    brand_score = 0.0
    detected_brand = None
    for brand, official in BRAND_MAP.items():
        if brand in host.lower():
            if reg_domain != official and not host.endswith("." + official):
                brand_score = 100.0
                detected_brand = brand
                break
            else:
                brand_score = 0.0
                detected_brand = brand

    # 4. TLD Reputation (0-100)
    tld = host.split(".")[-1].lower() if "." in host else ""
    tld_score = 0.0
    if tld in SUSPICIOUS_TLDS:
        tld_score = 95.0
    elif any(reg_domain == fh or host.endswith("." + fh) for fh in FREE_HOSTS):
        tld_score = 85.0
    elif is_top_authority:
        tld_score = 0.0
    else:
        tld_score = 10.0

    # 5. Transport Security (0-100)
    transport_score = 85.0 if parsed.scheme.lower() == "http" else 5.0

    # 6. Credential Intent (0-100)
    sensitive_kw = [kw for kw in ["login", "signin", "verify", "verification", "account", "banking", "security", "update", "recover", "wallet", "confirm", "credential", "password"] if kw in (parsed.path.lower() + " " + parsed.query.lower())]
    if sensitive_kw:
        if is_top_authority and brand_score == 0:
            intent_score = 15.0
        else:
            intent_score = 95.0
    else:
        intent_score = 5.0

    risk_vectors = [
        {
            "id": "lexical",
            "name": "Lexical Entropy",
            "score": lexical_score,
            "status": "critical" if lexical_score >= 70 else ("warning" if lexical_score >= 35 else "clean"),
            "desc": f"N-gram randomness score {lexical_score}% (entropy: {ent_netloc})."
        },
        {
            "id": "structure",
            "name": "Host Deception",
            "score": struct_score,
            "status": "critical" if struct_score >= 70 else ("warning" if struct_score >= 35 else "clean"),
            "desc": f"Subdomain & hyphen density score {struct_score}%."
        },
        {
            "id": "brand",
            "name": "Brand Spoofing",
            "score": brand_score,
            "status": "critical" if brand_score >= 70 else ("clean" if brand_score == 0 else "warning"),
            "desc": f"Target impersonation hazard: {detected_brand.upper() if detected_brand else 'NONE'}."
        },
        {
            "id": "tld",
            "name": "TLD Risk",
            "score": tld_score,
            "status": "critical" if tld_score >= 70 else ("warning" if tld_score >= 40 else "clean"),
            "desc": f"TLD registry .{tld} reputation score {tld_score}%."
        },
        {
            "id": "transport",
            "name": "Transport Risk",
            "score": transport_score,
            "status": "critical" if transport_score >= 70 else "clean",
            "desc": f"Scheme {parsed.scheme.upper()} encryption score {transport_score}%."
        },
        {
            "id": "intent",
            "name": "Credential Intent",
            "score": intent_score,
            "status": "critical" if intent_score >= 70 else ("warning" if intent_score >= 35 else "clean"),
            "desc": f"Credential targeting keywords: {', '.join(sensitive_kw) if sensitive_kw else 'NONE'}."
        }
    ]

    # Topological Route Graph
    nodes = []
    # Node 1: Client
    nodes.append({
        "id": "node_client",
        "step": "01",
        "label": "VISITOR",
        "sub": "ORIGIN BROWSER",
        "status": "neutral"
    })
    # Node 2: Gateway
    nodes.append({
        "id": "node_gate",
        "step": "02",
        "label": f"{parsed.scheme.upper()}",
        "sub": "TLS GATEWAY" if parsed.scheme == "https" else "UNENCRYPTED",
        "status": "clean" if parsed.scheme == "https" else "warning"
    })
    # Node 3: If Brand lure
    is_diverted = False
    if detected_brand and brand_score >= 70:
        is_diverted = True
        nodes.append({
            "id": "node_lure",
            "step": "LURE",
            "label": detected_brand.upper(),
            "sub": "PERCEIVED BRAND",
            "status": "critical",
            "is_lure": True
        })
    # Node 4: Actual Registered Host
    nodes.append({
        "id": "node_dest",
        "step": "03" if not is_diverted else "ACTUAL",
        "label": reg_domain,
        "sub": "TRUE REGISTRY HOST",
        "status": "critical" if is_diverted or struct_score >= 60 else ("clean" if is_top_authority else "neutral")
    })
    # Node 5: TLD Zone
    nodes.append({
        "id": "node_tld",
        "step": "04",
        "label": f".{tld.upper()}",
        "sub": "TLD AUTHORITY",
        "status": "critical" if tld in SUSPICIOUS_TLDS else "clean"
    })
    # Node 6: Endpoint
    path_clean = parsed.path or "/"
    nodes.append({
        "id": "node_endpoint",
        "step": "05",
        "label": (path_clean[:18] + "..") if len(path_clean) > 18 else path_clean,
        "sub": "TARGET ENDPOINT",
        "status": "warning" if sensitive_kw else "clean"
    })

    if is_diverted:
        route_summary = f"Deceptive Routing Detected: The link displays '{detected_brand}' to impersonate an authentic service, but traffic diverts to '{reg_domain}' on .{tld}."
    elif is_top_authority:
        route_summary = f"Verified Authority Route: Traffic terminates directly at official domain '{reg_domain}' over {parsed.scheme.upper()}."
    else:
        route_summary = f"Standard Route: Link directs to '{reg_domain}' via {parsed.scheme.upper()} without brand collision."

    return {
        "risk_vectors": risk_vectors,
        "route_topology": {
            "nodes": nodes,
            "is_diverted": is_diverted,
            "detected_brand": detected_brand,
            "summary": route_summary
        }
    }

