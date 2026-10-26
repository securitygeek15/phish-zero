# phish-zero

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 9/9 Passing](https://img.shields.io/badge/tests-9%2F9%20passing-brightgreen.svg)]()
[![Privacy: Zero--Egress](https://img.shields.io/badge/privacy-100%25%20local%20%2F%20zero--egress-blueviolet.svg)]()

> **Inspect and verify suspicious links safely — 100% offline with zero data leakage.**

`phish-zero` is a fast, local link forensics tool and phishing detector. It breaks down suspicious URLs, highlights deceptive tricks (like lookalike domains or hidden redirects), and scores risk using a machine learning model paired with rule-based heuristics — all on your machine without connecting to the target website.

---

## ⚡ Quickstart (Run in 30 Seconds)

### 1. Clone & Install

```bash
# Clone the repository
git clone https://github.com/securitygeek15/phish-zero.git
cd phish-zero

# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1

# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start the App

```bash
python app.py
```

### 3. Open in Browser

Go to **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser, paste any link, and get an instant security verdict!

---

## ✨ Key Features at a Glance

### 🎯 4-Tier Color-Coded Verdicts
Every scanned link is categorized into a clear, color-coded security tier so you immediately know whether it's safe to open:

| Level | Color | Meaning | Typical Examples |
| :--- | :--- | :--- | :--- |
| **Dangerous** | 🔴 **Red** | Confirmed phishing or active brand impersonation | Fake login portals, deceptive subdomains (`paypal.com.attacker.tk`) |
| **Potentially Dangerous** | 🟡 **Yellow** | Elevated risk indicators present | Raw numerical IP addresses, free app hosts, unencrypted logins |
| **Potentially Safe** | 🔵 **Blue** | Standard website with low risk | Technical blogs, open-source repos, unverified public websites |
| **Safe** | 🟢 **Green** | Verified trusted domain with clean structure | Official domains like `google.com`, `github.com`, `wikipedia.org` |

---

### 🔍 Interactive URL Dissector
URLs can be confusing on purpose — attackers frequently hide the real destination behind long prefixes or subdomains. 

`phish-zero` splits the URL into clear, clickable components:
- **Scheme**: `https://` (Encrypted) vs `http://` (Insecure)
- **Subdomain**: Highlights deceptive prefixes designed to look authentic
- **Apex Domain**: The real registered domain where your traffic will actually go
- **TLD**: Warns if the domain zone is a disposable, high-risk extension (`.tk`, `.ml`, `.xyz`)
- **Port**: Flags non-standard ports that might bypass firewalls
- **Path & Query**: Detects credential-harvesting triggers (`/login`, `/verify`, `token=`)

> **Interactive:** Click on any segment to view its length, character entropy score, and plain-English explanation, or copy it directly with one click.

---

### 📊 Threat Surface Radar & Route Topology Flow
- **Risk Radar**: A 6-axis visual chart showing where the risk is coming from (Lexical Randomness, Host Deception, Brand Spoofing, TLD Risk, Transport Security, and Credential Intent).
- **Route Topology**: A visual map tracing the connection path from your browser to the final server. It instantly flags when a link uses a recognized brand name as a "lure" to send you to an entirely different website.
- **Dual View**: Switch between the Radar chart, Route map, or both side-by-side.

---

### 🔒 Why "Zero-Egress" Matters (Privacy-First)
Most online link scanners send the URL to a remote server or crawl the target page. This creates two serious privacy and security risks:
1. **Data Leakage**: Private reset tokens, invite codes, or internal corporate addresses are exposed to third-party services.
2. **Attacker Alerting**: Visiting the page lets the attacker know their email was opened, or triggers one-time evasion tricks.

**`phish-zero` runs 100% locally on your machine.** It analyzes the URL's structure, spelling patterns, and statistical markers without ever sending requests to the destination or any third-party cloud.

---

## 📈 Model Performance & Accuracy

The built-in model combines a sublinear TF-IDF character n-gram vectorizer with Logistic Regression, evaluated on over **266,000 URLs**. 

To ensure realistic real-world evaluation, testing used `GroupShuffleSplit` partitioned strictly by registered domain — meaning no domain evaluated during testing was present during training:

| Metric | Score | What It Means |
| :--- | :--- | :--- |
| **Accuracy** | **98.32%** | Overall percentage of correct predictions |
| **Phishing Precision** | **99.78%** | When flagged as phishing, it is correct 99.8% of the time |
| **Phishing Recall** | **96.15%** | Successfully catches 96.2% of all phishing attacks |
| **False Positive Rate** | **0.15%** | Less than 1 in 650 safe sites are accidentally flagged |
| **Dataset Size** | **266,593 URLs** | 220,378 train / 46,215 test (zero hostname overlap) |

---

## 🛠️ How It Works Under the Hood

```text
                           [ Your Target URL ]
                                    │
                      [ Canonical Preprocessing ]
                      (Scheme, Port, IDNA Host)
                                    │
              ┌─────────────────────┴─────────────────────┐
              ▼                                           ▼
   [ Machine Learning Pipeline ]               [ Heuristic Rule Engine ]
   - Character N-Gram TF-IDF                   - Brand Impersonation Checks
   - Trained Logistic Regression               - Deceptive Subdomains
   - Statistical Pattern Score                 - Disposable TLDs & Free Hosts
              │                                - Credential Target Keywords
              └─────────────────────┬─────────────────────┘
                                    ▼
                      [ Composite Risk Synthesis ]
                                    │
         ┌──────────────────────────┼──────────────────────────┐
         ▼                          ▼                          ▼
[ URL Dissector ]         [ 6-Axis Risk Radar ]      [ Route Topology Map ]
Decomposed tokens         Visual threat surface      Visual redirection flow
```

1. **Normalization**: Canonicalizes formatting, decodes Punycode/IDNA characters, and removes artificial `www.` bias so `site.com` and `www.site.com` evaluate identically.
2. **ML Inference**: Inspects sub-word character patterns across the URL to detect statistical anomalies common in phishing URLs.
3. **Heuristic Engine**: Checks for known brand spoofing targets (PayPal, Apple, Google, Microsoft, Chase, etc.), abused free hosting providers (`firebaseapp.com`, `pages.dev`, `ngrok.io`), and suspicious TLDs.
4. **Composite Verdict**: Merges the ML probability and structural signals into a calibrated 0–100 risk score.

---

## 🔌 REST API Documentation

`phish-zero` includes a clean REST API so you can integrate link auditing into your own scripts, bots, or security pipelines.

### Check Engine Health
```bash
curl http://127.0.0.1:5000/api/health
```

**Response:**
```json
{
  "status": "ok",
  "model_loaded": true,
  "model_name": "Normalized Canonical URL TF-IDF + Logistic Regression",
  "message": "Model ready"
}
```

---

### Analyze a Link
```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-verification-account-update.tk/login"}'
```

**Response (Sample):**
```json
{
  "url": "http://paypal-verification-account-update.tk/login",
  "hostname": "paypal-verification-account-update.tk",
  "registered_domain": "paypal-verification-account-update.tk",
  "prediction": "phishing",
  "threat_level": "danger",
  "threat_label": "DANGEROUS // THREAT CONFIRMED",
  "threat_color": "#ef4444",
  "phishing_score": 100.0,
  "ml_score": 99.9,
  "heuristic_score": 100.0,
  "is_top_authority": false,
  "dissection": [
    { "type": "scheme", "label": "SCHEME", "value": "http://", "severity": "medium" },
    { "type": "domain", "label": "APEX DOMAIN", "value": "paypal-verification-account-update", "severity": "critical" },
    { "type": "tld", "label": "TLD", "value": ".tk", "severity": "high" },
    { "type": "path", "label": "PATH", "value": "/login", "severity": "high" }
  ],
  "graph_data": {
    "risk_vectors": [
      { "id": "brand", "name": "Brand Spoofing", "score": 100.0, "status": "critical" },
      { "id": "tld", "name": "TLD Risk", "score": 95.0, "status": "critical" },
      { "id": "intent", "name": "Credential Intent", "score": 95.0, "status": "critical" }
    ],
    "route_topology": {
      "is_diverted": true,
      "detected_brand": "paypal",
      "summary": "Deceptive Routing Detected: The link displays 'paypal' to impersonate an authentic service, but traffic diverts to 'paypal-verification-account-update.tk'."
    }
  }
}
```

---

## 🧪 Running Automated Tests

To run the complete automated test suite (verifying URL normalization, health checks, and all 4 threat levels):

```bash
python -m unittest discover -s tests -v
```

All 9 tests should pass with `OK`.

---

## ⌨️ Helpful Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `/` | Instantly focus and select the URL input bar |
| `Esc` | Clear the input bar or remove focus |
| `Enter` | Run the security audit |

---

## 📁 Project Structure

```text
phish-zero/
├── app.py                 # Flask server & REST API
├── url_features.py        # URL dissector, Shannon entropy & heuristics
├── train.py               # Model training script with GroupShuffleSplit
├── requirements.txt       # Python dependencies
├── data/
│   └── urls.csv           # Reference training dataset
├── model/
│   ├── url_model.joblib   # Pre-trained model bundle
│   └── metrics.json       # Benchmark metrics and validation report
├── static/
│   ├── app.js             # Frontend interactivity, SVG radar & topology charts
│   └── style.css          # Design system & threat-tier styling
├── templates/
│   └── index.html         # Web application interface
└── tests/
    └── test_app.py        # Automated test suite (9 test cases)
```

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).
