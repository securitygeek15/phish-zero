# phish-zero

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests: 11/11 Passing](https://img.shields.io/badge/tests-11%2F11%20passing-brightgreen.svg)]()
[![Privacy: Zero--Egress](https://img.shields.io/badge/privacy-100%25%20local%20%2F%20zero--egress-blueviolet.svg)]()
[![Explainable AI: Linear Shapley](https://img.shields.io/badge/Explainable%20AI-Linear%20Shapley%20XAI-8b5cf6.svg)]()
[![Forensics: URL & Quishing](https://img.shields.io/badge/forensics-URL%20%26%20Quishing%20(QR)-informational.svg)]()

> **Inspect and verify suspicious links and QR codes safely — 100% offline with zero data leakage.**

`phish-zero` is a fast, local link forensics tool and phishing intelligence engine. It deconstructs suspicious URLs and QR code payloads ("quishing"), flags deceptive tricks (like lookalike domains or hidden redirects), and scores risk using a machine learning model paired with rule-based heuristics — all on your machine without connecting to the target website.

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

Go to **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser, paste any link or scan a QR code, and get an instant security verdict!

---

## ✨ Key Features at a Glance

### 📷 QR Code Phishing ("Quishing") Forensics Engine
Attackers increasingly embed credential harvesting traps inside QR codes in emails, PDF invoices, and physical flyers to bypass perimeter email URL gateways.
- **100% Client-Side Decoding**: Uses vendored `jsQR` to unpack QR codes directly in your browser. Not a single pixel or byte of your image ever leaves your computer.
- **Instant Input Modes**:
  - Drag-and-drop any QR image file (`.png`, `.jpg`, `.webp`)
  - **Clipboard Paste (`Ctrl + V`)**: Screenshot any suspicious QR code and hit `Ctrl + V` anywhere to audit it instantly
  - File browser upload
  - **1-Click Demo Presets**: Includes pre-built test QR codes (Spoofed Microsoft 365 MFA reset, Fake PayPal Invoice, and clean Google SSO) for instant hackathon demos
- **Payload Extraction & Audit**: Automatically extracts the embedded lure destination and feeds it directly into the 18-signal forensic inspection engine and ML classifier in under 5ms.

---

### 🔬 Explainable AI (XAI) Sub-Word Token Attribution Lens
Judges and security analysts demand to know *why* a machine learning model flagged a link rather than trusting a black box. `phish-zero` introduces a mathematically exact, sub-millisecond local Explainable AI engine:
- **Exact Linear Shapley Attribution**: Decomposes the Logistic Regression decision boundary ($z = \beta_0 + \sum x_j \beta_j$) without stochastic approximations or slow perturbation sampling (e.g. LIME).
- **Interactive Character Risk Heatmap**: Maps active n-gram weights directly to characters in the URL string. High-risk sub-tokens (`.tk`, `update`, `/login`) glow in neon red/amber, while trusted structural anchors glow in emerald green. Hovering or tapping any character reveals its exact contribution impact and primary n-gram pattern.
- **Dual Attribution Stream**:
  - **Top Threat Drivers (+Risk)**: Ranks the top 6 character n-grams pushing the model toward Phishing with exact coefficient weights and contribution percentage bars.
  - **Top Trust Anchors (-Risk)**: Highlights the top 6 structural n-grams pulling the model toward Safe.
- **Mathematical Logit HUD & Synthesis**: Visualizes the exact linear formula ($\text{Base Prior } \beta_0 + \text{Malicious Evidence} - \text{Benign Resistance} = \text{Net Logit } z \to \sigma(z)$) alongside a plain-English AI decision synthesis narrative.

---

### 🪟 Floating Glassmorphism HUD & Official Emblem
- Features a floating glassmorphic navbar with translucent backdrop blur (`backdrop-filter: blur(20px)`), ambient specular border highlights, dynamic live system latency indicator (`SYSTEM: ONLINE [LOCAL]`), zero-egress privacy lock, and the official `phish-zero` emblem.

---

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
     [ Direct URL Input ]   ──or──   [ QR Code ("Quishing") Image ]
               │                                   │
               │                      [ Client-Side jsQR Decoder ]
               │                      (100% Offline / Zero-Egress)
               └─────────────────┬─────────────────┘
                                 ▼
                        [ Target URL Payload ]
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

1. **Ingestion**: Accepts raw URLs or decodes QR codes offline via vendored `jsQR` (no image data is transmitted over any network).
2. **Normalization**: Canonicalizes formatting, decodes Punycode/IDNA characters, and removes artificial `www.` bias so `site.com` and `www.site.com` evaluate identically.
3. **ML Inference**: Inspects sub-word character patterns across the URL to detect statistical anomalies common in phishing URLs.
4. **Heuristic Engine**: Checks for known brand spoofing targets (PayPal, Apple, Google, Microsoft, Chase, etc.), abused free hosting providers (`firebaseapp.com`, `pages.dev`, `ngrok.io`), and suspicious TLDs.
5. **Composite Verdict**: Merges the ML probability and structural signals into a calibrated 0–100 risk score.

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
# Standard URL inspection
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-verification-account-update.tk/login"}'

# Or with Quishing (QR) telemetry tag
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-verification-account-update.tk/login", "vector": "quishing"}'
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
  "vector": "quishing",
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
  },
  "xai": {
    "status": "ready",
    "intercept": 3.121,
    "decision_logit": 10.361,
    "ml_probability": 100.0,
    "net_risk_evidence": 8.66,
    "net_safe_evidence": 1.42,
    "top_risk_tokens": [
      { "ngram": "tk/", "weight": 3.55, "contrib": 0.35, "pct": 4.0 },
      { "ngram": ".tk/", "weight": 3.54, "contrib": 0.35, "pct": 4.0 },
      { "ngram": "http:", "weight": 9.42, "contrib": 0.306, "pct": 3.5 }
    ],
    "top_safe_tokens": [
      { "ngram": "://p", "weight": -2.41, "contrib": -0.116, "pct": 8.2 }
    ],
    "narrative": "The model's linear decision boundary flagged this URL with a logit of +10.36. Adversarial risk is predominantly concentrated in the sub-word patterns 'tk/', '.tk/', '.tk', generating +8.66 units of malicious evidence that overcome benign structural anchors."
  }
}
```

---

## 🧪 Running Automated Tests

To run the complete automated test suite (verifying URL normalization, health checks, Quishing vector telemetry, Explainable AI attributions, and all 4 threat levels):

```bash
python -m unittest discover -s tests -v
```

All 11 tests should pass with `OK`.

---

## ⌨️ Helpful Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `/` | Instantly focus and select the URL input bar |
| `Ctrl + V` | Paste any QR screenshot from clipboard anywhere to audit instantly |
| `Esc` | Close QR scanner modal or clear the URL input bar |
| `Enter` | Run the security audit |

---

## 📁 Project Structure

```text
phish-zero/
├── app.py                 # Flask server & REST API
├── xai_explainer.py        # Sub-word token attribution & Linear Shapley XAI engine
├── url_features.py        # URL dissector, Shannon entropy & heuristics
├── train.py               # Model training script with GroupShuffleSplit
├── requirements.txt       # Python dependencies
├── assets/
│   └── logophishzero.png  # Official high-resolution logo & branding asset
├── data/
│   └── urls.csv           # Reference training dataset
├── model/
│   ├── url_model.joblib   # Pre-trained model bundle
│   └── metrics.json       # Benchmark metrics and validation report
├── static/
│   ├── app.js             # Frontend interactivity, QR scanner, XAI lens & SVG charts
│   ├── style.css          # Design system, glassmorphic HUD & threat-tier styling
│   ├── jsqr.min.js        # Vendored offline client-side QR decoder engine (zero-egress)
│   ├── emblem.png         # Glassmorphic navbar brand emblem
│   ├── favicon.ico        # Root browser favicon
│   ├── favicon.png        # High-DPI browser icon
│   └── samples/           # Pre-packaged quishing test QR samples (PayPal, M365, Google)
├── templates/
│   └── index.html         # Web application interface & Quishing HUD modal
└── tests/
    └── test_app.py        # Automated test suite (11 unit test cases)
```

---

## 📄 License

This project is open-source and available under the [MIT License](LICENSE).

