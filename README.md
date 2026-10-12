# PHISH // ZERO

**Tactical Adversarial Link Forensics — v0.2.0 (Monochrome Edition)**

PHISH // ZERO is a local link-intelligence and phishing forensic engine that combines canonical character n-gram machine learning with deep topological heuristic analysis. It features a tactical, ultra-minimalist monochrome cyber-terminal interface engineered for zero-distraction link auditing.

---

## Capabilities & Architecture

- **Canonical URL Normalization ([url_features.py](file:///c:/Users/amaan/Desktop/phish-zero/url_features.py))**: Eliminates spurious dataset shortcuts by canonicalizing schemes, standardizing ports, and stripping artificial `www.` bias so `domain.com` and `www.domain.com` evaluate identically.
- **Neural Pipeline ([train.py](file:///c:/Users/amaan/Desktop/phish-zero/train.py))**: Sublinear character n-gram TF-IDF vectorizer + balanced Logistic Regression trained on 220,000+ domain-grouped samples with benign path augmentation.
- **Deep Forensic Signal Analyzer**:
  - **Brand Impersonation & Typosquatting**: Detects target brand spoofing (PayPal, Apple, Google, Microsoft, Netflix, Chase, Bank of America, Amazon, etc.) when embedded in deceptive hostnames.
  - **High-Risk Disposable TLDs**: Flags top-level domains statistically overrepresented in mass phishing (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.buzz`, `.cam`, etc.).
  - **Free App Host & Tunnel Abuse**: Identifies phishing forms hosted on disposable public app services (`firebaseapp.com`, `weeblysite.com`, `repl.co`, `ngrok.io`, `pages.dev`, etc.).
  - **Raw IP & Punycode Homographs**: Identifies raw IP address destinations and internationalized Punycode lookalikes (`xn--`).
  - **Credential Harvesting Indicators**: Detects sensitive authentication and security target keywords in paths and query strings.
  - **Verified Authority Baseline**: Validates established global authority domains (`google.com`, `github.com`, `wikipedia.org`, etc.) to prevent false alarms on authentic sites.
- **Calibrated Composite Scoring ([app.py](file:///c:/Users/amaan/Desktop/phish-zero/app.py))**: Synthesizes neural pattern confidence with observable forensic heuristics into a transparent 0–100 risk score.
- **Tactical Monochrome UI ([templates/index.html](file:///c:/Users/amaan/Desktop/phish-zero/templates/index.html), [static/style.css](file:///c:/Users/amaan/Desktop/phish-zero/static/style.css), [static/app.js](file:///c:/Users/amaan/Desktop/phish-zero/static/app.js))**:
  - Pure black canvas with ambient technical coordinate grid and subtle radial illumination.
  - Typography pairing **Space Grotesk** (display), **Inter** (body), and **JetBrains Mono** (telemetry).
  - Live system telemetry ticker with latency ping and engine heartbeat.
  - Quick-audit preset chips for instant 1-click testing (`google.com`, `github.com`, `paypal-verification.tk`, `login-apple-security.com`, `192.168.1.1/admin`).
  - Animated live scanning HUD displaying sequential forensic decomposition steps.
  - Oversized brutalist risk numeral (`0.0` to `100.0`) with count-up animation.
  - Mechanical 20-segment VU meter that illuminates smoothly with threat severity.
  - 4-card forensic telemetry grid: Destination Host, Transport & Port, Neural Estimate, and Observed Signals.
  - Granular evidence ledger with severity badges (`[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[CLEAN]`).
  - One-click clipboard utilities: **Copy Target URL**, **Copy Markdown Audit Report**, and **View/Copy Raw Telemetry JSON**.
  - Keyboard shortcuts (`/` to focus search, `Esc` to clear).

---

## Evaluated Benchmark Performance

Evaluated via `GroupShuffleSplit` by hostname to strictly prevent domain leakage between training and testing splits:

| Metric | Score |
| :--- | :--- |
| **Accuracy** | `98.32%` |
| **Phishing Precision** | `99.78%` |
| **Phishing Recall** | `96.15%` |
| **Phishing F1** | `97.93%` |
| **Benign False-Positive Rate** | `0.15%` |
| **Evaluation Split** | 220,378 train rows / 46,215 test rows |

---

## Requirements

- Python 3.10 or newer
- Virtual environment with dependencies in `requirements.txt`

---

## Setup & Quickstart (Windows PowerShell)

### 1. Environment Setup

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell script execution is restricted, run using the virtual environment interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Dataset

Ensure your dataset is placed at `data/urls.csv` containing at least `URL` and `label` columns (with `0` / `phishing` and `1` / `benign`).

### 3. Train the Model

```powershell
.\.venv\Scripts\python.exe train.py
```

Generates the calibrated model bundle at `model/url_model.joblib` and evaluation metrics at `model/metrics.json`.

### 4. Run the Web Application

```powershell
.\.venv\Scripts\python.exe app.py
```

Access the interface in your browser at:
**http://127.0.0.1:5000**

### 5. Run Automated Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

---

## API Reference

### Health Check

```http
GET /api/health
```

**Response (`200 OK`)**:
```json
{
  "status": "ok",
  "model_loaded": true,
  "model_name": "Normalized Canonical URL TF-IDF + Logistic Regression",
  "message": "Model ready"
}
```

### URL Forensic Analysis

```http
POST /api/analyze
Content-Type: application/json

{
  "url": "http://paypal-verification-account-update.tk/login"
}
```

**Response (`200 OK`)**:
```json
{
  "url": "http://paypal-verification-account-update.tk/login",
  "hostname": "paypal-verification-account-update.tk",
  "registered_domain": "paypal-verification-account-update.tk",
  "prediction": "phishing",
  "phishing_score": 99.9,
  "ml_score": 99.9,
  "heuristic_score": 100.0,
  "is_top_authority": false,
  "model_name": "Normalized Canonical URL TF-IDF + Logistic Regression",
  "diagnostics": {
    "protocol": "HTTP",
    "port": 80,
    "tld": "tk",
    "path": "/login",
    "has_query": false,
    "findings_count": 4
  },
  "findings": [
    {
      "name": "Unencrypted HTTP Scheme",
      "detail": "Connection is unencrypted. Legitimate services requesting credentials require TLS/HTTPS.",
      "severity": "medium"
    },
    {
      "name": "High-Risk TLD (.tk)",
      "detail": "The top-level domain .tk is statistically overrepresented in disposable phishing campaigns.",
      "severity": "high"
    },
    {
      "name": "Brand Impersonation Target: PAYPAL",
      "detail": "Hostname contains brand keyword \"paypal\", but the registered destination domain is \"paypal-verification-account-update.tk\", not official domain \"paypal.com\".",
      "severity": "critical"
    },
    {
      "name": "Credential Harvesting Signals",
      "detail": "URL path or query includes sensitive target keywords: login.",
      "severity": "high"
    }
  ],
  "caveat": "Machine-learning & security signal intelligence. A low score indicates no known phishing anomalies, but always exercise caution."
}
```

---

## Important Security Context

PHISH // ZERO operates in an isolated zero-egress mode: it evaluates lexical syntax, topological domain structures, and statistical n-gram probabilities without making outbound HTTP network requests or rendering remote untrusted code. It is designed as an adversarial triage and link forensics tool.

---

## License

MIT License. Dataset rights remain with their respective creators and open-source contributors.
