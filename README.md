# phish-zero

**Tactical Adversarial Link Forensics & Neural Threat Intelligence — v0.3.0**

`phish-zero` is a local link-intelligence and phishing forensic engine that combines canonical character n-gram machine learning with deep topological heuristic analysis. It features an interactive URL dissector, a visual threat surface radar chart, an end-to-end route topology analyzer, and a 4-tier security color-coded forensic interface engineered for rapid, zero-egress link auditing.

---

## Key Features & Architecture

### 1. Interactive URL Dissector ([url_features.py](file:///c:/Users/amaan/Desktop/phish-zero/url_features.py))
- **Granular Tokenization**: Decomposes any destination URI into syntactic segments: **Scheme**, **Subdomain**, **Apex Domain**, **TLD**, **Port**, **Path**, and **Query**.
- **Shannon Entropy Analysis**: Computes character entropy for each individual token to identify algorithmically generated randomness, DGA domains, or obfuscated hex strings.
- **Deep Token Inspector**: Clickable segment tabs displaying length, entropy, security tag (`TLS-ENCRYPTED`, `DECEPTIVE-BRAND`, `BRAND-SPOOF`, `HIGH-RISK-TLD`, etc.), and plain-English forensic explanations with 1-click token copying.

### 2. Visual Threat Graph Analyzer
- **6-Axis Risk Surface Radar**: Interactive SVG radar chart projecting risk vectors across:
  - **Lexical Entropy**: N-gram randomness and length penalties
  - **Host Deception**: Subdomain nesting, hyphen density, and numerical IP patterns
  - **Brand Spoofing**: Target brand impersonation collision score
  - **TLD Reputation**: Burner TLD vs. legitimate registry trust
  - **Transport Security**: TLS encryption status
  - **Credential Intent**: Authentication and sensitive credential-harvesting keyword density
- **Topology Route Flow**: Interactive graph tracing the visitor's logical hop sequence:
  `Visitor` $\rightarrow$ `Transport Gateway` $\rightarrow$ `[LURE (Perceived Brand)]` $\rightarrow$ `True Registry Host` $\rightarrow$ `TLD Authority` $\rightarrow$ `Endpoint`.
- **View Switcher**: Seamlessly toggle between **Risk Surface Radar**, **Topology Route Flow**, and **Dual View**.

### 3. 4-Tier Security Color Channels
The interface dynamically morphs its aesthetic and telemetry based on the evaluated threat level:
- 🔴 **Dangerous (`#ef4444`)**: Confirmed phishing attacks, active brand impersonation, and critical deception vectors.
- 🟡 **Potentially Dangerous (`#f59e0b`)**: Raw IP hosts, unencrypted login endpoints, free hosting abuse, or elevated heuristic warnings.
- 🔵 **Potentially Safe (`#3b82f6`)**: Standard unverified web domains, open-source documentation, and blogs with low-to-moderate risk.
- 🟢 **Safe (`#10b981`)**: Verified global authority domains (`google.com`, `github.com`, `wikipedia.org`, etc.) with zero-threat baselines.

### 4. Canonical Machine Learning & Heuristic Signals
- **Canonical Normalization**: Standardizes ports, normalizes schemes, and strips artificial `www.` bias so `domain.com` and `www.domain.com` evaluate identically.
- **TF-IDF + Logistic Regression Pipeline ([train.py](file:///c:/Users/amaan/Desktop/phish-zero/train.py))**: Trained on 220,000+ domain-grouped samples with benign path augmentation.
- **Brand Impersonation & Typosquat Detection**: Monitors major targets (PayPal, Apple, Google, Microsoft, Netflix, Chase, Bank of America, Amazon, etc.) embedded inside lookalike hostnames.
- **High-Risk Burner TLDs**: Flags disposable domains (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, `.top`, `.xyz`, `.buzz`, `.cam`, etc.).
- **Free App Host & Tunnel Abuse**: Identifies phishing forms hosted on disposable public services (`firebaseapp.com`, `weeblysite.com`, `repl.co`, `ngrok.io`, `pages.dev`, etc.).

### 5. Tactical Cyber-Forensic UI ([static/app.js](file:///c:/Users/amaan/Desktop/phish-zero/static/app.js), [static/style.css](file:///c:/Users/amaan/Desktop/phish-zero/static/style.css))
- Pure black canvas with ambient technical coordinate grid and radial illumination.
- Typography pairing **Space Grotesk** (display), **Inter** (body), and **JetBrains Mono** (telemetry).
- Quick-audit preset chips with color-coded threat tags for 1-click testing.
- Mechanical 20-segment VU meter illuminating smoothly with threat severity.
- Animated live scanning HUD displaying sequential decomposition stages.
- One-click clipboard utilities: **Copy Target URL**, **Copy Segment**, **Copy Audit Summary**, and **Inspect Raw JSON**.
- Keyboard shortcuts (`/` to focus input, `Esc` to clear/blur).

---

## Evaluated Benchmark Performance

Evaluated via `GroupShuffleSplit` strictly by hostname to prevent domain leakage between training and testing splits:

| Metric | Score |
| :--- | :--- |
| **Accuracy** | `98.32%` |
| **Phishing Precision** | `99.78%` |
| **Phishing Recall** | `96.15%` |
| **Phishing F1** | `97.93%` |
| **Benign False-Positive Rate** | `0.15%` |
| **Evaluation Split** | 220,378 train rows / 46,215 test rows |

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

### 2. Dataset & Model Training

A trained model bundle is included in `model/url_model.joblib`. To retrain from `data/urls.csv`:

```powershell
.\.venv\Scripts\python.exe train.py
```

### 3. Launch Web Application

```powershell
.\.venv\Scripts\python.exe app.py
```

Open your browser at: **http://127.0.0.1:5000**

### 4. Run Automated Test Suite

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

All 9 test cases covering safe, caution, warning, and danger threat levels should pass.

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
  "threat_level": "danger",
  "threat_label": "DANGEROUS // THREAT CONFIRMED",
  "threat_color": "#ef4444",
  "phishing_score": 100.0,
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
  "dissection": [
    {
      "type": "scheme",
      "label": "SCHEME",
      "value": "http://",
      "raw": "http",
      "severity": "medium",
      "entropy": 1.5,
      "length": 7,
      "explanation": "Unencrypted HTTP transport protocol.",
      "tag": "HTTP-INSECURE"
    },
    {
      "type": "domain",
      "label": "APEX DOMAIN",
      "value": "paypal-verification-account-update",
      "raw": "paypal-verification-account-update",
      "severity": "critical",
      "entropy": 3.72,
      "length": 34,
      "explanation": "Brand impersonation alert: mentions 'paypal' but root registry is 'paypal-verification-account-update.tk'.",
      "tag": "BRAND-SPOOF"
    },
    {
      "type": "tld",
      "label": "TLD",
      "value": ".tk",
      "raw": ".tk",
      "severity": "high",
      "entropy": 1.0,
      "length": 3,
      "explanation": "High-risk TLD (.tk): statistically associated with burner phishing campaigns.",
      "tag": "HIGH-RISK-TLD"
    },
    {
      "type": "path",
      "label": "PATH",
      "value": "/login",
      "raw": "/login",
      "severity": "high",
      "entropy": 2.32,
      "length": 6,
      "explanation": "Endpoint targets authentication credentials: login.",
      "tag": "CREDENTIAL-TARGET"
    }
  ],
  "graph_data": {
    "risk_vectors": [
      { "id": "lexical", "name": "Lexical Entropy", "score": 91.2, "status": "critical" },
      { "id": "structure", "name": "Host Deception", "score": 40.0, "status": "warning" },
      { "id": "brand", "name": "Brand Spoofing", "score": 100.0, "status": "critical" },
      { "id": "tld", "name": "TLD Risk", "score": 95.0, "status": "critical" },
      { "id": "transport", "name": "Transport Risk", "score": 85.0, "status": "critical" },
      { "id": "intent", "name": "Credential Intent", "score": 95.0, "status": "critical" }
    ],
    "route_topology": {
      "is_diverted": true,
      "detected_brand": "paypal",
      "summary": "Deceptive Routing Detected: The link displays 'paypal' to impersonate an authentic service, but traffic diverts to 'paypal-verification-account-update.tk' on .tk."
    }
  },
  "findings": [
    {
      "name": "Brand Impersonation Target: PAYPAL",
      "detail": "Hostname contains brand keyword \"paypal\", but registered destination domain is \"paypal-verification-account-update.tk\".",
      "severity": "critical"
    }
  ],
  "caveat": "Machine-learning & security signal intelligence. A low score indicates no known phishing anomalies, but always exercise caution."
}
```

---

## Zero-Egress Privacy Model

`phish-zero` operates entirely locally without external API telemetry or remote data egress:
- All lexical breakdown, Shannon entropy calculations, and topological route analysis happen locally on the server and client.
- The machine learning model executes entirely offline via `scikit-learn`.
- No outbound network connections are initiated to the inspected URLs, preventing tracking pixels or active exploitation.

---

## License

MIT License. Dataset rights remain with their respective creators and open-source contributors.
