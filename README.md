# phish-zero

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-9%2F9%20passing-brightgreen.svg)]()
[![Privacy](https://img.shields.io/badge/privacy-zero--egress-blueviolet.svg)]()

A lightweight, zero-egress link forensics engine that combines character-level n-gram machine learning with topological heuristic analysis for real-time phishing detection.

---

## Overview

Traditional phishing scanners typically rely on external cloud lookups, active HTTP crawling, or third-party reputation feeds. While useful, this approach introduces two key security concerns: it leaks potentially sensitive URLs (such as password-reset tokens or private workspace links) to third parties, and outbound requests can alert attackers or trigger one-time evasion mechanisms.

**phish-zero** operates entirely offline. It evaluates lexical syntax, domain topology, character randomness, and structural deception patterns without initiating outbound network connections. It provides security engineers and end-users with an immediate forensic breakdown of destination links prior to navigation.

---

## System Architecture

```text
                               [ Submitted URL ]
                                       │
                         [ Canonical Normalization ]
                         (Scheme, Port, IDNA Host)
                                       │
                 ┌─────────────────────┴─────────────────────┐
                 ▼                                           ▼
      [ Lexical ML Pipeline ]                     [ Heuristic Rule Engine ]
      - Sublinear Char N-Grams (TF-IDF)           - Brand Spoofing / Lookalikes
      - Logistic Regression Classifier            - Deceptive Subdomain Nesting
      - Probability Calibration                   - High-Risk TLD & Free Host Abuse
                 │                                - Sensitive Credential Keywords
                 │                                - Raw IP & Punycode Flags
                 └─────────────────────┬─────────────────────┘
                                       ▼
                         [ Composite Risk Synthesis ]
                                       │
            ┌──────────────────────────┼──────────────────────────┐
            ▼                          ▼                          ▼
  [ Syntactic Dissector ]    [ Threat Surface Radar ]    [ Route Topology Flow ]
  - Token-level Breakdown    - 6-Axis Risk Vectors       - Visitor → Gateway
  - Shannon Entropy          - Normalized Weights        - Perceived Brand vs True Host
```

---

## Core Capabilities

### 1. Syntactic URL Decomposition & Entropy Analysis
- **Tokenization**: Decomposes URLs into standard RFC syntactic components: Scheme, Subdomain, Apex Domain, TLD, Port, Path, and Query parameters.
- **Shannon Entropy Scoring**: Calculates character entropy ($H$) across individual tokens to identify algorithmically generated domains (DGA), randomized hex strings, and obfuscated paths.
- **Segment Inspector**: Provides token-by-token forensic summaries, entropy metrics, and character counts with one-click clipboard copying.

### 2. Multi-Vector Risk Surface & Route Topology
- **6-Axis Threat Radar**: Evaluates and graphs risk contributions across distinct forensic dimensions:
  - **Lexical Entropy**: Character randomness and structural length anomalies.
  - **Host Deception**: Subdomain nesting, excessive hyphens, and numerical IP patterns.
  - **Brand Spoofing**: Collision scores against monitored high-value targets.
  - **TLD Reputation**: Statistical reputation of the destination top-level domain.
  - **Transport Security**: Encryption protocol status (HTTPS vs. unencrypted HTTP).
  - **Credential Intent**: Prevalence of authentication-targeting keywords in paths and parameters.
- **Topology Route Graph**: Visualizes the logical connection flow from the origin client to the final endpoint, unmasking deceptive brand lures that divert traffic to unrelated root domains.

### 3. Four-Tier Threat Severity Classification
The evaluation engine categorizes destinations into four standardized security tiers:

| Tier | Status | Criteria |
| :--- | :--- | :--- |
| **Danger** | Confirmed Threat | Verified brand impersonation, deceptive subdomain spoofing, or composite risk score $\ge 70\%$. |
| **Warning** | Elevated Risk | Raw IP destinations, disposable free application hosts, unencrypted authentication endpoints, or composite score $45\% - 69.9\%$. |
| **Caution** | Standard / Low Risk | Unverified public domains, technical documentation, or blogs with minor lexical anomalies ($15\% - 44.9\%$). |
| **Safe** | Verified Benign | Recognized global authority domains and clean URLs with composite risk score $< 15\%$. |

### 4. Machine Learning & Heuristic Detection Engine
- **Balanced Model Bundle**: Sublinear TF-IDF character n-gram vectorizer paired with Logistic Regression, calibrated against 220,000+ domain-grouped samples.
- **Canonical Standardization**: Normalizes schemes and standardizes hostname representations to eliminate training artifacts (such as spurious `www.` bias).
- **Brand Collision Library**: Monitors impersonation attempts targeting major institutions, including PayPal, Apple, Google, Microsoft, Amazon, Netflix, and financial providers.
- **High-Risk TLD & Disposable Host Detection**: Flags TLDs frequently abused in mass disposable campaigns (`.tk`, `.ml`, `.xyz`, `.top`, etc.) and public cloud app deployments (`firebaseapp.com`, `pages.dev`, `ngrok.io`, `weeblysite.com`, etc.).

---

## Benchmark Performance

The model was validated using `GroupShuffleSplit` partitioned strictly by registered hostname to prevent domain leakage between training and evaluation splits:

| Metric | Score | Details |
| :--- | :--- | :--- |
| **Accuracy** | **98.32%** | Overall test set correctness |
| **Phishing Precision** | **99.78%** | Ratio of true phishing detections to all positive flags |
| **Phishing Recall** | **96.15%** | Ratio of detected phishing attacks to total actual phishing URLs |
| **Phishing F1** | **97.93%** | Harmonic mean of precision and recall |
| **Benign False Positive Rate** | **0.15%** | Percentage of benign links incorrectly flagged |
| **Evaluation Split** | — | 220,378 training rows / 46,215 evaluation rows (0 hostname overlap) |

---

## Installation & Quickstart

### Prerequisites
- Python 3.10 or newer
- Standard virtual environment tools (`venv`)

### 1. Clone & Environment Setup

```bash
# Clone the repository
git clone https://github.com/securitygeek15/phish-zero.git
cd phish-zero

# Create and activate virtual environment
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Linux / macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Model Training (Optional)
A pre-trained model bundle is included in `model/url_model.joblib`. To retrain the pipeline using the dataset in `data/urls.csv`:

```bash
python train.py
```

### 3. Start Application Server

```bash
python app.py
```

Open your browser and navigate to:
```text
http://127.0.0.1:5000
```

### 4. Run Test Suite

```bash
python -m unittest discover -s tests -v
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

---

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

## Project Structure

```text
phish-zero/
├── app.py                 # Flask application server & API endpoints
├── url_features.py        # Tokenizer, entropy calculations, heuristics & topology
├── train.py               # Model training script with GroupShuffleSplit validation
├── requirements.txt       # Python dependencies
├── data/
│   └── urls.csv           # Reference dataset (URL and label)
├── model/
│   ├── url_model.joblib   # Trained pipeline artifact
│   └── metrics.json       # Benchmark evaluation results
├── static/
│   ├── app.js             # Client-side UI logic, SVG charts & state handling
│   └── style.css          # Design system & threat-tier styling
├── templates/
│   └── index.html         # Application interface markup
└── tests/
    └── test_app.py        # Automated test suite (9 test cases)
```

---

## Security & Privacy Considerations

- **Zero Egress**: All parsing, Shannon entropy scoring, and model inference take place locally. No external HTTP requests are dispatched to target URLs.
- **Defensive Triage**: Static lexical and heuristic analysis serves as an initial risk indicator. It is designed to complement existing security controls, such as DNS filtering, email authentication (SPF/DKIM/DMARC), and browser sandboxing.

---

## License

This project is licensed under the [MIT License](LICENSE).
