# phish-zero

Fast, offline link and QR code phishing forensics. Inspect deceptive URLs and credential-harvesting lures locally with zero network requests and zero data leakage.

---

## Features

- Zero-Egress Privacy: Runs entirely on your local machine. No external API calls, no cloud lookups, and no telemetry.
- Quishing (QR Code) Scanner: Decodes and analyzes QR codes directly in the browser via file upload, drag-and-drop, or clipboard paste (Ctrl + V).
- Batch Multi-URL Triage: Stream and audit bulk URL lists with live progress metrics and export to CSV, JSON, or DNS blocklists.
- Optical Homoglyph Detection: Unmasks mixed-script IDN spoofing (such as Cyrillic lookalikes) using client-side pixel correlation.
- Automated SOC Containment Rules: Instantly generates ready-to-use defense rules for Suricata IDS, Snort 3, Pi-hole, /etc/hosts, STIX 2.1, and Sigma SIEM.
- Dual Theme: High-contrast light and dark mode with system preference auto-detection.

---

## Quickstart

### Option 1: Docker (Recommended)

```bash
git clone https://github.com/securitygeek15/phish-zero.git
cd phish-zero
docker compose up -d
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

### Option 2: Local Python

```bash
git clone https://github.com/securitygeek15/phish-zero.git
cd phish-zero

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1

# Install dependencies and start
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## API Usage

Analyze a URL:

```bash
curl -X POST http://127.0.0.1:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-verification-account-update.tk/login"}'
```

Batch analyze multiple URLs:

```bash
curl -X POST http://127.0.0.1:5000/api/batch_analyze \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://google.com", "http://suspicious-link.xyz/auth"]}'
```

---

## Keyboard Shortcuts

| Key | Action |
| --- | --- |
| `/` | Focus URL search bar |
| `Ctrl + V` | Paste QR image from clipboard anywhere |
| `Shift + T` | Toggle Light / Dark theme |
| `Esc` | Close modal or clear input |
| `Enter` | Run security audit |

---

## License

This project is licensed under the [MIT License](LICENSE).
