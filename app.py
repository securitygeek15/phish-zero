from pathlib import Path
import ipaddress
import logging
import re
from urllib.parse import urlparse

import joblib
from flask import Flask, jsonify, render_template, request, send_from_directory

from url_features import (
    normalize_for_model,
    analyze_security_signals,
    extract_registered_domain,
    dissect_url,
    compute_graph_data,
    BRAND_MAP,
)
from xai_explainer import explain_url_prediction



BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model" / "url_model.joblib"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0


@app.get("/favicon.ico")
def favicon():
    return send_from_directory("static", "favicon.ico", mimetype="image/vnd.microsoft.icon")

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

_model_bundle = None


def load_model():
    """Load the trained model once, on demand."""
    global _model_bundle

    if _model_bundle is None and MODEL_PATH.exists():
        _model_bundle = joblib.load(MODEL_PATH)

    return _model_bundle


def normalize_url(value):
    """Validate a submitted URL and return its display URL and hostname."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Enter a URL or domain.")

    value = value.strip()

    if re.search(r"\s", value):
        raise ValueError("URLs cannot contain spaces.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", value):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("Could not find a hostname in that URL.")

    if parsed.username or parsed.password:
        raise ValueError("Remove embedded credentials before analyzing this URL.")

    try:
        parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")

    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("The hostname contains invalid international characters.")

    if host.endswith("."):
        host = host[:-1]

    if not host:
        raise ValueError("Could not find a valid hostname.")

    if (
        host == "localhost"
        or host.endswith((".localhost", ".local", ".internal", ".test"))
    ):
        raise ValueError("Local and internal hostnames are not supported.")

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        if "." not in host:
            raise ValueError("Enter a complete public domain, such as example.com.")

    return value, host


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    try:
        bundle = load_model()
    except Exception:
        app.logger.exception("Unable to load the model")
        return jsonify({
            "status": "error",
            "model_loaded": False,
            "message": "Model loading failed. Check the server log.",
        }), 500

    return jsonify({
        "status": "ok",
        "model_loaded": bundle is not None,
        "model_name": bundle.get("model_name") if bundle else None,
        "message": (
            "Model ready"
            if bundle
            else "No trained model found. Run train.py first."
        ),
    })


@app.post("/api/analyze")
def analyze():
    body = request.get_json(silent=True)

    if not isinstance(body, dict):
        return jsonify({"error": "Send a JSON object containing a URL."}), 400

    vector = str(body.get("vector", "direct_input")).strip().lower()

    try:
        raw_url, host = normalize_url(body.get("url", ""))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    try:
        bundle = load_model()
    except Exception:
        app.logger.exception("Unable to load the model")
        return jsonify({"error": "The trained model could not be loaded."}), 500

    if bundle is None:
        return jsonify({
            "error": "The model has not been trained yet.",
            "next_step": "Run: .\\.venv\\Scripts\\python.exe train.py",
        }), 503

    try:
        pipeline = bundle["pipeline"]
        model_url = normalize_for_model(raw_url)

        probabilities = pipeline.predict_proba([model_url])[0]
        classes = list(pipeline.classes_)

        positive_label = bundle.get("positive_label", "phishing")

        if positive_label not in classes:
            raise ValueError(
                f"Expected class {positive_label!r}; found {classes!r}"
            )

        phishing_index = classes.index(positive_label)
        ml_score = float(probabilities[phishing_index])

        # Deep security signal heuristics
        security_analysis = analyze_security_signals(raw_url, host)
        heuristic_risk = security_analysis["heuristic_risk"]
        is_top_authority = security_analysis["is_top_authority"]
        reg_domain = security_analysis["reg_domain"]
        findings = security_analysis["findings"]

        # Check for confirmed brand impersonation, IP destination, or critical findings
        has_critical = any(f.get("severity") == "critical" for f in findings)
        brand_spoofed = any(
            brand in host.lower() and reg_domain != official and not host.endswith("." + official)
            for brand, official in BRAND_MAP.items()
        )
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            pass

        # 4-Tier Security Channel Calibration:
        # - Danger (Red): Confirmed brand impersonation, spoofed subdomains, critical hazards
        # - Warning (Yellow): Potentially dangerous (raw numerical IPs, free hosts, unencrypted logins, elevated risk)
        # - Caution (Blue): Potentially safe (general unverified domains, community sites with clean/minor signals)
        # - Safe (Green): Verified top authority domains and pristine zero-threat targets
        if is_top_authority and heuristic_risk < 0.35:
            phishing_score = min(ml_score * 0.05, 0.015)
            threat_level = "safe"
            threat_label = "SAFE // VERIFIED"
            threat_color = "#10b981"
            prediction = "benign"
        elif brand_spoofed or (has_critical and not is_ip) or (heuristic_risk >= 0.75 and not is_ip):
            phishing_score = max(ml_score, 0.985)
            threat_level = "danger"
            threat_label = "DANGEROUS // THREAT CONFIRMED"
            threat_color = "#ef4444"
            prediction = "phishing"
        elif is_ip or heuristic_risk >= 0.35 or (ml_score >= 0.60 and not is_top_authority):
            phishing_score = max(0.48, min(0.68, 0.45 + heuristic_risk * 0.20 + ml_score * 0.10))
            threat_level = "warning"
            threat_label = "POTENTIALLY DANGEROUS"
            threat_color = "#f59e0b"
            prediction = "phishing" if phishing_score >= 0.50 else "suspicious"
        elif not is_top_authority or ml_score >= 0.12 or heuristic_risk >= 0.10:
            phishing_score = max(0.16, min(0.38, 0.15 + ml_score * 0.25 + heuristic_risk * 0.15))
            threat_level = "caution"
            threat_label = "POTENTIALLY SAFE"
            threat_color = "#3b82f6"
            prediction = "benign"
        else:
            phishing_score = max(0.005, min(0.10, ml_score * 0.20))
            threat_level = "safe"
            threat_label = "SAFE // VERIFIED"
            threat_color = "#10b981"
            prediction = "benign"

        phishing_score = max(0.001, min(0.999, phishing_score))

    except Exception:
        app.logger.exception("Model prediction failed")
        return jsonify({
            "error": "Model prediction failed. Check the model bundle and training labels."
        }), 500

    parsed = urlparse(raw_url)
    dissection = dissect_url(raw_url, host, security_analysis)
    graph_data = compute_graph_data(raw_url, host, security_analysis, ml_score * 100)
    xai_data = explain_url_prediction(pipeline, raw_url)

    return jsonify({
        "url": raw_url,
        "hostname": host,
        "vector": vector,
        "vector_label": "QR Code (Quishing)" if vector == "quishing" else "Direct Link Audit",
        "registered_domain": reg_domain,
        "prediction": prediction,
        "threat_level": threat_level,
        "threat_label": threat_label,
        "threat_color": threat_color,
        "phishing_score": round(phishing_score * 100, 1),
        "ml_score": round(ml_score * 100, 1),
        "heuristic_score": round(heuristic_risk * 100, 1),
        "is_top_authority": is_top_authority,
        "model_name": bundle.get(
            "model_name",
            "Normalized Canonical URL TF-IDF + Logistic Regression",
        ),
        "diagnostics": {
            "protocol": parsed.scheme.upper(),
            "port": parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            "tld": host.split(".")[-1] if "." in host else "NONE",
            "path": parsed.path or "/",
            "has_query": bool(parsed.query),
            "findings_count": len(findings),
        },
        "dissection": dissection,
        "graph_data": graph_data,
        "xai": xai_data,
        "findings": findings,
        "caveat": (
            "Machine-learning & security signal intelligence. "
            "A low score indicates no known phishing anomalies, but always exercise caution."
        ),
    })


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request is too large."}), 413


if __name__ == "__main__":
    app.run(
        debug=False,
        host="127.0.0.1",
        port=5000,
    )
