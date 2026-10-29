"""Explainable AI (XAI) Sub-Word Token Attribution Engine for Phish-Zero.

Computes mathematically exact linear feature attributions from the trained
TF-IDF character n-gram + Logistic Regression pipeline without sampling or approximations.
Maps n-gram coefficients directly back to character-level URL spans.
"""

from typing import Any, Dict, List
import numpy as np

from url_features import normalize_for_model


def explain_url_prediction(pipeline: Any, raw_url: str) -> Dict[str, Any]:
    """Deconstruct the Logistic Regression prediction into exact feature attributions.

    Args:
        pipeline: The trained scikit-learn Pipeline containing 'tfidf' and 'classifier'.
        raw_url: The submitted raw URL string.

    Returns:
        Dict containing:
          - intercept: float (base prior log-odds b_0)
          - net_risk_evidence: float (sum of positive risk contributions)
          - net_safe_evidence: float (sum of negative safe contributions)
          - decision_logit: float (z = b_0 + sum(c_j))
          - ml_probability: float (sigmoid activation in percent)
          - top_risk_tokens: list of top positive n-grams with weights & impact
          - top_safe_tokens: list of top negative n-grams with weights & impact
          - char_heatmap: list of character dicts with normalized risk intensity [0, 1]
          - narrative: human-readable explainability synthesis
    """
    if pipeline is None:
        return {"status": "unavailable", "message": "Model pipeline not loaded"}

    tfidf = pipeline.named_steps.get("tfidf")
    clf = pipeline.named_steps.get("classifier")

    if tfidf is None or clf is None:
        return {"status": "unavailable", "message": "Pipeline components missing"}

    norm_url = normalize_for_model(raw_url)
    if not norm_url:
        return {"status": "unavailable", "message": "URL normalization returned empty"}

    feature_names = tfidf.get_feature_names_out()
    coefs = clf.coef_[0]
    intercept = float(clf.intercept_[0])

    # Transform normalized URL to sparse TF-IDF vector
    X = tfidf.transform([norm_url])
    indices = X.indices
    data = X.data

    # Map active feature indices to their TF-IDF weight and linear logit contribution
    feat_contribs: Dict[int, tuple] = {}
    for idx, val in zip(indices, data):
        weight = float(coefs[idx])
        contrib = float(val * weight)
        feat_contribs[idx] = (val, weight, contrib)

    char_len = len(norm_url)
    char_risk = [0.0] * char_len
    char_safe = [0.0] * char_len
    char_ngrams: List[List[tuple]] = [[] for _ in range(char_len)]

    # Project n-grams directly back onto string character positions
    vocab = tfidf.vocabulary_
    for n in (3, 4, 5):
        for i in range(char_len - n + 1):
            sub = norm_url[i : i + n]
            if sub in vocab:
                f_idx = vocab[sub]
                if f_idx in feat_contribs:
                    val, weight, contrib = feat_contribs[f_idx]
                    for k in range(i, i + n):
                        if contrib > 0:
                            char_risk[k] += contrib / n
                        else:
                            char_safe[k] += abs(contrib) / n
                        char_ngrams[k].append((sub, contrib, weight))

    # Compile and rank all active token contributions
    all_contribs = []
    for f_idx, (val, weight, contrib) in feat_contribs.items():
        all_contribs.append({
            "ngram": feature_names[f_idx],
            "weight": round(weight, 3),
            "contrib": round(contrib, 4),
            "abs_contrib": abs(contrib),
            "type": "risk" if contrib > 0 else "safe",
        })

    all_contribs.sort(key=lambda item: item["abs_contrib"], reverse=True)

    raw_risk_tokens = [c for c in all_contribs if c["type"] == "risk"]
    raw_safe_tokens = [c for c in all_contribs if c["type"] == "safe"]

    net_risk = sum(c["contrib"] for c in raw_risk_tokens)
    net_safe = sum(c["abs_contrib"] for c in raw_safe_tokens)
    total_logit = intercept + (net_risk - net_safe)
    prob = 1.0 / (1.0 + np.exp(-total_logit))

    # Compute percentage contribution of top tokens
    top_risk_tokens = []
    for c in raw_risk_tokens[:6]:
        pct = round((c["contrib"] / net_risk * 100), 1) if net_risk > 0 else 0.0
        top_risk_tokens.append({
            "ngram": c["ngram"],
            "weight": c["weight"],
            "contrib": c["contrib"],
            "pct": pct,
        })

    top_safe_tokens = []
    for c in raw_safe_tokens[:6]:
        pct = round((c["abs_contrib"] / net_safe * 100), 1) if net_safe > 0 else 0.0
        top_safe_tokens.append({
            "ngram": c["ngram"],
            "weight": c["weight"],
            "contrib": c["contrib"],
            "pct": pct,
        })

    # Per-character net risk scoring & normalization
    net_char = [max(0.0, r - s) for r, s in zip(char_risk, char_safe)]
    max_c = max(net_char) if net_char and max(net_char) > 0 else 1.0

    char_heatmap = []
    for idx, (ch, nc) in enumerate(zip(norm_url, net_char)):
        intensity = round(nc / max_c, 3) if max_c > 0 else 0.0
        
        # Categorize tier
        if intensity >= 0.70:
            tier = "critical"
        elif intensity >= 0.40:
            tier = "high"
        elif intensity >= 0.15:
            tier = "medium"
        else:
            tier = "low"

        # Find the single most influential n-gram covering this character
        top_tok = None
        top_tok_weight = 0.0
        if char_ngrams[idx]:
            best = sorted(char_ngrams[idx], key=lambda x: abs(x[1]), reverse=True)[0]
            top_tok = best[0]
            top_tok_weight = round(best[1], 4)

        char_heatmap.append({
            "char": ch,
            "index": idx,
            "intensity": intensity,
            "tier": tier,
            "risk_score": round(nc, 4),
            "top_token": top_tok,
            "token_impact": top_tok_weight,
        })

    # Synthesize plain-English XAI narrative
    if prob >= 0.50:
        top_danger_subtokens = [f"'{t['ngram']}'" for t in top_risk_tokens[:3]]
        joined_danger = ", ".join(top_danger_subtokens) if top_danger_subtokens else "lexical anomaly patterns"
        narrative = (
            f"The model's linear decision boundary flagged this URL with a logit of {total_logit:+.2f}. "
            f"Adversarial risk is predominantly concentrated in the sub-word patterns {joined_danger}, "
            f"generating +{net_risk:.2f} units of malicious evidence that overcome benign structural anchors."
        )
    else:
        top_clean_subtokens = [f"'{t['ngram']}'" for t in top_safe_tokens[:3]]
        joined_clean = ", ".join(top_clean_subtokens) if top_clean_subtokens else "trusted TLS tokens"
        narrative = (
            f"The model's linear decision boundary resolved this URL with a benign logit of {total_logit:+.2f}. "
            f"Structural trust anchors {joined_clean} generated -{net_safe:.2f} units of safe resistance, "
            f"suppressing deceptive pattern risks."
        )

    return {
        "status": "ready",
        "norm_url": norm_url,
        "intercept": round(intercept, 3),
        "net_risk_evidence": round(net_risk, 3),
        "net_safe_evidence": round(net_safe, 3),
        "decision_logit": round(total_logit, 3),
        "ml_probability": round(prob * 100, 2),
        "active_features_count": len(indices),
        "top_risk_tokens": top_risk_tokens,
        "top_safe_tokens": top_safe_tokens,
        "char_heatmap": char_heatmap,
        "narrative": narrative,
    }

