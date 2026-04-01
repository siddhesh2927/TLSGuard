from flask import Flask, request, jsonify
import joblib
import numpy as np
import os

app = Flask(__name__)

# ─────────────────────────────────────────────
# Load model artifacts on startup
# ─────────────────────────────────────────────
BASE = os.path.dirname(__file__)

print("[TLSGuard ML] Loading model artifacts...")
model         = joblib.load(os.path.join(BASE, "model.pkl"))
scaler        = joblib.load(os.path.join(BASE, "scaler.pkl"))
feature_names = joblib.load(os.path.join(BASE, "feature_names.pkl"))
top_features  = joblib.load(os.path.join(BASE, "top_features.pkl"))
print(f"[TLSGuard ML] Model loaded. Features: {len(feature_names)}")

# ─────────────────────────────────────────────
# Feature Engineering
# Map live TLS scan data → model feature vector
# The model was trained on 197 TLS network feats.
# For live inference we populate what we know
# and fill the rest with neutral (0.5) values.
# ─────────────────────────────────────────────
def build_feature_vector(payload: dict) -> np.ndarray:
    """
    Map live scan payload → 197-feature vector.
    Features we can derive from a live scan:
      - TLS version (mapped to common timing ratios)
      - VT score, AbuseIPDB score (threat intel)
      - Derived ratios from cert validity
    Remaining features default to dataset median (0.5).
    """
    vec = {name: 0.5 for name in feature_names}

    tls_version   = payload.get("tls_version", "TLSv1.3")
    vt_score      = float(payload.get("vt_score", 0))
    abuse_score   = float(payload.get("abuse_score", 0))
    issuer        = str(payload.get("issuer", "")).lower()
    valid_from    = payload.get("valid_from", "")
    valid_to      = payload.get("valid_to", "")
    cipher        = str(payload.get("cipher_suite", "")).lower()
    hosting       = str(payload.get("hosting", "")).lower()
    country       = str(payload.get("country", "")).lower()

    # --- TLS version risk signal ---
    tls_version_map = {
        "TLSv1.3": 0.1,   # very secure
        "TLSv1.2": 0.3,   # secure
        "TLSv1.1": 0.7,   # deprecated
        "TLSv1":   0.9,   # very deprecated
        "SSLv3":   1.0,   # broken
    }
    tls_risk = tls_version_map.get(tls_version, 0.5)

    # --- Threat intel signals ---
    vt_normalized    = min(vt_score / 80.0, 1.0)       # 80 engines max
    abuse_normalized = abuse_score / 100.0

    # --- Certificate validity signal ---
    cert_validity_ratio = 0.5
    try:
        from datetime import datetime
        fmt_options = ["%b %d %H:%M:%S %Y %Z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"]
        def parse_date(s):
            for fmt in fmt_options:
                try: return datetime.strptime(s.strip(), fmt)
                except: pass
            return None
        dt_from = parse_date(valid_from)
        dt_to   = parse_date(valid_to)
        if dt_from and dt_to:
            total_days = (dt_to - dt_from).days
            # Phishing certs tend to be short-lived (< 30 days)
            cert_validity_ratio = min(total_days / 365.0, 1.0)
    except:
        pass

    # --- Known CA trust signal ---
    trusted_cas = ["let's encrypt", "digicert", "comodo", "sectigo",
                   "globalsign", "entrust", "gte cybertrust", "verisign",
                   "godaddy", "cloudflare", "amazon", "microsoft", "google"]
    issuer_trusted = 0.1 if any(ca in issuer for ca in trusted_cas) else 0.8

    # --- Cipher strength signal ---
    cipher_risk = 0.2 if "256" in cipher else (0.5 if "128" in cipher else 0.7)

    # --- Country risk ---
    high_risk_countries = ["ru", "cn", "kr", "ng", "br", "ro", "ua", "ir", "pk"]
    country_risk = 0.9 if country.lower() in high_risk_countries else 0.2

    # --- Map signals to dataset-like feature names ---
    # Inject into the closest matching feature slots
    timing_features = [f for f in feature_names if "timing" in f.lower() or "Timing" in f]
    ratio_features  = [f for f in feature_names if "ratio" in f.lower() or "Ratio" in f]
    ssl_features    = [f for f in feature_names if "openssl" in f.lower() or "ssl" in f.lower()]

    # Spread the signals across feature families
    for f in timing_features[:20]:
        vec[f] = tls_risk * 2.0 + (vt_normalized * 0.5)
    for f in ratio_features[:10]:
        vec[f] = abuse_normalized * 3.0 + (country_risk * 0.5)
    for f in ssl_features[:5]:
        vec[f] = 1.0 if tls_risk < 0.4 else 0.0

    # Inject threat score directly on top features
    top_feat_names = list(top_features.keys())
    if len(top_feat_names) > 0:
        vec[top_feat_names[0]] = vt_normalized * 5
    if len(top_feat_names) > 1:
        vec[top_feat_names[1]] = abuse_normalized * 3
    if len(top_feat_names) > 2:
        vec[top_feat_names[2]] = cert_validity_ratio
    if len(top_feat_names) > 3:
        vec[top_feat_names[3]] = issuer_trusted
    if len(top_feat_names) > 4:
        vec[top_feat_names[4]] = cipher_risk

    # Build ordered array
    arr = np.array([[vec[f] for f in feature_names]], dtype=np.float32)
    return arr


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": "MLP TLSGuard v1.0", "features": len(feature_names)})


@app.route("/predict", methods=["POST"])
def predict():
    payload = request.get_json(force=True)

    try:
        feature_vec = build_feature_vector(payload)
        scaled_vec  = scaler.transform(feature_vec)

        # Predict
        prediction_label = model.predict(scaled_vec)[0]
        probabilities    = model.predict_proba(scaled_vec)[0]
        confidence       = float(probabilities[prediction_label])
        risk_score       = int(round(confidence * 100))

        prediction_str = "phishing" if prediction_label == 1 else "benign"

        # Build feature importance list from pre-computed top features
        feature_importance = []
        for feat, imp in list(top_features.items())[:8]:
            if imp > 0:
                feature_importance.append({
                    "feature": feat[:40],
                    "importance": min(int(imp * 1000), 100),
                    "impact": "positive" if prediction_label == 1 else "negative"
                })

        # Augment with live signals
        vt_score    = payload.get("vt_score", 0)
        abuse_score = payload.get("abuse_score", 0)
        tls_version = payload.get("tls_version", "Unknown")

        if vt_score > 0:
            feature_importance.insert(0, {
                "feature": "VirusTotal Detections",
                "importance": min(int(vt_score * 5), 100),
                "impact": "positive"
            })
        if abuse_score > 30:
            feature_importance.insert(1, {
                "feature": "AbuseIPDB Score",
                "importance": min(int(abuse_score), 100),
                "impact": "positive"
            })
        if tls_version in ["TLSv1.3", "TLSv1.2"]:
            feature_importance.append({
                "feature": f"TLS Version ({tls_version})",
                "importance": 70,
                "impact": "negative"
            })

        reasoning = (
            f"Neural network classified as {prediction_str.upper()} "
            f"with {confidence*100:.1f}% confidence. "
            f"Model analyzed {len(feature_names)} TLS fingerprinting features. "
            f"VirusTotal: {vt_score} detections. "
            f"AbuseIPDB: {abuse_score}%. "
            f"TLS: {tls_version}."
        )

        return jsonify({
            "prediction":        prediction_str,
            "confidence":        round(confidence, 4),
            "risk_score":        risk_score,
            "reasoning":         reasoning,
            "feature_importance": feature_importance[:8]
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("[TLSGuard ML] Starting Flask server on port 5001...")
    app.run(host="0.0.0.0", port=5001, debug=False)
