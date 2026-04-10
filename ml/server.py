from flask import Flask, request, jsonify
import joblib
import numpy as np
import os
from datetime import datetime

app = Flask(__name__)

BASE = os.path.dirname(__file__)

print("[TLSGuard] Loading model and scaler...")
model = joblib.load(os.path.join(BASE, "model.pkl"))
scaler = joblib.load(os.path.join(BASE, "scaler.pkl"))
feature_names = joblib.load(os.path.join(BASE, "feature_names.pkl"))
print(f"[TLSGuard] Loaded model with {len(feature_names)} features")

# ─────────────────────────────────────────────
# Human-readable labels for features
# ─────────────────────────────────────────────
FEATURE_LABELS = {
    "TLSv1.3":            "TLS 1.3 Protocol",
    "TLSv1.2":            "TLS 1.2 Protocol",
    "TLSv1.1":            "TLS 1.1 Protocol (Deprecated)",
    "TLSv1":              "TLS 1.0 Protocol (Insecure)",
    "SSLv3":              "SSLv3 Protocol (Insecure)",
    "cert_validity_ratio":"Certificate Validity Duration",
    "issuer_trusted":     "Trusted Certificate Issuer",
    "cipher_risk":        "Weak Cipher Suite (SHA1/MD5)",
    "country_risk":       "High-Risk Country Origin",
    "vt_score":           "VirusTotal Detections",
    "abuse_score":        "AbuseIPDB Confidence Score",
}

# ─────────────────────────────────────────────
# Feature Builder
# ─────────────────────────────────────────────
def build_features(payload):
    # Calculate cert_validity_ratio
    days_valid = 0
    try:
        if payload.get("valid_from") and payload.get("valid_to") and payload.get("valid_from") != "Unknown":
            fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
            start = datetime.strptime(payload.get("valid_from"), fmt)
            end = datetime.strptime(payload.get("valid_to"), fmt)
            days_valid = (end - start).days
    except:
        pass

    # Mapping keys from Node.js server to training features
    mapping = {
        "TLSv1.3":            1 if "1.3" in str(payload.get("tls_version", "")) else 0,
        "TLSv1.2":            1 if "1.2" in str(payload.get("tls_version", "")) else 0,
        "TLSv1.1":            1 if "1.1" in str(payload.get("tls_version", "")) else 0,
        "TLSv1":              1 if "TLSv1" == str(payload.get("tls_version", "")) else 0,
        "SSLv3":              1 if "SSLv3" in str(payload.get("tls_version", "")) else 0,
        "cert_validity_ratio":min(1.0, days_valid / 365.0) if days_valid > 0 else 0.0,
        "issuer_trusted":     1 if payload.get("issuer") and "Let's Encrypt" in str(payload.get("issuer")) else 0,
        "cipher_risk":        1.0 if "SHA1" in str(payload.get("cipher_suite", "")) or "MD5" in str(payload.get("cipher_suite", "")) else 0.0,
        "country_risk":       1.0 if payload.get("country") in ["CN", "RU", "IR", "KP"] else 0.0,
        "vt_score":           float(payload.get("vt_score", 0)),
        "abuse_score":        float(payload.get("abuse_score", 0)) / 100.0,
    }

    vec = [mapping.get(feat, 0.0) for feat in feature_names]
    return np.array([vec], dtype=np.float32), mapping


# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route("/predict", methods=["POST"])
def predict():
    try:
        payload = request.get_json()

        X, mapping = build_features(payload)
        X_scaled = scaler.transform(X)
        probs = model.predict_proba(X_scaled)[0]
        risk_prob = float(probs[1])  # malicious/risky class probability
        tls_risk_score = int(round(risk_prob * 100))

        # ── Security posture classification ──
        if tls_risk_score < 30:
            security_posture = "secure"
            security_level   = "low"
        elif tls_risk_score < 70:
            security_posture = "moderate"
            security_level   = "moderate"
        else:
            security_posture = "risky"
            security_level   = "high"

        # ── Feature importance ──
        # Uses global model importances weighted by actual feature value
        # to produce per-prediction directional signal.
        importances = model.feature_importances_
        feat_imp = []
        for name, imp in zip(feature_names, importances):
            feat_val = mapping.get(name, 0.0)
            label    = FEATURE_LABELS.get(name, name)

            # Direction: does this feature's value push risk UP or DOWN?
            # Risk-increasing features: cipher_risk, country_risk, vt_score,
            #   abuse_score, TLSv1.1, TLSv1, SSLv3 → high value = more risk
            # Risk-reducing features: TLSv1.3, TLSv1.2, issuer_trusted,
            #   cert_validity_ratio → high value = less risk
            risk_increasing = name in [
                "cipher_risk", "country_risk", "vt_score",
                "abuse_score", "TLSv1.1", "TLSv1", "SSLv3"
            ]
            if risk_increasing:
                impact = "increases_risk" if feat_val > 0 else "neutral"
            else:
                impact = "reduces_risk" if feat_val > 0 else "neutral"

            feat_imp.append({
                "feature":   name,
                "label":     label,
                "importance": int(round(imp * 100)),
                "value":     round(float(feat_val), 4),
                "impact":    impact,
            })

        # Sort by raw importance descending
        feat_imp = sorted(feat_imp, key=lambda x: x["importance"], reverse=True)
        print(f"[TLSGuard] Prediction: risk_score={tls_risk_score}, posture={security_posture}")

        return jsonify({
            "tls_risk_score":   tls_risk_score,
            "security_posture": security_posture,   # "secure" | "moderate" | "risky"
            "security_level":   security_level,     # "low" | "moderate" | "high"
            "high_risk":        tls_risk_score > 60,
            "confidence":       round(risk_prob, 4),
            "feature_importance": feat_imp,
        })

    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_features": len(feature_names)})


if __name__ == "__main__":
    app.run(port=5001)