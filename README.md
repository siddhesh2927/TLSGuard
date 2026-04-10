# TLSGuard — TLS Security Risk Assessment System

> **"Evaluates TLS and certificate-level security signals to estimate the risk posture of a domain using machine learning."**

---

## What TLSGuard Does

TLSGuard is a **domain security posture analyzer**, not a phishing detector.

It evaluates the **network-level security configuration** of any domain by analyzing its TLS setup, certificate chain, and cross-referencing external threat intelligence sources. All risk estimation is driven by a trained machine learning model — there are no hardcoded rules or static score weightings.

---

## How It Works — 6 Steps

```
1. INPUT          → User submits a domain name
2. TLS HANDSHAKE  → System extracts protocol, cipher suite, certificate metadata
3. THREAT INTEL   → VirusTotal + AbuseIPDB + IPInfo APIs queried
4. FEATURE ENG.   → Raw data converted into structured ML features
5. ML INFERENCE   → Trained model outputs probabilistic risk score (0–100)
6. REPORT         → Security posture classification + feature signal breakdown
```

---

## Signal → Feature Mapping (What the Model Analyzes)

| Raw Signal | Engineered Feature | Risk Direction |
|---|---|---|
| TLS 1.3 | `TLSv1.3` = 1 | ↓ Reduces risk |
| TLS 1.2 | `TLSv1.2` = 1 | ↓ Reduces risk |
| TLS 1.0 / 1.1 | `TLSv1` / `TLSv1.1` = 1 | ↑ Increases risk |
| SSLv3 | `SSLv3` = 1 | ↑ High risk |
| Short cert validity | `cert_validity_ratio` < 0.5 | ↑ Increases risk |
| Self-signed / untrusted issuer | `issuer_trusted` = 0 | ↑ Increases risk |
| SHA1/MD5 cipher | `cipher_risk` = 1 | ↑ Increases risk |
| High VirusTotal detections | `vt_score` > 0 | ↑ Increases risk |
| High AbuseIPDB score | `abuse_score` → normalized 0–1 | ↑ Increases risk |
| Origin CN/RU/IR/KP | `country_risk` = 1 | ↑ Increases risk |

---

## Output — What the System Reports

| Output Field | Description |
|---|---|
| **Risk Score** | 0–100 probabilistic score from ML model |
| **Security Posture** | `secure` / `moderate` / `risky` |
| **Security Level** | `low` / `moderate` / `high` |
| **ML Confidence** | Model's probability for the risky class |
| **Feature Importance** | Which signals drove the score (with direction) |
| **TLS Details** | Protocol, cipher, issuer, validity dates |
| **Threat Intel** | VirusTotal, AbuseIPDB, hosting, country |

### Output Language

| ❌ Incorrect | ✅ Correct |
|---|---|
| "This site is phishing" | "This site has a high-risk TLS configuration" |
| "Benign / Malicious" | "Secure / Moderate Risk / High Risk" |

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   Browser (React)                │
│  - Domain input, scan progress, report view      │
│  - Feature importance bar chart                  │
└───────────────────┬──────────────────────────────┘
                    │ HTTP
┌───────────────────▼──────────────────────────────┐
│         Node.js / Express API (port 3001)        │
│  - TLS handshake (Node tls module)               │
│  - DNS resolution                                │
│  - Threat Intel API calls                        │
│  - SQLite persistence (better-sqlite3)           │
└───────────────────┬──────────────────────────────┘
                    │ HTTP
┌───────────────────▼──────────────────────────────┐
│         Python / Flask ML Server (port 5001)     │
│  - Feature engineering                           │
│  - RandomForest / GBM model inference            │
│  - Feature importance per prediction             │
└──────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React + TypeScript (Vite), Recharts, Framer Motion |
| Backend | Node.js + Express + TypeScript |
| Database | SQLite via better-sqlite3 |
| ML Server | Python + Flask + scikit-learn + joblib |
| Threat Intel | VirusTotal API v3, AbuseIPDB API v2, IPInfo |

---

## Running Locally

### Prerequisites
- Node.js ≥ 18
- Python ≥ 3.9
- API keys: VirusTotal, AbuseIPDB, IPInfo

### 1. Start the ML Server
```bash
cd ml
pip install -r requirements.txt
python server.py
# Runs on http://localhost:5001
```

### 2. Configure Environment
```bash
cp server/.env.example server/.env
# Fill in: VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, IPINFO_TOKEN
```

### 3. Start the Full Stack
```bash
npm install         # root
npm run dev         # starts both Node API + Vite dev server
```

Open [http://localhost:3001](http://localhost:3001)

---

## Interview Summary

> The system evaluates the security posture of a domain by analyzing its TLS configuration and certificate properties alongside external threat intelligence signals. Rather than detecting phishing directly, the model identifies risk patterns — such as weak encryption, untrusted certificate issuers, short certificate lifespans, and known threat indicators — and transforms these into structured features fed into a trained ML model. The model outputs a probabilistic risk score and security posture classification, enabling assessment of how secure or potentially risky a domain is based on its network-level behavior, rather than relying on blacklists or signature-based detection.

---

## Similar Real-World Systems

- SSL Labs SSL Test
- Qualys SSL Server Test  
- SecurityScorecard domain ratings
- Risk scoring engines in SOC/SIEM tools

---

*TLSGuard is a security research and educational project.*
