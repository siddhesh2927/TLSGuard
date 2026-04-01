# TLSGuard: Phishing Detection via TLS Fingerprinting

<div align="center">
<img width="1200" height="475" alt="TLSGuard Banner" src="https://github.com/user-attachments/assets/0aa67016-6eaf-458a-adb2-6e31a0763ed6" />
</div>

## 🛡️ Overview
**TLSGuard** is a high-performance security tool that identifies phishing websites by analyzing their **TLS Infrastructure Fingerprints**. 

Unlike traditional methods that rely on blocklists, TLSGuard uses a **Neural Network (MLP)** trained on over 125,000+ domains to detect malicious infrastructure patterns, cipher-suite anomalies, and threat intelligence signals in real-time.

### Key Features
- **Real-time TLS Handshake Analysis**: Extracts protocol versions, ciphers, and certificate metadata.
- **Deep Learning Classifier**: Multi-layer Perceptron (MLP) achieves **99.98% Recall** on phishing detection.
- **Hybrid Intelligence**: Combines structural TLS signals with live threat data from VirusTotal and AbuseIPDB.
- **Explainable AI**: Provides "Feature Importance" breakdowns for every scan.

---

## 🚀 Getting Started

### 1. Prerequisites
- **Node.js** (v18+)
- **Python** (v3.9+)
- API Keys for **VirusTotal**, **AbuseIPDB**, and **IPinfo** (Optional but recommended).

### 2. Installation

#### Clone the Repository
```bash
git clone https://github.com/your-username/tlsguard.git
cd tlsguard
```

#### Set Up Environment
Copy the example environment file and add your API keys:
```bash
cp .env.example .env
```

#### Install Backend & Frontend (Node.js)
```bash
npm install
```

#### Install ML Service (Python)
```bash
pip install -r ml/requirements.txt
```

---

## 🛠️ Usage

### 1. Train the Model (Optional)
If you have a new dataset, you can retrain the model:
```bash
python ml/train.py
```

### 2. Start the ML Service
The ML microservice must be running for predictions to work:
```bash
python ml/server.py
```

### 3. Start the Web App
In a new terminal, start the main application:
```bash
npm run dev
```
Open **[http://localhost:3001](http://localhost:3001)** in your browser.

---

## 🏗️ Architecture
- **Frontend**: React + Tailwind CSS + Framer Motion.
- **Backend API**: Node.js + Express + Better-SQLite3.
- **ML Microservice**: Python Flask + Scikit-Learn (MLP Neural Network).
- **Network**: Service-to-service communication via HTTP/REST.

## 🔒 Security
Your API keys are stored in the `.env` file, which is ignored by Git. **Never** commit your `.env` file to a public repository.

---
© 2026 TLSGUARD • SECURE INFRASTRUCTURE ANALYSIS
