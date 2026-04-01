import "dotenv/config";
import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import tls from "tls";
import axios from "axios";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const db = new Database("tlsguard.db");

// Initialize Database
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip_address TEXT,
    prediction TEXT,
    confidence REAL,
    risk_score INTEGER,
    tls_version TEXT,
    cipher_suite TEXT,
    issuer TEXT,
    valid_from TEXT,
    valid_to TEXT,
    virustotal_score INTEGER,
    abuseipdb_score INTEGER,
    hosting_provider TEXT,
    country TEXT,
    feature_importance TEXT,
    reasoning TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:5001";

async function getTLSInfo(domain: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const options = {
      host: domain,
      port: 443,
      servername: domain,
      rejectUnauthorized: false, // We want to scan even if self-signed
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate(true);
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();

      const info = {
        tlsVersion: protocol,
        cipherSuite: cipher.name,
        issuer: cert.issuer?.O || cert.issuer?.CN,
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        subject: cert.subject?.CN,
        fingerprint: cert.fingerprint,
        raw: cert
      };
      
      socket.end();
      resolve(info);
    });

    socket.on("error", (err) => {
      reject(err);
    });

    socket.setTimeout(5000, () => {
      socket.destroy();
      reject(new Error("Timeout connecting to " + domain));
    });
  });
}

async function getThreatIntel(domain: string, ip: string) {
  const vtKey = process.env.VIRUSTOTAL_API_KEY;
  const abuseKey = process.env.ABUSEIPDB_API_KEY;
  const ipinfoToken = process.env.IPINFO_TOKEN;

  let vtScore = 0;
  let abuseScore = 0;
  let hosting = "Unknown";
  let country = "Unknown";

  try {
    if (vtKey) {
      const vtRes = await axios.get(`https://www.virustotal.com/api/v3/domains/${domain}`, {
        headers: { "x-apikey": vtKey }
      });
      vtScore = vtRes.data.data.attributes.last_analysis_stats.malicious;
    }
  } catch (e) {}

  try {
    if (abuseKey && ip) {
      const abuseRes = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
        params: { ipAddress: ip },
        headers: { "Key": abuseKey, "Accept": "application/json" }
      });
      abuseScore = abuseRes.data.data.abuseConfidenceScore;
    }
  } catch (e) {}

  try {
    if (ipinfoToken && ip) {
      const ipinfoRes = await axios.get(`https://ipinfo.io/${ip}?token=${ipinfoToken}`);
      hosting = ipinfoRes.data.org || "Unknown";
      country = ipinfoRes.data.country || "Unknown";
    }
  } catch (e) {}

  return { vtScore, abuseScore, hosting, country };
}

async function predictRisk(tlsInfo: any, threatIntel: any) {
  // Call our locally-trained Python ML model (MLP Neural Network)
  try {
    const res = await axios.post(`${ML_SERVICE_URL}/predict`, {
      tls_version:  tlsInfo.tlsVersion,
      cipher_suite: tlsInfo.cipherSuite,
      issuer:       tlsInfo.issuer,
      valid_from:   tlsInfo.validFrom,
      valid_to:     tlsInfo.validTo,
      vt_score:     threatIntel.vtScore,
      abuse_score:  threatIntel.abuseScore,
      hosting:      threatIntel.hosting,
      country:      threatIntel.country,
    }, { timeout: 10000 });
    return res.data;
  } catch (e) {
    console.warn("[TLSGuard] ML service unreachable, using fallback heuristic.", (e as any).message);
    // Fallback heuristic when Python service is down
    const risk = (threatIntel.vtScore * 10) + (threatIntel.abuseScore / 2);
    return {
      prediction: risk > 50 ? "phishing" : "benign",
      confidence: 0.65,
      risk_score: Math.min(100, Math.round(risk)),
      reasoning: "Heuristic fallback: ML service unavailable. Score based on VirusTotal and AbuseIPDB signals only.",
      feature_importance: [
        { feature: "VirusTotal Detections", importance: 80, impact: "positive" },
        { feature: "AbuseIPDB Score",       importance: 60, impact: "positive" }
      ]
    };
  }
}

async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3001;

  app.use(express.json());

  // API Routes
  app.post("/api/scan", async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "Domain is required" });

    try {
      const tlsInfo = await getTLSInfo(domain);
      // Simple IP lookup for threat intel
      const dns = await import("dns/promises");
      const addresses = await dns.resolve4(domain).catch(() => []);
      const ip = addresses[0] || "";

      const threatIntel = await getThreatIntel(domain, ip);
      const prediction = await predictRisk(tlsInfo, threatIntel);

      const stmt = db.prepare(`
        INSERT INTO scans (
          domain, ip_address, prediction, confidence, risk_score, 
          tls_version, cipher_suite, issuer, valid_from, valid_to,
          virustotal_score, abuseipdb_score, hosting_provider, country,
          feature_importance, reasoning
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const result = stmt.run(
        domain, ip, prediction.prediction, prediction.confidence, prediction.risk_score,
        tlsInfo.tlsVersion, tlsInfo.cipherSuite, tlsInfo.issuer, tlsInfo.validFrom, tlsInfo.validTo,
        threatIntel.vtScore, threatIntel.abuseScore, threatIntel.hosting, threatIntel.country,
        JSON.stringify(prediction.feature_importance), prediction.reasoning
      );

      res.json({
        id: result.lastInsertRowid,
        domain,
        ip,
        ...prediction,
        tls: tlsInfo,
        intel: threatIntel
      });
    } catch (error: any) {
      console.error(error);
      res.status(500).json({ error: error.message });
    }
  });

  app.get("/api/history", (req, res) => {
    const scans = db.prepare("SELECT * FROM scans ORDER BY created_at DESC LIMIT 50").all();
    const parsedScans = scans.map(s => ({
      ...s,
      feature_importance: s.feature_importance ? JSON.parse(s.feature_importance) : []
    }));
    res.json(parsedScans);
  });

  app.get("/api/report/:id", (req, res) => {
    const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(req.params.id);
    if (!scan) return res.status(404).json({ error: "Scan not found" });
    res.json(scan);
  });

  app.delete("/api/scan/:id", (req, res) => {
    const result = db.prepare("DELETE FROM scans WHERE id = ?").run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: "Scan not found" });
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
      root: path.resolve(__dirname, "../client")
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, "../client/dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.resolve(__dirname, "../client/dist", "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
