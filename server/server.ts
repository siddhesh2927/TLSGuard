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

console.log("VT KEY:", process.env.VIRUSTOTAL_API_KEY ? process.env.VIRUSTOTAL_API_KEY.slice(0, 5) + "..." : "undefined");
console.log("ABUSE KEY:", process.env.ABUSEIPDB_API_KEY ? process.env.ABUSEIPDB_API_KEY.slice(0, 5) + "..." : "undefined");
console.log("IPINFO:", process.env.IPINFO_TOKEN ? process.env.IPINFO_TOKEN.slice(0, 5) + "..." : "undefined");

// ─────────────────────────────────────────────
// Database Init
// ─────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    ip_address TEXT,
    prediction TEXT,
    confidence REAL,
    risk_score INTEGER,
    security_posture TEXT,
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
    tls TEXT,
    intel TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Migration: Add columns if they don't exist
try { db.exec("ALTER TABLE scans ADD COLUMN tls TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE scans ADD COLUMN intel TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE scans ADD COLUMN security_posture TEXT"); } catch (e) {}

const ML_SERVICE_URL = process.env.ML_SERVICE_URL || "http://localhost:5001";

// ─────────────────────────────────────────────
// TLS Info Extraction
// ─────────────────────────────────────────────
async function getTLSInfo(domain: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        const formatDN = (dn: any) => {
          if (!dn) return "Unknown";
          if (typeof dn === "string") return dn;
          return dn.O || dn.CN || JSON.stringify(dn);
        };

        const info = {
          tlsVersion: protocol,
          cipherSuite: cipher.name,
          issuer: formatDN(cert.issuer),
          validFrom: cert.valid_from
            ? new Date(cert.valid_from).toISOString()
            : "Unknown",
          validTo: cert.valid_to
            ? new Date(cert.valid_to).toISOString()
            : "Unknown",
          subject: formatDN(cert.subject),
          fingerprint: cert.fingerprint,
        };

        socket.end();
        resolve(info);
      }
    );

    socket.on("error", reject);

    socket.setTimeout(10000, () => {
      socket.destroy();
      reject(new Error("Timeout connecting to " + domain));
    });
  });
}

// ─────────────────────────────────────────────
// Threat Intelligence Collection
// ─────────────────────────────────────────────
async function getThreatIntel(domain: string, ip: string) {
  let vtScore = 0;
  let abuseScore = 0;
  let hosting = "Unknown";
  let country = "Unknown";

  try {
    if (process.env.VIRUSTOTAL_API_KEY) {
      const res = await axios.get(
        `https://www.virustotal.com/api/v3/domains/${domain}`,
        { headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY } }
      );
      console.log("VT RAW:", JSON.stringify(res.data, null, 2));
      vtScore = res.data?.data?.attributes?.last_analysis_stats?.malicious || 0;
    }
  } catch (err: any) {
    console.error("[TLSGuard] VirusTotal API Error:", err.response?.data || err.message);
  }

  try {
    if (process.env.ABUSEIPDB_API_KEY && ip) {
      const res = await axios.get(
        `https://api.abuseipdb.com/api/v2/check`,
        {
          params: { ipAddress: ip },
          headers: {
            Key: process.env.ABUSEIPDB_API_KEY,
            Accept: "application/json",
          },
        }
      );
      console.log("ABUSE RAW:", JSON.stringify(res.data, null, 2));
      abuseScore = res.data?.data?.abuseConfidenceScore || 0;
    } else if (!ip) {
      console.warn("Skipping ABUSEIPDB - missing IP for domain:", domain);
    }
  } catch (err: any) {
    console.error("[TLSGuard] AbuseIPDB API Error:", err.response?.data || err.message);
  }

  try {
    if (process.env.IPINFO_TOKEN && ip) {
      const res = await axios.get(
        `https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN}`
      );
      console.log("IPINFO RAW:", JSON.stringify(res.data, null, 2));
      hosting = res.data?.org || "Unknown";
      country = res.data?.country || "Unknown";
    } else if (!ip) {
       console.warn("Skipping IPINFO - missing IP for domain:", domain);
    }
  } catch (err: any) {
    console.error("[TLSGuard] IPINFO API Error:", err.response?.data || err.message);
  }

  return { vtScore, abuseScore, hosting, country };
}

// ─────────────────────────────────────────────
// ML Risk Assessment
// All risk scoring and classification is driven entirely
// by the ML model — no hardcoded rules or weightings.
// ─────────────────────────────────────────────
async function assessRisk(tlsInfo: any, threatIntel: any) {
  const res = await axios.post(`${ML_SERVICE_URL}/predict`, {
    tls_version: tlsInfo.tlsVersion,
    cipher_suite: tlsInfo.cipherSuite,
    issuer: tlsInfo.issuer,
    valid_from: tlsInfo.validFrom,
    valid_to: tlsInfo.validTo,
    vt_score: threatIntel.vtScore,
    abuse_score: threatIntel.abuseScore,
    hosting: threatIntel.hosting,
    country: threatIntel.country,
  });

  return res.data;
}

// ─────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────
async function startServer() {
  const app = express();
  const PORT = 3001;

  app.use(express.json());

  // GET /api/history — Retrieve all past scans
  app.get("/api/history", (req, res) => {
    try {
      const scans = db.prepare("SELECT * FROM scans ORDER BY created_at DESC").all();
      const parsedScans = scans.map((s: any) => ({
        ...s,
        tls_risk_score:  s.risk_score,
        security_level:  s.risk_score < 30 ? "low" : s.risk_score < 70 ? "moderate" : "high",
        security_posture: s.security_posture || (s.risk_score < 30 ? "secure" : s.risk_score < 70 ? "moderate" : "risky"),
        high_risk:       s.risk_score > 60,
        tls:             JSON.parse(s.tls || "{}"),
        intel:           JSON.parse(s.intel || "{}"),
        feature_importance: JSON.parse(s.feature_importance || "[]"),
      }));
      res.json(parsedScans);
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // DELETE /api/scan/:id — Remove a scan record
  app.delete("/api/scan/:id", (req, res) => {
    try {
      const { id } = req.params;
      db.prepare("DELETE FROM scans WHERE id = ?").run(id);
      res.json({ success: true });
    } catch (e: any) {
      res.status(500).json({ error: e.message });
    }
  });

  // POST /api/scan — Run a new security assessment
  app.post("/api/scan", async (req, res) => {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: "Domain required" });

    try {
      // Step 1: TLS Handshake & Certificate Extraction
      let tlsInfo: any;
      try {
        tlsInfo = await getTLSInfo(domain);
      } catch (tlsErr: any) {
        console.warn(`[TLSGuard] TLS Handshake failed for ${domain}:`, tlsErr.message);
        tlsInfo = {
          tlsVersion:  "Unknown (No TLS)",
          cipherSuite: "None",
          issuer:      "Unknown / Connection Failed",
          validFrom:   "Unknown",
          validTo:     "Unknown",
          subject:     "Unknown",
          fingerprint: "None",
        };
      }

      // Step 2: IP Resolution
      const dns = await import("dns/promises");
      console.log(`[TLSGuard] Resolving IP for domain: ${domain}`);
      let ip = "";
      try {
        const addresses = await dns.resolve4(domain);
        ip = addresses[0] || "";
      } catch (err: any) {
        console.warn(`[TLSGuard] DNS Resolve4 failed:`, err.message);
        try {
          const lookup = await dns.lookup(domain);
          ip = lookup.address || "";
        } catch (lookupErr: any) {
          console.error(`[TLSGuard] DNS Lookup also failed:`, lookupErr.message);
        }
      }

      // Step 3: Threat Intelligence
      console.log(`[TLSGuard] Final IP selected: ${ip}`);
      const threatIntel = await getThreatIntel(domain, ip);

      // Step 4: ML-Driven Risk Assessment
      const mlResult = await assessRisk(tlsInfo, threatIntel);

      // Step 5: Compose final risk score from ML model output only
      const finalRisk = Math.min(100, Math.max(0, Math.round(mlResult.tls_risk_score)));

      // prediction label: reflects security posture, not phishing classification
      const prediction = mlResult.security_posture === "risky"
        ? "high_risk"
        : mlResult.security_posture === "moderate"
          ? "moderate_risk"
          : "secure";

      const responseData = {
        domain,
        ip_address:       ip,
        prediction,
        risk_score:        finalRisk,
        security_posture:  mlResult.security_posture,
        tls_version:       tlsInfo.tlsVersion,
        cipher_suite:      tlsInfo.cipherSuite,
        issuer:            tlsInfo.issuer,
        valid_from:        tlsInfo.validFrom,
        valid_to:          tlsInfo.validTo,
        virustotal_score:  threatIntel.vtScore,
        abuseipdb_score:   threatIntel.abuseScore,
        hosting_provider:  threatIntel.hosting,
        country:           threatIntel.country,
        feature_importance: JSON.stringify(mlResult.feature_importance || []),
        tls:               JSON.stringify(tlsInfo),
        intel:             JSON.stringify(threatIntel),
      };

      const stmt = db.prepare(`
        INSERT INTO scans (
          domain, ip_address, prediction, risk_score, security_posture,
          tls_version, cipher_suite, issuer, valid_from, valid_to,
          virustotal_score, abuseipdb_score, hosting_provider, country,
          feature_importance, tls, intel
        ) VALUES (
          @domain, @ip_address, @prediction, @risk_score, @security_posture,
          @tls_version, @cipher_suite, @issuer, @valid_from, @valid_to,
          @virustotal_score, @abuseipdb_score, @hosting_provider, @country,
          @feature_importance, @tls, @intel
        )
      `);

      const info = stmt.run(responseData);
      const savedScan = db.prepare("SELECT * FROM scans WHERE id = ?").get(info.lastInsertRowid) as any;

      res.json({
        ...savedScan,
        tls_risk_score:    savedScan.risk_score,
        security_level:    savedScan.risk_score < 30 ? "low" : savedScan.risk_score < 70 ? "moderate" : "high",
        security_posture:  savedScan.security_posture,
        high_risk:         savedScan.risk_score > 60,
        confidence:        mlResult.confidence,
        tls:               JSON.parse(savedScan.tls || "{}"),
        intel:             JSON.parse(savedScan.intel || "{}"),
        feature_importance: JSON.parse(savedScan.feature_importance || "[]"),
      });
    } catch (e: any) {
      console.error(e);
      res.status(500).json({ error: e.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`[TLSGuard] Security assessment server running on http://localhost:${PORT}`);
  });
}

startServer();