import React, { useState, useEffect } from "react";
import {
  Shield,
  Search,
  History,
  AlertTriangle,
  CheckCircle,
  Info,
  ExternalLink,
  Globe,
  Lock,
  Server,
  Activity,
  ArrowRight,
  ChevronRight,
  Loader2,
  Trash2,
  TrendingUp,
  Cpu,
  ShieldAlert,
  ShieldCheck,
  BarChart2,
  Zap,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  LineChart,
  Line,
  CartesianGrid,
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import axios from "axios";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// ─────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────
interface FeatureImportance {
  feature: string;
  label: string;
  importance: number;
  value: number;
  impact: "increases_risk" | "reduces_risk" | "neutral";
}

interface TLSInfo {
  tlsVersion: string;
  cipherSuite: string;
  issuer: string;
  validFrom: string;
  validTo: string;
}

interface ThreatIntel {
  vtScore: number;
  abuseScore: number;
  hosting: string;
  country: string;
}

interface ScanResult {
  id?: number;
  domain: string;
  tls_risk_score: number;
  security_level: string;
  security_posture: string; // "secure" | "moderate" | "risky"
  high_risk: boolean;
  confidence: number;
  prediction: string;
  tls: TLSInfo;
  intel: ThreatIntel;
  feature_importance?: FeatureImportance[];
  ip_address?: string;
  created_at?: string;
}

// ─────────────────────────────────────────────
// Shared UI Components
// ─────────────────────────────────────────────
const Card = ({
  children,
  className,
  title,
}: {
  children: React.ReactNode;
  className?: string;
  title?: string;
}) => (
  <div className={cn("bg-white border border-ink/10 rounded-xl overflow-hidden shadow-sm", className)}>
    {title && (
      <div className="px-5 py-2.5 border-b border-ink/10 bg-ink/[0.03]">
        <h3 className="text-[10px] uppercase tracking-widest font-mono font-bold opacity-60">
          {title}
        </h3>
      </div>
    )}
    <div className="p-5">{children}</div>
  </div>
);

const RiskBadge = ({ posture }: { posture: string }) => {
  if (posture === "risky")
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-red-50 text-red-600 border border-red-200">
        <ShieldAlert className="w-3 h-3" /> HIGH RISK
      </span>
    );
  if (posture === "moderate")
    return (
      <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-amber-50 text-amber-600 border border-amber-200">
        <AlertTriangle className="w-3 h-3" /> MODERATE RISK
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-emerald-50 text-emerald-600 border border-emerald-200">
      <ShieldCheck className="w-3 h-3" /> SECURE
    </span>
  );
};

// ─────────────────────────────────────────────
// App
// ─────────────────────────────────────────────
export default function App() {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [view, setView] = useState<"home" | "report" | "history">("home");

  const scanSteps = [
    "Initiating TLS Handshake...",
    "Extracting Certificate Metadata...",
    "Querying Threat Intelligence APIs...",
    "Running ML Risk Assessment...",
    "Computing Security Posture Score...",
  ];

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const res = await axios.get("/api/history");
      setHistory(res.data);
    } catch (e) {
      console.error("Failed to fetch history", e);
    }
  };

  const handleDelete = async (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (!confirm("Delete this scan record?")) return;
    try {
      await axios.delete(`/api/scan/${id}`);
      fetchHistory();
    } catch (e) {
      alert("Delete failed");
    }
  };

  const handleScan = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!domain) return;

    setIsScanning(true);
    setScanStep(0);

    const stepInterval = setInterval(() => {
      setScanStep((prev) => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 1400);

    try {
      const res = await axios.post("/api/scan", { domain });
      clearInterval(stepInterval);
      setScanStep(scanSteps.length - 1);
      setTimeout(() => {
        setSelectedScan(res.data);
        setView("report");
        fetchHistory();
        setIsScanning(false);
      }, 500);
    } catch (e: any) {
      clearInterval(stepInterval);
      alert("Assessment failed: " + (e.response?.data?.error || e.message));
      setIsScanning(false);
    }
  };

  // Chart data
  const riskData = selectedScan
    ? [
        { name: "Risk", value: selectedScan.tls_risk_score },
        { name: "Safe", value: 100 - selectedScan.tls_risk_score },
      ]
    : [];

  const riskColor =
    selectedScan?.security_posture === "risky"
      ? "#ef4444"
      : selectedScan?.security_posture === "moderate"
      ? "#f59e0b"
      : "#10b981";

  const trendData = history.map((s, i) => ({
    date: `#${i + 1}`,
    score: s.tls_risk_score,
    domain: s.domain,
  }));

  // Feature importance bar data (top 6)
  const featureBarData = (selectedScan?.feature_importance || [])
    .slice(0, 6)
    .map((f) => ({
      name: f.label || f.feature,
      value: f.importance,
      impact: f.impact,
    }));

  return (
    <div className="min-h-screen flex flex-col bg-bg">
      {/* ── Header ── */}
      <header className="border-b border-ink/10 px-6 py-4 flex items-center justify-between bg-white/70 backdrop-blur-md sticky top-0 z-50">
        <div
          className="flex items-center gap-3 cursor-pointer"
          onClick={() => setView("home")}
        >
          <div className="w-10 h-10 bg-ink flex items-center justify-center rounded-xl">
            <Shield className="text-bg w-5 h-5" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tighter leading-none">
              TLSGUARD
            </h1>
            <p className="text-[9px] font-mono opacity-40 uppercase tracking-widest">
              TLS Security Risk Assessment
            </p>
          </div>
        </div>

        <nav className="flex items-center gap-6">
          {(["home", "history"] as const).map((v) => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={cn(
                "text-[11px] font-mono uppercase tracking-widest hover:opacity-100 transition-opacity",
                view === v
                  ? "opacity-100 font-bold underline underline-offset-8"
                  : "opacity-40"
              )}
            >
              {v === "home" ? "Scanner" : "History"}
            </button>
          ))}
        </nav>
      </header>

      <main className="flex-1 max-w-7xl mx-auto w-full px-6 py-8">
        <AnimatePresence mode="wait">
          {/* ════════════════════════════════════════
              HOME VIEW
          ════════════════════════════════════════ */}
          {view === "home" && (
            <motion.div
              key="home"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -16 }}
              className="flex flex-col items-center"
            >
              {/* Hero */}
              <div className="text-center mb-10 max-w-2xl pt-8">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-ink/5 border border-ink/10 text-[10px] font-mono uppercase tracking-widest opacity-70 mb-5">
                  <Cpu className="w-3 h-3" /> ML-Powered · TLS Analysis · Threat Intelligence
                </div>
                <h2 className="text-5xl font-bold tracking-tighter mb-4 font-serif">
                  Assess Domain{" "}
                  <span className="text-accent italic">Security Posture</span>
                  <br />via TLS Analysis
                </h2>
                <p className="text-ink/55 font-mono text-sm leading-relaxed">
                  Evaluates TLS configuration, certificate properties &amp; threat
                  intelligence signals to estimate how secure — or risky — a
                  domain's network-level behaviour is.
                </p>
              </div>

              {/* Search Box */}
              <form onSubmit={handleScan} className="w-full max-w-xl relative mb-6">
                <input
                  id="domain-input"
                  type="text"
                  placeholder="Enter domain (e.g. example.com)"
                  className="w-full bg-white border-2 border-ink p-6 rounded-2xl text-lg font-mono focus:outline-none focus:ring-4 focus:ring-accent/20 transition-all shadow-2xl"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={isScanning}
                />
                <button
                  id="scan-btn"
                  type="submit"
                  disabled={isScanning || !domain}
                  className="absolute right-3 top-3 bottom-3 bg-ink text-bg px-7 rounded-xl font-bold flex items-center gap-2 hover:bg-ink/85 disabled:opacity-40 transition-all text-sm"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      ASSESSING...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4" />
                      ASSESS
                    </>
                  )}
                </button>
              </form>

              {/* Scan Progress */}
              {isScanning && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="w-full max-w-md mb-10"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono uppercase tracking-widest opacity-50">
                      Progress
                    </span>
                    <span className="text-[10px] font-mono uppercase tracking-widest opacity-50">
                      {Math.round(((scanStep + 1) / scanSteps.length) * 100)}%
                    </span>
                  </div>
                  <div className="h-1 bg-ink/10 w-full rounded-full overflow-hidden">
                    <motion.div
                      className="h-full bg-accent"
                      initial={{ width: 0 }}
                      animate={{
                        width: `${((scanStep + 1) / scanSteps.length) * 100}%`,
                      }}
                    />
                  </div>
                  <p className="mt-3 text-center text-xs font-mono italic opacity-60 animate-pulse">
                    {scanSteps[scanStep]}
                  </p>
                </motion.div>
              )}

              {/* How It Works — the 6-step methodology */}
              <div className="w-full max-w-4xl mb-10">
                <h3 className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4 text-center">
                  How the Assessment Works
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                  {[
                    {
                      icon: <Globe className="w-4 h-4" />,
                      step: "01",
                      title: "TLS Handshake",
                      desc: "Connects to the domain and extracts protocol version, cipher suite, and certificate details.",
                    },
                    {
                      icon: <Lock className="w-4 h-4" />,
                      step: "02",
                      title: "Certificate Analysis",
                      desc: "Inspects issuer trust, validity period, and self-signed certificate indicators.",
                    },
                    {
                      icon: <Activity className="w-4 h-4" />,
                      step: "03",
                      title: "Threat Intelligence",
                      desc: "Cross-references the domain and IP against VirusTotal and AbuseIPDB datasets.",
                    },
                    {
                      icon: <Zap className="w-4 h-4" />,
                      step: "04",
                      title: "Feature Engineering",
                      desc: "Converts raw signals into structured risk features (TLS version risk, cipher strength, country risk).",
                    },
                    {
                      icon: <Cpu className="w-4 h-4" />,
                      step: "05",
                      title: "ML Inference",
                      desc: "A trained model processes all features and outputs a probabilistic risk score (0–100).",
                    },
                    {
                      icon: <BarChart2 className="w-4 h-4" />,
                      step: "06",
                      title: "Posture Report",
                      desc: "Delivers a classified security posture: Secure, Moderate Risk, or High Risk.",
                    },
                  ].map((item) => (
                    <div
                      key={item.step}
                      className="bg-white border border-ink/10 rounded-xl p-4 hover:shadow-md transition-shadow"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <div className="w-7 h-7 bg-ink/5 rounded-lg flex items-center justify-center text-ink/60">
                          {item.icon}
                        </div>
                        <span className="text-[9px] font-mono opacity-30 font-bold">
                          STEP {item.step}
                        </span>
                      </div>
                      <h4 className="font-bold text-sm mb-1">{item.title}</h4>
                      <p className="text-xs text-ink/50 leading-relaxed">{item.desc}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Signal Table */}
              <div className="w-full max-w-4xl">
                <h3 className="text-[10px] font-mono uppercase tracking-widest opacity-50 mb-4 text-center">
                  Signals Analyzed by the Model
                </h3>
                <div className="bg-white border border-ink/10 rounded-xl overflow-hidden">
                  <div className="grid grid-cols-3 bg-ink/5 border-b border-ink/10 px-5 py-2">
                    <span className="text-[10px] font-mono uppercase opacity-50">Raw Signal</span>
                    <span className="text-[10px] font-mono uppercase opacity-50">Interpretation</span>
                    <span className="text-[10px] font-mono uppercase opacity-50">Risk Impact</span>
                  </div>
                  {[
                    ["TLS 1.3", "Latest encryption standard", "↓ Reduces Risk"],
                    ["TLS 1.0 / SSLv3", "Deprecated, breakable protocols", "↑ Increases Risk"],
                    ["Short cert validity", "Often used in disposable infrastructure", "↑ Increases Risk"],
                    ["Self-signed cert", "No CA verification", "↑ Increases Risk"],
                    ["Weak cipher (SHA1/MD5)", "Cryptographically insecure", "↑ Increases Risk"],
                    ["High VirusTotal score", "Multiple engine detections", "↑ Increases Risk"],
                    ["High AbuseIPDB score", "Reported abusive IP", "↑ Increases Risk"],
                    ["High-risk country", "CN / RU / IR / KP origin", "↑ Increases Risk"],
                  ].map(([signal, interp, impact]) => (
                    <div
                      key={signal}
                      className="grid grid-cols-3 px-5 py-2.5 border-b border-ink/5 last:border-0 hover:bg-ink/[0.02]"
                    >
                      <span className="text-xs font-mono font-bold">{signal}</span>
                      <span className="text-xs text-ink/60">{interp}</span>
                      <span
                        className={cn(
                          "text-[11px] font-mono font-bold",
                          impact.startsWith("↑") ? "text-red-500" : "text-emerald-500"
                        )}
                      >
                        {impact}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}

          {/* ════════════════════════════════════════
              REPORT VIEW
          ════════════════════════════════════════ */}
          {view === "report" && selectedScan && (
            <motion.div
              key="report"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              {/* Page header */}
              <div className="flex items-center justify-between">
                <div>
                  <button
                    onClick={() => setView("home")}
                    className="text-[10px] font-mono uppercase tracking-widest opacity-40 hover:opacity-100 flex items-center gap-1 mb-2"
                  >
                    <ChevronRight className="w-3 h-3 rotate-180" /> Back to Scanner
                  </button>
                  <h2 className="text-3xl font-bold tracking-tighter flex items-center gap-3 flex-wrap">
                    {selectedScan.domain}
                    <RiskBadge posture={selectedScan.security_posture} />
                  </h2>
                  {selectedScan.ip_address && (
                    <p className="text-xs font-mono opacity-40 mt-1">
                      IP: {selectedScan.ip_address}
                    </p>
                  )}
                </div>
              </div>

              {/* ── Risk Assessment + TLS Info ── */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                {/* Risk Score Donut */}
                <Card title="RISK SCORE" className="lg:col-span-1">
                  <div className="flex flex-col items-center py-2">
                    <div className="relative w-44 h-44">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={riskData}
                            cx="50%"
                            cy="50%"
                            innerRadius={55}
                            outerRadius={76}
                            paddingAngle={4}
                            dataKey="value"
                            startAngle={90}
                            endAngle={450}
                          >
                            <Cell fill={riskColor} />
                            <Cell fill="#f4f4f3" />
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-4xl font-bold tracking-tighter">
                          {selectedScan.tls_risk_score}
                        </span>
                        <span className="text-[9px] font-mono uppercase opacity-40">
                          / 100
                        </span>
                      </div>
                    </div>
                    <div className="mt-3 text-center space-y-1">
                      <p className="text-xs font-bold">
                        ML Confidence:{" "}
                        {(selectedScan.confidence * 100).toFixed(1)}%
                      </p>
                      <p className="text-[10px] font-mono opacity-50 uppercase tracking-widest">
                        Security Level:{" "}
                        <span className="font-bold">
                          {selectedScan.security_level}
                        </span>
                      </p>
                    </div>

                    {/* Plain-language explanation */}
                    <div className="mt-4 p-3 rounded-xl bg-ink/[0.03] border border-ink/8 text-xs text-ink/60 leading-relaxed text-center">
                      {selectedScan.security_posture === "risky" ? (
                        <>
                          This domain exhibits a <strong>high-risk TLS/security configuration</strong>.
                          The ML model detected multiple risk signals including weak
                          encryption indicators or elevated threat intelligence scores.
                        </>
                      ) : selectedScan.security_posture === "moderate" ? (
                        <>
                          This domain has a <strong>moderate security posture</strong>.
                          Some risk signals are present but no critical vulnerabilities
                          were detected by the model.
                        </>
                      ) : (
                        <>
                          This domain demonstrates a <strong>strong security posture</strong>.
                          Modern encryption, a trusted certificate issuer, and low threat
                          intelligence signals indicate a well-secured configuration.
                        </>
                      )}
                    </div>
                  </div>
                </Card>

                {/* TLS Infrastructure */}
                <Card title="TLS INFRASTRUCTURE" className="lg:col-span-2">
                  <div className="grid grid-cols-2 gap-5">
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-40 block mb-1">
                          Protocol Version
                        </label>
                        <div className="flex items-center gap-2">
                          <Lock className="w-4 h-4 text-accent" />
                          <span className="font-mono text-sm font-bold">
                            {selectedScan.tls?.tlsVersion || "—"}
                          </span>
                        </div>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-40 block mb-1">
                          Cipher Suite
                        </label>
                        <div className="flex items-start gap-2">
                          <Activity className="w-4 h-4 text-accent mt-0.5 shrink-0" />
                          <span className="font-mono text-xs break-all">
                            {selectedScan.tls?.cipherSuite || "—"}
                          </span>
                        </div>
                      </div>
                    </div>
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-40 block mb-1">
                          Certificate Issuer
                        </label>
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-accent" />
                          <span className="font-mono text-sm font-bold">
                            {selectedScan.tls?.issuer || "—"}
                          </span>
                        </div>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-40 block mb-1">
                          Validity Period
                        </label>
                        <div className="flex items-start gap-2">
                          <Globe className="w-4 h-4 text-accent mt-0.5" />
                          <span className="font-mono text-[11px] leading-snug">
                            {selectedScan.tls?.validFrom && selectedScan.tls.validFrom !== "Unknown"
                              ? new Date(selectedScan.tls.validFrom).toLocaleDateString()
                              : "Unknown"}
                            {" — "}
                            {selectedScan.tls?.validTo && selectedScan.tls.validTo !== "Unknown"
                              ? new Date(selectedScan.tls.validTo).toLocaleDateString()
                              : "Unknown"}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </Card>
              </div>

              {/* ── Threat Intelligence ── */}
              <Card title="THREAT INTELLIGENCE">
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    {
                      label: "VirusTotal",
                      value:
                        selectedScan.intel?.vtScore === -1
                          ? "INVALID KEY"
                          : String(selectedScan.intel?.vtScore ?? "—"),
                      sub: "Malicious Detections",
                      danger:
                        selectedScan.intel?.vtScore !== -1 &&
                        (selectedScan.intel?.vtScore ?? 0) > 0,
                    },
                    {
                      label: "AbuseIPDB",
                      value:
                        selectedScan.intel?.abuseScore === -1
                          ? "AUTH ERROR"
                          : `${selectedScan.intel?.abuseScore ?? 0}%`,
                      sub: "Abuse Confidence",
                      danger:
                        selectedScan.intel?.abuseScore !== -1 &&
                        (selectedScan.intel?.abuseScore ?? 0) > 50,
                    },
                    {
                      label: "Hosting Provider",
                      value: selectedScan.intel?.hosting || "—",
                      sub: "ISP / ASN",
                      danger: false,
                      icon: <Server className="w-4 h-4 opacity-40" />,
                    },
                    {
                      label: "Country",
                      value: selectedScan.intel?.country || "—",
                      sub: "Origin Location",
                      danger: ["CN", "RU", "IR", "KP"].includes(
                        selectedScan.intel?.country || ""
                      ),
                      icon: <Globe className="w-4 h-4 opacity-40" />,
                    },
                  ].map((item) => (
                    <div
                      key={item.label}
                      className="p-4 bg-ink/[0.025] rounded-xl border border-ink/5"
                    >
                      <label className="text-[10px] font-mono uppercase opacity-40 block mb-2">
                        {item.label}
                      </label>
                      <div className="flex items-end justify-between gap-2">
                        <span
                          className={cn(
                            "text-xl font-bold font-mono truncate",
                            item.danger ? "text-red-500" : "text-emerald-600"
                          )}
                        >
                          {item.value}
                        </span>
                        {item.icon}
                      </div>
                      <p className="text-[10px] opacity-40 mt-1">{item.sub}</p>
                    </div>
                  ))}
                </div>
              </Card>

              {/* ── Feature Importance ── */}
              {selectedScan.feature_importance &&
                selectedScan.feature_importance.length > 0 && (
                  <Card title="MODEL SIGNAL WEIGHTS — Top Contributing Factors">
                    <p className="text-xs text-ink/50 mb-4 leading-relaxed">
                      The chart below shows which signals had the most influence on
                      the model's risk assessment for this domain. Signals marked in{" "}
                      <span className="text-red-500 font-bold">red</span> increase
                      risk; those in{" "}
                      <span className="text-emerald-500 font-bold">green</span> reduce
                      it.
                    </p>
                    <div className="h-56">
                      <ResponsiveContainer width="100%" height="100%">
                        <BarChart
                          data={featureBarData}
                          layout="vertical"
                          margin={{ left: 0, right: 24 }}
                        >
                          <XAxis type="number" fontSize={10} tick={{ fill: "#14141450" }} />
                          <YAxis
                            type="category"
                            dataKey="name"
                            fontSize={9}
                            tick={{ fill: "#141414AA" }}
                            width={160}
                          />
                          <Tooltip
                            contentStyle={{
                              backgroundColor: "#141414",
                              color: "#E4E3E0",
                              border: "none",
                              borderRadius: "8px",
                              fontSize: "11px",
                            }}
                            formatter={(value: any) => [`${value}%`, "Importance"]}
                          />
                          <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                            {featureBarData.map((entry, index) => (
                              <Cell
                                key={`cell-${index}`}
                                fill={
                                  entry.impact === "increases_risk"
                                    ? "#ef4444"
                                    : entry.impact === "reduces_risk"
                                    ? "#10b981"
                                    : "#94a3b8"
                                }
                              />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </Card>
                )}
            </motion.div>
          )}

          {/* ════════════════════════════════════════
              HISTORY VIEW
          ════════════════════════════════════════ */}
          {view === "history" && (
            <motion.div
              key="history"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-3xl font-bold tracking-tighter">
                    Scan History
                  </h2>
                  <p className="text-xs text-ink/40 font-mono mt-1">
                    {history.length} assessment{history.length !== 1 ? "s" : ""}{" "}
                    on record
                  </p>
                </div>
                <button
                  onClick={fetchHistory}
                  className="p-2.5 border border-ink/10 rounded-xl hover:bg-white transition-colors"
                  title="Refresh"
                >
                  <History className="w-4 h-4" />
                </button>
              </div>

              {history.length > 0 && (
                <Card title="RISK SCORE TREND">
                  <div className="h-44 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trendData}>
                        <CartesianGrid
                          strokeDasharray="3 3"
                          stroke="#14141410"
                        />
                        <XAxis
                          dataKey="date"
                          fontSize={10}
                          tick={{ fill: "#14141550" }}
                        />
                        <YAxis
                          fontSize={10}
                          tick={{ fill: "#14141550" }}
                          domain={[0, 100]}
                        />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#141414",
                            color: "#E4E3E0",
                            border: "none",
                            borderRadius: "8px",
                            fontSize: "10px",
                          }}
                          itemStyle={{ color: "#F27D26" }}
                          formatter={(value: any, _: any, props: any) => [
                            `${value} — ${props.payload.domain}`,
                            "Risk Score",
                          ]}
                        />
                        <Line
                          type="monotone"
                          dataKey="score"
                          stroke="#F27D26"
                          strokeWidth={2}
                          dot={{ fill: "#F27D26", r: 4 }}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              )}

              <div className="bg-white border border-ink/10 rounded-xl overflow-hidden">
                {/* Table Header */}
                <div className="grid grid-cols-[2rem_1fr_auto_auto_auto] gap-4 items-center bg-ink/[0.03] border-b border-ink/10 px-5 py-2.5">
                  <span className="text-[10px] font-mono uppercase opacity-40">#</span>
                  <span className="text-[10px] font-mono uppercase opacity-40">Domain</span>
                  <span className="text-[10px] font-mono uppercase opacity-40">Risk Level</span>
                  <span className="text-[10px] font-mono uppercase opacity-40">Score</span>
                  <span className="text-[10px] font-mono uppercase opacity-40"></span>
                </div>

                {history.map((scan, idx) => (
                  <div
                    key={scan.id || idx}
                    className="grid grid-cols-[2rem_1fr_auto_auto_auto] gap-4 items-center px-5 py-3.5 border-b border-ink/5 last:border-0 hover:bg-ink/[0.02] cursor-pointer transition-colors"
                    onClick={() => {
                      setSelectedScan(scan);
                      setView("report");
                    }}
                  >
                    <span className="text-[10px] font-mono opacity-30">
                      {idx + 1}
                    </span>
                    <span className="font-bold text-sm truncate pr-2">
                      {scan.domain}
                    </span>
                    <RiskBadge posture={scan.security_posture || (scan.high_risk ? "risky" : "secure")} />
                    <span
                      className={cn(
                        "font-mono font-bold text-sm",
                        scan.tls_risk_score > 60
                          ? "text-red-500"
                          : scan.tls_risk_score > 29
                          ? "text-amber-500"
                          : "text-emerald-600"
                      )}
                    >
                      {scan.tls_risk_score}
                    </span>
                    <button
                      id={`delete-scan-${scan.id || idx}`}
                      onClick={(e) => handleDelete(e, scan.id!)}
                      className="p-1.5 rounded-lg text-ink/30 hover:text-red-500 hover:bg-red-50 transition-colors"
                      title="Delete scan"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}

                {history.length === 0 && (
                  <div className="p-16 text-center opacity-40 font-mono text-sm">
                    No assessment history found.
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-ink/10 p-6 bg-white/40">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <p className="text-[10px] font-mono opacity-40 uppercase tracking-widest">
            © 2026 TLSGUARD · TLS SECURITY POSTURE ANALYSIS
          </p>
          <p className="text-[10px] font-mono opacity-30 italic hidden md:block">
            "Evaluates TLS/certificate-level security signals to estimate domain risk using machine learning."
          </p>
        </div>
      </footer>
    </div>
  );
}
