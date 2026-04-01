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
  Trash2
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
  Legend,
  LineChart,
  Line,
  CartesianGrid
} from "recharts";
import { motion, AnimatePresence } from "motion/react";
import axios from "axios";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// --- Types ---
interface FeatureImportance {
  feature: string;
  importance: number;
  impact: "positive" | "negative";
}

interface ScanResult {
  id: number;
  domain: string;
  ip_address: string;
  prediction: "phishing" | "benign";
  confidence: number;
  risk_score: number;
  tls_version: string;
  cipher_suite: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  virustotal_score: number;
  abuseipdb_score: number;
  hosting_provider: string;
  country: string;
  reasoning?: string;
  feature_importance?: FeatureImportance[];
  created_at: string;
}

// --- Components ---

const Card = ({ children, className, title }: { children: React.ReactNode; className?: string; title?: string }) => (
  <div className={cn("bg-white border border-ink/10 rounded-lg overflow-hidden", className)}>
    {title && (
      <div className="px-4 py-2 border-bottom border-ink/10 bg-ink/5">
        <h3 className="text-[10px] uppercase tracking-widest font-mono font-bold opacity-60">{title}</h3>
      </div>
    )}
    <div className="p-4">{children}</div>
  </div>
);

const Badge = ({ children, variant = "default" }: { children: React.ReactNode; variant?: "default" | "danger" | "success" | "warning" }) => {
  const styles = {
    default: "bg-ink/10 text-ink",
    danger: "bg-danger/20 text-danger border border-danger/30",
    success: "bg-success/20 text-success border border-success/30",
    warning: "bg-accent/20 text-accent border border-accent/30",
  };
  return (
    <span className={cn("px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold", styles[variant])}>
      {children}
    </span>
  );
};

export default function App() {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
  const [view, setView] = useState<"home" | "report" | "history">("home");

  const scanSteps = [
    "Initializing TLS Handshake...",
    "Extracting Certificate Metadata...",
    "Querying Threat Intelligence APIs...",
    "Running Machine Learning Inference...",
    "Generating Risk Assessment..."
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
    if (!confirm("Are you sure you want to delete this scan?")) return;
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
    
    // Simulate steps for UI
    const stepInterval = setInterval(() => {
      setScanStep(prev => (prev < scanSteps.length - 1 ? prev + 1 : prev));
    }, 1500);

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
      alert("Scan failed: " + (e.response?.data?.error || e.message));
      setIsScanning(false);
    }
  };

  const riskData = selectedScan ? [
    { name: "Risk", value: selectedScan.risk_score },
    { name: "Safe", value: 100 - selectedScan.risk_score },
  ] : [];

  const trendData = [...history].reverse().map(s => ({
    date: new Date(s.created_at).toLocaleDateString(),
    score: s.risk_score,
    domain: s.domain
  }));

  const COLORS = ["#FF4444", "#00FF00"];

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-ink/20 px-6 py-4 flex items-center justify-between bg-white/50 backdrop-blur-md sticky top-0 z-50">
        <div className="flex items-center gap-3 cursor-pointer" onClick={() => setView("home")}>
          <div className="w-10 h-10 bg-ink flex items-center justify-center rounded">
            <Shield className="text-bg w-6 h-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tighter leading-none">TLSGUARD</h1>
            <p className="text-[10px] font-mono opacity-50 uppercase tracking-widest">Infrastructure Analysis</p>
          </div>
        </div>

        <nav className="flex items-center gap-6">
          <button 
            onClick={() => setView("home")}
            className={cn("text-xs font-mono uppercase tracking-widest hover:opacity-100 transition-opacity", view === "home" ? "opacity-100 font-bold underline underline-offset-8" : "opacity-50")}
          >
            Scanner
          </button>
          <button 
            onClick={() => setView("history")}
            className={cn("text-xs font-mono uppercase tracking-widest hover:opacity-100 transition-opacity", view === "history" ? "opacity-100 font-bold underline underline-offset-8" : "opacity-50")}
          >
            History
          </button>
        </nav>
      </header>

      <main className="flex-1 max-w-7xl mx-auto w-full p-6">
        <AnimatePresence mode="wait">
          {view === "home" && (
            <motion.div 
              key="home"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              className="flex flex-col items-center justify-center py-20"
            >
              <div className="text-center mb-12 max-w-2xl">
                <h2 className="text-5xl font-bold tracking-tighter mb-4 italic font-serif">
                  Detect Phishing via <span className="text-accent">TLS Fingerprinting</span>
                </h2>
                <p className="text-ink/60 font-mono text-sm">
                  Analyze infrastructure signals, certificate metadata, and threat intelligence without decrypting traffic.
                </p>
              </div>

              <form onSubmit={handleScan} className="w-full max-w-xl relative">
                <input 
                  type="text" 
                  placeholder="Enter domain (e.g., example.com)"
                  className="w-full bg-white border-2 border-ink p-6 rounded-xl text-lg font-mono focus:outline-none focus:ring-4 focus:ring-accent/20 transition-all shadow-xl"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={isScanning}
                />
                <button 
                  type="submit"
                  disabled={isScanning || !domain}
                  className="absolute right-3 top-3 bottom-3 bg-ink text-bg px-8 rounded-lg font-bold flex items-center gap-2 hover:bg-ink/90 disabled:opacity-50 transition-all"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      ANALYZING...
                    </>
                  ) : (
                    <>
                      <Search className="w-5 h-5" />
                      ANALYZE
                    </>
                  )}
                </button>
              </form>

              {isScanning && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="mt-8 w-full max-w-md"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-[10px] font-mono uppercase tracking-widest opacity-50">Progress</span>
                    <span className="text-[10px] font-mono uppercase tracking-widest opacity-50">{Math.round(((scanStep + 1) / scanSteps.length) * 100)}%</span>
                  </div>
                  <div className="h-1 bg-ink/10 w-full rounded-full overflow-hidden">
                    <motion.div 
                      className="h-full bg-accent"
                      initial={{ width: 0 }}
                      animate={{ width: `${((scanStep + 1) / scanSteps.length) * 100}%` }}
                    />
                  </div>
                  <p className="mt-4 text-center text-xs font-mono italic opacity-70 animate-pulse">
                    {scanSteps[scanStep]}
                  </p>
                </motion.div>
              )}

              <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6 w-full max-w-4xl">
                <Card title="TLS HANDSHAKE">
                  <p className="text-xs text-ink/60 leading-relaxed">
                    Extracts cipher suites, protocol versions, and handshake characteristics to build a unique infrastructure fingerprint.
                  </p>
                </Card>
                <Card title="THREAT INTEL">
                  <p className="text-xs text-ink/60 leading-relaxed">
                    Integrates with VirusTotal and AbuseIPDB to cross-reference infrastructure with known malicious patterns.
                  </p>
                </Card>
                <Card title="ML PREDICTION">
                  <p className="text-xs text-ink/60 leading-relaxed">
                    Uses a LightGBM-inspired model to classify infrastructure risk based on 197+ network features.
                  </p>
                </Card>
              </div>
            </motion.div>
          )}

          {view === "report" && selectedScan && (
            <motion.div 
              key="report"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              <div className="flex items-center justify-between">
                <div>
                  <button 
                    onClick={() => setView("home")}
                    className="text-[10px] font-mono uppercase tracking-widest opacity-50 hover:opacity-100 flex items-center gap-1 mb-2"
                  >
                    <ChevronRight className="w-3 h-3 rotate-180" /> Back to Scanner
                  </button>
                  <h2 className="text-3xl font-bold tracking-tighter flex items-center gap-3">
                    {selectedScan.domain}
                    {selectedScan.prediction === "phishing" ? (
                      <Badge variant="danger">Malicious</Badge>
                    ) : (
                      <Badge variant="success">Benign</Badge>
                    )}
                  </h2>
                  <p className="text-xs font-mono opacity-50">IP: {selectedScan.ip_address} • Scanned on {new Date(selectedScan.created_at).toLocaleString()}</p>
                </div>
                <div className="flex gap-2">
                  <button className="p-2 border border-ink/10 rounded hover:bg-white transition-colors">
                    <ExternalLink className="w-4 h-4" />
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Risk Score Card */}
                <Card title="RISK ASSESSMENT" className="lg:col-span-1">
                  <div className="flex flex-col items-center py-4">
                    <div className="relative w-48 h-48">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={riskData}
                            cx="50%"
                            cy="50%"
                            innerRadius={60}
                            outerRadius={80}
                            paddingAngle={5}
                            dataKey="value"
                            startAngle={90}
                            endAngle={450}
                          >
                            {riskData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                            ))}
                          </Pie>
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="absolute inset-0 flex flex-col items-center justify-center">
                        <span className="text-4xl font-bold tracking-tighter">{selectedScan.risk_score}</span>
                        <span className="text-[10px] font-mono uppercase opacity-50">Risk Score</span>
                      </div>
                    </div>
                    <div className="mt-4 text-center">
                      <p className="text-sm font-bold mb-1">
                        Confidence: {(selectedScan.confidence * 100).toFixed(1)}%
                      </p>
                      <p className="text-xs text-ink/60 italic font-serif">
                        "{selectedScan.reasoning}"
                      </p>
                    </div>
                  </div>
                </Card>

                {/* TLS Info Card */}
                <Card title="TLS INFRASTRUCTURE" className="lg:col-span-2">
                  <div className="grid grid-cols-2 gap-6">
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-50 block mb-1">Protocol Version</label>
                        <div className="flex items-center gap-2">
                          <Lock className="w-4 h-4 text-accent" />
                          <span className="font-mono text-sm font-bold">{selectedScan.tls_version}</span>
                        </div>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-50 block mb-1">Cipher Suite</label>
                        <div className="flex items-center gap-2">
                          <Activity className="w-4 h-4 text-accent" />
                          <span className="font-mono text-xs break-all">{selectedScan.cipher_suite}</span>
                        </div>
                      </div>
                    </div>
                    <div className="space-y-4">
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-50 block mb-1">Certificate Issuer</label>
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4 text-accent" />
                          <span className="font-mono text-sm font-bold">{selectedScan.issuer}</span>
                        </div>
                      </div>
                      <div>
                        <label className="text-[10px] font-mono uppercase opacity-50 block mb-1">Validity Period</label>
                        <div className="flex items-center gap-2">
                          <Globe className="w-4 h-4 text-accent" />
                          <span className="font-mono text-[10px]">
                            {new Date(selectedScan.valid_from).toLocaleDateString()} - {new Date(selectedScan.valid_to).toLocaleDateString()}
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                </Card>

                {/* Threat Intel Card */}
                <Card title="THREAT INTELLIGENCE" className="lg:col-span-3">
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                    <div className="p-4 bg-ink/5 rounded border border-ink/5">
                      <label className="text-[10px] font-mono uppercase opacity-50 block mb-2">VirusTotal</label>
                      <div className="flex items-end justify-between">
                        <span className={cn("text-2xl font-bold", selectedScan.virustotal_score > 0 ? "text-danger" : "text-success")}>
                          {selectedScan.virustotal_score}
                        </span>
                        <span className="text-[10px] font-mono opacity-50">Detections</span>
                      </div>
                    </div>
                    <div className="p-4 bg-ink/5 rounded border border-ink/5">
                      <label className="text-[10px] font-mono uppercase opacity-50 block mb-2">AbuseIPDB</label>
                      <div className="flex items-end justify-between">
                        <span className={cn("text-2xl font-bold", selectedScan.abuseipdb_score > 50 ? "text-danger" : "text-success")}>
                          {selectedScan.abuseipdb_score}%
                        </span>
                        <span className="text-[10px] font-mono opacity-50">Abuse Score</span>
                      </div>
                    </div>
                    <div className="p-4 bg-ink/5 rounded border border-ink/5">
                      <label className="text-[10px] font-mono uppercase opacity-50 block mb-2">Hosting Provider</label>
                      <div className="flex items-center gap-2">
                        <Server className="w-4 h-4 opacity-50" />
                        <span className="text-xs font-bold truncate">{selectedScan.hosting_provider}</span>
                      </div>
                    </div>
                    <div className="p-4 bg-ink/5 rounded border border-ink/5">
                      <label className="text-[10px] font-mono uppercase opacity-50 block mb-2">Location</label>
                      <div className="flex items-center gap-2">
                        <Globe className="w-4 h-4 opacity-50" />
                        <span className="text-xs font-bold">{selectedScan.country}</span>
                      </div>
                    </div>
                  </div>
                </Card>

                {/* Feature Importance Card */}
                {selectedScan.feature_importance && (
                  <Card title="MODEL FEATURE IMPORTANCE" className="lg:col-span-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {selectedScan.feature_importance.map((feat, i) => (
                        <div key={i} className="flex items-center justify-between p-3 border border-ink/5 rounded bg-white">
                          <div className="flex flex-col">
                            <span className="text-[10px] font-mono uppercase font-bold">{feat.feature}</span>
                            <span className={cn("text-[8px] font-mono uppercase", feat.impact === "positive" ? "text-danger" : "text-success")}>
                              {feat.impact === "positive" ? "Increases Risk" : "Decreases Risk"}
                            </span>
                          </div>
                          <div className="flex items-center gap-2">
                            <div className="w-24 h-1.5 bg-ink/5 rounded-full overflow-hidden">
                              <div 
                                className={cn("h-full", feat.impact === "positive" ? "bg-danger" : "bg-success")}
                                style={{ width: `${feat.importance}%` }}
                              />
                            </div>
                            <span className="text-[10px] font-mono font-bold">{feat.importance}%</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}
              </div>
            </motion.div>
          )}

          {view === "history" && (
            <motion.div 
              key="history"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="space-y-6"
            >
              <div className="flex items-center justify-between">
                <h2 className="text-3xl font-bold tracking-tighter">Scan History</h2>
                <button 
                  onClick={fetchHistory}
                  className="p-2 border border-ink/10 rounded hover:bg-white transition-colors"
                >
                  <History className="w-4 h-4" />
                </button>
              </div>

              {history.length > 0 && (
                <Card title="RISK TRENDS OVER TIME">
                  <div className="h-48 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={trendData}>
                        <CartesianGrid strokeDasharray="3 3" stroke="#14141410" />
                        <XAxis dataKey="date" fontSize={10} tick={{ fill: '#14141450' }} />
                        <YAxis fontSize={10} tick={{ fill: '#14141450' }} />
                        <Tooltip 
                          contentStyle={{ backgroundColor: '#141414', color: '#E4E3E0', border: 'none', borderRadius: '4px', fontSize: '10px' }}
                          itemStyle={{ color: '#F27D26' }}
                        />
                        <Line type="monotone" dataKey="score" stroke="#F27D26" strokeWidth={2} dot={{ fill: '#F27D26' }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                </Card>
              )}

              <div className="bg-white border border-ink/10 rounded-lg overflow-hidden">
                <div className="data-row bg-ink/5 border-b border-ink/10 cursor-default hover:bg-ink/5 hover:text-ink">
                  <div className="col-header">ID</div>
                  <div className="col-header">Domain</div>
                  <div className="col-header">Prediction</div>
                  <div className="col-header">Risk Score</div>
                  <div className="col-header">Actions</div>
                </div>
                {history.map((scan) => (
                  <div 
                    key={scan.id} 
                    className="data-row"
                    onClick={() => {
                      setSelectedScan(scan);
                      setView("report");
                    }}
                  >
                    <div className="data-value text-[10px] opacity-50">#{scan.id}</div>
                    <div className="font-bold text-sm truncate pr-4">{scan.domain}</div>
                    <div>
                      {scan.prediction === "phishing" ? (
                        <Badge variant="danger">Phishing</Badge>
                      ) : (
                        <Badge variant="success">Benign</Badge>
                      )}
                    </div>
                    <div className="data-value font-bold">{scan.risk_score}</div>
                    <div className="flex items-center gap-2">
                      <button 
                        onClick={(e) => handleDelete(e, scan.id)}
                        className="p-1 hover:text-danger transition-colors opacity-50 hover:opacity-100"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                      <ChevronRight className="w-4 h-4 opacity-20" />
                    </div>
                  </div>
                ))}
                {history.length === 0 && (
                  <div className="p-12 text-center opacity-50 font-mono text-sm">
                    No scan history found.
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>

      {/* Footer */}
      <footer className="border-t border-ink/10 p-6 bg-white/50">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <p className="text-[10px] font-mono opacity-50 uppercase tracking-widest">
            © 2026 TLSGUARD • SECURE INFRASTRUCTURE ANALYSIS
          </p>
          <div className="flex gap-4">
            <a href="#" className="text-[10px] font-mono uppercase tracking-widest opacity-50 hover:opacity-100">API Docs</a>
            <a href="#" className="text-[10px] font-mono uppercase tracking-widest opacity-50 hover:opacity-100">Privacy</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
