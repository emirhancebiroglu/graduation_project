"use client";

type ModelEntry = {
  name: string;
  gid: number;
  attack: string;
  dataset: string;
  recall: string;
  precision: string;
  fp: string;
  status: "pass";
};

const MODELS: ModelEntry[] = [
  {
    name: "DoS Inspector",
    gid: 301,
    attack: "DoS / Slowloris / Hulk",
    dataset: "CIC Wed",
    recall: "99.99%",
    precision: "97.16%",
    fp: "FPR 1.68%",
    status: "pass",
  },
  {
    name: "PortScan",
    gid: 302,
    attack: "TCP SYN Port Scan",
    dataset: "CIC Fri",
    recall: "91% window",
    precision: "FP = 0",
    fp: "FP 0",
    status: "pass",
  },
  {
    name: "DDoS Aggregator",
    gid: 304,
    attack: "Distributed SYN / HTTP Flood",
    dataset: "CIC Fri",
    recall: "20 attack wins",
    precision: "FP = 0",
    fp: "FP 0",
    status: "pass",
  },
  {
    name: "Botnet Client",
    gid: 306,
    attack: "Botnet C2 Beaconing",
    dataset: "CIC Fri",
    recall: "85.7%",
    precision: "75.0%",
    fp: "FP ≤ 5",
    status: "pass",
  },
  {
    name: "Brute Force",
    gid: 307,
    attack: "SSH / FTP Brute Force",
    dataset: "CIC Tue",
    recall: "100%",
    precision: "FPR ~0%",
    fp: "FP ≤ 2",
    status: "pass",
  },
];

const GID_COLOR: Record<number, { text: string; border: string; bg: string; glow: string }> = {
  301: { text: "#ff3b3b", border: "rgba(255,59,59,0.25)", bg: "rgba(255,59,59,0.04)", glow: "0 0 12px rgba(255,59,59,0.12)" },
  302: { text: "#f59e0b", border: "rgba(245,158,11,0.22)", bg: "rgba(245,158,11,0.04)", glow: "0 0 12px rgba(245,158,11,0.08)" },
  304: { text: "#e879f9", border: "rgba(232,121,249,0.22)", bg: "rgba(232,121,249,0.04)", glow: "0 0 12px rgba(232,121,249,0.08)" },
  306: { text: "#38bdf8", border: "rgba(56,189,248,0.22)", bg: "rgba(56,189,248,0.04)", glow: "0 0 12px rgba(56,189,248,0.08)" },
  307: { text: "#34d399", border: "rgba(52,211,153,0.22)", bg: "rgba(52,211,153,0.04)", glow: "0 0 12px rgba(52,211,153,0.08)" },
};

function ModelCard({ m }: { m: ModelEntry }) {
  const c = GID_COLOR[m.gid];
  return (
    <div
      className="relative flex flex-col gap-2 p-3 overflow-hidden"
      style={{
        border: `1px solid ${c.border}`,
        background: c.bg,
        boxShadow: c.glow,
      }}
    >
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l" style={{ borderColor: c.border }} />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r" style={{ borderColor: c.border }} />

      {/* GID badge + name */}
      <div className="flex items-center gap-2">
        <span
          className="text-[9px] font-mono px-1.5 py-0.5 shrink-0"
          style={{ background: c.border, color: c.text, letterSpacing: "0.08em" }}
        >
          GID:{m.gid}
        </span>
        <span className="text-[10px] font-mono font-semibold truncate" style={{ color: c.text, letterSpacing: "0.06em" }}>
          {m.name.toUpperCase()}
        </span>
        {/* Pass tick */}
        <span className="ml-auto text-[10px] font-mono" style={{ color: "#10b981" }}>✓</span>
      </div>

      {/* Attack type */}
      <p className="text-[9px] font-mono leading-tight" style={{ color: "rgba(148,163,184,0.75)" }}>
        {m.attack}
      </p>

      {/* Metrics row */}
      <div className="flex gap-3 mt-auto pt-1 border-t" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
        <div>
          <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>RECALL</p>
          <p className="text-[11px] font-mono font-semibold" style={{ color: c.text }}>{m.recall}</p>
        </div>
        <div>
          <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>PRECISION</p>
          <p className="text-[11px] font-mono font-semibold" style={{ color: c.text }}>{m.precision}</p>
        </div>
        <div className="ml-auto text-right">
          <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>DATASET</p>
          <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.7)" }}>{m.dataset}</p>
        </div>
      </div>
    </div>
  );
}

export function DetectionCoverage() {
  return (
    <div
      className="relative overflow-hidden"
      style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}
    >
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(16,185,129,0.8)", boxShadow: "0 0 6px rgba(16,185,129,0.5)" }} />
        <span className="section-label" style={{ color: "#10b981" }}>DETECTION COVERAGE</span>
        <span className="ml-auto text-[9px] font-mono" style={{ color: "rgba(16,185,129,0.6)" }}>
          {MODELS.length}/{MODELS.length} MODELS ACTIVE
        </span>
      </div>

      {/* Cards grid */}
      <div className="p-3 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2">
        {MODELS.map((m) => (
          <ModelCard key={m.gid} m={m} />
        ))}
      </div>

      {/* Footer note */}
      <div className="px-4 py-2 border-t flex items-center gap-4" style={{ borderColor: "rgba(0,212,255,0.05)" }}>
        <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.35)" }}>
          EVALUATED · CIC-IDS2017 · LOCKED METRICS
        </span>
        <span className="text-[9px] font-mono ml-auto" style={{ color: "rgba(16,185,129,0.4)" }}>
          ALL CRITERIA MET ✓
        </span>
      </div>
    </div>
  );
}
