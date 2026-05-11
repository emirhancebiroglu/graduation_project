"use client";
import type { IdsStreamState } from "@/lib/use-ids-stream";

type Props = Pick<
  IdsStreamState,
  "metrics" | "snortRunning" | "pcapProgress" | "replayStartedAt" | "firstAlertAt"
>;

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function fmtAps(n: number): string {
  return n >= 100 ? `${Math.round(n)}/s` : `${n.toFixed(1)}/s`;
}

function latencyLabel(
  replayStartedAt: number | null,
  firstAlertAt: number | null,
  snortRunning: boolean,
): string {
  if (!replayStartedAt) return "—";
  if (!firstAlertAt) return snortRunning ? "WAIT…" : "—";
  const ms = firstAlertAt - replayStartedAt;
  return ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;
}

type StatCardProps = {
  label: string;
  sublabel?: string;
  value: string;
  subvalue?: string;
  color: "cyan" | "red" | "amber" | "muted";
  accent?: boolean;
};

const COLORS = {
  cyan: { text: "#00d4ff", border: "rgba(0,212,255,0.2)", bg: "rgba(0,212,255,0.04)", glow: "0 0 20px rgba(0,212,255,0.08)" },
  red:  { text: "#ff3b3b", border: "rgba(255,59,59,0.25)", bg: "rgba(255,59,59,0.04)", glow: "0 0 20px rgba(255,59,59,0.1)" },
  amber: { text: "#f59e0b", border: "rgba(245,158,11,0.2)", bg: "rgba(245,158,11,0.04)", glow: "0 0 20px rgba(245,158,11,0.06)" },
  muted: { text: "#64748b", border: "rgba(0,212,255,0.08)", bg: "rgba(0,212,255,0.02)", glow: "none" },
};

function StatCard({ label, sublabel, value, subvalue, color }: StatCardProps) {
  const c = COLORS[color];
  return (
    <div className="relative flex flex-col justify-between p-4 overflow-hidden" style={{
      border: `1px solid ${c.border}`,
      background: `${c.bg}`,
      boxShadow: c.glow,
      minHeight: "100px",
    }}>
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-2.5 h-2.5 border-t border-l" style={{ borderColor: c.border }} />
      <div className="absolute bottom-0 right-0 w-2.5 h-2.5 border-b border-r" style={{ borderColor: c.border }} />

      <div>
        <p className="section-label mb-0.5" style={{ color: "rgba(0,212,255,0.4)" }}>{label}</p>
        {sublabel && <p className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.7)" }}>{sublabel}</p>}
      </div>

      <div>
        <p className="display-num mt-2" style={{ fontSize: "2rem", lineHeight: 1, color: c.text, letterSpacing: "-0.02em" }}>
          {value}
        </p>
        {subvalue && (
          <p className="text-[10px] font-mono mt-1.5" style={{ color: "rgba(100,116,139,0.8)" }}>{subvalue}</p>
        )}
      </div>
    </div>
  );
}

export function MetricsPanel({
  metrics,
  snortRunning,
  pcapProgress,
  replayStartedAt,
  firstAlertAt,
}: Props) {
  const xgb = metrics.xgboost;
  const comm = metrics.community;
  const pct = Math.round(pcapProgress * 100);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 h-full">
      <StatCard
        label="XGBOOST ALERTS"
        sublabel="ML ENGINE"
        value={fmt(xgb.total)}
        subvalue={`${fmtAps(xgb.alertsPerSec)} · 10s avg`}
        color="red"
      />
      <StatCard
        label="COMMUNITY ALERTS"
        sublabel="SNORT3 RULES"
        value={fmt(comm.total)}
        subvalue={`${fmtAps(comm.alertsPerSec)} · 10s avg`}
        color="cyan"
      />
      <StatCard
        label="FIRST DETECTION"
        sublabel="XGBOOST LATENCY"
        value={latencyLabel(replayStartedAt, firstAlertAt, snortRunning)}
        subvalue="from replay start"
        color="amber"
      />

      {/* Status + progress */}
      <div className="relative flex flex-col justify-between p-4 overflow-hidden" style={{
        border: "1px solid rgba(0,212,255,0.12)",
        background: "rgba(0,212,255,0.02)",
        minHeight: "100px",
      }}>
        <div className="absolute top-0 left-0 w-2.5 h-2.5 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.2)" }} />
        <div className="absolute bottom-0 right-0 w-2.5 h-2.5 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.2)" }} />

        <p className="section-label" style={{ color: "rgba(0,212,255,0.4)" }}>SYSTEM STATUS</p>

        <div>
          <div className="flex items-center gap-2 mt-2">
            <div className={`w-1.5 h-1.5 rounded-full ${snortRunning ? "bg-emerald-400 status-dot-active" : "bg-slate-600"}`}
              style={{ boxShadow: snortRunning ? "0 0 8px #10b981" : "none" }} />
            <span className="display-num" style={{
              fontSize: "1.4rem",
              color: snortRunning ? "#10b981" : "#475569",
              letterSpacing: "0.08em",
              fontFamily: '"IBM Plex Mono", monospace',
            }}>
              {snortRunning ? "RUNNING" : "IDLE"}
            </span>
          </div>

          {/* Progress bar */}
          <div className="mt-3">
            <div className="h-1 w-full overflow-hidden" style={{ background: "rgba(0,212,255,0.06)", border: "1px solid rgba(0,212,255,0.08)" }}>
              <div
                style={{
                  width: `${pct}%`,
                  height: "100%",
                  background: "linear-gradient(90deg, rgba(0,212,255,0.4), #00d4ff)",
                  boxShadow: pct > 0 ? "0 0 8px rgba(0,212,255,0.6)" : "none",
                  transition: "width 0.5s ease-out",
                }}
              />
            </div>
            <p className="text-[10px] font-mono mt-1" style={{ color: "rgba(100,116,139,0.7)" }}>
              {pct}% PCAP PROCESSED
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
