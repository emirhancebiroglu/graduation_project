"use client";
import type { EvaluationResult } from "@/lib/types";

type Props = { evaluation: EvaluationResult | null };

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

function FpBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: "rgba(100,116,139,0.7)" }}>{label}</span>
      <div className="flex-1 h-3 rounded-sm overflow-hidden" style={{ background: "rgba(0,212,255,0.06)" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, boxShadow: `0 0 8px ${color}40`, transition: "width 0.8s ease" }} />
      </div>
      <span className="text-xs font-mono font-semibold tabular-nums w-16 text-right" style={{ color }}>{fmtN(value)}</span>
    </div>
  );
}

export function ImpactSummary({ evaluation }: Props) {
  if (!evaluation) {
    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.15)", background: "#0f1318" }}>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
        <div className="flex items-center justify-center py-16">
          <div className="text-center space-y-3">
            <div className="flex items-center justify-center gap-2">
              <div className="w-3 h-3 border border-t-transparent rounded-full animate-spin" style={{ borderColor: "rgba(245,158,11,0.4)", borderTopColor: "transparent" }} />
            </div>
            <span className="section-label block" style={{ color: "rgba(245,158,11,0.3)" }}>
              ROI ANALYSIS LOADING...
            </span>
          </div>
        </div>
      </div>
    );
  }

  const xgb = evaluation.xgboost;
  const comm = evaluation.community;
  const fpGap = comm.FP - xgb.FP;
  const analystHrsPerWorkingDay = Math.min((fpGap * 6.5) / 60, 24);

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.2)", background: "#0f1318", animation: "fadeIn 0.6s ease-in" }}>
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }`}</style>

      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.4)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.4)" }} />

      <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.1)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(245,158,11,0.7)", boxShadow: "0 0 8px rgba(245,158,11,0.6)" }} />
        <span className="section-label" style={{ color: "#f59e0b" }}>ROI ANALYSIS — BUSINESS IMPACT</span>
      </div>

      <div className="p-6 space-y-6">
        <div className="text-center py-5 px-4 rounded-sm" style={{
          background: "rgba(245,158,11,0.06)",
          border: "1px solid rgba(245,158,11,0.15)",
        }}>
          <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
            Analyst Time Recovered Per Replay
          </p>
          <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
            ~{analystHrsPerWorkingDay.toFixed(1)}h
          </p>
          <p className="text-[10px] font-mono mt-2" style={{ color: "rgba(100,116,139,0.6)" }}>
            {fmtN(fpGap)} false alarms eliminated · {fmtN(comm.FP)} alerts → {fmtN(xgb.FP)}
          </p>
        </div>

        <div className="space-y-3">
          <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.3)" }}>
            FALSE ALARM COMPARISON
          </p>
          <div className="space-y-2">
            <FpBar label="XGBoost" value={xgb.FP} max={comm.FP} color="#64748b" />
            <FpBar label="Community" value={comm.FP} max={comm.FP} color="#ff3b3b" />
          </div>
          <div className="text-right pt-1">
            <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
              −{fmtN(fpGap)} fewer false alarms ({((fpGap / comm.FP) * 100).toFixed(1)}% reduction)
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 pt-2 border-t" style={{ borderColor: "rgba(245,158,11,0.08)" }}>
          <div className="text-center py-3 rounded-sm" style={{ background: "rgba(16,185,129,0.06)", border: "1px solid rgba(16,185,129,0.15)" }}>
            <p className="text-lg font-bold font-mono tabular-nums" style={{ color: "#10b981" }}>{(xgb.accuracy * 100).toFixed(2)}%</p>
            <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(100,116,139,0.5)" }}>XGB ACCURACY</p>
          </div>
          <div className="text-center py-3 rounded-sm" style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.1)" }}>
            <p className="text-lg font-bold font-mono tabular-nums" style={{ color: "#00d4ff" }}>{(xgb.recall * 100).toFixed(2)}%</p>
            <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(100,116,139,0.5)" }}>XGB RECALL</p>
          </div>
        </div>
      </div>
    </div>
  );
}