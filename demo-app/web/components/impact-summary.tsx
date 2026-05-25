"use client";
import type { EvaluationResult } from "@/lib/types";
import type { ReplayPhase } from "@/lib/use-ids-stream";

type FrozenMetrics = {
  xgb_FP: number;
  community_FP: number;
  fp_gap: number;
};

type Props = {
  evaluation: EvaluationResult | null;
  replayPhase: ReplayPhase;
  pcapProgress: number;
  frozenMetrics?: FrozenMetrics | null;
};

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

function FpBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-3">
      <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: "rgba(148,163,184,0.9)" }}>{label}</span>
      <div className="flex-1 h-3 rounded-sm overflow-hidden" style={{ background: "rgba(0,212,255,0.06)" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, boxShadow: `0 0 8px ${color}40`, transition: "width 0.8s ease" }} />
      </div>
      <span className="text-xs font-mono font-semibold tabular-nums w-16 text-right" style={{ color }}>{fmtN(value)}</span>
    </div>
  );
}

export function ImpactSummary({ evaluation, replayPhase, pcapProgress, frozenMetrics }: Props) {
  const xgbFP = frozenMetrics?.xgb_FP ?? 7393;
  const commFP = frozenMetrics?.community_FP ?? 36633;
  const fpGapBaseline = frozenMetrics?.fp_gap ?? (commFP - xgbFP);
  const isIdle = !evaluation;
  const isRunning = replayPhase === "running";

  if (isIdle && !isRunning) {
    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.15)", background: "#0f1318" }}>
        <style>{`
          @keyframes skeletonPulse {
            0%, 100% { opacity: 0.4; }
            50% { opacity: 0.9; }
          }
          .skel { animation: skeletonPulse 1.5s ease-in-out infinite; }
        `}</style>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />

        <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.1)" }}>
          <div className="w-1 h-4 skel" style={{ background: "rgba(245,158,11,0.7)" }} />
          <span className="section-label" style={{ color: "#f59e0b" }}>ROI ANALYSIS — BUSINESS IMPACT</span>
        </div>

        <div className="p-6 space-y-6">
          <div className="text-center py-5 px-4 rounded-sm skel"
            style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
            <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.3)" }}>
              Analyst Time Recovered
            </p>
            <p className="text-4xl font-bold tabular-nums leading-none skel" style={{ color: "rgba(245,158,11,0.4)", letterSpacing: "-0.03em" }}>
              ~--h
            </p>
          </div>

          <div className="space-y-3">
            <p className="section-label text-[10px] skel" style={{ color: "rgba(0,212,255,0.2)" }}>
              FALSE ALARM COMPARISON
            </p>
            {[["ML Ensemble","#64748b"],["Community","#ff3b3b"]].map(([label, color]) => (
              <div key={label as string} className="flex items-center gap-3 skel">
                <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: "rgba(148,163,184,0.65)" }}>{label as string}</span>
                <div className="flex-1 h-3 rounded-sm skel" style={{ background: "rgba(0,212,255,0.06)" }} />
                <span className="text-xs font-mono font-semibold tabular-nums w-16 text-right" style={{ color }}>---</span>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-3 pt-2 border-t skel" style={{ borderColor: "rgba(245,158,11,0.08)" }}>
            {[["#10b981","XGB ACCURACY"],["#00d4ff","XGB RECALL"]].map(([color, label]) => (
              <div key={label as string} className="text-center py-3 rounded-sm"
                style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.08)" }}>
                <p className="text-lg font-bold font-mono tabular-nums" style={{ color: color as string, opacity: 0.4 }}>--%</p>
                <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.5)" }}>{label as string}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (isRunning) {
    const liveFpGap = Math.round(fpGapBaseline * pcapProgress);
    const liveXgbFp = Math.round(xgbFP * pcapProgress);
    const liveCommFp = Math.round(commFP * pcapProgress);
    const liveAnalystHrs = Math.round((fpGapBaseline * pcapProgress) * 3 / 60);

    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.15)", background: "#0f1318" }}>
        <style>{`@keyframes fadeSlide { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; transform: translateX(0); } }`}</style>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />

        <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.1)" }}>
          <div className="w-1 h-4" style={{ background: "rgba(245,158,11,0.7)", boxShadow: "0 0 8px rgba(245,158,11,0.6)" }} />
          <span className="section-label" style={{ color: "#f59e0b" }}>ROI ANALYSIS — LIVE</span>
          <span className="section-label ml-auto text-[9px]" style={{ color: "rgba(245,158,11,0.4)" }}>PCAP {Math.round(pcapProgress * 100)}%</span>
        </div>

        <div className="p-6 space-y-6">
          <div className="text-center py-5 px-4 rounded-sm"
            style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
            <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
              Analyst Time Recovered
            </p>
            <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
              ~{liveAnalystHrs.toLocaleString("en-US")}h
            </p>
            <p className="text-[10px] font-mono mt-2" style={{ color: "rgba(148,163,184,0.85)" }}>
              Equivalent to ~{Math.round((fpGapBaseline * pcapProgress) * 3 / 60 / 8)} working days saved (assuming 3 min/alert, 8h/day)
            </p>
          </div>

          <div className="space-y-3">
            <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.3)" }}>
              FALSE ALARM COMPARISON
            </p>
            <div className="space-y-2">
              <FpBar label="ML Ensemble" value={liveXgbFp} max={commFP} color="#64748b" />
              <FpBar label="Community" value={liveCommFp} max={commFP} color="#ff3b3b" />
            </div>
            <div className="text-right pt-1">
              <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
                −{liveFpGap.toLocaleString("en-US")} fewer false alarms ({((liveFpGap / liveCommFp) * 100).toFixed(1)}% reduction)
              </span>
            </div>
          </div>

        </div>
      </div>
    );
  }

  if (!evaluation) return null;
  const xgb = evaluation.xgboost;
  const comm = evaluation.community;
  const fpGap = comm.FP - xgb.FP;
  const analystHrs = Math.round(fpGap * 3 / 60);

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
            Analyst Time Recovered
          </p>
<p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
              ~{analystHrs.toLocaleString("en-US")}h
            </p>
            <p className="text-[10px] font-mono mt-2" style={{ color: "rgba(148,163,184,0.85)" }}>
              Equivalent to ~{Math.round(fpGap * 3 / 60 / 8)} working days saved (assuming 3 min/alert, 8h/day)
            </p>
        </div>

        <div className="space-y-3">
          <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.3)" }}>
            FALSE ALARM COMPARISON
          </p>
          <div className="space-y-2">
            <FpBar label="ML Ensemble" value={xgb.FP} max={comm.FP} color="#64748b" />
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
            <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.75)" }}>XGB ACCURACY</p>
          </div>
          <div className="text-center py-3 rounded-sm" style={{ background: "rgba(0,212,255,0.04)", border: "1px solid rgba(0,212,255,0.1)" }}>
            <p className="text-lg font-bold font-mono tabular-nums" style={{ color: "#00d4ff" }}>{(xgb.recall * 100).toFixed(2)}%</p>
            <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.75)" }}>XGB RECALL</p>
          </div>
        </div>
      </div>
    </div>
  );
}