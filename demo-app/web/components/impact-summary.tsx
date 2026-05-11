"use client";
import type { EvaluationResult } from "@/lib/types";

type Props = { evaluation: EvaluationResult | null };

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

export function ImpactSummary({ evaluation }: Props) {
  if (!evaluation) {
    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="flex items-center justify-center py-10">
          <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>
            ATTACK DETECTION SUMMARY APPEARS AFTER EVALUATION
          </span>
        </div>
      </div>
    );
  }

  const xgb = evaluation.xgboost;
  const comm = evaluation.community;
  const fpGap = comm.FP - xgb.FP;
  const analystMinsPerReplay = fpGap * 6.5;
  const analystHrsPerReplay = analystMinsPerReplay / 60;
  const analystHrsPerWorkingDay = Math.min(analystHrsPerReplay, 24);

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.15)", background: "#0f1318", animation: "fadeIn 0.5s ease-in" }}>
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }`}</style>

      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(245,158,11,0.3)" }} />

      <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.08)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(245,158,11,0.6)", boxShadow: "0 0 6px rgba(245,158,11,0.6)" }} />
        <span className="section-label" style={{ color: "#f59e0b" }}>ATTACK DETECTION SUMMARY</span>
      </div>

      <div className="p-5">
        <div className="space-y-1 mb-4">
          <div className="grid grid-cols-3 gap-2 pb-2 border-b" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
            <span className="section-label" style={{ color: "rgba(0,212,255,0.35)" }}>METRIC</span>
            <span className="section-label" style={{ color: "#ff3b3b" }}>XGBOOST</span>
            <span className="section-label" style={{ color: "#00d4ff" }}>COMMUNITY RULES</span>
          </div>

          <div className="grid grid-cols-3 gap-2 py-2">
            <span className="text-xs font-mono" style={{ color: "rgba(100,116,139,0.6)" }}>Attacks detected</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>{fmtN(xgb.TP)}</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#00d4ff" }}>{fmtN(comm.TP)}</span>
          </div>

          <div className="grid grid-cols-3 gap-2 py-2 border-b" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
            <span className="text-xs font-mono" style={{ color: "rgba(100,116,139,0.6)" }}>False alarms</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: xgb.FP > 0 ? "rgba(255,59,59,0.8)" : "#10b981" }}>{fmtN(xgb.FP)}</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>{fmtN(comm.FP)}</span>
          </div>

          <div className="grid grid-cols-3 gap-2 py-2">
            <span className="text-xs font-mono" style={{ color: "rgba(100,116,139,0.6)" }}>FPR</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>{(xgb.fpr * 100).toFixed(2)}%</span>
            <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>{(comm.fpr * 100).toFixed(2)}%</span>
          </div>
        </div>

        <div className="text-center py-4 border-t" style={{ borderColor: "rgba(245,158,11,0.1)", background: "rgba(245,158,11,0.04)" }}>
          <p className="text-2xl font-mono font-bold tabular-nums" style={{ color: "#f59e0b", letterSpacing: "-0.02em" }}>
            {fmtN(fpGap)} FEWER FALSE ALARMS
          </p>
          <p className="text-xs font-mono mt-1" style={{ color: "rgba(100,116,139,0.7)" }}>
            ~{analystHrsPerWorkingDay.toFixed(1)} analyst-hours saved · {fmtN(fpGap)} alerts reviewed
          </p>
        </div>
      </div>
    </div>
  );
}