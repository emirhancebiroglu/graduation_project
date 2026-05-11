"use client";
import { useState } from "react";

const XGB = {
  TP: 252610, FP: 7679, FN: 62, TN: 432352,
  accuracy: 98.88, precision: 97.05, recall: 99.98, f1: 98.49, fpr: 1.75,
};
const COMM = {
  TP: 252634, FP: 51343, FN: 38, TN: 388688,
  accuracy: 92.58, precision: 83.11, recall: 99.98, f1: 90.77, fpr: 11.67,
};

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

type CellProps = {
  label: string;
  value: number;
  variant: "tp" | "tn" | "fp" | "fn";
};

function MatrixCell({ label, value, variant }: CellProps) {
  const styles = {
    tp: { border: "rgba(16,185,129,0.3)", bg: "rgba(16,185,129,0.06)", label: "#10b981", val: "#10b981" },
    tn: { border: "rgba(16,185,129,0.15)", bg: "rgba(16,185,129,0.03)", label: "#059669", val: "#059669" },
    fp: { border: "rgba(255,59,59,0.3)", bg: "rgba(255,59,59,0.07)", label: "#ff3b3b", val: "#ff3b3b" },
    fn: { border: "rgba(245,158,11,0.25)", bg: "rgba(245,158,11,0.05)", label: "#f59e0b", val: "#f59e0b" },
  };
  const s = styles[variant];
  return (
    <div className="flex flex-col items-center justify-center p-3 relative" style={{ border: `1px solid ${s.border}`, background: s.bg, minWidth: "90px" }}>
      <span className="section-label mb-1" style={{ color: s.label }}>{label}</span>
      <span className="display-num text-lg tabular-nums" style={{ color: s.val, fontFamily: '"IBM Plex Mono", monospace' }}>{fmtN(value)}</span>
    </div>
  );
}

type MetricBarProps = {
  label: string;
  xgbValue: number;
  commValue: number;
  xgbWins: boolean;
  isPercent?: boolean;
  invertWin?: boolean;
};

function MetricBar({ label, xgbValue, commValue, xgbWins, isPercent, invertWin }: MetricBarProps) {
  const suffix = isPercent ? "%" : "";
  const isTie = xgbValue.toFixed(2) === commValue.toFixed(2);

  const xgbActuallyWins = !isTie && xgbWins;
  const commActuallyWins = !isTie && !xgbWins;

  const xgbBarColor = isTie ? "#64748b" : invertWin ? (xgbWins ? "#10b981" : "#ff3b3b") : (xgbWins ? "#10b981" : "#ff3b3b");
  const commBarColor = isTie ? "#64748b" : invertWin ? (!xgbWins ? "#10b981" : "#ff3b3b") : (!xgbWins ? "#10b981" : "#00d4ff");

  const tieTag = (
    <span className="text-[9px] font-mono px-1.5 py-0.5" style={{ border: "1px solid rgba(100,116,139,0.3)", background: "rgba(100,116,139,0.08)", color: "#64748b" }}>
      TIE
    </span>
  );
  const winTag = (
    <span className="text-[9px] font-mono px-1.5 py-0.5" style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)", color: "#10b981" }}>
      WIN
    </span>
  );

  return (
    <div className={`grid grid-cols-2 gap-4 py-2 border-b last:border-0 ${invertWin && !isTie ? "rounded px-1" : ""}`}
      style={{ borderColor: "rgba(0,212,255,0.06)", background: invertWin && !isTie ? "rgba(255,59,59,0.03)" : "transparent" }}>
      {/* XGBoost side */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="section-label w-20 shrink-0" style={{ color: "rgba(100,116,139,0.7)" }}>{label}</span>
          <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>
            {xgbValue.toFixed(2)}{suffix}
          </span>
          {isTie ? tieTag : xgbActuallyWins ? winTag : null}
        </div>
        <div className="h-px w-full" style={{ background: "rgba(0,212,255,0.06)" }}>
          <div
            style={{
              width: `${Math.min((xgbValue / 100) * 100, 100)}%`,
              height: "1px",
              background: xgbBarColor,
              transition: "width 0.5s ease",
            }}
          />
        </div>
      </div>
      {/* Community side */}
      <div className="space-y-1">
        <div className="flex items-center gap-2">
          <span className="section-label w-20 shrink-0" style={{ color: "rgba(100,116,139,0.7)" }}>{label}</span>
          <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "#00d4ff" }}>
            {commValue.toFixed(2)}{suffix}
          </span>
          {isTie ? tieTag : commActuallyWins ? winTag : null}
        </div>
        <div className="h-px w-full" style={{ background: "rgba(0,212,255,0.06)" }}>
          <div
            style={{
              width: `${Math.min((commValue / 100) * 100, 100)}%`,
              height: "1px",
              background: commBarColor,
              transition: "width 0.5s ease",
            }}
          />
        </div>
      </div>
    </div>
  );
}

export function ConfusionMatrixPanel() {
  const [open, setOpen] = useState(true);

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      {/* Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-5 py-3 border-b text-left"
        style={{ borderColor: "rgba(0,212,255,0.08)" }}
      >
        <div className="flex items-center gap-3">
          <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
          <div>
            <span className="section-label" style={{ color: "#00d4ff" }}>PERFORMANCE METRICS — WEDNESDAY CIC-IDS2017</span>
            <span className="section-label ml-3" style={{ color: "rgba(100,116,139,0.5)" }}>DoS Hulk · GoldenEye · Slowloris · Heartbleed</span>
          </div>
        </div>
        <span className="section-label transition-transform" style={{ color: "rgba(0,212,255,0.4)", transform: open ? "rotate(90deg)" : "none", display: "inline-block" }}>▸</span>
      </button>

      {open && (
        <div className="p-5 space-y-5">
          {/* Engine labels */}
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2" style={{ background: "#ff3b3b", boxShadow: "0 0 6px #ff3b3b" }} />
              <span className="section-label" style={{ color: "#ff3b3b" }}>XGBOOST INSPECTOR</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2" style={{ background: "#00d4ff", boxShadow: "0 0 6px #00d4ff" }} />
              <span className="section-label" style={{ color: "#00d4ff" }}>SNORT3 COMMUNITY RULES</span>
            </div>
          </div>

          {/* Confusion matrices */}
          <div className="grid grid-cols-2 gap-4">
            <div className="grid grid-cols-2 gap-1.5">
              <MatrixCell label="TP" value={XGB.TP} variant="tp" />
              <MatrixCell label="FP" value={XGB.FP} variant="fp" />
              <MatrixCell label="FN" value={XGB.FN} variant="fn" />
              <MatrixCell label="TN" value={XGB.TN} variant="tn" />
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <MatrixCell label="TP" value={COMM.TP} variant="tp" />
              <MatrixCell label="FP" value={COMM.FP} variant="fp" />
              <MatrixCell label="FN" value={COMM.FN} variant="fn" />
              <MatrixCell label="TN" value={COMM.TN} variant="tn" />
            </div>
          </div>

          {/* Metric bars */}
          <div className="space-y-0 pt-1 border-t" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
            <MetricBar label="Accuracy" xgbValue={XGB.accuracy} commValue={COMM.accuracy} xgbWins={true} isPercent />
            <MetricBar label="Precision" xgbValue={XGB.precision} commValue={COMM.precision} xgbWins={true} isPercent />
            <MetricBar label="Recall" xgbValue={XGB.recall} commValue={COMM.recall} xgbWins={false} isPercent />
            <MetricBar label="F1-Score" xgbValue={XGB.f1} commValue={COMM.f1} xgbWins={true} isPercent />
            <MetricBar label="FPR ↓" xgbValue={XGB.fpr} commValue={COMM.fpr} xgbWins={true} isPercent invertWin />
          </div>

          {/* Footer */}
          <p className="section-label pt-2 border-t" style={{ color: "rgba(100,116,139,0.4)", borderColor: "rgba(0,212,255,0.06)" }}>
            EVALUATED ON 692,703 FLOWS · WEDNESDAY-WORKINGHOURS.PCAP · GROUND TRUTH LABELS
          </p>
        </div>
      )}
    </div>
  );
}
