"use client";
import { useState } from "react";
import type { EngineEvaluation, EvaluationResult } from "@/lib/types";
import { useT } from "@/lib/i18n";

type Props = { evaluation: EvaluationResult | null };

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

type EngineDef = {
  key: keyof Omit<EvaluationResult, "total_flows">;
  label: string;
  mode: "flow" | "ip";
  color: string;
};

const ENGINES: EngineDef[] = [
  { key: "xgboost", label: "DoS (Per-Flow)", mode: "flow", color: "#ff3b3b" },
  { key: "portscan", label: "PortScan", mode: "ip", color: "#a855f7" },
  { key: "dos_agg", label: "DoS Aggregator", mode: "ip", color: "#f59e0b" },
  { key: "bot", label: "Bot Client", mode: "ip", color: "#06b6d4" },
  { key: "bruteforce", label: "BruteForce", mode: "ip", color: "#ec4899" },
  { key: "ddos", label: "DDoS", mode: "ip", color: "#ef4444" },
  { key: "community", label: "Community", mode: "flow", color: "#00d4ff" },
];

type CellProps = {
  label: string;
  value: number;
  variant: "tp" | "tn" | "fp" | "fn";
  size?: "sm" | "lg";
};

function MatrixCell({ label, value, variant, size = "sm" }: CellProps) {
  const styles = {
    tp: { border: "rgba(16,185,129,0.3)", bg: "rgba(16,185,129,0.06)", label: "#10b981", val: "#10b981" },
    tn: { border: "rgba(16,185,129,0.15)", bg: "rgba(16,185,129,0.03)", label: "#059669", val: "#059669" },
    fp: { border: "rgba(255,59,59,0.25)", bg: "rgba(255,59,59,0.05)", label: "#64748b", val: "#64748b" },
    fn: { border: "rgba(245,158,11,0.25)", bg: "rgba(245,158,11,0.05)", label: "#f59e0b", val: "#f59e0b" },
  };
  const s = styles[variant];
  const fontSize = size === "lg" ? "text-base" : "text-xs";
  const padding = size === "lg" ? "p-4" : "p-2.5";
  return (
    <div className={`flex flex-col items-center justify-center ${padding} relative`}
      style={{ border: `1px solid ${s.border}`, background: s.bg, minWidth: size === "lg" ? "100px" : "72px" }}>
      <span className="text-[9px] font-mono mb-1" style={{ color: s.label }}>{label}</span>
      <span className={`${fontSize} font-mono font-semibold tabular-nums`} style={{ color: s.val }}>{fmtN(value)}</span>
    </div>
  );
}

function EngineMatrix({ engine, data }: { engine: EngineDef; data: EngineEvaluation }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <div className="w-1.5 h-1.5" style={{ background: engine.color, boxShadow: `0 0 6px ${engine.color}` }} />
        <span className="section-label text-[9px]" style={{ color: engine.color }}>{engine.label}</span>
        {engine.mode === "ip" && (
          <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(168,85,247,0.3)", background: "rgba(168,85,247,0.08)", color: "#a855f7" }}>IP-Level</span>
        )}
      </div>
      <div className="grid grid-cols-4 gap-1">
        <MatrixCell label="TP" value={data.TP} variant="tp" />
        <MatrixCell label="FP" value={data.FP} variant="fp" />
        <MatrixCell label="FN" value={data.FN} variant="fn" />
        <MatrixCell label="TN" value={data.TN} variant="tn" />
      </div>
      <div className="flex items-center gap-3 text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.6)" }}>
        <span>Acc {(data.accuracy * 100).toFixed(2)}%</span>
        <span>Prec {(data.precision * 100).toFixed(2)}%</span>
        <span>Rec {(data.recall * 100).toFixed(2)}%</span>
        <span>F1 {(data.f1 * 100).toFixed(2)}%</span>
        <span>FPR {(data.fpr * 100).toFixed(2)}%</span>
      </div>
    </div>
  );
}

type MetricBarProps = {
  label: string;
  xgbValue: number;
  commValue: number;
  xgbWins: boolean;
  invertWin?: boolean;
};

function MetricBar({ label, xgbValue, commValue, xgbWins, invertWin }: MetricBarProps) {
  const { t } = useT();
  const isTie = xgbValue.toFixed(4) === commValue.toFixed(4);

  const xgbActuallyWins = !isTie && xgbWins;
  const commActuallyWins = !isTie && !xgbWins;

  const xgbBarColor = isTie ? "#64748b" : invertWin ? (xgbWins ? "#10b981" : "#ff3b3b") : (xgbWins ? "#10b981" : "#ff3b3b");
  const commBarColor = isTie ? "#64748b" : invertWin ? (!xgbWins ? "#10b981" : "#ff3b3b") : (!xgbWins ? "#10b981" : "#ff3b3b");

  return (
    <div className="flex items-center gap-4 py-2 border-b last:border-0" style={{ borderColor: "rgba(0,212,255,0.05)" }}>
      <span className="section-label w-16 shrink-0 text-[9px]" style={{ color: "rgba(148,163,184,0.85)" }}>{label}</span>

      <div className="flex-1">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-[10px] font-mono font-semibold tabular-nums" style={{ color: "#ff3b3b" }}>{xgbValue.toFixed(2)}%</span>
          {isTie ? (
            <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(148,163,184,0.5)", background: "rgba(148,163,184,0.1)", color: "#94a3b8" }}>{t("evaluation.tie")}</span>
          ) : xgbActuallyWins ? (
            <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)", color: "#10b981" }}>{t("evaluation.win")}</span>
          ) : null}
        </div>
        <div className="h-px w-full" style={{ background: "rgba(0,212,255,0.06)" }}>
          <div style={{ width: `${Math.min(xgbValue, 100)}%`, height: "1px", background: xgbBarColor, transition: "width 0.6s ease" }} />
        </div>
      </div>

      <div className="flex-1">
        <div className="flex items-center gap-1.5 mb-1">
          <span className="text-[10px] font-mono font-semibold tabular-nums" style={{ color: "#00d4ff" }}>{commValue.toFixed(2)}%</span>
          {isTie ? null : commActuallyWins ? (
            <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(148,163,184,0.5)", background: "rgba(148,163,184,0.1)", color: "#94a3b8" }}>{t("evaluation.win")}</span>
          ) : null}
        </div>
        <div className="h-px w-full" style={{ background: "rgba(0,212,255,0.06)" }}>
          <div style={{ width: `${Math.min(commValue, 100)}%`, height: "1px", background: commBarColor, transition: "width 0.6s ease" }} />
        </div>
      </div>
    </div>
  );
}

export function EvaluationReport({ evaluation }: Props) {
  const { t } = useT();
  const [open, setOpen] = useState(false);

  if (!evaluation) {
    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
        <style>{`
          @keyframes skeletonPulse {
            0%, 100% { opacity: 0.4; }
            50% { opacity: 0.8; }
          }
          .skel { animation: skeletonPulse 1.5s ease-in-out infinite; }
        `}</style>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

        <button
          onClick={() => setOpen((v) => !v)}
          className="w-full flex items-center justify-between px-5 py-2.5 border-b text-left"
          style={{ borderColor: "rgba(0,212,255,0.06)" }}
        >
          <div className="flex items-center gap-3">
            <div className="w-1 h-3.5 skel" style={{ background: "rgba(0,212,255,0.6)" }} />
            <span className="section-label text-[10px]" style={{ color: "#00d4ff" }}>{t("evaluation.title")}</span>
          </div>
          <span className="section-label transition-transform" style={{ color: "rgba(0,212,255,0.4)", transform: open ? "rotate(90deg)" : "none", display: "inline-block" }}>▸</span>
        </button>

        {open && <div className="p-4 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 skel" style={{ background: "#ff3b3b", borderRadius: "50%" }} />
                <span className="section-label text-[9px]" style={{ color: "#ff3b3b" }}>{t("evaluation.mlEnsemble")}</span>
              </div>
              <div className="grid grid-cols-2 gap-1">
                {["TP","FP","FN","TN"].map(v => (
                  <div key={v} className="flex flex-col items-center justify-center p-2.5 relative skel"
                    style={{ border: "1px solid rgba(0,212,255,0.08)", background: "rgba(0,212,255,0.03)", minWidth: "72px", minHeight: "40px" }}>
                    <span className="text-[9px] font-mono mb-1" style={{ color: "rgba(0,212,255,0.25)" }}>{v}</span>
                    <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "rgba(0,212,255,0.25)", minWidth: "40px", display: "inline-block" }}>---</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 skel" style={{ background: "#00d4ff", borderRadius: "50%" }} />
                <span className="section-label text-[9px]" style={{ color: "#00d4ff" }}>{t("evaluation.snortCommunity")}</span>
              </div>
              <div className="grid grid-cols-2 gap-1">
                {["TP","FP","FN","TN"].map(v => (
                  <div key={v} className="flex flex-col items-center justify-center p-2.5 relative skel"
                    style={{ border: "1px solid rgba(0,212,255,0.08)", background: "rgba(0,212,255,0.03)", minWidth: "72px", minHeight: "40px" }}>
                    <span className="text-[9px] font-mono mb-1" style={{ color: "rgba(0,212,255,0.25)" }}>{v}</span>
                    <span className="text-xs font-mono font-semibold tabular-nums" style={{ color: "rgba(0,212,255,0.25)", minWidth: "40px", display: "inline-block" }}>---</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="border-t pt-3 space-y-0" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
            <div className="flex items-center gap-3 pb-1.5 border-b" style={{ borderColor: "rgba(0,212,255,0.05)" }}>
              <span className="section-label w-16 shrink-0 text-[9px] skel" style={{ color: "rgba(148,163,184,0.5)" }}>{t("evaluation.metric")}</span>
              <span className="flex-1 section-label text-[9px] skel" style={{ color: "rgba(255,59,59,0.65)" }}>{t("evaluation.mlEns")}</span>
              <span className="flex-1 section-label text-[9px] skel" style={{ color: "rgba(0,212,255,0.65)" }}>{t("evaluation.comm")}</span>
            </div>
            {[
              { k: "accuracy", label: t("evaluation.accuracy") },
              { k: "precision", label: t("evaluation.precision") },
              { k: "recall", label: t("evaluation.recall") },
              { k: "f1", label: t("evaluation.f1") },
              { k: "fpr", label: t("evaluation.fpr") },
            ].map(({ k, label }) => (
              <div key={k} className="flex items-center gap-4 py-2 border-b last:border-0 skel"
                style={{ borderColor: "rgba(0,212,255,0.04)" }}>
                <span className="section-label w-16 shrink-0 text-[9px]" style={{ color: "rgba(148,163,184,0.5)" }}>{label}</span>
                <div className="flex-1 h-px skel" style={{ background: "rgba(0,212,255,0.1)" }} />
                <div className="flex-1 h-px skel" style={{ background: "rgba(0,212,255,0.1)" }} />
              </div>
            ))}
          </div>

          <p className="section-label text-[9px] pt-2 border-t skel" style={{ color: "rgba(148,163,184,0.7)", borderColor: "rgba(0,212,255,0.04)" }}>
            {t("evaluation.awaiting")}
          </p>
        </div>}
      </div>
    );
  }

  const xgb = evaluation.xgboost;
  const comm = evaluation.community;

  const otherEngines = ENGINES.filter((e) => e.key !== "xgboost" && e.key !== "community");
  const activeOtherEngines = otherEngines.filter((e) => {
    const val = evaluation[e.key];
    return val !== null && val !== undefined;
  });

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318", animation: "fadeIn 0.6s ease-in" }}>
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }`}</style>

      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-5 py-2.5 border-b text-left"
        style={{ borderColor: "rgba(0,212,255,0.06)" }}
      >
        <div className="flex items-center gap-3">
          <div className="w-1 h-3.5" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
          <div>
            <span className="section-label text-[10px]" style={{ color: "#00d4ff" }}>{t("evaluation.title")}</span>
            {activeOtherEngines.length > 0 && (
              <span className="ml-2 text-[8px] font-mono px-1.5 py-0.5" style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)", color: "#10b981" }}>
                +{activeOtherEngines.length} engine{activeOtherEngines.length > 1 ? "s" : ""}
              </span>
            )}
          </div>
        </div>
        <span className="section-label transition-transform" style={{ color: "rgba(0,212,255,0.4)", transform: open ? "rotate(90deg)" : "none", display: "inline-block" }}>▸</span>
      </button>

      {open && (
        <div className="p-4 space-y-4">
          {/* Primary: XGBoost vs Community */}
          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5" style={{ background: "#ff3b3b", boxShadow: "0 0 6px #ff3b3b" }} />
                <span className="section-label text-[9px]" style={{ color: "#ff3b3b" }}>{t("evaluation.mlEnsemble")}</span>
              </div>
              <div className="grid grid-cols-2 gap-1">
                <MatrixCell label="TP" value={xgb.TP} variant="tp" />
                <MatrixCell label="FP" value={xgb.FP} variant="fp" />
                <MatrixCell label="FN" value={xgb.FN} variant="fn" />
                <MatrixCell label="TN" value={xgb.TN} variant="tn" />
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5" style={{ background: "#00d4ff", boxShadow: "0 0 6px #00d4ff" }} />
                <span className="section-label text-[9px]" style={{ color: "#00d4ff" }}>{t("evaluation.snortCommunity")}</span>
              </div>
              <div className="grid grid-cols-2 gap-1">
                <MatrixCell label="TP" value={comm.TP} variant="tp" />
                <MatrixCell label="FP" value={comm.FP} variant="fp" />
                <MatrixCell label="FN" value={comm.FN} variant="fn" />
                <MatrixCell label="TN" value={comm.TN} variant="tn" />
              </div>
            </div>
          </div>

          <div className="border-t pt-3 space-y-0" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
            <div className="flex items-center gap-3 pb-1.5 border-b" style={{ borderColor: "rgba(0,212,255,0.05)" }}>
              <span className="section-label w-16 shrink-0 text-[9px]" style={{ color: "rgba(148,163,184,0.9)" }}>{t("evaluation.metric")}</span>
              <span className="flex-1 section-label text-[9px]" style={{ color: "rgba(255,59,59,0.85)" }}>{t("evaluation.mlEns")}</span>
              <span className="flex-1 section-label text-[9px]" style={{ color: "rgba(0,212,255,0.85)" }}>{t("evaluation.comm")}</span>
            </div>
            <MetricBar label={t("evaluation.accuracy")} xgbValue={xgb.accuracy * 100} commValue={comm.accuracy * 100} xgbWins={xgb.accuracy >= comm.accuracy} />
            <MetricBar label={t("evaluation.precision")} xgbValue={xgb.precision * 100} commValue={comm.precision * 100} xgbWins={xgb.precision >= comm.precision} />
            <MetricBar label={t("evaluation.recall")} xgbValue={xgb.recall * 100} commValue={comm.recall * 100} xgbWins={xgb.recall >= comm.recall} />
            <MetricBar label={t("evaluation.f1")} xgbValue={xgb.f1 * 100} commValue={comm.f1 * 100} xgbWins={xgb.f1 >= comm.f1} />
            <MetricBar label={t("evaluation.fpr")} xgbValue={xgb.fpr * 100} commValue={comm.fpr * 100} xgbWins={xgb.fpr <= comm.fpr} invertWin />
          </div>

          {/* Secondary: Other engines */}
          {activeOtherEngines.length > 0 && (
            <div className="border-t pt-3 space-y-3" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
              <div className="flex items-center gap-2">
                <div className="w-1 h-3" style={{ background: "rgba(168,85,247,0.6)", boxShadow: "0 0 6px rgba(168,85,247,0.4)" }} />
                <span className="section-label text-[10px]" style={{ color: "#a855f7" }}>ML INSPECTORS</span>
              </div>
              <div className="grid grid-cols-2 gap-3">
                {activeOtherEngines.map((eng) => {
                  const data = evaluation[eng.key];
                  if (!data) return null;
                  return <EngineMatrix key={eng.key} engine={eng} data={data} />;
                })}
              </div>
            </div>
          )}

          <p className="section-label text-[9px] pt-2 border-t" style={{ color: "rgba(148,163,184,0.5)", borderColor: "rgba(0,212,255,0.05)" }}>
            {t("evaluation.flowsEvaluated", { count: evaluation.total_flows.toLocaleString("en-US") })}
          </p>
        </div>
      )}
    </div>
  );
}