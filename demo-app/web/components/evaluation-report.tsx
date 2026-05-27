"use client";
import { useState } from "react";
import type { EngineEvaluation, EvaluationResult, ScenarioPayload } from "@/lib/types";
import { useT } from "@/lib/i18n";

type Props = { evaluation: EvaluationResult | null; scenario?: ScenarioPayload | null };

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

const ENGINE_BY_KEY: Record<string, EngineDef> = ENGINES.reduce((acc, e) => {
  acc[e.key] = e;
  return acc;
}, {} as Record<string, EngineDef>);

export function EvaluationReport({ evaluation, scenario }: Props) {
  const { t } = useT();
  const [open, setOpen] = useState(false);
  const activeEngineKey = (scenario?.active_engine ?? "xgboost") as EngineDef["key"];
  const activeEngineDef = ENGINE_BY_KEY[activeEngineKey] ?? ENGINE_BY_KEY.xgboost;

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

  const isWindowLevel = scenario?.metric_level === "window";

  // When a scenario is active, show FROZEN day-wide baseline.
  // Window-level scenarios use TP_windows/FP_windows/FN_windows from the baseline.
  // Flow-level (DoS) uses classic IP-level confusion from the baseline.
  let xgb: EngineEvaluation;
  let comm: EngineEvaluation;

  if (scenario && scenario.ml.confusion) {
    const mlC = scenario.ml.confusion;
    if (isWindowLevel) {
      // Window-level: use window counts; accuracy/FPR not meaningful
      const tpW = mlC.TP_windows ?? scenario.ml.alerts;
      const fpW = mlC.FP_windows ?? 0;
      const fnW = mlC.FN_windows ?? 0;
      const prec = tpW + fpW > 0 ? tpW / (tpW + fpW) : 1;
      const rec = tpW + fnW > 0 ? tpW / (tpW + fnW) : 1;
      const f1 = prec + rec > 0 ? 2 * prec * rec / (prec + rec) : 0;
      xgb = { TP: tpW, FP: fpW, FN: fnW, TN: 0, accuracy: 0, precision: prec, recall: rec, f1, fpr: 0 };

      // Community window-level: if confusion exists use it; else derive from fpr
      const commC = scenario.community.confusion;
      if (commC) {
        const tpC = commC.TP ?? 0, fpC = commC.FP ?? 0, fnC = commC.FN ?? 0, tnC = commC.TN ?? 0;
        const precC = tpC + fpC > 0 ? tpC / (tpC + fpC) : 0;
        const recC = tpC + fnC > 0 ? tpC / (tpC + fnC) : 0;
        const f1C = precC + recC > 0 ? 2 * precC * recC / (precC + recC) : 0;
        comm = { TP: tpC, FP: fpC, FN: fnC, TN: tnC, accuracy: 0, precision: precC, recall: recC, f1: f1C, fpr: scenario.community.fpr };
      } else {
        // No IP-level confusion for community — derive from alert volume.
        // TP ≈ alerts_on_attackers (community fired on attacker IPs)
        // FP ≈ alerts_total_day - alerts_on_attackers (community fired on benign IPs)
        const commTP = scenario.community.alerts_on_attackers ?? 0;
        const commFP = (scenario.community.alerts_total_day ?? 0) - commTP;
        const precC = commTP + commFP > 0 ? commTP / (commTP + commFP) : 0;
        comm = { TP: commTP, FP: commFP, FN: 0, TN: 0, accuracy: 0, precision: precC, recall: 1, f1: precC > 0 ? 2 * precC / (1 + precC) : 0, fpr: scenario.community.fpr };
      }
    } else {
      // Flow-level: IP-level confusion matrix
      const tpF = mlC.TP ?? 0, fpF = mlC.FP ?? 0, fnF = mlC.FN ?? 0, tnF = mlC.TN ?? 0;
      const total = tpF + fpF + fnF + tnF;
      xgb = {
        TP: tpF, FP: fpF, FN: fnF, TN: tnF,
        accuracy: scenario.ml.accuracy ?? (total > 0 ? (tpF + tnF) / total : 0),
        precision: scenario.ml.precision ?? (tpF + fpF > 0 ? tpF / (tpF + fpF) : 0),
        recall: scenario.ml.recall ?? (tpF + fnF > 0 ? tpF / (tpF + fnF) : 0),
        f1: scenario.ml.f1 ?? 0,
        fpr: scenario.ml.fpr ?? (fpF + tnF > 0 ? fpF / (fpF + tnF) : 0),
      };
      const commC = scenario.community.confusion;
      if (commC) {
        const tpC = commC.TP ?? 0, fpC = commC.FP ?? 0, fnC = commC.FN ?? 0, tnC = commC.TN ?? 0;
        const totalC = tpC + fpC + fnC + tnC;
        const precC = tpC + fpC > 0 ? tpC / (tpC + fpC) : 0;
        const recC = tpC + fnC > 0 ? tpC / (tpC + fnC) : 0;
        comm = {
          TP: tpC, FP: fpC, FN: fnC, TN: tnC,
          accuracy: totalC > 0 ? (tpC + tnC) / totalC : 0,
          precision: precC, recall: recC,
          f1: precC + recC > 0 ? 2 * precC * recC / (precC + recC) : 0,
          fpr: fpC + tnC > 0 ? fpC / (fpC + tnC) : 0,
        };
      } else {
        comm = evaluation.community;
      }
    }
  } else {
    xgb = (evaluation[activeEngineKey] as EngineEvaluation | null) ?? evaluation.xgboost;
    comm = evaluation.community;
  }
  const activeLabel = activeEngineDef.label;
  const activeColor = activeEngineDef.color;
  const activeMode = activeEngineDef.mode;

  // In single-scenario view (scenario set), hide the secondary "ML INSPECTORS"
  // grid — focus the audience on the active inspector vs Community contrast.
  const otherEngines = ENGINES.filter((e) => e.key !== activeEngineKey && e.key !== "community");
  const activeOtherEngines = scenario
    ? []
    : otherEngines.filter((e) => {
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
            {scenario && (
              <span className="ml-2 text-[9px] font-mono tracking-wider uppercase" style={{ color: "rgba(0,212,255,0.6)" }}>
                — {scenario.display.dataset_label}
              </span>
            )}
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
          {/* Primary: ML engine vs Community */}
          <div className="grid grid-cols-2 gap-3 items-stretch">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5" style={{ background: activeColor, boxShadow: `0 0 6px ${activeColor}` }} />
                <span className="section-label text-[9px]" style={{ color: activeColor }}>
                  {scenario ? activeLabel : t("evaluation.mlEnsemble")}
                </span>
                {isWindowLevel && scenario && (
                  <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(168,85,247,0.3)", background: "rgba(168,85,247,0.08)", color: "#a855f7" }}>Window</span>
                )}
                {!isWindowLevel && activeMode === "ip" && scenario && (
                  <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(168,85,247,0.3)", background: "rgba(168,85,247,0.08)", color: "#a855f7" }}>IP-Level</span>
                )}
              </div>
              {isWindowLevel ? (
                <div className="grid grid-cols-3 gap-1">
                  <MatrixCell label="TP" value={xgb.TP} variant="tp" />
                  <MatrixCell label="FP" value={xgb.FP} variant="fp" />
                  <MatrixCell label="FN" value={xgb.FN} variant="fn" />
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-1">
                  <MatrixCell label="TP" value={xgb.TP} variant="tp" />
                  <MatrixCell label="FP" value={xgb.FP} variant="fp" />
                  <MatrixCell label="FN" value={xgb.FN} variant="fn" />
                  <MatrixCell label="TN" value={xgb.TN} variant="tn" />
                </div>
              )}
              {isWindowLevel && scenario?.ml.attacker_ips_detected && (
                <p className="text-[9px] font-mono" style={{ color: "#10b981" }}>
                  {scenario.ml.attacker_ips_detected} detected
                </p>
              )}
              {isWindowLevel && scenario?.ml.fpr != null && (
                <div className="flex justify-between text-[9px] font-mono pt-0.5">
                  <span style={{ color: "rgba(148,163,184,0.5)" }}>FPR</span>
                  <span style={{ color: "#10b981" }}>{(scenario.ml.fpr * 100).toFixed(2)}%</span>
                </div>
              )}
            </div>

            <div className="flex flex-col space-y-2">
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5" style={{ background: "#00d4ff", boxShadow: "0 0 6px #00d4ff" }} />
                <span className="section-label text-[9px]" style={{ color: "#00d4ff" }}>{t("evaluation.snortCommunity")}</span>
                {isWindowLevel && scenario?.community.confusion && (
                  <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(168,85,247,0.3)", background: "rgba(168,85,247,0.08)", color: "#a855f7" }}>IP-Level</span>
                )}
              </div>
              {isWindowLevel && !scenario?.community.confusion ? (
                /* No IP-level confusion for this scenario — show FPR proxy */
                <div className="flex-1 flex flex-col justify-center p-3 space-y-2" style={{ background: "rgba(255,59,59,0.04)", border: "1px solid rgba(255,59,59,0.12)" }}>
                  <div className="flex justify-between">
                    <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.5)" }}>FPR (day-wide)</span>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "#ff3b3b" }}>{((scenario?.community.fpr ?? 0) * 100).toFixed(1)}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.5)" }}>Total alerts</span>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "rgba(148,163,184,0.7)" }}>{(scenario?.community.alerts_total_day ?? 0).toLocaleString("en-US")}</span>
                  </div>
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-1">
                  <MatrixCell label="TP" value={comm.TP} variant="tp" />
                  <MatrixCell label="FP" value={comm.FP} variant="fp" />
                  <MatrixCell label="FN" value={comm.FN} variant="fn" />
                  {!isWindowLevel && <MatrixCell label="TN" value={comm.TN} variant="tn" />}
                </div>
              )}
            </div>
          </div>

          {!isWindowLevel && (
            <div className="border-t pt-3 space-y-0" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
              <div className="flex items-center gap-3 pb-1.5 border-b" style={{ borderColor: "rgba(0,212,255,0.05)" }}>
                <span className="section-label w-16 shrink-0 text-[9px]" style={{ color: "rgba(148,163,184,0.9)" }}>{t("evaluation.metric")}</span>
                <span className="flex-1 section-label text-[9px]" style={{ color: activeColor }}>{scenario ? activeLabel : t("evaluation.mlEns")}</span>
                <span className="flex-1 section-label text-[9px]" style={{ color: "rgba(0,212,255,0.85)" }}>{t("evaluation.comm")}</span>
              </div>
              <MetricBar label={t("evaluation.accuracy")} xgbValue={xgb.accuracy * 100} commValue={comm.accuracy * 100} xgbWins={xgb.accuracy >= comm.accuracy} />
              <MetricBar label={t("evaluation.precision")} xgbValue={xgb.precision * 100} commValue={comm.precision * 100} xgbWins={xgb.precision >= comm.precision} />
              <MetricBar label={t("evaluation.recall")} xgbValue={xgb.recall * 100} commValue={comm.recall * 100} xgbWins={xgb.recall >= comm.recall} />
              <MetricBar label={t("evaluation.f1")} xgbValue={xgb.f1 * 100} commValue={comm.f1 * 100} xgbWins={xgb.f1 >= comm.f1} />
              <MetricBar label={t("evaluation.fpr")} xgbValue={xgb.fpr * 100} commValue={comm.fpr * 100} xgbWins={xgb.fpr <= comm.fpr} invertWin />
            </div>
          )}

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
            {scenario
              ? t("evaluation.frozenBaseline", { dataset: scenario.display.dataset_label })
              : t("evaluation.flowsEvaluated", { count: evaluation.total_flows.toLocaleString("en-US") })}
          </p>
        </div>
      )}
    </div>
  );
}