"use client";
import type { EvaluationResult, ReplayPhase, ScenarioPayload } from "@/lib/types";
import { useT } from "@/lib/i18n";

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
  scenario?: ScenarioPayload | null;
};

const TL_RATE = 280; // ₺/hour SOC analyst
const TRIAGE_MIN_PER_ALERT = 3;
const WORK_DAYS_PER_YEAR = 250;

function fmtN(n: number): string {
  return n.toLocaleString("en-US");
}

function fmtTL(annualHrs: number): string {
  const amount = Math.round(annualHrs * TL_RATE);
  return amount.toLocaleString("tr-TR");
}



function FpBar({ label, value, max, color }: { label: string; value: number; max: number; color: string }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="flex items-center gap-3">
      <span className="text-[11px] font-mono w-20 shrink-0" style={{ color: "rgba(148,163,184,0.95)" }}>{label}</span>
      <div className="flex-1 h-3 rounded-sm overflow-hidden" style={{ background: "rgba(0,212,255,0.06)" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, boxShadow: `0 0 8px ${color}40`, transition: "width 0.8s ease" }} />
      </div>
      <span className="text-[12px] font-mono font-semibold tabular-nums w-16 text-right" style={{ color }}>{fmtN(value)}</span>
    </div>
  );
}

export function ImpactSummary({ evaluation, replayPhase, pcapProgress, frozenMetrics, scenario }: Props) {
  const { t } = useT();
  const useFlowLevel = scenario?.metric_level === "flow";
  // Flow-level: classic false alarm gap story (FP counts)
  // Window-level: alert-volume reduction story (ML windows vs community total alerts)
  const xgbFromScenario = useFlowLevel
    ? scenario?.ml.confusion?.FP
    : scenario?.ml.alerts;
  const commFromScenario = useFlowLevel
    ? scenario?.community.confusion?.FP
    : scenario?.community.alerts_total_day;

  const xgbFP = xgbFromScenario ?? frozenMetrics?.xgb_FP ?? 7393;
  const commFP = commFromScenario ?? frozenMetrics?.community_FP ?? 36633;
  const fpGapBaseline = Math.max(commFP - xgbFP, 0);
  const reductionMultiplier = xgbFP > 0 ? Math.round(commFP / Math.max(xgbFP, 1)) : 0;
  const isIdle = !evaluation;
  const isRunning = replayPhase === "running" || replayPhase === "draining";

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
          <span className="section-label" style={{ color: "#f59e0b" }}>{t("roi.titleIdle")}</span>
        </div>

        <div className="p-6 space-y-6">
          <div className="text-center py-5 px-4 rounded-sm skel"
            style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
            <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.3)" }}>
              {t("roi.analystTimeRecovered")}
            </p>
            <p className="text-4xl font-bold tabular-nums leading-none skel" style={{ color: "rgba(245,158,11,0.4)", letterSpacing: "-0.03em" }}>
              ~--{t("roi.hoursSuffix")}
            </p>
          </div>

          <div className="space-y-3">
            <p className="section-label text-[10px] skel" style={{ color: "rgba(0,212,255,0.55)" }}>
              {t("roi.falseAlarmComparison")}
            </p>
            {[[t("roi.mlEnsemble"),"#64748b"],[t("roi.community"),"#ff3b3b"]].map(([label, color]) => (
              <div key={label as string} className="flex items-center gap-3 skel">
                <span className="text-[10px] font-mono w-20 shrink-0" style={{ color: "rgba(148,163,184,0.65)" }}>{label as string}</span>
                <div className="flex-1 h-3 rounded-sm skel" style={{ background: "rgba(0,212,255,0.06)" }} />
                <span className="text-xs font-mono font-semibold tabular-nums w-16 text-right" style={{ color }}>---</span>
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
    const liveAnnualHrs = liveAnalystHrs * 12;

    return (
      <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.15)", background: "#0f1318" }}>
        <style>{`@keyframes fadeSlide { from { opacity: 0; transform: translateX(-4px); } to { opacity: 1; transform: translateX(0); } }`}</style>
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.3)" }} />

        <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.1)" }}>
          <div className="w-1 h-4" style={{ background: "rgba(245,158,11,0.7)", boxShadow: "0 0 8px rgba(245,158,11,0.6)" }} />
          <span className="section-label" style={{ color: "#f59e0b" }}>{t("roi.titleLive")}</span>
          <span className="section-label ml-auto text-[9px]" style={{ color: "rgba(245,158,11,0.4)" }}>{t("roi.pcapProgress", { pct: Math.round(pcapProgress * 100) })}</span>
        </div>

        <div className="p-5 space-y-4">
          {!useFlowLevel && scenario ? (
            /* Window-level: alert-volume ROI story */
            (() => {
              const mlAlerts = scenario.ml.alerts;
              const commAlerts = scenario.community.alerts_total_day;
              const alertGap = Math.max(commAlerts - mlAlerts, 0);
              const liveAlertGap = Math.round(alertGap * pcapProgress);
              const liveMlAlerts = Math.round(mlAlerts * pcapProgress);
              const liveCommAlerts = Math.round(commAlerts * pcapProgress);
              const liveHrs = Math.round(liveAlertGap * TRIAGE_MIN_PER_ALERT / 60);
              const liveAnnual = liveHrs * 12;
              return (
                <>
                  <div className="text-center py-5 px-4 rounded-sm"
                    style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
                    <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
                      {t("roi.analystTimeRecovered")}
                    </p>
                    <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
                      ~{liveHrs.toLocaleString("en-US")}{t("roi.hoursSuffix")}
                    </p>
                    <p className="text-[11px] font-mono font-semibold mt-2" style={{ color: "#10b981" }}>
                      {t("roi.tlSavings", { amount: fmtTL(liveAnnual) })}
                    </p>
                    <p className="text-[9px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.45)" }}>
                      {t("roi.tlRate")}
                    </p>
                    <p className="text-[10px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.85)" }}>
                      {t("roi.equivalentDays", { days: Math.round(liveAlertGap * TRIAGE_MIN_PER_ALERT / 60 / 8) })}
                    </p>
                  </div>
                  <div className="space-y-3">
                    <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.7)" }}>
                      {t("roi.alertVolumeComparison")}
                    </p>
                    <div className="space-y-2">
                      <FpBar label={t("roi.mlEnsemble")} value={liveMlAlerts} max={Math.max(liveCommAlerts, 1)} color="#94a3b8" />
                      <FpBar label={t("roi.community")} value={liveCommAlerts} max={Math.max(liveCommAlerts, 1)} color="#ff3b3b" />
                    </div>
                    <div className="text-right pt-1">
                      <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
                        {t("roi.fewerAlertsToTriage", { count: liveAlertGap.toLocaleString("en-US"), pct: ((liveAlertGap / Math.max(liveCommAlerts, 1)) * 100).toFixed(1) })}
                      </span>
                    </div>
                  </div>
                </>
              );
            })()
          ) : (
            /* Flow-level: classic analyst-hours hero metric */
            <>
              <div className="text-center py-5 px-4 rounded-sm"
                style={{ background: "rgba(245,158,11,0.06)", border: "1px solid rgba(245,158,11,0.15)" }}>
                <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
                  {t("roi.analystTimeRecovered")}
                </p>
                <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
                  ~{liveAnalystHrs.toLocaleString("en-US")}{t("roi.hoursSuffix")}
                </p>
                <p className="text-[11px] font-mono font-semibold mt-2" style={{ color: "#10b981" }}>
                  {t("roi.tlSavings", { amount: fmtTL(liveAnnualHrs) })}
                </p>
                <p className="text-[9px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.45)" }}>
                  {t("roi.tlRate")}
                </p>
                <p className="text-[10px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.85)" }}>
                  {t("roi.equivalentDays", { days: Math.round((fpGapBaseline * pcapProgress) * 3 / 60 / 8) })}
                </p>
              </div>

              <div className="space-y-3">
                <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.7)" }}>
                  {t("roi.falseAlarmComparison")}
                </p>
                <div className="space-y-2">
                  <FpBar label={t("roi.mlEnsemble")} value={liveXgbFp} max={commFP} color="#94a3b8" />
                  <FpBar label={t("roi.community")} value={liveCommFp} max={commFP} color="#ff3b3b" />
                </div>
                <div className="text-right pt-1">
                  <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
                    {t("roi.fewerFalseAlarms", { count: liveFpGap.toLocaleString("en-US"), pct: ((liveFpGap / Math.max(liveCommFp, 1)) * 100).toFixed(1) })}
                  </span>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    );
  }

  if (!evaluation) return null;
  // Active engine from scenario (defaults to xgboost for legacy flow).
  const activeEngineKey = (scenario?.active_engine ?? "xgboost") as keyof typeof evaluation;
  const activeEval = (evaluation[activeEngineKey] as typeof evaluation.xgboost | null) ?? evaluation.xgboost;
  const xgb = activeEval;
  const comm = evaluation.community;
  // For complete view, prefer scenario frozen baselines (apples-to-apples with
  // the headline that was shown during replay). Live eval xgb.FP / comm.FP can
  // be smaller if the replay was a short slice — that would shrink the gap
  // visually. Use scenario values when present, else fall back to live eval.
  const completeXgbFP = xgbFromScenario ?? xgb.FP;
  const completeCommFP = commFromScenario ?? comm.FP;
  const fpGap = Math.max(completeCommFP - completeXgbFP, 0);
  const analystHrs = Math.round(fpGap * 3 / 60);
  const annualHrs = analystHrs * 12;

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(245,158,11,0.2)", background: "#0f1318", animation: "fadeIn 0.6s ease-in" }}>
      <style>{`@keyframes fadeIn { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }`}</style>

      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(245,158,11,0.4)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(245,158,11,0.4)" }} />

      <div className="flex items-center gap-3 px-5 py-3 border-b" style={{ borderColor: "rgba(245,158,11,0.1)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(245,158,11,0.7)", boxShadow: "0 0 8px rgba(245,158,11,0.6)" }} />
        <span className="section-label" style={{ color: "#f59e0b" }}>{t("roi.titleComplete")}</span>
      </div>

      <div className="p-5 space-y-4">
        {!useFlowLevel && scenario ? (
          /* Window-level: alert-volume ROI story (frozen baselines) */
          (() => {
            const mlAlerts = scenario.ml.alerts;
            const commAlerts = scenario.community.alerts_total_day;
            const alertGap = Math.max(commAlerts - mlAlerts, 0);
            const analystHrsW = Math.round(alertGap * TRIAGE_MIN_PER_ALERT / 60);
            const annualHrsW = analystHrsW * 12;
            const mult = mlAlerts > 0 ? Math.round(commAlerts / Math.max(mlAlerts, 1)) : 0;
            return (
              <>
                <div className="text-center py-5 px-4 rounded-sm" style={{
                  background: "rgba(245,158,11,0.06)",
                  border: "1px solid rgba(245,158,11,0.15)",
                }}>
                  <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
                    {t("roi.analystTimeRecovered")}
                  </p>
                  <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
                    ~{analystHrsW.toLocaleString("en-US")}{t("roi.hoursSuffix")}
                  </p>
                  <p className="text-[11px] font-mono font-semibold mt-2" style={{ color: "#10b981" }}>
                    {t("roi.tlSavings", { amount: fmtTL(annualHrsW) })}
                  </p>
                  <p className="text-[9px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.45)" }}>
                    {t("roi.tlRate")}
                  </p>
                  <p className="text-[10px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.85)" }}>
                    {t("roi.equivalentDays", { days: Math.round(alertGap * TRIAGE_MIN_PER_ALERT / 60 / 8) })}
                  </p>
                </div>
                <div className="space-y-3">
                  <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.3)" }}>
                    {t("roi.alertVolumeComparison")}
                  </p>
                  <div className="space-y-2">
                    <FpBar label={t("roi.mlEnsemble")} value={mlAlerts} max={Math.max(commAlerts, 1)} color="#94a3b8" />
                    <FpBar label={t("roi.community")} value={commAlerts} max={Math.max(commAlerts, 1)} color="#ff3b3b" />
                  </div>
                  <div className="text-right pt-1">
                    <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
                      {t("roi.fewerAlertsToTriage", { count: fmtN(alertGap), pct: ((alertGap / Math.max(commAlerts, 1)) * 100).toFixed(1) })}
                    </span>
                  </div>
                  {mult > 1 && (
                    <div className="text-right">
                      <span className="text-[10px] font-mono" style={{ color: "rgba(0,212,255,0.6)" }}>
                        {t("roi.reductionMultiplier", { x: fmtN(mult) })}
                      </span>
                    </div>
                  )}
                </div>
              </>
            );
          })()
        ) : (
          /* Flow-level: classic analyst-hours + FP bars */
          <>
            <div className="text-center py-5 px-4 rounded-sm" style={{
              background: "rgba(245,158,11,0.06)",
              border: "1px solid rgba(245,158,11,0.15)",
            }}>
              <p className="text-[11px] font-mono uppercase tracking-widest mb-3" style={{ color: "rgba(245,158,11,0.5)" }}>
                {t("roi.analystTimeRecovered")}
              </p>
              <p className="text-4xl font-bold tabular-nums leading-none" style={{ color: "#f59e0b", letterSpacing: "-0.03em", textShadow: "0 0 20px rgba(245,158,11,0.3)" }}>
                ~{analystHrs.toLocaleString("en-US")}{t("roi.hoursSuffix")}
              </p>
              <p className="text-[11px] font-mono font-semibold mt-2" style={{ color: "#10b981" }}>
                {t("roi.tlSavings", { amount: fmtTL(annualHrs) })}
              </p>
              <p className="text-[9px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.45)" }}>
                {t("roi.tlRate")}
              </p>
              <p className="text-[10px] font-mono mt-1" style={{ color: "rgba(148,163,184,0.85)" }}>
                {t("roi.equivalentDays", { days: Math.round(fpGap * 3 / 60 / 8) })}
              </p>
            </div>

            <div className="space-y-3">
              <p className="section-label text-[10px]" style={{ color: "rgba(0,212,255,0.3)" }}>
                {t("roi.falseAlarmComparison")}
              </p>
              <div className="space-y-2">
                <FpBar label={t("roi.mlEnsemble")} value={completeXgbFP} max={Math.max(completeCommFP, 1)} color="#94a3b8" />
                <FpBar label={t("roi.community")} value={completeCommFP} max={Math.max(completeCommFP, 1)} color="#ff3b3b" />
              </div>
              <div className="text-right pt-1">
                <span className="text-xs font-mono font-semibold" style={{ color: "#10b981" }}>
                  {t("roi.fewerFalseAlarms", { count: fmtN(fpGap), pct: ((fpGap / Math.max(completeCommFP, 1)) * 100).toFixed(1) })}
                </span>
              </div>
              {reductionMultiplier > 1 && (
                <div className="text-right">
                  <span className="text-[10px] font-mono" style={{ color: "rgba(0,212,255,0.6)" }}>
                    {t("roi.reductionMultiplier", { x: fmtN(reductionMultiplier) })}
                  </span>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}