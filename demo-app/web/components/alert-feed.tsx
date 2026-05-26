"use client";
import type React from "react";
import { useEffect, useRef, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Alert, Engine, CoreEngine, ShapContribution, ReplayPhase } from "@/lib/types";
import { useT } from "@/lib/i18n";

type Filter = "all" | "xgboost" | "community";

type Props = {
  alerts: Alert[];
  engineAlerts: Record<CoreEngine, Alert[]>;
  replayPhase: ReplayPhase;
  onClear: () => void;
};

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

function getSeverity(alert: Alert): Severity {
  if (alert.engine === "community") return "LOW";
  const s = alert.score;
  if (typeof s !== "number") return "LOW";
  if (s >= 0.95) return "CRITICAL";
  if (s >= 0.85) return "HIGH";
  if (s >= 0.70) return "MEDIUM";
  return "LOW";
}

const _SEVERITY_STYLE: Record<Severity, { color: string; border: string; bg: string; dot: string }> = {
  CRITICAL: { color: "#ff3b3b", border: "rgba(255,59,59,0.4)",  bg: "rgba(255,59,59,0.10)", dot: "#ff3b3b" },
  HIGH:     { color: "#f97316", border: "rgba(249,115,22,0.4)",  bg: "rgba(249,115,22,0.10)", dot: "#f97316" },
  MEDIUM:   { color: "#f59e0b", border: "rgba(245,158,11,0.35)", bg: "rgba(245,158,11,0.08)", dot: "#f59e0b" },
  LOW:      { color: "#64748b", border: "rgba(100,116,139,0.3)", bg: "rgba(100,116,139,0.06)", dot: "#64748b" },
};

function SeverityChip({ alert }: { alert: Alert }): React.ReactElement {
  const { t } = useT();
  if (alert.engine === "community") {
    return (
      <span className="text-[10px] font-mono tabular-nums" style={{ color: "rgba(148,163,184,0.4)" }}>—</span>
    );
  }
  const sev = getSeverity(alert);
  const st = _SEVERITY_STYLE[sev];
  const sevLabel = t(`alerts.sev.${sev.toLowerCase()}`);
  return (
    <span
      className="inline-flex items-center gap-1 text-[8px] font-mono px-1.5 py-0.5 font-bold"
      style={{ border: `1px solid ${st.border}`, background: st.bg, color: st.color, letterSpacing: "0.06em" }}
    >
      <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: st.dot, boxShadow: `0 0 4px ${st.dot}` }} />
      {sevLabel}
    </span>
  );
}

type AttackType = "DoS" | "DDoS" | "Scan" | "BruteForce" | "Bot" | "Exploit" | "Other";

const _TECHNIQUE_TO_TYPE: Record<string, AttackType> = {
  T1499: "DoS",
  T1498: "DDoS",
  T1046: "Scan",
  T1110: "BruteForce",
  T1071: "Bot",
  T1190: "Exploit",
};

const _TYPE_STYLE: Record<AttackType, { color: string; border: string; bg: string }> = {
  DoS:        { color: "#ff3b3b", border: "rgba(255,59,59,0.35)",   bg: "rgba(255,59,59,0.08)" },
  DDoS:       { color: "#f97316", border: "rgba(249,115,22,0.35)",  bg: "rgba(249,115,22,0.08)" },
  Scan:       { color: "#a78bfa", border: "rgba(139,92,246,0.35)",  bg: "rgba(139,92,246,0.08)" },
  BruteForce: { color: "#f59e0b", border: "rgba(245,158,11,0.35)",  bg: "rgba(245,158,11,0.08)" },
  Bot:        { color: "#38bdf8", border: "rgba(56,189,248,0.35)",  bg: "rgba(56,189,248,0.08)" },
  Exploit:    { color: "#f43f5e", border: "rgba(244,63,94,0.35)",   bg: "rgba(244,63,94,0.08)" },
  Other:      { color: "#64748b", border: "rgba(100,116,139,0.25)", bg: "rgba(100,116,139,0.05)" },
};

function getAttackType(alert: Alert): AttackType {
  if (alert.mitre_technique && alert.mitre_technique in _TECHNIQUE_TO_TYPE) {
    return _TECHNIQUE_TO_TYPE[alert.mitre_technique];
  }
  return "Other";
}

function AttackTypeBadge({ alert }: { alert: Alert }): React.ReactElement {
  const type = getAttackType(alert);
  const st = _TYPE_STYLE[type];
  return (
    <span
      className="text-[8px] font-mono px-1.5 py-0.5 font-bold shrink-0"
      style={{ border: `1px solid ${st.border}`, background: st.bg, color: st.color, letterSpacing: "0.04em" }}
    >
      {type}
    </span>
  );
}

function rowColor(alert: Alert): string {
  const sev = getSeverity(alert);
  return _SEVERITY_STYLE[sev].dot;
}

function scoreBadgeStyle(alert: Alert): React.CSSProperties {
  const sev = getSeverity(alert);
  const st = _SEVERITY_STYLE[sev];
  return { border: `1px solid ${st.border}`, background: st.bg, color: st.color };
}

function scoreLabel(alert: Alert): string {
  if (alert.engine === "community") return "—";
  return typeof alert.score === "number" ? alert.score.toFixed(3) : "—";
}

function scoreBand(alert: Alert): string {
  if (alert.engine === "community") return "Community rule match";
  if (alert.score === undefined) return "XGBoost (no score)";
  if (alert.score >= 0.95) return "Critical (score ≥ 0.95)";
  if (alert.score >= 0.85) return "High (score ≥ 0.85)";
  if (alert.score >= 0.70) return "Medium (score ≥ 0.70)";
  return "Low";
}

function GtBadge({ gt }: { gt: string | null | undefined }): React.ReactNode {
  const { t } = useT();
  if (!gt) return null;
  if (gt === "attack") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(16,185,129,0.4)", background: "rgba(16,185,129,0.12)", color: "#10b981", letterSpacing: "0.05em" }}>
        {t("alerts.gt.realAttack")}
      </span>
    );
  }
  if (gt === "benign") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(255,59,59,0.35)", background: "rgba(255,59,59,0.1)", color: "#ff3b3b", letterSpacing: "0.05em" }}>
        {t("alerts.gt.falseAlarm")}
      </span>
    );
  }
  return null;
}

const _MITRE_NAMES: Record<string, string> = {
  T1499: "Endpoint DoS",
  T1498: "Network DoS",
  T1046: "Service Discovery",
  T1110: "Brute Force",
  T1071: "App Layer Protocol",
  T1190: "Exploit Public App",
};

function mitreBadge(technique: string | null | undefined): React.ReactNode {
  if (!technique) return null;
  const name = _MITRE_NAMES[technique] ?? technique;
  return (
    <span
      title={name}
      className="text-[8px] font-mono px-1 py-0.5 font-bold tabular-nums"
      style={{
        border: "1px solid rgba(139,92,246,0.35)",
        background: "rgba(139,92,246,0.08)",
        color: "#a78bfa",
        letterSpacing: "0.04em",
      }}
    >
      {technique}
    </span>
  );
}

function IfBadge({ ifLabel }: { ifLabel: string | null | undefined }): React.ReactNode {
  const { t } = useT();
  if (!ifLabel) return null;
  if (ifLabel === "anomaly_candidate") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(251,191,36,0.4)", background: "rgba(251,191,36,0.1)", color: "#fbbf24", letterSpacing: "0.05em" }}>
        {t("alerts.anomaly.anomaly")}
      </span>
    );
  }
  return (
    <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(148,163,184,0.5)", background: "rgba(148,163,184,0.1)", color: "rgba(148,163,184,0.85)", letterSpacing: "0.05em" }}>
      {t("alerts.anomaly.known")}
    </span>
  );
}

const FILTER_KEYS: { key: "filterAll" | "filterXgboost" | "filterCommunity"; value: Filter }[] = [
  { key: "filterAll", value: "all" },
  { key: "filterXgboost", value: "xgboost" },
  { key: "filterCommunity", value: "community" },
];

export function AlertFeed({ alerts, engineAlerts, replayPhase, onClear }: Props) {
  const { t } = useT();
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [userScrolled, setUserScrolled] = useState(false);
  const [shap, setShap] = useState<ShapContribution[] | null>(null);
  const [shapNarrative, setShapNarrative] = useState<string | null>(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const prevAlertCount = useRef(alerts.length);

  async function fetchShap(alertId: string) {
    setShapLoading(true);
    setShapError(null);
    setShap(null);
    setShapNarrative(null);
    try {
      const res = await fetch(`http://localhost:8000/api/explain/${alertId}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setShapError(body.detail ?? `HTTP ${res.status}`);
        return;
      }
      const data = await res.json();
      setShap(data.contributions ?? data);
      setShapNarrative(data.narrative ?? null);
    } catch (e) {
      setShapError(String(e));
    } finally {
      setShapLoading(false);
    }
  }

  function handleSelectAlert(a: Alert) {
    setSelected(a);
    setShap(null);
    setShapNarrative(null);
    setShapError(null);
    setShapLoading(false);
  }

  const filtered =
    filter === "all"
      ? alerts
      : engineAlerts[filter as CoreEngine];

  const displayed = filtered.slice(0, 200);


  useEffect(() => {
    if (alerts.length === prevAlertCount.current) return;
    prevAlertCount.current = alerts.length;
    if (!userScrolled && scrollRef.current) scrollRef.current.scrollTop = 0;
  }, [alerts.length, userScrolled]);

  useEffect(() => {
    if (alerts.length === 0) setUserScrolled(false);
  }, [alerts.length]);


  function handleScroll(e: React.UIEvent<HTMLDivElement>) {
    setUserScrolled(e.currentTarget.scrollTop > 40);
  }

  return (
    <div className="flex flex-col gap-2 h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 flex-wrap pb-2 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="flex gap-1">
          {FILTER_KEYS.map((f) => (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              className="px-3 py-1 text-[10px] font-mono transition-all"
              style={{
                border: `1px solid ${filter === f.value ? "rgba(0,212,255,0.4)" : "rgba(0,212,255,0.1)"}`,
                background: filter === f.value ? "rgba(0,212,255,0.1)" : "transparent",
                color: filter === f.value ? "#00d4ff" : "rgba(148,163,184,0.9)",
                letterSpacing: "0.1em",
              }}
            >
              {t(`alerts.${f.key}`)}
            </button>
          ))}
        </div>
        <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.75)" }}>
          {displayed.length}/{filtered.length}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {userScrolled && (
            <button
              onClick={() => { setUserScrolled(false); if (scrollRef.current) scrollRef.current.scrollTop = 0; }}
              className="text-[10px] font-mono"
              style={{ color: "rgba(0,212,255,0.5)" }}
            >
              {t("alerts.top")}
            </button>
          )}
          <button
            onClick={onClear}
            className="text-[10px] font-mono px-2 py-1 transition-all"
            style={{ border: "1px solid rgba(148,163,184,0.4)", color: "rgba(148,163,184,0.85)", background: "transparent" }}
          >
            {t("alerts.clear")}
          </button>
        </div>
      </div>

      {/* Table */}
      <div ref={scrollRef} onScroll={handleScroll} className="flex-1 overflow-auto min-h-0">
        {/* Header row */}
        <div className="grid sticky top-0 gap-2 px-2 py-1.5 text-[9px] font-mono border-b" style={{
          gridTemplateColumns: "72px 90px 72px 1fr 1fr 50px 60px 1fr",
          background: "#0f1318",
          borderColor: "rgba(0,212,255,0.08)",
          color: "rgba(0,212,255,0.35)",
          letterSpacing: "0.12em",
        }}>
          <span>{t("alerts.col.time")}</span>
          <span>{t("alerts.col.severity")}</span>
          <span>{t("alerts.col.gt")}</span>
          <span>{t("alerts.col.source")}</span>
          <span>{t("alerts.col.destination")}</span>
          <span>{t("alerts.col.proto")}</span>
          <span>{t("alerts.col.score")}</span>
          <span>{t("alerts.col.typeMessage")}</span>
        </div>

        {/* Data rows */}
        <div className="space-y-px">
          {displayed.map((a) => {
            const color = rowColor(a);
            return (
              <div
                key={a.id}
                onClick={() => handleSelectAlert(a)}
                className="ids-row grid gap-2 px-2 py-2 cursor-pointer transition-all"
                style={{
                  gridTemplateColumns: "72px 90px 72px 1fr 1fr 50px 60px 1fr",
                  borderLeft: `2px solid ${color}33`,
                  background: "transparent",
                }}
              >
                <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.85)" }}>
                  {new Date(a.ts).toLocaleTimeString()}
                </span>
                <span className="flex items-center">
                  <SeverityChip alert={a} />
                </span>
                <span className="flex items-center">
                  <GtBadge gt={a.ground_truth} />
                </span>
                <span className="text-[10px] font-mono truncate" style={{ color }}>
                  {a.src_ip}:{a.src_port}
                </span>
                <span className="text-[10px] font-mono truncate" style={{ color: "rgba(148,163,184,0.95)" }}>
                  {a.dst_ip}:{a.dst_port}
                </span>
                <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.85)" }}>{a.proto}</span>
                <span className="text-[10px] font-mono tabular-nums" style={{ color }}>{scoreLabel(a)}</span>
                <span className="flex items-center gap-1.5 min-w-0">
                  <AttackTypeBadge alert={a} />
                  {mitreBadge(a.mitre_technique)}
                  <span className="text-[10px] font-mono truncate" style={{ color: "rgba(148,163,184,0.85)" }}>{a.msg}</span>
                </span>
              </div>
            );
          })}
          {displayed.length === 0 && (
            <div className="flex items-center justify-center py-12">
              <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>
                {alerts.length === 0 ? t("alerts.awaiting") : t("alerts.noMatch")}
              </span>
            </div>
          )}
          {replayPhase === "draining" && alerts.length > 0 && (
            <div
              className="sticky bottom-0 px-3 py-2 text-center"
              style={{
                background: "rgba(245,158,11,0.08)",
                borderTop: "1px solid rgba(245,158,11,0.2)",
              }}
            >
              <span className="text-[9px] font-mono" style={{ color: "#f59e0b", letterSpacing: "0.08em" }}>
                {t("alerts.drainingNote", { count: alerts.length })}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Detail dialog */}
      <Dialog open={selected !== null} onOpenChange={(open) => !open && setSelected(null)}>
        <DialogContent className="max-w-lg" style={{ background: "#0f1318", border: "1px solid rgba(0,212,255,0.2)" }}>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 font-mono text-sm" style={{ color: "#e2e8f0" }}>
              {t("alerts.dialog.title")}
              {selected && (
                <>
                  <SeverityChip alert={selected} />
                  <AttackTypeBadge alert={selected} />
                </>
              )}
            </DialogTitle>
          </DialogHeader>
          {selected && (
            <div className="space-y-4 text-sm">
              <div className="rounded-none p-3 space-y-1.5" style={{ background: "rgba(0,212,255,0.03)", border: "1px solid rgba(0,212,255,0.1)" }}>
                <Row label={t("alerts.dialog.time")} value={new Date(selected.ts).toISOString()} />
                <Row label={t("alerts.dialog.source")} value={`${selected.src_ip}:${selected.src_port}`} />
                <Row label={t("alerts.dialog.destination")} value={`${selected.dst_ip}:${selected.dst_port}`} />
                <Row label={t("alerts.dialog.protocol")} value={selected.proto} />
                <Row label={t("alerts.dialog.gidSid")} value={`${selected.gid}:${selected.sid}`} />
                <Row label={t("alerts.dialog.message")} value={selected.msg} />
                {selected.score != null && <Row label={t("alerts.dialog.score")} value={selected.score.toFixed(6)} />}
                <Row label={t("alerts.dialog.band")} value={scoreBand(selected)} />
                {selected.ground_truth && (
                  <Row label={t("alerts.dialog.groundTruth")} value={selected.ground_truth === "attack" ? t("alerts.dialog.realAttack") : t("alerts.dialog.falseAlarm")} />
                )}
                {selected.if_label && (
                  <div className="flex gap-3 items-center">
                    <span className="text-[10px] font-mono w-28 shrink-0" style={{ color: "rgba(0,212,255,0.4)", letterSpacing: "0.1em" }}>{t("alerts.dialog.ifAnomaly")}</span>
                    <span className="flex items-center gap-2">
                      <IfBadge ifLabel={selected.if_label} />
                      {selected.if_score != null && (
                        <span className="text-[10px] font-mono tabular-nums" style={{ color: "rgba(148,163,184,0.85)" }}>
                          score={selected.if_score.toFixed(4)}
                        </span>
                      )}
                    </span>
                  </div>
                )}
                {selected.mitre_technique && (
                  <div className="flex gap-3 items-center pt-1 border-t" style={{ borderColor: "rgba(139,92,246,0.12)" }}>
                    <span className="text-[10px] font-mono w-28 shrink-0" style={{ color: "rgba(139,92,246,0.6)", letterSpacing: "0.1em" }}>{t("alerts.dialog.mitre")}</span>
                    <span className="flex items-center gap-2 flex-wrap">
                      {mitreBadge(selected.mitre_technique)}
                      {selected.mitre_tactic && (
                        <span className="text-[8px] font-mono px-1 py-0.5" style={{ border: "1px solid rgba(139,92,246,0.2)", background: "rgba(139,92,246,0.05)", color: "rgba(167,139,250,0.6)" }}>
                          {selected.mitre_tactic}
                        </span>
                      )}
                      <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.75)" }}>
                        {_MITRE_NAMES[selected.mitre_technique] ?? ""}
                      </span>
                    </span>
                  </div>
                )}
              </div>

              {/* SHAP Explain — XGBoost only */}
              {selected.engine === "xgboost" && (
                <div className="space-y-2">
                  {/* Narrative — always visible after fetch */}
                  {shapNarrative && (
                    <div
                      className="px-3 py-2.5"
                      style={{
                        borderLeft: "3px solid rgba(245,158,11,0.7)",
                        background: "rgba(245,158,11,0.06)",
                        border: "1px solid rgba(245,158,11,0.18)",
                        borderLeftWidth: "3px",
                      }}
                    >
                      <p className="text-[9px] font-mono mb-1" style={{ color: "rgba(245,158,11,0.5)", letterSpacing: "0.1em" }}>
                        {t("alerts.dialog.aiAnalysis")}
                      </p>
                      <p className="text-[11px] font-mono leading-relaxed" style={{ color: "#e2e8f0" }}>
                        {shapNarrative}
                      </p>
                    </div>
                  )}

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => fetchShap(selected.id)}
                      disabled={shapLoading}
                      className="text-[10px] font-mono px-3 py-1 transition-all"
                      style={{
                        border: "1px solid rgba(0,212,255,0.3)",
                        background: shapLoading ? "rgba(0,212,255,0.05)" : "transparent",
                        color: shapLoading ? "rgba(0,212,255,0.4)" : "#00d4ff",
                        letterSpacing: "0.08em",
                        cursor: shapLoading ? "wait" : "pointer",
                      }}
                    >
                      {shapLoading ? t("alerts.dialog.computing") : shap ? t("alerts.dialog.reExplain") : t("alerts.dialog.explain")}
                    </button>
                    <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>{t("alerts.dialog.topFeatures")}</span>
                  </div>
                  {shapError && (
                    <div className="text-[10px] font-mono p-2" style={{ background: "rgba(255,59,59,0.07)", border: "1px solid rgba(255,59,59,0.2)", color: "#ff3b3b" }}>
                      {shapError}
                    </div>
                  )}
                  {shap && <ShapChart contributions={shap} />}
                </div>
              )}

              <details>
                <summary className="text-[10px] font-mono cursor-pointer select-none" style={{ color: "rgba(0,212,255,0.4)" }}>
                  {t("alerts.dialog.rawJson")}
                </summary>
                <pre className="mt-2 p-3 text-[10px] overflow-auto max-h-48 font-mono" style={{ background: "rgba(0,0,0,0.4)", border: "1px solid rgba(0,212,255,0.08)", color: "#94a3b8" }}>
                  {JSON.stringify(selected, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3">
      <span className="text-[10px] font-mono w-28 shrink-0" style={{ color: "rgba(0,212,255,0.4)", letterSpacing: "0.1em" }}>{label}</span>
      <span className="text-[10px] font-mono break-all" style={{ color: "#94a3b8" }}>{value}</span>
    </div>
  );
}

function ShapChart({ contributions }: { contributions: ShapContribution[] }) {
  const maxAbs = Math.max(...contributions.map((c) => Math.abs(c.shap_value)), 0.001);
  return (
    <div className="rounded-none p-3 space-y-2" style={{ background: "rgba(0,0,0,0.3)", border: "1px solid rgba(0,212,255,0.08)" }}>
      <div className="text-[9px] font-mono mb-2" style={{ color: "rgba(0,212,255,0.35)", letterSpacing: "0.1em" }}>
        FEATURE CONTRIBUTIONS (SHAP)
      </div>
      {contributions.map((c) => {
        const pct = Math.abs(c.shap_value) / maxAbs * 100;
        const isAttack = c.direction === "attack";
        const barColor = isAttack ? "#ff3b3b" : "#10b981";
        return (
          <div key={c.feature} className="space-y-0.5">
            <div className="flex justify-between items-center gap-2">
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-[10px] font-mono font-semibold shrink-0" style={{ color: "#94a3b8" }}>{c.feature}</span>
                {c.description && c.description !== c.feature && (
                  <span className="text-[9px] font-mono truncate" style={{ color: "rgba(148,163,184,0.5)" }}>({c.description})</span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className="text-[9px] font-mono tabular-nums" style={{ color: "rgba(148,163,184,0.85)" }}>
                  {typeof c.raw_value === "number" && c.raw_value === Math.floor(c.raw_value) ? c.raw_value : c.raw_value?.toFixed(3)}
                </span>
                <span className="text-[9px] font-mono tabular-nums font-bold" style={{ color: barColor }}>
                  {c.shap_value > 0 ? "+" : ""}{c.shap_value.toFixed(3)}
                </span>
              </div>
            </div>
            <div className="relative h-1.5 rounded-none" style={{ background: "rgba(148,163,184,0.18)" }}>
              <div
                className="absolute top-0 h-full transition-all"
                style={{
                  width: `${pct}%`,
                  background: barColor,
                  opacity: 0.7,
                  left: 0,
                }}
              />
            </div>
          </div>
        );
      })}
      <div className="flex gap-4 pt-1">
        <span className="text-[9px] font-mono" style={{ color: "rgba(255,59,59,0.6)" }}>■ pushes toward attack</span>
        <span className="text-[9px] font-mono" style={{ color: "rgba(16,185,129,0.6)" }}>■ pushes toward benign</span>
      </div>
    </div>
  );
}
