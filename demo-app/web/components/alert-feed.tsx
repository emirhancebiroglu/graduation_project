"use client";
import type React from "react";
import { useEffect, useRef, useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Alert, Engine, ShapContribution } from "@/lib/types";

type Filter = "all" | "xgboost" | "community";

type Props = {
  alerts: Alert[];
  engineAlerts: Record<Engine, Alert[]>;
  onClear: () => void;
};

function rowColor(alert: Alert): string {
  if (alert.engine === "community") return "#00d4ff";
  if (typeof alert.score === "number" && alert.score > 0.95) return "#ff3b3b";
  return "#f59e0b";
}

function scoreBadgeStyle(alert: Alert): React.CSSProperties {
  if (alert.engine === "community") return { border: "1px solid rgba(0,212,255,0.3)", background: "rgba(0,212,255,0.08)", color: "#00d4ff" };
  if (typeof alert.score === "number" && alert.score > 0.95) return { border: "1px solid rgba(255,59,59,0.35)", background: "rgba(255,59,59,0.1)", color: "#ff3b3b" };
  return { border: "1px solid rgba(245,158,11,0.3)", background: "rgba(245,158,11,0.08)", color: "#f59e0b" };
}

function scoreLabel(alert: Alert): string {
  if (alert.engine === "community") return "—";
  return typeof alert.score === "number" ? alert.score.toFixed(3) : "—";
}

function scoreBand(alert: Alert): string {
  if (alert.engine === "community") return "Community rule match";
  if (alert.score === undefined) return "XGBoost (no score)";
  if (alert.score > 0.95) return "Critical (score > 0.95)";
  return "High (score 0.90–0.95)";
}

function gtBadge(gt: string | null | undefined): React.ReactNode {
  if (!gt) return null;
  if (gt === "attack") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(16,185,129,0.4)", background: "rgba(16,185,129,0.12)", color: "#10b981", letterSpacing: "0.05em" }}>
        REAL ATTACK
      </span>
    );
  }
  if (gt === "benign") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(255,59,59,0.35)", background: "rgba(255,59,59,0.1)", color: "#ff3b3b", letterSpacing: "0.05em" }}>
        FALSE ALARM
      </span>
    );
  }
  return null;
}

function ifBadge(ifLabel: string | null | undefined): React.ReactNode {
  if (!ifLabel) return null;
  if (ifLabel === "anomaly_candidate") {
    return (
      <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(251,191,36,0.4)", background: "rgba(251,191,36,0.1)", color: "#fbbf24", letterSpacing: "0.05em" }}>
        ANOMALY
      </span>
    );
  }
  return (
    <span className="text-[8px] font-mono px-1 py-0.5 font-bold" style={{ border: "1px solid rgba(100,116,139,0.3)", background: "rgba(100,116,139,0.08)", color: "rgba(100,116,139,0.6)", letterSpacing: "0.05em" }}>
      KNOWN
    </span>
  );
}

const FILTERS: { label: string; value: Filter }[] = [
  { label: "ALL", value: "all" },
  { label: "XGBOOST", value: "xgboost" },
  { label: "COMMUNITY", value: "community" },
];

export function AlertFeed({ alerts, engineAlerts, onClear }: Props) {
  const [filter, setFilter] = useState<Filter>("all");
  const [selected, setSelected] = useState<Alert | null>(null);
  const [userScrolled, setUserScrolled] = useState(false);
  const [shap, setShap] = useState<ShapContribution[] | null>(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const prevAlertCount = useRef(alerts.length);

  async function fetchShap(alertId: string) {
    setShapLoading(true);
    setShapError(null);
    setShap(null);
    try {
      const res = await fetch(`http://localhost:8000/api/explain/${alertId}`);
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setShapError(body.detail ?? `HTTP ${res.status}`);
        return;
      }
      setShap(await res.json());
    } catch (e) {
      setShapError(String(e));
    } finally {
      setShapLoading(false);
    }
  }

  function handleSelectAlert(a: Alert) {
    setSelected(a);
    setShap(null);
    setShapError(null);
    setShapLoading(false);
  }

  // Use per-engine buffer for XGBOOST/COMMUNITY filters so community alerts are never
  // squeezed out of the combined 1000-cap array by the high XGBoost volume.
  const filtered =
    filter === "all"
      ? alerts
      : engineAlerts[filter as Engine];
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
          {FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              className="px-3 py-1 text-[10px] font-mono transition-all"
              style={{
                border: `1px solid ${filter === f.value ? "rgba(0,212,255,0.4)" : "rgba(0,212,255,0.1)"}`,
                background: filter === f.value ? "rgba(0,212,255,0.1)" : "transparent",
                color: filter === f.value ? "#00d4ff" : "rgba(100,116,139,0.7)",
                letterSpacing: "0.1em",
              }}
            >
              {f.label}
            </button>
          ))}
        </div>
        <span className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.5)" }}>
          {displayed.length}/{filtered.length}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {userScrolled && (
            <button
              onClick={() => { setUserScrolled(false); if (scrollRef.current) scrollRef.current.scrollTop = 0; }}
              className="text-[10px] font-mono"
              style={{ color: "rgba(0,212,255,0.5)" }}
            >
              ↑ TOP
            </button>
          )}
          <button
            onClick={onClear}
            className="text-[10px] font-mono px-2 py-1 transition-all"
            style={{ border: "1px solid rgba(100,116,139,0.2)", color: "rgba(100,116,139,0.6)", background: "transparent" }}
          >
            CLEAR
          </button>
        </div>
      </div>

      {/* Table */}
      <div ref={scrollRef} onScroll={handleScroll} className="flex-1 overflow-auto min-h-0">
        {/* Header row */}
        <div className="grid sticky top-0 gap-2 px-2 py-1.5 text-[9px] font-mono border-b" style={{
          gridTemplateColumns: "80px 80px 72px 1fr 1fr 50px 60px 1fr",
          background: "#0f1318",
          borderColor: "rgba(0,212,255,0.08)",
          color: "rgba(0,212,255,0.35)",
          letterSpacing: "0.12em",
        }}>
          <span>TIME</span>
          <span>ENGINE</span>
          <span>GT</span>
          <span>SOURCE</span>
          <span>DESTINATION</span>
          <span>PROTO</span>
          <span>SCORE</span>
          <span>MESSAGE</span>
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
                  gridTemplateColumns: "80px 80px 72px 1fr 1fr 50px 60px 1fr",
                  borderLeft: `2px solid ${color}22`,
                  background: "transparent",
                }}
              >
                <span className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.6)" }}>
                  {new Date(a.ts).toLocaleTimeString()}
                </span>
                <span>
                  <span className="text-[9px] font-mono px-1.5 py-0.5" style={scoreBadgeStyle(a)}>
                    {a.engine === "xgboost" ? "XGB" : "COM"}
                  </span>
                </span>
                <span className="flex items-center">
                  {gtBadge(a.ground_truth)}
                </span>
                <span className="text-[10px] font-mono truncate" style={{ color }}>
                  {a.src_ip}:{a.src_port}
                </span>
                <span className="text-[10px] font-mono truncate" style={{ color: "rgba(100,116,139,0.8)" }}>
                  {a.dst_ip}:{a.dst_port}
                </span>
                <span className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.6)" }}>{a.proto}</span>
                <span className="text-[10px] font-mono tabular-nums" style={{ color }}>{scoreLabel(a)}</span>
                <span className="text-[10px] font-mono truncate" style={{ color: "rgba(100,116,139,0.6)" }}>{a.msg}</span>
              </div>
            );
          })}
          {displayed.length === 0 && (
            <div className="flex items-center justify-center py-12">
              <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>
                {alerts.length === 0 ? "AWAITING ALERTS…" : "NO ALERTS MATCH FILTER"}
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
              ALERT DETAIL
              {selected && (
                <span className="text-[10px] px-1.5 py-0.5 font-mono" style={scoreBadgeStyle(selected)}>
                  {selected.engine}
                </span>
              )}
            </DialogTitle>
          </DialogHeader>
          {selected && (
            <div className="space-y-4 text-sm">
              <div className="rounded-none p-3 space-y-1.5" style={{ background: "rgba(0,212,255,0.03)", border: "1px solid rgba(0,212,255,0.1)" }}>
                <Row label="TIME" value={new Date(selected.ts).toISOString()} />
                <Row label="SOURCE" value={`${selected.src_ip}:${selected.src_port}`} />
                <Row label="DESTINATION" value={`${selected.dst_ip}:${selected.dst_port}`} />
                <Row label="PROTOCOL" value={selected.proto} />
                <Row label="GID:SID" value={`${selected.gid}:${selected.sid}`} />
                <Row label="MESSAGE" value={selected.msg} />
                {selected.score != null && <Row label="SCORE" value={selected.score.toFixed(6)} />}
                <Row label="BAND" value={scoreBand(selected)} />
                {selected.ground_truth && (
                  <Row label="GROUND TRUTH" value={selected.ground_truth === "attack" ? "REAL ATTACK" : "FALSE ALARM"} />
                )}
                {selected.if_label && (
                  <div className="flex gap-3 items-center">
                    <span className="text-[10px] font-mono w-28 shrink-0" style={{ color: "rgba(0,212,255,0.4)", letterSpacing: "0.1em" }}>IF ANOMALY</span>
                    <span className="flex items-center gap-2">
                      {ifBadge(selected.if_label)}
                      {selected.if_score != null && (
                        <span className="text-[10px] font-mono tabular-nums" style={{ color: "rgba(100,116,139,0.6)" }}>
                          score={selected.if_score.toFixed(4)}
                        </span>
                      )}
                    </span>
                  </div>
                )}
              </div>

              {/* SHAP Explain — XGBoost only */}
              {selected.engine === "xgboost" && (
                <div className="space-y-2">
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
                      {shapLoading ? "COMPUTING…" : "EXPLAIN (SHAP)"}
                    </button>
                    <span className="text-[9px] font-mono" style={{ color: "rgba(100,116,139,0.4)" }}>top-5 features</span>
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
                  RAW JSON ▸
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
            <div className="flex justify-between items-center">
              <span className="text-[10px] font-mono" style={{ color: "#94a3b8" }}>{c.feature}</span>
              <div className="flex items-center gap-2">
                <span className="text-[9px] font-mono tabular-nums" style={{ color: "rgba(100,116,139,0.6)" }}>
                  val={c.raw_value}
                </span>
                <span className="text-[9px] font-mono tabular-nums font-bold" style={{ color: barColor }}>
                  {c.shap_value > 0 ? "+" : ""}{c.shap_value.toFixed(3)}
                </span>
              </div>
            </div>
            <div className="relative h-1.5 rounded-none" style={{ background: "rgba(100,116,139,0.12)" }}>
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
