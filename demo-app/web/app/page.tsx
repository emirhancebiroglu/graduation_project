"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { useIdsStream } from "@/lib/use-ids-stream";
import { AlertFeed } from "@/components/alert-feed";
import { EvaluationReport } from "@/components/evaluation-report";
import { ImpactSummary } from "@/components/impact-summary";
// import { TrafficChart } from "@/components/traffic-chart";  // DISABLED
import { DetectionCoverage } from "@/components/detection-coverage";
import { ArcxIntegration } from "@/components/arcx-integration";
import { AttackNarration } from "@/components/attack-narration";
import { MitreMap } from "@/components/mitre-map";
import { ThreatBriefing } from "@/components/threat-briefing";
import { LanguageToggle } from "@/components/language-toggle";
import { useT } from "@/lib/i18n";
import { toast } from "sonner";
import type { Engine, Alert } from "@/lib/types";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

async function startReplay(): Promise<void> {
  const res = await fetch(`${API}/api/replay/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pcap: "full_wednesday" }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
}

async function stopReplay(): Promise<void> {
  const res = await fetch(`${API}/api/replay/stop`, { method: "POST" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

type FrozenMetrics = {
  xgb_FP: number;
  community_FP: number;
  fp_gap: number;
};

export default function Page() {
  const { t } = useT();
  const stream = useIdsStream();
  const [isStarting, setIsStarting] = useState(false);
  const { connected, snortRunning, pcapProgress, replayPhase, evaluation, alerts, engineAlerts, markStarted } = stream;
  const [feedAlerts, setFeedAlerts] = useState(alerts);
  const [feedEngineAlerts, setFeedEngineAlerts] = useState<Record<Engine, Alert[]>>(engineAlerts);
  const [frozenMetrics, setFrozenMetrics] = useState<FrozenMetrics | null>(null);
  const [replayStartedAt, setReplayStartedAt] = useState<number | null>(null);

  // On mount: stop any in-progress replay so UI always starts clean
  useEffect(() => {
    fetch(`${API}/api/replay/stop`, { method: "POST" }).catch(() => {});
  }, []);

  useEffect(() => {
    fetch("/api/config")
      .then((r) => r.json())
      .then((cfg) => {
        setFrozenMetrics({
          xgb_FP: cfg.metrics?.FP ?? 7393,
          community_FP: cfg.community_baseline?.FP ?? 36633,
          fp_gap: cfg.community_baseline?.fp_gap ?? 29240,
        });
      })
      .catch(() => {
        setFrozenMetrics({ xgb_FP: 7393, community_FP: 36633, fp_gap: 29240 });
      });
  }, []);

  // Debounced sync — batch UI updates at ~150ms, pass stream arrays directly
  const throttleRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingAlertsRef = useRef<Alert[]>(alerts);
  const pendingEngineRef = useRef<Record<Engine, Alert[]>>(engineAlerts);

  useEffect(() => {
    pendingAlertsRef.current = alerts;
    pendingEngineRef.current = engineAlerts;
    if (throttleRef.current) return;
    throttleRef.current = setTimeout(() => {
      throttleRef.current = null;
      setFeedAlerts(pendingAlertsRef.current);
      setFeedEngineAlerts(pendingEngineRef.current);
    }, 150);
  }, [alerts, engineAlerts]);

  const [clockStr, setClockStr] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => setClockStr(new Date().toUTCString().slice(17, 25));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const [replayLoading, setReplayLoading] = useState<"start" | "stop" | null>(null);

  async function handleStart() {
    markStarted();
    setReplayLoading("start");
    setIsStarting(true);
    try {
      await startReplay();
      toast.success(t("toast.started"));
    } catch (err) {
      setIsStarting(false);
      toast.error(t("toast.startFail", { err: err instanceof Error ? err.message : String(err) }));
    } finally {
      setReplayLoading(null);
    }
  }

  async function handleStop() {
    setReplayLoading("stop");
    try {
      await stopReplay();
      toast.success(t("toast.stopped"));
    } catch (err) {
      toast.error(t("toast.stopFail", { err: err instanceof Error ? err.message : String(err) }));
    } finally {
      setReplayLoading(null);
    }
  }

  const prevSnortRunning = useRef(false);
  useEffect(() => {
    if (snortRunning && isStarting) setIsStarting(false);
    if (snortRunning && !prevSnortRunning.current) setReplayStartedAt(Date.now());
    prevSnortRunning.current = snortRunning;
  }, [snortRunning, isStarting]);

  const effectiveRunning = snortRunning || isStarting;

  // chartMetrics — DISABLED (TrafficChart disconnected)
  /*
  const chartMetrics = useMemo(() => ({
    xgboost:   { total: feedEngineAlerts.xgboost.length,   alertsPerSec: 0 },
    community: { total: feedEngineAlerts.community.length, alertsPerSec: 0 },
    portscan:  { total: feedEngineAlerts.portscan.length,  alertsPerSec: 0 },
    dos_agg:   { total: feedEngineAlerts.dos_agg.length,   alertsPerSec: 0 },
    bot:       { total: feedEngineAlerts.bot.length,       alertsPerSec: 0 },
    bruteforce:{ total: feedEngineAlerts.bruteforce.length,alertsPerSec: 0 },
  }), [
    feedEngineAlerts.xgboost.length, feedEngineAlerts.community.length,
    feedEngineAlerts.portscan.length, feedEngineAlerts.dos_agg.length,
    feedEngineAlerts.bot.length, feedEngineAlerts.bruteforce.length,
  ]);
  */

  return (
    <main className="flex min-h-screen flex-col" style={{ background: "#0a0c0f" }}>
      {/* ── HEADER ── */}
      <header
        className="relative flex items-center justify-between px-6 py-3 border-b"
        style={{ borderColor: "rgba(0,212,255,0.12)", background: "rgba(10,12,15,0.95)" }}
      >
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.4)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.4)" }} />

        <div className="flex items-center gap-4">
          <div className="relative">
            <div
              className="w-8 h-8 flex items-center justify-center"
              style={{ border: "1px solid rgba(0,212,255,0.4)", background: "rgba(0,212,255,0.08)" }}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,0.1)" />
                <path d="M8 4L11 5.75V9.25L8 11L5 9.25V5.75L8 4Z" fill="#00d4ff" fillOpacity="0.6" />
              </svg>
            </div>
            {connected && (
              <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ boxShadow: "0 0 6px #10b981" }} />
            )}
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-widest uppercase" style={{ fontFamily: '"IBM Plex Mono", monospace', color: "#e2e8f0", letterSpacing: "0.2em" }}>
              {t("header.title")}
            </h1>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="section-label">{t("header.subtitle")}</span>
              <span className="section-label opacity-50">·</span>
              <span className="section-label" style={{ color: "rgba(0,212,255,0.6)" }}>{t("header.demoMode")}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <LanguageToggle />
          <span className="section-label tabular-nums" style={{ color: "rgba(0,212,255,0.6)" }}>
            {clockStr ? `${clockStr} UTC` : null}
          </span>

          {/* ── REPLAY CONTROL ── */}
          {!effectiveRunning ? (
            <button
              disabled={replayLoading !== null}
              onClick={handleStart}
              className="flex items-center gap-2.5 px-3 py-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                border: "1px solid rgba(0,212,255,0.35)",
                background: "rgba(0,212,255,0.06)",
              }}
            >
              {replayLoading === "start" ? (
                <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin shrink-0" style={{ borderColor: "#00d4ff", borderTopColor: "transparent" }} />
              ) : (
                <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                  <polygon points="1,0 10,5 1,10" fill="#00d4ff" />
                </svg>
              )}
              <span className="section-label" style={{ color: "#00d4ff" }}>{t("header.runAnalysis")}</span>
            </button>
          ) : (
            <button
              disabled={replayLoading === "stop"}
              onClick={handleStop}
              className="flex items-center gap-2.5 px-3 py-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{
                border: "1px solid rgba(255,59,59,0.35)",
                background: "rgba(255,59,59,0.06)",
              }}
            >
              {replayLoading === "stop" ? (
                <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin shrink-0" style={{ borderColor: "#ff3b3b", borderTopColor: "transparent" }} />
              ) : (
                <div className="w-2 h-2 shrink-0" style={{ background: "#ff3b3b" }} />
              )}
              <span className="section-label" style={{ color: "#ff3b3b" }}>{t("header.stop")}</span>
            </button>
          )}

          {/* ── ENGINE HEALTH CHIP ── */}
          <div
            className="flex items-center gap-2 px-3 py-1.5"
            style={{
              border: `1px solid ${effectiveRunning ? "rgba(16,185,129,0.25)" : "rgba(0,212,255,0.12)"}`,
              background: effectiveRunning ? "rgba(16,185,129,0.05)" : "rgba(0,212,255,0.03)",
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full"
              style={{
                background: effectiveRunning ? "#10b981" : "#475569",
                boxShadow: effectiveRunning ? "0 0 6px #10b981" : "none",
                animation: effectiveRunning ? "status-breathe 2s ease-in-out infinite" : "none",
              }}
            />
            <span className="section-label" style={{ color: effectiveRunning ? "#10b981" : "rgba(148,163,184,0.5)" }}>
              {effectiveRunning ? t("header.inspectorsActive") : t("header.standby")}
            </span>
            <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>·</span>
            <span className="section-label tabular-nums" style={{ color: effectiveRunning ? "rgba(148,163,184,0.75)" : "rgba(148,163,184,0.35)" }}>
              176MB
            </span>
          </div>

          <div
            className="flex items-center gap-1.5 px-3 py-1.5"
            style={{ border: `1px solid ${connected ? "rgba(0,212,255,0.25)" : "rgba(255,59,59,0.25)"}`, background: connected ? "rgba(0,212,255,0.05)" : "rgba(255,59,59,0.05)" }}
          >
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: connected ? "#00d4ff" : "#ff3b3b", boxShadow: connected ? "0 0 6px #00d4ff" : "0 0 6px #ff3b3b" }} />
            <span className="section-label" style={{ color: connected ? "#00d4ff" : "#ff3b3b" }}>
              {connected ? t("header.connected") : t("header.offline")}
            </span>
          </div>
        </div>
      </header>

      {/* ── REPLAY PHASE INDICATOR ── */}
      {replayPhase === "idle" && (
        <div className="text-center py-2.5" style={{ background: "rgba(0,212,255,0.03)", borderBottom: "1px solid rgba(0,212,255,0.06)" }}>
          <span className="section-label" style={{ color: "rgba(0,212,255,0.7)" }}>
            {t("phase.idle")}
          </span>
        </div>
      )}

      {replayPhase !== "idle" && (
        <div
          className="relative flex items-center justify-center gap-3 px-6 py-2.5"
          style={{
            background:
              replayPhase === "complete"
                ? "rgba(16,185,129,0.06)"
                : replayPhase === "draining"
                ? "rgba(245,158,11,0.06)"
                : "rgba(0,212,255,0.04)",
            borderBottom: `1px solid ${
              replayPhase === "complete"
                ? "rgba(16,185,129,0.2)"
                : replayPhase === "draining"
                ? "rgba(245,158,11,0.2)"
                : "rgba(0,212,255,0.08)"
            }`,
          }}
        >
          {replayPhase === "running" && (
            <div className="w-2 h-2 rounded-full" style={{ background: "#00d4ff", boxShadow: "0 0 8px #00d4ff", animation: "pulse 1.5s infinite" }} />
          )}
          {replayPhase === "draining" && (
            <div className="w-2 h-2 rounded-full" style={{ background: "#f59e0b", boxShadow: "0 0 8px #f59e0b", animation: "pulse 1s infinite" }} />
          )}
          {replayPhase === "complete" && (
            <div className="w-2 h-2 rounded-full" style={{ background: "#10b981", boxShadow: "0 0 8px #10b981" }} />
          )}
          <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }`}</style>
          <span
            className="section-label text-[0.65rem] tracking-widest"
            style={{
              color:
                replayPhase === "complete"
                  ? "#10b981"
                  : replayPhase === "draining"
                  ? "#f59e0b"
                  : "#00d4ff",
            }}
          >
            {replayPhase === "running"
              ? t("phase.running")
              : replayPhase === "draining"
              ? t("phase.draining")
              : t("phase.complete")}
          </span>

          {(replayPhase === "running" || replayPhase === "draining") && (
            <div
              className="absolute inset-x-0 bottom-0"
              style={{ height: "3px", overflow: "hidden" }}
            >
              <div
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  right: 0,
                  height: "100%",
                  width: `${Math.round(pcapProgress * 100)}%`,
                  background: replayPhase === "draining"
                    ? "linear-gradient(90deg, #f59e0b 0%, #f59e0b 85%, rgba(245,158,11,0.2) 100%)"
                    : "linear-gradient(90deg, #00d4ff 0%, #00d4ff 85%, rgba(0,212,255,0.2) 100%)",
                  boxShadow: replayPhase === "draining"
                    ? "0 0 12px rgba(245,158,11,0.7), 0 0 4px rgba(245,158,11,0.5)"
                    : "0 0 12px rgba(0,212,255,0.7), 0 0 4px rgba(0,212,255,0.5)",
                  transition: "width 0.4s ease",
                }}
              />
            </div>
          )}
        </div>
      )}

      {/* ── ATTACK NARRATION ── */}
      <AttackNarration alerts={feedAlerts} replayPhase={replayPhase} replayStartedAt={replayStartedAt} />

      {/* ── MAIN CONTENT ── */}
      <div className="flex-1 p-5 flex flex-col gap-4">

        {/* ROI / Impact — hero section, most prominent */}
        <ImpactSummary evaluation={evaluation} replayPhase={replayPhase} pcapProgress={pcapProgress} frozenMetrics={frozenMetrics} />

        {/* Performance Metrics */}
        <EvaluationReport evaluation={evaluation} />

        {/* Detection Timeline — DISABLED (not working correctly) */}
        {/*
        {(feedAlerts.length > 0 || replayPhase === "running" || replayPhase === "draining" || replayPhase === "complete") && (
          <TrafficChart
            metrics={chartMetrics}
            snortRunning={effectiveRunning}
            replayStartedAt={replayStartedAt}
            pcapProgress={pcapProgress}
            alerts={feedAlerts}
          />
        )}
        */}

        {/* Alert Feed — live alerts with IF anomaly tags + SHAP explain */}
        {(feedAlerts.length > 0 || replayPhase === "running" || replayPhase === "draining") && (
          <div
            className="relative"
            style={{
              border: `1px solid ${replayPhase === "draining" ? "rgba(245,158,11,0.2)" : "rgba(0,212,255,0.12)"}`,
              background: replayPhase === "draining" ? "rgba(245,158,11,0.02)" : "#0f1318",
              minHeight: "320px",
              maxHeight: "480px",
              display: "flex",
              flexDirection: "column",
            }}
          >
            <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
            <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
            <div className="flex items-center gap-3 px-5 py-3 border-b shrink-0" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
              <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.7)", boxShadow: "0 0 8px rgba(0,212,255,0.4)" }} />
              <span className="section-label" style={{ color: replayPhase === "draining" ? "#f59e0b" : "#00d4ff" }}>
                {replayPhase === "draining" ? t("alertFeedSection.finalizing") : t("alertFeedSection.live")}
              </span>
              <span className="section-label ml-2 text-[9px]" style={{ color: "rgba(0,212,255,0.65)" }}>
                {feedAlerts.length} {t("alertFeedSection.countSuffix")}
              </span>
            </div>
            <div className="flex-1 overflow-hidden p-3">
              <AlertFeed
                alerts={feedAlerts}
                engineAlerts={feedEngineAlerts}
                replayPhase={replayPhase}
                onClear={() => {
                  setFeedAlerts([]);
                  setFeedEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [] });
                }}
              />
            </div>
          </div>
        )}
      </div>

      {/* Footer */}
      <footer className="px-6 py-2 flex items-center justify-between border-t" style={{ borderColor: "rgba(0,212,255,0.08)", background: "rgba(10,12,15,0.9)" }}>
        <span className="section-label" style={{ color: "rgba(0,212,255,0.55)" }}>
          {t("footer.tag")}
        </span>
        {evaluation && (
          <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>
            FPR {(evaluation.xgboost.fpr * 100).toFixed(2)}% // F1 {(evaluation.xgboost.f1 * 100).toFixed(2)}%
          </span>
        )}
      </footer>

      {/* Fixed right-rail coverage drawer */}
      <DetectionCoverage />
      {/* Fixed left-rail ARCX integration drawer */}
      <ArcxIntegration alerts={feedAlerts} />
      {/* Bottom MITRE ATT&CK map */}
      <MitreMap alerts={feedAlerts} />
      {/* Fullscreen idle overlay — threat statistics */}
      <ThreatBriefing replayPhase={replayPhase} />
    </main>
  );
}