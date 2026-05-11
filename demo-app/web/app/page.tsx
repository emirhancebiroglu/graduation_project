"use client";
import { useState, useEffect } from "react";
import { useIdsStream } from "@/lib/use-ids-stream";
import { Badge } from "@/components/ui/badge";
import { MetricsPanel } from "@/components/metrics-panel";
import { AlertFeed } from "@/components/alert-feed";
import { TrafficChart } from "@/components/traffic-chart";
import { ComparisonPanel } from "@/components/comparison-panel";
import { AttackControl } from "@/components/attack-control";
import { ConfusionMatrixPanel } from "@/components/confusion-matrix-panel";

export default function Page() {
  const stream = useIdsStream();
  const [isStarting, setIsStarting] = useState(false);
  const [activePcap, setActivePcap] = useState<"normal_2min" | "dos_hulk_2min" | "full_wednesday" | null>(null);
  const {
    alerts,
    engineAlerts,
    connected,
    metrics,
    snortRunning,
    pcapProgress,
    replayStartedAt,
    firstAlertAt,
    firstAlertAtByEngine,
    fileCounts,
    clearAlerts,
  } = stream;

  const [clockStr, setClockStr] = useState<string | null>(null);
  useEffect(() => {
    const tick = () => setClockStr(new Date().toUTCString().slice(17, 25));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  if (snortRunning && isStarting) setIsStarting(false);
  if (!snortRunning && !isStarting && activePcap) setActivePcap(null);

  const effectiveRunning = snortRunning || isStarting;
  const isDos = activePcap === "dos_hulk_2min";

  return (
    <main className="flex min-h-screen flex-col ops-grid" style={{ background: "#0a0c0f" }}>
      {/* ── HEADER ── */}
      <header className="relative flex items-center justify-between px-6 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.12)", background: "rgba(10,12,15,0.95)", backdropFilter: "blur(8px)" }}>
        {/* Left bracket corner */}
        <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.4)" }} />
        <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.4)" }} />

        <div className="flex items-center gap-4">
          {/* Logo mark */}
          <div className="relative">
            <div className="w-8 h-8 flex items-center justify-center" style={{ border: "1px solid rgba(0,212,255,0.4)", background: "rgba(0,212,255,0.08)" }}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z" stroke="#00d4ff" strokeWidth="1" fill="rgba(0,212,255,0.1)" />
                <path d="M8 4L11 5.75V9.25L8 11L5 9.25V5.75L8 4Z" fill="#00d4ff" fillOpacity="0.6" />
              </svg>
            </div>
            {connected && (
              <span className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 rounded-full bg-emerald-400 status-dot-active" />
            )}
          </div>
          <div>
            <h1 className="text-base font-semibold tracking-widest uppercase" style={{ fontFamily: '"IBM Plex Mono", monospace', color: "#e2e8f0", letterSpacing: "0.2em" }}>
              Aegis IDS
            </h1>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="section-label">INTRUSION DETECTION SYSTEM</span>
              <span className="section-label opacity-50">·</span>
              <span className="section-label" style={{ color: "rgba(0,212,255,0.35)" }}>DEMO MODE</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          {/* System clock */}
          <span className="section-label tabular-nums" style={{ color: "rgba(0,212,255,0.35)" }}>
            {clockStr ? `${clockStr} UTC` : null}
          </span>
          {/* Connection status */}
          <div className="flex items-center gap-1.5 px-3 py-1.5" style={{ border: `1px solid ${connected ? "rgba(0,212,255,0.25)" : "rgba(255,59,59,0.25)"}`, background: connected ? "rgba(0,212,255,0.05)" : "rgba(255,59,59,0.05)" }}>
            <span className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-cyan-400 status-dot-active" : "bg-red-500"}`} />
            <span className="section-label" style={{ color: connected ? "#00d4ff" : "#ff3b3b" }}>
              {connected ? "CONNECTED" : "OFFLINE"}
            </span>
          </div>
        </div>
      </header>

      {/* ── THREAT BANNER ── */}
      {effectiveRunning && activePcap && (
        <div className={`relative flex items-center gap-3 px-6 py-2.5 ${isDos ? "threat-active" : ""}`}
          style={{
            background: isDos ? "rgba(255,59,59,0.08)" : "rgba(16,185,129,0.06)",
            borderBottom: `1px solid ${isDos ? "rgba(255,59,59,0.3)" : "rgba(16,185,129,0.2)"}`,
          }}
        >
          <div className={`w-2 h-2 rounded-full ${isDos ? "bg-red-500" : "bg-emerald-400"}`}
            style={{ boxShadow: isDos ? "0 0 8px #ff3b3b" : "0 0 6px #10b981" }} />
          <span className="section-label" style={{ color: isDos ? "#ff3b3b" : "#10b981", fontSize: "0.65rem" }}>
            {isDos ? "⚠ ACTIVE THREAT — DOS HULK ATTACK SIMULATION IN PROGRESS" :
              activePcap === "normal_2min" ? "● BASELINE — NORMAL TRAFFIC REPLAY ACTIVE" :
              "● FULL WEDNESDAY PCAP REPLAY ACTIVE"}
          </span>
        </div>
      )}

      {!effectiveRunning && (
        <div className="text-center py-2" style={{ background: "rgba(0,212,255,0.03)", borderBottom: "1px solid rgba(0,212,255,0.06)" }}>
          <span className="section-label" style={{ color: "rgba(0,212,255,0.4)" }}>
            SYSTEM IDLE — SELECT REPLAY MODE TO BEGIN DEMONSTRATION
          </span>
        </div>
      )}

      {/* ── MAIN CONTENT ── */}
      <div className="flex-1 p-5 flex flex-col gap-4">

        {/* Row 1: Attack Control + Metrics */}
        <div className="grid grid-cols-12 gap-4">
          <div className="col-span-12 md:col-span-4">
            <AttackControl
              snortRunning={effectiveRunning}
              onStarting={(v, pcap) => {
                setIsStarting(v);
                if (v && pcap) setActivePcap(pcap);
                if (!v && !snortRunning) setActivePcap(null);
              }}
            />
          </div>
          <div className="col-span-12 md:col-span-8">
            <MetricsPanel
              metrics={metrics}
              snortRunning={effectiveRunning}
              pcapProgress={pcapProgress}
              replayStartedAt={replayStartedAt}
              firstAlertAt={firstAlertAt}
            />
          </div>
        </div>

        {/* Row 2: Traffic chart */}
        <TrafficChart
          metrics={metrics}
          snortRunning={effectiveRunning}
          replayStartedAt={replayStartedAt}
        />

        {/* Row 3: Confusion matrix */}
        <ConfusionMatrixPanel />

        {/* Row 4: Alert feed + Comparison */}
        <div className="grid grid-cols-12 gap-4 flex-1">
          <div className="col-span-12 md:col-span-8 flex flex-col min-h-[500px]" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
            <div className="flex items-center justify-between px-4 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.1)" }}>
              <div className="flex items-center gap-3">
                <div className="w-1 h-4 bg-cyan-400" style={{ boxShadow: "0 0 6px #00d4ff" }} />
                <span className="section-label" style={{ color: "#00d4ff", fontSize: "0.65rem" }}>LIVE ALERTS</span>
                <span className="display-num text-sm" style={{ color: "#00d4ff" }}>{alerts.length}</span>
              </div>
            </div>
            <div className="flex-1 flex flex-col min-h-0 p-3 pt-2">
              <AlertFeed alerts={alerts} engineAlerts={engineAlerts} onClear={clearAlerts} />
            </div>
          </div>

          <div className="col-span-12 md:col-span-4 flex flex-col gap-4">
            <ComparisonPanel
              alerts={alerts}
              metrics={metrics}
              replayStartedAt={replayStartedAt}
              firstAlertAtByEngine={firstAlertAtByEngine}
              snortRunning={effectiveRunning}
              fileCounts={fileCounts}
            />

            {/* Legend */}
            <div className="relative p-4" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
              <p className="section-label mb-3" style={{ color: "rgba(0,212,255,0.5)" }}>ALERT CLASSIFICATION</p>
              <div className="space-y-2.5">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-red-500" style={{ boxShadow: "0 0 6px #ff3b3b" }} />
                  <span className="text-xs font-mono" style={{ color: "#94a3b8" }}>XGBoost score <span style={{ color: "#ff3b3b" }}>&gt; 0.95</span> — Critical</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-amber-500" style={{ boxShadow: "0 0 6px #f59e0b" }} />
                  <span className="text-xs font-mono" style={{ color: "#94a3b8" }}>XGBoost score <span style={{ color: "#f59e0b" }}>0.90–0.95</span> — High</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full bg-cyan-400" style={{ boxShadow: "0 0 6px #00d4ff" }} />
                  <span className="text-xs font-mono" style={{ color: "#94a3b8" }}>Community rule <span style={{ color: "#00d4ff" }}>match</span></span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="px-6 py-2 flex items-center justify-between border-t" style={{ borderColor: "rgba(0,212,255,0.08)", background: "rgba(10,12,15,0.9)" }}>
        <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>AEGIS IDS // CIC-IDS2017 WEDNESDAY DATASET // XGBOOST v1 PRODUCTION MODEL</span>
        <span className="section-label" style={{ color: "rgba(0,212,255,0.2)" }}>FPR 1.75% // F1 98.49%</span>
      </footer>
    </main>
  );
}
