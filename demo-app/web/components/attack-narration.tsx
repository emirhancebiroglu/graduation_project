"use client";
import { useEffect, useRef, useState } from "react";
import { useT } from "@/lib/i18n";
import type { Alert, MetricLevel, ReplayPhase } from "@/lib/types";

type Props = {
  alerts: Alert[];
  replayPhase: ReplayPhase;
  replayStartedAt: number | null;
  metricLevel?: MetricLevel;
};

const ENGINE_COLOR: Record<string, string> = {
  xgboost:    "#ff3b3b",
  portscan:   "#a855f7",
  dos_agg:    "#f97316",
  ddos:       "#f97316",
  bot:        "#ec4899",
  bruteforce: "#facc15",
};

const ENGINE_LABEL: Record<string, string> = {
  xgboost:    "DoS",
  portscan:   "PortScan",
  dos_agg:    "DDoS",
  ddos:       "DDoS",
  bot:        "Bot",
  bruteforce: "BruteForce",
};

const NARRATION_KEY: Record<string, string> = {
  xgboost:    "narration.dos",
  portscan:   "narration.portscan",
  dos_agg:    "narration.dos_agg",
  ddos:       "narration.dos_agg",
  bot:        "narration.bot",
  bruteforce: "narration.bruteforce",
};

const NARRATION_WINDOW_KEY: Record<string, string> = {
  dos_agg:    "narration.dos_agg_window",
  ddos:       "narration.dos_agg_window",
  portscan:   "narration.portscan_window",
  bot:        "narration.bot_window",
  bruteforce: "narration.bruteforce_window",
};

// Only ML engines — community is Snort rule match, not meaningful for narration
const ML_ENGINES = new Set(["xgboost", "portscan", "dos_agg", "ddos", "bot", "bruteforce"]);

const DISPLAY_MS = 7000;
const FADE_MS = 600;

export function AttackNarration({ alerts, replayPhase, replayStartedAt, metricLevel }: Props) {
  const { t } = useT();
  const isWindowLevel = metricLevel === "window";

  // Queue of ML alerts waiting to be shown
  const queueRef = useRef<Alert[]>([]);
  const seenIdsRef = useRef<Set<string>>(new Set());
  // Window-level: track seen IPs and window counts (src_ip → count)
  const seenIpsRef = useRef<Map<string, number>>(new Map());
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const startedAtRef = useRef<number | null>(null);

  const [displayed, setDisplayed] = useState<Alert | null>(null);
  const [displayedWindowCount, setDisplayedWindowCount] = useState<number>(1);
  const [phase, setPhase] = useState<"in" | "hold" | "out" | "hidden">("hidden");
  const [elapsed, setElapsed] = useState<string>("0.0");

  // Enqueue new ML alerts
  useEffect(() => {
    if (replayPhase !== "running") return;
    alerts.forEach((a) => {
      if (!ML_ENGINES.has(a.engine)) return;
      if (a.ground_truth === "benign") return;

      if (isWindowLevel) {
        // Deduplicate by src_ip — one narration per unique attacker IP
        const key = a.src_ip;
        const prevCount = seenIpsRef.current.get(key);
        if (prevCount !== undefined) {
          // IP already seen — just increment window count (don't re-queue)
          seenIpsRef.current.set(key, prevCount + 1);
        } else {
          seenIpsRef.current.set(key, 1);
          seenIdsRef.current.add(a.id);
          queueRef.current.push(a);
        }
      } else {
        if (seenIdsRef.current.has(a.id)) return;
        seenIdsRef.current.add(a.id);
        queueRef.current.push(a);
      }
    });
  }, [alerts, replayPhase, isWindowLevel]);

  // Advance queue on a fixed cadence — never reset timer mid-display
  function showNext() {
    const next = queueRef.current.shift();
    if (!next) {
      setPhase("hidden");
      setDisplayed(null);
      // Poll again after a short wait in case more alerts arrive
      timerRef.current = setTimeout(showNext, 1500);
      return;
    }
    const elapsedSec = startedAtRef.current
      ? ((Date.now() - startedAtRef.current) / 1000).toFixed(1)
      : "0.0";
    setElapsed(elapsedSec);
    setDisplayed(next);
    // For window-level, snapshot current window count for this IP
    if (isWindowLevel) {
      setDisplayedWindowCount(seenIpsRef.current.get(next.src_ip) ?? 1);
    }
    setPhase("in");

    // After DISPLAY_MS, start fade-out
    timerRef.current = setTimeout(() => {
      setPhase("out");
      // After fade completes, show next
      timerRef.current = setTimeout(showNext, FADE_MS);
    }, DISPLAY_MS);
  }

  // Keep ref in sync so showNext closure always reads current value
  useEffect(() => {
    startedAtRef.current = replayStartedAt;
  }, [replayStartedAt]);

  // Start cadence when replay begins
  useEffect(() => {
    if (replayPhase === "running") {
      if (timerRef.current) return; // already running
      timerRef.current = setTimeout(showNext, 2000); // slight delay before first
    } else {
      if (timerRef.current) { clearTimeout(timerRef.current); timerRef.current = null; }
      queueRef.current = [];
      seenIdsRef.current = new Set();
      seenIpsRef.current = new Map();
      startedAtRef.current = null;
      setPhase("hidden");
      setDisplayed(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [replayPhase]);

  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);

  if (phase === "hidden" || !displayed) return null;

  const color = ENGINE_COLOR[displayed.engine] ?? "#94a3b8";
  const label = ENGINE_LABEL[displayed.engine] ?? displayed.engine;
  const narrationKey = isWindowLevel
    ? (NARRATION_WINDOW_KEY[displayed.engine] ?? NARRATION_KEY[displayed.engine] ?? "narration.community")
    : (NARRATION_KEY[displayed.engine] ?? "narration.community");
  const message = isWindowLevel
    ? t(narrationKey, { src: displayed.src_ip, dst: displayed.dst_ip, windows: displayedWindowCount })
    : t(narrationKey, { src: displayed.src_ip, dst: displayed.dst_ip });
  const detectedText = t("narration.detected", { elapsed });
  const scoreText = displayed.score !== null && displayed.score !== undefined
    ? `${t("narration.score")}: ${Number(displayed.score).toFixed(3)}`
    : null;

  const animClass = phase === "in" ? "narrate-enter" : phase === "out" ? "narrate-exit" : "";

  return (
    <>
      <style>{`
        @keyframes narrateIn {
          from { opacity: 0; transform: translateY(-5px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes narrateOut {
          from { opacity: 1; transform: translateY(0); }
          to   { opacity: 0; transform: translateY(-3px); }
        }
        .narrate-enter { animation: narrateIn 0.3s ease forwards; }
        .narrate-exit  { animation: narrateOut ${FADE_MS}ms ease forwards; }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
      `}</style>
      <div
        key={displayed.id}
        className={`${animClass} flex items-center gap-3 px-6 py-2`}
        style={{
          background: `linear-gradient(90deg, ${color}18 0%, rgba(10,12,15,0.97) 70%)`,
          borderBottom: `1px solid ${color}20`,
          borderLeft: `3px solid ${color}`,
          minHeight: "36px",
          backdropFilter: "blur(4px)",
        }}
      >
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: color, boxShadow: `0 0 8px ${color}`, animation: "pulse 1.2s infinite" }}
        />

        <span
          className="text-[8px] font-mono px-1.5 py-0.5 shrink-0"
          style={{ background: `${color}1a`, color, letterSpacing: "0.08em", border: `1px solid ${color}30` }}
        >
          {label}
        </span>

        <span className="text-[11px] font-mono" style={{ color: "rgba(226,232,240,0.9)" }}>
          {message}
        </span>

        <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.2)" }}>·</span>

        <span className="text-[10px] font-mono shrink-0" style={{ color: `${color}88` }}>
          {detectedText}
        </span>

        {scoreText && (
          <>
            <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.2)" }}>·</span>
            <span className="text-[10px] font-mono tabular-nums shrink-0" style={{ color: "rgba(148,163,184,0.45)" }}>
              {scoreText}
            </span>
          </>
        )}
      </div>
    </>
  );
}
