"use client";
import { useEffect, useRef, useState } from "react";
import {
  ComposedChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";
import type { Alert } from "@/lib/types";
import type { EngineMetrics } from "@/lib/use-ids-stream";

const DEFAULT_WINDOW_S = 90;
const TICK_MS = 250;

type Bucket = { t: number; xgboost: number; community: number; total: number };
type EventMarker = { t: number; label: string; color: string; engine: string };

type Props = {
  metrics: Record<"xgboost" | "community", EngineMetrics>;
  snortRunning: boolean;
  replayStartedAt: number | null;
  pcapProgress: number;
  pcapReplayWallS: number;
  alerts: Alert[];
};

const ENGINE_COLORS: Record<string, string> = {
  xgboost:    "#ff3b3b",
  portscan:   "#a855f7",
  dos_agg:    "#f97316",
  bot:        "#3b82f6",
  bruteforce: "#eab308",
  community:  "#00d4ff",
};

const ENGINE_LABELS: Record<string, string> = {
  xgboost:    "DoS",
  portscan:   "Scan",
  dos_agg:    "DDoS",
  bot:        "Bot",
  bruteforce: "BruteF",
  community:  "Comm",
};

function buildEmptyBuckets(windowS: number): Bucket[] {
  return Array.from({ length: windowS }, (_, i) => ({
    t: i,
    xgboost: 0,
    community: 0,
    total: 0,
  }));
}

interface TooltipPayloadEntry {
  dataKey: string;
  value: number;
  color: string;
}

function CustomTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  label?: number;
}) {
  if (!active || !payload?.length) return null;
  const t = typeof label === "number" ? label : 0;
  const tLabel = t >= 0 ? `T+${t}s` : `T${t}s`;
  const ml = payload.find((p) => p.dataKey === "xgboost");
  const comm = payload.find((p) => p.dataKey === "community");
  const total = (ml?.value ?? 0) + (comm?.value ?? 0);
  return (
    <div style={{
      background: "rgba(15,19,24,0.97)",
      border: "1px solid rgba(0,212,255,0.2)",
      padding: "8px 12px",
      fontFamily: '"IBM Plex Mono", monospace',
      fontSize: "10px",
      boxShadow: "0 0 20px rgba(0,212,255,0.1)",
      minWidth: 140,
    }}>
      <div style={{ color: "rgba(0,212,255,0.6)", marginBottom: 4, fontSize: 9 }}>{tLabel}</div>
      {ml && ml.value > 0 && (
        <div style={{ color: "#ff3b3b", display: "flex", justifyContent: "space-between", gap: 16 }}>
          <span>ML ENSEMBLE</span><span>{ml.value}/s</span>
        </div>
      )}
      {comm && comm.value > 0 && (
        <div style={{ color: "#00d4ff", display: "flex", justifyContent: "space-between", gap: 16 }}>
          <span>COMMUNITY</span><span>{comm.value}/s</span>
        </div>
      )}
      {total > 0 && (
        <div style={{ color: "rgba(148,163,184,0.6)", borderTop: "1px solid rgba(0,212,255,0.08)", marginTop: 4, paddingTop: 4, display: "flex", justifyContent: "space-between", gap: 16 }}>
          <span>TOTAL</span><span>{total}/s</span>
        </div>
      )}
    </div>
  );
}

export function TrafficChart({ metrics, snortRunning, replayStartedAt, pcapProgress, pcapReplayWallS, alerts }: Props) {
  const [mounted, setMounted] = useState(false);
  const [windowS, setWindowS] = useState(DEFAULT_WINDOW_S);
  const [buckets, setBuckets] = useState<Bucket[]>(() => buildEmptyBuckets(DEFAULT_WINDOW_S));
  const [eventMarkers, setEventMarkers] = useState<EventMarker[]>([]);
  const [peakBucket, setPeakBucket] = useState<{ t: number; val: number } | null>(null);
  const [replayEnded, setReplayEnded] = useState(false);
  const [hasEverReplayed, setHasEverReplayed] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);

  useEffect(() => { setMounted(true); }, []);

  const frozenBuckets = useRef<Bucket[] | null>(null);
  const replayEndedRef = useRef(false);
  const pending = useRef<Map<number, { xgboost: number; community: number }>>(new Map());
  const prevRunning = useRef(false);
  const replayStartSec = useRef<number | null>(null);
  const replayStartMs = useRef<number | null>(null);
  const prevTotals = useRef<Record<"xgboost" | "community", number>>({ xgboost: 0, community: 0 });
  const seenEngines = useRef<Set<string>>(new Set());
  const eventMarkersRef = useRef<EventMarker[]>([]);
  const windowSRef = useRef(DEFAULT_WINDOW_S);

  useEffect(() => {
    if (snortRunning && !prevRunning.current) {
      const nowMs = Date.now();
      replayStartMs.current = replayStartedAt ?? nowMs;
      replayStartSec.current = Math.floor((replayStartedAt ?? nowMs) / 1000);
      const initWindow = DEFAULT_WINDOW_S;
      windowSRef.current = initWindow;
      setWindowS(initWindow);
      setBuckets(buildEmptyBuckets(initWindow));
      frozenBuckets.current = null;
      replayEndedRef.current = false;
      setReplayEnded(false);
      setHasEverReplayed(true);
      setEventMarkers([]);
      setPeakBucket(null);
      setElapsedSec(0);
      pending.current = new Map();
      prevTotals.current = { xgboost: 0, community: 0 };
      seenEngines.current = new Set();
      eventMarkersRef.current = [];
    }
    if (!snortRunning && prevRunning.current) {
      replayEndedRef.current = true;
      setReplayEnded(true);
    }
    prevRunning.current = snortRunning;
  }, [snortRunning, replayStartedAt]);

  // Lock in final window size once Snort wall-clock is known
  useEffect(() => {
    if (pcapReplayWallS > 0) {
      const w = Math.ceil(pcapReplayWallS) + 10;
      windowSRef.current = w;
      setWindowS(w);
    }
  }, [pcapReplayWallS]);

  // Track new engine types from alerts → event markers
  useEffect(() => {
    if (!snortRunning || !replayStartMs.current) return;
    for (const alert of alerts) {
      const eng = alert.engine;
      if (!seenEngines.current.has(eng)) {
        seenEngines.current.add(eng);
        const alertMs = new Date(alert.ts).getTime();
        const tSec = Math.round((alertMs - replayStartMs.current) / 1000);
        const marker: EventMarker = {
          t: tSec,
          label: ENGINE_LABELS[eng] ?? eng.toUpperCase().slice(0, 5),
          color: ENGINE_COLORS[eng] ?? "#94a3b8",
          engine: eng,
        };
        eventMarkersRef.current = [...eventMarkersRef.current, marker];
        setEventMarkers([...eventMarkersRef.current]);
      }
    }
  }, [alerts, snortRunning]);

  // Accumulate metric deltas
  const xgbTotal = metrics?.xgboost?.total ?? 0;
  const commTotal = metrics?.community?.total ?? 0;
  if (xgbTotal !== prevTotals.current.xgboost || commTotal !== prevTotals.current.community) {
    const nowSec = Math.floor(Date.now() / 1000);
    if (!pending.current.has(nowSec)) pending.current.set(nowSec, { xgboost: 0, community: 0 });
    const b = pending.current.get(nowSec)!;
    b.xgboost += Math.max(0, xgbTotal - prevTotals.current.xgboost);
    b.community += Math.max(0, commTotal - prevTotals.current.community);
    prevTotals.current = { xgboost: xgbTotal, community: commTotal };
  }

  useEffect(() => {
    const id = setInterval(() => {
      if (frozenBuckets.current !== null) {
        setBuckets(frozenBuckets.current);
        return;
      }

      const nowSec = Math.floor(Date.now() / 1000);
      const startSec = replayStartSec.current ?? nowSec;
      const elapsed = nowSec - startSec;
      setElapsedSec(elapsed);

      // Expand window dynamically as elapsed grows, until pcapReplayWallS is known
      setWindowS((prev) => {
        const needed = elapsed + 15;
        return needed > prev ? needed : prev;
      });

      const cutoff = startSec - 10;
      for (const k of pending.current.keys()) { if (k < cutoff) pending.current.delete(k); }

      // Grow window dynamically until pcapReplayWallS is received
      const needed = elapsed + 15;
      if (needed > windowSRef.current) {
        windowSRef.current = needed;
        setWindowS(needed);
      }
      const currentWindow = windowSRef.current;

      const next: Bucket[] = Array.from({ length: currentWindow }, (_, i) => {
        const sec = startSec + i;
        const counts = pending.current.get(sec) ?? { xgboost: 0, community: 0 };
        return {
          t: i,
          xgboost: counts.xgboost,
          community: counts.community,
          total: counts.xgboost + counts.community,
        };
      });

      let peak = { t: 0, val: 0 };
      for (const bk of next) {
        const v = bk.xgboost + bk.community;
        if (v > peak.val) peak = { t: bk.t, val: v };
      }
      if (peak.val > 0) setPeakBucket(peak);

      if (replayEndedRef.current && next.some((bk) => bk.xgboost > 0 || bk.community > 0)) {
        frozenBuckets.current = next;
      }
      setBuckets(next);
    }, TICK_MS);
    return () => clearInterval(id);
  }, []);

  const hasData = buckets.some((b) => b.xgboost > 0 || b.community > 0);
  const maxVal = Math.max(...buckets.map((b) => b.xgboost + b.community), 1);
  const yDomain: [number, number | string] = maxVal < 3 ? [0, 5] : [0, "auto"];
  const showWaiting = !hasData && !hasEverReplayed;
  const xDomain: [number, number] = [0, windowS - 1];

  // Cursor position from pcapProgress — clamp to valid range
  const cursorT = snortRunning ? Math.min(Math.round(pcapProgress * (windowS - 1)), windowS - 1) : null;

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="flex items-center gap-3">
          <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
          <span className="section-label" style={{ color: "#00d4ff" }}>DETECTION TIMELINE</span>
          {snortRunning && (
            <span className="section-label tabular-nums" style={{ color: "rgba(0,212,255,0.4)" }}>
              T+{elapsedSec}s
            </span>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-5 h-px" style={{ background: "#ff3b3b", boxShadow: "0 0 4px #ff3b3b" }} />
            <span className="section-label" style={{ color: "rgba(255,59,59,0.7)" }}>ML ENSEMBLE</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-5 h-px" style={{ background: "#00d4ff" }} />
            <span className="section-label" style={{ color: "rgba(0,212,255,0.7)" }}>COMMUNITY</span>
          </div>
          {replayEnded && (
            <div className="flex items-center gap-1.5 px-2 py-0.5" style={{ border: "1px solid rgba(16,185,129,0.2)", background: "rgba(16,185,129,0.05)" }}>
              <span className="w-1 h-1 rounded-full" style={{ background: "#10b981" }} />
              <span className="section-label" style={{ color: "#10b981" }}>COMPLETE</span>
            </div>
          )}
        </div>
      </div>

      {/* Event marker legend — only show if markers exist */}
      {eventMarkers.length > 0 && (
        <div className="flex items-center gap-3 px-5 py-1.5 border-b" style={{ borderColor: "rgba(0,212,255,0.04)", background: "rgba(0,0,0,0.2)" }}>
          <span className="section-label" style={{ color: "rgba(0,212,255,0.3)", fontSize: "0.6rem" }}>DETECTED ATTACK TYPES:</span>
          {eventMarkers.map((m) => (
            <div key={m.engine} className="flex items-center gap-1">
              <div className="w-1.5 h-1.5" style={{ background: m.color, boxShadow: `0 0 4px ${m.color}` }} />
              <span className="section-label" style={{ color: m.color, fontSize: "0.6rem" }}>{m.label}</span>
            </div>
          ))}
        </div>
      )}

      {/* Chart */}
      <div className="relative px-2 pb-2 pt-3" style={{ height: 200 }}>
        {showWaiting && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-2">
            <div className="flex gap-1">
              {[0,1,2,3,4].map((i) => (
                <div
                  key={i}
                  className="w-0.5 rounded-full"
                  style={{
                    background: "rgba(0,212,255,0.2)",
                    height: `${8 + i * 4}px`,
                    animation: `barPulse 1.5s ease-in-out ${i * 0.1}s infinite alternate`,
                  }}
                />
              ))}
            </div>
            <span className="section-label" style={{ color: "rgba(0,212,255,0.25)" }}>AWAITING TRAFFIC DATA</span>
            <style>{`@keyframes barPulse { from { opacity: 0.15 } to { opacity: 0.5 } }`}</style>
          </div>
        )}

        {mounted && (
          <ResponsiveContainer width="100%" height={180}>
            <ComposedChart data={buckets} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="fillXgb2" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#ff3b3b" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="#ff3b3b" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="fillCom2" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00d4ff" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#00d4ff" stopOpacity={0.02} />
                </linearGradient>
              </defs>

              <CartesianGrid
                strokeDasharray="1 6"
                stroke="rgba(0,212,255,0.04)"
                vertical={false}
              />

              <XAxis
                dataKey="t"
                type="number"
                domain={xDomain}
                tickCount={7}
                tickFormatter={(v: number) => `T+${v}s`}
                tick={{ fontSize: 9, fill: "#334155", fontFamily: '"IBM Plex Mono", monospace' }}
                axisLine={{ stroke: "rgba(0,212,255,0.06)" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                domain={yDomain}
                tick={{ fontSize: 9, fill: "#334155", fontFamily: '"IBM Plex Mono", monospace' }}
                axisLine={false}
                tickLine={false}
                width={32}
                label={{
                  value: "alerts/s",
                  angle: -90,
                  position: "insideLeft",
                  offset: 20,
                  style: { fontSize: 8, fill: "rgba(0,212,255,0.2)", fontFamily: '"IBM Plex Mono", monospace' },
                }}
              />

              <Tooltip content={<CustomTooltip />} />

              {/* Event markers — one line per engine type */}
              {eventMarkers.map((m) => (
                <ReferenceLine
                  key={m.engine}
                  x={m.t}
                  stroke={m.color}
                  strokeOpacity={0.5}
                  strokeWidth={1}
                  strokeDasharray="2 3"
                  label={{
                    value: `↑${m.label}`,
                    position: "top",
                    fontSize: 8,
                    fill: m.color,
                    fontFamily: '"IBM Plex Mono", monospace',
                    opacity: 0.8,
                  }}
                />
              ))}

              {/* Peak annotation */}
              {peakBucket && peakBucket.val > 0 && replayEnded && (
                <ReferenceLine
                  x={peakBucket.t}
                  stroke="rgba(255,59,59,0.2)"
                  strokeWidth={1}
                  strokeDasharray="1 4"
                  label={{
                    value: `PEAK ${peakBucket.val}/s`,
                    position: "insideTopRight",
                    fontSize: 8,
                    fill: "rgba(255,59,59,0.5)",
                    fontFamily: '"IBM Plex Mono", monospace',
                    offset: 4,
                  }}
                />
              )}

              {/* Replay cursor */}
              {cursorT !== null && (
                <ReferenceLine
                  x={cursorT}
                  stroke="rgba(0,212,255,0.5)"
                  strokeWidth={1.5}
                  label={{
                    value: "▶",
                    position: "top",
                    fontSize: 10,
                    fill: "rgba(0,212,255,0.7)",
                    fontFamily: '"IBM Plex Mono", monospace',
                  }}
                />
              )}

              <Area
                type="monotone"
                dataKey="community"
                stroke="#00d4ff"
                strokeWidth={1.5}
                fill="url(#fillCom2)"
                fillOpacity={1}
                dot={false}
                isAnimationActive={false}
                stackId="1"
              />
              <Area
                type="monotone"
                dataKey="xgboost"
                stroke="#ff3b3b"
                strokeWidth={1.5}
                fill="url(#fillXgb2)"
                fillOpacity={1}
                dot={false}
                isAnimationActive={false}
                stackId="1"
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Bottom stats strip — only after replay ends */}
      {replayEnded && hasData && (
        <div
          className="flex items-center justify-between px-5 py-2 border-t"
          style={{ borderColor: "rgba(16,185,129,0.1)", background: "rgba(16,185,129,0.03)" }}
        >
          <div className="flex items-center gap-4">
            <span className="section-label" style={{ color: "rgba(16,185,129,0.6)" }}>ANALYSIS COMPLETE</span>
            <span className="section-label" style={{ color: "rgba(0,212,255,0.3)" }}>·</span>
            <span className="section-label tabular-nums" style={{ color: "rgba(148,163,184,0.5)" }}>
              {metrics.xgboost.total.toLocaleString()} ML · {metrics.community.total.toLocaleString()} COMM
            </span>
          </div>
          {peakBucket && (
            <span className="section-label tabular-nums" style={{ color: "rgba(255,59,59,0.5)" }}>
              PEAK {peakBucket.val}/s @ T+{peakBucket.t}s
            </span>
          )}
        </div>
      )}
    </div>
  );
}
