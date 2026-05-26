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
import { useT } from "@/lib/i18n";

const WINDOW_S = 90;
const TICK_MS = 250;

const ALL_ENGINES: string[] = ["community", "xgboost", "portscan", "dos_agg", "bot", "bruteforce"];

type Bucket = {
  t: number;
  community: number;
  xgboost: number;
  portscan: number;
  dos_agg: number;
  bot: number;
  bruteforce: number;
  total: number;
};

type EventMarker = { t: number; label: string; color: string; engine: string };

type Props = {
  metrics: Record<string, EngineMetrics>;
  snortRunning: boolean;
  replayStartedAt: number | null;
  pcapProgress: number;
  alerts: Alert[];
};

const ENGINE_COLORS: Record<string, string> = {
  community:  "#00d4ff",
  xgboost:    "#ff3b3b",
  portscan:   "#a855f7",
  dos_agg:    "#f97316",
  bot:        "#3b82f6",
  bruteforce: "#eab308",
};

const ENGINE_LABELS: Record<string, string> = {
  xgboost:    "DoS",
  portscan:   "Scan",
  dos_agg:    "DDoS",
  bot:        "Bot",
  bruteforce: "BruteF",
  community:  "Comm",
};

const STACK_ORDER = ["community", "xgboost", "portscan", "dos_agg", "bot", "bruteforce"];

function buildEmptyBuckets(): Bucket[] {
  return Array.from({ length: WINDOW_S }, (_, i) => ({
    t: i,
    community: 0, xgboost: 0, portscan: 0, dos_agg: 0, bot: 0, bruteforce: 0, total: 0,
  }));
}

function emptyCounts(): Record<string, number> {
  return { community: 0, xgboost: 0, portscan: 0, dos_agg: 0, bot: 0, bruteforce: 0 };
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
  const { t: tr } = useT();
  if (!active || !payload?.length) return null;
  const t = typeof label === "number" ? label : 0;
  const tLabel = t >= 0 ? `T+${t}s` : `T${t}s`;

  const entries = payload
    .filter((p) => p.value > 0)
    .sort((a, b) => b.value - a.value);

  if (entries.length === 0) return null;

  const total = entries.reduce((s, p) => s + p.value, 0);

  return (
    <div style={{
      background: "rgba(15,19,24,0.97)",
      border: "1px solid rgba(0,212,255,0.2)",
      padding: "8px 12px",
      fontFamily: '"IBM Plex Mono", monospace',
      fontSize: "10px",
      boxShadow: "0 0 20px rgba(0,212,255,0.1)",
      minWidth: 160,
    }}>
      <div style={{ color: "rgba(0,212,255,0.6)", marginBottom: 4, fontSize: 9 }}>{tLabel}</div>
      {entries.map((p) => {
        const engLabel = ENGINE_LABELS[p.dataKey] ?? p.dataKey;
        return (
          <div key={p.dataKey} style={{ color: p.color, display: "flex", justifyContent: "space-between", gap: 16 }}>
            <span>{engLabel}</span><span>{p.value}/s</span>
          </div>
        );
      })}
      <div style={{ color: "rgba(148,163,184,0.6)", borderTop: "1px solid rgba(0,212,255,0.08)", marginTop: 4, paddingTop: 4, display: "flex", justifyContent: "space-between", gap: 16 }}>
        <span>{tr("chart.tooltipTotal")}</span><span>{total}/s</span>
      </div>
    </div>
  );
}

export function TrafficChart({ metrics, snortRunning, replayStartedAt, pcapProgress, alerts }: Props) {
  const { t: tr } = useT();
  const [mounted, setMounted] = useState(false);
  const [buckets, setBuckets] = useState<Bucket[]>(buildEmptyBuckets);
  const [eventMarkers, setEventMarkers] = useState<EventMarker[]>([]);
  const [peakBucket, setPeakBucket] = useState<{ t: number; val: number } | null>(null);
  const [replayEnded, setReplayEnded] = useState(false);
  const [hasEverReplayed, setHasEverReplayed] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [windowOffset, setWindowOffset] = useState(0);

  useEffect(() => { setMounted(true); }, []);

  const frozenBuckets = useRef<Bucket[] | null>(null);
  const replayEndedRef = useRef(false);
  const pending = useRef<Map<number, Record<string, number>>>(new Map());
  const prevRunning = useRef(false);
  const replayStartSec = useRef<number | null>(null);
  const replayStartMs = useRef<number | null>(null);
  const seenEngines = useRef<Set<string>>(new Set());
  const eventMarkersRef = useRef<EventMarker[]>([]);
  const processedAlertIds = useRef<Set<string>>(new Set());

  useEffect(() => {
    if (snortRunning && !prevRunning.current) {
      const nowMs = Date.now();
      replayStartMs.current = replayStartedAt ?? nowMs;
      replayStartSec.current = Math.floor((replayStartedAt ?? nowMs) / 1000);
      setBuckets(buildEmptyBuckets());
      frozenBuckets.current = null;
      replayEndedRef.current = false;
      setReplayEnded(false);
      setHasEverReplayed(true);
      setEventMarkers([]);
      setPeakBucket(null);
      setElapsedSec(0);
      setWindowOffset(0);
      pending.current = new Map();
      seenEngines.current = new Set();
      eventMarkersRef.current = [];
      processedAlertIds.current = new Set();
    }
    if (!snortRunning && prevRunning.current) {
      replayEndedRef.current = true;
      setReplayEnded(true);
    }
    prevRunning.current = snortRunning;
  }, [snortRunning, replayStartedAt]);

  useEffect(() => {
    if (!replayStartMs.current) return;
    for (const alert of alerts) {
      if (processedAlertIds.current.has(alert.id)) continue;
      processedAlertIds.current.add(alert.id);

      const eng = alert.engine;
      const alertMs = new Date(alert.ts).getTime();
      const tSec = Math.round((alertMs - replayStartMs.current) / 1000);

      if (!seenEngines.current.has(eng)) {
        seenEngines.current.add(eng);
        const marker: EventMarker = {
          t: tSec,
          label: ENGINE_LABELS[eng] ?? eng.toUpperCase().slice(0, 5),
          color: ENGINE_COLORS[eng] ?? "#94a3b8",
          engine: eng,
        };
        eventMarkersRef.current = [...eventMarkersRef.current, marker];
        setEventMarkers([...eventMarkersRef.current]);
      }

      if (tSec >= 0) {
        const absKey = (replayStartSec.current ?? 0) + tSec;
        if (!pending.current.has(absKey)) pending.current.set(absKey, emptyCounts());
        const b = pending.current.get(absKey)!;
        b[eng] = (b[eng] ?? 0) + 1;
      }
    }
  }, [alerts]);

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

      const sliding = elapsed >= WINDOW_S;
      const winStart = sliding ? startSec + elapsed - WINDOW_S + 1 : startSec;
      const winOffset = sliding ? elapsed - WINDOW_S + 1 : 0;
      setWindowOffset(winOffset);

      const cutoff = winStart - WINDOW_S * 2;
      for (const k of pending.current.keys()) { if (k < cutoff) pending.current.delete(k); }

      const next: Bucket[] = Array.from({ length: WINDOW_S }, (_, i) => {
        const sec = winStart + i;
        const counts = pending.current.get(sec) ?? emptyCounts();
        let total = 0;
        const bucket: Bucket = { t: i, community: 0, xgboost: 0, portscan: 0, dos_agg: 0, bot: 0, bruteforce: 0, total: 0 };
        for (const eng of ALL_ENGINES) {
          bucket[eng as keyof Bucket] = counts[eng] ?? 0;
          total += counts[eng] ?? 0;
        }
        bucket.total = total;
        return bucket;
      });

      let peak = { t: 0, val: 0 };
      for (const bk of next) {
        if (bk.total > peak.val) peak = { t: bk.t, val: bk.total };
      }
      if (peak.val > 0) setPeakBucket(peak);

      if (replayEndedRef.current && next.some((bk) => bk.total > 0)) {
        frozenBuckets.current = next;
      }
      setBuckets(next);
    }, TICK_MS);
    return () => clearInterval(id);
  }, []);

  const hasData = buckets.some((b) => b.total > 0);
  const maxVal = Math.max(...buckets.map((b) => b.total), 1);
  const yDomain: [number, number] = maxVal < 5 ? [0, 5] : [0, Math.ceil(maxVal * 1.15)];
  const showWaiting = !hasData && !hasEverReplayed;
  const xDomain: [number, number] = [0, WINDOW_S - 1];

  const cursorT = snortRunning
    ? (elapsedSec < WINDOW_S ? elapsedSec : WINDOW_S - 1)
    : null;

  const visibleMarkers = eventMarkers.filter((m) => {
    return m.t >= windowOffset && m.t < windowOffset + WINDOW_S;
  });

  const isLive = snortRunning && elapsedSec >= WINDOW_S;

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="flex items-center gap-3">
          <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
          <span className="section-label" style={{ color: "#00d4ff" }}>{tr("chart.title")}</span>
          {snortRunning && (
            <span className="section-label tabular-nums" style={{ color: "rgba(0,212,255,0.4)" }}>
              T+{elapsedSec}s
            </span>
          )}
          {isLive && (
            <div className="flex items-center gap-1 px-1.5 py-0.5" style={{ border: "1px solid rgba(255,59,59,0.2)", background: "rgba(255,59,59,0.05)" }}>
              <span className="w-1 h-1 rounded-full" style={{ background: "#ff3b3b", animation: "pulse 1s infinite" }} />
              <span className="section-label" style={{ color: "#ff3b3b", fontSize: "0.55rem" }}>LIVE</span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-5 h-px" style={{ background: "#ff3b3b", boxShadow: "0 0 4px #ff3b3b" }} />
            <span className="section-label" style={{ color: "rgba(255,59,59,0.7)" }}>{tr("chart.mlEnsemble")}</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-5 h-px" style={{ background: "#00d4ff" }} />
            <span className="section-label" style={{ color: "rgba(0,212,255,0.7)" }}>{tr("chart.community")}</span>
          </div>
          {replayEnded && (
            <div className="flex items-center gap-1.5 px-2 py-0.5" style={{ border: "1px solid rgba(16,185,129,0.2)", background: "rgba(16,185,129,0.05)" }}>
              <span className="w-1 h-1 rounded-full" style={{ background: "#10b981" }} />
              <span className="section-label" style={{ color: "#10b981" }}>{tr("chart.complete")}</span>
            </div>
          )}
        </div>
      </div>

      {eventMarkers.length > 0 && (
        <div className="flex items-center gap-3 px-5 py-1.5 border-b" style={{ borderColor: "rgba(0,212,255,0.04)", background: "rgba(0,0,0,0.2)" }}>
          <span className="section-label" style={{ color: "rgba(0,212,255,0.3)", fontSize: "0.6rem" }}>{tr("chart.detectedTypes")}</span>
          {eventMarkers.map((m) => {
            const inView = m.t >= windowOffset && m.t < windowOffset + WINDOW_S;
            return (
              <div key={m.engine} className="flex items-center gap-1" style={{ opacity: inView ? 1 : 0.25 }}>
                <div className="w-1.5 h-1.5" style={{ background: m.color, boxShadow: `0 0 4px ${m.color}` }} />
                <span className="section-label" style={{ color: m.color, fontSize: "0.6rem" }}>{tr(`chart.engineLabels.${m.label}`) || m.label}</span>
              </div>
            );
          })}
        </div>
      )}

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
            <span className="section-label" style={{ color: "rgba(0,212,255,0.25)" }}>{tr("chart.awaiting")}</span>
            <style>{`@keyframes barPulse { from { opacity: 0.15 } to { opacity: 0.5 } }`}</style>
          </div>
        )}

        {mounted && (
          <ResponsiveContainer width="100%" height={180}>
            <ComposedChart data={buckets} margin={{ top: 8, right: 16, left: -16, bottom: 0 }}>
              <defs>
                {STACK_ORDER.map((eng) => (
                  <linearGradient key={eng} id={`fill_${eng}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={ENGINE_COLORS[eng]} stopOpacity={0.55} />
                    <stop offset="100%" stopColor={ENGINE_COLORS[eng]} stopOpacity={0.05} />
                  </linearGradient>
                ))}
              </defs>

              <CartesianGrid strokeDasharray="1 6" stroke="rgba(0,212,255,0.04)" vertical={false} />

              <XAxis
                dataKey="t"
                type="number"
                domain={xDomain}
                tickCount={7}
                tickFormatter={(v: number) => `T+${v + windowOffset}s`}
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
                  value: tr("chart.alertsPerSec"),
                  angle: -90,
                  position: "insideLeft",
                  offset: 20,
                  style: { fontSize: 8, fill: "rgba(0,212,255,0.2)", fontFamily: '"IBM Plex Mono", monospace' },
                }}
              />

              <Tooltip content={<CustomTooltip />} />

              {visibleMarkers.map((m) => (
                <ReferenceLine
                  key={m.engine}
                  x={m.t - windowOffset}
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

              {peakBucket && peakBucket.val > 0 && replayEnded && (
                <ReferenceLine
                  x={peakBucket.t}
                  stroke="rgba(255,59,59,0.2)"
                  strokeWidth={1}
                  strokeDasharray="1 4"
                  label={{
                    value: `${tr("chart.peak")} ${peakBucket.val}/s`,
                    position: "insideTopRight",
                    fontSize: 8,
                    fill: "rgba(255,59,59,0.5)",
                    fontFamily: '"IBM Plex Mono", monospace',
                    offset: 4,
                  }}
                />
              )}

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

              {STACK_ORDER.map((eng) => (
                <Area
                  key={eng}
                  type="monotone"
                  dataKey={eng}
                  stroke={ENGINE_COLORS[eng]}
                  strokeWidth={1.5}
                  fill={`url(#fill_${eng})`}
                  fillOpacity={1}
                  dot={false}
                  isAnimationActive={false}
                  stackId="default"
                />
              ))}
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>

      {replayEnded && hasData && (
        <div
          className="flex items-center justify-between px-5 py-2 border-t"
          style={{ borderColor: "rgba(16,185,129,0.1)", background: "rgba(16,185,129,0.03)" }}
        >
          <div className="flex items-center gap-4">
            <span className="section-label" style={{ color: "rgba(16,185,129,0.6)" }}>{tr("chart.analysisComplete")}</span>
            <span className="section-label" style={{ color: "rgba(0,212,255,0.3)" }}>·</span>
            <span className="section-label tabular-nums" style={{ color: "rgba(148,163,184,0.5)" }}>
              {Object.entries(metrics)
                .filter(([k]) => k !== "community")
                .reduce((s, [, m]) => s + m.total, 0)
                .toLocaleString()} ML · {metrics.community?.total.toLocaleString() ?? 0} {tr("evaluation.comm")}
            </span>
          </div>
          {peakBucket && (
            <span className="section-label tabular-nums" style={{ color: "rgba(255,59,59,0.5)" }}>
              {tr("chart.peak")} {peakBucket.val}/s @ T+{peakBucket.t + windowOffset}s
            </span>
          )}
        </div>
      )}
    </div>
  );
}
