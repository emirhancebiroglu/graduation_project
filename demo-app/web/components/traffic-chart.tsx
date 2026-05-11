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

const WINDOW_S = 60;
const TICK_MS = 250;
const TICK_COLOR = "#334155";

type Bucket = { t: number; xgboost: number; community: number };
type Props = { alerts: Alert[]; snortRunning: boolean; replayStartedAt: number | null };

function buildEmptyBuckets(): Bucket[] {
  return Array.from({ length: WINDOW_S }, (_, i) => ({ t: i - WINDOW_S + 1, xgboost: 0, community: 0 }));
}

export function TrafficChart({ alerts, snortRunning, replayStartedAt }: Props) {
  const [mounted, setMounted] = useState(false);
  const [buckets, setBuckets] = useState<Bucket[]>(buildEmptyBuckets);
  const [replayEnded, setReplayEnded] = useState(false);
  const [hasEverReplayed, setHasEverReplayed] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  const frozenBuckets = useRef<Bucket[] | null>(null);
  const replayEndedRef = useRef(false);
  const pending = useRef<Map<number, { xgboost: number; community: number }>>(new Map());
  const prevRunning = useRef(false);
  const prevLength = useRef(0);
  const replayStartSec = useRef<number | null>(null);

  useEffect(() => {
    if (snortRunning && !prevRunning.current) {
      replayStartSec.current = replayStartedAt
        ? Math.floor(replayStartedAt / 1000)
        : Math.floor(Date.now() / 1000);
      setBuckets(buildEmptyBuckets());
      frozenBuckets.current = null;
      replayEndedRef.current = false;
      setReplayEnded(false);
      setHasEverReplayed(true);
      pending.current = new Map();
      prevLength.current = 0;
    }
    if (!snortRunning && prevRunning.current) {
      replayStartSec.current = null;
      replayEndedRef.current = true;
      setReplayEnded(true);
    }
    prevRunning.current = snortRunning;
  }, [snortRunning, replayStartedAt]);

  if (alerts.length !== prevLength.current) {
    if (alerts.length < prevLength.current) {
      pending.current = new Map();
      prevLength.current = alerts.length;
    } else {
      const added = alerts.length - prevLength.current;
      const newAlerts = alerts.slice(0, added);
      prevLength.current = alerts.length;
      const nowSec = Math.floor(Date.now() / 1000);
      for (const a of newAlerts) {
        if (!pending.current.has(nowSec)) pending.current.set(nowSec, { xgboost: 0, community: 0 });
        const bucket = pending.current.get(nowSec)!;
        if (a.engine === "xgboost") bucket.xgboost += 1;
        else if (a.engine === "community") bucket.community += 1;
      }
    }
  }

  useEffect(() => {
    const id = setInterval(() => {
      if (frozenBuckets.current !== null) { setBuckets(frozenBuckets.current); return; }
      const nowSec = Math.floor(Date.now() / 1000);
      const cutoff = nowSec - WINDOW_S;
      for (const k of pending.current.keys()) { if (k <= cutoff) pending.current.delete(k); }
      const next: Bucket[] = Array.from({ length: WINDOW_S }, (_, i) => {
        const sec = nowSec - (WINDOW_S - 1 - i);
        const counts = pending.current.get(sec) ?? { xgboost: 0, community: 0 };
        return { t: sec - nowSec, xgboost: counts.xgboost, community: counts.community };
      });
      if (replayEndedRef.current && next.some((b) => b.xgboost > 0 || b.community > 0)) {
        frozenBuckets.current = next;
      }
      setBuckets(next);
    }, TICK_MS);
    return () => clearInterval(id);
  }, []);

  const replayRefT =
    replayStartSec.current !== null
      ? replayStartSec.current - Math.floor(Date.now() / 1000)
      : null;

  const hasData = buckets.some((b) => b.xgboost > 0 || b.community > 0);
  const maxVal = Math.max(...buckets.map((b) => Math.max(b.xgboost, b.community)));
  const yDomain: [number, number | string] = maxVal < 2 ? [0, 3] : [0, "auto"];
  const showWaiting = !hasData && !hasEverReplayed;

  return (
    <div className="relative p-0 overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="flex items-center gap-3">
          <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
          <span className="section-label" style={{ color: "#00d4ff" }}>ALERT RATE — 60s ROLLING WINDOW</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <div className="w-6 h-px" style={{ background: "#ff3b3b" }} />
            <span className="section-label" style={{ color: "rgba(255,59,59,0.7)" }}>XGBOOST</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="w-6 h-px" style={{ background: "#00d4ff" }} />
            <span className="section-label" style={{ color: "rgba(0,212,255,0.7)" }}>COMMUNITY</span>
          </div>
          {replayEnded && (
            <span className="section-label italic" style={{ color: "rgba(100,116,139,0.5)" }}>REPLAY ENDED</span>
          )}
        </div>
      </div>

      {/* Chart */}
      <div className="w-full relative px-2 pb-2 pt-3" style={{ height: 200 }}>
        {showWaiting && (
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="section-label" style={{ color: "rgba(0,212,255,0.25)" }}>AWAITING TRAFFIC DATA…</span>
          </div>
        )}
        {mounted && (
          <ResponsiveContainer width="100%" height={180}>
            <ComposedChart data={buckets} margin={{ top: 4, right: 16, left: -16, bottom: 0 }}>
              <defs>
                <linearGradient id="fillXgb" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ff3b3b" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#ff3b3b" stopOpacity={0.02} />
                </linearGradient>
                <linearGradient id="fillCom" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.02} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="1 4" stroke="rgba(0,212,255,0.05)" vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                domain={[-(WINDOW_S - 1), 0]}
                tickCount={7}
                tickFormatter={(v: number) => (v === 0 ? "NOW" : `-${Math.abs(v)}s`)}
                tick={{ fontSize: 9, fill: TICK_COLOR, fontFamily: '"IBM Plex Mono", monospace' }}
                axisLine={{ stroke: "rgba(0,212,255,0.08)" }}
                tickLine={false}
              />
              <YAxis
                allowDecimals={false}
                domain={yDomain}
                tick={{ fontSize: 9, fill: TICK_COLOR, fontFamily: '"IBM Plex Mono", monospace' }}
                axisLine={false}
                tickLine={false}
                width={32}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#0f1318",
                  border: "1px solid rgba(0,212,255,0.2)",
                  borderRadius: "2px",
                  fontSize: "10px",
                  color: "#e2e8f0",
                  fontFamily: '"IBM Plex Mono", monospace',
                  boxShadow: "0 0 20px rgba(0,212,255,0.1)",
                }}
                labelFormatter={(v) => {
                  const n = v as number;
                  return n === 0 ? "NOW" : `${n}s`;
                }}
                formatter={(value, name) => [
                  value as number,
                  (name as string) === "xgboost" ? "XGBoost" : "Community",
                ]}
              />
              {replayRefT !== null && replayRefT >= -(WINDOW_S - 1) && (
                <ReferenceLine
                  x={replayRefT}
                  stroke="rgba(0,212,255,0.3)"
                  strokeDasharray="2 4"
                  strokeWidth={1}
                  label={{
                    value: "REPLAY",
                    position: "insideTopRight",
                    fontSize: 8,
                    fill: "rgba(0,212,255,0.4)",
                    offset: 4,
                    fontFamily: '"IBM Plex Mono", monospace',
                  }}
                />
              )}
              <Area
                type="monotone"
                dataKey="xgboost"
                stroke="#ff3b3b"
                strokeWidth={1.5}
                fill="url(#fillXgb)"
                fillOpacity={1}
                dot={false}
                isAnimationActive={false}
                name="xgboost"
              />
              <Area
                type="monotone"
                dataKey="community"
                stroke="#00d4ff"
                strokeWidth={1.5}
                fill="url(#fillCom)"
                fillOpacity={1}
                dot={false}
                isAnimationActive={false}
                name="community"
              />
            </ComposedChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
