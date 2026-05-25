"use client";
import { useEffect, useRef, useState } from "react";
import { AreaChart, Area, ResponsiveContainer, YAxis } from "recharts";
import type { Alert, AlertCounts, CoreEngine } from "@/lib/types";

type CumulPoint = { t: number; count: number };

type EngineState = {
  total: number;
  firstAlertAt: number | null;
  history: CumulPoint[];
};

const EMPTY_ENGINE = (): EngineState => ({ total: 0, firstAlertAt: null, history: [] });
const MAX_HISTORY = 300;

type Props = {
  alerts: Alert[];
  metrics: Record<CoreEngine, { total: number; alertsPerSec: number }>;
  replayStartedAt: number | null;
  firstAlertAtByEngine: Record<CoreEngine, number | null>;
  snortRunning: boolean;
  fileCounts: AlertCounts;
};

type VerdictProps = {
  xgbFirst: number | null;
  commFirst: number | null;
  replayStart: number | null;
  xgbTotal: number;
  commTotal: number;
  snortRunning: boolean;
};

function VerdictBar({ xgbFirst, commFirst, replayStart, xgbTotal, commTotal, snortRunning }: VerdictProps) {
  if (!replayStart && xgbTotal === 0 && commTotal === 0) {
    return (
      <div className="text-center py-3">
        <span className="section-label" style={{ color: "rgba(0,212,255,0.25)" }}>START REPLAY TO COMPARE</span>
      </div>
    );
  }
  if (xgbTotal === 0 && commTotal === 0) {
    return (
      <div className="text-center py-3">
        <span className="section-label animate-pulse" style={{ color: "rgba(0,212,255,0.4)" }}>AWAITING FIRST ALERTS…</span>
      </div>
    );
  }

  const xgbLatency = xgbFirst && replayStart ? xgbFirst - replayStart : null;
  const commLatency = commFirst && replayStart ? commFirst - replayStart : null;

  const fmtMs = (ms: number) => ms < 1000 ? `${ms}ms` : `${(ms / 1000).toFixed(2)}s`;

  if (commFirst === null || commTotal === 0) {
    return (
      <div className="space-y-1 text-center py-2">
        <div className="flex items-center justify-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#ff3b3b", boxShadow: "0 0 6px #ff3b3b" }} />
          <span className="section-label" style={{ color: "#ff3b3b" }}>ML ENSEMBLE WINNER</span>
        </div>
        <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.85)" }}>
          Detected{xgbLatency !== null ? ` in ${fmtMs(xgbLatency)}` : ""} — Community: no detection
        </p>
      </div>
    );
  }

  if (xgbLatency !== null && commLatency !== null) {
    if (commLatency <= xgbLatency) {
      const ratio = commLatency > 0 ? (xgbLatency / commLatency).toFixed(1) : "∞";
      return (
        <div className="space-y-1 text-center py-2">
          <div className="flex items-center justify-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full" style={{ background: "#00d4ff", boxShadow: "0 0 6px #00d4ff" }} />
            <span className="section-label" style={{ color: "#00d4ff" }}>COMMUNITY {ratio}× FASTER</span>
          </div>
        </div>
      );
    }
    const ratio = xgbLatency > 0 ? (commLatency / xgbLatency).toFixed(1) : "∞";
    return (
      <div className="space-y-1 text-center py-2">
        <div className="flex items-center justify-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full threat-active" style={{ background: "#ff3b3b" }} />
          <span className="section-label" style={{ color: "#ff3b3b" }}>ML ENSEMBLE {ratio}× FASTER</span>
        </div>
        <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.85)" }}>
          {fmtMs(xgbLatency)} vs Community {fmtMs(commLatency)}
        </p>
      </div>
    );
  }

  return (
    <div className="text-center py-3">
      <span className="section-label" style={{ color: "rgba(148,163,184,0.75)" }}>
        XGB: {xgbTotal} · COMM: {commTotal}
      </span>
    </div>
  );
}

function MiniChart({ history, color }: { history: CumulPoint[]; color: string }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => { setMounted(true); }, []);
  if (history.length < 2) {
    return <div className="h-16 flex items-center justify-center">
      <span className="section-label" style={{ color: "rgba(0,212,255,0.15)" }}>—</span>
    </div>;
  }
  return (
    <div className="h-16 w-full" style={{ opacity: 0.8 }}>
      {mounted && (
        <ResponsiveContainer width="100%" height={64}>
          <AreaChart data={history} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id={`grad-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                <stop offset="95%" stopColor={color} stopOpacity={0} />
              </linearGradient>
            </defs>
            <YAxis domain={[0, "auto"]} hide />
            <Area
              type="monotone"
              dataKey="count"
              stroke={color}
              strokeWidth={1}
              fill={`url(#grad-${color.replace("#", "")})`}
              dot={false}
              isAnimationActive={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

function fmtCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

function EngineSide({
  engine,
  state,
  replayStart,
  fileCount,
}: {
  engine: CoreEngine;
  state: EngineState;
  replayStart: number | null;
  fileCount: number;
}) {
  const isXgb = engine === "xgboost";
  const color = isXgb ? "#ff3b3b" : "#00d4ff";
  const border = isXgb ? "rgba(255,59,59,0.2)" : "rgba(0,212,255,0.15)";
  const bg = isXgb ? "rgba(255,59,59,0.03)" : "rgba(0,212,255,0.03)";

  const latencyMs =
    state.firstAlertAt !== null && replayStart !== null
      ? state.firstAlertAt - replayStart
      : null;

  const latencyStr = latencyMs === null
    ? (replayStart ? "WAIT…" : "—")
    : latencyMs < 1000
    ? `${latencyMs}ms`
    : `${(latencyMs / 1000).toFixed(2)}s`;

  return (
    <div className="flex-1 flex flex-col gap-2 p-3" style={{ border: `1px solid ${border}`, background: bg }}>
      {/* Engine label */}
      <div className="flex items-center gap-1.5">
        <div className="w-1.5 h-1.5" style={{ background: color, boxShadow: `0 0 4px ${color}` }} />
        <span className="section-label" style={{ color }}>{isXgb ? "ML ENSEMBLE" : "COMMUNITY"}</span>
      </div>

      {/* Alert count */}
      <div>
        <p className="display-num" style={{ fontSize: "2.2rem", lineHeight: 1, color, fontFamily: '"IBM Plex Mono", monospace', letterSpacing: "-0.02em" }}>
          {state.total.toLocaleString()}
        </p>
        <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.85)" }}>ALERTS STREAMED</p>
        {fileCount > 0 && (
          <p className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>
            {fmtCount(fileCount)} IN FILE
          </p>
        )}
      </div>

      {/* First detection */}
      <div>
        <p className="section-label mb-0.5" style={{ color: "rgba(148,163,184,0.75)" }}>FIRST DETECT</p>
        <p className="text-xs font-mono font-semibold" style={{ color: state.firstAlertAt ? color : "rgba(148,163,184,0.65)" }}>
          {latencyStr}
        </p>
        {isXgb && state.firstAlertAt && (
          <p className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>PKT 2 · max_packets=2</p>
        )}
      </div>

      {/* Mini chart */}
      <MiniChart history={state.history} color={color} />
    </div>
  );
}

export function ComparisonPanel({
  alerts,
  metrics,
  replayStartedAt,
  firstAlertAtByEngine,
  snortRunning,
  fileCounts,
}: Props) {
  const [engineStates, setEngineStates] = useState<Record<CoreEngine, EngineState>>({
    xgboost: EMPTY_ENGINE(),
    community: EMPTY_ENGINE(),
  });

  const pendingTotals = useRef<Record<CoreEngine, number>>({ xgboost: 0, community: 0 });
  const prevAlertCount = useRef(0);
  const prevRunning = useRef(false);

  useEffect(() => {
    if (snortRunning && !prevRunning.current) {
      setEngineStates({ xgboost: EMPTY_ENGINE(), community: EMPTY_ENGINE() });
      pendingTotals.current = { xgboost: 0, community: 0 };
      prevAlertCount.current = 0;
    }
    prevRunning.current = snortRunning;
  }, [snortRunning]);

  useEffect(() => {
    setEngineStates((prev) => {
      const next = { ...prev };
      for (const eng of ["xgboost", "community"] as CoreEngine[]) {
        const t = firstAlertAtByEngine[eng];
        if (t !== null && prev[eng].firstAlertAt === null) {
          next[eng] = { ...prev[eng], firstAlertAt: t };
        }
      }
      return next;
    });
  }, [firstAlertAtByEngine]);

  if (alerts.length !== prevAlertCount.current) {
    if (alerts.length < prevAlertCount.current) {
      pendingTotals.current = { xgboost: 0, community: 0 };
    } else {
      const newCount = alerts.length - prevAlertCount.current;
      const newAlerts = alerts.slice(0, newCount);
      for (const a of newAlerts) {
        const bucket: CoreEngine = a.engine === "community" ? "community" : "xgboost";
        pendingTotals.current[bucket] += 1;
      }
    }
    prevAlertCount.current = alerts.length;
  }

  useEffect(() => {
    const id = setInterval(() => {
      const now = Date.now();
      setEngineStates((prev) => {
        const next: Record<CoreEngine, EngineState> = { xgboost: prev.xgboost, community: prev.community };
        for (const eng of ["xgboost", "community"] as CoreEngine[]) {
          const total = metrics[eng].total;
          if (total === prev[eng].total) continue;
          const history = [...prev[eng].history, { t: now, count: total }].slice(-MAX_HISTORY);
          next[eng] = { ...prev[eng], total, history };
        }
        return next;
      });
    }, 250);
    return () => clearInterval(id);
  }, [metrics]);

  return (
    <div className="relative overflow-hidden" style={{ border: "1px solid rgba(0,212,255,0.1)", background: "#0f1318" }}>
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.6)", boxShadow: "0 0 6px rgba(0,212,255,0.6)" }} />
        <span className="section-label" style={{ color: "#00d4ff" }}>ENGINE COMPARISON</span>
      </div>

      <div className="p-3 space-y-3">
        {/* Split cards */}
        <div className="flex gap-2">
          <EngineSide engine="xgboost" state={engineStates.xgboost} replayStart={replayStartedAt} fileCount={fileCounts.xgboost_file_count} />
          <EngineSide engine="community" state={engineStates.community} replayStart={replayStartedAt} fileCount={fileCounts.community_file_count} />
        </div>

        {/* Hero stat */}
        <div className="flex items-center justify-center gap-3 py-3 border-t border-b" style={{ borderColor: "rgba(0,212,255,0.06)" }}>
          <span className="display-num" style={{ fontSize: "2rem", color: "#10b981", fontFamily: '"IBM Plex Mono", monospace', lineHeight: 1 }}>
            {Math.round(11.67 / 1.75)}×
          </span>
          <div>
            <p className="section-label" style={{ color: "#10b981" }}>FEWER FALSE ALARMS</p>
            <p className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.75)" }}>XGBoost vs Community Rules</p>
          </div>
        </div>

        {/* Verdict */}
        <VerdictBar
          xgbFirst={firstAlertAtByEngine.xgboost}
          commFirst={firstAlertAtByEngine.community}
          replayStart={replayStartedAt}
          xgbTotal={engineStates.xgboost.total}
          commTotal={engineStates.community.total}
          snortRunning={snortRunning}
        />
      </div>
    </div>
  );
}
