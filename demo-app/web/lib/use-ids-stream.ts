"use client";
import { useEffect, useRef, useState } from "react";
import useWebSocket, { ReadyState } from "react-use-websocket";
import type { WsMessage, Alert, Engine, AlertCounts } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";

export type EngineMetrics = {
  total: number;
  alertsPerSec: number;       // 10-second rolling window
};

export type IdsStreamState = {
  alerts: Alert[];
  connected: boolean;
  snortRunning: boolean;
  pcapProgress: number;       // 0..1
  error: string | null;
  replayStartedAt: number | null;       // Date.now() when snortRunning flipped true
  firstAlertAt: number | null;          // Date.now() of first xgboost alert this run
  firstAlertAtByEngine: Record<Engine, number | null>;  // per-engine first alert
  metrics: Record<Engine, EngineMetrics>;
  fileCounts: AlertCounts;              // file-based line counts from backend
  clearAlerts: () => void;
};

const WINDOW_MS = 10_000;

const emptyMetrics = (): Record<Engine, EngineMetrics> => ({
  xgboost: { total: 0, alertsPerSec: 0 },
  community: { total: 0, alertsPerSec: 0 },
});

export function useIdsStream(): IdsStreamState {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [snortRunning, setSnortRunning] = useState(false);
  const [pcapProgress, setPcapProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [replayStartedAt, setReplayStartedAt] = useState<number | null>(null);
  const [firstAlertAt, setFirstAlertAt] = useState<number | null>(null);
  const [firstAlertAtByEngine, setFirstAlertAtByEngine] = useState<Record<Engine, number | null>>({ xgboost: null, community: null });
  const [metrics, setMetrics] = useState<Record<Engine, EngineMetrics>>(emptyMetrics);
  const [fileCounts, setFileCounts] = useState<AlertCounts>({ xgboost_file_count: 0, community_file_count: 0 });

  // Rolling timestamp buffers for alerts/sec calculation
  const tsBuffers = useRef<Record<Engine, number[]>>({
    xgboost: [],
    community: [],
  });
  const totalCounts = useRef<Record<Engine, number>>({ xgboost: 0, community: 0 });
  const prevRunning = useRef(false);

  const { lastJsonMessage, readyState } = useWebSocket<WsMessage | null>(
    WS_URL,
    { shouldReconnect: () => true, reconnectInterval: 1500 }
  );

  useEffect(() => {
    if (!lastJsonMessage) return;
    const msg = lastJsonMessage as WsMessage;

    if (msg.type === "alert") {
      const now = Date.now();
      const engine = msg.data.engine;

      // Update alert list
      setAlerts((prev) => [msg.data, ...prev].slice(0, 1000));

      // Track first alert per engine (xgboost also feeds the latency card)
      if (engine === "xgboost") {
        setFirstAlertAt((prev) => prev ?? now);
      }
      setFirstAlertAtByEngine((prev) => prev[engine] !== null ? prev : { ...prev, [engine]: now });

      // Rolling window for alerts/sec
      const buf = tsBuffers.current[engine];
      buf.push(now);
      totalCounts.current[engine] += 1;

      // Prune entries older than 10s
      const cutoff = now - WINDOW_MS;
      while (buf.length > 0 && buf[0] < cutoff) buf.shift();

      const aps = buf.length / (WINDOW_MS / 1000);
      const total = totalCounts.current[engine];
      setMetrics((prev) => ({
        ...prev,
        [engine]: { total, alertsPerSec: aps },
      }));

    } else if (msg.type === "status") {
      const running = msg.data.snort_running;
      setPcapProgress(msg.data.pcap_progress ?? 0);
      setError(msg.data.error ?? null);
      setSnortRunning(running);

      // Reset per-run state when a new replay starts
      if (running && !prevRunning.current) {
        setReplayStartedAt(Date.now());
        setFirstAlertAt(null);
        setFirstAlertAtByEngine({ xgboost: null, community: null });
        setAlerts([]);
        setFileCounts({ xgboost_file_count: 0, community_file_count: 0 });
        tsBuffers.current = { xgboost: [], community: [] };
        totalCounts.current = { xgboost: 0, community: 0 };
        setMetrics(emptyMetrics());
      }
      prevRunning.current = running;
    } else if (msg.type === "alert_counts") {
      setFileCounts(msg.data);
    }
  }, [lastJsonMessage]);

  return {
    alerts,
    connected: readyState === ReadyState.OPEN,
    snortRunning,
    pcapProgress,
    error,
    replayStartedAt,
    firstAlertAt,
    firstAlertAtByEngine,
    metrics,
    fileCounts,
    clearAlerts: () => setAlerts([]),
  };
}
