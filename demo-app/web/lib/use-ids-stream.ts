"use client";
import { useEffect, useRef, useState, useCallback } from "react";
import type { WsMessage, Alert, EvaluationResult, Engine, CoreEngine, ReplayPhase } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";
const MAX_RECENT_ALERTS = 20;
const MAX_FEED_ALERTS = 500;       // cap for community alerts
const MAX_ML_FEED_ALERTS = 2000;   // cap for ML engine alerts (never crowded out by community)
const FLUSH_INTERVAL_MS = 150; // batch setState at most ~6x/sec

export type EngineMetrics = { total: number; alertsPerSec: number };

export type IdsStreamState = {
  connected: boolean;
  snortRunning: boolean;
  pcapProgress: number;
  error: string | null;
  pcapProgressVisible: boolean;
  replayPhase: ReplayPhase;
  evaluation: EvaluationResult | null;
  recentAlerts: Alert[];
  alerts: Alert[];
  engineAlerts: Record<Engine, Alert[]>;
  markStarted: () => void;
  resetToIdle: () => void;
};

export function useIdsStream(): IdsStreamState {
  const [connected, setConnected] = useState(false);
  const [snortRunning, setSnortRunning] = useState(false);
  const [pcapProgress, setPcapProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [replayPhase, setReplayPhase] = useState<ReplayPhase>("idle");
  const [evaluation, setEvaluation] = useState<EvaluationResult | null>(null);
  const [pcapProgressVisible, setPcapProgressVisible] = useState(false);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [engineAlerts, setEngineAlerts] = useState<Record<Engine, Alert[]>>({
    xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [],
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRunning = useRef(false);
  const replayPhaseRef = useRef<ReplayPhase>("idle");
  const recentAlertsRef = useRef<Alert[]>([]);
  const alertsRef = useRef<Alert[]>([]);
  const engineAlertsRef = useRef<Record<Engine, Alert[]>>({
    xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [],
  });
  const pendingFlush = useRef(false);
  // True only after user clicks start in this browser session
  const sessionStartedRef = useRef(false);

  const handleStatus = useCallback((running: boolean, progress: number, err: string | null | undefined, phase?: ReplayPhase) => {
    // Ignore leftover backend state from before page load
    if (!sessionStartedRef.current && (phase === "draining" || phase === "running" || running)) {
      return;
    }

    setSnortRunning(running);
    setPcapProgress(progress);
    setError(err ?? null);

    if (phase === "draining") {
      replayPhaseRef.current = "draining";
      setReplayPhase("draining");
      setPcapProgress(1.0);
      prevRunning.current = running;
      return;
    }

    if (phase === "complete" && replayPhaseRef.current !== "idle") {
      replayPhaseRef.current = "complete";
      setReplayPhase("complete");
      setPcapProgressVisible(false);
      setSnortRunning(false);
      prevRunning.current = false;
      return;
    }

    // Stop pressed mid-replay or mid-draining — reset to idle
    if (!running && !phase && replayPhaseRef.current !== "idle" && replayPhaseRef.current !== "complete") {
      replayPhaseRef.current = "idle";
      setReplayPhase("idle");
      setPcapProgress(0);
      setPcapProgressVisible(false);
      setSnortRunning(false);
      setEvaluation(null);
      alertsRef.current = [];
      setAlerts([]);
      engineAlertsRef.current = { xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] };
      setEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] });
      recentAlertsRef.current = [];
      setRecentAlerts([]);
      prevRunning.current = false;
      return;
    }

    if (running && !prevRunning.current) {
      replayPhaseRef.current = "running";
      setReplayPhase("running");
      setPcapProgressVisible(true);
      setEvaluation(null);
      recentAlertsRef.current = [];
      setRecentAlerts([]);
      alertsRef.current = [];
      setAlerts([]);
      engineAlertsRef.current = { xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] };
      setEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] });
    } else if (!running && prevRunning.current) {
      setPcapProgressVisible(false);
    }
    prevRunning.current = running;
  }, []);

  const handleEvaluation = useCallback((data: EvaluationResult) => {
    setEvaluation(data);
    setReplayPhase("complete");
    setSnortRunning(false);
    setPcapProgressVisible(false);
    recentAlertsRef.current = [];
    setRecentAlerts([]);
    // keep alerts/engineAlerts for review after replay completes
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        if (reconnectTimer.current) {
          clearTimeout(reconnectTimer.current);
          reconnectTimer.current = null;
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data as string) as WsMessage;

          if (msg.type === "status") {
            handleStatus(
              msg.data.snort_running,
              msg.data.pcap_progress ?? 0,
              msg.data.error,
              msg.data.phase
            );
          } else if (msg.type === "evaluation") {
            handleEvaluation(msg.data);
          } else if (msg.type === "alert") {
            const alert = msg.data as Alert;
            if (alert.engine !== "community") console.log("[aegis-debug] alert", alert.engine, alert.src_ip, "score=", alert.score);
            const frozen = replayPhaseRef.current === "draining" || replayPhaseRef.current === "complete";
            // During draining/complete: still ingest ML alerts (window-level engines may broadcast
            // during the drain window, after snort exits). Drop community noise when frozen.
            if (frozen && alert.engine === "community") return;
            const bucket: Engine = alert.engine;

            // ML alerts use a higher cap so community flood can't evict them from the merged feed.
            const cap = bucket === "community" ? MAX_FEED_ALERTS : MAX_ML_FEED_ALERTS;
            engineAlertsRef.current = {
              ...engineAlertsRef.current,
              [bucket]: [alert, ...engineAlertsRef.current[bucket]].slice(0, cap),
            };
            // Rebuild merged alerts: ML engines first (sorted newest-first), then community.
            // Only re-sort when an ML alert arrives — community just prepends to its own bucket.
            if (bucket !== "community") {
              const mlEntries = (Object.entries(engineAlertsRef.current) as [Engine, Alert[]][])
                .filter(([e]) => e !== "community")
                .flatMap(([, arr]) => arr)
                .sort((a, b) => b.ts.localeCompare(a.ts));
              alertsRef.current = [...mlEntries, ...engineAlertsRef.current.community];
            } else {
              // Community prepended to front of community bucket; just update the tail of merged array.
              alertsRef.current = [
                ...alertsRef.current.filter((a) => a.engine !== "community"),
                ...engineAlertsRef.current.community,
              ];
            }
            if (bucket !== "community" && !frozen) {
              recentAlertsRef.current = [alert, ...recentAlertsRef.current].slice(0, MAX_RECENT_ALERTS);
            }

            // Schedule a single batched flush
            if (!pendingFlush.current) {
              pendingFlush.current = true;
              flushTimer.current = setTimeout(() => {
                setAlerts([...alertsRef.current]);
                setEngineAlerts({ ...engineAlertsRef.current });
                setRecentAlerts([...recentAlertsRef.current]);
                pendingFlush.current = false;
              }, FLUSH_INTERVAL_MS);
            }
          } else if (msg.type === "alerts_updated") {
            console.log("[aegis-debug] alerts_updated received, count=", (msg.data as Alert[]).length);
            // Retroactive score patch for window-level alerts (sent after Snort exits)
            const updated = msg.data as Alert[];
            updated.forEach((upd: Alert) => {
              const patch = { score: upd.score, if_score: upd.if_score, if_label: upd.if_label };
              const bucket: Engine = upd.engine;
              const bidx = engineAlertsRef.current[bucket]?.findIndex((a) => a.id === upd.id) ?? -1;
              if (bidx !== -1) engineAlertsRef.current[bucket][bidx] = { ...engineAlertsRef.current[bucket][bidx], ...patch };
            });
            // Rebuild merged alerts after patch
            const mlEntries = (Object.entries(engineAlertsRef.current) as [Engine, Alert[]][])
              .filter(([e]) => e !== "community")
              .flatMap(([, arr]) => arr)
              .sort((a, b) => b.ts.localeCompare(a.ts));
            alertsRef.current = [...mlEntries, ...engineAlertsRef.current.community];
            setAlerts([...alertsRef.current]);
            setEngineAlerts({ ...engineAlertsRef.current });
          }
        } catch (e) {
          console.error("Failed to parse WS message:", e);
        }
      };

      ws.onerror = () => {};
      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        reconnectTimer.current = setTimeout(() => connect(), 1500);
      };
    } catch (e) {
      reconnectTimer.current = setTimeout(() => connect(), 1500);
    }
  }, [handleStatus, handleEvaluation]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      if (flushTimer.current) clearTimeout(flushTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  const markStarted = useCallback(() => { sessionStartedRef.current = true; }, []);

  const resetToIdle = useCallback(() => {
    replayPhaseRef.current = "idle";
    setReplayPhase("idle");
    setPcapProgress(0);
    setPcapProgressVisible(false);
    setSnortRunning(false);
    setEvaluation(null);
    alertsRef.current = [];
    setAlerts([]);
    engineAlertsRef.current = { xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] };
    setEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], ddos: [], bot: [], bruteforce: [] });
    recentAlertsRef.current = [];
    setRecentAlerts([]);
    prevRunning.current = false;
  }, []);

  return {
    connected,
    snortRunning,
    pcapProgress,
    error,
    pcapProgressVisible,
    replayPhase,
    evaluation,
    recentAlerts,
    alerts,
    engineAlerts,
    markStarted,
    resetToIdle,
  };
}