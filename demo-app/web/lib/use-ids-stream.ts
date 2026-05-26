"use client";
import { useEffect, useRef, useState, useCallback } from "react";
import type { WsMessage, Alert, EvaluationResult, Engine, CoreEngine, ReplayPhase } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";
const MAX_RECENT_ALERTS = 20;
const MAX_FEED_ALERTS = 500;
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
    xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [],
  });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const flushTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRunning = useRef(false);
  const replayPhaseRef = useRef<ReplayPhase>("idle");
  const recentAlertsRef = useRef<Alert[]>([]);
  const alertsRef = useRef<Alert[]>([]);
  const engineAlertsRef = useRef<Record<Engine, Alert[]>>({
    xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [],
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
      engineAlertsRef.current = { xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [] };
      setEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [] });
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
      engineAlertsRef.current = { xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [] };
      setEngineAlerts({ xgboost: [], community: [], portscan: [], dos_agg: [], bot: [], bruteforce: [] });
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
            // Don't append if in draining/complete phase — feed is frozen
            if (replayPhaseRef.current === "draining" || replayPhaseRef.current === "complete") {
              // Still process for backend enrichment but don't update feed
              return;
            }
            // Use the actual engine as bucket key
            const bucket: Engine = alert.engine;

            alertsRef.current = [alert, ...alertsRef.current].slice(0, MAX_FEED_ALERTS);
            engineAlertsRef.current = {
              ...engineAlertsRef.current,
              [bucket]: [alert, ...engineAlertsRef.current[bucket]].slice(0, MAX_FEED_ALERTS),
            };
            if (bucket !== "community") {
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
  };
}