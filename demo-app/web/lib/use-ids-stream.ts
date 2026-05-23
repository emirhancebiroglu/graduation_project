"use client";
import { useEffect, useRef, useState, useCallback } from "react";
import type { WsMessage, Alert, EvaluationResult } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";
const MAX_RECENT_ALERTS = 20;
const MAX_FEED_ALERTS = 500;

export type ReplayPhase = "idle" | "running" | "evaluating" | "complete";
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
  engineAlerts: Record<"xgboost" | "community", Alert[]>;
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
  const [engineAlerts, setEngineAlerts] = useState<Record<"xgboost" | "community", Alert[]>>({ xgboost: [], community: [] });

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRunning = useRef(false);
  const recentAlertsRef = useRef<Alert[]>([]);
  const alertsRef = useRef<Alert[]>([]);
  const engineAlertsRef = useRef<Record<"xgboost" | "community", Alert[]>>({ xgboost: [], community: [] });

  const handleStatus = useCallback((running: boolean, progress: number, err: string | null | undefined) => {
    setSnortRunning(running);
    setPcapProgress(progress);
    setError(err ?? null);

    if (running && !prevRunning.current) {
      setReplayPhase("running");
      setPcapProgressVisible(true);
      setEvaluation(null);
      recentAlertsRef.current = [];
      setRecentAlerts([]);
      alertsRef.current = [];
      setAlerts([]);
      engineAlertsRef.current = { xgboost: [], community: [] };
      setEngineAlerts({ xgboost: [], community: [] });
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
              msg.data.error
            );
          } else if (msg.type === "evaluation") {
            handleEvaluation(msg.data);
          } else if (msg.type === "alert") {
            const alert = msg.data as Alert;
            const eng = msg.engine as "xgboost" | "community";

            // Feed (all engines, newest-first, capped)
            alertsRef.current = [alert, ...alertsRef.current].slice(0, MAX_FEED_ALERTS);
            setAlerts([...alertsRef.current]);

            engineAlertsRef.current = {
              ...engineAlertsRef.current,
              [eng]: [alert, ...engineAlertsRef.current[eng]].slice(0, MAX_FEED_ALERTS),
            };
            setEngineAlerts({ ...engineAlertsRef.current });

            // Recent alerts for ImpactSummary terminal (XGB only)
            if (eng === "xgboost") {
              recentAlertsRef.current = [
                ...recentAlertsRef.current,
                alert,
              ].slice(-MAX_RECENT_ALERTS);
              setRecentAlerts([...recentAlertsRef.current]);
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
      wsRef.current?.close();
    };
  }, [connect]);

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
  };
}