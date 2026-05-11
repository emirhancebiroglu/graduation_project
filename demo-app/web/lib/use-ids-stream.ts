"use client";
import { useEffect, useRef, useState, useCallback } from "react";
import type { WsMessage, AlertCounts, EvaluationResult } from "./types";

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws";

export type ReplayPhase = "idle" | "running" | "evaluating" | "complete";

export type IdsStreamState = {
  connected: boolean;
  snortRunning: boolean;
  pcapProgress: number;
  error: string | null;
  pcapProgressVisible: boolean;
  replayPhase: ReplayPhase;
  evaluation: EvaluationResult | null;
};

export function useIdsStream(): IdsStreamState {
  const [connected, setConnected] = useState(false);
  const [snortRunning, setSnortRunning] = useState(false);
  const [pcapProgress, setPcapProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [replayPhase, setReplayPhase] = useState<ReplayPhase>("idle");
  const [evaluation, setEvaluation] = useState<EvaluationResult | null>(null);
  const [pcapProgressVisible, setPcapProgressVisible] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevRunning = useRef(false);

  const handleStatus = useCallback((running: boolean, progress: number, err: string | null | undefined) => {
    setSnortRunning(running);
    setPcapProgress(progress);
    setError(err ?? null);

    if (running && !prevRunning.current) {
      setReplayPhase("running");
      setPcapProgressVisible(true);
      setEvaluation(null);
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
  };
}