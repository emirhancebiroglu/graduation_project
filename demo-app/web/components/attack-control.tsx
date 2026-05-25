"use client";
import { useState } from "react";
import { toast } from "sonner";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Pcap = "full_wednesday";

async function startReplay(pcap: Pcap): Promise<void> {
  const res = await fetch(`${API}/api/replay/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pcap }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.detail ?? `HTTP ${res.status}`);
  }
}

async function stopReplay(): Promise<void> {
  const res = await fetch(`${API}/api/replay/stop`, { method: "POST" });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
}

type Props = {
  snortRunning: boolean;
  onStarting?: (starting: boolean) => void;
};

export function AttackControl({ snortRunning, onStarting }: Props) {
  const [loading, setLoading] = useState<Pcap | "stop" | null>(null);

  async function handleStart() {
    setLoading("full_wednesday");
    onStarting?.(true);
    try {
      await startReplay("full_wednesday");
      toast.success("Full Wednesday replay started");
    } catch (err) {
      onStarting?.(false);
      toast.error(`Failed to start replay: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(null);
    }
  }

  async function handleStop() {
    setLoading("stop");
    try {
      await stopReplay();
      toast.success("Replay stopped");
    } catch (err) {
      toast.error(`Failed to stop: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="relative overflow-hidden" style={{
      border: "1px solid rgba(0,212,255,0.1)",
      background: "#0f1318",
    }}>
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.2)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.2)" }} />

      {!snortRunning ? (
        <button
          disabled={loading !== null}
          onClick={handleStart}
          className="w-full flex items-center gap-4 px-5 py-4 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          style={{
            background: "rgba(0,212,255,0.04)",
            borderBottom: "1px solid rgba(0,212,255,0.08)",
          }}
        >
          {loading === "full_wednesday" ? (
            <span className="w-5 h-5 rounded-full border-2 border-t-transparent animate-spin shrink-0" style={{ borderColor: "#00d4ff", borderTopColor: "transparent" }} />
          ) : (
            <div className="w-8 h-8 rounded-full flex items-center justify-center shrink-0" style={{ border: "1px solid rgba(0,212,255,0.4)", background: "rgba(0,212,255,0.08)" }}>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <polygon points="3,1 12,7 3,13" fill="#00d4ff" />
              </svg>
            </div>
          )}
          <div className="text-left">
            <p className="text-sm font-mono font-semibold" style={{ color: "#00d4ff", letterSpacing: "0.05em" }}>RUN ENSEMBLE ANALYSIS</p>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.75)" }}>CIC-IDS2017 Wednesday · ML Ensemble + Community Rules · click to start</p>
          </div>
          <div className="ml-auto flex items-center gap-2 px-3 py-1.5 rounded-sm" style={{ border: "1px solid rgba(0,212,255,0.15)", background: "rgba(0,212,255,0.05)" }}>
            <span className="text-[9px] font-mono" style={{ color: "rgba(0,212,255,0.5)" }}>~180s</span>
          </div>
        </button>
      ) : (
        <div className="relative px-5 py-4 flex items-center gap-4" style={{ borderBottom: "1px solid rgba(148,163,184,0.15)" }}>
          <div className="relative shrink-0">
            <div className="radar-sweep w-8 h-8 rounded-full" style={{ border: "1px solid rgba(0,212,255,0.3)", background: "rgba(0,212,255,0.05)" }}>
              <div className="radar-sweep-inner absolute inset-0 rounded-full" style={{ background: "conic-gradient(from 0deg, transparent 0deg, rgba(0,212,255,0.4) 30deg, transparent 60deg)" }} />
            </div>
            <style>{`
              @keyframes radarSweep {
                from { transform: rotate(0deg); }
                to { transform: rotate(360deg); }
              }
              .radar-sweep-inner {
                animation: radarSweep 2s linear infinite;
                transform-origin: center;
              }
            `}</style>
          </div>
          <div className="flex-1">
            <p className="text-sm font-mono font-semibold" style={{ color: "#00d4ff" }}>ANALYSIS IN PROGRESS</p>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.75)" }}>Snort inspector running · alerts being processed</p>
          </div>
          <button
            disabled={loading === "stop"}
            onClick={handleStop}
            className="flex items-center gap-2 px-3 py-2 rounded-sm transition-all disabled:opacity-40"
            style={{ border: "1px solid rgba(255,59,59,0.25)", background: "rgba(255,59,59,0.05)" }}
          >
            {loading === "stop" ? (
              <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin" style={{ borderColor: "#64748b", borderTopColor: "transparent" }} />
            ) : (
              <div className="w-2.5 h-2.5" style={{ background: "#ff3b3b" }} />
            )}
            <span className="text-[10px] font-mono" style={{ color: "#ff3b3b" }}>STOP</span>
          </button>
        </div>
      )}
    </div>
  );
}