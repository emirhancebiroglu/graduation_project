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
    <div className="relative p-4 flex flex-col gap-4" style={{
      border: "1px solid rgba(0,212,255,0.12)",
      background: "#0f1318",
      minHeight: "140px",
    }}>
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      <p className="section-label" style={{ color: "rgba(0,212,255,0.5)" }}>REPLAY CONTROL</p>

      {!snortRunning ? (
        <button
          disabled={loading !== null}
          onClick={handleStart}
          className="relative group flex items-center gap-3 px-4 py-3 text-left transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          style={{
            border: "1px solid rgba(0,212,255,0.3)",
            background: "rgba(0,212,255,0.05)",
            boxShadow: "0 0 20px rgba(0,212,255,0.08), inset 0 0 20px rgba(0,212,255,0.02)",
          }}
        >
          {loading === "full_wednesday" ? (
            <span className="w-4 h-4 rounded-full border-2 border-t-transparent animate-spin shrink-0" style={{ borderColor: "#00d4ff", borderTopColor: "transparent" }} />
          ) : (
            <div className="w-6 h-6 flex items-center justify-center shrink-0" style={{ border: "1px solid rgba(0,212,255,0.4)", background: "rgba(0,212,255,0.1)" }}>
              <svg width="10" height="10" viewBox="0 0 10 10" fill="#00d4ff">
                <polygon points="2,1 9,5 2,9" />
              </svg>
            </div>
          )}
          <div>
            <p className="text-xs font-mono font-medium" style={{ color: "#00d4ff" }}>FULL WEDNESDAY PCAP</p>
            <p className="text-[10px] font-mono mt-0.5" style={{ color: "rgba(100,116,139,0.7)" }}>~180s wall-clock · click to begin</p>
          </div>
        </button>
      ) : (
        <button
          disabled={loading === "stop"}
          onClick={handleStop}
          className="flex items-center gap-3 px-4 py-2.5 text-left transition-all disabled:opacity-40"
          style={{ border: "1px solid rgba(100,116,139,0.2)", background: "rgba(100,116,139,0.04)" }}
        >
          <div className="w-5 h-5 flex items-center justify-center shrink-0">
            {loading === "stop" ? (
              <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin" style={{ borderColor: "#64748b", borderTopColor: "transparent" }} />
            ) : (
              <div className="w-2.5 h-2.5" style={{ background: "#64748b" }} />
            )}
          </div>
          <span className="text-xs font-mono" style={{ color: "#64748b" }}>STOP REPLAY</span>
        </button>
      )}
    </div>
  );
}