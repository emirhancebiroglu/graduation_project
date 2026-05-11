"use client";
import { useState } from "react";
import { toast } from "sonner";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Pcap = "normal_2min" | "dos_hulk_2min" | "full_wednesday";

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
  onStarting?: (starting: boolean, pcap?: Pcap) => void;
};

export function AttackControl({ snortRunning, onStarting }: Props) {
  const [loading, setLoading] = useState<Pcap | "stop" | null>(null);
  const [advanced, setAdvanced] = useState(false);

  const busy = loading !== null;

  async function handleStart(pcap: Pcap) {
    setLoading(pcap);
    onStarting?.(true, pcap);
    try {
      await startReplay(pcap);
      const label = pcap === "normal_2min" ? "Normal traffic" : pcap === "dos_hulk_2min" ? "DoS attack" : "Full Wednesday PCAP";
      toast.success(`${label} replay started`);
    } catch (err) {
      onStarting?.(false, pcap);
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
    <div className="relative p-4 h-full flex flex-col gap-4" style={{
      border: "1px solid rgba(0,212,255,0.12)",
      background: "#0f1318",
    }}>
      {/* Corner brackets */}
      <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      <p className="section-label" style={{ color: "rgba(0,212,255,0.5)" }}>REPLAY CONTROL</p>

      {/* Normal traffic button */}
      <button
        disabled={snortRunning || busy}
        onClick={() => handleStart("normal_2min")}
        className="relative group flex items-center gap-3 px-4 py-3 w-full text-left transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        style={{
          border: "1px solid rgba(16,185,129,0.25)",
          background: "rgba(16,185,129,0.04)",
        }}
      >
        <div className="w-6 h-6 flex items-center justify-center shrink-0" style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.1)" }}>
          {loading === "normal_2min" ? (
            <span className="w-3 h-3 rounded-full border border-current border-t-transparent animate-spin" style={{ borderColor: "#10b981", borderTopColor: "transparent" }} />
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10" fill="#10b981">
              <polygon points="2,1 9,5 2,9" />
            </svg>
          )}
        </div>
        <div>
          <p className="text-xs font-mono font-medium" style={{ color: "#10b981" }}>NORMAL TRAFFIC</p>
          <p className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.7)" }}>2 min baseline replay</p>
        </div>
      </button>

      {/* DoS Attack button — primary action */}
      <button
        disabled={snortRunning || busy}
        onClick={() => handleStart("dos_hulk_2min")}
        className="relative group flex items-center gap-3 px-4 py-3 w-full text-left transition-all disabled:opacity-30 disabled:cursor-not-allowed"
        style={{
          border: `1px solid ${!snortRunning && !busy ? "rgba(255,59,59,0.5)" : "rgba(255,59,59,0.2)"}`,
          background: !snortRunning && !busy ? "rgba(255,59,59,0.08)" : "rgba(255,59,59,0.03)",
          boxShadow: !snortRunning && !busy ? "0 0 20px rgba(255,59,59,0.1), inset 0 0 20px rgba(255,59,59,0.04)" : "none",
        }}
      >
        {/* Pulse ring when idle */}
        {!snortRunning && !busy && (
          <span className="absolute inset-0 animate-ping opacity-10" style={{ background: "rgba(255,59,59,0.3)", pointerEvents: "none" }} />
        )}
        <div className="w-6 h-6 flex items-center justify-center shrink-0 z-10" style={{ border: "1px solid rgba(255,59,59,0.4)", background: "rgba(255,59,59,0.12)" }}>
          {loading === "dos_hulk_2min" ? (
            <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin" style={{ borderColor: "#ff3b3b", borderTopColor: "transparent" }} />
          ) : (
            <span style={{ fontSize: "12px" }}>⚡</span>
          )}
        </div>
        <div className="z-10">
          <p className="text-xs font-mono font-medium" style={{ color: "#ff3b3b" }}>LAUNCH DOS ATTACK</p>
          <p className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.7)" }}>Hulk flood simulation</p>
        </div>
      </button>

      {/* Stop */}
      {(snortRunning || loading === "stop") && (
        <button
          disabled={loading === "stop"}
          onClick={handleStop}
          className="flex items-center gap-3 px-4 py-2.5 w-full text-left transition-all disabled:opacity-40"
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

      {/* Advanced */}
      <div>
        <button
          onClick={() => setAdvanced((v) => !v)}
          className="flex items-center gap-2 text-left"
        >
          <span className="section-label" style={{ color: "rgba(0,212,255,0.3)" }}>
            {advanced ? "▾" : "▸"} ADVANCED
          </span>
        </button>

        {advanced && (
          <div className="mt-2 pl-3 space-y-2" style={{ borderLeft: "1px solid rgba(0,212,255,0.1)" }}>
            <button
              disabled={snortRunning || busy}
              onClick={() => handleStart("full_wednesday")}
              className="flex items-center gap-2 px-3 py-2 w-full text-left disabled:opacity-30"
              style={{ border: "1px solid rgba(0,212,255,0.1)", background: "rgba(0,212,255,0.02)" }}
            >
              {loading === "full_wednesday" ? (
                <span className="w-3 h-3 rounded-full border border-t-transparent animate-spin" style={{ borderColor: "#00d4ff", borderTopColor: "transparent" }} />
              ) : (
                <span className="text-[10px]" style={{ color: "rgba(0,212,255,0.5)" }}>▸</span>
              )}
              <span className="text-[10px] font-mono" style={{ color: "rgba(0,212,255,0.6)" }}>FULL WEDNESDAY PCAP</span>
            </button>
            <p className="text-[10px] font-mono" style={{ color: "rgba(100,116,139,0.5)" }}>
              ~8h of traffic · progress bar shows %
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
