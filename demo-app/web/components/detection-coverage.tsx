"use client";
import { useState } from "react";
import { useT } from "@/lib/i18n";
import type { ScenarioPayload } from "@/lib/types";

type ModelKey = "dos" | "portscan" | "ddos" | "bot" | "bruteforce";

type ModelEntry = {
  key: ModelKey;
  gid: number;
  dataset: string;
  recall: string;
  precision: string;
  fp: string;
  status: "pass";
};

const MODELS: ModelEntry[] = [
  { key: "dos",        gid: 301, dataset: "CIC Wed", recall: "99.99%",      precision: "97.16%", fp: "FPR 1.68%", status: "pass" },
  { key: "ddos",       gid: 304, dataset: "CIC Fri", recall: "20 attack wins", precision: "FP = 0", fp: "FP 0",   status: "pass" },
  { key: "portscan",   gid: 302, dataset: "CIC Fri", recall: "91% window",  precision: "FP = 0", fp: "FP 0",      status: "pass" },
  { key: "bruteforce", gid: 307, dataset: "CIC Tue", recall: "100%",        precision: "FPR ~0%", fp: "FP ≤ 2",  status: "pass" },
  { key: "bot",        gid: 306, dataset: "CIC Fri", recall: "85.7%",       precision: "75.0%",  fp: "FP ≤ 5",   status: "pass" },
];

const GID_COLOR: Record<number, { text: string; border: string; bg: string; glow: string }> = {
  301: { text: "#ff3b3b", border: "rgba(255,59,59,0.25)", bg: "rgba(255,59,59,0.04)", glow: "0 0 12px rgba(255,59,59,0.12)" },
  304: { text: "#f97316", border: "rgba(249,115,22,0.22)", bg: "rgba(249,115,22,0.04)", glow: "0 0 12px rgba(249,115,22,0.08)" },
  302: { text: "#a855f7", border: "rgba(168,85,247,0.22)", bg: "rgba(168,85,247,0.04)", glow: "0 0 12px rgba(168,85,247,0.08)" },
  307: { text: "#facc15", border: "rgba(250,204,21,0.22)", bg: "rgba(250,204,21,0.04)", glow: "0 0 12px rgba(250,204,21,0.08)" },
  306: { text: "#ec4899", border: "rgba(236,72,153,0.22)", bg: "rgba(236,72,153,0.04)", glow: "0 0 12px rgba(236,72,153,0.08)" },
};

function ModelCard({ m, active }: { m: ModelEntry; active: boolean }) {
  const { t } = useT();
  const c = GID_COLOR[m.gid];
  const name = t(`coverage.models.${m.key}`);
  const attack = t(`coverage.attacks.${m.key}`);
  return (
    <div
      className="relative flex flex-col gap-2 p-3 overflow-hidden"
      style={{
        border: `1px solid ${active ? c.text : c.border}`,
        background: c.bg,
        boxShadow: active ? `${c.glow}, 0 0 0 1px ${c.text}40` : c.glow,
      }}
    >
      <div className="absolute top-0 left-0 w-2 h-2 border-t border-l" style={{ borderColor: c.border }} />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b border-r" style={{ borderColor: c.border }} />

      <div className="flex items-center gap-2">
        <span className="text-[9px] font-mono px-1.5 py-0.5 shrink-0" style={{ background: c.border, color: c.text, letterSpacing: "0.08em" }}>
          GID:{m.gid}
        </span>
        <span className="text-[10px] font-mono font-semibold truncate" style={{ color: c.text, letterSpacing: "0.06em" }}>
          {name.toUpperCase()}
        </span>
        {active && (
          <span className="text-[9px] font-mono px-1 py-0.5 shrink-0 font-semibold" style={{ border: `1px solid ${c.text}`, background: `${c.text}20`, color: c.text }}>
            ACTIVE
          </span>
        )}
        <span className="ml-auto text-[10px] font-mono" style={{ color: "#10b981" }}>✓</span>
      </div>

      <p className="text-[10px] font-mono leading-tight" style={{ color: "rgba(148,163,184,0.85)" }}>
        {attack}
      </p>

      <div className="flex gap-3 mt-auto pt-1 border-t" style={{ borderColor: "rgba(255,255,255,0.04)" }}>
        <div>
          <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>{t("coverage.recall")}</p>
          <p className="text-[13px] font-mono font-semibold" style={{ color: c.text }}>{m.recall}</p>
        </div>
        <div>
          <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>{t("coverage.precision")}</p>
          <p className="text-[13px] font-mono font-semibold" style={{ color: c.text }}>{m.precision}</p>
        </div>
        <div className="ml-auto text-right">
          <p className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.65)" }}>{t("coverage.dataset")}</p>
          <p className="text-[11px] font-mono" style={{ color: "rgba(148,163,184,0.85)" }}>{m.dataset}</p>
        </div>
      </div>
    </div>
  );
}

export function DetectionCoverage({ scenario }: { scenario?: ScenarioPayload | null }) {
  const { t } = useT();
  const [open, setOpen] = useState(false);
  const activeKey: ModelKey | null = scenario?.key ?? null;

  return (
    <>
      <style>{`
        @keyframes slideInRight {
          from { transform: translateX(100%); opacity: 0; }
          to   { transform: translateX(0);    opacity: 1; }
        }
        @keyframes slideOutRight {
          from { transform: translateX(0);    opacity: 1; }
          to   { transform: translateX(100%); opacity: 0; }
        }
        .coverage-panel-open  { animation: slideInRight  0.22s cubic-bezier(0.16,1,0.3,1) forwards; }
        .coverage-panel-close { animation: slideOutRight 0.18s cubic-bezier(0.4,0,1,1) forwards; }
      `}</style>

      {/* Fixed trigger button — right edge, vertically centered */}
      <button
        onClick={() => setOpen(true)}
        title={t("coverage.title")}
        className="fixed z-40 flex flex-col items-center justify-center gap-1.5"
        style={{
          right: 0,
          top: "50%",
          transform: "translateY(-50%)",
          width: "28px",
          padding: "10px 0",
          background: "rgba(10,12,15,0.95)",
          border: "1px solid rgba(16,185,129,0.25)",
          borderRight: "none",
          borderRadius: "4px 0 0 4px",
          boxShadow: "-2px 0 12px rgba(16,185,129,0.08)",
          cursor: "pointer",
        }}
      >
        {/* Shield icon */}
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M7 1L12.5 3.5V7C12.5 10 7 13 7 13C7 13 1.5 10 1.5 7V3.5L7 1Z"
            stroke="#10b981" strokeWidth="1" fill="rgba(16,185,129,0.12)" />
          <path d="M4.5 7L6.2 8.7L9.5 5.5" stroke="#10b981" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        {/* Rotated label */}
        <span
          className="text-[9px] font-mono tracking-widest"
          style={{
            color: "rgba(16,185,129,0.9)",
            writingMode: "vertical-rl",
            textOrientation: "mixed",
            transform: "rotate(180deg)",
            letterSpacing: "0.15em",
          }}
        >
          {t("coverage.buttonLabel")}
        </span>
        {/* Active dot */}
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#10b981", boxShadow: "0 0 6px #10b981" }} />
      </button>

      {/* Backdrop */}
      {open && (
        <div
          className="fixed inset-0 z-40"
          style={{ background: "rgba(0,0,0,0.35)" }}
          onClick={() => setOpen(false)}
        />
      )}

      {/* Drawer panel */}
      {open && (
        <div
          className="fixed z-50 top-0 right-0 h-full coverage-panel-open flex flex-col"
          style={{
            width: "min(420px, 90vw)",
            background: "rgba(10,12,15,0.98)",
            borderLeft: "1px solid rgba(16,185,129,0.2)",
            boxShadow: "-8px 0 40px rgba(0,0,0,0.6)",
          }}
        >
          {/* Corner brackets */}
          <div className="absolute top-0 left-0 w-3 h-3 border-t border-l z-10" style={{ borderColor: "rgba(16,185,129,0.4)" }} />
          <div className="absolute bottom-0 right-0 w-3 h-3 border-b border-r z-10" style={{ borderColor: "rgba(16,185,129,0.4)" }} />

          {/* Header */}
          <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0" style={{ borderColor: "rgba(16,185,129,0.12)" }}>
            <div className="w-1 h-4" style={{ background: "rgba(16,185,129,0.8)", boxShadow: "0 0 6px rgba(16,185,129,0.5)" }} />
            <span className="section-label" style={{ color: "#10b981" }}>{t("coverage.title")}</span>
            <span className="ml-auto text-[9px] font-mono" style={{ color: "rgba(16,185,129,0.6)" }}>
              {t("coverage.modelsActive", { n: MODELS.length, total: MODELS.length })}
            </span>
            <button
              onClick={() => setOpen(false)}
              className="ml-2 flex items-center justify-center w-5 h-5"
              style={{ border: "1px solid rgba(0,212,255,0.15)", background: "rgba(0,212,255,0.04)", color: "rgba(0,212,255,0.4)", fontSize: "10px", fontFamily: "monospace" }}
            >
              ✕
            </button>
          </div>

          {/* Cards */}
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {MODELS.map((m) => (
              <ModelCard key={m.gid} m={m} active={m.key === activeKey} />
            ))}
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t shrink-0 flex items-center gap-4" style={{ borderColor: "rgba(16,185,129,0.08)" }}>
            <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.6)" }}>
              {t("coverage.footerEvaluated")}
            </span>
            <span className="text-[10px] font-mono ml-auto" style={{ color: "rgba(16,185,129,0.7)" }}>
              {t("coverage.footerCriteriaMet")}
            </span>
          </div>
        </div>
      )}
    </>
  );
}
