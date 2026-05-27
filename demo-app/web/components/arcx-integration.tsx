"use client";
import { useState } from "react";
import { useT } from "@/lib/i18n";
import type { Alert, ReplayPhase } from "@/lib/types";

type Props = {
  alerts: Alert[];
  replayPhase: ReplayPhase;
};

const ENGINE_COLOR: Record<string, string> = {
  xgboost:    "#ff3b3b",
  portscan:   "#f59e0b",
  dos_agg:    "#e879f9",
  bot:        "#38bdf8",
  bruteforce: "#34d399",
  community:  "#94a3b8",
};

const ENGINE_SHORT: Record<string, string> = {
  xgboost:    "DoS",
  portscan:   "Scan",
  dos_agg:    "DDoS",
  bot:        "Bot",
  bruteforce: "BruteF",
  community:  "Comm",
};

function SeverityDot({ score }: { score?: number | null }) {
  const color =
    score == null ? "#64748b"
    : score >= 0.95 ? "#ff3b3b"
    : score >= 0.85 ? "#f59e0b"
    : score >= 0.70 ? "#e879f9"
    : "#34d399";
  return (
    <span
      className="w-1.5 h-1.5 rounded-full shrink-0"
      style={{ background: color, boxShadow: `0 0 4px ${color}` }}
    />
  );
}

export function ArcxIntegration({ alerts, replayPhase }: Props) {
  const { t } = useT();
  const [open, setOpen] = useState(false);

  const mlAlerts = alerts.filter((a) => a.engine !== "community");
  const recent = mlAlerts.slice(0, 5);

  return (
    <>
      <style>{`
        @keyframes slideInLeft {
          from { transform: translateX(-100%); opacity: 0; }
          to   { transform: translateX(0);     opacity: 1; }
        }
        @keyframes slideOutLeft {
          from { transform: translateX(0);     opacity: 1; }
          to   { transform: translateX(-100%); opacity: 0; }
        }
        .arcx-panel-open  { animation: slideInLeft  0.22s cubic-bezier(0.16,1,0.3,1) forwards; }
        .arcx-panel-close { animation: slideOutLeft 0.18s cubic-bezier(0.4,0,1,1) forwards; }
        @keyframes flowPulse {
          0%,100% { opacity: 0.3; transform: scaleX(0.95); }
          50%     { opacity: 1;   transform: scaleX(1); }
        }
        @keyframes dotFlow {
          0%   { left: 0%;   opacity: 0; }
          10%  { opacity: 1; }
          90%  { opacity: 1; }
          100% { left: 100%; opacity: 0; }
        }
        .flow-dot {
          position: absolute;
          top: 50%;
          transform: translateY(-50%);
          width: 4px;
          height: 4px;
          border-radius: 50%;
          background: #7c3aed;
          box-shadow: 0 0 6px #7c3aed;
          animation: dotFlow 1.8s linear infinite;
        }
        .flow-dot:nth-child(2) { animation-delay: 0.6s; }
        .flow-dot:nth-child(3) { animation-delay: 1.2s; }
      `}</style>

      {/* Fixed trigger — left edge, vertically centered */}
      <button
        onClick={() => setOpen(true)}
        title={t("arcx.title")}
        className="fixed z-40 flex flex-col items-center justify-center gap-1.5"
        style={{
          left: 0,
          top: "50%",
          transform: "translateY(-50%)",
          width: "28px",
          padding: "10px 0",
          background: "rgba(10,12,15,0.95)",
          border: "1px solid rgba(124,58,237,0.3)",
          borderLeft: "none",
          borderRadius: "0 4px 4px 0",
          boxShadow: "2px 0 12px rgba(124,58,237,0.12)",
          cursor: "pointer",
        }}
      >
        {/* ARCX hexagon icon */}
        <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
          <path d="M7 1L12 3.8V10.2L7 13L2 10.2V3.8L7 1Z"
            stroke="#7c3aed" strokeWidth="1" fill="rgba(124,58,237,0.12)" />
          <path d="M4.5 5.5L7 4L9.5 5.5V8.5L7 10L4.5 8.5V5.5Z"
            fill="rgba(124,58,237,0.4)" stroke="#7c3aed" strokeWidth="0.5" />
        </svg>
        <span
          className="text-[8px] font-mono tracking-widest"
          style={{
            color: "rgba(124,58,237,0.7)",
            writingMode: "vertical-rl",
            textOrientation: "mixed",
            transform: "rotate(180deg)",
            letterSpacing: "0.15em",
          }}
        >
          {t("arcx.buttonLabel")}
        </span>
        <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#7c3aed", boxShadow: "0 0 6px #7c3aed" }} />
      </button>

      {/* Backdrop */}
      {open && (
        <div
          className="fixed inset-0 z-40"
          style={{ background: "rgba(0,0,0,0.35)" }}
          onClick={() => setOpen(false)}
        />
      )}

      {/* Drawer panel — left side */}
      {open && (
        <div
          className="fixed z-50 top-0 left-0 h-full arcx-panel-open flex flex-col"
          style={{
            width: "min(460px, 92vw)",
            background: "rgba(10,12,15,0.98)",
            borderRight: "1px solid rgba(124,58,237,0.2)",
            boxShadow: "8px 0 40px rgba(0,0,0,0.6)",
          }}
        >
          {/* Corner brackets */}
          <div className="absolute top-0 right-0 w-3 h-3 border-t border-r z-10" style={{ borderColor: "rgba(124,58,237,0.4)" }} />
          <div className="absolute bottom-0 left-0 w-3 h-3 border-b border-l z-10" style={{ borderColor: "rgba(124,58,237,0.4)" }} />

          {/* Header */}
          <div className="flex items-center gap-3 px-4 py-3 border-b shrink-0" style={{ borderColor: "rgba(124,58,237,0.12)" }}>
            <div className="w-1 h-4" style={{ background: "rgba(124,58,237,0.8)", boxShadow: "0 0 6px rgba(124,58,237,0.5)" }} />
            <div>
              <span className="section-label" style={{ color: "#7c3aed" }}>{t("arcx.title")}</span>
              <p className="text-[9px] font-mono mt-0.5" style={{ color: "rgba(148,163,184,0.4)" }}>{t("arcx.subtitle")}</p>
            </div>
            <button
              onClick={() => setOpen(false)}
              className="ml-auto flex items-center justify-center w-5 h-5"
              style={{ border: "1px solid rgba(124,58,237,0.2)", background: "rgba(124,58,237,0.04)", color: "rgba(124,58,237,0.4)", fontSize: "10px", fontFamily: "monospace" }}
            >
              ✕
            </button>
          </div>

          <div className="flex-1 overflow-y-auto">
            {/* ARCX Platform mockup */}
            <div className="p-4">
              {/* Platform header bar */}
              <div
                className="flex items-center gap-3 px-3 py-2 mb-3"
                style={{
                  background: "rgba(124,58,237,0.06)",
                  border: "1px solid rgba(124,58,237,0.15)",
                }}
              >
                {/* ARCX wordmark */}
                <div className="flex items-center gap-1.5">
                  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
                    <path d="M9 1L16 5V13L9 17L2 13V5L9 1Z" stroke="#7c3aed" strokeWidth="1.2" fill="rgba(124,58,237,0.15)" />
                    <path d="M6 9L9 7L12 9V12L9 14L6 12V9Z" fill="#7c3aed" fillOpacity="0.5" />
                  </svg>
                  <span className="text-[13px] font-mono font-bold tracking-widest" style={{ color: "#7c3aed", letterSpacing: "0.2em" }}>ARCX</span>
                </div>
                <span className="text-[9px] font-mono" style={{ color: "rgba(124,58,237,0.5)" }}>·</span>
                <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.5)" }}>{t("arcx.platformLabel")}</span>
                <div className="ml-auto flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#10b981", boxShadow: "0 0 4px #10b981" }} />
                  <span className="text-[8px] font-mono" style={{ color: "rgba(16,185,129,0.6)" }}>ONLINE</span>
                </div>
              </div>

              {/* Existing modules label */}
              <p className="text-[8px] font-mono tracking-widest mb-2 px-1" style={{ color: "rgba(148,163,184,0.3)" }}>
                {t("arcx.existingModules")}
              </p>

              {/* 2×2 module grid */}
              <div className="grid grid-cols-2 gap-2 mb-2">
                {/* Module 1 — Server Performance */}
                <div
                  className="p-3"
                  style={{
                    border: "1px solid rgba(0,212,255,0.15)",
                    background: "rgba(0,212,255,0.03)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <rect x="1" y="1" width="10" height="10" rx="1" stroke="#00d4ff" strokeWidth="0.8" fill="rgba(0,212,255,0.1)" />
                      <rect x="3" y="3" width="6" height="1.5" rx="0.5" fill="#00d4ff" fillOpacity="0.6" />
                      <rect x="3" y="5.5" width="4" height="1.5" rx="0.5" fill="#00d4ff" fillOpacity="0.4" />
                      <rect x="3" y="8" width="2" height="1" rx="0.5" fill="#00d4ff" fillOpacity="0.3" />
                    </svg>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "#00d4ff" }}>{t("arcx.mod1Title")}</span>
                  </div>
                  <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>{t("arcx.mod1Desc")}</p>
                  <div className="mt-2 flex items-center gap-1">
                    <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: "rgba(0,212,255,0.08)" }}>
                      <div className="h-full rounded-full" style={{ width: "62%", background: "#00d4ff", opacity: 0.5 }} />
                    </div>
                    <span className="text-[8px] font-mono" style={{ color: "rgba(0,212,255,0.4)" }}>62%</span>
                  </div>
                </div>

                {/* Module 2 — Network Outage */}
                <div
                  className="p-3"
                  style={{
                    border: "1px solid rgba(245,158,11,0.15)",
                    background: "rgba(245,158,11,0.03)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <circle cx="6" cy="6" r="4.5" stroke="#f59e0b" strokeWidth="0.8" fill="rgba(245,158,11,0.1)" />
                      <path d="M3.5 6 Q6 3 8.5 6 Q6 9 3.5 6Z" stroke="#f59e0b" strokeWidth="0.6" fill="none" />
                      <line x1="6" y1="1.5" x2="6" y2="10.5" stroke="#f59e0b" strokeWidth="0.5" strokeOpacity="0.4" />
                    </svg>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "#f59e0b" }}>{t("arcx.mod2Title")}</span>
                  </div>
                  <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>{t("arcx.mod2Desc")}</p>
                  <div className="mt-2 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#10b981" }} />
                    <span className="text-[8px] font-mono" style={{ color: "rgba(16,185,129,0.6)" }}>NOMINAL</span>
                  </div>
                </div>

                {/* Module 3 — SLA */}
                <div
                  className="p-3"
                  style={{
                    border: "1px solid rgba(16,185,129,0.15)",
                    background: "rgba(16,185,129,0.03)",
                  }}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M1 9 L3 5 L5 7 L7 3 L9 6 L11 4" stroke="#10b981" strokeWidth="0.8" fill="none" strokeLinecap="round" />
                      <circle cx="11" cy="4" r="1" fill="#10b981" fillOpacity="0.6" />
                    </svg>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "#10b981" }}>{t("arcx.mod3Title")}</span>
                  </div>
                  <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>{t("arcx.mod3Desc")}</p>
                  <div className="mt-2">
                    <span className="text-[9px] font-mono font-semibold" style={{ color: "#10b981" }}>99.8%</span>
                    <span className="text-[8px] font-mono ml-1" style={{ color: "rgba(16,185,129,0.4)" }}>uptime</span>
                  </div>
                </div>

                {/* Module 4 — Security Threat (NEW — Aegis) */}
                <div
                  className="p-3 relative"
                  style={{
                    border: "1px solid rgba(124,58,237,0.4)",
                    background: "rgba(124,58,237,0.06)",
                    boxShadow: "0 0 16px rgba(124,58,237,0.08)",
                  }}
                >
                  {/* NEW badge */}
                  <div
                    className="absolute -top-px -right-px px-1.5 py-0.5"
                    style={{ background: "#7c3aed", fontSize: "7px", fontFamily: "monospace", color: "#fff", letterSpacing: "0.08em" }}
                  >
                    {t("arcx.mod4Badge")}
                  </div>

                  <div className="flex items-center gap-2 mb-1.5">
                    <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                      <path d="M6 1L10.5 3.25V7C10.5 9.5 6 11.5 6 11.5C6 11.5 1.5 9.5 1.5 7V3.25L6 1Z"
                        stroke="#7c3aed" strokeWidth="0.8" fill="rgba(124,58,237,0.2)" />
                      <path d="M4 6L5.3 7.3L8 4.5" stroke="#7c3aed" strokeWidth="0.8" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                    <span className="text-[10px] font-mono font-semibold" style={{ color: "#7c3aed" }}>{t("arcx.mod4Title")}</span>
                  </div>
                  <p className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.45)" }}>{t("arcx.mod4Desc")}</p>
                  <div className="mt-2 flex items-center gap-1.5">
                    <span
                      className="w-1.5 h-1.5 rounded-full"
                      style={{
                        background: mlAlerts.length > 0 ? "#ff3b3b" : "#7c3aed",
                        boxShadow: mlAlerts.length > 0 ? "0 0 6px #ff3b3b" : "0 0 4px #7c3aed",
                        animation: mlAlerts.length > 0 ? "pulse 1s infinite" : "none",
                      }}
                    />
                    <span className="text-[8px] font-mono" style={{ color: mlAlerts.length > 0 ? "#ff3b3b" : "rgba(124,58,237,0.5)" }}>
                      {mlAlerts.length > 0 ? `${mlAlerts.length} ALERT` : "MONITORING"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Flow arrow: Aegis → ARCX */}
              <div className="flex items-center gap-2 my-4 px-1">
                <div className="text-[8px] font-mono shrink-0" style={{ color: "rgba(124,58,237,0.5)" }}>AEGIS IDS</div>
                <div className="relative flex-1 h-px" style={{ background: "rgba(124,58,237,0.15)" }}>
                  {mlAlerts.length > 0 && (
                    <>
                      <div className="flow-dot" />
                      <div className="flow-dot" />
                      <div className="flow-dot" />
                    </>
                  )}
                </div>
                <div className="text-[8px] font-mono shrink-0" style={{ color: "rgba(124,58,237,0.5)" }}>
                  {t("arcx.flowLabel")}
                </div>
              </div>

              {/* Live alerts section */}
              <div
                className="rounded-sm overflow-hidden"
                style={{ border: "1px solid rgba(124,58,237,0.15)", background: "rgba(124,58,237,0.03)" }}
              >
                <div className="flex items-center gap-2 px-3 py-2 border-b" style={{ borderColor: "rgba(124,58,237,0.1)" }}>
                  <div className="w-1 h-3" style={{ background: "rgba(124,58,237,0.7)", boxShadow: "0 0 4px rgba(124,58,237,0.5)" }} />
                  <span className="text-[9px] font-mono tracking-widest" style={{ color: "rgba(124,58,237,0.7)" }}>
                    {t("arcx.liveAlerts")}
                  </span>
                  {mlAlerts.length > 0 && (
                    <span
                      className="ml-auto text-[8px] font-mono px-1.5 py-0.5"
                      style={{ background: "rgba(124,58,237,0.15)", color: "#7c3aed" }}
                    >
                      {mlAlerts.length}
                    </span>
                  )}
                </div>

                <div className="p-2 space-y-1" style={{ minHeight: "80px" }}>
                  {recent.length === 0 ? (
                    <div className="flex items-center justify-center h-16 gap-2">
                      {(replayPhase === "running" || replayPhase === "draining") && (
                        <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: "#7c3aed", boxShadow: "0 0 6px #7c3aed", animation: "pulse 1.5s infinite" }} />
                      )}
                      <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.25)" }}>
                        {replayPhase === "running" || replayPhase === "draining"
                          ? t("arcx.waiting")
                          : t("arcx.noAlerts")}
                      </span>
                    </div>
                  ) : (
                    recent.map((a) => {
                      const color = ENGINE_COLOR[a.engine] ?? "#94a3b8";
                      const label = ENGINE_SHORT[a.engine] ?? a.engine;
                      return (
                        <div
                          key={a.id}
                          className="flex items-center gap-2 px-2 py-1.5"
                          style={{
                            background: "rgba(124,58,237,0.04)",
                            border: "1px solid rgba(124,58,237,0.08)",
                            borderLeft: `2px solid ${color}`,
                          }}
                        >
                          <SeverityDot score={a.score} />
                          <span className="text-[8px] font-mono px-1 py-0.5 shrink-0" style={{ background: `${color}22`, color }}>
                            {label}
                          </span>
                          <span className="text-[9px] font-mono truncate flex-1" style={{ color: "rgba(148,163,184,0.7)" }}>
                            {a.src_ip} → {a.dst_ip}
                          </span>
                          <span className="text-[8px] font-mono shrink-0 tabular-nums" style={{ color: "rgba(148,163,184,0.35)" }}>
                            {a.ts.slice(11, 19)}
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="px-4 py-2 border-t shrink-0 flex items-center gap-4" style={{ borderColor: "rgba(124,58,237,0.08)" }}>
            <span className="text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.3)" }}>
              {t("arcx.footerLeft")}
            </span>
            <span className="text-[9px] font-mono ml-auto" style={{ color: "rgba(124,58,237,0.4)" }}>
              {t("arcx.footerRight")}
            </span>
          </div>
        </div>
      )}
    </>
  );
}
