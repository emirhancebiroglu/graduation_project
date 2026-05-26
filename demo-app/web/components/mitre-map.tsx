"use client";
import { useState } from "react";
import { useT } from "@/lib/i18n";
import type { Alert } from "@/lib/types";

type Props = { alerts: Alert[] };

type TechniqueKey = "T1046" | "T1110" | "T1071" | "T1499" | "T1498";

type Technique = {
  id: TechniqueKey;
  name: string;
  engine: string;
  tactic: "discovery" | "credential" | "c2" | "impact";
  color: string;
  engineLabel: string;
};

const TECHNIQUES: Technique[] = [
  { id: "T1046", name: "Network Service Discovery", engine: "portscan",   tactic: "discovery",   color: "#f59e0b", engineLabel: "PortScan" },
  { id: "T1110", name: "Brute Force",               engine: "bruteforce", tactic: "credential",  color: "#34d399", engineLabel: "BruteForce" },
  { id: "T1071", name: "App Layer Protocol",         engine: "bot",        tactic: "c2",          color: "#38bdf8", engineLabel: "Bot" },
  { id: "T1499", name: "Endpoint DoS",               engine: "xgboost",   tactic: "impact",      color: "#ff3b3b", engineLabel: "DoS" },
  { id: "T1498", name: "Network DoS",                engine: "dos_agg",   tactic: "impact",      color: "#e879f9", engineLabel: "DDoS" },
];

const TACTIC_ORDER: Array<"discovery" | "credential" | "c2" | "impact"> = [
  "discovery", "credential", "c2", "impact",
];

const TACTIC_COLOR: Record<string, string> = {
  discovery:  "rgba(245,158,11,0.6)",
  credential: "rgba(52,211,153,0.6)",
  c2:         "rgba(56,189,248,0.6)",
  impact:     "rgba(255,59,59,0.6)",
};

export function MitreMap({ alerts }: Props) {
  const { t } = useT();
  const [open, setOpen] = useState(false);

  // Count alerts per technique via mitre_technique field
  const counts: Record<string, number> = {};
  for (const a of alerts) {
    if (a.mitre_technique) counts[a.mitre_technique] = (counts[a.mitre_technique] ?? 0) + 1;
  }
  const maxCount = Math.max(...Object.values(counts), 1);
  const totalDetected = Object.values(counts).reduce((s, v) => s + v, 0);

  // Group by tactic
  const byTactic: Record<string, Technique[]> = {};
  for (const tc of TECHNIQUES) {
    if (!byTactic[tc.tactic]) byTactic[tc.tactic] = [];
    byTactic[tc.tactic].push(tc);
  }

  return (
    <>
      <style>{`
        @keyframes mitreSlideIn {
          from { transform: translateY(100%); opacity: 0; }
          to   { transform: translateY(0);    opacity: 1; }
        }
        .mitre-panel-open { animation: mitreSlideIn 0.22s cubic-bezier(0.16,1,0.3,1) forwards; }
      `}</style>

      {/* Trigger — bottom edge, horizontally centered */}
      <button
        onClick={() => setOpen(true)}
        title={t("mitre.title")}
        className="fixed z-40 flex items-center justify-center gap-2"
        style={{
          bottom: 0,
          left: "50%",
          transform: "translateX(-50%)",
          height: "26px",
          padding: "0 14px",
          background: "rgba(10,12,15,0.95)",
          border: "1px solid rgba(139,92,246,0.28)",
          borderBottom: "none",
          borderRadius: "4px 4px 0 0",
          boxShadow: "0 -2px 12px rgba(139,92,246,0.1)",
          cursor: "pointer",
        }}
      >
        <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
          <rect x="0.5" y="0.5" width="4" height="4" stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.15)" />
          <rect x="6.5" y="0.5" width="4" height="4" stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.15)" />
          <rect x="0.5" y="6.5" width="4" height="4" stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.15)" />
          <rect x="6.5" y="6.5" width="4" height="4" stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.15)" />
        </svg>
        <span className="text-[8px] font-mono tracking-widest" style={{ color: "rgba(139,92,246,0.75)", letterSpacing: "0.15em" }}>
          {t("mitre.buttonLabel")}
        </span>
        {totalDetected > 0 && (
          <span
            className="text-[8px] font-mono px-1 py-0.5 tabular-nums"
            style={{ background: "rgba(139,92,246,0.2)", color: "#a78bfa" }}
          >
            {totalDetected}
          </span>
        )}
      </button>

      {/* Backdrop */}
      {open && (
        <div
          className="fixed inset-0 z-40"
          style={{ background: "rgba(0,0,0,0.4)" }}
          onClick={() => setOpen(false)}
        />
      )}

      {/* Bottom drawer */}
      {open && (
        <div
          className="fixed z-50 bottom-0 left-0 right-0 mitre-panel-open"
          style={{
            background: "rgba(10,12,15,0.98)",
            borderTop: "1px solid rgba(139,92,246,0.2)",
            boxShadow: "0 -8px 40px rgba(0,0,0,0.6)",
            maxHeight: "320px",
          }}
        >
          {/* Corner brackets */}
          <div className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(139,92,246,0.4)" }} />
          <div className="absolute top-0 right-0 w-3 h-3 border-t border-r" style={{ borderColor: "rgba(139,92,246,0.4)" }} />

          {/* Header */}
          <div className="flex items-center gap-3 px-5 py-2.5 border-b" style={{ borderColor: "rgba(139,92,246,0.12)" }}>
            <div className="w-1 h-4" style={{ background: "rgba(139,92,246,0.8)", boxShadow: "0 0 6px rgba(139,92,246,0.5)" }} />
            <div>
              <span className="section-label" style={{ color: "#a78bfa" }}>{t("mitre.title")}</span>
              <span className="text-[9px] font-mono ml-3" style={{ color: "rgba(148,163,184,0.35)" }}>{t("mitre.subtitle")}</span>
            </div>
            <div className="ml-auto flex items-center gap-3">
              {totalDetected > 0 && (
                <span className="text-[9px] font-mono" style={{ color: "rgba(139,92,246,0.5)" }}>
                  {totalDetected} {t("mitre.alertsSuffix")}
                </span>
              )}
              <button
                onClick={() => setOpen(false)}
                className="flex items-center justify-center w-5 h-5"
                style={{ border: "1px solid rgba(139,92,246,0.2)", background: "rgba(139,92,246,0.04)", color: "rgba(139,92,246,0.4)", fontSize: "10px", fontFamily: "monospace" }}
              >
                ✕
              </button>
            </div>
          </div>

          {/* Heatmap grid */}
          <div className="p-4 overflow-x-auto">
            {alerts.length === 0 ? (
              <div className="flex items-center justify-center py-8">
                <span className="text-[10px] font-mono" style={{ color: "rgba(148,163,184,0.2)" }}>{t("mitre.noAlerts")}</span>
              </div>
            ) : (
              <div className="flex gap-4 min-w-max">
                {TACTIC_ORDER.map((tactic) => {
                  const techs = byTactic[tactic] ?? [];
                  const tacticColor = TACTIC_COLOR[tactic];
                  return (
                    <div key={tactic} className="flex flex-col gap-2" style={{ minWidth: "160px" }}>
                      {/* Tactic header */}
                      <div
                        className="px-2 py-1 text-center"
                        style={{ borderBottom: `2px solid ${tacticColor}`, background: `${tacticColor}10` }}
                      >
                        <span className="text-[8px] font-mono tracking-widest font-bold" style={{ color: tacticColor, letterSpacing: "0.12em" }}>
                          {t(`mitre.tactics.${tactic}`)}
                        </span>
                      </div>

                      {/* Technique cards */}
                      {techs.map((tech) => {
                        const count = counts[tech.id] ?? 0;
                        const intensity = count > 0 ? Math.max(0.12, count / maxCount) : 0;
                        const active = count > 0;
                        return (
                          <div
                            key={tech.id}
                            className="p-2.5 flex flex-col gap-1.5 transition-all"
                            style={{
                              border: `1px solid ${active ? tech.color + "55" : "rgba(148,163,184,0.08)"}`,
                              background: active ? `${tech.color}${Math.round(intensity * 25).toString(16).padStart(2, "0")}` : "rgba(15,19,24,0.6)",
                              boxShadow: active ? `0 0 12px ${tech.color}15` : "none",
                            }}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span
                                className="text-[9px] font-mono font-bold tabular-nums"
                                style={{ color: active ? tech.color : "rgba(148,163,184,0.25)", letterSpacing: "0.06em" }}
                              >
                                {tech.id}
                              </span>
                              <span
                                className="text-[8px] font-mono px-1 py-0.5"
                                style={{
                                  background: active ? `${tech.color}22` : "rgba(148,163,184,0.06)",
                                  color: active ? tech.color : "rgba(148,163,184,0.25)",
                                  border: `1px solid ${active ? tech.color + "33" : "rgba(148,163,184,0.08)"}`,
                                }}
                              >
                                {tech.engineLabel}
                              </span>
                            </div>
                            <p className="text-[9px] font-mono leading-tight" style={{ color: active ? "rgba(226,232,240,0.7)" : "rgba(148,163,184,0.2)" }}>
                              {tech.name}
                            </p>
                            <div className="flex items-center gap-2 mt-0.5">
                              {/* Count bar */}
                              <div className="flex-1 h-1" style={{ background: "rgba(148,163,184,0.06)" }}>
                                {active && (
                                  <div
                                    className="h-full transition-all duration-500"
                                    style={{ width: `${(count / maxCount) * 100}%`, background: tech.color, boxShadow: `0 0 4px ${tech.color}` }}
                                  />
                                )}
                              </div>
                              <span className="text-[10px] font-mono tabular-nums font-semibold shrink-0" style={{ color: active ? tech.color : "rgba(148,163,184,0.2)" }}>
                                {active ? count.toLocaleString() : "—"}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="px-5 py-1.5 border-t flex items-center" style={{ borderColor: "rgba(139,92,246,0.08)" }}>
            <span className="text-[8px] font-mono" style={{ color: "rgba(148,163,184,0.25)" }}>{t("mitre.footerNote")}</span>
          </div>
        </div>
      )}
    </>
  );
}
