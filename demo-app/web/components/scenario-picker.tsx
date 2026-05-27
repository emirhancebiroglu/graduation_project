"use client";
import type { ReactElement } from "react";
import { useT } from "@/lib/i18n";
import type { ScenarioKey, ScenarioPayload, ReplayPhase } from "@/lib/types";

type Props = {
  scenarios: ScenarioPayload[];
  activeScenario: ScenarioKey;
  onSelect: (key: ScenarioKey) => void;
  replayPhase: ReplayPhase;
};

const SCENARIO_COLOR: Record<ScenarioKey, string> = {
  dos: "#ff3b3b",
  ddos: "#f97316",
  portscan: "#a855f7",
  bruteforce: "#facc15",
  bot: "#ec4899",
};

const SCENARIO_ICON: Record<ScenarioKey, ReactElement> = {
  dos: (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <path d="M9 1 L17 5 L17 13 L9 17 L1 13 L1 5 Z" stroke="currentColor" strokeWidth="1.2" fill="currentColor" fillOpacity="0.15" />
      <path d="M9 5 L13 7 L13 11 L9 13 L5 11 L5 7 Z" fill="currentColor" />
    </svg>
  ),
  ddos: (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <circle cx="9" cy="9" r="2" fill="currentColor" />
      <circle cx="3" cy="3" r="1.4" fill="currentColor" />
      <circle cx="15" cy="3" r="1.4" fill="currentColor" />
      <circle cx="3" cy="15" r="1.4" fill="currentColor" />
      <circle cx="15" cy="15" r="1.4" fill="currentColor" />
      <line x1="4" y1="4" x2="8" y2="8" stroke="currentColor" strokeWidth="1" />
      <line x1="14" y1="4" x2="10" y2="8" stroke="currentColor" strokeWidth="1" />
      <line x1="4" y1="14" x2="8" y2="10" stroke="currentColor" strokeWidth="1" />
      <line x1="14" y1="14" x2="10" y2="10" stroke="currentColor" strokeWidth="1" />
    </svg>
  ),
  portscan: (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <rect x="1" y="1" width="3" height="3" fill="currentColor" />
      <rect x="7" y="1" width="3" height="3" fill="currentColor" fillOpacity="0.6" />
      <rect x="13" y="1" width="3" height="3" fill="currentColor" fillOpacity="0.3" />
      <rect x="1" y="7" width="3" height="3" fill="currentColor" fillOpacity="0.6" />
      <rect x="7" y="7" width="3" height="3" fill="currentColor" />
      <rect x="13" y="7" width="3" height="3" fill="currentColor" fillOpacity="0.6" />
      <rect x="1" y="13" width="3" height="3" fill="currentColor" fillOpacity="0.3" />
      <rect x="7" y="13" width="3" height="3" fill="currentColor" fillOpacity="0.6" />
      <rect x="13" y="13" width="3" height="3" fill="currentColor" />
    </svg>
  ),
  bruteforce: (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <circle cx="6" cy="9" r="3.5" stroke="currentColor" strokeWidth="1.2" fill="currentColor" fillOpacity="0.15" />
      <line x1="9.5" y1="9" x2="16" y2="9" stroke="currentColor" strokeWidth="1.2" />
      <line x1="13" y1="9" x2="13" y2="12" stroke="currentColor" strokeWidth="1.2" />
      <line x1="15" y1="9" x2="15" y2="11" stroke="currentColor" strokeWidth="1.2" />
    </svg>
  ),
  bot: (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
      <rect x="3" y="5" width="12" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.2" fill="currentColor" fillOpacity="0.15" />
      <circle cx="7" cy="9" r="1.2" fill="currentColor" />
      <circle cx="11" cy="9" r="1.2" fill="currentColor" />
      <line x1="9" y1="2" x2="9" y2="5" stroke="currentColor" strokeWidth="1.2" />
      <circle cx="9" cy="2" r="0.8" fill="currentColor" />
    </svg>
  ),
};

function ScenarioCard({
  scenario,
  active,
  disabled,
  onClick,
  t,
}: {
  scenario: ScenarioPayload;
  active: boolean;
  disabled: boolean;
  onClick: () => void;
  t: ReturnType<typeof useT>["t"];
}) {
  const color = SCENARIO_COLOR[scenario.key];
  const icon = SCENARIO_ICON[scenario.key];
  const title = t(`scenarios.${scenario.key}.title`) || scenario.display.attack_label;
  const description = t(`scenarios.${scenario.key}.description`) || "";
  const modelLine = t(`scenarios.${scenario.key}.modelLine`) || "";
  const chip = t(`scenarios.${scenario.key}.generalizationChip`) || scenario.display.generalization_chip;

  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onClick}
      aria-pressed={active}
      className="relative text-left transition-all disabled:cursor-not-allowed group"
      style={{
        flex: "1 1 0",
        minWidth: "180px",
        padding: "12px 14px",
        border: `1px solid ${active ? color : "rgba(0,212,255,0.12)"}`,
        background: active
          ? `linear-gradient(180deg, ${color}14 0%, rgba(15,19,24,0.95) 100%)`
          : "rgba(15,19,24,0.7)",
        boxShadow: active ? `0 0 0 1px ${color}40, 0 0 18px ${color}25, inset 0 1px 0 ${color}30` : "none",
        opacity: disabled && !active ? 0.5 : 1,
      }}
    >
      {/* corner brackets */}
      <span
        className="absolute top-0 left-0 w-2 h-2 border-t border-l"
        style={{ borderColor: active ? color : "rgba(0,212,255,0.3)" }}
      />
      <span
        className="absolute bottom-0 right-0 w-2 h-2 border-b border-r"
        style={{ borderColor: active ? color : "rgba(0,212,255,0.3)" }}
      />

      {/* header row */}
      <div className="flex items-center gap-2 mb-1.5">
        <span style={{ color }}>{icon}</span>
        <span
          className="text-[11px] font-mono font-semibold tracking-widest uppercase"
          style={{ color: active ? color : "rgba(226,232,240,0.85)" }}
        >
          {title}
        </span>
        {active && (
          <span
            className="ml-auto w-1.5 h-1.5 rounded-full"
            style={{ background: color, boxShadow: `0 0 6px ${color}` }}
          />
        )}
      </div>

      {/* description */}
      <p className="text-[10px] mb-2 leading-relaxed" style={{ color: "rgba(148,163,184,0.75)" }}>
        {description}
      </p>

      {/* model line */}
      <p
        className="text-[9px] font-mono mb-1.5 tracking-wider uppercase"
        style={{ color: active ? `${color}cc` : "rgba(0,212,255,0.55)" }}
      >
        {modelLine}
      </p>

      {/* generalization chip */}
      <div
        className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono"
        style={{
          border: `1px solid ${color}40`,
          background: `${color}10`,
          color: `${color}dd`,
          letterSpacing: "0.05em",
        }}
      >
        <span style={{ color }}>●</span>
        {chip}
      </div>
    </button>
  );
}

export function ScenarioPicker({ scenarios, activeScenario, onSelect, replayPhase }: Props) {
  const { t } = useT();
  // Lock only during active replay/draining — allow switching after complete
  const disabled = replayPhase === "running" || replayPhase === "draining";

  if (scenarios.length === 0) return null;

  return (
    <section
      className="relative"
      style={{ border: "1px solid rgba(0,212,255,0.12)", background: "#0f1318" }}
    >
      <span className="absolute top-0 left-0 w-3 h-3 border-t border-l" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
      <span className="absolute bottom-0 right-0 w-3 h-3 border-b border-r" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

      <div className="flex items-center gap-3 px-5 py-2.5 border-b" style={{ borderColor: "rgba(0,212,255,0.08)" }}>
        <div className="w-1 h-4" style={{ background: "rgba(0,212,255,0.7)", boxShadow: "0 0 8px rgba(0,212,255,0.4)" }} />
        <span className="section-label" style={{ color: "#00d4ff" }}>
          {t("scenarios.title") || "ATTACK SCENARIO"}
        </span>
        <span className="section-label ml-2 text-[9px]" style={{ color: "rgba(0,212,255,0.5)" }}>
          {t("scenarios.subtitle") || "select to load the matching PCAP and frozen baseline"}
        </span>
        {disabled && (
          <span className="section-label ml-auto text-[9px]" style={{ color: "rgba(245,158,11,0.7)" }}>
            {t("scenarios.disabledHint") || "stop replay to switch"}
          </span>
        )}
      </div>

      <div className="flex flex-wrap gap-2 p-3">
        {scenarios.map((s) => (
          <ScenarioCard
            key={s.key}
            scenario={s}
            active={s.key === activeScenario}
            disabled={disabled}
            onClick={() => onSelect(s.key)}
            t={t}
          />
        ))}
      </div>
    </section>
  );
}
