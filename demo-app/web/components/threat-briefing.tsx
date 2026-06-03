"use client";
import { useEffect, useRef, useState } from "react";
import { useT } from "@/lib/i18n";
import type { ReplayPhase, ScenarioKey, ScenarioPayload } from "@/lib/types";

type Props = {
  replayPhase: ReplayPhase;
  scenarios?: ScenarioPayload[];
  activeScenario?: ScenarioKey;
  onSelectScenario?: (key: ScenarioKey) => void;
};

type Stat = {
  value: string;
  label: string;
  sub: string;
  source: string;
  color: string;
};

const STATS_TR: Stat[] = [
  {
    value: "₺17.000.000",
    label: "KVKK tek ihlal tavan cezası",
    sub: "2026 yılı güncel tutarı — %25.49 artış",
    source: "KVKK Resmi Tebliği 2026",
    color: "#ff3b3b",
  },
  {
    value: "158 gün",
    label: "Ortalama siber ihlal tespit süresi",
    sub: "Tespit edilemeyen her gün = veri sızıntısı büyüyor",
    source: "IBM Cost of Data Breach 2025",
    color: "#f59e0b",
  },
  {
    value: "%52",
    label: "SOC analist zamanı yanlış alarmda harcanıyor",
    sub: "Gerçek tehditler gözden kaçarken ekipler tükeniyor",
    source: "Trend Micro SOC Survey 2025",
    color: "#e879f9",
  },
  {
    value: "%5,1",
    label: "LockBit fidye yazılım kurbanları Türkiye'den",
    sub: "Q1 2026 — Türkiye yükselen hedef konumunda",
    source: "Check Point Research Q1 2026",
    color: "#38bdf8",
  },
  {
    value: "%63",
    label: "Günlük siber uyarılar incelenmeden geçiyor",
    sub: "Kuruluşlar ortalama günde 2.992 uyarı alıyor",
    source: "AI SOC Market Report 2025",
    color: "#34d399",
  },
];

const STATS_EN: Stat[] = [
  {
    value: "₺17,000,000",
    label: "KVKK maximum single-breach fine",
    sub: "2026 updated amount — 25.49% increase",
    source: "KVKK Official Gazette 2026",
    color: "#ff3b3b",
  },
  {
    value: "158 days",
    label: "Average breach detection time",
    sub: "Every undetected day = growing data exfiltration",
    source: "IBM Cost of Data Breach 2025",
    color: "#f59e0b",
  },
  {
    value: "52%",
    label: "SOC analyst time lost to false positives",
    sub: "Real threats slip through while teams burn out",
    source: "Trend Micro SOC Survey 2025",
    color: "#e879f9",
  },
  {
    value: "5.1%",
    label: "LockBit ransomware victims from Turkey",
    sub: "Q1 2026 — Turkey is an increasingly targeted market",
    source: "Check Point Research Q1 2026",
    color: "#38bdf8",
  },
  {
    value: "63%",
    label: "Daily security alerts go unreviewed",
    sub: "Organizations receive avg. 2,992 alerts per day",
    source: "AI SOC Market Report 2025",
    color: "#34d399",
  },
];

const DISPLAY_MS = 7000;
const FADE_MS = 500;

const SCENARIO_COLOR: Record<ScenarioKey, string> = {
  dos: "#ff3b3b",
  ddos: "#f97316",
  portscan: "#a855f7",
  bruteforce: "#facc15",
  bot: "#ec4899",
};

export function ThreatBriefing({ replayPhase, scenarios, activeScenario, onSelectScenario }: Props) {
  const { locale } = useT();
  const STATS = locale === "tr" ? STATS_TR : STATS_EN;

  const [idx, setIdx] = useState(0);
  const [phase, setPhase] = useState<"in" | "hold" | "out">("in");
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (replayPhase !== "idle") return;

    function advance() {
      setPhase("out");
      timerRef.current = setTimeout(() => {
        setIdx((i) => (i + 1) % STATS.length);
        setPhase("in");
        timerRef.current = setTimeout(() => {
          setPhase("hold");
          timerRef.current = setTimeout(advance, DISPLAY_MS);
        }, FADE_MS);
      }, FADE_MS);
    }

    setPhase("in");
    timerRef.current = setTimeout(() => {
      setPhase("hold");
      timerRef.current = setTimeout(advance, DISPLAY_MS);
    }, FADE_MS);

    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [replayPhase, locale]);

  if (replayPhase !== "idle") return null;

  const stat = STATS[idx];
  const animClass = phase === "in" ? "tb-in" : phase === "out" ? "tb-out" : "";

  const heading = locale === "tr"
    ? "SİBER TEHDIT TABLOSU"
    : "CYBER THREAT LANDSCAPE";
  const subheading = locale === "tr"
    ? "Neden StratosAI gerekli?"
    : "Why StratosAI?";
  const ctaLabel = locale === "tr"
    ? "Analizi başlatmak için ▶ BAŞLAT butonuna basın"
    : "Press ▶ RUN ANALYSIS to start the demo";
  const ofLabel = locale === "tr" ? `${idx + 1} / ${STATS.length}` : `${idx + 1} / ${STATS.length}`;

  return (
    <>
      <style>{`
        @keyframes tbIn  { from { opacity:0; transform:translateY(12px); } to { opacity:1; transform:translateY(0); } }
        @keyframes tbOut { from { opacity:1; transform:translateY(0); }    to { opacity:0; transform:translateY(-8px); } }
        .tb-in  { animation: tbIn  ${FADE_MS}ms cubic-bezier(0.16,1,0.3,1) forwards; }
        .tb-out { animation: tbOut ${FADE_MS}ms ease forwards; }
        @keyframes scanline {
          0%   { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        @keyframes tbPulse { 0%,100%{opacity:1} 50%{opacity:0.35} }
        @keyframes progressBar {
          from { width: 0%; }
          to   { width: 100%; }
        }
      `}</style>

      {/* Fullscreen overlay — sits below header (z-30) */}
      <div
        className="fixed inset-0 z-30 flex flex-col items-center justify-center"
        style={{
          background: "rgba(10,12,15,0.97)",
          top: "57px", // header height
        }}
      >
        {/* Scanline effect */}
        <div
          className="pointer-events-none absolute inset-0 overflow-hidden"
          style={{ opacity: 0.025 }}
        >
          <div
            style={{
              position: "absolute",
              left: 0,
              right: 0,
              height: "2px",
              background: "rgba(0,212,255,0.8)",
              animation: "scanline 4s linear infinite",
            }}
          />
        </div>

        {/* Grid background */}
        <div
          className="pointer-events-none absolute inset-0"
          style={{
            backgroundImage: `
              linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px),
              linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)
            `,
            backgroundSize: "40px 40px",
          }}
        />

        {/* Corner brackets */}
        <div className="absolute top-4 left-4 w-8 h-8 border-t-2 border-l-2" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="absolute top-4 right-4 w-8 h-8 border-t-2 border-r-2" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="absolute bottom-4 left-4 w-8 h-8 border-b-2 border-l-2" style={{ borderColor: "rgba(0,212,255,0.3)" }} />
        <div className="absolute bottom-4 right-4 w-8 h-8 border-b-2 border-r-2" style={{ borderColor: "rgba(0,212,255,0.3)" }} />

        {/* Header label */}
        <div className="mb-10 text-center">
          <div className="flex items-center justify-center gap-3 mb-2">
            <div className="w-8 h-px" style={{ background: "rgba(0,212,255,0.3)" }} />
            <span
              className="text-[9px] font-mono tracking-[0.25em] uppercase"
              style={{ color: "rgba(0,212,255,0.5)" }}
            >
              {heading}
            </span>
            <div className="w-8 h-px" style={{ background: "rgba(0,212,255,0.3)" }} />
          </div>
          <span className="text-[11px] font-mono" style={{ color: "rgba(148,163,184,0.35)" }}>
            {subheading}
          </span>
        </div>

        {/* Stat card */}
        <div
          key={`${idx}-${locale}`}
          className={`${animClass} flex flex-col items-center text-center`}
          style={{ maxWidth: "560px", width: "90%" }}
        >
          {/* Big number */}
          <div
            className="text-[72px] font-mono font-bold tabular-nums leading-none mb-4"
            style={{
              color: stat.color,
              textShadow: `0 0 40px ${stat.color}60, 0 0 80px ${stat.color}20`,
              letterSpacing: "-0.02em",
            }}
          >
            {stat.value}
          </div>

          {/* Label */}
          <div
            className="text-[18px] font-mono mb-3"
            style={{ color: "rgba(226,232,240,0.9)", letterSpacing: "0.02em" }}
          >
            {stat.label}
          </div>

          {/* Sub */}
          <div
            className="text-[12px] font-mono mb-6"
            style={{ color: "rgba(148,163,184,0.5)" }}
          >
            {stat.sub}
          </div>

          {/* Source badge */}
          <div
            className="px-3 py-1 text-[9px] font-mono tracking-wider"
            style={{
              border: `1px solid ${stat.color}30`,
              background: `${stat.color}08`,
              color: `${stat.color}70`,
              letterSpacing: "0.1em",
            }}
          >
            {stat.source}
          </div>
        </div>

        {/* Progress dots + counter */}
        <div className="mt-12 flex items-center gap-3">
          {STATS.map((s, i) => (
            <div
              key={i}
              style={{
                width: i === idx ? "24px" : "6px",
                height: "6px",
                background: i === idx ? s.color : "rgba(148,163,184,0.2)",
                boxShadow: i === idx ? `0 0 8px ${s.color}` : "none",
                transition: "all 0.3s ease",
              }}
            />
          ))}
          <span className="ml-2 text-[9px] font-mono" style={{ color: "rgba(148,163,184,0.25)" }}>
            {ofLabel}
          </span>
        </div>

        {/* Progress bar — resets on each stat */}
        <div className="mt-4" style={{ width: "200px", height: "1px", background: "rgba(148,163,184,0.08)" }}>
          <div
            key={`prog-${idx}`}
            style={{
              height: "100%",
              background: stat.color,
              opacity: 0.5,
              animation: `progressBar ${DISPLAY_MS}ms linear forwards`,
            }}
          />
        </div>

        {/* Scenario selector */}
        {scenarios && scenarios.length > 0 && onSelectScenario && (
          <div className="mt-10 flex flex-col items-center gap-2">
            <span className="text-[10px] font-mono tracking-[0.2em] uppercase" style={{ color: "rgba(0,212,255,0.6)" }}>
              {locale === "tr" ? "senaryo seçin" : "select scenario"}
            </span>
            <div className="flex flex-wrap justify-center gap-2">
              {scenarios.map((s) => {
                const color = SCENARIO_COLOR[s.key];
                const isActive = s.key === activeScenario;
                return (
                  <button
                    key={s.key}
                    type="button"
                    onClick={() => onSelectScenario(s.key)}
                    className="px-3 py-1.5 text-[10px] font-mono tracking-wider uppercase transition-all"
                    style={{
                      border: `1px solid ${isActive ? color : `${color}40`}`,
                      background: isActive ? `${color}18` : "rgba(15,19,24,0.6)",
                      color: isActive ? color : `${color}80`,
                      boxShadow: isActive ? `0 0 10px ${color}30` : "none",
                    }}
                  >
                    {isActive && <span style={{ marginRight: "4px" }}>●</span>}
                    {s.display.attack_label}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* CTA */}
        <div className="mt-6 flex items-center gap-2">
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: "#00d4ff", animation: "tbPulse 1.5s infinite" }}
          />
          <span className="text-[10px] font-mono" style={{ color: "rgba(0,212,255,0.4)" }}>
            {ctaLabel}
          </span>
        </div>
      </div>
    </>
  );
}
