"use client";
import { useLocale, type Locale } from "@/lib/i18n";

const OPTIONS: { value: Locale; label: string }[] = [
  { value: "tr", label: "TR" },
  { value: "en", label: "EN" },
];

export function LanguageToggle() {
  const { locale, setLocale } = useLocale();
  return (
    <div
      className="flex items-center"
      style={{
        border: "1px solid rgba(0,212,255,0.18)",
        background: "rgba(0,212,255,0.03)",
      }}
    >
      {OPTIONS.map((opt) => {
        const active = opt.value === locale;
        return (
          <button
            key={opt.value}
            onClick={() => setLocale(opt.value)}
            aria-pressed={active}
            className="px-2.5 py-1.5 text-[10px] font-mono transition-all"
            style={{
              background: active ? "rgba(0,212,255,0.12)" : "transparent",
              color: active ? "#00d4ff" : "rgba(148,163,184,0.7)",
              letterSpacing: "0.1em",
              boxShadow: active ? "inset 0 0 8px rgba(0,212,255,0.18)" : "none",
              cursor: active ? "default" : "pointer",
            }}
          >
            {opt.label}
          </button>
        );
      })}
    </div>
  );
}
