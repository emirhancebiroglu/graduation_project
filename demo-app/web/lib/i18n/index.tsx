"use client";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import tr from "./messages/tr.json";
import en from "./messages/en.json";

export type Locale = "tr" | "en";

const DICTIONARIES = { tr, en } as const;
const STORAGE_KEY = "stratosai.locale";
const DEFAULT_LOCALE: Locale = "tr";

type Dict = typeof tr;

type I18nContextValue = {
  locale: Locale;
  setLocale: (l: Locale) => void;
  dict: Dict;
};

const I18nContext = createContext<I18nContextValue | null>(null);

function isLocale(v: unknown): v is Locale {
  return v === "tr" || v === "en";
}

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(DEFAULT_LOCALE);

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (isLocale(stored) && stored !== locale) setLocaleState(stored);
    } catch {
      // ignore
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const setLocale = useCallback((l: Locale) => {
    setLocaleState(l);
    try {
      window.localStorage.setItem(STORAGE_KEY, l);
    } catch {
      // ignore
    }
    if (typeof document !== "undefined") {
      document.documentElement.lang = l;
    }
  }, []);

  useEffect(() => {
    if (typeof document !== "undefined") document.documentElement.lang = locale;
  }, [locale]);

  const value = useMemo<I18nContextValue>(
    () => ({ locale, setLocale, dict: DICTIONARIES[locale] }),
    [locale, setLocale],
  );

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

function getByPath(obj: unknown, path: string): unknown {
  return path.split(".").reduce<unknown>((acc, part) => {
    if (acc && typeof acc === "object" && part in (acc as Record<string, unknown>)) {
      return (acc as Record<string, unknown>)[part];
    }
    return undefined;
  }, obj);
}

function interpolate(template: string, vars?: Record<string, string | number>): string {
  if (!vars) return template;
  return template.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? String(vars[k]) : `{${k}}`));
}

export function useT() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useT must be used within I18nProvider");

  const t = useCallback(
    (key: string, vars?: Record<string, string | number>): string => {
      const v = getByPath(ctx.dict, key);
      if (typeof v === "string") return interpolate(v, vars);
      return "";
    },
    [ctx.dict],
  );

  return { t, locale: ctx.locale, setLocale: ctx.setLocale };
}

export function useLocale() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useLocale must be used within I18nProvider");
  return { locale: ctx.locale, setLocale: ctx.setLocale };
}
