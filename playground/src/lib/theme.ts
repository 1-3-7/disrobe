import { useCallback, useSyncExternalStore } from "react";

export type ThemeVariant = "slate" | "zinc" | "midnight";

export interface ThemeOption {
  readonly id: ThemeVariant;
  readonly label: string;
  readonly swatch: string;
}

export const THEME_STORAGE_KEY: string = "disrobe.theme";

export const DEFAULT_THEME: ThemeVariant = "zinc";

export const THEME_OPTIONS: readonly ThemeOption[] = [
  { id: "midnight", label: "Midnight", swatch: "#86A8F0" },
  { id: "zinc", label: "Graphite", swatch: "#8FB3D9" },
  { id: "slate", label: "Sage", swatch: "#9EC5A8" },
];

const THEME_IDS: ReadonlySet<string> = new Set<string>(["slate", "zinc", "midnight"]);

interface FaviconColors {
  readonly fill: string;
  readonly stroke: string;
}

const FAVICON_COLORS: Readonly<Record<ThemeVariant, FaviconColors>> = {
  zinc: { fill: "#161616", stroke: "#8fb3d9" },
  slate: { fill: "#1a1815", stroke: "#9ec5a8" },
  midnight: { fill: "#10141f", stroke: "#86a8f0" },
};

export function faviconDataUri(theme: ThemeVariant): string {
  const { fill, stroke }: FaviconColors = FAVICON_COLORS[theme];
  const svg: string =
    `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>` +
    `<rect width='32' height='32' rx='7' fill='${fill}'/>` +
    `<g fill='none' stroke='${stroke}' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'>` +
    `<path d='M13 8c-2.4 0-3 1.2-3 3v2.6c0 1.4-.7 2.4-2 2.4 1.3 0 2 1 2 2.4V24c0 1.8.6 3 3 3'/>` +
    `<path d='M19 8c2.4 0 3 1.2 3 3v2.6c0 1.4.7 2.4 2 2.4-1.3 0-2 1-2 2.4V24c0 1.8-.6 3-3 3'/>` +
    `</g></svg>`;
  return `data:image/svg+xml,${encodeURIComponent(svg)}`;
}

function applyFavicon(theme: ThemeVariant): void {
  if (typeof document === "undefined") {
    return;
  }
  const link: HTMLLinkElement | null =
    document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (link === null) {
    return;
  }
  link.href = faviconDataUri(theme);
}

export function isThemeVariant(value: string | null): value is ThemeVariant {
  return value !== null && THEME_IDS.has(value);
}

export function readStoredTheme(): ThemeVariant {
  try {
    const raw: string | null = window.localStorage.getItem(THEME_STORAGE_KEY);
    return isThemeVariant(raw) ? raw : DEFAULT_THEME;
  } catch {
    return DEFAULT_THEME;
  }
}

const listeners: Set<() => void> = new Set<() => void>();

function emit(): void {
  for (const listener of listeners) {
    listener();
  }
}

export function applyTheme(variant: ThemeVariant): void {
  if (typeof document === "undefined") {
    return;
  }
  document.documentElement.setAttribute("data-theme", variant);
  emit();
}

export function setTheme(variant: ThemeVariant): void {
  applyTheme(variant);
  applyFavicon(variant);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, variant);
  } catch {
    return;
  }
}

export function initFavicon(): void {
  applyFavicon(currentTheme());
}

export function currentTheme(): ThemeVariant {
  if (typeof document === "undefined") {
    return DEFAULT_THEME;
  }
  const attr: string | null = document.documentElement.getAttribute("data-theme");
  return isThemeVariant(attr) ? attr : DEFAULT_THEME;
}

export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return (): void => {
    listeners.delete(listener);
  };
}

export function useTheme(): readonly [ThemeVariant, (next: ThemeVariant) => void] {
  const variant: ThemeVariant = useSyncExternalStore(
    subscribeTheme,
    currentTheme,
    (): ThemeVariant => DEFAULT_THEME,
  );
  const update = useCallback((next: ThemeVariant): void => {
    setTheme(next);
  }, []);
  return [variant, update];
}
