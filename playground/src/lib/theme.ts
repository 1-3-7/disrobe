import { useSyncExternalStore } from "react";

export type ThemeMode = "light" | "dark";

export interface ThemeState {
  readonly mode: ThemeMode;
  readonly persistent: boolean;
}

const STORAGE_KEY: string = "disrobe.theme";
const listeners: Set<() => void> = new Set<() => void>();
let state: ThemeState = { mode: "dark", persistent: true };

function modeFrom(value: string | null): ThemeMode {
  return value === "light" ? "light" : "dark";
}

function isStorageRestriction(error: unknown): boolean {
  return error instanceof DOMException &&
    (error.name === "SecurityError" || error.name === "QuotaExceededError");
}

function applyTheme(mode: ThemeMode, persistent: boolean): void {
  state = { mode, persistent };
  document.documentElement.dataset["theme"] = mode;
  const icon: HTMLLinkElement | null = document.querySelector('link[rel="icon"]');
  if (icon !== null) {
    icon.href = `${import.meta.env.BASE_URL}brand/mark-${mode}.svg`;
  }
  for (const listener of listeners) {
    listener();
  }
  for (const animation of document.getAnimations()) {
    if (animation instanceof CSSTransition && animation.transitionProperty.endsWith("color")) {
      animation.finish();
    }
  }
}

export function initTheme(): void {
  let mode: ThemeMode = "dark";
  let persistent: boolean = true;
  let storage: Storage | null = null;
  try {
    storage = window.localStorage;
    mode = modeFrom(storage.getItem(STORAGE_KEY));
  } catch (error: unknown) {
    if (!isStorageRestriction(error)) throw error;
    persistent = false;
  }
  applyTheme(mode, persistent);
  window.addEventListener("storage", (event: StorageEvent): void => {
    if (storage !== null && event.storageArea === storage &&
      (event.key === STORAGE_KEY || event.key === null)) {
      applyTheme(modeFrom(event.newValue), true);
    }
  });
}

export function setTheme(mode: ThemeMode): void {
  let persistent: boolean = true;
  try {
    window.localStorage.setItem(STORAGE_KEY, mode);
  } catch (error: unknown) {
    if (!isStorageRestriction(error)) throw error;
    persistent = false;
  }
  applyTheme(mode, persistent);
}

export function currentTheme(): ThemeState {
  return state;
}

export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return (): void => { listeners.delete(listener); };
}

export function useTheme(): ThemeState {
  return useSyncExternalStore(subscribeTheme, currentTheme);
}
