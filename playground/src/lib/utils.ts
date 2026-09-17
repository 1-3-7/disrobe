import { clsx, type ClassValue } from "clsx";
import { useCallback, useState } from "react";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: readonly ClassValue[]): string {
  return twMerge(clsx(inputs));
}

function readStoredBoolean(key: string, fallback: boolean): boolean {
  try {
    const raw: string | null = window.localStorage.getItem(key);
    if (raw === null) {
      return fallback;
    }
    return raw === "true";
  } catch {
    return fallback;
  }
}

export function usePersistentBoolean(
  key: string,
  fallback: boolean,
): readonly [boolean, (next: boolean) => void] {
  const [value, setValue] = useState<boolean>((): boolean => readStoredBoolean(key, fallback));
  const update = useCallback(
    (next: boolean): void => {
      setValue(next);
      try {
        window.localStorage.setItem(key, String(next));
      } catch {
        setValue(next);
      }
    },
    [key],
  );
  return [value, update];
}
