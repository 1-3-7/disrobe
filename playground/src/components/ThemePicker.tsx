import type { ReactElement } from "react";
import { Moon, Sun, type LucideIcon } from "lucide-react";
import { setTheme, useTheme, type ThemeMode, type ThemeState } from "@/lib/theme";

interface ThemeOption {
  readonly value: ThemeMode;
  readonly label: string;
  readonly Icon: LucideIcon;
}

const OPTIONS: readonly ThemeOption[] = [
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "light", label: "Light", Icon: Sun },
];

export function ThemePicker(): ReactElement {
  const theme: ThemeState = useTheme();
  return (
    <fieldset className="theme-picker">
      <legend className="sr-only">Color theme</legend>
      <div className="flex items-center gap-0.5">
        {OPTIONS.map(({ value, label, Icon }: ThemeOption): ReactElement => (
          <label key={value} className="theme-choice" title={label}>
            <input
              className="peer sr-only"
              type="radio"
              name="color-theme"
              value={value}
              checked={theme.mode === value}
              onChange={(): void => { setTheme(value); }}
            />
            <span className="theme-choice-label">
              <Icon aria-hidden="true" className="size-3.5" />
              <span className="hidden sm:inline">{label}</span>
              <span className="sr-only sm:hidden">{label}</span>
            </span>
          </label>
        ))}
      </div>
      {!theme.persistent && (
        <p className="text-xs text-ink-muted" role="status">Theme applies for this visit.</p>
      )}
    </fieldset>
  );
}
