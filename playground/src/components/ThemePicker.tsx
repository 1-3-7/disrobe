import type { ReactElement } from "react";
import { THEME_OPTIONS, useTheme, type ThemeOption, type ThemeVariant } from "@/lib/theme";
import { cn } from "@/lib/utils";

export function ThemePicker(): ReactElement {
  const [variant, setVariant] = useTheme();
  return (
    <div
      aria-label="Color theme"
      className="inline-flex items-center gap-0.5 rounded-sm border border-hairline bg-surface p-0.5"
      role="radiogroup"
    >
      {THEME_OPTIONS.map((option: ThemeOption): ReactElement => {
        const selected: boolean = option.id === variant;
        return (
          <button
            key={option.id}
            aria-checked={selected}
            aria-label={option.label}
            className={cn(
              "inline-flex h-7 cursor-pointer items-center gap-1.5 rounded-xs px-2 font-sans text-[12px] font-medium transition-[background-color,color]",
              selected
                ? "bg-inset text-ink"
                : "text-ink-muted hover:bg-inset/60 hover:text-ink",
            )}
            role="radio"
            title={option.label}
            type="button"
            onClick={(): void => {
              setVariant(option.id as ThemeVariant);
            }}
          >
            <span
              aria-hidden="true"
              className="size-2.5 shrink-0 rounded-full ring-1 ring-inset ring-black/20"
              style={{ backgroundColor: option.swatch }}
            />
            <span className="hidden sm:inline">{option.label}</span>
          </button>
        );
      })}
    </div>
  );
}
