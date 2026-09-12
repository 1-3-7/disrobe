import {
  Combobox,
  ComboboxButton,
  ComboboxInput,
  ComboboxOption,
  ComboboxOptions,
} from "@headlessui/react";
import { Check, ChevronDown } from "lucide-react";
import { useState, type ReactElement } from "react";
import { ECOSYSTEMS, filterEcosystems, type Ecosystem, type Mode } from "@/lib/modes";
import { cn } from "@/lib/utils";

export interface ModePickerProps {
  readonly activeMode: Mode;
  readonly onSelect: (id: string) => void;
}

export function ModePicker({
  activeMode,
  onSelect,
}: ModePickerProps): ReactElement {
  const [query, setQuery] = useState<string>("");
  const filtered: readonly Ecosystem[] = filterEcosystems(ECOSYSTEMS, query);
  return (
    <Combobox
      by="id"
      immediate
      value={activeMode}
      onChange={(mode: Mode | null): void => { if (mode !== null) onSelect(mode.id); }}
      onClose={(): void => { setQuery(""); }}
    >
      <div className="relative">
        <ComboboxInput
          aria-label="Find an analysis mode"
          className="h-10 w-full rounded-sm border border-hairline bg-inset pl-3 pr-10 font-sans text-[13px] font-medium text-ink placeholder:text-ink-faint"
          displayValue={(mode: Mode | null): string => mode?.label ?? ""}
          placeholder="Find a mode…"
          onChange={(event): void => { setQuery(event.currentTarget.value); }}
          onFocus={(event): void => { event.currentTarget.select(); }}
        />
        <ComboboxButton aria-label={activeMode.label} className="absolute inset-y-0 right-0 grid w-10 cursor-pointer place-items-center rounded-sm text-ink-faint hover:text-ink">
          <ChevronDown aria-hidden="true" className="size-4 shrink-0 text-ink-faint" />
        </ComboboxButton>
        <ComboboxOptions
          anchor="bottom"
          className="z-50 mt-2 max-h-[min(28rem,var(--anchor-max-height))] w-[var(--input-width)] overflow-auto rounded-sm border border-hairline bg-canvas p-1 shadow-2xl shadow-black/45 focus:outline-none"
          modal={false}
        >
          {filtered.length === 0 ? (
            <p className="px-3 py-4 font-sans text-[12px] text-ink-muted" role="status">No modes match “{query.trim()}”.</p>
          ) : null}
          {filtered.map((ecosystem: Ecosystem): ReactElement => (
            <div key={ecosystem.id} className="py-1">
              <div className="px-2 py-1 font-sans text-[10px] font-semibold uppercase tracking-wide text-ink-faint">
                {ecosystem.label}
              </div>
              {ecosystem.modes.map((mode: Mode): ReactElement => (
                <ComboboxOption
                  key={mode.id}
                  className={({ focus, selected }): string =>
                    cn(
                      "flex cursor-pointer items-center justify-between gap-3 rounded-xs px-2 py-1.5 font-sans text-[13px]",
                      focus ? "bg-surface text-ink" : "text-ink-muted",
                      selected ? "text-accent" : "",
                    )
                  }
                  value={mode}
                >
                  {({ selected }): ReactElement => (
                    <>
                      <span className="min-w-0 truncate">{mode.label}</span>
                      {selected ? <Check aria-hidden="true" className="size-3.5 shrink-0" /> : null}
                    </>
                  )}
                </ComboboxOption>
              ))}
            </div>
          ))}
        </ComboboxOptions>
      </div>
    </Combobox>
  );
}
