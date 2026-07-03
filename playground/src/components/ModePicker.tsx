import {
  Listbox,
  ListboxButton,
  ListboxOption,
  ListboxOptions,
} from "@headlessui/react";
import { Check, ChevronDown } from "lucide-react";
import type { ReactElement } from "react";
import { ECOSYSTEMS, type Mode } from "@/lib/modes";
import { cn } from "@/lib/utils";

export interface ModePickerProps {
  readonly activeMode: Mode;
  readonly activeModeId: string;
  readonly onSelect: (id: string) => void;
}

export function ModePicker({
  activeMode,
  activeModeId,
  onSelect,
}: ModePickerProps): ReactElement {
  return (
    <Listbox value={activeModeId} onChange={onSelect}>
      <div className="relative">
        <ListboxButton className="flex h-10 w-full cursor-pointer items-center justify-between gap-3 rounded-sm border border-hairline bg-inset px-3 font-sans text-[13px] font-medium text-ink transition-[border-color,background-color,color] hover:border-hairline-strong focus-visible:outline-none">
          <span className="min-w-0 truncate">{activeMode.label}</span>
          <ChevronDown aria-hidden="true" className="size-4 shrink-0 text-ink-faint" />
        </ListboxButton>
        <ListboxOptions
          anchor="bottom"
          className="z-50 mt-2 max-h-[min(28rem,var(--button-bottom-space))] w-[var(--button-width)] overflow-auto rounded-sm border border-hairline bg-canvas p-1 shadow-2xl shadow-black/45 focus:outline-none"
          modal={false}
        >
          {ECOSYSTEMS.map((ecosystem): ReactElement => (
            <div key={ecosystem.id} className="py-1">
              <div className="px-2 py-1 font-sans text-[10px] font-semibold uppercase tracking-wide text-ink-faint">
                {ecosystem.label}
              </div>
              {ecosystem.modes.map((mode: Mode): ReactElement => (
                <ListboxOption
                  key={mode.id}
                  className={({ focus, selected }): string =>
                    cn(
                      "flex cursor-pointer items-center justify-between gap-3 rounded-xs px-2 py-1.5 font-sans text-[13px]",
                      focus ? "bg-surface text-ink" : "text-ink-muted",
                      selected ? "text-accent" : "",
                    )
                  }
                  value={mode.id}
                >
                  {({ selected }): ReactElement => (
                    <>
                      <span className="min-w-0 truncate">{mode.label}</span>
                      {selected ? <Check aria-hidden="true" className="size-3.5 shrink-0" /> : null}
                    </>
                  )}
                </ListboxOption>
              ))}
            </div>
          ))}
        </ListboxOptions>
      </div>
    </Listbox>
  );
}
