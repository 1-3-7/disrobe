import { PanelLeftClose, PanelLeftOpen, Search } from "lucide-react";
import { useState, type ReactElement } from "react";
import { filterEcosystems, type Ecosystem, type Mode } from "@/lib/modes";
import { cn } from "@/lib/utils";

export interface SidebarProps {
  readonly ecosystems: readonly Ecosystem[];
  readonly activeModeId: string;
  readonly collapsed: boolean;
  readonly onToggle: () => void;
  readonly onSelect: (id: string) => void;
}

export function Sidebar({
  ecosystems,
  activeModeId,
  collapsed,
  onToggle,
  onSelect,
}: SidebarProps): ReactElement {
  const [query, setQuery] = useState<string>("");
  const filtered: readonly Ecosystem[] = filterEcosystems(ecosystems, query);
  return (
    <aside
      className={cn(
        "hidden min-h-0 border-r border-hairline transition-[width] duration-200 ease-out lg:block",
        collapsed ? "w-[52px]" : "w-[248px]",
      )}
      data-collapsed={collapsed ? "true" : "false"}
    >
      <div className="flex h-full min-h-0 flex-col">
        <div
          className={cn(
            "flex shrink-0 items-center border-b border-hairline px-2 py-2",
            collapsed ? "justify-center" : "justify-between",
          )}
        >
          {collapsed ? null : (
            <span className="pl-1 font-sans text-[10px] font-semibold uppercase tracking-wide text-ink-faint">
              modes
            </span>
          )}
          <button
            aria-controls="mode-nav"
            aria-expanded={!collapsed}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className="grid size-8 shrink-0 cursor-pointer place-items-center rounded-sm border border-transparent text-ink-faint transition-[background-color,border-color,color] hover:border-hairline hover:bg-surface hover:text-ink"
            type="button"
            onClick={onToggle}
          >
            {collapsed ? (
              <PanelLeftOpen aria-hidden="true" className="size-4" />
            ) : (
              <PanelLeftClose aria-hidden="true" className="size-4" />
            )}
          </button>
        </div>

        {collapsed ? null : (
          <div className="relative shrink-0 border-b border-hairline p-3">
            <Search aria-hidden="true" className="pointer-events-none absolute left-5 top-1/2 size-3.5 -translate-y-1/2 text-ink-faint" />
            <input
              aria-label="Filter analysis modes"
              className="h-9 w-full rounded-sm border border-hairline bg-inset pl-8 pr-2 font-sans text-[12px] text-ink placeholder:text-ink-faint"
              placeholder="Find a mode…"
              type="search"
              value={query}
              onChange={(event): void => { setQuery(event.currentTarget.value); }}
              onKeyDown={(event): void => {
                if (event.key === "Escape") setQuery("");
              }}
            />
          </div>
        )}

        {collapsed ? null : (
          <nav
            aria-label="analysis modes"
            className="panel-scroll min-h-0 flex-1 overflow-auto"
            id="mode-nav"
          >
            {filtered.length === 0 ? (
              <p className="px-4 py-5 font-sans text-[12px] text-ink-muted" role="status">No modes match “{query.trim()}”.</p>
            ) : null}
            {filtered.map((ecosystem: Ecosystem): ReactElement => (
              <div
                key={ecosystem.id}
                className="border-b border-hairline px-3 py-3 last:border-b-0"
              >
                <span className="font-sans text-[10px] font-semibold uppercase tracking-wide text-ink-faint">
                  {ecosystem.label}
                </span>
                <ul aria-label={`${ecosystem.label} modes`} className="mt-2 flex flex-col gap-1" role="list">
                  {ecosystem.modes.map((mode: Mode): ReactElement => {
                    const selected: boolean = mode.id === activeModeId;
                    return (
                      <li key={mode.id}>
                        <button
                          aria-current={selected ? "page" : undefined}
                          className={cn(
                            "group w-full cursor-pointer rounded-sm border px-2.5 py-2 text-left transition-[background-color,border-color,color]",
                            selected
                              ? "border-accent/35 bg-accent/[0.08] text-ink"
                              : "border-transparent text-ink-muted hover:border-hairline hover:bg-surface/75 hover:text-ink",
                          )}
                          type="button"
                          onClick={(): void => {
                            onSelect(mode.id);
                          }}
                        >
                          <span className="flex items-center justify-between gap-2">
                            <span className="min-w-0 truncate font-sans text-[13px] font-medium tracking-tight">
                              {mode.label}
                            </span>
                            <span
                              aria-hidden="true"
                              className={cn(
                                "size-1.5 shrink-0 rounded-full transition-colors",
                                selected ? "bg-accent" : "bg-hairline-strong",
                              )}
                            />
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ))}
          </nav>
        )}
      </div>
    </aside>
  );
}
