import { PanelLeftClose, PanelLeftOpen } from "lucide-react";
import type { ReactElement } from "react";
import type { Ecosystem, Mode } from "@/lib/modes";
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
          <nav
            aria-label="analysis modes"
            className="panel-scroll min-h-0 flex-1 overflow-auto"
            id="mode-nav"
          >
            {ecosystems.map((ecosystem: Ecosystem): ReactElement => (
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
