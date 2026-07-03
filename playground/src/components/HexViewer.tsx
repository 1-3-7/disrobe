import { Search } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactElement,
} from "react";
import { cn } from "@/lib/utils";

export interface HexRange {
  readonly start: number;
  readonly end: number;
  readonly label?: string;
}

export interface HexViewerProps {
  readonly bytes: Uint8Array;
  readonly name?: string;
  readonly ranges?: readonly HexRange[];
  readonly bytesPerRow?: number;
  readonly rowHeight?: number;
  readonly viewportRows?: number;
}

interface Selection {
  readonly anchor: number;
  readonly head: number;
}

function selectionBounds(selection: Selection): readonly [number, number] {
  return selection.anchor <= selection.head
    ? [selection.anchor, selection.head]
    : [selection.head, selection.anchor];
}

function offsetHex(offset: number, width: number): string {
  return offset.toString(16).padStart(width, "0");
}

function byteHex(value: number): string {
  return value.toString(16).padStart(2, "0");
}

function printable(value: number): string {
  return value >= 0x20 && value <= 0x7e ? String.fromCharCode(value) : ".";
}

function parseSearch(query: string): { bytes: Uint8Array; kind: "hex" | "ascii" } | null {
  const trimmed: string = query.trim();
  if (trimmed.length === 0) {
    return null;
  }
  const hexCandidate: string = trimmed.replace(/^0x/i, "").replace(/\s+/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexCandidate) && hexCandidate.length % 2 === 0) {
    const out: Uint8Array = new Uint8Array(hexCandidate.length / 2);
    for (let i: number = 0; i < out.length; i += 1) {
      out[i] = Number.parseInt(hexCandidate.slice(i * 2, i * 2 + 2), 16);
    }
    return { bytes: out, kind: "hex" };
  }
  return { bytes: new TextEncoder().encode(trimmed), kind: "ascii" };
}

function findNext(haystack: Uint8Array, needle: Uint8Array, from: number): number {
  if (needle.length === 0 || needle.length > haystack.length) {
    return -1;
  }
  const limit: number = haystack.length - needle.length;
  for (let start: number = Math.max(0, from); start <= limit; start += 1) {
    let matched: boolean = true;
    for (let j: number = 0; j < needle.length; j += 1) {
      if (haystack[start + j] !== needle[j]) {
        matched = false;
        break;
      }
    }
    if (matched) {
      return start;
    }
  }
  return -1;
}

function rangeFor(offset: number, ranges: readonly HexRange[]): HexRange | undefined {
  return ranges.find((range: HexRange): boolean => offset >= range.start && offset < range.end);
}

const ROW_OVERHEAD_PX: number = 140;
const HEX_CELL_PX: number = 20;
const ASCII_CELL_PX: number = 10;

function fitBytesPerRow(width: number, max: number): number {
  if (width <= 0) {
    return max;
  }
  const perByte: number = HEX_CELL_PX + ASCII_CELL_PX;
  const fits: number = Math.floor((width - ROW_OVERHEAD_PX) / perByte);
  const clamped: number = Math.max(8, Math.min(max, fits));
  return clamped >= 16 ? 16 : 8;
}

export function HexViewer({
  bytes,
  name = "",
  ranges = [],
  bytesPerRow = 16,
  rowHeight = 20,
  viewportRows = 24,
}: HexViewerProps): ReactElement {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState<number>(0);
  const [columns, setColumns] = useState<number>(bytesPerRow);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);
  const [query, setQuery] = useState<string>("");
  const [matchOffset, setMatchOffset] = useState<number | null>(null);

  useEffect((): (() => void) | undefined => {
    const node: HTMLDivElement | null = containerRef.current;
    if (node === null || typeof ResizeObserver === "undefined") {
      return undefined;
    }
    const observer: ResizeObserver = new ResizeObserver((entries: readonly ResizeObserverEntry[]): void => {
      const entry: ResizeObserverEntry | undefined = entries[0];
      if (entry === undefined) {
        return;
      }
      setColumns(fitBytesPerRow(entry.contentRect.width, bytesPerRow));
    });
    observer.observe(node);
    return (): void => {
      observer.disconnect();
    };
  }, [bytesPerRow]);

  const effectiveBytesPerRow: number = columns;
  const total: number = bytes.byteLength;
  const rowCount: number = Math.max(1, Math.ceil(total / effectiveBytesPerRow));
  const offsetWidth: number = Math.max(6, Math.ceil(Math.log2(Math.max(total, 1)) / 4));
  const totalHeight: number = rowCount * rowHeight;

  const firstVisibleRow: number = Math.max(0, Math.floor(scrollTop / rowHeight) - 4);
  const lastVisibleRow: number = Math.min(rowCount, firstVisibleRow + viewportRows + 8);

  const onScroll = useCallback((): void => {
    const node: HTMLDivElement | null = scrollRef.current;
    if (node !== null) {
      setScrollTop(node.scrollTop);
    }
  }, []);

  const scrollToByte = useCallback(
    (offset: number): void => {
      const node: HTMLDivElement | null = scrollRef.current;
      if (node === null) {
        return;
      }
      const targetRow: number = Math.floor(offset / effectiveBytesPerRow);
      const targetTop: number = targetRow * rowHeight;
      const viewHeight: number = node.clientHeight;
      if (targetTop < node.scrollTop || targetTop > node.scrollTop + viewHeight - rowHeight) {
        node.scrollTop = Math.max(0, targetTop - viewHeight / 2);
      }
    },
    [effectiveBytesPerRow, rowHeight],
  );

  const matchLength: number = useMemo((): number => {
    const parsed: { bytes: Uint8Array } | null = parseSearch(query);
    return parsed === null ? 0 : parsed.bytes.length;
  }, [query]);

  const runSearch = useCallback(
    (from: number): void => {
      const parsed: { bytes: Uint8Array; kind: "hex" | "ascii" } | null = parseSearch(query);
      if (parsed === null) {
        setMatchOffset(null);
        return;
      }
      let found: number = findNext(bytes, parsed.bytes, from);
      if (found === -1 && from > 0) {
        found = findNext(bytes, parsed.bytes, 0);
      }
      if (found === -1) {
        setMatchOffset(null);
        return;
      }
      setMatchOffset(found);
      setSelection({ anchor: found, head: found + parsed.bytes.length - 1 });
      scrollToByte(found);
    },
    [bytes, query, scrollToByte],
  );

  function selectByte(offset: number, extend: boolean): void {
    setSelection((current: Selection | null): Selection => {
      if (extend && current !== null) {
        return { anchor: current.anchor, head: offset };
      }
      return { anchor: offset, head: offset };
    });
  }

  function onGridKeyDown(event: KeyboardEvent<HTMLDivElement>): void {
    if (selection === null) {
      return;
    }
    const step: Record<string, number> = {
      ArrowLeft: -1,
      ArrowRight: 1,
      ArrowUp: -effectiveBytesPerRow,
      ArrowDown: effectiveBytesPerRow,
    };
    const delta: number | undefined = step[event.key];
    if (delta === undefined) {
      return;
    }
    event.preventDefault();
    const next: number = Math.min(total - 1, Math.max(0, selection.head + delta));
    setSelection({ anchor: event.shiftKey ? selection.anchor : next, head: next });
    scrollToByte(next);
  }

  useEffect((): void => {
    setSelection(null);
    setMatchOffset(null);
    setScrollTop(0);
    const node: HTMLDivElement | null = scrollRef.current;
    if (node !== null) {
      node.scrollTop = 0;
    }
  }, [bytes]);

  const bounds: readonly [number, number] | null = selection === null ? null : selectionBounds(selection);
  const selectionLength: number = bounds === null ? 0 : bounds[1] - bounds[0] + 1;

  const rows: ReactElement[] = [];
  for (let row: number = firstVisibleRow; row < lastVisibleRow; row += 1) {
    const base: number = row * effectiveBytesPerRow;
    const hexCells: ReactElement[] = [];
    const asciiCells: ReactElement[] = [];
    for (let col: number = 0; col < effectiveBytesPerRow; col += 1) {
      const offset: number = base + col;
      if (offset >= total) {
        hexCells.push(
          <span key={`h-${offset}`} className="inline-block w-[1.25rem] text-center text-transparent">
            00
          </span>,
        );
        continue;
      }
      const value: number = bytes[offset] ?? 0;
      const selected: boolean = bounds !== null && offset >= bounds[0] && offset <= bounds[1];
      const isHovered: boolean = hovered === offset;
      const inMatch: boolean =
        matchOffset !== null && offset >= matchOffset && offset < matchOffset + matchLength;
      const field: HexRange | undefined = rangeFor(offset, ranges);
      const cellClass: string = cn(
        "inline-block w-[1.25rem] cursor-pointer rounded-xs text-center",
        col === effectiveBytesPerRow / 2 - 1 ? "mr-2" : "",
        selected
          ? "bg-accent/30 text-ink"
          : inMatch
            ? "bg-yellow/25 text-ink"
            : isHovered
              ? "bg-hairline-strong/60 text-ink"
              : field !== undefined
                ? "text-cyan"
                : "text-ink-muted",
      );
      hexCells.push(
        <span
          key={`h-${offset}`}
          className={cellClass}
          data-offset={offset}
          title={field?.label}
          onClick={(event): void => {
            selectByte(offset, event.shiftKey);
          }}
          onMouseEnter={(): void => {
            setHovered(offset);
          }}
          onMouseLeave={(): void => {
            setHovered(null);
          }}
        >
          {byteHex(value)}
        </span>,
      );
      asciiCells.push(
        <span
          key={`a-${offset}`}
          className={cn(
            "inline-block w-[0.6rem] cursor-pointer text-center",
            selected
              ? "bg-accent/30 text-ink"
              : inMatch
                ? "bg-yellow/25 text-ink"
                : isHovered
                  ? "bg-hairline-strong/60 text-ink"
                  : field !== undefined
                    ? "text-cyan"
                    : "text-ink-faint",
          )}
          data-offset={offset}
          onClick={(event): void => {
            selectByte(offset, event.shiftKey);
          }}
          onMouseEnter={(): void => {
            setHovered(offset);
          }}
          onMouseLeave={(): void => {
            setHovered(null);
          }}
        >
          {printable(value)}
        </span>,
      );
    }
    rows.push(
      <div
        key={row}
        className="absolute left-0 flex w-max items-center gap-4 px-3 whitespace-nowrap"
        style={{ top: row * rowHeight, height: rowHeight }}
      >
        <span className="shrink-0 text-ink-faint">{offsetHex(base, offsetWidth)}</span>
        <span className="shrink-0">{hexCells}</span>
        <span className="shrink-0 border-l border-hairline pl-3">{asciiCells}</span>
      </div>,
    );
  }

  return (
    <div
      ref={containerRef}
      className="flex min-h-0 flex-col overflow-hidden rounded-sm border border-hairline bg-inset"
    >
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-hairline bg-surface px-3 py-1.5">
        <span className="min-w-0 truncate font-sans text-[11px] font-medium uppercase tracking-wide text-ink-faint">
          {name || "hex view"}
        </span>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5 rounded-sm border border-hairline bg-inset px-2">
            <Search aria-hidden="true" className="size-3 text-ink-faint" />
            <input
              aria-label="Search hex or ascii"
              className="w-36 bg-transparent py-1 font-mono text-[11px] text-ink placeholder:text-ink-faint focus:outline-none"
              placeholder="hex or text"
              spellCheck={false}
              value={query}
              onChange={(event): void => {
                setQuery(event.currentTarget.value);
              }}
              onKeyDown={(event): void => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  runSearch(matchOffset === null ? 0 : matchOffset + 1);
                }
              }}
            />
          </div>
        </div>
      </div>

      <div
        ref={scrollRef}
        aria-label={`hex bytes for ${name || "input"}`}
        className="panel-scroll relative min-h-0 overflow-auto font-mono text-[12px] leading-none"
        role="grid"
        style={{ maxHeight: viewportRows * rowHeight }}
        tabIndex={0}
        onKeyDown={onGridKeyDown}
        onScroll={onScroll}
      >
        <div className="relative w-max min-w-full" style={{ height: totalHeight }}>
          {rows}
        </div>
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-x-4 gap-y-1 border-t border-hairline bg-surface px-3 py-1.5 font-mono text-[11px] text-ink-faint">
        <span>{total.toLocaleString()} bytes</span>
        {bounds !== null ? (
          <>
            <span className="text-ink-muted">
              offset 0x{offsetHex(bounds[0], offsetWidth)}
            </span>
            <span className="text-ink-muted">selection {selectionLength}</span>
          </>
        ) : (
          <span>click a byte to select</span>
        )}
        {query.length > 0 ? (
          <span className={matchOffset === null ? "text-warn" : "text-accent"}>
            {matchOffset === null ? "no match" : `match @ 0x${offsetHex(matchOffset, offsetWidth)}`}
          </span>
        ) : null}
      </div>
    </div>
  );
}
