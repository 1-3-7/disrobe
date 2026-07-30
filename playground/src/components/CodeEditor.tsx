import { syntaxHighlighting } from "@codemirror/language";
import { Compartment, EditorState, type Extension } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, type KeyBinding } from "@codemirror/view";
import { Check, Copy, Download } from "lucide-react";
import { useEffect, useRef, useState, type ReactElement } from "react";
import { Button } from "@/components/ui/button";
import {
  buildEditorTheme,
  buildHighlightStyle,
  downloadMetaFor,
  loadLanguage,
  type DownloadMeta,
  type EditorLanguage,
} from "@/lib/editor";
import { subscribeTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";

export interface CodeEditorProps {
  readonly code: string;
  readonly label?: string;
  readonly language?: EditorLanguage;
  readonly badge?: string;
  readonly editable?: boolean;
  readonly fill?: boolean;
  readonly placeholder?: string;
  readonly downloadName?: string;
  readonly onChange?: (value: string) => void;
  readonly onRun?: () => void;
}

function downloadFilename(base: string, extension: string): string {
  const trimmed: string = base.trim().length > 0 ? base.trim() : "disrobe-output";
  const lower: string = trimmed.toLowerCase();
  if (lower.endsWith(`.${extension}`)) {
    return trimmed;
  }
  const lastDot: number = trimmed.lastIndexOf(".");
  const stem: string = lastDot > 0 ? trimmed.slice(0, lastDot) : trimmed;
  return `${stem}.${extension}`;
}

function downloadText(base: string, language: EditorLanguage, text: string): void {
  const meta: DownloadMeta = downloadMetaFor(language);
  const blob: Blob = new Blob([text], { type: meta.mime });
  const url: string = URL.createObjectURL(blob);
  const anchor: HTMLAnchorElement = document.createElement("a");
  anchor.href = url;
  anchor.download = downloadFilename(base, meta.extension);
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function CodeEditor({
  code,
  label = "",
  language = "text",
  badge = "",
  editable = false,
  fill = false,
  placeholder = "",
  downloadName = "",
  onChange,
  onRun,
}: CodeEditorProps): ReactElement {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const languageCompartment = useRef<Compartment>(new Compartment()).current;
  const themeCompartment = useRef<Compartment>(new Compartment()).current;
  const resetHandleRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onChangeRef = useRef<((value: string) => void) | undefined>(onChange);
  const onRunRef = useRef<(() => void) | undefined>(onRun);
  const [copied, setCopied] = useState<boolean>(false);

  onChangeRef.current = onChange;
  onRunRef.current = onRun;

  useEffect((): (() => void) | undefined => {
    const host: HTMLDivElement | null = hostRef.current;
    if (host === null) {
      return undefined;
    }
    const runKeymap: readonly KeyBinding[] = [
      {
        key: "Mod-Enter",
        preventDefault: true,
        run: (): boolean => {
          onRunRef.current?.();
          return true;
        },
      },
    ];
    const updateListener: Extension = EditorView.updateListener.of((update): void => {
      if (update.docChanged) {
        onChangeRef.current?.(update.state.doc.toString());
      }
    });
    const view: EditorView = new EditorView({
      state: EditorState.create({
        doc: code,
        extensions: [
          lineNumbers(),
          keymap.of(runKeymap),
          EditorView.editable.of(editable),
          EditorState.readOnly.of(!editable),
          EditorView.lineWrapping,
          themeCompartment.of([buildEditorTheme(), syntaxHighlighting(buildHighlightStyle())]),
          EditorView.contentAttributes.of(
            placeholder.length > 0 ? { "aria-label": placeholder } : {},
          ),
          updateListener,
          languageCompartment.of([]),
        ],
      }),
      parent: host,
    });
    viewRef.current = view;
    return (): void => {
      view.destroy();
      viewRef.current = null;
    };
  }, [editable, placeholder, languageCompartment, themeCompartment]);

  useEffect((): (() => void) => {
    return subscribeTheme((): void => {
      viewRef.current?.dispatch({
        effects: themeCompartment.reconfigure([
          buildEditorTheme(),
          syntaxHighlighting(buildHighlightStyle()),
        ]),
      });
    });
  }, [themeCompartment]);

  useEffect((): void => {
    const view: EditorView | null = viewRef.current;
    if (view === null || code === view.state.doc.toString()) {
      return;
    }
    view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: code } });
  }, [code]);

  useEffect((): (() => void) => {
    let canceled: boolean = false;
    void loadLanguage(language).then((extension: readonly Extension[]): void => {
      if (canceled) {
        return;
      }
      viewRef.current?.dispatch({
        effects: languageCompartment.reconfigure(extension as Extension[]),
      });
    });
    return (): void => {
      canceled = true;
    };
  }, [language, languageCompartment]);

  useEffect((): (() => void) => {
    return (): void => {
      if (resetHandleRef.current !== null) {
        clearTimeout(resetHandleRef.current);
      }
    };
  }, []);

  async function copyCode(): Promise<void> {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      if (resetHandleRef.current !== null) {
        clearTimeout(resetHandleRef.current);
      }
      resetHandleRef.current = setTimeout((): void => {
        setCopied(false);
      }, 1400);
    } catch {
      setCopied(false);
    }
  }

  const showHeader: boolean = label.length > 0 || badge.length > 0;

  return (
    <div
      className={cn(
        "flex min-h-0 flex-col overflow-hidden rounded-sm border border-hairline bg-inset",
        fill ? "flex-1" : "",
      )}
    >
      {showHeader ? (
        <div className="flex shrink-0 items-center justify-between gap-3 border-b border-hairline bg-surface px-3 py-1.5">
          <span className="min-w-0 truncate font-mono text-[11px] uppercase tracking-normal text-ink-faint">
            {label}
          </span>
          <div className="flex shrink-0 items-center gap-2">
            {badge.length > 0 ? (
              <span className="font-mono text-[11px] text-ink-faint">{badge}</span>
            ) : null}
            {downloadName.length > 0 ? (
              <Button
                aria-label="Download output"
                className="h-6 px-2 text-[11px]"
                size="sm"
                variant="ghost"
                onClick={(): void => {
                  downloadText(downloadName, language, code);
                }}
              >
                <Download aria-hidden="true" className="size-3.5" />
                <span>save</span>
              </Button>
            ) : null}
            <Button
              aria-label={copied ? "Copied code" : "Copy code"}
              className="h-6 px-2 text-[11px]"
              size="sm"
              variant="ghost"
              onClick={(): void => {
                void copyCode();
              }}
            >
              {copied ? <Check aria-hidden="true" className="size-3.5" /> : <Copy aria-hidden="true" className="size-3.5" />}
              <span>{copied ? "copied" : "copy"}</span>
            </Button>
          </div>
        </div>
      ) : null}
      <div ref={hostRef} className="cm-host min-h-0 overflow-auto" data-fill={fill ? "true" : "false"} />
    </div>
  );
}
