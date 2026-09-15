import { syntaxHighlighting } from "@codemirror/language";
import { Annotation, Compartment, EditorState, type AnnotationType, type Extension } from "@codemirror/state";
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
  readonly downloadLabel?: string;
  readonly onChange?: (value: string) => void;
  readonly onRun?: (value: string) => void;
}

const externalDocumentUpdate: AnnotationType<boolean> = Annotation.define<boolean>();

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
  downloadLabel = "Download output",
  onChange,
  onRun,
}: CodeEditorProps): ReactElement {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const viewRef = useRef<EditorView | null>(null);
  const loadedLanguageRef = useRef<readonly Extension[] | null>(null);
  const languageCompartment = useRef<Compartment>(new Compartment()).current;
  const themeCompartment = useRef<Compartment>(new Compartment()).current;
  const resetHandleRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onChangeRef = useRef<((value: string) => void) | undefined>(onChange);
  const onRunRef = useRef<((value: string) => void) | undefined>(onRun);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const [failedLanguage, setFailedLanguage] = useState<EditorLanguage | null>(null);
  const phpSource: string = language === "php" ? code : "";

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
        run: (view: EditorView): boolean => {
          onRunRef.current?.(view.state.doc.toString());
          return true;
        },
      },
    ];
    const updateListener: Extension = EditorView.updateListener.of((update): void => {
      if (update.transactions.some((transaction): boolean =>
        transaction.docChanged && transaction.annotation(externalDocumentUpdate) !== true)) {
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
          EditorView.contentAttributes.of({
            "aria-label": label || placeholder || (editable ? "Source input" : "Recovered output"),
            "aria-readonly": String(!editable),
            tabindex: "0",
          }),
          updateListener,
          languageCompartment.of([]),
        ],
      }),
      parent: host,
    });
    viewRef.current = view;
    loadedLanguageRef.current = null;
    return (): void => {
      view.destroy();
      viewRef.current = null;
    };
  }, [editable, label, placeholder, languageCompartment, themeCompartment]);

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
    view.dispatch({
      changes: { from: 0, to: view.state.doc.length, insert: code },
      annotations: externalDocumentUpdate.of(true),
    });
  }, [code]);

  useEffect((): (() => void) => {
    let canceled: boolean = false;
    void loadLanguage(language, phpSource).then((extension: readonly Extension[]): void => {
      if (canceled) {
        return;
      }
      if (loadedLanguageRef.current !== extension) {
        viewRef.current?.dispatch({
          effects: languageCompartment.reconfigure(extension as Extension[]),
        });
        loadedLanguageRef.current = extension;
      }
      setFailedLanguage(null);
    }).catch((): void => {
      if (!canceled) setFailedLanguage(language);
    });
    return (): void => {
      canceled = true;
    };
  }, [editable, label, placeholder, language, phpSource, languageCompartment]);

  useEffect((): (() => void) => {
    return (): void => {
      if (resetHandleRef.current !== null) {
        clearTimeout(resetHandleRef.current);
      }
    };
  }, []);

  async function copyCode(): Promise<void> {
    if (resetHandleRef.current !== null) {
      clearTimeout(resetHandleRef.current);
    }
    try {
      await navigator.clipboard.writeText(code);
      setCopyState("copied");
      resetHandleRef.current = setTimeout((): void => {
        setCopyState("idle");
      }, 1400);
    } catch {
      setCopyState("failed");
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
                aria-label={downloadLabel}
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
              aria-label={copyState === "copied" ? "Copied code" : "Copy code"}
              className="h-6 px-2 text-[11px]"
              size="sm"
              variant="ghost"
              onClick={(): void => {
                void copyCode();
              }}
            >
              {copyState === "copied" ? <Check aria-hidden="true" className="size-3.5" /> : <Copy aria-hidden="true" className="size-3.5" />}
              <span>{copyState === "copied" ? "copied" : "copy"}</span>
            </Button>
          </div>
        </div>
      ) : null}
      {failedLanguage === language ? (
        <p className="border-b border-hairline px-3 py-2 text-xs text-ink" role="status">
          Syntax highlighting could not load. Reconnect and reload the page.
        </p>
      ) : null}
      {copyState === "failed" ? (
        <p className="border-b border-hairline px-3 py-2 text-xs text-ink" role="alert">
          Copy failed. Select the code to copy it manually, or try again.
        </p>
      ) : null}
      <div ref={hostRef} className="cm-host min-h-0 overflow-auto" data-fill={fill ? "true" : "false"} />
    </div>
  );
}
