import { ExternalLink, Lightbulb } from "lucide-react";
import type { ReactElement, ReactNode } from "react";
import { CodeEditor } from "@/components/CodeEditor";

const CLI_ONLY: readonly string[] = [
  "Native executable decompilation, packer recovery, and installed analysis backends.",
  "Dalvik bytecode and JAR archives.",
  "PyInstaller archives and recursive multi-file extraction.",
  "Directory analysis and batch recovery.",
];

const LIMITATIONS: readonly string[] = [
  "The playground runs a WebAssembly build of the pass library entirely client-side; nothing is uploaded.",
  "It takes one input at a time. PHAR members can be extracted and reused as input; batch recovery and directory analysis use the CLI.",
  "Recompilation and runtime comparisons require the separate host toolchains listed in the documentation.",
];

function Section({ title, children }: { readonly title: string; readonly children: ReactNode }): ReactElement {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="font-sans text-[12px] font-semibold uppercase tracking-wide text-ink-muted">{title}</h2>
      {children}
    </section>
  );
}

export function AboutView(): ReactElement {
  return (
    <article className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-8">
      <header className="flex flex-col gap-3">
        <div className="brand-lockup">
          <span aria-hidden="true" className="brand-symbol" />
          <h1 className="brand-wordmark">disrobe</h1>
        </div>
        <p className="max-w-[68ch] font-sans text-[14px] leading-relaxed text-ink">
          Disrobe recovers source, structure, and unpacked bytes from compiled or obfuscated software.
          This playground runs the supported single-file passes in your browser. Inputs stay on your device.
        </p>
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Recovery tests use format-specific checks: normalized Python opcode structure, original unpacked
          bytes, source compilation, and runtime comparisons on known test programs. Each published result
          names its input population and comparison method.
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <a
            className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-sm border border-hairline bg-surface px-2.5 font-sans text-[12px] text-ink-muted transition-[border-color,background-color,color] hover:border-hairline-strong hover:bg-inset hover:text-ink"
            href="https://github.com/1-3-7/disrobe"
            rel="noreferrer"
            target="_blank"
          >
            <ExternalLink aria-hidden="true" className="size-3.5" />
            <span>github.com/1-3-7/disrobe</span>
          </a>
          <a
            className="inline-flex h-8 cursor-pointer items-center gap-2 rounded-sm border border-hairline bg-surface px-2.5 font-sans text-[12px] text-ink-muted transition-[border-color,background-color,color] hover:border-hairline-strong hover:bg-inset hover:text-ink"
            href="https://1-3-7.github.io/disrobe/"
            rel="noreferrer"
            target="_blank"
          >
            <ExternalLink aria-hidden="true" className="size-3.5" />
            <span>documentation</span>
          </a>
        </div>
      </header>

      <div className="rounded-sm border border-accent/45 bg-accent/[0.05] px-4 py-3">
        <div className="flex items-center gap-2">
          <Lightbulb aria-hidden="true" className="size-4 text-accent" />
          <h2 className="font-sans text-[12px] font-semibold uppercase tracking-wide text-accent">When to use the CLI</h2>
        </div>
        <p className="mt-2 font-sans text-[12.5px] leading-relaxed text-ink">
          Individual JVM classfiles and .NET assemblies work in the browser. Use the CLI for:
        </p>
        <ul className="mt-2 flex flex-col gap-1.5">
          {CLI_ONLY.map((item: string): ReactElement => (
            <li key={item} className="flex gap-2 font-sans text-[12.5px] leading-relaxed text-ink-muted">
              <span aria-hidden="true" className="mt-2 size-1.5 shrink-0 rounded-full bg-accent" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
        <p className="mt-3 font-sans text-[12px] font-medium uppercase tracking-wide text-ink-faint">Playground limits</p>
        <ul className="mt-2 flex flex-col gap-1.5">
          {LIMITATIONS.map((item: string): ReactElement => (
            <li key={item} className="flex gap-2 font-sans text-[12.5px] leading-relaxed text-ink-muted">
              <span aria-hidden="true" className="mt-2 size-1.5 shrink-0 rounded-full bg-hairline-strong" />
              <span>{item}</span>
            </li>
          ))}
        </ul>
      </div>

      <Section title="Install">
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Building the CLI requires the repository's Rust toolchain and a linker/C toolchain for your
          target. The workspace requires Rust 1.95 or newer. Optional analysis backends have separate prerequisites.
        </p>
        <CodeEditor
          label="Build commands"
          language="shell"
          code={`git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --locked --release -p disrobe-cli --bin disrobe`}
        />
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          The executable is <code>target/release/disrobe</code> (<code>target/release/disrobe.exe</code> on Windows).
          Copy it to a directory on your <code>PATH</code> before running the commands below.
        </p>
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          The documentation lists supported platforms, release verification commands, and optional backend dependencies.
        </p>
      </Section>

      <Section title="Command line">
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Start with identify to inspect an input, then use auto to select a recovery chain.
          The catalog lists format families and support tiers; each command's help describes its options.
        </p>
        <CodeEditor
          label="Recovery commands"
          language="shell"
          code={`disrobe identify path/to/artifact
disrobe auto path/to/artifact --out recovered/ --capture-stages
disrobe catalog
disrobe --help`}
        />
      </Section>
    </article>
  );
}
