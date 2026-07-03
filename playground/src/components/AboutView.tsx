import { ExternalLink, Lightbulb } from "lucide-react";
import type { ReactElement, ReactNode } from "react";

const CLI_ONLY: readonly string[] = [
  "Native code: x86-64 to pseudo-C and pseudo-Rust, packer / unpacker stub emulation, bytecode-VM devirtualization, and format / compiler / protector identification.",
  "Compiled-binary language recovery: Go, .NET / CIL, JVM and Android / Dalvik from real binaries, Swift / Objective-C class-dump, and native languages (Nim, Zig, Crystal, D).",
  "Python packaging: PyArmor detect / classify, PyInstaller, Nuitka, PyOxidizer, and Cython native-body recovery.",
  "Recon over trees and bundles: frisk secrets / IOC and prowl over whole directories, archives, and APK / IPA bundles.",
  "Whole-pipeline workflows: disrobe auto chaining, batch directory runs, and the self-contained offline HTML forensic report.",
];

const LIMITATIONS: readonly string[] = [
  "The playground runs a WebAssembly build of the pass library entirely client-side; nothing is uploaded.",
  "It takes a single in-memory input; multi-file, archive-walking, and directory recon are CLI-only.",
  "Passes that need a host toolchain for recompile-equivalence grading run only in the CLI and CI.",
];

function Section({ title, children }: { readonly title: string; readonly children: ReactNode }): ReactElement {
  return (
    <section className="flex flex-col gap-3">
      <h2 className="font-sans text-[12px] font-semibold uppercase tracking-wide text-ink-muted">{title}</h2>
      {children}
    </section>
  );
}

function CodeBlock({ code }: { readonly code: string }): ReactElement {
  return (
    <pre className="overflow-x-auto rounded-sm border border-hairline bg-inset px-4 py-3 font-mono text-[12.5px] leading-relaxed text-ink">
      {code}
    </pre>
  );
}

export function AboutView(): ReactElement {
  return (
    <article className="mx-auto flex w-full max-w-3xl flex-col gap-8 px-6 py-8">
      <header className="flex flex-col gap-3">
        <span className="font-mono text-[22px] font-bold tracking-tight text-ink">disrobe</span>
        <p className="max-w-[68ch] font-sans text-[14px] leading-relaxed text-ink">
          One static Rust binary that decompiles, deobfuscates, and unpacks software across 20+ ecosystems and proves
          what it recovered against an independent oracle. Deterministic, no execution of the sample, no model. Built
          for malware analysis, CTFs, IP recovery, and security research.
        </p>
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Recovered Python is recompiled and diffed opcode-for-opcode in CI; unpacked bytes are byte-compared to the
          original; recovered Android, WebAssembly, and Lua are re-run through the real JVM verifier, wasmtime, and lua.
          Identical input yields identical output on every machine.
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
          <span className="font-sans text-[12px] font-semibold uppercase tracking-wide text-accent">Tip</span>
        </div>
        <p className="mt-2 font-sans text-[12.5px] leading-relaxed text-ink">
          The playground exposes the passes that run purely on a single in-memory input. These run only in the disrobe
          CLI, not the in-browser playground:
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
          A release build needs only Rust 1.95+ stable and produces one binary that links or invokes no Python, Node,
          JVM, wasmtime, Lua, or external tool at run time.
        </p>
        <CodeBlock
          code={`cargo install --git https://github.com/1-3-7/disrobe disrobe-cli

# or build from source
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --release`}
        />
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Prebuilt binaries for Windows, Linux (glibc and musl), and macOS, each for x86-64 and ARM64, are on the
          Releases page with SHA256SUMS and a cosign signature bundle.
        </p>
      </Section>

      <Section title="Command line">
        <p className="max-w-[68ch] font-sans text-[13px] leading-relaxed text-ink-muted">
          Each pass is a subcommand. disrobe auto fingerprints the input and composes the full pipeline in one call; run
          disrobe --help, disrobe passes, or disrobe catalog to discover the surface.
        </p>
        <CodeBlock
          code={`disrobe auto suspect.exe --out recovered/      # fingerprint, then chain the whole pipeline
disrobe identify suspect.exe                   # format, packer, and compiler ID
disrobe py decompile module.pyc --out src/     # CPython 1.0-3.15 to source
disrobe native decompile app.exe --backend native            # x86-64 to C pseudo-code, graded vs gcc/clang
disrobe native decompile app.exe --backend native --format rust  # x86-64 to idiomatic Rust, graded vs rustc
disrobe native unpack packed.exe --out unpacked.bin          # stub-emulator unpack, byte-recovery graded
disrobe jvm decompile app.apk --out src/       # in-house Dalvik decompiler
disrobe dotnet decompile App.dll --out src/    # in-house CIL to C#/F#/VB
disrobe frisk ./repo --format html             # secrets and IOC recon over a tree`}
        />
      </Section>
    </article>
  );
}
