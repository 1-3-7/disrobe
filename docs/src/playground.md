# The browser playground

The [playground](https://1-3-7.github.io/disrobe/playground/) runs **disrobe** in your browser. The analysis passes are compiled to WebAssembly (the `disrobe-wasm` crate) and execute entirely client-side: you drop in a file, it is analyzed in the page, and nothing is uploaded. There is no server, no telemetry, and no account.

## What it does

The playground exposes the read-only analysis surface, the operations that are safe to run on an untrusted file without writing to disk or executing the sample:

| Input | Operations |
|---|---|
| Python `.pyc` | Disassemble and decompile to source. |
| Python pickle (`.pkl`, `.pt`) | Static disasm, symbolic trace, safety grading (scan for a `REDUCE` against a code-execution sink), and polyglot detection. Never unpickles. |
| WebAssembly `.wasm` | Module summary and obfuscator detection. |
| Lua chunk | Dialect detection and decompile. |
| PyArmor-wrapped source | Version detection and protection-mode classification. |
| Any binary | String extraction, IOC scan (defanged), and a behavior summary. |

Everything is the same code the CLI runs, compiled to a different target. A pickle graded `overtly_malicious` in the playground grades the same way under `disrobe pickle safety` on the command line.

## Why it is safe

The playground inherits **disrobe**'s static, deterministic posture. The pickle suite is symbolic: it walks the opcode stream and reconstructs the object graph without importing a module or calling `__reduce__`. The Python and WASM paths parse and lower bytecode without running it. The one thing the browser build deliberately omits is any code-execution path (the PyArmor dynamic hook and the BCC native lift), so there is nothing in the page that can run the sample.

Because the build is deterministic, a given file produces the same result on every load, which is what makes the playground usable as a quick triage step rather than a toy. For the full pass set, the chain runner, and the writeable emits, use the CLI or the [library](./library.md).
