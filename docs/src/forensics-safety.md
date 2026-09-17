# Forensics and malware-safety posture

Analysts run `disrobe` against hostile input that must not detonate. Everything below states what executes and what does not, so you can decide what to run inside a sandbox.

## The default is static analysis, no sample execution

By default, `disrobe` does not execute the sample. Every default path is pure static analysis: it parses bytes, decodes bytecode, walks structures, and emits derived artifacts. It does not unpickle, does not call `__reduce__`, does not run a packed binary, does not invoke a sample's entry point.

This holds for the entire pickle suite in particular. `disrobe pickle trace` runs a **symbolic** VM: it walks the opcode stream and builds the object graph without instantiating a single real object or resolving a single real global. `disrobe pickle safety` grades danger statically. You can audit a downloaded `.pt` or `.pkl` for what it *would* do on load without ever letting it load.

## Opt-in gated paths

Only `--allow-dynamic` executes sample code. `--allow-bcc` enables additional static analysis. Neither path is enabled by default.

| Path | Gate | What it does |
|---|---|---|
| PyArmor v6/v7 dynamic-hook | `--allow-dynamic` | Runs the obfuscated wrapper in a watched subprocess to capture marshal streams. Watchdog timeout via `--dynamic-timeout` (default 60s). |
| PyArmor BCC native-body analysis | `--allow-bcc` | Parses extracted BCC objects in-process and attempts x86-64 pseudo-C analysis. It does not execute the sample or invoke Ghidra. |

Once wrapper and runtime discovery succeeds, omitting `--allow-bcc` makes a detected BCC unpack return `DR-PYARM-0050` before version-specific unpacking. Native builds use the Microsoft x64 ABI for Windows x86-64, the System V ABI for Linux x86-64, and AAPCS64 for Darwin ARM64. Unknown architecture IDs produce a typed refusal instead of selecting an ABI. Wasm builds record that native lifting is unavailable. The dedicated command and path-aware automatic extraction publish the same bounded recovery JSON, pseudo-C, and recovered Python skeleton. Each unmodeled function retains its native disassembly and typed reason.

If you must use `--allow-dynamic`, **do it inside an isolated sandbox** (a disposable VM or container with no network and no access to anything you care about). `disrobe` gives you the watchdog timeout and a captured-marshal manifest, but a dynamic hook is, by definition, executing adversarial code. The non-BCC v8/v9 paths remain static and need no execution opt-in. BCC analysis is also static but separately gated.

## Subprocess backends

The optional external backends (Ghidra, CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Rizin) run as subprocesses over the *artifact*, not by executing the sample's own logic. Command lines are constructed from configuration and sometimes user input; command injection or argument smuggling there is in scope for the security policy.

## Hardened parsing surface

`disrobe` parses adversarial binary input constantly, so the parsing surface is hardened deliberately:

- Format decoders avoid `unsafe`. The remaining unsafe code is limited to audited boundary code such as C interop, WASM exports, archive/io shims, build/install helpers, and native-loader interfaces. Any panic or abort on adversarial input that is not a clean `Result::Err` is a bug.
- Zip-bombs, decompression bombs, container-recursion bombs, and malformed-length-field bombs are defused by the shared quota machinery in `crates/disrobe-binfmt/src/quota.rs`, whose per-entry ratio the phar reader mirrors in-crate rather than calling (per-entry cap, aggregate cap, recursion-depth cap).
- zip-slip and equivalent path traversals are sanitized on every container extraction path.
- The `.dr` envelope decoder is fuzzed. Read-past-end, integer overflow, and BLAKE3-mismatch acceptance are all in scope.
- A depth cap (default 8) and content-hash cycle detection stop a malicious input from making a chain recurse forever.

## Reporting

A way to make a default path execute a sample, escape a container, or crash the parser is a security issue. Report it privately, never as a public issue. See [Security](./security.md).
