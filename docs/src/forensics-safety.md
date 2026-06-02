# Forensics and malware-safety posture

**disrobe** is designed to be run against hostile input by analysts who must not detonate it. This page states precisely what does and does not execute, so you can decide what to run inside a sandbox.

## The default is static analysis — no sample execution

By default, ****disrobe** does not execute the sample.** Every default path is pure static analysis: it parses bytes, decodes bytecode, walks structures, and emits derived artifacts. It does not unpickle, does not call `__reduce__`, does not run a packed binary, does not invoke a sample's entry point.

This holds for the entire pickle suite in particular. `disrobe pickle trace` runs a **symbolic** VM: it walks the opcode stream and builds the object graph without instantiating a single real object or resolving a single real global. `disrobe pickle safety` grades danger statically. You can audit a downloaded `.pt` or `.pkl` for what it *would* do on load without ever letting it load.

## The opt-in execution paths

There are a small number of paths that *can* execute code, and every one is behind an explicit, named flag. None of them is on by default.

| Path | Gate | What it does |
|---|---|---|
| PyArmor v6/v7 dynamic-hook | `--allow-dynamic` | Runs the obfuscated wrapper in a watched subprocess to capture marshal streams. Watchdog timeout via `--dynamic-timeout` (default 60s). |
| PyArmor BCC native-body lift | `--allow-bcc` | Lifts BCC-protected native bodies via Ghidra-headless on PATH (Ghidra runs, not the sample's logic in-process). |

If you must use `--allow-dynamic`, **do it inside an isolated sandbox** (a disposable VM or container with no network and no access to anything you care about). **disrobe** gives you the watchdog timeout and a captured-marshal manifest, but a dynamic hook is, by definition, executing adversarial code. The pure-static paths (v8, v9-pro) need no such gate.

## Subprocess backends

The optional external backends (Ghidra, CFR, Vineflower, jadx, ILSpy, dnSpy, de4dot, Rizin) run as subprocesses over the *artifact*, not by executing the sample's own logic. Command lines are constructed from configuration and sometimes user input; command injection or argument smuggling there is in scope for the security policy.

## Hardened parsing surface

Because **disrobe** parses adversarial binary input all day, the parsing surface is hardened as a first-class concern:

- **Pure-Rust, `unsafe` forbidden workspace-wide.** The only opt-outs are the two pyo3 C-interop crates (`disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`), gated behind explicit features. Any panic or abort on adversarial input that is not a clean `Result::Err` is a bug.
- **Resource-exhaustion guards.** Zip-bombs, decompression bombs, container-recursion bombs, and malformed-length-field bombs are defused by the shared quota machinery in `crates/disrobe-binfmt/src/quota.rs` (per-entry cap, aggregate cap, recursion-depth cap).
- **Path-traversal guards.** zip-slip and equivalents are sanitized on every one of the 26 container formats.
- **Envelope decoder hardening.** The `.dr` decoder is fuzzed; read-past-end, integer overflow, and BLAKE3-mismatch acceptance are all in scope.
- **Chain safety.** Depth cap (default 8) and content-hash cycle detection stop a malicious input from making a chain recurse forever.

## Reporting

Found a way to make a default path execute a sample, or to escape a container, or to crash the parser? That is a security issue — report it privately, never as a public issue. See [Security](./security.md).
