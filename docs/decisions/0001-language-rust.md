# 1. Implement disrobe in Rust

- Status: accepted
- Date: 2025-09-01
- Deciders: project maintainer

## Context and Problem Statement

disrobe parses adversarial binary input as its core activity: protector output, packed executables, obfuscated bytecode, exotic encoders. Every length field, offset, and nested container is potentially attacker-controlled. The implementation language is the single largest lever on the project's two hardest requirements at once: **memory safety on a hostile parsing surface** and **deterministic, reproducible output usable as a forensic baseline**. We must pick the language before any pass exists, because the choice constrains the whole workspace.

The candidates were Rust, C/C++, and a managed runtime (Go or a JVM/CLR language).

## Decision Drivers

- Memory safety on an adversarial parsing surface, ideally enforced at compile time rather than by discipline.
- Determinism: identical bytes in must yield identical bytes out, with no GC nondeterminism or implicit floating clocks in the hot path.
- A single statically-linked binary with no runtime dependency, for analyst portability and sandbox use.
- A crate-per-ecosystem workspace model so each pass stays focused and independently testable.
- Mature decode/parse tooling (binary format crates, disassembler bindings, serialization).

## Considered Options

1. **Rust** - compile-time memory safety without GC, `#![forbid(unsafe_code)]` enforceable workspace-wide, strong workspace/crate model, mature `object`/`wasmparser`/`capstone`/`iced-x86`/`yaxpeax` ecosystem, deterministic by default.
2. **C / C++** - maximal ecosystem of existing reverse-engineering code, but memory safety is a matter of discipline; an adversarial parser written in C is a perpetual CVE surface.
3. **Go / managed runtime** - memory-safe and productive, but a GC introduces nondeterministic pauses, the single-static-binary story is weaker for native-interop backends, and the type system is thinner for the IR-ladder modeling we need.

## Decision Outcome

Chosen option: **Rust**, because it is the only option that delivers compile-time memory safety on the hostile parsing surface *and* GC-free determinism *and* a first-class workspace model, simultaneously. We forbid `unsafe` workspace-wide; the only opt-out is the two pyo3 C-interop crates (`disrobe-pyarmor-cextract`, `disrobe-pyarmor-pytrace`), gated behind explicit features and kept off every default path.

## Consequences

- **Good:** any panic/abort on adversarial input that is not a clean `Result::Err` is treated as a bug, and the compiler eliminates the entire class of use-after-free / buffer-overflow defects from the parsing surface. The workspace splits cleanly into a small set of shared cores plus one `disrobe-pass-*` crate per ecosystem.
- **Good:** GC-free execution and explicit `--seed` plumbing make byte-identical reproducibility achievable, which is the precondition for `disrobe diff` and forensic baselining.
- **Good:** single statically-linked binary ships cleanly into analyst sandboxes.
- **Bad / accepted cost:** some mature reverse-engineering tooling exists only as C/C++ or JVM programs (Ghidra, CFR, jadx, ILSpy). We accept this by wrapping them as subprocess backends over the *artifact* rather than reimplementing them, and by treating their command-line construction as an in-scope security surface.
- **Bad / accepted cost:** Rust's learning curve and compile times are higher than Go's; we accept this for the safety and determinism guarantees.
