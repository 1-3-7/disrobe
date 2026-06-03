# 4. Gate pass composition with an explicit capability model

- Status: accepted
- Date: 2025-09-22
- Deciders: project maintainer

## Context and Problem Statement

The IR ladder (ADR 0002) lets passes compose by rung, and the `.dr` envelope (ADR 0003) carries them between stages. But "rung N → rung N+1" alone is not enough to know whether a given pass can *legally and soundly* run on a given envelope. A `.pyc` decompiler must not run on an envelope that is still encrypted; a paid-tier protector peel must not run without authorization; a BCC native lift needs Ghidra on PATH. We need a single mechanism that decides, for any envelope and any candidate pass, whether the pass may run - and that fails *explicitly* when it may not, rather than producing silent garbage. Without it, the chain runner would either hand-wire every legal ordering or run passes optimistically and emit wrong output.

## Decision Drivers

- The chain runner must compose arbitrary passes without hard-coding orderings, while never running a pass whose preconditions are unmet.
- Authorization and execution gates (`--i-have-authorization`, `--allow-dynamic`, `--allow-bcc`) must be expressible in the same mechanism, not bolted on per-pass.
- A pass that cannot produce a requested emit must say so explicitly, not drop it.
- Failure to satisfy a precondition must surface as a typed, documented error, not a panic or a wrong answer.

## Considered Options

1. **Explicit capability descriptors.** Every pass declares the capabilities it **Requires** on the way in and **Produces** on the way out; a capability resolver gates what can run next. Emits a `DR-IR-NotApplicable` stub when a standardized emit cannot be produced.
2. **Hard-wired pipelines per ecosystem.** The chain runner enumerates legal orderings by hand. No surprises, but every new pass means editing the runner, and cross-ecosystem chains must each be hand-authored.
3. **Optimistic run-and-check.** Run any rung-compatible pass and validate the output afterward. Simplest to wire, but it executes passes on inputs they cannot handle and turns precondition failures into silent or late errors.

## Decision Outcome

Chosen option: **explicit capability descriptors with a resolver**. Every pass speaks the same envelope dialect and declares its `Requires` / `Produces` capability sets. The capability resolver decides whether a candidate pass may run against the current envelope; the chain runner composes any pass with any other exactly when the resolver is satisfied. Authorization and execution gates are modeled as capabilities, so `--i-have-authorization`, `--allow-dynamic`, and `--allow-bcc` flow through the same machinery. A pass that cannot emit a standardized output (`source`, `disasm`, `ast`, `cfg`, `ir`, `manifest`, `sourcemap`, `symbols`, `strings`, `imports`, `signatures`, `report`) writes an explicit `applicable: false` stub with `DR-IR-NotApplicable`.

## Consequences

- **Good:** `PyInstaller → PyArmor → .pyc decompile` is one `disrobe auto` invocation, not three hand-wired steps - the resolver, not the maintainer, finds the legal chain.
- **Good:** authorization and sandbox gates are uniform and auditable; the same capability machinery that orders passes also enforces that a paid-tier peel cannot run without its gate, and a precondition miss is a typed error (e.g. the `--i-have-authorization`-gated `decryption-keys` request failing with `DR-CLI-0420`).
- **Good:** "cannot produce this emit" is a first-class, documented state (`DR-IR-NotApplicable`) rather than a missing file, which keeps the honesty invariant from ADR 0002 intact.
- **Bad / accepted cost:** every pass must author accurate `Requires`/`Produces` sets; an under-declared requirement lets a pass run when it should not, and an over-declared one blocks legal chains. Capability declarations become part of the test surface.
- **Bad / accepted cost:** the resolver adds a layer between "rung-compatible" and "actually runs", which is more machinery than optimistic execution - accepted because it is what prevents silent wrong output on adversarial or mis-ordered input.
