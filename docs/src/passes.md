# Passes and pass selection

A **pass** is the unit of work in `disrobe`. Chain passes implement a shared trait and register a detector that scores how confidently each one recognizes a given input. Ecosystem crates may expose one or more passes plus direct APIs. `disrobe auto` picks the next pass by comparing detector verdicts, not by matching capability descriptors between passes; see [Pass selection](#pass-selection) below.

## Commands and auto-chain passes

The CLI has two related surfaces:

- Direct commands are the operations shown by `disrobe --help`. They include ecosystem command families such as `py`, `native`, and `jvm`, plus analysis commands such as `scan`, `frisk`, `query`, `taint`, and `webview`.
- Chain passes implement the shared `Pass` trait and can be selected by `disrobe auto`. Their IDs are not necessarily CLI subcommand names.

`disrobe passes` prints both layers. Its first block summarizes direct recovery families. Its second block is the authoritative list of chain pass IDs reachable from `disrobe auto` in that binary, with an ecosystem and `full`, `partial`, or `detect-only` tier. The standard CLI build at this revision reports:

| Group | Auto-chain pass IDs |
|---|---|
| Python | `nuitka.extract`, `pickle.classify`, `py.decompile`, `py.deob`, `py.disasm`, `pyarmor.unpack`, `pyfreeze.extract`, `pyinstaller.extract`, `sourcedefender.decrypt` |
| Managed and mobile | `dotnet.classify`, `jvm.classify`, `mobile.classify`, `swift-objc.classify` |
| Source and bytecode | `as3.classify`, `beam.classify`, `js.deob`, `lua.deob`, `php.peel`, `ruby.classify`, `scriptlang.classify`, `shell.deob`, `wasm.deob` |
| Native and containers | `binfmt.container`, `go.classify`, `native.ne-structure`, `native.packer-unpack`, `nativelang.classify` |

This distinction matters for reachability. For example, `disrobe webview` directly recovers Electron, Tauri, and Wails frontend assets, but the standard CLI's `chain` feature does not enable `webview.carve`, so `disrobe auto` does not advertise that pass. Use the direct command for that surface. Build feature selection can change the chain registry; inspect the binary you are running instead of relying on a copied count.

The direct JavaScript catalog currently carries <!-- m:js_bundlers -->11<!-- /m --> bundler families. The WebAssembly catalog carries <!-- m:wasm_direct_helpers -->4<!-- /m --> direct-helper families; three transformations run through `wasm deob`, while Tigress-via-Emscripten and wasm-name-obfuscator are classification-only. These catalog counts describe direct command capability and do not add chain pass IDs.

## Pass selection

Rather than hard-coding which pass follows which, every pass registers a `Detector` (`chain::detector::Detector` in `disrobe-core`) that inspects the current bytes and, if it recognizes them, returns a `DetectVerdict`: a pass ID, a format tag, a family (`obfuscator-wrapper`, `packer-archive`, `interpreter-bytecode`, `source`, `container`, `native-format`, or `unknown`), a confidence score, and a specificity rank.

`PassRegistry::run_all` (`chain/registry.rs`) runs every registered detector against the bytes. Six extraction-first passes (`nuitka.extract`, `pyinstaller.extract`, `pyfreeze.extract`, `pyarmor.unpack`, `binfmt.container`, `sourcedefender.decrypt`) are tried before the rest, and the sweep stops early the moment one of them returns a `High`-band verdict (confidence >= 0.90) with specificity <= 30. A raw confidence buckets into `ConfidenceBand::Low` (< 0.70), `Medium` (0.70-0.89), or `High` (>= 0.90).

A `SelectionPolicy` then picks the winner among whatever verdicts came back: candidates below its minimum confidence (0.5 by default) are dropped, and the survivors are ranked by `precedence::compare` (`chain/precedence.rs`), which breaks ties in order: confidence band, then raw confidence, then the lower specificity value, then a fixed family-precedence table (`obfuscator-wrapper` beats `packer-archive` beats `interpreter-bytecode` beats `source` beats `container` beats `native-format` beats `unknown`), then the lexically smaller pass ID.

The chain driver (`chain/state_machine.rs`) runs this selection once per queued artifact, executes the winning pass, and re-runs detection on its output to decide what happens next. A branch ends when no verdict clears the minimum confidence (`Stalled`), when the same output bytes reappear (`Cycle`), or when the depth cap or cumulative-output budget is exceeded (`CapReached`). This is why `disrobe auto` can detect that a PyInstaller archive contains a PyArmor-protected module and route it through the unpack-then-decompile chain without any per-combination glue code.

## Standardized emits

The CLI's shared emit parser recognizes these fifteen labels:

```text
source  disasm  ast  cfg  ir  manifest  sourcemap  symbols  strings
imports  signatures  fingerprints  report  recovery  provenancemap
```

Commands opt into this contract individually. Where a command accepts `--emit`, pass a comma-separated subset such as `--emit source,disasm,report`. A supporting command writes an explicit stub when the requested kind does not apply:

```json
{
  "schema": "disrobe.emit.stub/v0",
  "pass": "beam-lift",
  "emit_kind": "fingerprints",
  "applicable": false,
  "reason": "not implemented for the beam pass in this build"
}
```

Support is not universal. `auto` accepts only `--emit recovery`, and commands that do not expose `--emit` use their own output contract. `--all-emits` is also command-specific. Check `disrobe <command> --help` before building a consumer around an emit.

## Error codes

Every failure carries a `DR-<DOMAIN>-<NNNN>` code rendered through miette diagnostics. Look any code up with:

```sh
disrobe explain DR-PYARM-0050
disrobe explain CLI-1            # short form also works
```
