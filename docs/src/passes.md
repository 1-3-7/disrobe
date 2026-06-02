# Passes and the capability model

A **pass** is the unit of work in disrobe. Each pass lives in its own crate, implements a shared trait, and declares the capabilities it requires and produces. The capability resolver is what allows arbitrary passes to chain.

## Registered passes

Run `disrobe passes` for the live list. As of the current release:

| Pass | Capability summary |
|---|---|
| `pyarmor` | PyArmor v6 / v7 (dynamic-hook) + v8 / v9-pro static unpack. |
| `pyinstaller` | PyInstaller 2.1 .. 6.x extract + AES-CTR / CFB decrypt. |
| `pyfreeze` | cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase detect + extract. |
| `nuitka` | `--onefile` payload extract (zstd) + symbol / constants scan. |
| `py` | Deobfuscate (peel + cleanup) / disassemble / decompile / extract / SourceDefender decrypt. |
| `js` | Deobfuscate (string-array + unminify + scope-aware rename) / unbundle 10+ bundlers. |
| `wasm` | Analyze / decompile (JSON / Rust / TypeScript / WAT / C) / deobfuscate 5 families. |
| `envelope` | `.dr` create / inspect / verify / diff / migrate-check. |
| `native` | Ghidra-headless decompile / symbol dump / unpack / entropy / crypto signatures. |
| `jvm` | Classfile / `.jar` / `.dex` / `.apk` decompile via CFR / Vineflower / Procyon / JADX. |
| `dotnet` | .NET PE decompile via ILSpy / dnSpyEx / de4dot + protector detection. |
| `hermes` | React Native Hermes bundle disasm + JS surface lift. |
| `macho` | Mach-O / fat / `.ipa` dump + ObjC + Swift class-dump. |
| `lua` | Lua 5.1-5.4 / LuaJIT / Luau / GLua decompile + obfuscator peel. |
| `php` | Encoder decode (phar / ionCube / SourceGuardian / ZendGuard) + eval-chain peel. |
| `ruby` | MRI / YARV / mruby / JRuby / TruffleRuby / Ruby2Exe / Ocra analysis. |
| `beam` | `.beam` IFF parse + Core Erlang lift + Code chunk disasm. |
| `pickle` | Disasm + decompile + safety + symbolic trace + polyglot + ML model detect. |
| `go` | pclntab + moduledata + garble report + embed.FS extraction. |
| `swift` | Swift / ObjC class-dump + SwiftShield undo + Confidential XOR-decrypt. |
| `as3` | ActionScript 3 `.swf` DoABC tag disasm. |
| `flutter` | Dart AOT / libapp.so dump + obfuscation_map parse. |
| `chain` | Explicit pass pipeline orchestrator. |
| `serve` | HTTP daemon + WebSocket stream + LSP-stdio + gRPC + MCP. |

## The capability resolver

Rather than hard-coding which pass follows which, each pass declares:

- **Requires** — the capabilities and IR rung its input envelope must already carry.
- **Produces** — the capabilities and IR rung its output envelope will carry.

When the chain runner picks the next pass, it matches the current envelope's produced capabilities against each candidate pass's requirements. A pass only runs if its requirements are satisfiable. This is why `disrobe auto` can detect that a PyInstaller archive contains a PyArmor-protected module and route it through the unpack-then-decompile chain without any per-combination glue code.

Capabilities are versioned. A pass can require, for example, "a CPython 3.12 code object at the Disasm rung," and the resolver will refuse to feed it a 2.7 object. This keeps the chain sound across the wide version ranges `disrobe` supports.

## Standardized emits

Every pass exposes the same twelve emit kinds:

```text
source  disasm  ast  cfg  ir  manifest  sourcemap  symbols  strings  imports  signatures  report
```

Pass `--emit source,disasm,report` (comma-separated) to select a subset, or `--all-emits` on passes that support it to write every kind. A pass that cannot produce a given emit writes an explicit stub:

```json
{
  "schema": "disrobe.emit.stub/v0",
  "pass": "pyarmor",
  "emit_kind": "source",
  "applicable": false,
  "error_code": "DR-IR-NotApplicable",
  "reason": "pyarmor pass does not produce source; chain with disrobe py decompile"
}
```

This means a downstream tool can always request any emit from any pass and get a well-formed, self-describing answer — either the artifact or an honest "not applicable here, chain with X."

## Error codes

Every failure carries a `DR-<DOMAIN>-<NNNN>` code rendered through miette diagnostics. Look any code up with:

```sh
disrobe explain DR-PYARM-0050
disrobe explain CLI-1            # short form also works
```
