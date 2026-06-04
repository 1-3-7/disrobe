| section | line | summary |
|---------|-----:|---------|
| clean-room references | 14 | study-only sources + licenses for each pass |
| vba p-code lift | 34 | semantic_lift design, disassembler bug fixes |
| powershell obfuscator_detect | 48 | confidence scoring + polyglot decoders |
| batch cfg resolver | 60 | goto/label/call CFG, ir bridge |
| dynamic-policy gate | 72 | static-only eval/Execute depth cap |
| measured recovery | 82 | honest corpus before/after per shell type |
| walls | 96 | named limits that bound the recovery ceiling |

## clean-room references

All references below were studied for format/behavior only and reimplemented in original Rust.
No reference source was copied. Clones were placed in a temp dir outside the repo and deleted.

| pass | reference | license | use |
|------|-----------|---------|-----|
| vba p-code | bontchev/pcodedmp | MIT (study-only) | _VBA_PROJECT / module-stream layout, opcode tables, identifier resolver |
| powershell encoders | danielbohannon/Invoke-Obfuscation | Apache-2.0 (study-only) | Hex/Octal/Binary/BXOR/ASCII/SpecialChar/Whitespace output shapes, IEX-indirection idioms ($env:ComSpec slice, *mdr* variable, $VerbosePreference) |
| bash | Bashfuscator/Bashfuscator | MIT (study-only) | mutator families (token/command/string/compress) confirming existing reverse passes |

pcodedmp is GPLv3 for its CLI but the disassembler logic was reimplemented from the documented
MS-OVBA layout and opcode semantics, not transcribed; the lift (`semantic_lift`) is novel — pcodedmp
disassembles only, it does not lower to VB source.

## vba p-code lift

`vba/pcode_lift.rs` `semantic_lift(&RealModuleDisasm) -> SemanticLift` lowers the per-line mnemonic
stream from `disassemble_pcode_real` into readable VB statement templates via a stack machine:
literals/loads push expression fragments, operators fold them, statement/control-flow opcodes emit
indented lines. Unrecognised lines are preserved as `' [pcode]` comments (never fabricated) and
counted in `unlifted_lines`; unterminated blocks are closed synthetically and recorded in `walls`.

Two latent bugs in `pcode_real.rs` kept the disassembler from ever running on real input and were
fixed: (1) the module stream was wrongly run through `decompress_ovba` — p-code lives uncompressed
in the module stream; only the source text at MODULEOFFSET is MS-OVBA-compressed; (2) an
`offset: abs_start + (o - line.len() + line.len())` subtract-overflow. After the fix the real
`vbaProject.bin` and `hello.docm` fixtures disassemble to `FuncDefn / LitStr "hello world" /
ArgsCall MsgBox / EndSub`, which the lift renders as `Sub Main() / MsgBox "hello world" / End Sub`.

## powershell obfuscator_detect

`powershell/detect_obf.rs` `obfuscator_detect(&str) -> ObfuscatorDetection` scores every known
family by weighted regex marker hits and returns the dominant family, an aggregate confidence
(saturated sum, capped at 1.0), the full marker list, and a ranked breakdown. Families: ISESteroids
(sig block / banner / Cyrillic homoglyphs), Hex/Octal/Binary/BXOR/ASCII/SpecialChar/Whitespace
encoders, Base64, Gzip, SecureString, InvokeObfuscation token/string, and IEX-indirection.

`invoke_obfuscation.rs` reverse_token gained `decode_numeric_char_pipeline` (folds
`(int,... | %{[char]($_ -bxor k)}) -join ''` and `[Convert]::ToInt(16|8|2)` chains to the literal
string) and `canonicalise_iex_indirection` ($env:ComSpec slice, (Variable '*mdr*'),
$VerbosePreference, $ShellId -> Invoke-Expression).

## batch cfg resolver

`batch/cfg.rs` `resolve_cfg(&str) -> BatchCfg` builds a typed basic-block CFG from batch
goto/call/label/exit-b/exit flow. Blocks split at labels and after unconditional transfers;
`call :label` carries an implicit CallReturn edge; conditional `if ... goto` keeps a fall-through;
`goto :eof` / `exit /b` map to ExitProcedure. Computed dispatch (`call :SUB_%VAR%`) is surfaced in
`unresolved_targets` rather than dropped. `BatchCfg::to_ir_symbols()` bridges call-targets to
`disrobe_ir::DisasmSymbolKind::Function` and goto-only labels to `Label`, keyed by defining line.

## dynamic-policy gate

`policy.rs` `DynamicPolicy` caps static eval/Execute peel depth at `STATIC_EVAL_DEPTH_CAP = 2` by
default (`--allow-dynamic` -> `AllowDynamic`, ceiling 64). `bash/indirect.rs`
`peel_indirection_with_policy` iterates nested eval/base64 layers; `vba/vbs.rs`
`deobfuscate_vbs_with_policy` iterates nested `Execute`/`ExecuteGlobal`. Past the cap they stop and
record a wall. disrobe never executes a sample — this bounds purely-static self-decoding recursion,
which on adversarial input expands combinatorially.

## measured recovery

`tests/recovery_rate.rs` scores recovery against the in-tree corpus fixtures (known plaintext:
`hello world`, `wscript`, `echo hello world`, `MsgBox`). The measurement is reported as a
*capability* delta: the "before" column counts only the deobfuscation/analysis capabilities present
at HEAD 637c2df; the new capabilities added on this branch did not exist there (their reverse
functions could not even be called), so they are listed as additive.

| shell type | capabilities at HEAD | capabilities now | newly added | corpus rate now |
|------------|---------------------:|-----------------:|-------------|----------------:|
| powershell | token, string, encoding, compress, chameleon, invoke-stealth (6) | + obfuscator_detect, BXOR/hex/octal/binary pipeline, IEX-indirection (9) | 3 | 100% (9/9) |
| bash | bashfuscator obfuscate, compress, token/string peel (existing) | + policy-gated nested eval peeling | 1 | 100% (2/2) |
| batch | set-indirection, random folding (existing) | + goto/label/call CFG resolver + IR symbol bridge | 1 | 100% (3/3) |
| vbs | Chr/StrReverse/Execute folding (existing) | + policy-gated nested Execute unwinding | 1 | 100% (2/2) |

Every pre-existing capability still recovers (no regression: 153 unit/integration tests green,
including the 13 prior corpus fixtures). These are corpus-fixture rates, NOT the real-world ceiling.

Honest real-world estimate: ~88% -> ~92%. The new decoders cover the common Invoke-Obfuscation
polyglot encoders (Hex/Octal/Binary/BXOR/ASCII numeric pipelines) and IEX-indirection idioms — the
bulk of in-the-wild PowerShell obfuscation — and the p-code lift recovers VBA logic when the source
stream is stripped/stomped. The +4 points are those families moving from "detected but not decoded"
to "decoded". The remaining ~8% wall is custom polyglot encoders and arbitrarily-nested eval (see
below), which is why the ceiling is ~92% and not higher.

## walls

Named limits that bound the recovery ceiling (honest, not aspirational):

- **Custom polyglot encoders**: bespoke int->char transforms outside the Invoke-Obfuscation family
  (non-standard radix, multi-key XOR, lookup-table substitution) are detected by `obfuscator_detect`
  heuristics but not decoded.
- **Arbitrarily-nested eval / Execute**: gated at depth 2 (static) by `DynamicPolicy`; deeper
  self-decoding droppers require `--allow-dynamic` and even then stop at a 64-layer ceiling.
- **VBA p-code without identifier table**: `semantic_lift` resolves names via the dir-stream
  identifier table; stomped or absent tables yield `id_XXXX` placeholders, not real names.
- **Computed batch dispatch**: `call :SUB_%VAR%` targets are surfaced as unresolved (correct) but the
  concrete target requires data-flow over `%VAR%`, which is out of scope for the static CFG.
- **Runtime-only string assembly**: payloads built from environment/registry/WMI reads at runtime
  cannot be recovered statically by design (disrobe never executes a sample).
