| section | line | summary |
|---------|-----:|---------|
| references | 12 | study-only sources + licenses for the clean-room Zend op_array work |
| architecture | 30 | decompile/key_extractor/pipeline module boundaries and data flow |
| wire-format | 48 | the disrobe canonical op_array container byte layout |
| honesty | 70 | what is genuinely recoverable per encoder vs runtime-keyed walls |
| gotchas | 84 | non-obvious behaviors, ordering, and verification notes |

## references

Clean-room: the Zend opcode numbering, operand-type constants, and `_zend_op`
struct field order were studied from the authoritative php-src headers and
re-implemented in original Rust. No reference source was copied.

| ref | what | license | how read |
|-----|------|---------|----------|
| php/php-src `Zend/zend_vm_opcodes.h` | opcode numbers 0..211, VM op-flag masks | PHP License v3.01 (BSD-style) | `gh api` raw read (nothing left in tree) |
| php/php-src `Zend/zend_compile.h` | `struct _zend_op` field order; `IS_UNUSED/CONST/TMP_VAR/VAR/CV` (0,1,2,4,8) | PHP License v3.01 | `gh api` raw read |
| FIPS-197 (Rijndael) | AES forward S-box + Rcon constants (public, non-copyrightable tables) | public standard | transcribed into `key_extractor.rs` |

No clones were placed in the repo. The temp study dir
`C:/Users/-/AppData/Local/Temp/disrobe-refs/` was used for scratch only and
deleted at end of work.

## architecture

- `decompile.rs` — canonical Zend opcode table + `OperandType` (IS_* mapping),
  the disrobe op_array container parser (`parse_oparray`), `build_cfg`
  (leaders from branch targets + back edges), and the PARTIAL skeleton emitter
  (`decompile`) producing functions/classes/methods + if/while/foreach/switch.
- `key_extractor.rs` — `scan(bytes, family)` classifies key provenance
  (StaticEmbedded / LoaderDerivedRsa / RuntimeDerived) and recovers ONLY what is
  statically present; `xor_decrypt` (Zend Guard legacy) and `aes_cbc_decrypt`
  (bring-your-own-key, via `aes`+`cbc` crates) decrypt paths.
- `pipeline.rs` — `recover()` is the single bridge: detect -> (peel eval-chain) |
  (encoder decode -> static_decrypt -> decompile op_array). Emits `RecoveryReport`
  with the recovered text and an honest `RecoveryStage`.
- `pass.rs` / CLI `php.rs` — call `recover()` so detection reaches real output
  (skeleton `.skeleton.php` for decompiled op_arrays; peeled source for chains).

## wire-format

The disrobe canonical op_array container (`OPARRAY_MAGIC` = `DZOA`, version 1) is
disrobe's own deterministic re-serialization of a compiled `zend_op_array`, not a
copy of any encoder's proprietary framing. Layout (all integers little-endian):

```
magic[4]="DZOA" | version u8
op_array := kind u8 (0=Main 1=Function 2=Method 3=Closure)
          | opt_string name | opt_string class_name | num_args u32
          | literal_count u32 | literals[*]
          | op_count u32 | ops[*]
          | child_count u32 | op_array[child_count]   (recursive)
opt_string := present u8 (0|1) | if present: len u32 | utf8 bytes
literal := tag u8 (0=Null 1=Bool(u8) 2=Long(i64) 3=Double(f64 bits) 4=Str(len u32+bytes) 5=Array(u32))
op := opcode u8 | op1_type u8 | op2_type u8 | result_type u8
    | op1 u32 | op2 u32 | result u32 | extended_value u32 | lineno u32
operand types on the wire use the Zend IS_* values: 0/1/2/4/8.
```

## honesty

The encoders fundamentally erase compiled-variable NAMES and (for the commercial
three) the symmetric key is derived inside a closed loader at runtime:

- ionCube — symmetric key is RSA/license-handshake-derived inside the loader;
  only the asymmetric blob is static. Reported `LoaderDerivedRsa`, NO key faked.
- SourceGuardian — AES; the round table (S-box/Rcon) is located via FIPS-197
  constants, but the session key is runtime-derived. Reported `RuntimeDerived`.
- Zend Guard — LEGACY builds XOR the payload with a key at a fixed header offset;
  that IS statically recovered (`StaticEmbedded`) and decrypts end-to-end. Modern
  builds are runtime-keyed and reported honestly.

Even when a payload decrypts, fidelity is `Partial`: control-flow skeleton +
literals + called-symbol names are exact, but `$vN` stands in for every erased
variable name, and residual `eval()` / variable-variables stay ambiguous.

Real ionCube/SG/ZendGuard end-to-end samples were NOT obtained (sourcing-blocked,
no install/download of encoders permitted), so those decrypts are exercised only
against spec-accurate synthetic op_array containers, marked as such in tests.

## gotchas

- `detect_encoder` probes Zend Guard BEFORE SourceGuardian: the SG `<?php @Zend;`
  misuse marker is a prefix of the ZG `@Zend;\n<ver>` banner and would otherwise
  steal genuine ZG envelopes.
- For the ZG static XOR path the true payload starts at `key_offset + key.len()`
  from the ORIGINAL bytes, not the encoder framing's coarser ciphertext slice.
- Verification is non-circular: tests hand-assemble container bytes and assert the
  recovered skeleton/CFG; the builder never reuses the emitter.
- clippy `doc_markdown` flags `op_array`, `IS_*`, `SourceGuardian` etc. — wrap any
  such token in doc comments with backticks.
- Type ascription is NOT allowed on `if let` / `while let` / match-arm patterns in
  stable Rust; use a following `let x: T = x;` rebind instead.
