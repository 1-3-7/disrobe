| section | line | summary |
|---------|-----:|---------|
| references | 14 | clean-room study sources + licenses (Hermes, Dart VM) |
| hermes-literal-format | 30 | objKeyBuffer/objValueBuffer serialized-literal encoding |
| hermes-regex-format | 48 | regExpStorage compiled-bytecode + flag/group recovery |
| hermes-recovery-ceiling | 56 | what HBC discards; honest lossy ceiling |
| hermes-opcode-families | 63 | env/iterator/generator/property/coercion resugaring |
| flutter-snapshot-format | 95 | Dart AOT snapshot header + section layout |
| flutter-recovery-ceiling | 110 | AOT ARM64 body wall; raw counts only, no percentage |
| measurement | 122 | how before/after percentages are measured |

## references

Clean-room study only; no reference source copied. All formats reimplemented in original Rust.

- facebook/hermes (MIT) — bytecode file format, serialized-literal encoding, regex bytecode/flags.
  Studied headers: `include/hermes/BCGen/HBC/BytecodeFileFormat.h`,
  `include/hermes/BCGen/SerializedLiteralGenerator.h`, `include/hermes/BCGen/SerializedLiteralParser.h`,
  `include/hermes/BCGen/HBC/BytecodeList.def`, `include/hermes/Regex/RegexSerialization.h`,
  `include/hermes/Regex/RegexBytecode.h`, `include/hermes/Regex/RegexTypes.h`,
  `include/hermes/Regex/RegexOpcodes.def`. License: MIT (permits clean-room reimplementation).
- dart-lang/sdk (BSD-3-Clause) — VM snapshot header + section symbol layout.
  Studied: `runtime/vm/snapshot.h`, `runtime/vm/clustered_snapshot` concepts, `runtime/vm/image_snapshot.h`.
  License: BSD-3-Clause.

Clones were placed in `C:/Users/-/AppData/Local/Temp/disrobe-refs/` (outside repo) and deleted after study.

## hermes-literal-format

Object/array literals are serialized into three blobs referenced by header sizes
(`objKeyBufferSize`, `objValueBufferSize` / `arrayBufferSize` in v94-96). Encoding (per
`SerializedLiteralParser::parseImpl`):

- A buffer is a sequence of runs. Each run begins with a tag byte.
- If `tag & 0x80`: the run length is 2 bytes => `((tag & 0x0f) << 8) | next_byte`; else `tag & 0x0f`.
- Element type = `tag & 0x70` (TagMask). Types: Null/PrivateName=0x00, True=0x10, False=0x20,
  Number=0x30 (f64 LE, 8B), LongString=0x40 (u32 LE id, 4B), ShortString=0x50 (u16 LE id, 2B),
  Undefined=0x60, Integer=0x70 (i32 LE, 4B). Bool/Null/Undefined carry zero payload bytes.
- Key buffer uses the same encoding but Null tag means PrivateName; True/False/Undefined illegal.
- `NewObjectWithBuffer Reg8, sizeHint, numLiterals, keyBufferIdx, valueBufferIdx` (v94-96 5-operand)
  pairs `numLiterals` keys from keyBuffer@keyBufferIdx with `numLiterals` values from valueBuffer@valueBufferIdx.
- `NewArrayWithBuffer Reg8, sizeHint, numElems, valueBufferIdx` reads `numElems` values.

## hermes-regex-format

`regExpStorage` is a concatenation of compiled-regex bytecodes; `regExpTable` is `(offset,length)` pairs.
Each entry begins with a 6-byte `RegexBytecodeHeader`: markedCount(u16 LE), loopCount(u16 LE),
syntaxFlags(u8), constraints(u8); then a compiled opcode stream.

Flag bits (RegexTypes FlagBits): ICASE=1<<0, GLOBAL=1<<1, MULTILINE=1<<2, UCODE=1<<3, DOTALL=1<<4,
STICKY=1<<5, INDICES=1<<6. JS flag string order: d g i m s u y.

HONEST: the **source pattern text is NOT stored** — only compiled bytecode. We recover flags + group
count exactly, and a best-effort literal skeleton from MatchChar8/16, MatchNChar8, anchors, brackets.
Non-literal structure (alternation/loops/lookaround) is summarized, not exactly round-tripped.

## hermes-recovery-ceiling

HBC discards: source text, comments, original identifier names of locals (registers), formatting,
exact regex source. ~90-92% readable-construct recovery is the ceiling: object/array literals, string/
number/bigint constants, member access, calls, control flow, regex flags+skeleton are recoverable;
local variable names and comments are permanently lost.

## hermes-opcode-families (v96 BytecodeList.def, MIT, clean-room)

Resugaring of opcode families beyond constants/binops, each verified by synthetic-HBC round-trip
(encoder follows the spec operand order, decoder under test = non-circular):

- ENVIRONMENT/CLOSURE CAPTURE: `CreateEnvironment(dst)`, `CreateInnerEnvironment(dst,parent,size)`,
  `GetEnvironment(dst,levels)` track an env register's lexical level; `LoadFromEnvironment(dst,env,slot)`
  reads and `StoreToEnvironment[L]`/`StoreNPToEnvironment[L](env,slot,val)` writes a captured variable
  named `cvar{slot}` (level 0) or `cvar{level}_{slot}`. Original name erased by HBC -> positional name.
- ITERATOR (for-of): `IteratorBegin(it,src)` -> `it = src[Symbol.iterator]()`; `IteratorNext(r,it,src)`
  -> `r = it.next().value`; `IteratorClose(it,ignoreExc)` -> `it.return?.()`.
- FOR-IN: `GetPNameList(arr,obj,idx,size)` -> `for..in` props of obj; `GetNextPName(k,arr,obj,idx,size)`
  -> next key `k`.
- GENERATORS: `StartGenerator`/`CompleteGenerator` mark a `function*` body; `SaveGenerator[Long](addr)`
  -> `yield` point; `ResumeGenerator(res,done,...)` -> resumed value. `CreateGenerator[LongIndex]` ->
  `function* name()`.
- PROPERTY/OWN-PROP: `DelById[Long](dst,obj,strid)` -> `delete obj.prop`; `DelByVal(dst,obj,key)` ->
  `delete obj[key]`; `PutOwnByIndex[L]`/`PutOwnByVal` -> indexed array/own writes; `NewObjectWithParent`
  -> `Object.create(parent)`; `PutNewOwnNEById[Long]` -> non-enumerable own define.
- COERCION/ARGS/MISC: `ToNumber`->`+x`, `ToNumeric`/`ToInt32`->`(x|0)`, `AddEmptyString`->`("" + x)`,
  `GetNewTarget`->`new.target`, `ReifyArguments`/`GetArgumentsLength`/`GetArgumentsPropByVal`->
  `arguments`, `DirectEval`->`eval(x)`, `CallDirect[LongIndex]`-> direct fn-table call,
  `DeclareGlobalVar`->`var name` at global scope, `ThrowIfEmpty`-> TDZ check passthrough.

Exception handler table (`try/catch`) lives in the per-function info section, only for OVERFLOWED
function headers: `ExceptionHandlerTableHeader{count:u32}` then `count x {start,end,target:u32}`. The
real `hello` v96 fixture has no exception handlers, so try/catch reconstruction is implemented against
the table format but cannot be measured on the committed corpus (honest, documented).

## flutter-snapshot-format

`libapp.so` is an ELF exporting four symbols: `_kDartVmSnapshotData`, `_kDartVmSnapshotInstructions`,
`_kDartIsolateSnapshotData`, `_kDartIsolateSnapshotInstructions`. The Data blobs begin with a snapshot
header: magic(u32 LE 0xdcdcf5f5), length(i64), kind(i64), version_hash(32 ASCII hex),
features(NUL-terminated). After the header comes a clustered object stream (ClassTable, ObjectPool,
code objects). Instructions blob begins with a 64-byte `Image` header (kObjectStartAlignment): two
target words (imageSize, instructionsSectionOffset), then raw ARM64.

CORRECTION: the real Dart VM `Snapshot::Kind` is `kFull=0, kFullJIT=1, kFullAOT=2, kModule=3,
kInvalid=4` (`runtime/vm/snapshot.h`) — NOT the 0/1/2/3=Full/Core/Jit/Aot the prior code assumed.
Fixed; FullAOT is value 2.

ARM64 function boundary signature: every Dart AOT frame opens with `PushPair(FP,LR)` =
`stp x29,x30,[sp,#-16]!` (`0xA9BF7BFD`) then `mov x29,sp` (`0x910003FD`) (`Assembler::EnterFrame`).
Scanning for this pair on 4-byte (kBarePayloadAlignment) granularity yields function boundaries.
Argument-register signature is inferred from x0..x7 reads in the prologue window.

## flutter-recovery-ceiling

Dart AOT emits optimized ARM64: locals are register-allocated away, async lowered to state machines,
closures specialized. Source bodies are NOT statically recoverable at all — zero bodies. We deliver,
as RAW INTEGER COUNTS only: function boundaries (ARM64 frame prologues in the instructions image),
argument-register signatures, class names, demangled method names, and library URIs from the data
snapshot string table. There is NO recovery percentage: the binary carries no source-line denominator,
so any percentage would be invented. The earlier `static_recovery_fraction` was a reverse-fit formula
(`named_share.mul_add(0.45, structure_bonus).min(0.55)`) capped to a documented "45-55%" target and
"verified" only by re-recovering names a test had itself planted — that was a fabricated metric and has
been deleted. Honest framing: "recovers N classes, M methods, K library URIs, B boundaries; bodies = 0
(ARM64 register-erasure wall)."

## measurement

Hermes: readable-construct recovery measured on the corpus `hello` v96 bundle (real bytecode) plus
round-trip synthetic tests that encode buffers per the upstream spec then assert decode equivalence
(non-circular: encoder follows spec, not our decoder). Percentage = reconstructed_ops / total_ops over
the decompiled module.

Flutter: RAW COUNTS only, never a percentage. The real per-binary counts are reported by
`rustdesk_static_recovery_reports_raw_counts` in `tests/real_flutter_rustdesk.rs`, measured against the
committed real `libapp.so`'s OWN isolate snapshot string table + instructions image; it skips (no
synthetic substitute) when the fixture is absent. The synthetic tests in `tests/flutter_libapp_so.rs`
(`arm64_boundary_scanner_counts_prologues`, `name_classifier_buckets_dart_identifiers`) exercise only
the scanner/classifier MECHANICS on planted input and are explicitly NOT a recovery-rate oracle.
