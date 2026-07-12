# disrobe: deterministic static recovery of compiled and obfuscated programs

disrobe is a deterministic, non-LLM static reverse-engineering and deobfuscation suite. It
recovers source, intermediate language, or original bytes from compiled and protected
artifacts by explicit rule, so that the same input always yields the same output and every
result is checkable by a third party. No statistical model, no learned prior, and no
execution of the analyzed program participates in recovery.

**Abstract.** This paper documents three recovery subsystems of disrobe and the verification
discipline common to all of them. The first is deterministic decompilation of CPython
bytecode across the release surface from 1.0 through the 3.15 development line and PyPy,
reducing per-release opcode drift and adaptive specialization to a single version-agnostic
vocabulary before any structuring begins. The second is a native decompiler that lifts
x86-64 machine code into a typed abstract syntax tree with a single precedence authority and
emits both C and Rust, removing the parenthesization errors intrinsic to
string-concatenation emission. The third is managed-VM devirtualization, reconstructing
Common Intermediate Language from two bytecode-virtualizing .NET VM schemes, an in-repo
reimplementation of Eazfuscator.NET's EazVM and the real ConfuserEx-lineage KoiVM, and recording information-theoretic walls where the
plaintext leaves the static file. The final part is the verification methodology itself, a
four-tier taxonomy of non-circular oracles ordered from recompile-equivalence to byte-exact
comparison against the original. The central methodological claim is that every capability is
graded by an oracle disrobe does not control: a real compiler, interpreter, or virtual
machine, or the true pre-transformation input, never disrobe's own output. A green
measurement is treated as false until it has been shown incapable of flattering the tool that
produced it.

## Introduction

### Scope and conventions

This paper covers exactly the recovery passes whose difficulty, or whose method of
evaluation, is not already settled by existing tools. Container parsing, linear and recursive
disassembly, and ordinary bytecode reading are standard practice and are excluded; what
remains are the passes where the reconstruction is ambiguous, where the emitted output can be
silently wrong, or where the correctness of a result is itself hard to establish. Each
section keeps one shape: the problem, why it resists a naive solution, the reconstruction
method with verbatim code, and an evaluation graded by an independent oracle, with
limitations stated beside the results rather than in a footnote.

Every number in this document is read directly from committed sources, a committed test, a
committed data file, or a commit in the repository's own history; none is estimated. Figures
are per code object, per method, or per function unless stated otherwise. Where a measurement
depends on a compiler's code generation, the number reported is a CI-enforced floor set below
the locally observed value, because a floor has to hold on a slower machine and a narrower
toolchain than a development box.

Two terms recur. Recompile-equivalence always means grading against a real, independent
toolchain that disrobe does not control, never against disrobe's re-emission of its own
output. A wall means the pass detects and structurally classifies an artifact but declines to
fabricate a body for data that provenance analysis proves is absent from that artifact, such
as a runtime-derived key or a native-loader-only decryption step; a wall is reported as a
distinct, typed outcome, never folded into a success count.

### Why these passes

The three recovery subsystems are chosen because each isolates a distinct failure mode that a
careless recovery tool hides. Deterministic Python decompilation confronts a moving instruction set
and an interpreter that rewrites its own bytecode, where the risk is a decoder correct for one
release and silently wrong for the rest. The native lift confronts the precedence and
declarator grammar of C, where a printer that concatenates strings produces text that
computes a different value from the machine code it claims to represent. Managed-VM
devirtualization confronts the circular oracle head on, because a devirtualizer graded
against its own output certifies nothing. The verification section then states the discipline
the first three depend on, so that the recovery claims and the evidence for them are read
together. The account begins with the Python decompiler, the largest and most finely graded of
the three recovery subsystems.

### Contributions

The paper's specific contributions, each demonstrated by the evidence in its section, are:

1. A single deterministic CPython bytecode decoder that spans 30 version-specific opcode
   tables from 1.0 through the 3.15 line plus PyPy, folding per-release renumbering and
   adaptive specialization into one version-agnostic vocabulary before any structuring
   (Section 1).
2. A native lift from x86-64 into a typed abstract syntax tree with one precedence authority
   that emits both C and Rust, so that parenthesization and declarator grouping are decided
   once by the grammar rather than per print site (Section 2).
3. In-crate devirtualization of two managed VMs, EazVM and KoiVM, with information-theoretic
   walls recorded where the plaintext body leaves the static file (Section 3).
4. A four-tier non-circular oracle taxonomy applied uniformly across passes, held by
   conservative CI floors on a three-platform matrix (Section 4).

## Related work

disrobe sits beside three established bodies of tooling, and the point of this section is to
say what it does differently, not to rank it.

Python bytecode decompilers. uncompyle6, decompyle3, and pycdc recover Python source from
compiled code objects, each over its own supported range of CPython releases. disrobe's decoder
differs in two concrete ways demonstrated in Section 1: one decoder routes 30 version-specific
tables plus a PyPy overlay through a single canonical opcode vocabulary, and correctness is
graded by recompile-equivalence against a real CPython interpreter rather than by textual
resemblance to the original source.

Native decompilers. Ghidra, RetDec, and Hex-Rays lift machine code to C-like pseudocode. The
native path in Section 2 differs in emission and in grading: recovered code is built as a typed
AST whose parenthesization and C declarator grouping are computed once from the grammar
(Section 2.1 sets out why string-concatenation emission is unsound), and it is validated by a
recompile-execute-differential oracle that links the recovered function against the original
object and refuses any input it cannot soundly lift.

.NET deobfuscation and devirtualization. de4dot cleans a wide range of .NET protectors, and
separate community work has devirtualized KoiVM and ConfuserEx. Section 3 differs in the
oracle rather than the target set: EazVM recovery is graded instruction by instruction against
CIL that a C# compiler emitted into a separate clean assembly the recovery code never reads,
and KoiVM recovery is graded against a hand-derived ground truth that is independent of the
lifter, so neither number can be manufactured by the tool under test.

## 1. Deterministic decompilation of CPython bytecode across versions

This section documents the `disrobe-pass-py-decompile` crate, which recovers Python source from
compiled CPython code objects without any statistical model, learned prior, or interpreter in the
loop at recovery time. The crate spans 84 source files and roughly 41,500 lines. The argument below
proceeds from the problem it solves, to why the problem resists a naive solution, to the exact
reconstruction algorithms in the code, to the recompile-equivalence oracle that grades the result,
to the measured numbers, and finally to the limits the code itself exposes. Every claim is anchored
to a line in the reviewed tree, and every code excerpt is reproduced verbatim.

### 1.1 The problem: deterministic recovery of Python source from bytecode

A CPython `.pyc` file is a container around a marshalled code object: a byte string of bytecode
(`code.code`), a constants pool (`code.consts`), interned name and local-variable tables
(`code.names`, `code.varnames`, `code.localsplusnames`, `code.cellvars`, `code.freevars`), argument
counts, flags, and side tables for source lines and exception ranges. Compilation is lossy in the
directions that matter to a reverse engineer: comments and formatting are gone, and control flow has
been lowered from structured statements into a flat instruction stream threaded by jumps. Decompilation
is the inverse map, from that instruction stream back to source that a person can read and that a
compiler will accept.

Two families of decompiler exist. One family is probabilistic: a model is trained on source and
bytecode pairs and predicts likely source. That approach produces plausible text but offers no
guarantee that the text means what the bytecode meant, which is precisely the guarantee a malware
analyst needs before acting on a finding. The crate here is the other family. It is deterministic and
non-probabilistic: the same input always yields the same output, the output is derived by explicit
rules from the bytecode, and the output is checkable. The pass declares itself a pure transform that
detects raw pyc/pypy/micropython bytes and always emits formatted Python source:

```rust
impl Pass for PyDecompilePass {
    ...
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Python,
            formatted: true,
        }
```
(`src/chain_detector.rs:53-68`)

Determinism matters for reverse engineering and malware analysis for three concrete reasons. First,
static safety: the recovery runs no attacker-controlled code, so analyzing a hostile sample cannot
execute it. The entry point parses bytes and never calls the payload:

```rust
pub fn decompile_pyc(bytes: &[u8]) -> Result<NativeDecompile> {
    if bytes.len() < 4 {
        return Err(DecompileError::Marshal(
            disrobe_py_marshal::Error::PycHeaderShort {
                need: 4,
                got: bytes.len(),
            },
        ));
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
```
(`src/engine.rs:28-37`)

Second, coverage: a rule-based system can be pushed to a measured ceiling on a real corpus and held
there by a regression gate, which a model that guesses cannot promise. Third, reproducibility: a
finding is worth citing only if a stranger can rerun the exact transform and get the exact result,
and only a deterministic transform admits that.

The crate covers a wide version surface deliberately. Malicious and legacy Python arrives compiled
under whatever interpreter its author used, from 1990s 1.x through the 3.15 development line, and
under alternative runtimes such as PyPy and MicroPython. The public API exposes one decompile entry
per runtime family, all returning the same `NativeDecompile` record:

```rust
pub use engine::{
    NativeDecompile, decompile_micropython, decompile_pyc, decompile_pypy, pypy_variant_label,
};
```
(`src/lib.rs:29-31`)

### 1.2 Why it is hard

Three independent difficulties compound: the opcode numbering is not stable across releases, the
modern interpreter carries instructions that hold no source meaning, and the recovery of structured
control flow from a stack machine is ambiguous in general.

#### 1.2.1 Per-release opcode reassignment

CPython renumbers its opcode table almost every minor release and periodically reshapes how an
instruction packs its argument. The crate therefore treats a version not as a single integer but as
a distinct decoding context. The version enumeration carries a variant per supported release plus a
recursive PyPy wrapper:

```rust
pub enum PyVersion {
    V1_0,
    V1_1,
    V1_3,
    ...
    V3_14,
    V3_15,
    PyPy(Box<PyVersion>),
}
```
(`src/bytecode/version.rs:4-36`)

Each release is bound to its magic number, so a raw `.pyc` is routed to the correct context by the
four header bytes:

```rust
3495 => Self::V3_11,
3531 => Self::V3_12,
3571 => Self::V3_13,
3627 => Self::V3_14,
3666 => Self::V3_15,
```
(`src/bytecode/version.rs:106-110`)

The renumbering problem is not only that byte 100 means different things in 3.10 and 3.12. The
argument encoding also drifts. In 3.11 `LOAD_GLOBAL` began using the low argument bit as a flag and
shifting the name index left by one; 3.12 did the same for `LOAD_ATTR`; 3.13 through 3.15 widened the
`COMPARE_OP` operator field; 3.15 shifted the `IMPORT_NAME` index by two to make room for
lazy/eager flags. The decoder computes each of these version-dependent shifts explicitly before it
resolves an operand:

```rust
let attr_index: u32 = if (maj, min) >= (3, 12) { arg >> 1 } else { arg };
let global_index: u32 = if (maj, min) >= (3, 11) { arg >> 1 } else { arg };
let import_index: u32 = if (maj, min) >= (3, 15) { arg >> 2 } else { arg };
let compare_index: u32 = match (maj, min) {
    (3, 13..=15) => arg >> 5,
    (3, 12) => arg >> 4,
    _ => arg,
};
```
(`src/bytecode/opcode/mod.rs:418-425`)

The regression suite pins these shifts against the exact byte values a real interpreter emits, which
is why a mis-shift is caught rather than silently absorbed:

```rust
#[test]
fn import_name_index_shifted_on_315() {
    let op: CanonicalOp = shared_decode(&PyVersion::V3_15, IMPORT_NAME_315, 8);
    assert_eq!(op, CanonicalOp::ImportName(2));
}
```
(`src/bytecode/opcode/mod.rs:1078-1082`)

#### 1.2.2 Adaptive specialization, superinstructions, and quickening carry no source meaning

Since 3.11 the interpreter rewrites its own bytecode at run time. A generic `LOAD_ATTR` is replaced
in place by a specialized `LOAD_ATTR_INSTANCE_VALUE` once the interpreter has observed the receiver
shape; `BINARY_OP` becomes `BINARY_OP_ADD_INT`; hot instructions are followed by `CACHE` entries
that hold inline caches; and pairs of common instructions are fused into superinstructions such as
`LOAD_FAST_LOAD_FAST`. None of these carries information about the original source. A `.pyc` written
after specialization, or a code object captured from a running interpreter, is full of them, and a
decompiler that took them at face value would emit nonsense.

The crate neutralizes all three. Specialized forms are demoted back to their generic meaning before
any structuring sees them:

```rust
"BINARY_OP_ADD_INT" | "BINARY_OP_ADD_FLOAT" | "BINARY_OP_ADD_UNICODE" => {
    Some(CanonicalOp::BinaryOp(BinOp::Add))
}
...
"LOAD_ATTR_INSTANCE_VALUE"
...
| "LOAD_ATTR_SLOT"
| "LOAD_ATTR_WITH_HINT" => Some(CanonicalOp::LoadAttr(arg >> 1)),
```
(`src/bytecode/opcode/mod.rs:757-815`)

Cache slots are counted and skipped during decoding rather than decoded as instructions. The decoder
advances the cursor by the per-opcode cache width so the inline cache bytes never enter the stream:

```rust
cursor += WIDE_STEP;
let caches: usize = usize::from(opmap.cache_size(raw));
if caches > 0 {
    cursor += caches * WIDE_STEP;
}
```
(`src/ast/builder/mod.rs:955-959`)

Superinstructions are split back into their component operations, restoring the two logical pushes
the source implies:

```rust
"LOAD_FAST_LOAD_FAST" => CanonicalOp::LoadFastLoadFast(arg >> 4, arg & 0xF),
"STORE_FAST_LOAD_FAST" => CanonicalOp::StoreFastLoadFast(arg >> 4, arg & 0xF),
"STORE_FAST_STORE_FAST" => CanonicalOp::StoreFastStoreFast(arg >> 4, arg & 0xF),
```
(`src/bytecode/opcode/mod.rs:745-747`)

#### 1.2.3 Stack-machine to structured control flow is ambiguous

CPython is a stack machine. Source expressions become sequences of pushes and pops with no explicit
tree, and source statements such as `if`, `while`, `for`, `with`, `try`, and `match` become flat
regions joined by conditional and unconditional jumps. Recovering the tree and the statement
boundaries is the hard center of decompilation because many distinct source shapes lower to jump
graphs that look alike locally. A conditional forward jump can be the head of an `if`, the head of a
`while`, one link of a short-circuit `and`/`or` expression, one comparator of a chained comparison,
or the guard of a comprehension filter. The same `POP_JUMP_IF_FALSE` opcode participates in all of
these, and the surrounding shape is what disambiguates it. The crate encodes that disambiguation as
an ordered cascade of pattern recognizers, described in 1.3.3, rather than a single generic
control-flow-graph algorithm, because the idioms the compiler emits are specific and version-bound.

### 1.3 Reconstruction methodology

The end-to-end data flow is: raw `.pyc` or code-object bytes, then a version-normalized opcode
stream, then a frame tree and a decoded stream with resolved offsets, then a structured abstract
syntax tree, then emitted source. `build_real_source` is the spine:

```rust
pub fn build_real_source(
    code: &CodeObject,
    decompile_version: &DecompileVersion,
    marshal_version: MarshalVersion,
) -> Result<String> {
    let started: Option<Instant> = wall_clock_start();
    let frame_tree: FrameTree = builder_for(marshal_version).build(code, marshal_version)?;
    let module: AstModule = structure_module(code, &frame_tree, decompile_version)?;
    let pipeline: EmitPipeline = EmitPipeline {
        emitter: Box::new(DefaultEmitter {
            unicode_literals: module_has_unicode_literals(&module),
            ..DefaultEmitter::new()
        }),
```
(`src/engine.rs:212-224`)

Structuring runs on a dedicated 256 MB stack, because the structuring recursion tracks deeply nested
control flow and the default thread stack is not enough for adversarial inputs:

```rust
#[cfg(not(target_arch = "wasm32"))]
const STRUCTURE_STACK_BYTES: usize = 256 * 1024 * 1024;
```
(`src/engine.rs:166-167`)

#### 1.3.1 Opcode normalization: raw byte, to stable mnemonic, to version-agnostic canonical op

The normalization strategy has two stages, and it is the key to spanning the whole version surface
without duplicating decoding logic per release. First, a per-version `OpcodeMap` maps a raw byte to
that version's mnemonic. The crate ships 30 CPython version-specific opcode tables spanning `v1_0`
through `v3_15` (there is no `v1_2`, because CPython 1.2 shares no distinct table), plus dedicated
PyPy tables (`pypy.rs` and `pypy_extras.rs`). All are reachable through one dispatch, `map_for`, which
routes to the 30 concrete release adapters or wraps any base version in the PyPy overlay.

```rust
pub trait OpcodeMap: Debug + Send + Sync {
    fn version(&self) -> PyVersion;
    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp;
    fn cache_size(&self, op: u8) -> u8;
    fn has_arg(&self) -> u8;
    fn opname(&self, op: u8) -> &'static str;
    fn jump_kind(&self, op: u8) -> JumpKind;
    fn family(&self, op: u8) -> OpcodeFamily;
}
```
(`src/bytecode/opcode/mod.rs:296-304`)

```rust
pub fn map_for(version: PyVersion) -> Box<dyn OpcodeMap> {
    match version {
        PyVersion::V1_0 => Box::new(v1_0::V10OpcodeMap),
        ...
        PyVersion::V3_15 => Box::new(v3_15::V315OpcodeMap),
        PyVersion::PyPy(inner) => Box::new(pypy::PyPyOpcodeMap {
            base: map_for(*inner),
        }),
    }
}
```
(`src/bytecode/opcode/mod.rs:307-343`)

The concrete adapters are intentionally thin. Each one binds its version and forwards to the shared
implementation, so the release-specific knowledge is the version tag plus the byte-to-name table it
selects, not a hand-copied decoder:

```rust
impl OpcodeMap for V311OpcodeMap {
    fn version(&self) -> PyVersion {
        PyVersion::V3_11
    }

    fn decode(&self, raw: u8, arg: u32) -> CanonicalOp {
        shared_decode(&PyVersion::V3_11, raw, arg)
    }
```
(`src/bytecode/opcode/v3_11.rs:10-17`)

The PyPy overlay is the one map with genuine per-variant bytes, because PyPy adds opcodes above the
CPython range. It intercepts those and delegates everything else to the wrapped base:

```rust
fn decode(&self, raw: u8, arg: u32) -> CanonicalOp {
    match raw {
        PYPY_LOOKUP_METHOD => CanonicalOp::LoadAttr(arg),
        PYPY_CALL_METHOD => CanonicalOp::CallFunction(u8::try_from(arg & 0xFF).unwrap_or(0)),
        ...
        _ => self.base.decode(raw, arg),
    }
}
```
(`src/bytecode/opcode/pypy.rs:21-33`)

Second, the shared decoder maps the mnemonic, not the byte, to a version-agnostic `CanonicalOp`.
This is what makes per-release renumbering a non-problem for everything downstream: byte 100 differs
across releases, but the name `LOAD_GLOBAL` is stable, and the name is what carries into the single
canonical vocabulary. That vocabulary is a wide enum spanning the whole history of the instruction
set, from `PRINT_ITEM` and `EXEC_STMT` of the 1.x line to `BUILD_TEMPLATE` and `LOAD_SMALL_INT` of
the 3.14+ line:

```rust
pub enum CanonicalOp {
    Nop,
    Pop,
    ...
    LoadConst(ConstIndex),
    LoadSmallInt(i32),
    ...
    BuildTemplate,
    ...
    Specialized(u16),
    Other(u8, u8),
}
```
(`src/bytecode/opcode/mod.rs:140-294`)

The mnemonic-to-canonical mapping is one large explicit match. It folds families of legacy and modern
spellings onto one canonical form, so that later stages never branch on version for meaning. Old and
new division, method-call fusions, and renamed jumps all converge:

```rust
"CALL_FUNCTION" | "CALL" => CanonicalOp::CallFunction(arg_lo),
"CALL_FUNCTION_KW" | "CALL_KW" => CanonicalOp::CallFunctionKw(arg_lo),
...
"JUMP_ABSOLUTE" | "JUMP" => CanonicalOp::JumpAbsolute(arg),
```
(`src/bytecode/opcode/mod.rs:539-562`)

Instructions that exist only to drive interpreter mechanics collapse to `Nop`, including block-setup
opcodes from the pre-3.11 exception model, which are reconstructed structurally later rather than
represented as operations:

```rust
"SETUP_LOOP"
| "SETUP_EXCEPT"
| "SETUP_FINALLY"
| "POP_BLOCK"
...
| "SET_LINENO" => CanonicalOp::Nop,
```
(`src/bytecode/opcode/mod.rs:635-648`)

Genuinely unknown bytes are preserved rather than dropped, as `Specialized(raw)` for instrumentation
and executor opcodes or `Other(raw, arg)` for anything unrecognized, so recovery degrades locally
instead of desynchronizing the whole stream:

```rust
_ => CanonicalOp::Other(raw, arg_lo),
```
(`src/bytecode/opcode/mod.rs:750`)

#### 1.3.2 Decoding, offsets, and jump resolution

Decoding walks the byte string with the version's instruction width. Wordcode (3.6 and later) is
two bytes per instruction with `EXTENDED_ARG` prefixes accumulating a wide argument; classic bytecode
is one byte for opcodes below the argument threshold and three bytes otherwise:

```rust
const LEGACY_HAVE_ARGUMENT: u8 = 90;
const WIDE_STEP: usize = 2;
const NARROW_STEP: usize = 1;
```
(`src/ast/builder/mod.rs:996-998`)

The decoder records, for every emitted canonical op, its starting byte offset and its following byte
offset, into parallel vectors. Because some decodes expand into more than one canonical op (a fused
superinstruction, or a `PUSH_NULL` slot synthesized ahead of a method-form `LOAD_ATTR`), each
synthetic op inherits the enclosing instruction's offsets so that jump arithmetic stays exact:

```rust
offsets.push(here);
ops.push(opmap.decode(raw, arg));
if crate::bytecode::opcode::shared_method_form_load_attr(version, raw, arg) {
    offsets.push(here);
    ops.push(CanonicalOp::Push(0));
}
```
(`src/ast/builder/mod.rs:949-954`)

The decoded stream carries the offset tables plus everything structuring needs to reason about
version-specific flow, including whether jumps are measured in instruction units or bytes and whether
conditional jumps are relative:

```rust
struct DecodedStream {
    ops: Vec<CanonicalOp>,
    offsets: Vec<u32>,
    next_offsets: Vec<u32>,
    ...
    wordcode: bool,
    instr_unit_jumps: bool,
    relative_cond_jumps: bool,
    exception_table: Vec<crate::bytecode::flow::ExceptionTableEntry>,
    ...
    version: PyVersion,
}
```
(`src/ast/builder/mod.rs:320-337`)

Jump targets are resolved from a byte offset to an instruction index by binary search over the
recorded offsets, with a ceiling variant for targets that land inside a decoded region:

```rust
fn index_for_offset(&self, byte_offset: u32) -> Option<usize> {
    self.offsets.binary_search(&byte_offset).ok()
}
```
(`src/ast/builder/mod.rs:340-342`)

Exception structure is version-split. From 3.11 the compiler emits a zero-cost exception table, a
base-128-style varint encoding of protected ranges and handler targets, parsed directly:

```rust
fn read_varint(&mut self) -> Result<u64> {
    let first: u8 = self.read_byte()?;
    let mut value: u64 = u64::from(first & 0x3F);
    let mut more: bool = (first & 0x40) != 0;
    ...
    while more {
        ...
        let next: u8 = self.read_byte()?;
        value = (value << 6) | u64::from(next & 0x3F);
        more = (next & 0x40) != 0;
```
(`src/bytecode/flow.rs:119-133`)

Before 3.11 there is no such table, so the crate synthesizes protected ranges from the
`SETUP_FINALLY` and `SETUP_EXCEPT` block-setup opcodes, computing handler targets from the setup
argument and the instruction width:

```rust
if matches!(name, "SETUP_FINALLY" | "SETUP_EXCEPT") {
    let after: u32 = u32::try_from(cursor + WIDE_STEP).unwrap_or(u32::MAX);
    let delta_bytes: u32 = if version.major() == 3 && version.minor() >= 10 {
        arg.saturating_mul(2)
    } else {
        arg
    };
    let target: u32 = after.saturating_add(delta_bytes);
```
(`src/ast/builder/mod.rs:869-876`)

Source line numbers, used to place recovered statements, are likewise parsed per era: the [PEP 626]
linetable for 3.11+, a transitional linetable for 3.10, and classic `lnotab` before that
(`src/bytecode/flow.rs:146-154`).

#### 1.3.3 Frame tree: a coarse skeleton of compound statements

Recovery is two-phase. First a frame tree gives a coarse, nested skeleton of the compound statements;
then the stack machine and the recursive structurer fill each region with statements and expressions.
A frame is a typed range with children:

```rust
pub struct Frame {
    pub id: FrameId,
    pub kind: FrameKind,
    pub range: Range<u32>,
    pub body_range: Range<u32>,
    pub child_ranges: Vec<Range<u32>>,
    pub handlers: Vec<HandlerRange>,
    pub finally_range: Option<Range<u32>>,
    pub line: Option<u32>,
    pub children: Vec<Frame>,
}
```
(`src/frame_tree/mod.rs:41-52`)

The builder is version-split at the same 3.11 boundary as exception handling:

```rust
pub fn builder_for(version: PyVersion) -> Box<dyn FrameTreeBuilder> {
    if version.major > 3 || (version.major == 3 && version.minor >= 11) {
        Box::new(builder::Post311Builder::new())
    } else {
        Box::new(builder::Pre311Builder::new())
    }
}
```
(`src/frame_tree/mod.rs:107-113`)

The pre-3.11 builder is a straightforward block-stack walk. It pushes a frame on each `SETUP_*`
opcode and closes the top frame on `POP_BLOCK`, using per-version opcode numbers so the same walk
works from 2.x through 3.10:

```rust
if let Some(op) = ops.setup_loop
    && instr.opcode == op
{
    push_block(ctx, &mut stack, instr, FrameKind::WhileLoop)?;
    continue;
}
```
(`src/frame_tree/builder.rs:259-264`)

The post-3.11 builder derives try/with frames from the exception table and loop frames from backward
jumps, classifying each backward jump by what its target begins with (an async-iterator poll, a
`FOR_ITER`, or neither) to distinguish `async for`, `for`, and `while`:

```rust
let kind: FrameKind = if is_async_for {
    FrameKind::AsyncForLoop
} else if is_for {
    FrameKind::ForLoop
} else {
    FrameKind::WhileLoop
};
```
(`src/frame_tree/builder.rs:503-509`)

Frames are then nested by containment, with a depth cap that stops a pathological input from building
an unbounded tree:

```rust
const MAX_FRAME_NEST_DEPTH: usize = 256;
```
(`src/frame_tree/builder.rs:369`)

#### 1.3.4 The stack machine: expressions and statements from stack effects

The heart of expression recovery is an abstract stack simulator. It holds a vector of reconstructed
expressions and replays the canonical stream, applying each op's stack effect on `Expr` values
instead of runtime values:

```rust
pub(super) struct StackSim {
    pub(super) stack: Vec<Expr>,
}
```
(`src/ast/builder/exprs.rs:2669-2672`)

A load pushes a leaf, a binary or subscript op pops its operands and pushes a composite, and a store
pops the value and emits an assignment statement. Subscription is representative: the slice and the
container are popped in stack order and reassembled into a `Subscript` expression:

```rust
CanonicalOp::LoadSubscr => {
    let slice: Expr = sim.pop_or_synth(code, idx);
    let value: Expr = sim.pop_or_synth(code, idx);
    sim.push(Expr::Subscript {
        value: Box::new(value),
        slice: Box::new(slice),
        ctx: ExprCtx::Load,
    });
}
```
(`src/ast/builder/exprs.rs:814-822`)

The simulator is fail-soft by construction. A pop on an empty stack, which happens when a region is
entered mid-expression or when an opcode is unrecognized, yields a `None` constant rather than an
error, so a local gap does not abort the whole recovery:

```rust
pub(super) fn pop_or_synth(&mut self, code: &CodeObject, idx: usize) -> Expr {
    let _: (&CodeObject, usize) = (code, idx);
    self.stack.pop().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}
```
(`src/ast/builder/exprs.rs:2729-2735`)

The simulator returns both the statements it emitted and any residual expressions left on the stack,
which is how the structurer above it obtains, for example, the test expression of an `if` whose
condition was computed but not stored:

```rust
pub(super) fn build_linear_stmts_sim(
    code: &CodeObject,
    ops: &[CanonicalOp],
) -> Result<(Vec<Stmt>, Vec<Expr>)> {
    build_linear_stmts_sim_seed(code, ops, Vec::new())
}
```
(`src/ast/builder/exprs.rs:218-223`)

Beyond the base stack effects, the simulator recognizes several idioms that would otherwise
mis-decompile. Boolean short-circuits are accumulated across the branch instructions that implement
them into a single `BoolOp` rather than left as jumps (`src/ast/builder/exprs.rs:598-640`).
Simultaneous assignment, where the compiler emits a stack rotation followed by stores, is folded back
into a tuple assignment:

```rust
let merged: Stmt = Stmt::Assign {
    targets: vec![Expr::Tuple {
        elts: targets,
        ctx: ExprCtx::Store,
    }],
    value: Expr::Tuple {
        elts: values,
        ctx: ExprCtx::Load,
    },
    type_comment: None,
    line: None,
};
```
(`src/ast/builder/exprs.rs:333-344`)

Imports, class construction, type aliases, and type parameters are threaded through the stack as
encoded marker names (for example `DR_IMPORT_MODULE_PREFIX`, `DR_BUILD_CLASS_MARKER`,
`DR_TYPE_ALIAS_MARKER` at `src/ast/builder/exprs.rs:2782-2792`) that a later stage resolves into the
proper statement, because their bytecode spans several instructions whose meaning is only clear once
assembled.

#### 1.3.5 Recursive structuring: statements from regions

The recursive structurer, `structure_stmts`, turns a range of the canonical stream into a list of
statements. It is the disambiguation engine described in 1.2.3. Its body is an ordered cascade: each
recognizer inspects the region and, if the region matches its idiom, consumes it and returns; if no
compound idiom matches, the region is a leaf and goes to the stack machine. The order is load-bearing,
because the recognizers overlap and the earlier ones are the more specific:

```rust
if let Some(stmts) = try_structure_inline_comprehension(code, stream, lo, hi)? {
    return Ok(stmts);
}
if let Some(stmts) = try_structure_inline_comprehension_noclear(code, stream, lo, hi)? {
    return Ok(stmts);
}
if let Some(stmts) = structure_fallthrough_continue_and_chain(code, stream, lo, hi)? {
    return Ok(stmts);
}
```
(`src/ast/builder/stmts.rs:1632-1640`)

Loops, try regions, and match statements are recognized by dedicated detectors that first confirm the
region is not enclosed by a larger construct, so a nested loop is attributed to its enclosing try or
guard rather than lifted out:

```rust
if let Some(loop_region) = find_loop(stream, lo, hi)
    && !leading_guard_if_encloses_loop(stream, lo, hi, &loop_region)
    && !loop_enclosed_by_guard(stream, lo, &loop_region)
    && !loop_is_else_arm_of_leading_if(stream, lo, hi, &loop_region)
    && !leading_cond_arm_holds_loop(stream, lo, &loop_region)
    && !loop_inside_unpeeled_pre311_try(stream, hi, &loop_region)
{
    return structure_loop(code, stream, lo, hi, &loop_region);
}
```
(`src/ast/builder/stmts.rs:1701-1709`)

When a plain conditional is found, the structurer splits the region into head, then-arm, and else-arm,
recursively structures each arm, and reassembles an `If`, taking care to negate the test when the
jump polarity requires it and to detect the else-arm by a trailing forward jump over it:

```rust
if body_end > jump_idx + 1
    && let Some(last) = then_terminating_jump(stream, jump_idx + 1, body_end)
    && let CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) = stream.ops[last]
    && let Some(j) = resolve_jump_target(stream, last, &stream.ops[last])
    && j > target
    && (j <= hi || else_jump_exits_to_shared_join(stream, last, target, hi))
{
    join = j.min(hi);
    orelse_start = Some(last + 1);
    then_jump_at = Some(last);
}
```
(`src/ast/builder/stmts.rs:1834-1844`)

Chained and compound conditions are reconstructed before the simple case. `try_recover_compound_if`
walks the run of conditional jumps that a single source `if a and b or c:` compiles to, recovers each
operand by running the stack machine over the slice up to its jump, and folds them into one boolean
test:

```rust
for (n, &jump) in jumps.iter().enumerate() {
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
    let Some(value): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
```
(`src/ast/builder/stmts.rs:995-1000` calls into `src/ast/builder/branches.rs:960-1045`)

Exception recovery reads the parsed table to locate the protected body, the handler start, and the
region end, then distinguishes `try`/`except`, `try`/`finally`, and `with`/`async with` by the shape
of the handler prologue:

```rust
let is_with: bool = is_modern
    && matches!(
        stream.ops.get(handler_start + 1),
        Some(CanonicalOp::WithExceptStart)
    );
```
(`src/ast/builder/try_with.rs:416-420`)

Recursion is bounded on three axes so no input can hang the structurer: a per-region reentry limit of
four, a structuring depth limit of 600, and a nested-code-object depth limit of 200
(`src/ast/builder/mod.rs:1112-1187`). When a region reenters too many times it falls back to a linear
recovery rather than recursing again (`src/ast/builder/stmts.rs:1628-1631`).

#### 1.3.6 The AST and emission

The structured output is a typed Python AST that mirrors CPython's own `ast` module, including modern
constructs: `Match`/`MatchCase`/`Pattern` for structural pattern matching, `TypeParam` and
`TypeAlias` for [PEP 695] generics, `TStr`/`TStrItem` for 3.14 template strings, `NamedExpr` for the
walrus operator, and `TryStar` for exception groups (`src/ast/node.rs:133-330`). The emitter walks
this tree to a source string. Recovery is fail-soft at the top level as well: if structuring or
emission of a code object fails, the pass falls back to an annotated disassembly listing and records
that the object was not directly recovered, rather than failing the whole file:

```rust
Err(real_err) => {
    let reason: String = format!("{real_err}");
    let fallback: String = disasm_fallback_source(&code, &decompile_version, &reason);
    Ok(NativeDecompile {
        source: fallback,
        ...
        recovered_directly: false,
        fallback_reason: Some(reason),
    })
}
```
(`src/engine.rs:61-72`)

### 1.4 The recompile-equivalence oracle

The correctness claim rests on an oracle that is non-circular, meaning it never grades disrobe's
output against disrobe's own machinery. The oracle recompiles the recovered source with a real
CPython interpreter and compares the resulting code object to the original, per code object, on
normalized opcodes.

The in-crate oracle drives a real interpreter. It locates the matching interpreter on `PATH`, writes
the recovered source to a temporary file, and asks CPython itself to compile it via `py_compile`:

```rust
let script: String = format!(
    "import py_compile,sys\n\
try:\n    py_compile.compile({src_lit}, cfile={pyc_lit}, doraise=True)\n\
except Exception as e:\n    sys.stderr.write(str(e));sys.exit(2)\n"
);
```
(`src/recompile.rs:173-177`)

It then reads back the interpreter-produced `.pyc` and grades it against the original with
`semantic_equiv`. That function returns one of three verdicts, of which two count as recovered:

```rust
pub enum Verdict {
    Perfect,
    Semantic,
    CodeDiff(DiffDetail),
}
```
(`src/roundtrip/mod.rs:7-12`)

`Perfect` is reserved for a byte-identical code object, checked directly on the raw fields before any
normalization:

```rust
let byte_identical: bool =
    a.code == b.code && a.consts == b.consts && a.names == b.names && a.varnames == b.varnames;
if byte_identical {
    return match compare_nested(a, b, version) {
        Verdict::CodeDiff(d) => Verdict::CodeDiff(d),
        _ => Verdict::Perfect,
    };
}
```
(`src/roundtrip/mod.rs:110-117`)

`Semantic` is the more important verdict in practice, because two source spellings can compile to the
same behavior with different byte layout. It normalizes both instruction sequences and compares them
operation by operation:

```rust
let norm_a: NormalizedSequence = normalize_sequence(a, version);
let norm_b: NormalizedSequence = normalize_sequence(b, version);
if let Some(detail) = compare_normalized(&norm_a, &norm_b, qualname_of(a)) {
    return Verdict::CodeDiff(detail);
}
if let Verdict::CodeDiff(d) = compare_nested(a, b, version) {
    return Verdict::CodeDiff(d);
}
Verdict::Semantic
```
(`src/roundtrip/mod.rs:118-126`)

The normalization is what makes `Semantic` meaningful without being permissive. The Rust oracle and
the Python harness apply the same normalization tables independently: the harness defines the `NOOP`
set of padding mnemonics and the `SPLIT2`, `RENAME`, and `JUMPS` maps that expand superinstructions,
rename specialized loads, and collapse jump spellings (`tests/harness/py_arbitrary_measure.py:39-80`),
mirroring the Rust side. The Rust normalizer removes interpreter padding (`NOP`, `CACHE`, `RESUME`,
`EXTENDED_ARG`, `MAKE_CELL`, and so on at `src/roundtrip/normalize.rs:6-18`), expands superinstructions
and `RETURN_CONST` back to primitives
(`src/roundtrip/normalize.rs:174-241`), resolves each jump to a target instruction index so that
byte-offset drift does not register as a difference (`src/roundtrip/normalize.rs:578-597`), and
canonicalizes operand identity by resolving const, name, and local operands to their values rather
than their indices (`src/roundtrip/normalize.rs:289-320`). Two operations are equal only when opcode,
resolved const value, resolved name, resolved jump target, and compare-operator id all match:

```rust
fn ops_semantically_equal(a: &NormalizedOp, b: &NormalizedOp) -> bool {
    a.token == b.token
        && a.const_value == b.const_value
        && a.name_value == b.name_value
        && a.jump_target_index == b.jump_target_index
        && a.operator_id == b.operator_id
        && raw_arg_semantically_equal(a, b)
}
```
(`src/roundtrip/mod.rs:168-175`)

The comparison also recurses into nested code objects, so a function whose module compiles equal but
whose inner comprehension does not is still charged as a difference (`src/roundtrip/mod.rs:285-317`).

Two points establish non-circularity. First, the graded artifact is a code object produced by CPython
from disrobe's text, not disrobe's own re-emission; disrobe never grades itself. Second, the corpus
harness reimplements the normalization independently in Python and grades the same way, against a
genuine CPython recompile:

> Per-code-object recompile-to-equivalent-bytecode oracle ... compare EVERY nested code object ...
> individually via an opcode-normalized diff. The oracle is non-circular: disrobe's output is graded
> against a real CPython recompile, never against disrobe's own re-emission.
(`tests/harness/py_arbitrary_measure.py:3-8`)

The harness carries an explicit anti-masking guard against a subtle way a per-name comparison could
lie. When several code objects share a qualified name (multiple lambdas or comprehensions under one
parent), positional pairing could let a real miss on one sibling be hidden by a match on another. The
harness refuses that pairing and charges the whole group as failures when the counts differ:

```python
if len(blist) != len(alist):
    if len(alist) > 1:
        sibling_collisions += 1
    for i in range(len(alist)):
        if i >= len(blist):
            reasons["MISSING"] = reasons.get("MISSING", 0) + 1
        else:
            reasons["COLLISION"] = reasons.get("COLLISION", 0) + 1
```
(`tests/harness/py_arbitrary_measure.py:241-248`)

A code object counts as recovered only when its normalized instructions match and its argument counts
match:

```python
def own_equiv(a, b):
    if norm_instrs(a) != norm_instrs(b):
        return False, "code"
    for attr in ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount"):
        if getattr(a, attr) != getattr(b, attr):
            return False, "sig"
    return True, ""
```
(`tests/harness/py_arbitrary_measure.py:146-152`)

### 1.5 Evaluation

Each figure below is stated with its exact corpus, because the corpora differ and must not be
conflated. The representative headline is per-code-object recompile-equivalence on the full 571-module
CPython 3.14 standard library: <!-- m:py_stdlib_full_pct -->92.43%<!-- /m --> (16,880 of 18,262 code objects), locked at HEAD `7adfad10`. A
separate 200-module pinned corpus, a curated subset used as the CI regression sample, runs higher at
<!-- m:py_stdlib_pinned_pct -->95.83%<!-- /m --> (5,920 of 6,286 code objects), precisely because it over-represents recoverable modules; the
crate's own provenance record labels the full-stdlib number as "the honest representative number (the
200-module pinned corpus over-represents recoverable modules)".

The whole-module exact figure, where a module counts only if every one of its code objects is
equivalent, is 54.5%, and it is measured only on the pinned 200-module corpus. There is no
full-stdlib whole-module figure; since the pinned corpus over-represents recoverable modules, the
full-stdlib whole-module rate would be lower still, not higher. The gap between the <!-- m:py_stdlib_full_pct -->92.43%<!-- /m --> per-object
rate and the 54.5% per-module rate is the honest center of the evaluation, not a footnote, and the
two numbers are not even on the same corpus: a module passes only when all of its typically dozens of
code objects pass, so a small per-object miss rate compounds into a large per-module miss rate. A
module with fifty functions and a 92% per-object rate is more likely than not to contain at least one
imperfect object, which fails the whole module. The per-object figure is the metric that guides
improvement because it is granular and monotonic; the per-module figure is the end goal and is
deliberately reported as the harder, lower number. These figures are not re-measured here.

The measurement is enforced as a regression gate, not asserted. The CI gate runs the same harness
over the 200-module pinned corpus (the source of the <!-- m:py_stdlib_pinned_pct -->95.83%<!-- /m --> and 54.5% figures), parses its JSON, and
holds the per-object rate above a floor of 90.0%; the full-stdlib <!-- m:py_stdlib_full_pct -->92.43%<!-- /m --> comes from running that
harness over the entire Lib rather than the pinned list:

```rust
/// Floor enforced in CI.
const OBJECT_PCT_FLOOR: f64 = 90.0;
```
(`tests/arbitrary_recompile_gate.rs:19-20`)

```rust
assert!(
    m.object_pct >= OBJECT_PCT_FLOOR,
    "per-code-object recompile-equivalence regressed: {:.2}% < floor {OBJECT_PCT_FLOOR}% \
     ({}/{} objects on {} modules)",
```
(`tests/arbitrary_recompile_gate.rs:274-278`)

The legacy line has its own gate over a corpus of 191 vendored fixtures spanning 1.x through 3.x. It
grades by a two-verdict union: recompile-equivalence for versions with an available interpreter, and
structural token-match otherwise. The measured proven-correct count is 166 of 191, but the two halves
are not equally strong: 67 of those are recompile-equivalent (the strong, behavioral guarantee) and
99 rest on structural token-match (a strictly weaker guarantee that the recovered token stream matches
a reference, used where the 1.0 through 3.7 interpreter zoo is not present to recompile). The CI floor
of 150 holds on token-match alone, with a separate token-match floor of 86:

```rust
const PROVEN_CORRECT_FLOOR: usize = 150;
const SOURCE_TOKEN_FLOOR: usize = 86;
```
(`tests/legacy_recompile.rs:31-32`)

```rust
let proven_correct: usize = recompile_equiv + source_match;
assert!(
    proven_correct >= PROVEN_CORRECT_FLOOR,
    "proven-correct regressed: {proven_correct} < floor {PROVEN_CORRECT_FLOOR} \
     (platform-stable: recompile-equiv union token-match, minimum is the pure token-match count)"
);
```
(`tests/legacy_recompile.rs:378-383`)

The breadth of the version surface is not asserted rhetorically; it is the 30 CPython version-specific
opcode tables spanning `v1_0` through `v3_15`, plus the dedicated PyPy tables, all enumerated in
`map_for` (`src/bytecode/opcode/mod.rs:307-343`) as 30 concrete release adapters plus the PyPy overlay,
each exercised by the corpus that resolves through them.

Three properties of the evaluation deserve emphasis for a skeptical reader. The corpus is pinned and
version-stable, passed as an explicit module list so the same code objects are measured on every
machine (`tests/harness/py_arbitrary_measure.py:9-13`). The gate measures the real built CLI binary,
not an in-process shortcut, and refuses to run without it (`tests/arbitrary_recompile_gate.rs:170-177`).
And the grader is the independent Python reimplementation of the normalization, so agreement between
the Rust oracle and the Python harness is itself corroboration rather than a single point of trust.

### 1.6 Limitations

The code marks its own edges, and they are worth stating plainly.

Recovery is not total; it degrades to disassembly. When structuring or emission of a code object
throws, the pass emits an annotated disassembly listing and flags `recovered_directly = false`
(`src/engine.rs:61-72`, `src/engine.rs:240-261`). Such an object is legible but is not recovered
source and would not pass the oracle. The per-object percentages in 1.5 are exactly the fraction that
avoids this fallback and recompiles equivalent.

Structural pattern matching is only partially reconstructed on one of the two structuring paths. The
frame-dispatch builder for a `match` frame emits wildcard cases with placeholder patterns and a
`Pass` body rather than recovered patterns:

```rust
cases.push(MatchCase {
    pattern: Pattern::MatchAs {
        pattern: None,
        name: None,
    },
    guard: None,
    body: case_body,
});
```
(`src/ast/builder/stmts.rs:352-359`)

Full pattern recovery exists on the simulation path (`structure_match` in `branches.rs`), so which
result a given `match` receives depends on the route its enclosing region takes; the frame-dispatch
path is a skeleton.

Several statement attributes are not recovered on the frame-dispatch path. `build_function_def` sets
decorators to empty, the return annotation to `None`, and type parameters to empty
(`src/ast/builder/stmts.rs:88-104`); these are recovered elsewhere through the marker mechanism, but
the plain path does not carry them. Lambdas recovered through `build_lambda` reduce the body to the
first returned or expression value and default to `None` when neither is present
(`src/ast/builder/stmts.rs:106-123`).

Deeply nested or adversarial control flow hits hard caps and errors rather than recursing without
bound: structuring depth is limited to 600, nested-code-object depth to 200, frame nesting to 256,
and per-region reentry to 4 (`src/ast/builder/mod.rs:1112-1187`, `src/frame_tree/builder.rs:369`).
Input past these limits fails to a `StructuringDepthExceeded` error and therefore to the disassembly
fallback.

Unknown or future opcodes are preserved but not lifted. A byte with no canonical meaning becomes
`Other(raw, arg)` and instrumentation or executor opcodes become `Specialized(raw)`
(`src/bytecode/opcode/mod.rs:750`, `mod.rs:706-727`); such an op has no expression semantics and will
break recovery of the region that contains it, which is the correct fail-soft behavior but is not
recovery.

Finally, the oracle grades bytecode equivalence, not textual identity. A `Semantic` verdict certifies
that the recovered source compiles to the same normalized instructions, not that it is spelled as the
original author spelled it. This is the right guarantee for reverse engineering, where behavior is
what matters, but it means the numbers in 1.5 measure behavioral fidelity at the granularity of
individual code objects, and should be cited as such rather than as a claim of source reproduction.

Where the Python decompiler recovers structured intent from a stack machine, the native path
faces the inverse hazard on the way out: even a correctly recovered expression tree becomes
wrong source if it is printed without regard to the target grammar.

## 2. The native decompiler: a typed-AST lift from x86-64 to C and Rust

The native path recovers compilable source from raw machine code. It disassembles an
x86-64 function, lifts each instruction into a small typed intermediate representation,
reconstructs control flow, and emits two independent surface languages: C and Rust. The
design principle that separates this path from a string-concatenating printer is
that no target-language text is ever produced by concatenating strings whose meaning
depends on the reader guessing operator binding. Every emitted construct passes through a
typed abstract syntax tree with a single precedence authority, and the recovered source is
graded against the original binary by a recompile-execute-differential oracle that treats a
non-recoverable input as an honest skip rather than a silent pass.

This section documents the emission substrate (`disrobe-emit`), the lift that feeds it
(`disrobe-pass-native/src/pseudo_c.rs`), and the oracle that validates it
(`disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs`).

### 2.1 Why string-concatenation emission is unsound

The naive way to print a recovered expression is to recurse over a tree and glue operator
text together: `format!("{lhs} {op} {rhs}")`. This is unsound because textual
concatenation discards the structural information that decides whether a subexpression
needs parentheses. C and Rust are infix languages with roughly fifteen precedence levels
and per-level associativity; the meaning of a printed string is a function of that grammar,
not of the tree that produced it.

Consider a recovered multiplication whose left operand is itself a recovered addition. The
tree is `Mul(Add(a, b), c)` and denotes `(a + b) * c`. A concatenating printer that emits
each node without consulting the grammar produces `a + b * c`, which the C parser reads as
`a + (b * c)` because multiplication binds tighter than addition. The recovered text now
computes a different value from the machine code it claims to represent. The bug is not a
formatting blemish; it is a semantic corruption that a recompile oracle would surface only
if that exact operand shape happened to appear in a test. The symmetric failure mode is
over-parenthesization, where a printer that wraps every operand in parentheses to be "safe"
produces unreadable output and, for associativity-sensitive operators, can still be wrong
about which grouping the source expressed.

The precedence and associativity decision is not local to one node. It depends on the pair
(child precedence, parent precedence), on the parent's associativity, and on which side
(left or right operand) the child occupies. `a - (b - c)` requires parentheses on the right
operand of a left-associative subtraction; `(a - b) - c` does not require them on the left.
A string printer has no place to make this decision correctly and consistently, so in
practice it either omits parentheses and produces wrong groupings or adds them everywhere
and produces noise.

The typed-AST design removes the failure mode by construction. The recovered program is
built as a tree of typed nodes (`CExpr`, `CStmt`, `CDecl`, and their Rust counterparts).
Parenthesization is not a property the caller chooses per call site; it is computed once, in
one function, from the grammar. Because every operand goes through that one function, the
"forgot to parenthesize here" and "parenthesized inconsistently there" classes of bug
cannot occur: there is no per-site choice to get wrong.

### 2.2 The precedence model and its totality

The entire parenthesization policy lives in `crates/disrobe-emit/src/precedence.rs`, which
is 43 lines. Precedence is a single-byte newtype and an atom sentinel:

```rust
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Precedence(pub u8);

impl Precedence {
    pub const ATOM: Self = Self(u8::MAX);

    #[must_use]
    pub const fn tighter_than(self, other: Self) -> bool {
        self.0 > other.0
    }
}
```
(`crates/disrobe-emit/src/precedence.rs:14`)

The single authority is `parenthesize_operand`. It is a `const fn` and is reproduced here
verbatim:

```rust
#[must_use]
pub const fn parenthesize_operand(
    child: Precedence,
    parent: Precedence,
    parent_assoc: Assoc,
    side: Side,
) -> bool {
    if child.0 > parent.0 {
        false
    } else if child.0 < parent.0 {
        true
    } else {
        match (parent_assoc, side) {
            (Assoc::Left, Side::Left) | (Assoc::Right, Side::Right) => false,
            (Assoc::Left, Side::Right) | (Assoc::Right, Side::Left) | (Assoc::None, _) => true,
        }
    }
}
```
(`crates/disrobe-emit/src/precedence.rs:26`)

The signature is exactly `parenthesize_operand(child, parent, parent_assoc, side)`. The
function is total, and the totality is what makes the design trustworthy. `child` and
`parent` are `Precedence(u8)` values, so `child.0` and `parent.0` are two `u8`s; they are
either strictly ordered or equal. The first branch (`child.0 > parent.0`) handles the case
where the child binds tighter than the parent and therefore never needs parentheses. The
second branch (`child.0 < parent.0`) handles the child binding looser, which always needs
parentheses. The `else` handles equal precedence, where the answer depends on
associativity and side. That final `match` is exhaustive over `(Assoc, Side)`: `Assoc` has
the three variants `Left`, `Right`, `None` and `Side` has the two variants `Left`, `Right`,
so the pair ranges over six combinations, and the two match arms partition all six. There is
no wildcard hiding an unhandled case and no fallthrough default; the Rust compiler's
exhaustiveness check is itself the proof that every operand pair has a defined rule. A left
operand of a left-associative parent needs no parentheses; a right operand does. The mirror
holds for right-associative operators. A non-associative parent parenthesizes either side.
This is precisely the C and Rust grouping rule, encoded once.

The concrete precedence levels are assigned in the C printer,
`crates/disrobe-emit/src/c/print.rs:28`, as fifteen constants from `P_COMMA = Precedence(0)`
through `P_POSTFIX = Precedence(14)`, matching the C operator-precedence table. The atom
level `Precedence::ATOM = Precedence(u8::MAX)` sits above all of them, so literals and
identifiers are never parenthesized. The typed C AST carries 18 binary operators
(`BinaryOp`, `crates/disrobe-emit/src/c/ast.rs:192`), 8 unary operators (`UnaryOp`,
`ast.rs:174`), and 11 compound-assignment operators (`AssignOp`, `ast.rs:214`); every one
of these maps to a precedence and associativity through `binary_precedence`
(`c/print.rs:140`) and is routed through `parenthesize_operand` by the `operand_doc` helper
(`c/print.rs:201`) before it is printed. The worked `(a + b) * c` example resolves as
follows: the additive child has precedence `P_ADDITIVE = 11`, the multiplicative parent has
`P_MULTIPLICATIVE = 12`, so `child.0 < parent.0` fires the second branch and the operand is
parenthesized, yielding `(a + b) * c` rather than the corrupted `a + b * c`.

The rule is validated by a property test rather than by the tool grading its own output. In
`crates/disrobe-emit/tests/c_precedence.rs`, `check_reparse` renders a randomly generated
`CExpr`, parses the rendered text back with an independent C-expression parser, and asserts
the parsed tree is structurally equal to the original (`c_precedence.rs:567`), across 2048
generated cases in both minimal and full parenthesization modes. A precedence bug that
dropped or misplaced a parenthesis would change the reparsed tree and fail the round trip.
A companion invariant asserts that minimal-mode output is never longer than full-mode
output, so the minimal policy cannot secretly over-parenthesize.

### 2.3 The C AST and the inside-out declarator

C declarator syntax is the classic difficulty of any C emitter. A declaration reads
"inside out" and mixes prefix (`*`) and postfix (`[]`, `()`) constructors with parenthesis
grouping whose placement follows the spiral rule, so a pointer to an array is written
`int (*x)[10]` while an array of pointers is `int *x[10]`. Getting the parentheses wrong
changes the declared type.

The recovered type is not a string; it is a linked constructor chain,
`crates/disrobe-emit/src/c/ast.rs:76`:

```rust
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum DeclaratorChain {
    Terminal,
    Pointer {
        quals: CQuals,
        to: Box<Self>,
    },
    Array {
        of: Box<Self>,
        size: Option<Box<CExpr>>,
    },
    Function {
        returns: Box<Self>,
        params: Vec<CParam>,
        variadic: bool,
    },
}
```

A `TypeName` and a `CDecl` each carry a `CBaseType` (the leaf specifier, for example `int`)
plus a `DeclaratorChain`. The chain is built with the fluent constructors `pointer_to`,
`array_of`, and `returning` (`ast.rs:94`), so the type "pointer to function returning
pointer to array of int" is assembled by chaining those calls, and the enum's `Box<Self>`
recursion mirrors the inside-out nesting directly.

Printing is a recursion that threads an accumulator representing "the declarator built so
far" from the innermost constructor outward, and inserts grouping parentheses exactly where
the spiral rule demands them, `crates/disrobe-emit/src/c/print.rs:402`:

```rust
fn declarator_doc<'a>(ctx: &Ctx<'a>, chain: &'a DeclaratorChain, acc: Doc<'a>) -> Doc<'a> {
    let arena: &'a Arena<'a> = ctx.arena;
    match chain {
        DeclaratorChain::Terminal => acc,
        DeclaratorChain::Pointer { quals, to } => {
            let mut head: Doc<'a> = arena.text("*");
            if !quals.is_empty() {
                head = head
                    .append(qualifier_suffix_doc(ctx, *quals))
                    .append(arena.space());
            }
            let inner: Doc<'a> = head.append(acc);
            let wrapped: Doc<'a> = if matches!(
                to.as_ref(),
                DeclaratorChain::Array { .. } | DeclaratorChain::Function { .. }
            ) {
                inner.parens()
            } else {
                inner
            };
            declarator_doc(ctx, to, wrapped)
        }
        DeclaratorChain::Array { of, size } => {
            let bracket: Doc<'a> = size.as_deref().map_or_else(
                || arena.text("[]"),
                |expr: &CExpr| operand_min_doc(ctx, expr, P_ASSIGN).brackets(),
            );
            declarator_doc(ctx, of, acc.append(bracket))
        }
        DeclaratorChain::Function {
            returns,
            params,
            variadic,
        } => {
            let list: Doc<'a> = params_doc(ctx, params, *variadic);
            declarator_doc(ctx, returns, acc.append(list.parens()))
        }
    }
}
```

The grouping decision is the single `if matches!(...)` guard: a pointer whose target is an
array or a function must wrap the accumulated declarator in parentheses, because otherwise
the postfix `[]` or `()` of the target would bind tighter than the prefix `*` and change the
type. Array element size expressions are themselves printed through the precedence machinery
(`operand_min_doc(ctx, expr, P_ASSIGN)`), so a computed array bound cannot be miswritten.

The output layer is a [Wadler-Leijen] document algebra (the `pretty` crate), and the printer
lowers the whole file to a `Doc` before rendering (`c/print.rs`). Operator operands are
parenthesized through `operand_doc` and `operand_min_doc`, which call
`parenthesize_operand` from Section 2.2, so the expression printer and the declarator
printer share the one precedence authority. The declarator logic is checked by a golden
oracle, `crates/disrobe-emit/tests/c_cc_oracle.rs:46`, whose eight cases include the
adversarial spiral `int (*(*x)(int))[5];` (a pointer to a function returning a pointer to an
array of int), and by a proptest that generates random valid declarator chains and requires
a real C compiler to accept every one of them under `ProptestConfig::with_cases(64)`
(`c_cc_oracle.rs:378`). The compiler, not the tool, is the judge.

### 2.4 The Rust path via syn and prettyplease

The Rust emitter does not print Rust text at all. It constructs `syn` AST nodes (the same
data model the wider Rust ecosystem uses to represent parsed Rust) and hands the assembled
`syn::File` to `prettyplease` to unparse. The delegation is the whole of
`crates/disrobe-emit/src/rust/render.rs`:

```rust
use syn::Expr;

use crate::rust::builder::{file, function, trailing_expr};

#[must_use]
pub fn render(file: &syn::File) -> String {
    prettyplease::unparse(file)
}

#[must_use]
pub fn render_expr(expr: &Expr) -> String {
    let wrapped: syn::File = file(vec![function(
        "__disrobe_emit_expr",
        Vec::new(),
        None,
        vec![trailing_expr(expr.clone())],
    )]);
    let rendered: String = render(&wrapped);
    let open: usize = rendered.find('{').map_or(0, |idx: usize| idx + 1);
    let close: usize = rendered.rfind('}').unwrap_or(rendered.len());
    rendered[open..close]
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}
```
(`crates/disrobe-emit/src/rust/render.rs:1`)

`syn` [syn] and `prettyplease` [prettyplease] are widely used across the Rust ecosystem, not a bespoke component
of this project. `syn` is the de facto Rust parser used by procedural macros;
`prettyplease` is dtolnay's unparser that formats a `syn` AST in a rustfmt-style layout.
(The `rustc` compiler itself uses its own internal AST pretty-printer, not `prettyplease`;
the claim here is ecosystem ubiquity, not that this is what the compiler emits.) The
correctness argument is the same one that motivates the typed C AST: reusing a battle-tested
parser and formatter guarantees that any expression the builder can assemble is valid,
canonically formatted Rust, because `prettyplease` inserts grouping according to the Rust
grammar it was written against. There is no hand-rolled Rust precedence table to keep in
sync with the language, and there is no possibility of the recovered Rust failing to parse
because of a printer bug. `render_expr` reuses that guarantee even for a bare expression by
wrapping it in a throwaway function, unparsing, and slicing the body back out, so a lone
recovered expression is still formatted by the same trusted path.

The builder in `crates/disrobe-emit/src/rust/builder.rs` is a set of thin, fully typed
constructors over `syn` node types (`binary`, `unary`, `cast`, `method_call`, `if_else`,
`let_stmt`, `function`, and so on), each returning a `syn::Expr`, `syn::Stmt`, `syn::Type`,
or `syn::Item`. Because the builder produces `syn` nodes rather than text, the emitted Rust
is validated the moment `prettyplease` accepts it, and the round trip is itself property
tested: `crates/disrobe-emit/tests/rust_roundtrip.rs` contains two proptests
(`render_reparse_is_a_fixpoint` and `render_reparse_preserves_tree`) that render a generated
expression, reparse it with `syn`, and require the tree to survive.

### 2.5 The lift: x86-64 into the typed AST

The lift lives in `crates/disrobe-pass-native/src/pseudo_c.rs` and is entered through
`recover_leaf_function_calls_impl` (`pseudo_c.rs:1019`). The pipeline has four stages:
disassemble, lift per instruction into a private IR, structure the control flow, then emit C
and Rust from the structured tree.

Disassembly is delegated to the crate's `iced-x86`-backed decoder,
`disassemble(Arch::X86_64, base, machine_code)` (`pseudo_c.rs:1029`), which yields textual
mnemonic and operand fields per instruction. The lift then walks the instruction stream and
folds each instruction into a small typed IR: registers are modeled as a `Reg` enum with a
separate `Width` (`W8`/`W16`/`W32`/`W64`), memory operands as a `MemRef` with base, scaled
index, displacement, and access width, and each semantic effect as a `Stmt` variant
(`pseudo_c.rs:433`). Register operands are parsed by name into a `(Reg, Width)` pair by
`parse_reg` (`pseudo_c.rs:182`), so `eax` and `rax` resolve to the same `Reg::Rax` with
widths `W32` and `W64`; this is what lets the emitter model sub-register writes as masked
updates of a single 64-bit variable.

Instruction selection is a cascade of guarded lifters. The core arithmetic and data-movement
opcodes are handled by `lift_one` (`pseudo_c.rs:5530`), which recognizes `mov`, `lea`, the
`add`/`sub`/`imul`/`and`/`or`/`xor`/`shl`/`sal`/`shr`/`sar` family, `inc`/`dec`,
`neg`/`not`, `mul`, and the `shld`/`shrd` and three-operand `imul` forms, dispatching each
to a `Stmt`. One idiom: `xor reg, reg` and `sub reg, reg` are recognized as a
zeroing and lowered to `Assign { dest, src: Imm(0) }` (`pseudo_c.rs:5599`) rather than to a
literal self-subtraction, matching what the compiler meant.

Width extension is the part the reader specifically cares about, and it is handled by
`lift_width_extension` (`pseudo_c.rs:4807`):

```rust
fn lift_width_extension(mnemonic: &str, operands: &str) -> Option<Stmt> {
    if mnemonic == "cdqe" {
        if !operands.trim().is_empty() {
            return None;
        }
        return Some(Stmt::Extend {
            dest: RegRef {
                reg: Reg::Rax,
                width: Width::W64,
            },
            src: ExtSource::Reg(RegRef {
                reg: Reg::Rax,
                width: Width::W32,
            }),
            signed: true,
        });
    }
    let signed: bool = match mnemonic {
        "movzx" => false,
        "movsx" | "movsxd" => true,
        _ => return None,
    };
    let (lhs, rhs): (&str, &str) = operands.split_once(',')?;
    let dest: RegRef = parse_reg(lhs.trim())?;
    let rhs_tok: &str = rhs.trim();
    if is_mem_token(rhs_tok) {
        let mem: MemRef = parse_mem_access(rhs_tok, None)?;
        if mem.width >= dest.width {
            return None;
        }
        return Some(Stmt::Extend {
            dest,
            src: ExtSource::Mem(mem),
            signed,
        });
    }
    let src: RegRef = parse_reg(rhs_tok)?;
    if src.width >= dest.width {
        return None;
    }
    Some(Stmt::Extend {
        dest,
        src: ExtSource::Reg(src),
        signed,
    })
}
```

Three width-changing forms are captured here. `cdqe` sign-extends `eax` (32-bit) into `rax`
(64-bit) and is lowered to a signed `Stmt::Extend` from `W32` to `W64`. `movzx` is a
zero-extend, so `signed = false`. `movsx` and `movsxd` are sign-extends, so `signed = true`.
The guard `if src.width >= dest.width { return None; }` (and its memory-operand twin) is a
soundness check, not an optimization: a widening move whose source is not strictly narrower
than its destination is not the extension idiom being modeled, so the lifter declines to
lift it rather than emit a guess. The `signed` flag is carried into `Stmt::Extend` and later
realized by `extend_expr` (`pseudo_c.rs:7943`), which builds the exact mask-and-cast chain
in the typed C AST: it masks the source to its width, casts through the signed or unsigned
integer type of the source width, then to the destination width, then back to a 64-bit
unsigned storage value. Sign correctness of a recovered `movsx` versus `movzx` is therefore
a single boolean threaded from decode to the typed cast, and the oracle in Section 2.6 has a
dedicated teeth test that flips it.

After the linear lift, `structure_items` (`pseudo_c.rs:2974`) reconstructs structured
control flow from the branch and jump items: it builds a basic-block CFG, computes
dominators and post-dominators, detects natural loops and reducible regions, and rebuilds
`if`/`else`, `do`/`while`, top-guarded `while`, and dense `switch` constructs as a tree of
`Node` values (`pseudo_c.rs:574`). Conditions carry the originating comparison flags, and
the lifter tracks flag liveness so that a conditional branch, `cmov`, or `setcc` with no
live preceding comparison is rejected rather than lifted against stale flags
(`pseudo_c.rs:1182`).

Emission then lowers the structured `Node` tree into the typed AST. `node_to_cstmt`
(`pseudo_c.rs:7253`) maps each control node to a `CStmt` (`CStmt::If`, `CStmt::DoWhile`,
`CStmt::While`, `CStmt::Switch`), and `stmt_to_cstmt` (`pseudo_c.rs:7345`) maps each IR
`Stmt` to a `CStmt`, constructing `CExpr` nodes such as `CExpr::Binary`, `CExpr::Cast`,
`CExpr::Ternary`, and `CExpr::Unary`. Every statement is rendered through `render_stmt`,
which is the typed printer of Sections 2.2 and 2.3. The Rust emitter (`emit_rust`,
`pseudo_c.rs:8196`) walks the same structured tree and produces the pure-safe Rust subset,
returning `None` for constructs it does not model as safe Rust (struct returns and block
string operations), which is how the two targets stay independent while sharing one lift.

One honest implementation detail belongs in the record. The emitter is a hybrid: statement
and top-level expression nodes are typed AST values, but some composite subexpression
fragments are assembled as rendered strings and reinserted as opaque operands through
`c_opaque` (`pseudo_c.rs:5945`), which wraps the fragment in explicit parentheses
(`({text})`) before interning it as an identifier atom. The consequence is that the
precedence authority governs every AST-node boundary it constructs, and any pre-rendered
string fragment is defensively fully parenthesized at its splice point, so neither path can
produce a wrong grouping. The masked sub-register write helper `reg_write_rhs`
(`pseudo_c.rs:6034`), the binary-operator helper `bin_expr` (`pseudo_c.rs:7960`), and the
address helper `addr_expr` (`pseudo_c.rs:6064`) all build `CExpr` trees and thread their
results through this parenthesized-fragment convention.

### 2.6 The oracle: recompile, execute, differential, and the honesty property

Recovery is graded against the original binary, never against the tool's own output. The
oracle is `crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs`. The base flow, in
`process_case` (`pseudo_c.rs` test file `:181`) and
`leaf_functions_recompile_to_behavioral_equivalence` (`:264`), is:

1. Compile a hand-authored C battery to a real object file with a real compiler
   (`gcc`/`clang`/`cc`) at `-O1 -fno-stack-protector` (`:285`).
2. Locate each battery function's machine code in the object by symbol, using the `object`
   crate to slice the exact byte range (`function_code`, `:138`).
3. Lift the bytes with `recover_leaf_function_abi` (`:186`).
4. Emit a driver that calls both the original function (linked from the compiled battery
   object) and the recovered function `rec_*` over a fixed vector of adversarial inputs,
   masks both results to the recovered return width, and prints `MISMATCH ... return 1` on
   any disagreement and `OK` only if every input agrees (`:225`, `build_driver` `:245`).
5. Compile and link that driver against the original battery object, run it, and assert the
   process exits successfully with `OK` on stdout (`:341`).

The ground truth is the executed behavior of the compiler's own output for the same source,
so the oracle cannot be satisfied by a recovered function that merely looks plausible; it
must compute the same values as the original machine code on every probe input.

The honesty property is in step 3. When the lifter cannot soundly recover an input, it
returns `Err`, and `process_case` converts that into a skip, not a pass:

```rust
    let recovery: LeafRecovery = match recover_leaf_function_abi(&code, base, abi) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skip {} ({abi:?}): not in leaf class ({e})", case.name);
            return None;
        }
    };
```
(`pseudo_c.rs` test file `:186`)

A skipped case contributes nothing to the differential; it is neither counted as recovered
nor asserted to be correct. If a compiler build happens to lower none of the battery into the
leaf class, the whole test skips with an explanatory message rather than passing vacuously
(`:311`). The lifter reaches `Err` on any input it cannot model soundly: an absent `ret`
("no ret found; not a single-exit leaf", `pseudo_c.rs:1399`), a division without a modeled
high-half dividend setup (`pseudo_c.rs:1119`), a conditional set or branch with no live
compare (`pseudo_c.rs:1182`), a width move that is not the extension idiom (Section 2.5), a
backward string compare or an unbounded single string op (`pseudo_c.rs:1073`), and an
ordering `cmov` that selects a compared operand against their own difference
(`pseudo_c.rs:1242`). Each of these is a refusal to emit a guess, and each is what turns a
green oracle into an honest one.

The differential is proven non-vacuous by 23 companion "teeth" tests. Each takes a genuinely
recovered function, mutates one recovered constant, and asserts the harness now reports
`MISMATCH` rather than `OK`. The read-modify-write teeth test is representative
(`:4753`): it recovers a fused `or [mem], imm`, confirms the recovered OR mask literal
`23205LL` is present, replaces it with `10837LL`, and requires the perturbed harness to
diverge:

```rust
    let corrupted: String = recovered_decls.replacen("23205LL", "10837LL", 1);
    ...
    assert!(
        !stdout.contains("OK") && stdout.contains("MISMATCH"),
        "teeth check FAILED: perturbing the OR mask must diverge, got: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
```
(`pseudo_c.rs` test file `:4816`, `:4848`)

Analogous teeth tests flip `movsx` sign-extension to zero-extension, swap division
signedness, perturb a floating-point constant, relabel a switch case, corrupt a bitcast, and
negate a `setcc` predicate; each confirms that the corresponding recovered detail is load
bearing and that the oracle would catch a regression in it. Loop and control-flow classes
run their harness under a wall-clock watchdog (`run_bounded`, `:1199`) that kills a
non-terminating process and fails the test rather than hanging, so a recovered loop with a
wrong exit condition surfaces as a bounded failure.

### 2.7 Scope and boundaries

The claims above are bounded to what the code actually does, which is recovery of single-exit
leaf functions graded by a hand-authored battery.

The oracle corpus is a battery of small functions written by hand, not a sweep over
arbitrary stripped binaries. The base integer battery is 14 cases (`BATTERY`,
`pseudo_c.rs` test file `:35`), covering arithmetic, mixed-width expressions, min/max and
clamp idioms, and sign selection; the file defines many further batteries (memory access,
read-modify-write, control flow, split returns, natural and nested loops, guarded `while`,
width extension, same-object and precise calls, closed-form multiply-shift, divide, scalar
float arithmetic, min/max, square root, rounding, bitcast, dense and floating-point switch
tables, block move and fill, `setcc`, stack spills, and struct returns). The C oracle file
contains 90 `#[test]` functions and the Rust oracle file
(`crates/disrobe-pass-native/tests/pseudo_rust_leaf_oracle.rs`) contains 11; these are
backed in the emission crate by the precedence and declarator property oracles (roughly a
half-dozen golden and property tests across `c_precedence.rs` and `c_cc_oracle.rs`,
including the `with_cases(64)` declarator proptest) and by 2 render-reparse fixpoint
proptests in `rust_roundtrip.rs`. Both the MS x64 and the System V ABIs are exercised, with
the host-native class gated to Windows and the cross-platform System V floor carried by
`clang` cross-compilation guards on Linux.

What the native leaf path does not do is equally on the record. It recovers single-exit leaf
functions: the lifter requires a `ret` and treats a function it cannot reduce to a single
structured exit as out of class. It targets x86-64 only. The Rust emitter is a strict subset
of the C emitter; it declines struct-returning functions and block string operations by
returning `None`, so a function can be C-recoverable without being in the pure-safe Rust
class. Recovery of instructions outside the modeled set, of irreducible control flow, and of
anything the soundness guards reject is reported as `Err`, which the harness records as a
skip. The path makes no claim to recover whole stripped programs, obfuscated or virtualized
code, or functions whose behavior is not present in the static instruction stream. Its claim
is narrow and verified: for the modeled class, the recovered C and Rust recompile and
execute to the same behavior as the original machine code, and every input outside that class
is refused rather than faked.

The native path grades a recovered function against the behavior of the compiler's own
output; managed-VM devirtualization raises the same non-circularity demand against a harder
adversary, a protector that deletes the original code entirely and ships a randomized
interpreter in its place.

## 3. Managed-VM devirtualization: recovering CIL from bytecode-virtualized .NET assemblies

A bytecode-virtualizing protector does not encrypt a method and decrypt it at runtime. It deletes the method's Common Intermediate Language (CIL) entirely and replaces the body with a stub that hands a stream of custom virtual-machine (VM) bytecode to an interpreter shipped inside the same assembly. The interpreter's opcode table, register layout, and dispatch structure are randomized per build. Recovering the original method therefore means reconstructing three separate objects from static bytes alone: the per-build instruction encoding, the virtual program for each protected body, and a lifting from the VM's stack or register semantics back to CIL. disrobe implements this end to end for two managed VM schemes: an in-repo reimplementation of Eazfuscator.NET's EazVM (the graded sample is encoded by our own virtualizer, not the shipping Eazfuscator.NET product) and the real ConfuserEx-lineage KoiVM (whose sample is the genuine tool's output). It also records honest information-theoretic walls for the protectors whose bodies leave the static file altogether.

The .NET pass classifies twenty-three protector families. The canonical enumeration is fixed in the detector:

```rust
let all: [Protector; 23] = [
    Protector::ConfuserEx,
    Protector::ConfuserEx2,
    ...
    Protector::KoiVm,
    Protector::BitMono,
];
```
(`crates/disrobe-pass-dotnet/src/protectors.rs:222`)

Each family carries a static handling verdict, drawn from `Handling`: `De4dotDelegate`, `NativeStrip`, `GatedDe4dotDelegate`, `Devirtualize`, or `DetectOnly` (`protectors.rs:113-135`). Only KoiVM is tagged `Handling::Devirtualize`; ConfuserEx2's non-VM layers delegate to the de4dot-class cleaner while its constant protection is recovered in-crate; ILProtector, MaxToCode, and the Themida .NET wrapper are `DetectOnly`, for reasons Section 3.4 grounds in the location of the plaintext.

### 3.1 The circularity hazard and the independent-baseline discipline

A common failure mode in devirtualization work is a circular oracle. If a devirtualizer is graded by feeding its own recovered IL back through its own lifter, or by comparing against a "ground truth" that was itself produced by the tool under test, the measurement asserts nothing: a lifter that drops half the program will still agree with itself. A green number obtained this way is not evidence of recovery; it is evidence that a function equals itself.

disrobe's EazVM oracle refuses that shortcut. The virtualized sample and its expected answer come from two physically distinct assemblies. `EazSample.eazvm.dll` is the protected image the devirtualizer consumes, encoded by an in-repo reimplementation of the EazVM scheme (`corpus/dotnet/eazvm/virtualizer/`) rather than the shipping Eazfuscator.NET product; the answer key it is graded against is independent of disrobe's lifter, so the reimplemented encoder does not make the measurement circular. `EazSample.clean.dll` is the same source compiled without the protector; it still contains real, compiler-emitted CIL. The test parses the clean DLL's method bodies directly and treats that CIL, in program order, as the answer key:

```rust
let vm: Vec<u8> = corpus("EazSample.eazvm.dll");
let clean: Vec<u8> = corpus("EazSample.clean.dll");
let recovery: EazVmRecovery = devirtualize(&vm).expect("devirtualize");
...
let known: BTreeMap<String, Vec<OrderedInstr>> = known_method_ordered(&clean, "Compute");
```
(`crates/disrobe-pass-dotnet/tests/real_eazvm.rs:62-72`)

`known_method_ordered` runs disrobe's ordinary CIL parser over the clean image; it never touches the devirtualizer. It builds each expected instruction from the clean method body and resolves branch targets against the clean method's own offset map:

```rust
let body: MethodBody = parse_method_body(image.get(off..)?).ok()?;
let offset_to_index: BTreeMap<u32, usize> = body
    .instructions
    .iter()
    .enumerate()
    .map(|(i, ins): (usize, &Instruction)| (ins.offset, i))
    .collect();
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/grade.rs:160-166`)

Because the answer key is emitted by the C# compiler into a separate file that the recovery code has no access to, agreement between the recovered body and the clean body cannot be manufactured by the recovery code. The comparison is also ordered, not a bag of mnemonics: instruction *i* of the recovered body must equal instruction *i* of the clean body, so a lifter that recovers the right multiset in the wrong order fails.

The discipline has a second, negative half: the unobfuscated baseline must not be mistaken for a VM. The same test asserts that the clean DLL exposes no dispatch table and that attempting to devirtualize it is an error, which guards against a detector that fires on ordinary managed code:

```rust
assert!(
    !d.dispatch_table_present,
    "the unobfuscated baseline must not expose a VM dispatch table"
);
assert_eq!(d.stub_count, 0);
assert!(devirtualize(&image).is_err());
```
(`real_eazvm.rs:52-57`)

### 3.2 Devirtualization approach per protector

disrobe devirtualizes two managed VMs, and their machine models and encodings differ enough
that each gets its own decode-and-lift pipeline: EazVM is a stack machine whose bodies live in
an encrypted embedded resource, and KoiVM is a register machine whose bodies live in a `#Koi`
metadata stream permuted by a per-build seed. ConfuserEx2's remaining non-VM protections are
recovered by a third, static path. The three subsections below give each in turn.

#### 3.2.1 Eazfuscator.NET (EazVM)

EazVM's protected assembly carries an embedded resource named `EazVirtualizedStream` holding every virtualized body as a position-keyed, encrypted virtual-instruction stream (`crates/disrobe-pass-dotnet/src/peel/eazvm/mod.rs:84`, `read_embedded_resource` at `mod.rs:118-137`). Recovery proceeds in four stages: build the opcode map, locate the stubs, decrypt each body's region, and lift.

**Opcode map.** The per-build map from a virtual code to a CIL operation is not guessed. disrobe locates the interpreter's dispatch-table constructor by name, reads the `(virtual-code, handler-method-token)` pairs it installs, and then identifies each handler:

```rust
let dispatch: MethodModel =
    find_dispatch_table(&model).ok_or(DispatchError::NoDispatchTable)?;
let dispatch_body: MethodBody =
    read_body(image, pe, dispatch.rva).ok_or(DispatchError::NoDispatchTable)?;
let pairs: Vec<(i32, u32)> = dispatch_pairs(&dispatch_body);
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/dispatch.rs:135-139`)

`dispatch_pairs` pattern-matches the constructor's own CIL: an `ldc.i4` that supplies the virtual code, immediately followed by an `ldftn` that supplies the handler method token (`dispatch.rs:106-123`). Each handler is then classified by a fingerprint constant embedded in its body: disrobe finds the tagged constant and matches it against a fingerprint computed from the CIL mnemonic:

```rust
fn identify_handler(body: &MethodBody) -> Option<CilOp> {
    let target: i32 = body
        .instructions
        .iter()
        .filter_map(ldc_i4_value)
        .find(|v: &i32| (*v & 0x1000_0000) != 0)?;
    HANDLED_OPS
        .into_iter()
        .find(|op: &CilOp| handler_fingerprint(op.handler_key()) == target)
}
```
(`dispatch.rs:74-83`)

where `handler_fingerprint` is a 28-bit-masked [FNV] hash of `HANDLER:{mnemonic}` with a high tag bit (`dispatch.rs:38-51`). The identified table spans the 48 operations in `HANDLED_OPS` (`dispatch.rs:217-266`), and the oracle confirms all 48 are resolved (`real_eazvm.rs:44`). This fingerprint-keyed identification is how disrobe's corpus sample encodes handler identity; the surrounding pipeline (dispatch discovery, pair extraction, stream decode, lift, name resolution) is the general mechanism.

**Stub location and body decryption.** A virtualized method is recognized structurally: it carries an `ldstr` of an encrypted position string, at least two `ldc.i4` constants (the resource and position keys), and at least three `pop` operations (`is_vm_stub`, `dispatch.rs:194-215`). The position string is decrypted with candidate keys harvested from the stub itself, and the resulting offset selects the body's region inside the decrypted resource. The full per-body decode chain is:

```rust
fn decode_one(
    encrypted_resource: &[u8],
    resource_key: i32,
    position: i64,
    map: &OpcodeMap,
) -> Option<(EazMethodInfo, LiftedBody)> {
    let start: u64 = u64::try_from(position).ok()?;
    let remaining: usize = encrypted_resource
        .len()
        .checked_sub(usize::try_from(start).ok()?)?;
    let region: Vec<u8> = decrypt_region(encrypted_resource, resource_key, start, remaining)?;
    let info: EazMethodInfo = parse_method_info(&region).ok()?;
    let virtuals: Vec<VirtualInstr> = decode_stream(&info.code, map).ok()?;
    let lifted: LiftedBody = lift(&virtuals).ok()?;
    Some((info, lifted))
}
```
(`mod.rs:304-319`)

**Stream decode.** The virtual instruction stream is not little-endian. Each virtual opcode is a 32-bit word in a byte permutation disrobe reads with `read_int32_special`, then the operand is decoded per the opcode's operand class:

```rust
let virtual_code: i32 =
    read_int32_special(code, pos).ok_or(DecodeError::Truncated(virtual_offset))?;
pos += 4;
let op: CilOp = map
    .get(virtual_code)
    .ok_or(DecodeError::UnknownVirtualCode(virtual_code, virtual_offset))?;
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/disasm.rs:38-46`)

```rust
let value: u32 = (u32::from(b[3]) << 24)
    | u32::from(b[2])
    | (u32::from(b[1]) << 8)
    | (u32::from(b[0]) << 16);
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/opcodes.rs:192-197`)

Operand classes cover inline i8/i32 immediates, byte/word variable indices, a short branch (stored as a full i32 stream offset), and inline member and string tokens (`opcodes.rs:48-67`, `disasm.rs:48-92`).

**Lift.** Lifting resolves each decoded branch offset to a target *index* in the recovered instruction list, converting stream offsets into structured control flow:

```rust
DecodedOperand::Branch(target) => {
    let dest: usize = *index_by_offset
        .get(target)
        .ok_or(LiftError::UnresolvedBranch(*target))?;
    LiftedOperand::BranchTo(dest)
}
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/lift.rs:47-52`)

An unresolved branch is a hard error, not a silent drop, so a partially decoded body cannot masquerade as complete.

#### 3.2.2 KoiVM (the ConfuserEx / ConfuserEx2 VM)

KoiVM is a register-machine VM originally distributed as a ConfuserEx protection. Its virtualized bodies live in a metadata stream named `#Koi`, and its opcode, register, and virtual-call tables are permuted by a per-build seed fed to .NET's `System.Random`. disrobe reconstructs all three.

**Faithful RNG.** The descriptor tables can only be regenerated if the pseudo-random shuffle exactly matches .NET's. disrobe reimplements the framework's subtractive `Random` generator ([Knuth]) and pins it against real System.Random(0) output:

```rust
let mut r: NetRandom = NetRandom::new(0);
let got: [i32; 10] = core::array::from_fn(|_| r.next_bounded(1000));
let want: [i32; 10] = [726, 817, 768, 558, 206, 558, 906, 442, 977, 273];
assert_eq!(got, want, "NetRandom must match real System.Random(0)");
```
(`crates/disrobe-pass-dotnet/src/peel/koivm/random.rs:104-109`)

The descriptors are then derived by shuffling identity arrays with that generator, exactly as the protector does at build time:

```rust
let mut opcode_order: [u8; 256] = core::array::from_fn(|i: usize| i as u8);
rng.shuffle(&mut opcode_order);
...
let mut opcode_decode: [Option<KoiOp>; 256] = [None; 256];
for ordinal in 0u8..KOI_OP_MAX {
    let encoded: u8 = opcode_order[usize::from(ordinal)];
    opcode_decode[usize::from(encoded)] = KoiOp::from_ordinal(ordinal);
}
```
(`crates/disrobe-pass-dotnet/src/peel/koivm/descriptors.rs:17-37`)

The generated map is anchored against the real KoiVM's seed-0 tables (`descriptors.rs:104-119`, `random.rs:112-128`), so the encoding disrobe decodes is the encoding the protector emitted, not a plausible-looking guess.

**Encrypted stream decode and CFG recovery.** Each `#Koi` byte is XOR-decrypted with a rolling key that mutates after every byte, seeded per basic block by the block's entry key:

```rust
const fn decrypt(&mut self, cipher_byte: u8) -> u8 {
    let plain: u8 = cipher_byte ^ self.key;
    self.key = self.key.wrapping_mul(7).wrapping_add(plain);
    plain
}
```
(`crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs:56-60`)

`disassemble_method` walks the control-flow graph from the export's entry offset with a worklist, decoding one block at a time and following the exit key into each successor, so the per-block cipher state stays correct across jumps (`disasm.rs:193-229`). Terminators (`Jmp`, `Jz`, `Jnz`, `Ret`, `Leave`, `Swt`) end a block and enumerate its successors with their inherited keys (`disasm.rs:124-160`).

**Lift.** KoiVM is a register machine over a stack discipline. disrobe interprets the block abstractly, tracking a value stack and register file, recognizing the `BP`-relative address arithmetic that encodes frame slots, and classifying each slot as an argument or local:

```rust
const fn classify(self, slot: i32) -> Value {
    if slot < 0 {
        let arg_base: i32 = -(self.arg_count.cast_signed() + 1);
        let index: i32 = slot - arg_base;
        if index >= 0 && index.cast_unsigned() < self.arg_count {
            return Value::Arg(index.cast_unsigned());
        }
    } else if slot > 0 {
        let local_index: i32 = slot - 1;
        if local_index >= 0 {
            return Value::Local(local_index.cast_unsigned());
        }
    }
    Value::FrameAddr(slot)
}
```
(`crates/disrobe-pass-dotnet/src/peel/koivm/lift.rs:178-192`)

Indirect loads and stores against a recovered frame address emit `LoadArg`/`LoadLocal`/`StoreArg`/`StoreLocal`; arithmetic emits typed binary operations; `Vcall` codes resolve through the seed-derived virtual-call table to `LoadField`, `StoreField`, `LoadToken`, `LoadString`, `Throw`, or a named runtime service, and member operands resolve through the `#Koi` coded-token map back to real metadata tokens (`lift.rs:304-591`). A virtual-call code with no table entry surfaces as `Unknown` and is counted, never dropped; the lifter asserts zero unknown ops on every real body (`lift.rs:756-765`).

#### 3.2.3 ConfuserEx2 non-VM layers

ConfuserEx2 proper virtualizes through the KoiVM path above; its remaining protections are a constant-encryption pool and control-flow flattening. disrobe recovers the constant pool statically rather than delegating it. The encrypted blob is located via the class-layout and FieldRVA metadata, candidate seeds are harvested from the assembly's own `ldc.i4` immediates and by emulating the decoder, and each seed is validated by decrypting the blob and requiring a well-formed LZMA header before the pool is decompressed:

```rust
if plaintext.first() != Some(&CONSTANTS_LZMA_PROPS) || plaintext.len() < 9 {
    continue;
}
...
let Ok(pool): Result<Vec<u8>> = lzma_decompress(&plaintext) else {
    continue;
};
if pool.len() == uncompressed {
    return Some((*seed, pool));
}
```
(`crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs:283-297`)

The block cipher is the protector's own key-evolving XOR over 64-byte blocks with an XorShift-derived key schedule (`decrypt_constants_blob` and `derive_constants_key`, `confuserex_constants.rs:129-175`), and recovered strings are re-associated to their call sites through the `mutate_id` transform (`confuserex_constants.rs:177-204`). The seed is only accepted when the decompressed length matches the header's declared length, an internal consistency check that rejects wrong seeds without any external oracle.

### 3.3 The oracle: ordered CIL against a separately compiled baseline

The EazVM grade is the strongest in the .NET pass. `grade_ordered` compares the recovered and expected instruction lists position by position and reports both matched count and the maximum length, so a short or long recovery is penalized:

```rust
let length: usize = expected.len().max(recovered.len());
let common: usize = expected.len().min(recovered.len());
let mut matched: u32 = 0;
for i in 0..common {
    if expected.get(i) == recovered.get(i) {
        matched += 1;
    }
}
```
(`crates/disrobe-pass-dotnet/src/peel/eazvm/grade.rs:408-421`)

The corpus's five virtualized bodies hold exactly 57 instructions in the clean baseline, and every one of them must match in order. The test fixes both the count and the percentage:

```rust
assert_eq!(
    total_length, 57,
    "the five Compute bodies hold 57 instructions in the clean baseline"
);
assert!(
    (pct - 100.0).abs() < f64::EPSILON,
    "ordered CIL recovery against the known original must be 100%; got {pct:.2}% \
     ({total_matched}/{total_length})"
);
```
(`real_eazvm.rs:96-104`)

The result is 57 of 57 instructions recovered in order, a 100% ordered match against compiler-emitted CIL the recovery code never saw. A separate test closes the loop dynamically when a .NET runtime is present: the recovered CIL is rendered, re-injected into a rebuilt assembly, executed, and its standard output compared byte-for-byte against the clean program's output `"5\n69\n55\n-1\n9\n"` (`real_eazvm.rs:200-306`, expected constant at `real_eazvm.rs:23`). When no runtime is on `PATH` the dynamic half is skipped explicitly and the in-process ordered-CIL equivalence still gates the run (`real_eazvm.rs:223-233`); the numeric claim never silently depends on a tool that was absent.

KoiVM is graded against an independent, hand-specified projection of the same six methods rather than compiler-emitted CIL. The `ground_truth` table declares the expected operation sequence for each method (`koivm/grade.rs:64-126`), `project` collapses the lifted body into the same coarse vocabulary, and the aggregate must clear a 75% floor:

```rust
let pct: f64 = f64::from(total_matched) / f64::from(total_expected) * 100.0;
println!("AGGREGATE: {total_matched}/{total_expected} = {pct:.1}%");
assert!(
    pct >= 75.0,
    "aggregate structural recovery against known originals must be >= 75%; got {pct:.1}%"
);
```
(`koivm/grade.rs:226-232`)

All six bodies are decoded and lifted to CIL with zero unknown ops (`detect` reports `virtualized_method_count == 6`, and `devirtualize` returns six methods with no undecoded ids, `koivm/mod.rs:222-259`); of these, two (Add, Square) are proven to recover fully, matching their hand-derived ground-truth ops in full, and the remaining four (SumTo, Classify, Factorial, Max3) are bounded only by the >=75% aggregate floor. This oracle is weaker than the EazVM one: the answer key is authored by hand from knowledge of the source, not parsed from a separately compiled clean assembly, and the comparison is over a projected op vocabulary rather than exact ordered CIL. It is still non-circular, because the ground truth is independent of the recovery code, and it is anchored by the RNG and descriptor tests that validate the decode against real System.Random output.

### 3.4 Static-recovery walls: ILProtector, MaxToCode, and Themida-class native VMs

Three families are `DetectOnly` (`protectors.rs:134`), and their `plan_execution` verdict is `DetectOnly`, not devirtualization (`protectors.rs:371-390`). This is a proven information-theoretic ceiling, not an unfinished feature, because in each case the plaintext CIL is absent from the static file by construction.

**ILProtector** replaces each body with an Invoke-stub and stores the ciphertext in a managed resource, but the decryption key and logic live in a native runtime delegate. The plaintext exists only after the assembly runs and calls its own decrypt delegate:

```rust
const BASE_RATIONALE: &str = "ILProtector replaces every protected method body with an Invoke-stub (ldsfld <delegate>; \
     ldc.i4 <method-id>; call Invoke; ret) and stores the ciphertext for each body in an embedded \
     managed resource reached through the CLI resources directory. The plaintext IL is produced only \
     by invoking the assembly's own runtime decrypt delegate ...";
```
(`crates/disrobe-pass-dotnet/src/peel/ilprotector.rs:13-19`)

**MaxToCode** zeroes every protected method's RVA and restores bodies at JIT time through an unmanaged loader hooked into the execution engine. The per-method key is computed inside that native DLL, so it is not in the static metadata:

```rust
const BASE_RATIONALE: &str = "MaxToCode sets every protected MethodDef RVA to 0 and stores the ciphertext for each body in \
     an added native-loaded section, restoring the bodies at JIT time through an unmanaged loader \
     hooked into the EE/JIT layer ... The per-method key is computed inside that native DLL, so the \
     original CIL is not present in the static metadata ...";
```
(`crates/disrobe-pass-dotnet/src/peel/maxtocode.rs:13-19`)

**Themida .NET** wraps the managed assembly inside Oreans' native VM, translating protected bodies into native VM bytecode that is decrypted into RWX memory only at runtime:

```rust
const BASE_RATIONALE: &str = "Themida-.NET wraps the managed assembly inside the Oreans native VM. Protected method bodies \
     are translated into native VM bytecode and decrypted into RWX memory only at runtime. This is \
     genuine native virtualization; per project policy disrobe does not ship a native-VM \
     devirtualizer (VMP/Themida class). The native-VM-protected methods are walled, not fabricated.";
```
(`crates/disrobe-pass-dotnet/src/peel/themida_dotnet.rs:13-16`)

The wall is not silence. Each `DetectOnly` path still performs every static recovery the ceiling permits, and reports it honestly. ILProtector enumerates the Invoke-stubs and locates the encrypted-body resource (offset, size, hash) before declaring the `RUNTIME-DELEGATE WALL` (`ilprotector.rs:64-89`); MaxToCode enumerates the zero-RVA methods and the encrypted section before declaring the `NATIVE-KEY WALL` (`maxtocode.rs:63-86`); and all three disassemble the native loader or VM section as machine code through `surface_native_stub`, surfacing the unmanaged support code without claiming to have devirtualized it (`ilprotector.rs:44-60`, `maxtocode.rs:43-59`, `themida_dotnet.rs:22-37`). The distinction the pass draws is exact: what can be recovered statically is recovered and measured against an independent baseline; what genuinely leaves the static file (a runtime-produced key, a JIT-restored body, a native-VM translation) is walled with a stated reason and the residual static evidence, never fabricated.

Each preceding section asserted a recovery result and named the oracle that certified it; this
section states the oracle discipline in full, ordered from the weakest external check to the
strongest, so that every earlier number can be traced to the class of evidence behind it.

## 4. Verification methodology: grading recovery against non-circular oracles

Every capability claim disrobe makes rests on a single discipline: a recovery is credited only when an oracle that disrobe does not control confirms it. This section states that discipline precisely, enumerates the oracle forms disrobe uses from weakest to strongest, and shows the code that implements each. The organizing principle is adversarial.

### 4.1 The central failure mode: circular oracles

A circular oracle grades a tool against an artifact the tool itself produced, or against a synthetic fixture constructed so that it can only agree with the tool. Both are epistemically empty. If a deobfuscator emits an output and then a test asserts that the output equals what the deobfuscator emitted, the test asserts nothing about correctness; it asserts determinism. If a fixture is hand-written to match the exact opcode sequence a decoder happens to produce, the fixture certifies the decoder against its own assumptions rather than against ground truth. The history of the project records concrete instances of this trap: a bytecode decoder once passed a suite of synthetic tests that had been written to agree with it, and the decoder was wrong; the failure was invisible until the same code was run against a real interpreter and a real specification.

The discipline against circularity has three rules, and they bind every pass.

First, the oracle must be external. The reference answer is produced by a real compiler, a real interpreter, a real virtual machine, or the true pre-transformation input, never by disrobe. Second, the fixture must be real. Test inputs are produced by the genuine obfuscator, packer, or compiler under study, not authored by hand to agree with the recovery. Third, the comparison must be over ground truth, not over the tool's own intermediate representation. Where a synthetic helper is unavoidable, its provenance is auditable; the codebase is periodically swept for `synth_*` helpers precisely so that a synthetic fixture cannot silently become the grader of the code that generated it.

The consequence is that a passing test in disrobe is a claim about the world, not a claim about disrobe. Sections 4.2 through 4.4 show how that claim is made, and made portable.

### 4.2 The non-circular oracle taxonomy, weakest to strongest

disrobe grades recovery with four oracle forms of increasing strength. Each form is stronger than the one before it because it depends on a wider and more independent body of external truth. The recovery signal a pass reports is drawn directly from which oracle form certified it, so the confidence tier is not a self-assessment but a record of which external check passed.

The signal enum is the spine of this mapping:

```rust
pub enum RecoverySignal {
    ByteRoundtripVerified,
    RecompilesEquivalent,
    FullBodyLifted,
    SomeBodiesLifted,
    StructuredNoVerify,
    SignaturesOnly,
    NoRecovery,
}
```
`crates/disrobe-core/src/recovery.rs:48`

The two strongest variants, `ByteRoundtripVerified` and `RecompilesEquivalent`, correspond to the two strongest oracle forms below. A pass that cannot reach either reports a lower signal honestly rather than inflating the higher one.

#### 4.2.1 Recompile-equivalence (weakest of the strong forms)

The recovered artifact is fed back through the real compiler or interpreter for its language, and the resulting object is compared, after normalization, against the object produced from the original. The oracle here is the language toolchain itself. disrobe does not decide whether its recovered Python is correct; it recompiles the recovered source and asks whether the recompiled code object matches the original code object.

The Python decompiler's equivalence judge is the reference implementation of this form. It is the `semantic_equiv` judge shown in section 1.4: byte identity is checked first as the strongest possible outcome, and when the bytes differ the two code objects are normalized and compared operation by operation, descending into nested code objects, before any equivalence is granted (`crates/disrobe-pass-py-decompile/src/roundtrip/mod.rs:108`). What section 1.4 did not show is how a verdict becomes a recovery signal. The mapping is without editorializing: a byte-identical recompile is `ByteRoundtripVerified`, a normalized-equal recompile is `RecompilesEquivalent`, and any residual difference is `NoRecovery`:

```rust
impl From<&Verdict> for disrobe_core::RecoverySignal {
    #[inline]
    fn from(verdict: &Verdict) -> Self {
        match verdict {
            Verdict::Perfect => Self::ByteRoundtripVerified,
            Verdict::Semantic => Self::RecompilesEquivalent,
            Verdict::CodeDiff(_) => Self::NoRecovery,
        }
    }
}
```
`crates/disrobe-pass-py-decompile/src/roundtrip/mod.rs:14`

The normalization is deliberately narrow. It collapses only differences that are semantically irrelevant, and it is itself defended against a subtle circularity: floating-point constants are canonicalized so that a NaN produced on one architecture compares equal to a NaN produced on another, while signed infinities and negative zero remain distinct because they are semantically distinct.

```rust
/// Collapse every NaN payload to one representative bit pattern.
#[must_use]
fn canonical_float_bits(f: f64) -> u64 {
    if f.is_nan() {
        f64::NAN.to_bits()
    } else {
        f.to_bits()
    }
}
```
`crates/disrobe-pass-py-decompile/src/roundtrip/mod.rs:80`

This is the weakest of the strong forms because it certifies that the recovered source recompiles to the same code, not that the same code behaves identically on inputs. For most languages the two are equivalent, but the stronger forms below remove even that assumption.

#### 4.2.2 Recompile-execute-diff

Two binaries are produced independently, one from the recovered source and one from the ground-truth source, and both are executed over a shared battery of inputs. Equivalence is granted only when every input yields identical output. The oracle here is not a static comparison of code but the observable behavior of two separately compiled programs. This is stronger than recompile-equivalence because it survives any difference in code that does not change behavior, and it fails loudly on any difference that does.

The native pseudo-C leaf decompiler is graded this way. A battery of C functions is compiled to an object by the real system compiler, disrobe recovers C source from the machine code, and the recovered source is compiled and linked against the original object into a single harness that calls both and compares results:

```rust
const BATTERY: &[Case] = &[
    Case {
        name: "f_add",
        arity: 2,
        c_source: "long long f_add(long long a, long long b){ return a + b; }",
    },
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:35`

The differential loop is the heart of the oracle. For each input triple, the harness calls the original function and the recovered function and aborts on the first mismatch:

```rust
    let _ = write!(
        driver_snippet,
        "    for (size_t k = 0; k < n_inputs; k++) {{\n\
         \x20       long long in[3] = {{ inputs[k][0], inputs[k][1], inputs[k][2] }};\n\
         \x20       unsigned long long want = (unsigned long long){}({}) & {return_mask};\n\
         \x20       unsigned long long got = {recovered_name}({}) & {return_mask};\n\
         \x20       if (want != got) {{ printf(\"MISMATCH {} in=%lld,%lld,%lld want=%llu got=%llu\\n\", in[0], in[1], in[2], want, got); return 1; }}\n\
         \x20   }}\n",
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:226`

The pass is credited only if the linked harness runs and prints `OK`:

```rust
    let run: std::process::Output = Command::new(&harness_exe).output().expect("run harness");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success() && stdout.contains("OK"),
        "behavioral differential FAILED ({lifted_count} cases): {stdout}\nstderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:341`

Because the recovered function is linked against the same object that produced the reference, there is no shared code path between the recovery and the truth: the truth is native machine code compiled by a third-party compiler, the recovery is disrobe's reconstructed source, and the only thing they have in common is the input battery. A mismatch cannot be papered over.

#### 4.2.3 Independent-baseline grade

The recovered artifact is graded against a separately produced clean artifact that was never packed, virtualized, or obfuscated. The oracle is a second, independently built version of the same program. This is the form used when the recovery target is a transformation that has an inverse only in the presence of a known-good reference, such as a commercial virtualizing protector.

The Eazfuscator VM devirtualizer is graded against a clean assembly compiled from the same source without the protector. First, the clean baseline must not be mistaken for the protected one, which guards against a detector that fires on everything: the negative-baseline test shown in section 3.1 asserts the clean DLL exposes no dispatch table, carries zero stubs, and cannot be devirtualized (`crates/disrobe-pass-dotnet/tests/real_eazvm.rs:48`). Then the devirtualized CIL is graded instruction by instruction, in order, against the CIL of the clean baseline, and the match must be exact, using the `grade_ordered` comparison and the 57-of-57 assertion shown in section 3.3 (`crates/disrobe-pass-dotnet/tests/real_eazvm.rs:72`).

The strongest step in this oracle removes even the assumption that matching CIL implies matching behavior. The recovered CIL is re-injected into an assembly, rebuilt with the real .NET toolchain, executed, and its standard output is compared byte for byte against the known output of the clean program:

```rust
const EXPECTED_STDOUT: &str = "5\n69\n55\n-1\n9\n";
```
`crates/disrobe-pass-dotnet/tests/real_eazvm.rs:23`

```rust
    assert_eq!(
        stdout, EXPECTED_STDOUT,
        "the assembly rebuilt from the devirtualized CIL must print the clean baseline output \
         byte-for-byte; got {stdout:?}"
    );
```
`crates/disrobe-pass-dotnet/tests/real_eazvm.rs:301`

The independent baseline is what makes this non-circular. disrobe never sees the clean CIL during devirtualization; it recovers from the virtualized bytecode alone, and the clean assembly exists only in the test to grade the result.

#### 4.2.4 Byte-exact-vs-original (strongest)

The recovered image is compared byte for byte against the true pre-transformation input. The oracle is the original file itself, the one artifact that cannot be argued with. There is no normalization, no behavioral tolerance, no recompilation step that might absorb a defect: the recovered bytes either equal the original bytes or they do not.

The UPX unpacker is graded this way against a committed original that was compressed by the genuine UPX packer. The recovered executable section and the recovered exception-unwind section must be byte-identical to the original:

```rust
#[test]
fn nrv2b_recovered_text_is_byte_identical_to_committed_original() {
    let out: UpxUnpackOutput = unpack_upx(PACKED_NRV2B).expect("unpack committed UPX fixture");
    let sections: Vec<OriginalSection> = parse_original_sections(ORIGINAL);

    let text: &OriginalSection = section_by_name(&sections, ".text");
    let recovered_text: &[u8] = recovered_section(&out.recovered_image, text);
    let original_text: &[u8] = original_section_disk(text);
    let diffs: usize = byte_diff_count(recovered_text, original_text);
    assert_eq!(
        diffs, 0,
        "recovered .text must be BYTE-IDENTICAL to the committed original ({} bytes); the CT \
         call filter (0x49) reversal recovers the executable code exactly. measured diffs={diffs}",
        text.content_len
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:129`

The same byte-exact standard is applied to the LZMA-compressed variant, where the `.text` and `.pdata` sections must again show zero differences:

```rust
    assert_eq!(
        byte_diff_count(recovered_text, original_text),
        0,
        "UPX-LZMA recovered .text ({} bytes) must be byte-identical to the committed original",
        text.content_len
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:278`

For the whole image, where a portion of the file is legitimately rebuilt by the operating-system loader at run time and is therefore not present in the packed stream, disrobe does not claim byte identity it cannot honestly achieve. It measures content-section byte recovery against a stated floor and, separately, proves that every residual difference falls only in loader-rebuilt zones:

```rust
    assert!(
        recovery_pct >= FLOOR_PCT,
        "UPX content-section byte recovery {recovery_pct:.2}% fell below the {FLOOR_PCT:.2}% floor"
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:189`

```rust
    assert_eq!(
        diffs_outside_loader_zones, 0,
        "every UPX recovery residual must fall in a loader-rebuilt section (.reloc relocations, \
         or the import/IAT-patched .rdata/.data). the executable code (.text) and exception data \
         (.pdata) carry zero residual. these zones are reconstructed by the OS loader at run time \
         and are not byte-present in the packed stream, so they are not a depacker defect"
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:238`

The locked measurements are as follows. For the nrv2b and LZMA fixtures the `.text` and `.pdata` sections recover byte-identically, at zero differences. The nrv2b whole-image content floor is 96.0% (`FLOOR_PCT` at `crates/disrobe-pass-native/tests/upx_unpack_all.rs:158`). The large nrv2e fixtures set floors of 96% for the `rg` binary and 98% for the `git` binary:

```rust
    assert!(
        pct >= 96.0,
        "rg content-section byte recovery {pct:.2}% fell below the 96.0% floor"
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:345`

```rust
    assert!(
        pct >= 98.0,
        "git content-section byte recovery {pct:.2}% fell below the 98.0% floor"
    );
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:362`

The range 96 to 98 percent is the whole-image content figure for these UPX fixtures across nrv2b, LZMA, and nrv2e; the executable code itself is exact.

### 4.3 Recover-or-sound-reject

A pass has exactly two honest outcomes: it recovers correctly, or it rejects the input soundly. It must never emit a confident wrong answer. A wrong answer that is presented as a recovery is worse than no answer, because it poisons every downstream decision and cannot be distinguished from a real one by inspection.

The discipline is enforced at the type level. Every recovery entry point returns a `Result`, and the pass returns an error whenever the input falls outside the class it can prove it handles. The leaf decompiler refuses code with no structured body or no terminal return rather than guessing:

```rust
fn structure_items(items: &[Item]) -> Result<Structured> {
    if items.is_empty() {
        return Err(Error::LlvmIr("no structured body".to_owned()));
    }
    let Some(ret_pos): Option<usize> = items
        .iter()
        .position(|it: &Item| matches!(it.kind, ItemKind::Ret))
    else {
        return Err(Error::LlvmIr("missing terminal ret".to_owned()));
    };
```
`crates/disrobe-pass-native/src/pseudo_c.rs:2974`

The oracle harnesses honor these rejections instead of forcing an answer. When a battery case is not in the leaf class, the harness records a skip and moves on, the skip-not-pass conversion shown in section 2.6 (`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:186`); the differential is run only over the cases that were genuinely lifted, and the reported count reflects that.

Sound rejection is tested as a first-class capability, not left implicit. The UPX unpacker must reject a non-UPX buffer:

```rust
#[test]
fn non_upx_input_is_rejected() {
    let buf: Vec<u8> = vec![0x55u8; 4096];
    assert!(unpack_upx(&buf).is_err());
}
```
`crates/disrobe-pass-native/tests/upx_unpack_all.rs:247`

and the Eazfuscator devirtualizer must reject a clean assembly (`devirtualize(&image).is_err()` at `crates/disrobe-pass-dotnet/tests/real_eazvm.rs:57`). These negative oracles close the gap that a purely positive test suite leaves open, where a pass could score well on real samples while also happily producing garbage on anything else. The recovery signal makes the same distinction visible in output: `NoRecovery` and `SignaturesOnly` map to the skeleton tier, so a caller can tell a proven recovery from a sound refusal to guess.

### 4.4 CI portability: a green number that stays true across machines

An oracle that depends on compiler code generation is only as portable as the compiler. The recompile-execute-diff and recompile-equivalence forms both run real toolchains, and real toolchains differ across operating systems, versions, and vendors. A number measured green on one developer's machine can be a lie on another if the oracle silently depends on that machine's compiler. disrobe treats this as a correctness problem, not a convenience one, and defends against it three ways.

#### 4.4.1 A multi-platform matrix

The oracles are run under a three-operating-system matrix so that a platform-specific artifact of code generation cannot masquerade as a recovery result. The `check` and `test` jobs both fan out across Linux, macOS, and Windows:

```yaml
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
```
`.github/workflows/ci.yml:22`

The full test job runs on the same three-way matrix (`.github/workflows/ci.yml:87`) with the language runtimes the differentials need provisioned in the environment, including CPython 3.8 through 3.14, Temurin JDK 25, Ruby 3.4, and the uv toolchain (`.github/workflows/ci.yml:106`). A separate `execution-differentials` job installs Lua 5.4, LuaJIT, luau, PHP 8.3 with opcache, and Node 24 so that the re-execution oracles run against genuine interpreters rather than stubs (`.github/workflows/ci.yml:151`). Lint runs under `-D warnings` with `unreachable_pub`, `missing_debug_implementations`, and `unused` promoted to errors (`.github/workflows/ci.yml:64`), and a minimum-supported-Rust job pins the toolchain to 1.95.0 so that a portability regression in the language edition is caught as well (`.github/workflows/ci.yml:257`).

#### 4.4.2 Platform gates instead of platform lies

Where a host genuinely cannot run an oracle, disrobe skips it explicitly and states why, rather than weakening the assertion to something that passes everywhere. The native host oracle runs only where the host ABI matches, and says so:

```rust
#[test]
fn leaf_functions_recompile_to_behavioral_equivalence() {
    if !cfg!(windows) {
        eprintln!(
            "skipping host-native oracle class on non-windows: host cc is arm64 on macos and gcc codegen differs on linux; cross-platform x86-64 sysv coverage is the sysv_* clang guards"
        );
        return;
    }
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:264`

The cross-platform floor is not abandoned when the host cannot run it. It is carried by a separate SysV oracle that uses clang to emit a Linux x86-64 object regardless of host, so that the x86-64 System V ABI is exercised even on a Windows or macOS developer machine:

```rust
    let compile_sysv: std::process::Output = Command::new(&clang_cc)
        .args([
            "--target=x86_64-unknown-linux-gnu",
            "-O1",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-c",
            "-o",
        ])
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:389`

macOS is gated out of the SysV execution differential with an explicit rationale, because its `gcc` is an apple-clang alias and its arm64 core cannot execute an x86-64 battery; the note records that Ubuntu carries the cross-platform floor instead:

```rust
fn sysv_host_can_run() -> bool {
    if cfg!(target_os = "macos") {
        eprintln!(
            "skipping x86-64 sysv recompile-differential on macos: the host gcc is an apple-clang alias that rejects the gcc-only codegen flags, and arm64 cannot execute an x86-64 sysv battery; ubuntu carries the cross-platform sysv floor"
        );
        return false;
    }
    true
}
```
`crates/disrobe-pass-native/tests/pseudo_c_leaf_oracle.rs:121`

A skip that names its reason is honest; a silently relaxed assertion is not. disrobe uses the first and forbids the second.

#### 4.4.3 Conservative floors for codegen-sensitive measures

Where a measurement varies with compiler version or optimization but has a provable lower bound, disrobe asserts the floor, not a point estimate that only one machine produces. The floors are named constants, each traceable to the corpus and date on which it was measured, and each set below the locally observed value so that a legitimate codegen difference does not turn into a false failure while a real regression still trips the assertion. Representative floors across passes include:

- `crates/disrobe-pass-py-decompile/tests/arbitrary_recompile_gate.rs:20` sets `OBJECT_PCT_FLOOR = 90.0`, the per-code-object recompile-equivalence floor on the pinned CPython 3.14 corpus; the 3.12 gate raises it to 91.0 (`arbitrary_recompile_gate_312.rs:20`).
- `crates/disrobe-pass-jvm/tests/decompile_recompile_rate.rs:36` sets `PER_METHOD_JAVAC_OK_FLOOR = 131`, the count of methods that must recompile cleanly through javac.
- `crates/disrobe-pass-jvm/tests/jadx_head_to_head.rs:24` sets `RECOMPILE_FLOOR = 119` for the head-to-head recompile comparison.
- `crates/disrobe-pass-dotnet/tests/whole_type_il_equivalence_oracle.rs:697` sets `IL_EQUIVALENCE_FLOOR = 47`, and `crates/disrobe-pass-dotnet/tests/recompile_oracle.rs:212` sets `RECOMPILE_FLOOR = 6`.
- `crates/disrobe-pass-go/tests/go_crossformat_recovery.rs:30` sets `RECOVERY_FLOOR = 0.99` for cross-format Go symbol recovery.
- `crates/disrobe-pass-pyarmor/tests/static_unpack_corpus.rs:10` sets `RECOVERY_FLOOR = 72`, the count of PyArmor samples that must be recovered out of the 72-sample corpus.
- `crates/disrobe-pass-beam/tests/erlc_recompile_equivalence.rs:320` sets `EQUIVALENCE_FLOOR = 18`, and `crates/disrobe-pass-lua/tests/reexec_diff_oracle.rs:252` sets `REEXEC_FLOOR_NUM = 27` for the Lua re-execution differential.
- `crates/disrobe-pass-py-decompile/tests/roundtrip_metric.rs:641` sets `WHOLE_MODULE_FLOOR_PCT = 51.0` for whole-module recovery measured on the edge_cases monolith corpus (`roundtrip_metric.rs:635`), which is a distinct corpus from the 200-module pinned stdlib behind the 54.5% figure and must not be conflated with it, alongside the UPX content floors of 96.0% and 98.0% shown in section 4.2.4.

Each floor is a promise of the form "at least this much recovery is reproducible anywhere the matrix runs." It is deliberately weaker than the best local number and deliberately stronger than zero, because the honest claim is a guaranteed lower bound, not a lucky maximum. The recovery-execute-diff oracles that do run, such as the leaf behavioral differential and the Eazfuscator re-injection, are exact rather than floored, because behavioral equivalence over a shared input battery either holds or does not; there is no honest partial credit for a program that computes the wrong answer.

### 4.5 Summary

disrobe's verification stack is a ladder of external truth. Recompile-equivalence borrows the language toolchain as judge. Recompile-execute-diff replaces static comparison with the observable behavior of two independently compiled programs over a shared battery. Independent-baseline grading measures recovery against a separately built clean artifact the recovery never sees. Byte-exact-vs-original compares recovered bytes to the true pre-transformation input, the one reference that admits no argument. Beneath all four sits the recover-or-sound-reject invariant, which forbids a confident wrong answer, and above all four sits a three-platform CI matrix with named, dated, conservative floors and explicit platform gates, so that a number that is green in one place is not a lie in another. The result is a body of claims a stranger can re-run, and a measurement discipline built so that a green number cannot vouch for the tool that produced it.

## What this whitepaper does not claim

The boundaries below are stated so that the results above are not read as more than they are.
Each is a consequence of where the recoverable data actually resides, not an unfinished
feature.

disrobe does not devirtualize native VM-protected code. Themida- and VMProtect-class
protection, including the Themida wrapper applied to managed assemblies, translates a body
into native VM bytecode that is decrypted into memory only at run time; disrobe detects and
classifies it and disassembles the surrounding native stub, but does not reconstruct the
original body (Section 3.4).

disrobe does not recover bodies whose plaintext leaves the static file. Where a per-method key
is produced by a runtime delegate (ILProtector) or computed inside a native loader at JIT time
(MaxToCode), the original instructions are not present in the bytes under analysis; disrobe
walls these with a stated reason and the residual static evidence rather than fabricating a
body (Section 3.4).

Whole-module Python recovery is far below the per-object figure. The representative
per-code-object recompile-equivalence on the CPython 3.14 standard library is <!-- m:py_stdlib_full_pct -->92.43%<!-- /m -->, but the
whole-module exact rate, where a module counts only if every one of its code objects is
equivalent, is 54.5% on the pinned corpus; a module passes only when all of its typically
dozens of code objects pass, so a small per-object miss rate compounds into a large
per-module one (Section 1.5). The per-object number is the granular headline and the
whole-module number is the harder truth reported beside it.

The KoiVM oracle is weaker than the Eazfuscator oracle. EazVM recovery is graded against
ordered CIL that the C# compiler emitted into a separate clean assembly the recovery code
never sees, at 57 of 57 instructions in order. KoiVM is graded against a hand-specified
projection of the same six methods over a coarser operation vocabulary: two bodies (Add,
Square) are proven to recover fully and the aggregate clears a 75% floor, so the other four
are bounded only by that floor and are not claimed as full recoveries. The oracle is
non-circular but is not the same strength of evidence, and the difference is stated rather
than smoothed over (Section 3.3).

The native leaf results are for a hand-authored battery, not arbitrary binaries. The x86-64
to C and Rust path recovers single-exit leaf functions and is graded by a battery of small
functions written by hand, exercised under both the MS x64 and the System V ABIs. It makes no
claim to recover whole stripped programs, obfuscated or virtualized code, irreducible control
flow, or any input its soundness guards reject; every such input is refused rather than faked
(Section 2.7).

## Conclusion

The three recovery subsystems address different targets but share one shape. The Python
decompiler folds a moving instruction set into a single canonical vocabulary and recovers
structured source; the native path lifts x86-64 into a typed AST and emits C and Rust with one
precedence authority; the .NET path reconstructs CIL from two managed VMs and walls the cases
whose plaintext leaves the static file. What binds them is the verification methodology of
Section 4: each result is credited only by an oracle disrobe does not control, from
recompile-equivalence through recompile-execute-differential and independent-baseline grading
to byte-exact comparison, and each codegen-sensitive number is held by a conservative CI floor
on a three-platform matrix. The combined claim is therefore narrow and checkable: within the
class each pass proves it handles, disrobe recovers source, IL, or bytes that an independent
toolchain confirms, and outside that class it rejects the input rather than fabricating an
answer. Every figure in this paper is anchored to a committed source, test, or data file, so a
stranger can re-run the measurement and reach the same result.

## References

The externally cited prior art, with resolvable identifiers:

- [PEP 626], precise line numbers for debugging and other tools, Python Enhancement Proposal 626.
- [PEP 695], type parameter syntax, Python Enhancement Proposal 695.
- [Wadler-Leijen], Philip Wadler, "A prettier printer" (2003), extended by Daan Leijen in the `wl-pprint` library, the basis for the `pretty` document algebra.
- [Knuth], Donald E. Knuth, The Art of Computer Programming, Volume 2: Seminumerical Algorithms, section 3.2.2, the subtractive random number generator (ISBN 0-201-89684-2).
- [FNV], Glenn Fowler, Landon Curt Noll, and Kiem-Phong Vo, the FNV non-cryptographic hash function.
- [syn], David Tolnay, `syn`, a Rust source-code parser.
- [prettyplease], David Tolnay, `prettyplease`, a `syn` abstract-syntax-tree unparser.

[PEP 626]: https://peps.python.org/pep-0626/
[PEP 695]: https://peps.python.org/pep-0695/
[Wadler-Leijen]: https://homepages.inf.ed.ac.uk/wadler/papers/prettier/prettier.pdf
[Knuth]: https://www-cs-faculty.stanford.edu/~knuth/taocp.html
[FNV]: http://www.isthe.com/chongo/tech/comp/fnv/
[syn]: https://crates.io/crates/syn
[prettyplease]: https://crates.io/crates/prettyplease
