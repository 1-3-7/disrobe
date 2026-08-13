# Lua

`disrobe` decompiles compiled Lua chunks across every common dialect, peels the major Lua obfuscators, and devirtualizes custom-VM wrappers back to runnable Lua source.

## At a glance

| Layer | Coverage |
|---|---|
| Dialects | Lua 5.1 / 5.2 / 5.3 / 5.4, LuaJIT 2.0 / 2.1, Luau, GLua |
| Luau opcode coverage | <!-- m:luau_opcode_lift_count -->86 of 88<!-- /m --> opcodes in disrobe's declared table are lifted, with `BREAK` debugger instrumentation and `NEWCLASSMEMBER` decoded and reported rather than lifted; child-proto linking |
| Decompile output | Lua source plus a manifest recording the detected dialect, fidelity grade (`Lossless` / `Lossy` / `BestEffort`), and any warnings |
| Obfuscators (<!-- m:lua_catalog_obfuscators -->14<!-- /m -->) | IronBrew2, Prometheus, MoonSec V1 / V2 / V3, AztupBrew, DarkSec, Boronide, PSU, WeAreDevs, luaobfuscator.com, SLua, Hercules, Luraph |
| Chain catalog | <!-- m:lua_catalog_entries -->16<!-- /m --> entries: the <!-- m:lua_catalog_obfuscators -->14<!-- /m --> obfuscator families above plus the Luau and GLua dialect detectors |
| Peelers (`--family`) | `prometheus`, `moonsec-v1`, `moonsec-v2`, `moonsec-v3`, `ironbrew2`, `wearedevs`, `slua`; default `auto` detects first |
| VM devirtualization | IronBrew2 2.7.0 reversed on real committed output, graded by real-Lua execution differential (hello / arith / control / tables / edge in standard and MAX mode); MoonSec-shape recovery is pending a real sample |
| Prometheus `Vmify` | Container dispatch tree lifted back to structured Lua, including a closure that captures a variable; up to four stacked `Vmify` layers unwrapped in one call; graded by real-Lua 5.1 execution differential against the original source |

## Commands

```sh
disrobe lua decompile script.luac --out script.lua
disrobe lua detect script.luac
disrobe lua deobfuscate obfuscated.lua --out clean.lua
disrobe lua deobfuscate vmified.lua --family prometheus --out clean.lua
disrobe lua deobfuscate dumped.lua --family moonsec-v3 --i-have-authorization
```

`decompile` writes the recovered source (default `./out/<stem>.lua`) and a `manifest.json` recording the format, fidelity grade, and warnings. `detect` reports the dialect and header field summary (constant, proto, and code counts) without writing output. MoonSec v3 and IronBrew2 are commercial-tier wrappers; their peelers require the explicit `--i-have-authorization` flag.

`--family` pins one peeler instead of letting `auto` choose. Auto-detection tries Prometheus first, so a `Vmify` container needs no flag. Pass `--family prometheus` when you want a file carrying no Prometheus signature to fail rather than fall through to another family.

Output shapes below are illustrative.

```text
lua decompile: OK
  input:        script.luac
  format:       Lua54
  fidelity:     Lossless
  warnings:     0
  wrote:        ./out/script.lua
  manifest:     ./out/script.manifest.json
```

```text
lua deobfuscate: OK
  family:       Auto
  detected:     Prometheus (confidence=0.97)
  passes run:   3
    - string_decode
    - bytecode_unwrap
    - emit
  recovered:    12 string(s)
  fully peeled: true
  residual:     0
  wrote:        ./out/obfuscated.peeled.lua
```

The deobfuscate report lists every pass that ran, recovered string constants, a `fully peeled` verdict, and any residual markers.

## Coverage and fidelity

IronBrew2 and MoonSec ship their payload behind a custom register-VM: a permuted opcode-handler table and an embedded constant pool that a stock decompiler cannot read. The permutation is not stored in the loader; it is computed at load time inside the obfuscated bootstrap, then used to dispatch handlers and key the constant decryptor. `disrobe` reconstructs it the same way the loader does.

For IronBrew2 2.7.0, the devirtualizer parses the bootstrap's dispatch chain to derive the `encoded -> canonical` permutation and the XOR key, decodes the constant pool, and lifts the VM bytecode back to runnable Lua. The committed `corpus/lua/ironbrew2` set carries real obfuscated bootstraps for five programs in both standard and MAX mode; each must produce byte-identical output to the original under a real `lua` binary (`tests/ironbrew2_real_oracle.rs`).

MAX mode adds three layers on top of standard: a control-flow-flattened dispatch (a nested binary search over the opcode enum, which the same handler walker un-flattens), comparison-polarity number-mutation (the EQ handler tests `~=` and jumps on equality, captured as the literal operator plus jump direction), and fused super-operator handlers (one VM step covering several real ops, whose hoisted scratch locals are stripped after classification).

### Prometheus Vmify

The Prometheus `Vmify` step rewrites a chunk into a register machine held inside one container function. Every original function becomes a numbered entry point in a shared dispatch tree, and every call becomes a jump through that tree. `disrobe` reads the container, rebuilds a control-flow graph for each entry point, and re-emits structured Lua. The pass appears as `prometheus-vmify-container-devirt` in the `passes run` list. `Vmify` applied over its own output is unwrapped layer by layer, up to four layers in one call. A chunk that needed more than one layer also carries a `prometheus-vmify-nested-devirt-<n>-layers` entry naming the layer count.

`Vmify` does not keep a captured variable as a Lua upvalue. It moves the variable into a store table shared by the whole chunk, hands each closure a list of slot indices into that store, and uses a reference count to decide when a slot is cleared. `disrobe` fingerprints the allocator and the release helper by their statement shape, which is how it tells the capture store apart from any other table in the chunk. It then gives each allocation one Lua local, named `__vu0`, `__vu1`, and so on in allocation order, and declares it once in the scope that allocates it. Every read and write of that slot is rewritten to the same local, both in the allocating function and in each closure that receives the slot, so the recovered closure captures the variable by reference the way the original source did.

The committed `corpus/lua/prometheus/vmify_upvalue` pair holds real Prometheus `Vmify` output for a counter factory whose inner function captures a local. Two gates grade it. One asserts that the committed obfuscated file already prints what the clean file prints under a real `lua` 5.1 binary, so the fixture is a faithful transform. The other runs the recovered source under the same binary and requires identical output (`tests/reexec_diff_oracle.rs`).

Set `DISROBE_DEBUG=lua` to trace the capture analysis. It emits `prometheus_vmify.box_model`, naming the registers the capture helpers resolved to, and `prometheus_vmify.captured_variables`, the number of captured variables bound in the run.

## Limits

- Where `fully peeled` is `false` the report carries the residual marker names and the reason (runtime key, anti-tamper variant, unmodeled VM tier, or a refused Vmify recovery).
- Runtime-key and anti-tamper variants (MoonSec v3 with an encrypted constant pool keyed at runtime) are the wall: the key is not present statically, so `disrobe` returns `fully_recovered: false` with a `runtime keys` residual marker.
- The MoonSec `emulate_perm_builder` path interprets a bootstrap table-builder over its seed and is unit-tested on a realistic synthetic bootstrap of our own design whose permutation is derived at runtime. End-to-end validation against a real captured MoonSec dump is pending: no live sample is publicly available.

### Prometheus Vmify refusals

`Vmify` recovery either emits source that runs the same as the original or refuses. It never leaves a placeholder function standing in for a body it could not recover. A refusal names its cause, and where the cause is a specific expression it names the byte offset of that expression in the text the layer was reading.

A refusal takes one of two shapes.

- The whole container is refused. `fully peeled` is `false`, `prometheus-vmify-container-devirt` is absent from `passes run`, the output file holds the earlier peel stage rather than a devirtualized body, and a residual marker reads `a Vmify container was found but recovery was refused rather than emitted partly wrong`, followed by the reason.
- Some layers recovered and a further layer is refused. The recovered source is written, `fully peeled` is `false`, and a residual marker records how many layers recovered before the refusal, followed by the reason.

`disrobe` refuses these captured-variable shapes.

- A capture allocated on a cycle in the recovered control-flow graph, which is what a capture written inside a source loop becomes. Each iteration of such a loop captures a fresh variable, and one declaration at function scope would alias them into a single shared variable. The committed `corpus/lua/prometheus/vmify_loop_capture` pair is a loop that builds three closures over three different values, and `disrobe` refuses it. The cycle search runs under a step budget, and `disrobe` refuses when the search exceeds it.
- A chunk that creates a closure with a non-empty capture list, but whose reference-counted capture helpers do not match the shape `disrobe` fingerprints. The fingerprint accepts exactly one allocator and exactly one store bound to that allocator's reference-count table, so a chunk carrying more than one of either yields no model and no captured variable can be resolved to a real Lua variable. A chunk that captures nothing needs no model and is unaffected.
- A register that receives a second capture inside one recovered function, because the register cannot then carry one stable name.
- A capture allocator referenced anywhere other than a plain allocation assignment.
- A store slot read or written through anything other than a register the same function allocated a capture into, or an entry of the closure's own capture list indexed by a positive whole-number literal. An index past the end of the supplied capture list is also refused.
- A closure-creation call whose capture list is not a table constructor, or whose capture list carries a keyed entry. A keyed entry has no stable position to match against the closure body.
- A closure-creation call whose entry point is not a literal number, because the closure body cannot then be located in the dispatch tree.
- One dispatch leaf shared by two closures with different captured variables, which would bind one expression to two different recovered values.
- A recovered body that still names the container's own capture machinery, meaning the capture table, the store, the allocator, or a slot register. At least one access went unresolved in that case, so the body is refused rather than emitted.

Recovery is graded against Prometheus output built for Lua 5.1 with `Vmify` as the only step. Other target dialects and other step combinations are not graded.
