# Lua

`disrobe` decompiles compiled Lua chunks across every common dialect, peels the major Lua obfuscators, and devirtualizes custom-VM wrappers back to runnable Lua source.

## At a glance

| Layer | Coverage |
|---|---|
| Dialects | Lua 5.1 / 5.2 / 5.3 / 5.4, LuaJIT 2.0 / 2.1, Luau (<!-- m:luau_opcode_lift_count -->86 of 88<!-- /m --> opcodes in disrobe's declared table are lifted, with `BREAK` debugger instrumentation and `NEWCLASSMEMBER` decoded and reported rather than lifted; child-proto linking), GLua |
| Decompile output | Lua source plus a manifest recording the detected dialect, fidelity grade (`Lossless` / `Lossy` / `BestEffort`), and any warnings |
| Obfuscators (14) | IronBrew2, Prometheus, MoonSec V1 / V2 / V3, AztupBrew, DarkSec, Boronide, PSU, WeAreDevs, luaobfuscator.com, SLua, Hercules, Luraph |
| Chain catalog | 16 entries: the 14 obfuscator families above plus the Luau and GLua dialect detectors |
| Peelers (`--family`) | `prometheus`, `moonsec-v1`, `moonsec-v2`, `moonsec-v3`, `ironbrew2`, `wearedevs`, `slua`; default `auto` detects first |
| VM devirtualization | IronBrew2 2.7.0 reversed on real committed output, graded by real-Lua execution differential (hello / arith / control / tables / edge in standard and MAX mode); MoonSec-shape recovery is pending a real sample |

## Commands

```sh
disrobe lua decompile script.luac --out script.lua
disrobe lua detect script.luac
disrobe lua deobfuscate obfuscated.lua --out clean.lua
disrobe lua deobfuscate dumped.lua --family moonsec-v3 --i-have-authorization
```

`decompile` writes the recovered source (default `./out/<stem>.lua`) and a `manifest.json` recording the format, fidelity grade, and warnings. `detect` reports the dialect and header field summary (constant, proto, and code counts) without writing output. MoonSec v3 and IronBrew2 are commercial-tier wrappers; their peelers require the explicit `--i-have-authorization` flag.

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

## Limits

- Where `fully peeled` is `false` the report carries the residual marker names and the reason (runtime key, anti-tamper variant, or unmodeled VM tier).
- Runtime-key and anti-tamper variants (MoonSec v3 with an encrypted constant pool keyed at runtime) are the wall: the key is not present statically, so `disrobe` returns `fully_recovered: false` with a `runtime keys` residual marker.
- The MoonSec `emulate_perm_builder` path interprets a bootstrap table-builder over its seed and is unit-tested on a realistic synthetic bootstrap of our own design whose permutation is derived at runtime. End-to-end validation against a real captured MoonSec dump is pending: no live sample is publicly available.
