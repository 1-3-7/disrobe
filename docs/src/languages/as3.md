# ActionScript 3 / Flash

**disrobe** parses SWF files, disassembles their embedded ActionScript 3 bytecode, and lifts method bodies back into readable AS3 pseudocode.

```sh
disrobe as3 disasm movie.swf --out out/             # per-instruction AVM2 disassembly per DoABC tag
disrobe as3 disasm movie.swf --out out/ --emit source   # also decompile classes to .source.as3
disrobe as3 tags movie.swf                          # list every tag: TagCode, offset, payload size
```

`disasm` walks every `DoABC`/`DoABCDefine` tag and emits a per-instruction AVM2 listing. With `--emit source` it also reconstructs class skeletons with lifted method bodies (property access, calls, arithmetic, and `if`/`goto` control flow) by abstractly interpreting the operand stack.

## Honesty

Recovery is faithful, not optimistic. ABC erases local variable names (non-parameter slots surface as `loc{n}`) and the compiler erases generics before ABC, so those are hard ceilings. Any method the lifter could not fully model is prefixed with a `/// DR-AS3-PARTIAL:` line naming the unmodelled opcodes or fabricated operands. A partial recovery is never silently presented as complete.

## Obfuscation detection

`disrobe` can fingerprint commercial AS3 obfuscators/packers (secureSWF, DoSWF, Kindi, Irrfuscator, swfLock) and flag techniques (string encryption, name mangling, control-flow flattening, register/stack shuffle, string-pool-rebuild candidates) with confidence scores. This is detection only: it reports what an ABC *appears* to use and performs no decryption, pool rebuild, or unflattening.
