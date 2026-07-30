# ActionScript 3 / Flash

`disrobe` parses SWF files, disassembles their embedded ActionScript 3 bytecode (AVM2), and lifts method bodies back to readable AS3 pseudocode via operand-stack abstract interpretation.

## At a glance

| Layer | Coverage |
|---|---|
| Container | Every SWF tag, with its TagCode, byte offset, and payload size |
| Bytecode | Every `DoABC` and `DoABCDefine` block, disassembled per instruction |
| Source lift | Class skeletons with property access, calls, arithmetic, and `if` / `goto` control flow |
| Obfuscator detection | secureSWF, DoSWF, Kindi, Irrfuscator, swfLock, each finding with a confidence score |

## Commands

```sh
disrobe as3 disasm movie.swf --out out/
disrobe as3 tags movie.swf
```

`disasm` walks every `DoABC` and `DoABCDefine` tag, emits a per-instruction AVM2 listing as `<label>.disasm.txt` beside the JSON, and reconstructs class skeletons with lifted method bodies as `<label>.source.as3`. `tags` lists every tag in the SWF: TagCode, byte offset, and payload size.

Output shape (illustrative):

```text
as3 disasm: OK
  input:        movie.swf
  swf version:  10
  abc blocks:   2
  classes:      6
  methods:      24
  instructions: 512
  source files: 2
  disasm files: 2
  out dir:      ./out
  manifest:     ./out/manifest.json
```

## Coverage and fidelity

The source lifter reconstructs class skeletons with property access, calls, arithmetic, and `if` / `goto` control flow by abstractly interpreting the operand stack. Any method the lifter could not fully model is prefixed with a `/// DR-AS3-PARTIAL:` line naming the unmodelled opcodes or fabricated operands; a partial recovery is never silently presented as complete.

`disrobe` fingerprints commercial AS3 obfuscators (secureSWF, DoSWF, Kindi, Irrfuscator, swfLock) and flags techniques: string encryption, name mangling, control-flow flattening, register and stack shuffle, string-pool-rebuild candidates. Each finding carries a confidence score.

## Limits

- Obfuscator handling is detection only. No decryption, pool rebuild, or unflattening is performed.
- ABC erases local variable names (non-parameter slots surface as `loc{n}`) and the compiler erases generics before ABC. Both are hard ceilings.
- FFDec is the mature full Flash decompiler and goes further on source-level recovery; `disrobe` covers SWF parsing and AVM2 disassembly as part of its chain pass, not as a Flash-decompiler replacement.
