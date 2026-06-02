# ActionScript 3 / Flash

**disrobe** parses SWF files and disassembles their embedded ActionScript 3 bytecode.

```sh
disrobe as3 disasm movie.swf --out disasm.txt     # disassemble every DoABC tag into AS3 bytecode
disrobe as3 tags movie.swf                         # list every tag: TagCode, offset, payload size
```

`disasm` walks every `DoABC` tag and emits a per-instruction AS3 bytecode listing. `tags` gives a structural map of the SWF container. Full source-level recovery feeds into JPEXS, which **disrobe** is positioned to wrap.
