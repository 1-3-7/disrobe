# Python pickle

Pickle is a code-execution format masquerading as a data format, which makes it a recurring vector in weaponized ML model files. `disrobe` analyzes pickles **statically** — it never unpickles, never calls `__reduce__`, never executes a `REDUCE` opcode.

```sh
disrobe pickle disasm model.pkl --out trace.txt       # offset-annotated opcode listing
disrobe pickle decompile model.pkl --out graph.py      # symbolic object graph -> equivalent Python source
disrobe pickle safety model.pkl                         # severity tier + dangerous-import / REDUCE / memo findings
disrobe pickle trace model.pkl                          # symbolic VM trace: object graph, memo, globals, reduce count
disrobe pickle polyglot suspicious.bin                  # detect pickle/zip/zip64/tar polyglots (weaponized archives)
disrobe pickle model-detect model.bin                   # detect PyTorch / TorchScript / numpy + list embedded pickles
```

The `trace` command runs a **symbolic** VM: it walks the opcode stream and builds the object graph without ever instantiating a real object or resolving a real global. `safety` grades a pickle into a severity tier based on dangerous imports, `REDUCE` usage, and memo manipulation. `polyglot` catches the classic trick of hiding a malicious pickle inside a zip or tar that a model loader will happily open.

This pass is the core of `disrobe`'s ML-supply-chain story: you can audit a downloaded `.pt` or `.pkl` for what it *would* do on load, before it ever touches a real interpreter.
