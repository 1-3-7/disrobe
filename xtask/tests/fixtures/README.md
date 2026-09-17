# Native binding fixture

`flattened_function.bin` contains the 57-byte x86-64 input used by the Python
binding's control-flow recovery test. Its assembly source is
`flattened_function.s`; the test analyzes these bytes without executing them.

Rebuild it with LLVM:

```sh
clang --target=x86_64-unknown-linux-gnu -c flattened_function.s -o flattened_function.o
llvm-objcopy --only-section=.text --output-target=binary flattened_function.o flattened_function.bin
```

The explicit `0x05` opcode selects the `add eax, imm32` encoding to preserve the
original fixture's instruction offsets. The binary's SHA-256 is
`e9ef6e47e9195164b13dcb3ab0ff237b8f16f71053c58dc273bf8bdd7e36ca56`.
