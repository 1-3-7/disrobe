# Native-language references

`crystal_pairing_heap_reference.c` checks the recovered pairing-heap combine operation against an independent two-pass heap model over 929 bounded graphs.

`zig_float_rounding_reference.c` checks the Zig 0.13 `__truncxfsf2` body over 42 signed rounding inputs. Normal-result vectors use IEEE round-to-nearest, ties-to-even expectations, independently checked with GCC's x87 conversion. Subnormal vectors include values below, at, and above the original helper's halfway boundary.

Subnormal-result vectors preserve the original helper's behavior. [Zig 0.13's `trunc_f80`](https://github.com/ziglang/zig/blob/0.13.0/lib/compiler_rt/truncf.zig#L92-L165) clears the explicit integer bit before its underflow path and uses the masked fraction without restoring that bit. The tracked ELF does the same at `0x10bdf4e`. For significand `0x8000000000000000` and exponent `16256`, it returns zero, although IEEE conversion would produce float bits `0x00400000`. Recovery must preserve that behavior.

The tests compile recovered C and run it on authored inputs. They never execute the original ELF or PE fixtures.
