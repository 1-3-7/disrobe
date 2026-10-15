# Verify a native reconstruction

`disrobe native verify-function` differentially tests a candidate reconstruction of one x86 or x86-64 function. It executes the selected function from the input image and the candidate under the same generated cases in the bounded in-process x86 emulator. The input image, candidate, imports, and generated data never execute natively.

The command establishes evidence for the cases it ran. An `equivalent-on-cases` verdict is not a proof that the implementations are equivalent.

## Command

```sh
disrobe native verify-function <binary> --function <name|0xaddr> \
  --candidate <file.c|file.o|file.obj> \
  [--signature "<ret>(<args>)"] [--cases N] [--seed S] \
  [--compiler <path>] [--json]
```

`--function` accepts a recovered symbol name or a virtual address. `--candidate` accepts C source or a self-contained object. For C input, the command uses the compiler configured locally (or `--compiler`) to build a self-contained leaf candidate at both `-O0` and `-O2`, with freestanding, no-stack-protector, no-PIC settings. Supplying an object avoids compilation but does not relax object validation.

The signature is an integer-and-pointer function signature, including the return width. If `--signature` is omitted, the command uses the in-tree decompiler's recovered signature for the selected function. The ABI follows the container: SysV for ELF and Mach-O, Microsoft x64 for PE x86-64, and cdecl for 32-bit x86.

## What each case compares

The original image's sections are mapped at their virtual addresses with their recorded protections. Data has a private writable copy. Each invocation has a bounded stack, a return sentinel, and bounded scratch storage for pointer arguments. Candidate text and data are mapped separately; only relocation kinds needed by a self-contained function are accepted. An unsupported relocation or an unresolved external symbol is refused by name.

For a given seed, case generation is deterministic. It combines each argument width's boundary values (zero, one, minus one, minimum, maximum, powers of two, and adjacent values), small ranges, and pseudorandom values. Pointer arguments address scratch storage, whose initial bytes are included in the case.

Both implementations run with the same step cap. The comparison masks the return value to its declared width and checks the scratch bytes plus writes to the original image's data sections. The report classifies every case as one of:

- `match`
- `mismatch`, with the first differing output
- `original-faulted`
- `candidate-faulted`
- `step-cap`
- `escaped`

Imports, syscalls, and other host calls are never run. They end the affected case as `escaped` and name the attempted target. The text report includes totals and the reported divergences with their inputs; `--json` emits the same result as structured data.

## Limits and interpretation

The command bounds case count, steps per case, mapped memory, stack and scratch storage, relocation processing, write logging, and report output. Requests or inputs that exceed a bound are refused rather than being allowed to consume unbounded resources. A fault, step-cap result, escape, or mismatch is evidence that the candidate did not match that case; it does not characterize every input outside the generated set.

Use a fixed `--seed` when a result must be reproduced. Increase `--cases` only within the command's enforced limit. The default seed and case count are suitable for a first comparison, not a substitute for a specification or an independent oracle.

## Grading

The shipped grader uses authored repository C targets only. It compiles x86-64 ELF and PE targets and 32-bit PE targets at test time, then checks arithmetic overflow, read-only table access, early-exit loops, signed and unsigned comparisons, and writes through pointers. The original source must reach `equivalent-on-cases` for at least 2,000 cases. Off-by-one, wrong-signedness, and missing-side-effect candidate mutations must report their exact first failing input; an import-calling candidate is refused or reported as an escape by name.

For those authored sources only, the grader also compares native execution with emulator execution for a representative generated case. That is an emulator oracle for repository-owned code, not permission to run an analyzed image or sample on the host.
