# Go

`disrobe` recovers symbols from stripped and garbled Go binaries across PE, ELF, and Mach-O by parsing the Go runtime's own metadata tables. The deliverable is symbols, types, and embedded data, not source bodies.

## At a glance

| Layer | Coverage |
|---|---|
| Binary formats | PE, ELF, Mach-O, on little- and big-endian targets |
| Architectures | little-endian amd64/arm64 and big-endian s390x, ppc64, and mips, with the pclntab, type, and itab tables read in the image's own byte order |
| pclntab | Header eras go1.2, go1.16, go1.18, and go1.20, located structurally even when the magic word has been stomped |
| Symbol recovery | `pclntab` function table, `moduledata`, `typelinks`/`itablinks` type metadata, `buildversion` |
| Obfuscation | garble report graded `None` / `Detected` / `Partial` / `Full`, with per-scheme literal-recovery statistics |
| Embedded data | `embed.FS` usage report and directive extraction |
| Debug info | DWARF report when the sections survive |

## Recovering a binary

```sh
disrobe go recover app --out app-go.json
disrobe go info app
```

`recover` writes the full analysis JSON (default `./out/<stem>-go.json`); `info` prints the fingerprint without writing anything. Output shape (illustrative):

```text
go recover: OK
  input:        app
  image kind:   elf
  ptr size:     8
  pclntab ver:  go1.20
  buildversion: go1.26.3
  funcs:        ...
  packages:     ...
  garble:       None
  embed.FS:     used=true directives=...
  wrote:        ./out/app-go.json
```

`info` adds the stripped-binary fingerprint: whether the symbol table was stripped, how many functions were still recovered from `pclntab`, and the stdlib-name ratio that feeds the garble grading.

## Garble

The garble report separates a real wall from a tooling boundary. Standard-library names survive in `pclntab` and are recovered, while hashed user identifiers stay walled: garble hashes them with a keyed HMAC-SHA256 over a build seed that is not in the binary, so the original names are information-theoretically gone and are reported as a `name_recovery_wall` rather than guessed at.

`garble -literals` is handled separately from names. Simple rodata schemes are recovered by pairing adjacent key/data blobs and applying the inverse XOR/ADD/SUB or repeating-key operation. Full-key literals are recovered when their code and ciphertext are present: the thunk scanner follows bounded x86-64 init thunks or inline materializers, emulates the decrypt path, and accepts only UTF-8/readable plaintext. The tests assert the source strings are absent as cleartext before requiring byte-exact recovery, so the oracle is not circular. Remaining limits are concrete: missing bytes, runtime-only key material, unsupported architectures, exhausted budgets, or ambiguous short plaintext.

## Validation and chaining

The pass is validated against a go1.26.3 fixture, and the test suite gates type-name recovery at >= <!-- m:go_typename_pct -->85%<!-- /m --> on that fixture; 528 of 528 type names (100%) are recovered at HEAD, since the `typelinks` and `moduledata` tables survive `-s -w` stripping. Big-endian recovery has its own oracle: a cross-built stripped linux/s390x binary is parsed as a big-endian ELF and its named type and itab pairs are recovered by back-searching the metadata tables, graded against the build (`go_bigendian_recovery.rs`). UPX-on-Go chains automatically: `disrobe auto` unpacks the UPX layer first, then recovers the Go symbols underneath.
