# Go embed.FS recovery matrix

These images exist so `embed.FS` recovery is graded against the exact bytes the Go compiler
embedded, across every container, pointer width and endianness the capability claims.

## How they were built

Toolchain: `go version go1.26.5 windows/amd64`.

Source: `main.go` and `go.mod` in this directory, unmodified. The program embeds the `assets`
directory with a single `//go:embed assets` directive.

Command, run once per row of the matrix below, from this directory:

    go build -trimpath -ldflags "-s -w" -o <output> .

with `GOOS`, `GOARCH` and `CGO_ENABLED=0` set per row, adding `-buildmode=pie` for the row
that names it. A darwin arm64 build is position independent whether or not the flag is
given, so that row is marked yes without carrying the flag. `-trimpath` keeps build paths out of the
image. `-ldflags "-s -w"` drops the symbol table and DWARF, which cuts each image by about a third
and also proves recovery does not depend on symbols.

## Matrix

| Image | GOOS | GOARCH | Container | Pointer width | Byte order | Position independent |
| --- | --- | --- | --- | ---: | --- | --- |
| `goembed_pe32_le.exe` | windows | 386 | PE | 4 | little | no |
| `goembed_pe64_le.exe` | windows | amd64 | PE | 8 | little | no |
| `goembed_elf32_le` | linux | 386 | ELF | 4 | little | no |
| `goembed_elf64_le` | linux | amd64 | ELF | 8 | little | no |
| `goembed_elf32_be` | linux | mips | ELF | 4 | big | no |
| `goembed_elf64_be` | linux | s390x | ELF | 8 | big | no |
| `goembed_macho64_le` | darwin | arm64 | Mach-O | 8 | little | yes |
| `goembed_pie_elf64_le` | linux | amd64 | ELF | 8 | little | yes |

## What the assets cover

`assets/` is the reference tree. Recovery is compared against these files byte for byte, and the
path set must match exactly rather than be a subset.

| File | Bytes | Why it is here |
| --- | ---: | --- |
| `assets/empty.txt` | 0 | A zero-length member still carries the digest of its empty contents |
| `assets/data.bin` | 6 | Content that is not valid UTF-8 |
| `assets/deep/nested.txt` | 15 | A member below the top directory, which adds a directory record |
| `assets/note.txt` | 36 | Plain text |
| `assets/exactly-1024.bin` | 1024 | The largest size that still takes the one-shot digest branch |
| `assets/over-1024.bin` | 1025 | The smallest size that takes the streaming digest branch |
| `assets/large.txt` | 2368 | A member well past the branch boundary |

Each image therefore holds 7 file records and 2 directory records.

## The digest boundary

Every non-directory record carries the first 16 bytes of a compiler digest. Which digest depends on
the toolchain generation and on the member size. The 1024-byte boundary in this tree was measured
from these images rather than assumed: `exactly-1024.bin` verifies under the one-shot form and
`over-1024.bin` verifies under the streaming form, so the comparison the compiler applies is
`size > 1024`.

## Cross-checked against the compiler source

The layout and the digest rule were measured from these images and then confirmed against the
source of the same toolchain release, which reports itself as go1.26.5.

`src/cmd/compile/internal/staticdata/embed.go` writes the slice header and the records into one
symbol and sets the records pointer to that symbol plus three pointer-sized words, with the comment
"pointing just past slice". It writes the length twice, so length and capacity are always equal. A
directory record gets a zero data pointer, a zero data length and a hash field left at zero.

`src/cmd/compile/internal/staticdata/data.go` selects the digest form on `size <= 1*1024`, taking
the one-shot form at or below that size and the streaming form above it.

`src/cmd/internal/hash/hash.go` defines the one-shot form as `sha256.Sum256(data)` with byte 0
exclusive-ored with 0xff, and the streaming form as `sha256.New()` fed a single 0x01 byte before
the data. Its own comment records that the two forms compute different hashes.

`src/cmd/internal/notsha256` no longer exists in this release, which is consistent with the older
toolchain family being unreachable from a go1.26 build.

## Regenerating

Rebuild with the same toolchain and flags. A different Go release may change the digest family, in
which case `go_embed_digest.rs` reports the family it measured instead of the one recorded here, and
the recorded family must be updated only after confirming the change against the Go source.
