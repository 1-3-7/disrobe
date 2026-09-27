# SwiftHello Mach-O fixtures

`SwiftHello.original` and `SwiftHello.obfuscated` are arm64 macOS release builds of a Swift package, the second after SwiftShield renaming (`SwiftHello.swiftshield-mapping.txt`). `crates/disrobe-python/tests/fixtures/SwiftHello.macho` and `playground/public/samples/SwiftHello` are byte-identical copies of `SwiftHello.original`.

The debug-map source paths in the symbol string table named the build host home directory. Each `/Users/<name>/` prefix was replaced in place with the same-length `/src/work/`. The replaced bytes lie inside the signed range, so the page hashes of each ad hoc code directory were recomputed with SHA-256 over the rewritten pages. The same recomputation over the unmodified files reproduced their recorded cdhashes first.

| File | sha256 | cdhash |
| --- | --- | --- |
| `SwiftHello.original` | `b76a70d8d31a33f0ae91f529f5ec8b724ed1cbb02419bcbc5c00c1a7fbf69e7a` | `cda728f9a73b24e0839f0b18dc21025cca774abd1edffaadf49a7e8500fc1439` |
| `SwiftHello.obfuscated` | `c30bf1cf1a014e66f301d490473ebc31e611a7d02cb0a9a459b60878710058f3` | `3716cd17b60513ed86d113900b9ce9e01f4c12a266d75c770b30354854baa0eb` |
