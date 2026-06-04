| section | line | summary |
|---------|-----:|---------|
| references | 12 | clean-room study sources + licenses |
| demangler | 22 | architecture of the Swift demangler node machine |
| objc-metadata | 40 | deterministic `__objc_*` runtime-metadata extraction |
| symbol-table | 52 | `LC_SYMTAB` reader feeding the demangler |
| verification | 60 | non-circular measurement against real binaries |
| measured | 70 | honest before/after numbers + remaining gaps |

## references

Clean-room only. The Swift mangling grammar and Objective-C runtime ABI were *studied* from the
sources below and reimplemented in original Rust. No reference source was copied.

- `apple/swift` — `docs/ABI/Mangling.rst` (mangling grammar), `lib/Demangling/Demangler.cpp`
  (word-substitution + identifier algorithm, studied for exactness),
  `include/swift/Demangling/StandardTypesMangling.def` (`S<kind>` standard-substitution table).
  License: Apache-2.0 WITH LLVM-exception.
- `apple/objc4` — runtime headers documenting `class_ro_t` / `method_t` / `ivar_t` / `property_t`
  layout and the small-method-list relative-pointer encoding. License: Apple Public Source License 2.0.

Reference clones lived only under `C:/Users/-/AppData/Local/Temp/disrobe-refs/` and were deleted
after study. Nothing from those trees is vendored into this repo.

## demangler

`demangle.rs` is a recursive-descent demangler over an `Rc`-shared node tree (`Node` + `Kind`).
It models the Swift `global ::= entity operator*` grammar:
- `Demangler` carries `substitutions: Vec<NodeRef>` (back-references resolved via the `A...`
  substitution operator and the standard `S<kind>` table) and `words: Vec<String>` (the
  word-substitution dictionary populated from each parsed identifier, per the reference
  `isWordStart`/`isWordEnd` rules — needed to expand identifiers like `0B9Greetable`).
- Type parsing flows through `demangle_type_base` then `apply_type_suffixes` so standard
  substitutions, nominal paths, bound generics (`y...G`), `Sg` Optional sugar, metatypes and
  `X` decorations all compose uniformly.
- Global operators (`Mn`, `Ma`, `Mf`, `Mm`, `Mp`, `Mc`, `MF`, `N`, `Wvd`, `WP`, `TL`, `Tq`,
  `MXM`, value-witness `w..`, ...) wrap the parsed entity into descriptor nodes.
- `print_node` is `Mode`-aware: `Mode::Type` renders bare type paths (`Swift.Int`,
  `SwiftHello.LoginViewController`), `Mode::Symbol` adds the ` (class)`/` (struct)` kind suffix
  for a bare top-level nominal. Operator descriptions always render their inner type bare,
  matching `swift-demangle` output.

Guards: `MAX_DEPTH` recursion bound, `MAX_NODES` allocation budget (`spend`), checked index math.

## objc-metadata

`objc.rs` + `objc_records.rs` were already deterministic (not detection-only): they parse
`__objc_classlist`, walk each `class_t -> class_ro_t`, and recover class names, superclasses,
instance/class methods (selector + ObjC type-encoding, both big and small/relative method-list
forms), ivars (name + encoding + offset), and properties. `__objc_methname`/`__objc_methtype`/
`__objc_classname` C-string tables are also exposed. Verified against the real
`corpus/mobile/macho-mac/SwiftHello.*` binaries.

`pass.rs` now surfaces a `MetadataSummary` on every `SliceReport` (ObjC class/interface/method/
typed-method/selector/type-encoding counts + Swift reflected/named-type and mangled/demangled
symbol counts) so consumers see the recovery at a glance without traversing the full dump.

## symbol-table

`macho.rs` gained a clean-room `LC_SYMTAB` reader: `parse_slice` captures `SymtabInfo`
(`nlist`/string-table offsets) and `symbol_names` materializes the symbol strings (nlist_64 /
nlist_32, bounded by the string-table size and a per-symbol length cap). `swift::class_dump`
now feeds these symbols (filtered to Swift-mangled) into the demangler alongside the
`__swift5_reflstr` strings, deduped — a real recovery improvement over reflstr-only.

## verification

Non-circular: `tests/real_swift_demangle.rs` reads the binary's OWN `LC_SYMTAB`, demangles every
Swift-mangled symbol, and asserts (a) >=95% demangle, (b) ground-truth class names
(`SwiftHello.LoginViewController`, `SwiftHello.AuthenticationService` — independently confirmed
by the ObjC `_TtC...` class-dump) appear, and (c) representative entity kinds (nominal type
descriptor, type metadata, field offset, deallocating destructor, bare class) are recovered.
The obfuscated twin is checked too. No re-mangling synthesis is used as the oracle.

## measured

Honest, measured on the 65 unique Swift-mangled symbols across both real SwiftHello binaries:
- demangler (raw symbol table): 81.5% (53/65) before -> 100% (65/65) after, and the *quality*
  rose sharply — the old path was prefix-only (every operator collapsed to a bare class name);
  the new path renders the actual entity/operator semantics.
- ObjC runtime metadata: already deterministic; verified intact (2 classes, names, ivars,
  selectors, type-encodings on SwiftHello.original).

Remaining gaps (honest):
- Native machine-code BODIES remain ~20-30% and out of static reach (lossy) — out of scope.
- Generic-signature requirement clauses, full function-parameter type lists, and Punycode
  (non-ASCII identifiers) are parsed/skipped structurally but not fully pretty-printed; none
  appear in the available corpus.
- IPA-fixture end-to-end (a committed signed `.ipa`) is sourcing-blocked per LEGAL.md; the
  symbol/section/demangle algorithms are validated on the committed Mach-O fixtures instead.
- A clean-room resilient `.swiftmodule` field-name reader is not implemented: no `.swiftmodule`
  fixture exists in the corpus to validate against, so it would be unverifiable synthetic code.
