# Swift symbol demangle recall vs the binary's own symbol table

- id: `swift-demangle`
- ecosystem: swift
- claim: disrobe demangles the Swift-mangled symbols carried in a real Mach-O's own LC_SYMTAB, recovering class names, type metadata, and field offsets that match the reference swift-demangle.
- measured: 37/37 (100.0%)
- oracle strength: strong
- CI-attested: no [local]
- external oracle: the binary's own LC_SYMTAB Swift-mangled symbols (a non-circular, in-artifact ground truth); reference parity is the swift-demangle tool
- reproduce: `cargo test -p disrobe-pass-swift-objc --test real_swift_demangle  (harvested by cargo run -p disrobe-bench-head-to-head)`
- floor: 95.00 (holds)
- gate source: cargo test -p disrobe-pass-swift-objc --test real_swift_demangle (gate swift-demangle-recall, harvested by cargo run -p disrobe-bench-head-to-head)
- note: Local: the SwiftHello.original Mach-O fixture is LEGAL.md sourcing-gated, so this is [local] until the Swift toolchain + fixture run in a Swift CI lane. The number is the in-process demangle of the binary's own symbols.
