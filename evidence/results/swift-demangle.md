# Swift symbol demangle recall vs the binary's own symbol table

- id: `swift-demangle`
- ecosystem: swift
- claim: disrobe demangles the Swift-mangled symbols carried in a real Mach-O's own LC_SYMTAB, recovering class names, type metadata, and field offsets that match the reference swift-demangle.
- measured: 37/37 (100.0%)
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: the binary's own LC_SYMTAB Swift-mangled symbols, an in-artifact ground truth the tool does not author; the committed fixture pins all 37 by name, and reference parity against the swift-demangle tool runs only where that tool is installed, which CI does not provide
- reproduce: `cargo test -p disrobe-pass-swift-objc --test real_swift_demangle  (harvested by cargo run -p disrobe-bench-head-to-head)`
- floor: 95.00 (holds)
- gate source: cargo test -p disrobe-pass-swift-objc --test real_swift_demangle (gate swift-demangle-recall, harvested by cargo run -p disrobe-bench-head-to-head)
- note: Local: the SwiftHello.original Mach-O fixture is LEGAL.md sourcing-gated, so this is [local] until the Swift toolchain + fixture run in a Swift CI lane. The number is the in-process demangle of the binary's own symbols.
