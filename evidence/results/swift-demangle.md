# Pinned Swift symbol renderings from the committed SwiftHello Mach-O

- id: `swift-demangle`
- ecosystem: swift
- claim: disrobe recognizes and renders every Swift-mangled symbol in the committed SwiftHello Mach-O against pinned in-process output. No external demangler grades output correctness in this gate.
- measured: 100.00%
- oracle strength: coverage-self-reported
- CI-attested: yes [CI]
- evidence basis: the committed SwiftHello Mach-O LC_SYMTAB fixes the named Swift-mangled symbol population; expected renderings are committed regression pins, not an external correctness oracle
- reproduce: `cargo test -p disrobe-pass-swift-objc --test swift_hello_symbol_pin`
- gate source: crates/disrobe-pass-swift-objc/tests/swift_hello_symbol_pin.rs test published_swift_symbol_rendering_is_pinned_to_the_measured_membership, which pins the 37-symbol LC_SYMTAB membership, denominator and in-process rendering text against the committed fixture
