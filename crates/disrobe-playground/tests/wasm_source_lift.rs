#![cfg(feature = "chain")]
#![allow(clippy::expect_used)]

use disrobe_playground::{WasmSourceTarget, lift_wasm_source};

const ATOMIC_WAIT_NOTIFY_WASM: &[u8] = &[
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x02, 0x60, 0x03, 0x7f, 0x7f, 0x7e,
    0x01, 0x7f, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x03, 0x03, 0x02, 0x00, 0x01, 0x05, 0x04, 0x01,
    0x03, 0x01, 0x01, 0x07, 0x13, 0x02, 0x06, 0x77, 0x61, 0x69, 0x74, 0x33, 0x32, 0x00, 0x00, 0x06,
    0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x00, 0x01, 0x0a, 0x19, 0x02, 0x0c, 0x00, 0x20, 0x00, 0x20,
    0x01, 0x20, 0x02, 0xfe, 0x01, 0x02, 0x00, 0x0b, 0x0a, 0x00, 0x20, 0x00, 0x20, 0x01, 0xfe, 0x00,
    0x02, 0x00, 0x0b,
];

#[test]
fn playground_lifts_atomic_wait_and_notify_to_typescript_source() {
    let lifted = lift_wasm_source(ATOMIC_WAIT_NOTIFY_WASM, WasmSourceTarget::TypeScript)
        .expect("lift the committed inline module");

    assert_eq!(lifted.target, WasmSourceTarget::TypeScript);
    assert_eq!(lifted.function_count, 2);
    assert!(lifted.coverage.fully_recovered());
    assert!(lifted.source.contains("wasmMemoryAtomicWait32"));
    assert!(lifted.source.contains("wasmMemoryAtomicNotify"));
    assert!(lifted.source.contains("Atomics.wait"));
    assert!(lifted.source.contains("Atomics.notify"));
}

#[test]
fn playground_lifts_atomic_wait_and_notify_to_every_source_target() {
    let cases: [(WasmSourceTarget, &str, &str); 3] = [
        (
            WasmSourceTarget::Rust,
            "wasm_memory_atomic_wait32",
            "wasm_memory_atomic_notify",
        ),
        (
            WasmSourceTarget::C,
            "wasm_memory_atomic_wait32",
            "wasm_memory_atomic_notify",
        ),
        (
            WasmSourceTarget::Wat,
            "memory.atomic.wait32",
            "memory.atomic.notify",
        ),
    ];

    for (target, wait, notify) in cases {
        let lifted = lift_wasm_source(ATOMIC_WAIT_NOTIFY_WASM, target)
            .expect("lift the committed inline module");
        assert_eq!(lifted.target, target);
        assert_eq!(lifted.function_count, 2);
        assert!(lifted.coverage.fully_recovered());
        assert!(
            lifted.source.contains(wait),
            "{target:?}: {}",
            lifted.source
        );
        assert!(
            lifted.source.contains(notify),
            "{target:?}: {}",
            lifted.source
        );
    }
}
