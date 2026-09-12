#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{PanicKind, detect_panic_signatures};

#[test]
fn panic_handler_signature_classified() {
    let syms: [&str; 3] = [
        "core::panicking::panic_fmt::h0",
        "std::panic::catch_unwind::h2",
        "core::fmt::Arguments::new_v1::h7",
    ];
    let out = detect_panic_signatures(&syms);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].kind, PanicKind::CorePanicking);
    assert_eq!(out[1].kind, PanicKind::StdPanic);
    assert_eq!(out[2].kind, PanicKind::FormatArgs);
}
