#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{CxxAbi, CxxDemangled, demangle_msvc};

#[test]
fn msvc_simple_function_demangles() {
    let d: CxxDemangled = demangle_msvc("?foo@@YAHXZ").expect("msvc");
    assert!(d.demangled.contains("foo"));
    assert_eq!(d.abi, CxxAbi::Msvc);
}
