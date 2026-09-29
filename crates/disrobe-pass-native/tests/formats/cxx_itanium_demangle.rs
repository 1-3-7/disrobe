#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{CxxAbi, CxxDemangled, demangle_itanium};

#[test]
fn itanium_simple_function_demangles() {
    let d: CxxDemangled = demangle_itanium("_ZN3std3fooEv").expect("itanium");
    assert!(d.demangled.contains("std::foo"));
    assert_eq!(d.abi, CxxAbi::Itanium);
}
