#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{ScalaDemangled, demangle_scala};

#[test]
fn demangles_object_suffix() {
    let d: ScalaDemangled = demangle_scala("MyObject$");
    assert_eq!(d.demangled, "MyObject");
}

#[test]
fn demangles_operator_tokens() {
    let d: ScalaDemangled = demangle_scala("Foo$plus$plus");
    assert!(d.demangled.contains('+'));
}

#[test]
fn passes_through_unrelated_names() {
    let d: ScalaDemangled = demangle_scala("regular_name");
    assert_eq!(d.demangled, "regular_name");
}
