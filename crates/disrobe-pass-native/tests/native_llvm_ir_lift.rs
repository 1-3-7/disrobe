#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Error, lift_llvm_ir_to_pseudo_c};

#[test]
fn ir_with_define_emits_pseudo() {
    let ir: &str = "define i32 @main() {\n  ret i32 0\n}\n";
    let out: String = lift_llvm_ir_to_pseudo_c(ir).expect("lift");
    assert!(out.contains("return"));
}

#[test]
fn empty_ir_rejected() {
    let err: Error = lift_llvm_ir_to_pseudo_c("").expect_err("must reject empty");
    assert!(matches!(err, Error::LlvmIr(_)));
}
