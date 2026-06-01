#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use disrobe_pass_py_decompile::ast::Comprehension;
use disrobe_pass_py_decompile::codegen::inlined_comprehension_emit::{
    is_inlined, supports_pep_709,
};

use crate::common::{name, name_store, ver};

#[test]
fn pep_709_version_gate() {
    assert!(supports_pep_709(&ver(3, 12)));
    assert!(!supports_pep_709(&ver(3, 11)));
}

#[test]
fn comprehension_inlined_on_3_12_plus() {
    let comp: Comprehension = Comprehension {
        target: name_store("i"),
        iter: name("xs"),
        ifs: Vec::new(),
        is_async: false,
    };
    assert!(is_inlined(&comp, &ver(3, 12)));
    assert!(!is_inlined(&comp, &ver(3, 11)));
    assert!(!is_inlined(&comp, &ver(3, 10)));
}

#[test]
fn ast_shape_identical_3_10_vs_3_12() {
    let comp_3_10: Comprehension = Comprehension {
        target: name_store("x"),
        iter: name("items"),
        ifs: Vec::new(),
        is_async: false,
    };
    let comp_3_12: Comprehension = comp_3_10.clone();
    assert_eq!(comp_3_10, comp_3_12);
}
