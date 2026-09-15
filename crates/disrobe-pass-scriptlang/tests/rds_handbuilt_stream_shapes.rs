#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_scriptlang::lang::r_rds::{RdsClosure, RdsObject, read_rds};

const NILVALUE_SXP: u32 = 254;
const GLOBALENV_SXP: u32 = 253;
const MISSINGARG_SXP: u32 = 251;
const SYMSXP: u32 = 1;
const LISTSXP: u32 = 2;
const CLOSXP: u32 = 3;
const LANGSXP: u32 = 6;
const CHARSXP: u32 = 9;
const REALSXP: u32 = 14;
const REFSXP: u32 = 255;
const HAS_TAG_BIT: u32 = 1 << 10;

fn be(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&(v as i32).to_be_bytes());
}

fn header(out: &mut Vec<u8>) {
    out.extend_from_slice(b"X\n");
    out.extend_from_slice(&3i32.to_be_bytes());
    out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
    out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
    out.extend_from_slice(&5i32.to_be_bytes());
    out.extend_from_slice(b"UTF-8");
}

fn symsxp(out: &mut Vec<u8>, name: &str) {
    be(out, SYMSXP);
    be(out, CHARSXP);
    out.extend_from_slice(&(name.len() as i32).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
}

fn refsxp(out: &mut Vec<u8>, index: u32) {
    out.extend_from_slice(&((REFSXP | (index << 8)) as i32).to_be_bytes());
}

fn real_scalar(out: &mut Vec<u8>, x: f64) {
    be(out, REALSXP);
    out.extend_from_slice(&1i32.to_be_bytes());
    out.extend_from_slice(&x.to_be_bytes());
}

fn closure_x_plus_y() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    header(&mut out);
    be(&mut out, CLOSXP | HAS_TAG_BIT);
    be(&mut out, GLOBALENV_SXP);

    be(&mut out, LISTSXP | HAS_TAG_BIT);
    symsxp(&mut out, "x");
    be(&mut out, MISSINGARG_SXP);
    be(&mut out, LISTSXP | HAS_TAG_BIT);
    symsxp(&mut out, "y");
    be(&mut out, MISSINGARG_SXP);
    be(&mut out, NILVALUE_SXP);

    be(&mut out, LANGSXP);
    symsxp(&mut out, "+");
    be(&mut out, LISTSXP);
    refsxp(&mut out, 1);
    be(&mut out, LISTSXP);
    refsxp(&mut out, 2);
    be(&mut out, NILVALUE_SXP);

    out
}

fn closure_default_and_literal() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    header(&mut out);
    be(&mut out, CLOSXP | HAS_TAG_BIT);
    be(&mut out, GLOBALENV_SXP);

    be(&mut out, LISTSXP | HAS_TAG_BIT);
    symsxp(&mut out, "n");
    real_scalar(&mut out, 1.0);
    be(&mut out, NILVALUE_SXP);

    be(&mut out, LANGSXP);
    symsxp(&mut out, "*");
    be(&mut out, LISTSXP);
    refsxp(&mut out, 1);
    be(&mut out, LISTSXP);
    real_scalar(&mut out, 2.0);
    be(&mut out, NILVALUE_SXP);

    out
}

fn only_closure(obj: &RdsObject) -> &RdsClosure {
    assert_eq!(
        obj.closures.len(),
        1,
        "exactly one closure expected; got {}",
        obj.closures.len()
    );
    &obj.closures[0]
}

#[test]
fn handbuilt_closure_stream_reports_a_closure_root() {
    let obj: RdsObject = read_rds(&closure_x_plus_y()).expect("parse closure rds");
    assert_eq!(obj.root_type, "closure");
    assert_eq!(obj.closures.len(), 1);
}

#[test]
fn handbuilt_closure_pairlist_yields_formal_names_in_order() {
    let obj: RdsObject = read_rds(&closure_x_plus_y()).expect("parse");
    let c: &RdsClosure = only_closure(&obj);
    let names: Vec<&str> = c.formals.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, vec!["x", "y"], "formals must be recovered in order");
    assert!(
        c.formals.iter().all(|f| f.default.is_none()),
        "x and y have no defaults: {:?}",
        c.formals
    );
}

#[test]
fn handbuilt_language_body_renders_as_infix() {
    let obj: RdsObject = read_rds(&closure_x_plus_y()).expect("parse");
    let c: &RdsClosure = only_closure(&obj);
    assert_eq!(
        c.body, "x + y",
        "the hand-written language body must render as infix"
    );
    assert_eq!(c.rendered, "function(x, y) x + y");
}

#[test]
fn handbuilt_default_argument_and_numeric_literal_render() {
    let obj: RdsObject = read_rds(&closure_default_and_literal()).expect("parse");
    let c: &RdsClosure = only_closure(&obj);
    assert_eq!(c.formals.len(), 1);
    assert_eq!(c.formals[0].name, "n");
    assert_eq!(
        c.formals[0].default.as_deref(),
        Some("1"),
        "default value of n must round-trip"
    );
    assert_eq!(c.body, "n * 2");
    assert_eq!(c.rendered, "function(n = 1) n * 2");
}

#[test]
fn handbuilt_globalenv_singleton_marks_a_reference_environment() {
    let obj: RdsObject = read_rds(&closure_x_plus_y()).expect("parse");
    let c: &RdsClosure = only_closure(&obj);
    assert!(
        c.environment.is_reference,
        "the global environment is serialized as a singleton reference: {:?}",
        c.environment
    );
}
