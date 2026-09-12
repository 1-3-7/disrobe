#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const ORIG_FN_EXPORT: &str = "function a(x) { return x * 2; }\nconst seed = a(21);\nexport { a as computeDouble };\nconsole.log(seed);";

#[test]
fn aliased_function_export_restores_developer_name() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_FN_EXPORT);
    assert!(
        stats.aliased_exports_renamed >= 1,
        "the `a as computeDouble` export alias must be undone; got {}",
        stats.aliased_exports_renamed
    );
    assert!(
        recovered.contains("function computeDouble(x)"),
        "the binding must be renamed to the exported developer name:\n{recovered}"
    );
    assert!(
        recovered.contains("computeDouble(21)"),
        "the call-site reference must be rewritten:\n{recovered}"
    );
    assert!(
        recovered.contains("export { computeDouble }"),
        "the export specifier must collapse the alias:\n{recovered}"
    );
    assert!(
        !recovered.contains("as computeDouble"),
        "the `as` alias clause must be gone:\n{recovered}"
    );
}

const ORIG_CLASS_EXPORT: &str =
    "class h {\n  greet() { return 'hi'; }\n}\nexport { h as Greeter };";

#[test]
fn aliased_class_export_recovers() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_CLASS_EXPORT);
    assert_eq!(
        stats.aliased_exports_renamed, 1,
        "the `h as Greeter` class export must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("class Greeter"),
        "the class binding must become its exported name:\n{recovered}"
    );
    assert!(
        recovered.contains("export { Greeter }"),
        "the export must collapse:\n{recovered}"
    );
}

const SAFETY_COLLISION: &str = "function a() { return 1; }\nfunction compute() { return 2; }\nexport { a as compute };\nconsole.log(compute());";

#[test]
fn a_target_name_already_bound_blocks_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_COLLISION);
    assert_eq!(
        stats.aliased_exports_renamed, 0,
        "renaming `a`->`compute` would collide with the existing `compute` function:\n{recovered}"
    );
    assert!(
        recovered.contains("export { a as compute }"),
        "the aliased export must survive untouched:\n{recovered}"
    );
}

const SAFETY_REEXPORT_IMPORT: &str =
    "import { realName as a } from './mod';\nexport { a as publicName };";

#[test]
fn re_exporting_an_imported_binding_is_left_to_the_import_owner() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_REEXPORT_IMPORT);
    assert_eq!(
        stats.aliased_exports_renamed, 0,
        "the binding `a` is an import; its real name belongs to the import, not the export specifier"
    );
}

const SAFETY_SHORTER: &str = "function descriptiveName() {}\nexport { descriptiveName as d };";

#[test]
fn a_shorter_export_name_is_not_a_recovery() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHORTER);
    assert_eq!(
        stats.aliased_exports_renamed, 0,
        "shortening a name is minification, not recovery; the rule must only lengthen toward the developer name"
    );
}

const SAFETY_FROM_SOURCE: &str = "export { a as compute } from './other';";

#[test]
fn a_re_export_from_a_source_module_is_untouched() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_FROM_SOURCE);
    assert_eq!(
        stats.aliased_exports_renamed, 0,
        "`export ... from` names a binding in another module; there is no local binding to rename:\n{recovered}"
    );
}

const SAFE_INNER_BLOCK_SHADOW: &str = "function a() { return 1; }\nfunction g() { { let compute = 5; console.log(compute); } return a(); }\nexport { a as compute };\nconsole.log(g());";

#[test]
fn an_inner_block_shadow_does_not_block_the_export_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFE_INNER_BLOCK_SHADOW);
    assert_eq!(
        stats.aliased_exports_renamed, 1,
        "the inner-block `let compute` cannot capture the `return a()` reference, so renaming `a`->`compute` is safe:\n{recovered}"
    );
    assert!(
        recovered.contains("function compute() { return 1; }"),
        "the exported binding must take the developer name:\n{recovered}"
    );
    assert!(
        recovered.contains("return compute();"),
        "the outer call-site must be rewritten:\n{recovered}"
    );
    assert!(
        recovered.contains("let compute = 5;"),
        "the unrelated inner-block binding must be left as-is:\n{recovered}"
    );
    assert!(
        recovered.contains("export { compute }"),
        "the export alias must collapse:\n{recovered}"
    );
}

const UNSAFE_CAPTURING_SHADOW: &str = "function a() { return 1; }\nfunction g() { let compute = a(); return compute; }\nexport { a as compute };\nconsole.log(g());";

#[test]
fn a_capturing_inner_binding_blocks_the_export_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(UNSAFE_CAPTURING_SHADOW);
    assert_eq!(
        stats.aliased_exports_renamed, 0,
        "the `let compute = a()` reference sits in the same scope as a `compute` binding; renaming `a`->`compute` would self-capture:\n{recovered}"
    );
    assert!(
        recovered.contains("export { a as compute }"),
        "the aliased export must survive untouched:\n{recovered}"
    );
}
