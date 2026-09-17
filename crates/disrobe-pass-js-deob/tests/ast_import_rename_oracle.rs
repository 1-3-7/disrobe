#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};
use std::process::{Command, Output};

fn run_module(source: &str) -> Output {
    Command::new("node")
        .args(["--input-type=module", "-e", source])
        .output()
        .expect("Node must execute the module fixture")
}

fn run_exported_module(source: &str) -> Output {
    const HARNESS: &str = "const encoded = Buffer.from(process.argv[1]).toString('base64'); const module = await import('data:text/javascript;base64,' + encoded); console.log(module.a);";
    Command::new("node")
        .args(["--input-type=module", "-e", HARNESS, source])
        .output()
        .expect("Node must import the generated module fixture")
}

const ORIG_ALIASED: &str = "import { computeTotal as a } from './math';\nconst result = a(10, 20);\nconsole.log(result, a);";

#[test]
fn aliased_named_import_restores_developer_name() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_ALIASED);
    assert!(
        stats.aliased_imports_renamed >= 1,
        "the `foo as a` alias must be undone; got {}",
        stats.aliased_imports_renamed
    );
    assert!(
        recovered.contains("import { computeTotal }"),
        "the import specifier must drop the alias and restore the real name:\n{recovered}"
    );
    assert!(
        recovered.contains("computeTotal(10, 20)"),
        "the call-site reference to the minified local must be rewritten:\n{recovered}"
    );
    assert!(
        recovered.contains("result, computeTotal"),
        "the value-position reference must be rewritten:\n{recovered}"
    );
    assert!(
        !recovered.contains(" as a "),
        "the `as a` alias clause must be gone:\n{recovered}"
    );
}

const ORIG_MULTI: &str = "import { readFile as r, writeFile as w } from 'fs';\nr();\nw();\nconsole.log(typeof r, typeof w);";

#[test]
fn multiple_aliased_specifiers_each_recover() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_MULTI);
    assert_eq!(
        stats.aliased_imports_renamed, 2,
        "both `readFile as r` and `writeFile as w` must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("readFile") && recovered.contains("writeFile"),
        "both developer names must be restored:\n{recovered}"
    );
    assert!(
        recovered.contains("typeof readFile") && recovered.contains("typeof writeFile"),
        "references inside `typeof` must be rewritten:\n{recovered}"
    );
}

const SAFETY_SHADOW: &str = "import { state as a } from './store';\nfunction render() { const state = { x: 1 }; return state.x + a; }\nconsole.log(render());";

#[test]
fn an_inner_binding_that_would_capture_the_preferred_name_receives_a_safe_suffix() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 1,
        "the import must receive a name the inner `state` cannot capture:\n{recovered}"
    );
    assert!(
        recovered.contains("import { state as state_1 }")
            && recovered.contains("state.x + state_1"),
        "the safe suffix must update only the import binding and its references:\n{recovered}"
    );
}

const SAFETY_FREE_GLOBAL: &str =
    "import { document as a } from 'm';\nconsole.log(a, typeof document);";

#[test]
fn a_free_global_of_the_target_name_receives_a_safe_suffix() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_FREE_GLOBAL);
    assert_eq!(
        stats.aliased_imports_renamed, 1,
        "the imported binding must not collide with the free global:\n{recovered}"
    );
    assert!(recovered.contains("import { document as document_1 }"));
    assert!(recovered.contains("console.log(document_1, typeof document);"));
}

const SAFETY_MEMBER: &str =
    "import { length as a } from 'm';\nconst arr = [1, 2, 3];\nconsole.log(a, arr.length);";

#[test]
fn an_object_member_named_like_the_target_is_not_rewritten() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_MEMBER);
    assert!(
        stats.aliased_imports_renamed >= 1,
        "the import alias itself is renamable here (no `length` binding collides):\n{recovered}"
    );
    assert!(
        recovered.contains("arr.length"),
        "the `.length` member access is unrelated to the import binding and must be preserved:\n{recovered}"
    );
    assert!(
        recovered.contains("import { length }"),
        "the import must restore `length`:\n{recovered}"
    );
}

const SAFETY_STR_IMPORT: &str = "import { 'evil-name' as a } from 'm';\nconsole.log(a);";

#[test]
fn string_literal_import_names_are_left_alone() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_STR_IMPORT);
    assert_eq!(
        stats.aliased_imports_renamed, 0,
        "a string-literal import name is not a valid identifier and must never be promoted to a binding"
    );
}

const SAFE_INNER_BLOCK_SHADOW: &str = "import { foo as a } from 'm';\nfunction g() { { let foo = 9; console.log(foo); } return a; }\nconsole.log(g());";

#[test]
fn an_inner_block_shadow_that_cannot_capture_the_reference_still_renames() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFE_INNER_BLOCK_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 1,
        "the inner `let foo` is block-scoped and closes before `return a`, so renaming `a`->`foo` is safe:\n{recovered}"
    );
    assert!(
        recovered.contains("import { foo }"),
        "the import alias must be collapsed to the developer name:\n{recovered}"
    );
    assert!(
        recovered.contains("return foo;"),
        "the outer reference must be rewritten to the restored name:\n{recovered}"
    );
    assert!(
        recovered.contains("let foo = 9;"),
        "the unrelated inner-block binding must be left exactly as-is:\n{recovered}"
    );
}

const SAFE_SIBLING_SCOPE_SHADOW: &str = "import { foo as a } from 'm';\nfunction h() { let foo = 1; return foo; }\nfunction g() { return a; }\nconsole.log(h(), g());";

#[test]
fn a_sibling_scope_binding_of_the_target_name_does_not_block_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFE_SIBLING_SCOPE_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 1,
        "the `foo` in sibling function `h` cannot reach the reference in `g`, so the rename is safe:\n{recovered}"
    );
    assert!(
        recovered.contains("function g() { return foo; }"),
        "the reference in `g` must be rewritten:\n{recovered}"
    );
    assert!(
        recovered.contains("function h() { let foo = 1; return foo; }"),
        "the sibling `h` must be untouched:\n{recovered}"
    );
}

const UNSAFE_PARAM_SHADOW: &str =
    "import { foo as a } from 'm';\nfunction g(foo) { return foo + a; }\nconsole.log(g(1));";

#[test]
fn a_param_shadow_capturing_the_preferred_name_receives_a_safe_suffix() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(UNSAFE_PARAM_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 1,
        "the imported binding must remain distinct from the parameter:\n{recovered}"
    );
    assert!(
        recovered.contains("import { foo as foo_1 }") && recovered.contains("foo + foo_1"),
        "the safe suffix must preserve the parameter lookup:\n{recovered}"
    );
}

#[test]
fn colliding_imported_names_receive_distinct_scope_safe_bindings() {
    let source: &str = "import { foo as a } from 'data:text/javascript,export%20const%20foo%3D%22A%22';\nimport { foo as b } from 'data:text/javascript,export%20const%20foo%3D%22B%22';\nconsole.log(a + b);";
    let original: Output = run_module(source);
    assert!(original.status.success(), "original module must execute");
    assert_eq!(original.stdout, b"AB\n");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(
        stats.aliased_imports_renamed, 2,
        "both imports must receive readable, distinct bindings:\n{recovered}"
    );
    assert!(
        recovered.contains("import { foo } from"),
        "the first import must take the preferred binding:\n{recovered}"
    );
    assert!(
        recovered.contains("import { foo as foo_1 } from"),
        "the collision must receive the first available suffix:\n{recovered}"
    );
    assert!(
        recovered.contains("console.log(foo + foo_1);"),
        "each reference must follow its resolved import:\n{recovered}"
    );
    let rerun: Output = run_module(&recovered);
    assert!(rerun.status.success(), "recovered module must execute");
    assert_eq!(rerun.stdout, original.stdout);

    let (repeated, repeated_stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(repeated, recovered);
    assert_eq!(repeated_stats.aliased_imports_renamed, 2);
}

#[test]
fn comment_inside_import_specifier_causes_byte_preserving_refusal() {
    let source: &str = "import { foo /* retained */ as a } from 'm';\nconsole.log(a);";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.aliased_imports_renamed, 0);
    assert_eq!(recovered, source);
}

#[test]
fn object_shorthand_keeps_its_runtime_property_name() {
    let source: &str = "import { foo as a } from 'data:text/javascript,export%20const%20foo%3D%22A%22';\nconsole.log(JSON.stringify({ a }));";
    let original: Output = run_module(source);
    assert!(original.status.success());
    assert_eq!(original.stdout, b"{\"a\":\"A\"}\n");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.aliased_imports_renamed, 1);
    assert!(
        recovered.contains("{ a: foo }") || recovered.contains("{a: foo}"),
        "the property key must stay `a` while its value follows the import rename:\n{recovered}"
    );
    let rerun: Output = run_module(&recovered);
    assert!(rerun.status.success());
    assert_eq!(rerun.stdout, original.stdout);
}

#[test]
fn shorthand_export_keeps_its_public_name() {
    let source: &str = "import { foo as a } from 'data:text/javascript,export%20const%20foo%3D%22A%22';\nexport { a };";
    let original: Output = run_exported_module(source);
    assert!(original.status.success());
    assert_eq!(original.stdout, b"A\n");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.aliased_imports_renamed, 1);
    assert!(
        recovered.contains("export { foo as a }"),
        "the lexical rename must preserve the public export name:\n{recovered}"
    );
    let rerun: Output = run_exported_module(&recovered);
    assert!(rerun.status.success());
    assert_eq!(rerun.stdout, original.stdout);
}

#[test]
fn explicit_same_name_export_alias_remains_parseable() {
    let source: &str = "import { foo as a } from 'data:text/javascript,export%20const%20foo%3D%22A%22';\nexport { a as a };";
    let original: Output = run_exported_module(source);
    assert!(original.status.success());
    assert_eq!(original.stdout, b"A\n");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.aliased_imports_renamed, 1);
    assert!(recovered.contains("export { foo as a }"));
    assert!(!recovered.contains("as a as a"));
    let rerun: Output = run_exported_module(&recovered);
    assert!(
        rerun.status.success(),
        "recovered module must parse and execute"
    );
    assert_eq!(rerun.stdout, original.stdout);
}

#[test]
fn suffix_search_covers_descendant_scope_bindings() {
    let source: &str = "import { foo as a } from 'data:text/javascript,export%20const%20foo%3D%22A%22';\nfunction read(foo, foo_1, foo_2, foo_3) { return a; }\nconsole.log(read());";
    let original: Output = run_module(source);
    assert!(original.status.success());
    assert_eq!(original.stdout, b"A\n");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(source);
    assert_eq!(stats.aliased_imports_renamed, 1);
    assert!(
        recovered.contains("import { foo as foo_4 }") && recovered.contains("return foo_4;"),
        "the first safe suffix beyond every capturing parameter must be selected:\n{recovered}"
    );
    let rerun: Output = run_module(&recovered);
    assert!(rerun.status.success());
    assert_eq!(rerun.stdout, original.stdout);
}
