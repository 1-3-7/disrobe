#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

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
fn an_inner_binding_that_would_capture_the_rename_blocks_it() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 0,
        "renaming `a`->`state` would be shadowed by the inner `const state`; the alias must be left intact:\n{recovered}"
    );
    assert!(
        recovered.contains("import { state as a }"),
        "the original aliased import must survive untouched:\n{recovered}"
    );
}

const SAFETY_FREE_GLOBAL: &str =
    "import { document as a } from 'm';\nconsole.log(a, typeof document);";

#[test]
fn a_free_global_of_the_target_name_blocks_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_FREE_GLOBAL);
    assert_eq!(
        stats.aliased_imports_renamed, 0,
        "renaming `a`->`document` would collide with the free global `document` reference:\n{recovered}"
    );
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
fn a_param_shadow_capturing_the_reference_blocks_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(UNSAFE_PARAM_SHADOW);
    assert_eq!(
        stats.aliased_imports_renamed, 0,
        "renaming `a`->`foo` inside `g(foo)` would resolve to the parameter, changing behavior:\n{recovered}"
    );
    assert!(
        recovered.contains("import { foo as a }"),
        "the aliased import must survive untouched:\n{recovered}"
    );
}
