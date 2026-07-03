#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_wasm_deob::{
    ComponentBindingKind, ComponentBindings, ComponentManifest, lift_component_manifest,
    parse_component_manifest,
};
use wit_parser::{Resolve, UnresolvedPackageGroup};

const ALL_IMPORT_KINDS: &str = r#"
(component
  (type $rec (record (field "x" u32)))
  (import "a-func" (func))
  (import "a-type" (type (eq $rec)))
  (import "a-value" (value u32))
  (import "a-instance" (instance))
  (import "a-component" (component))
  (import "a-module" (core module))
)
"#;

const ALL_EXPORT_KINDS: &str = r#"
(component
  (core module $m
    (func (export "f")))
  (core instance $ci (instantiate $m))
  (alias core export $ci "f" (core func $cf))
  (func $lifted (canon lift (core func $cf)))
  (type $rec (record (field "x" u32)))
  (component $sub)
  (export "e-func" (func $lifted))
  (export "e-type" (type $rec))
  (export "e-module" (core module $m))
  (export "e-component" (component $sub))
)
"#;

fn manifest_of(wat: &str) -> ComponentManifest {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble component wat");
    parse_component_manifest(&bytes).expect("parse component manifest")
}

fn assert_wit_resolves(label: &str, wit: &str) {
    let group: UnresolvedPackageGroup = UnresolvedPackageGroup::parse("recovered.wit", wit)
        .unwrap_or_else(|e| panic!("{label}: generated WIT failed to parse: {e}\n{wit}"));
    let mut resolve: Resolve = Resolve::default();
    resolve
        .push_group(group)
        .unwrap_or_else(|e| panic!("{label}: generated WIT failed to resolve: {e}\n{wit}"));
}

fn assert_no_unsupported_marker(label: &str, wit: &str) {
    assert!(
        !wit.contains("unsupported kind"),
        "{label}: WIT still emits an unsupported-kind comment:\n{wit}"
    );
    assert!(
        !wit.contains(": type;"),
        "{label}: WIT emits the invalid `: type;` world item:\n{wit}"
    );
}

#[test]
fn all_import_kinds_lift_to_resolvable_wit() {
    let manifest: ComponentManifest = manifest_of(ALL_IMPORT_KINDS);
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "all-imports");

    let kinds: Vec<ComponentBindingKind> =
        bindings.imports.iter().map(|i| i.kind).collect::<Vec<_>>();
    assert!(kinds.contains(&ComponentBindingKind::Func));
    assert!(kinds.contains(&ComponentBindingKind::Type));
    assert!(kinds.contains(&ComponentBindingKind::Value));
    assert!(kinds.contains(&ComponentBindingKind::Instance));
    assert!(kinds.contains(&ComponentBindingKind::Component));
    assert!(kinds.contains(&ComponentBindingKind::Module));

    let wit: &str = bindings.wit_source.as_str();
    assert_no_unsupported_marker("imports", wit);
    assert_wit_resolves("imports", wit);

    assert!(wit.contains("import a-func: func();"), "func arm:\n{wit}");
    assert!(
        wit.contains("import a-instance: interface {}"),
        "instance arm:\n{wit}"
    );
    assert!(
        wit.contains("import a-component: interface {}"),
        "component arm:\n{wit}"
    );
    assert!(
        wit.contains("import a-module: interface {}"),
        "module arm:\n{wit}"
    );
    assert!(wit.contains("resource a-type;"), "type arm:\n{wit}");
    assert!(
        wit.contains("recovered value import `a-value`"),
        "value arm:\n{wit}"
    );
}

#[test]
fn all_export_kinds_lift_to_resolvable_wit() {
    let manifest: ComponentManifest = manifest_of(ALL_EXPORT_KINDS);
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "all-exports");

    let kinds: Vec<ComponentBindingKind> =
        bindings.exports.iter().map(|e| e.kind).collect::<Vec<_>>();
    assert!(kinds.contains(&ComponentBindingKind::Func));
    assert!(kinds.contains(&ComponentBindingKind::Type));
    assert!(kinds.contains(&ComponentBindingKind::Component));
    assert!(kinds.contains(&ComponentBindingKind::Module));

    let wit: &str = bindings.wit_source.as_str();
    assert_no_unsupported_marker("exports", wit);
    assert_wit_resolves("exports", wit);

    assert!(
        wit.contains("export e-func: func();"),
        "export func:\n{wit}"
    );
    assert!(
        wit.contains("export e-component: interface {}"),
        "export component:\n{wit}"
    );
    assert!(
        wit.contains("export e-module: interface {}"),
        "export module:\n{wit}"
    );
    assert!(wit.contains("resource e-type;"), "export type:\n{wit}");
}

#[test]
fn hello_world_wit_still_resolves() {
    let manifest: ComponentManifest = manifest_of(
        r#"
        (component
          (core module $m
            (func (export "greet") (param i32 i32) (result i32)
              local.get 0
              local.get 1
              i32.add))
          (core instance $i (instantiate $m))
          (alias core export $i "greet" (core func $greet))
          (func $lifted (param "x" u32) (param "y" u32) (result u32)
            (canon lift (core func $greet)))
          (export "greet" (func $lifted)))
        "#,
    );
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "hello-world");
    assert_wit_resolves("hello", bindings.wit_source.as_str());
    assert!(bindings.wit_source.contains("export greet: func();"));
}
