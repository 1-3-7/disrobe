#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{
    ComponentBindings, ComponentManifest, lift_component_manifest, parse_component_manifest,
};

const HELLO_COMPONENT: &str = r#"
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
"#;

#[test]
fn hello_component_lifts_to_typed_rust_trait_and_ts_interface() {
    let bytes: Vec<u8> = wat::parse_str(HELLO_COMPONENT).expect("parse wat");
    let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("parse manifest");
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "hello-world");

    assert_eq!(bindings.world_name, "hello_world");
    assert!(
        bindings
            .exports
            .iter()
            .any(|e: &disrobe_pass_wasm_deob::ComponentBindingItem| e.name == "greet")
    );

    let rs: &str = bindings.rust_source.as_str();
    assert!(rs.contains("pub trait ExportsHelloWorld"));
    assert!(rs.contains("fn greet(&self)"));
    assert!(rs.contains("Result<(), GuestError>"));

    let ts: &str = bindings.ts_source.as_str();
    assert!(ts.contains("export interface ExportsHelloWorld"));
    assert!(ts.contains("greet(): void"));

    let wit: &str = bindings.wit_source.as_str();
    assert!(wit.contains("world hello-world"));
    assert!(wit.contains("export greet: func();"));
}

#[test]
fn typed_rust_bindings_are_compileable_skeleton() {
    let bytes: Vec<u8> = wat::parse_str(HELLO_COMPONENT).expect("parse");
    let manifest: ComponentManifest = parse_component_manifest(&bytes).expect("manifest");
    let bindings: ComponentBindings = lift_component_manifest(&manifest, "hello_world");
    assert!(bindings.rust_source.starts_with("#![allow(dead_code)]"));
    assert!(bindings.rust_source.contains("pub struct HostError"));
    assert!(bindings.rust_source.contains("pub struct GuestError"));
}
