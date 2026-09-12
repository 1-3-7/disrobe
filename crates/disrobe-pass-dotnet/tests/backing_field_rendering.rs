#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

#[test]
fn auto_property_backing_fields_render_as_the_property_name() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        assert!(
            !m.body.contains("k__BackingField"),
            "the compiler-generated <X>k__BackingField (not a valid C# identifier) must render as the auto-property name X in {}; got:\n{}",
            m.signature,
            m.body
        );
    }
    let ctor: &str = &asm
        .methods
        .iter()
        .find(|m| m.signature.contains(".ctor(int X, int Y)"))
        .expect("record primary constructor")
        .body;
    assert!(
        ctor.contains("this.X = X;") && ctor.contains("this.Y = Y;"),
        "the record primary ctor must assign the recovered auto-properties; got:\n{ctor}"
    );
}

#[test]
fn decompile_remains_lossless_after_backing_field_rename() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after the backing-field rename; got {} failures",
        asm.methods_failed
    );
}
