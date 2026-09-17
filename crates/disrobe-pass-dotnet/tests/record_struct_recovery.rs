#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

const EDGECASES_BASELINE_REL: &str = "../../corpus/dotnet/megafile/EdgeCases.baseline.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn baseline() -> DecompiledAssembly {
    let bytes: Vec<u8> = load(EDGECASES_BASELINE_REL);
    decompile_assembly(&bytes).expect("decompile baseline")
}

fn method_by_signature<'a>(
    asm: &'a DecompiledAssembly,
    needle: &str,
) -> Option<&'a StructuredMethod> {
    asm.methods.iter().find(|m: &&StructuredMethod| {
        m.signature
            .lines()
            .next_back()
            .is_some_and(|l: &str| l.contains(needle))
    })
}

#[test]
fn coordinate_readonly_record_struct_carries_record_provenance() {
    let asm: DecompiledAssembly = baseline();
    let deconstruct: &StructuredMethod = method_by_signature(
        &asm,
        "Deconstruct(ref double Latitude, ref double Longitude)",
    )
    .expect("Coordinate.Deconstruct present in baseline");
    assert!(
        deconstruct.signature.contains("[record"),
        "the readonly record struct Coordinate has no EqualityContract (value types never \
         generate one), so a synthesized member like Deconstruct must still be recognized as \
         record-generated via the PrintMembers/Deconstruct/op_Equality/op_Inequality \
         fingerprint; got: {}",
        deconstruct.signature
    );
    assert!(
        deconstruct
            .signature
            .contains("[record - compiler-synthesized member]"),
        "Deconstruct is compiler-synthesized boilerplate, not a user method; got: {}",
        deconstruct.signature
    );
}

#[test]
fn coordinate_user_method_is_tagged_record_but_not_synthesized() {
    let asm: DecompiledAssembly = baseline();
    let distance_to: &StructuredMethod =
        method_by_signature(&asm, "DistanceTo").expect("Coordinate.DistanceTo present in baseline");
    assert!(
        distance_to.signature.contains("[record]"),
        "a real user-written instance method on a record struct still carries the [record] \
         provenance tag documenting its containing type; got: {}",
        distance_to.signature
    );
    assert!(
        !distance_to
            .signature
            .contains("[record - compiler-synthesized member]"),
        "DistanceTo is hand-written source, not compiler-synthesized boilerplate, and must \
         never be mislabeled as such; got: {}",
        distance_to.signature
    );
}

#[test]
fn shift_recovers_the_struct_with_expression() {
    let asm: DecompiledAssembly = baseline();
    let shift: &StructuredMethod =
        method_by_signature(&asm, "Coordinate Shift(").expect("Shift present in baseline");
    assert!(
        shift.body.contains("with {"),
        "the readonly record struct with-expression `c with {{ Latitude = ..., Longitude = ... }}` \
         has no <Clone>$ call to key off of (value-type records never synthesize Clone), so \
         recovery must key off the local-copy-then-field-mutate CIL shape instead; got:\n{}",
        shift.body
    );
    assert!(
        shift.body.contains("Latitude = c.Latitude + dx"),
        "each with-initializer must evaluate against the original source value `c`, not a \
         partially mutated copy; got:\n{}",
        shift.body
    );
    assert!(
        shift.body.contains("Longitude = c.Longitude + dy"),
        "got:\n{}",
        shift.body
    );
    assert!(
        !shift.body.contains("local0"),
        "once folded into a with-expression the intermediate copy local must no longer appear; \
         got:\n{}",
        shift.body
    );
}
