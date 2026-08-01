#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_pyfreeze::{FreezerKind, FreezerManifest, ModuleInventoryEntry};
use jsonschema::Validator;
use serde_json::{Value, json};

fn published_schema() -> Value {
    serde_json::from_str(include_str!("../../../schemas/v0/json/freezer-manifest.schema.json"))
        .expect("parse published freezer manifest schema")
}

fn validator() -> Validator {
    jsonschema::validator_for(&published_schema()).expect("compile published freezer manifest schema")
}

fn manifest_value(kind: FreezerKind, with_inventory: bool) -> Value {
    let mut manifest: FreezerManifest = FreezerManifest::new(kind, "fixture.exe".to_owned());
    if with_inventory {
        manifest.module_inventory.push(ModuleInventoryEntry {
            name: "pkg.module".to_owned(),
            is_package: false,
            has_source: true,
            has_bytecode: true,
            has_bytecode_opt1: false,
            has_bytecode_opt2: false,
            has_extension: false,
        });
    }
    serde_json::to_value(manifest).expect("serialize emitted freezer manifest")
}

fn assert_valid(validator: &Validator, manifest: &Value) {
    let errors: Vec<String> = validator
        .iter_errors(manifest)
        .map(|error: jsonschema::ValidationError<'_>| error.to_string())
        .collect();
    assert!(errors.is_empty(), "schema rejected emitted manifest: {errors:?}");
}

#[test]
fn published_schema_accepts_every_emitted_freezer_kind_and_pyoxidizer_inventory() {
    let validator: Validator = validator();
    for kind in [
        FreezerKind::CxFreeze,
        FreezerKind::Py2exe,
        FreezerKind::Bbfreeze,
        FreezerKind::Shiv,
        FreezerKind::Pex,
        FreezerKind::Zipapp,
        FreezerKind::Pyc,
        FreezerKind::PyOxidizer,
        FreezerKind::Briefcase,
        FreezerKind::Unknown,
    ] {
        assert_valid(
            &validator,
            &manifest_value(kind, matches!(kind, FreezerKind::PyOxidizer)),
        );
    }
}

#[test]
fn published_schema_rejects_a_corrupted_pyoxidizer_inventory_entry() {
    let validator: Validator = validator();
    let mut manifest: Value = manifest_value(FreezerKind::PyOxidizer, true);
    assert_valid(&validator, &manifest);
    manifest["module_inventory"][0]["has_source"] = json!("corrupted");
    let errors: Vec<jsonschema::ValidationError<'_>> = validator.iter_errors(&manifest).collect();
    assert!(
        !errors.is_empty(),
        "schema accepted a corrupted emitted module inventory entry"
    );
}
