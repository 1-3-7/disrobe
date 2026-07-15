use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_dart::{
    ClassInventory, DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES,
    DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH, DartBlobKind, Error, FieldInventory, LibraryInventory,
    MethodInventory, NameMode, ObfuscationHint, RecoveryOptions, RecoveryReport, RecoveryStatus,
    SnapshotBlob, SnapshotHeader, locate_snapshot_blobs, parse_snapshot_header, recover_elf,
    recover_standalone,
};
use serde::Deserialize;

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

#[derive(Debug, Clone, Deserialize)]
struct RecoveryOracle {
    snapshot_compatibility_hash: String,
    application_library: String,
    perturbation: Perturbation,
    builds: Vec<RecoveryBuild>,
}

#[derive(Debug, Clone, Deserialize)]
struct Perturbation {
    from: String,
    to: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RecoveryBuild {
    name: String,
    artifact: String,
    classes: usize,
    methods: usize,
    fields: usize,
    #[serde(default)]
    known_classes: Vec<String>,
    #[serde(default)]
    known_methods: Vec<KnownMethod>,
    #[serde(default)]
    known_fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct KnownMethod {
    name: String,
    parameter_count: Option<usize>,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("flutter_3_44_6")
        .join(name)
}

fn recover_fixture(name: &str, hint: ObfuscationHint) -> TestResult<RecoveryReport> {
    let bytes: Vec<u8> = fs::read(fixture(name))?;
    let options: RecoveryOptions = RecoveryOptions {
        obfuscation_hint: hint,
        ..RecoveryOptions::default()
    };
    Ok(recover_elf(&bytes, &options)?)
}

fn recovery_oracle() -> TestResult<RecoveryOracle> {
    let bytes: Vec<u8> = fs::read(fixture("oracle.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn oracle_build(oracle: &RecoveryOracle, name: &str) -> TestResult<RecoveryBuild> {
    oracle
        .builds
        .iter()
        .find(|build: &&RecoveryBuild| build.name == name)
        .cloned()
        .ok_or_else(|| std::io::Error::other("oracle build is absent").into())
}

fn application_library<'report>(
    report: &'report RecoveryReport,
    expected_url: &str,
) -> Option<&'report LibraryInventory> {
    report
        .inventory
        .libraries
        .iter()
        .find(|library: &&LibraryInventory| library.url.as_deref() == Some(expected_url))
}

fn named_class<'report>(
    library: &'report LibraryInventory,
    name: &str,
) -> Option<&'report ClassInventory> {
    library
        .classes
        .iter()
        .find(|class: &&ClassInventory| class.name.as_deref() == Some(name))
}

fn required_blob<'data>(
    blobs: &BTreeMap<DartBlobKind, SnapshotBlob<'data>>,
    kind: DartBlobKind,
) -> TestResult<SnapshotBlob<'data>> {
    blobs
        .get(&kind)
        .copied()
        .ok_or_else(|| std::io::Error::other("required snapshot blob is absent").into())
}

fn declaration_parts(value: &str) -> TestResult<(&str, &str)> {
    value
        .split_once('.')
        .ok_or_else(|| std::io::Error::other("declaration name has no owner").into())
}

#[test]
fn recovers_known_declarations_from_real_flutter_apk() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let report: RecoveryReport = recover_fixture(&build.artifact, ObfuscationHint::SourceNames)?;
    assert_eq!(report.status, RecoveryStatus::Recovered);
    assert_eq!(report.name_mode, NameMode::Source);
    assert_eq!(
        report.snapshot_compatibility_hash,
        oracle.snapshot_compatibility_hash
    );
    assert_eq!(
        report.snapshot_compatibility_hash,
        DART_3_12_2_SNAPSHOT_COMPATIBILITY_HASH
    );
    assert_eq!(report.inventory.counts.classes, build.classes);
    assert_eq!(report.inventory.counts.methods, build.methods);
    assert_eq!(report.inventory.counts.fields, build.fields);

    let library: &LibraryInventory = application_library(&report, &oracle.application_library)
        .ok_or_else(|| std::io::Error::other("application library was not recovered"))?;
    let recovered_class_count: usize = build
        .known_classes
        .iter()
        .filter(|name: &&String| {
            library
                .classes
                .iter()
                .any(|class: &ClassInventory| class.name.as_deref() == Some(name.as_str()))
        })
        .count();
    assert_eq!(recovered_class_count, build.known_classes.len());

    let recovered_method_count: usize = build
        .known_methods
        .iter()
        .filter(|expected: &&KnownMethod| {
            let Some((class_name, method_name)) = expected.name.split_once('.') else {
                return false;
            };
            named_class(library, class_name).is_some_and(|class: &ClassInventory| {
                class.methods.iter().any(|method: &MethodInventory| {
                    method.name.as_deref() == Some(method_name)
                        && method.parameter_count == expected.parameter_count
                })
            })
        })
        .count();
    assert_eq!(recovered_method_count, build.known_methods.len());

    let recovered_field_count: usize = build
        .known_fields
        .iter()
        .filter(|expected: &&String| {
            let Some((class_name, field_name)) = expected.split_once('.') else {
                return false;
            };
            named_class(library, class_name).is_some_and(|class: &ClassInventory| {
                class
                    .fields
                    .iter()
                    .any(|field: &FieldInventory| field.name.as_deref() == Some(field_name))
            })
        })
        .count();
    assert_eq!(recovered_field_count, build.known_fields.len());

    for expected in &build.known_methods {
        let (class_name, method_name): (&str, &str) = declaration_parts(&expected.name)?;
        let class: &ClassInventory = named_class(library, class_name)
            .ok_or_else(|| std::io::Error::other("known class was not recovered"))?;
        let method: &MethodInventory = class
            .methods
            .iter()
            .find(|method: &&MethodInventory| method.name.as_deref() == Some(method_name))
            .ok_or_else(|| std::io::Error::other("known method was not recovered"))?;
        assert_eq!(method.parameter_count, expected.parameter_count);
        let expected_signature: Option<String> = expected.parameter_count.map(|count: usize| {
            if count == 1 {
                "(1 parameter)".to_owned()
            } else {
                format!("({count} parameters)")
            }
        });
        assert_eq!(method.signature.as_deref(), expected_signature.as_deref());
    }
    Ok(())
}

#[test]
fn recovers_supported_standalone_snapshot_blobs() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let bytes: Vec<u8> = fs::read(fixture(&build.artifact))?;
    let blobs: BTreeMap<DartBlobKind, SnapshotBlob<'_>> = locate_snapshot_blobs(&bytes)?;
    let vm_data: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmData)?;
    let vm_instructions: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmInstructions)?;
    let isolate_data: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::IsolateData)?;
    let isolate_instructions: SnapshotBlob<'_> =
        required_blob(&blobs, DartBlobKind::IsolateInstructions)?;
    let report: RecoveryReport = recover_standalone(
        vm_data.bytes,
        vm_instructions.bytes,
        isolate_data.bytes,
        isolate_instructions.bytes,
        &RecoveryOptions::default(),
    )?;
    assert_eq!(report.status, RecoveryStatus::Recovered);
    assert_eq!(
        report.snapshot_compatibility_hash,
        oracle.snapshot_compatibility_hash
    );
    for expected in &build.known_classes {
        assert!(report.contains_class(expected));
    }
    for expected in &build.known_methods {
        let (_owner, name): (&str, &str) = declaration_parts(&expected.name)?;
        assert!(report.contains_method(name));
    }
    for expected in &build.known_fields {
        let (_owner, name): (&str, &str) = declaration_parts(expected)?;
        assert!(report.contains_field(name));
    }
    Ok(())
}

#[test]
fn class_rename_changes_recovered_snapshot_inventory() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let source_build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let renamed_build: RecoveryBuild = oracle_build(&oracle, "renamed")?;
    let source: RecoveryReport =
        recover_fixture(&source_build.artifact, ObfuscationHint::SourceNames)?;
    let renamed: RecoveryReport =
        recover_fixture(&renamed_build.artifact, ObfuscationHint::SourceNames)?;
    assert!(source.contains_class(&oracle.perturbation.from));
    assert!(!source.contains_class(&oracle.perturbation.to));
    assert!(!renamed.contains_class(&oracle.perturbation.from));
    assert!(renamed.contains_class(&oracle.perturbation.to));
    assert_eq!(source.inventory.counts, renamed.inventory.counts);
    Ok(())
}

#[test]
fn obfuscated_flutter_build_reports_structure_only() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "obfuscated")?;
    let report: RecoveryReport = recover_fixture(&build.artifact, ObfuscationHint::OpaqueNames)?;
    assert_eq!(report.status, RecoveryStatus::StructureOnly);
    assert_eq!(report.name_mode, NameMode::Opaque);
    assert_eq!(
        report.features,
        DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES
    );
    assert_eq!(report.inventory.counts.classes, build.classes);
    assert_eq!(report.inventory.counts.methods, build.methods);
    assert_eq!(report.inventory.counts.fields, build.fields);
    assert!(!report.inventory.libraries.is_empty());
    assert!(!report.warnings.is_empty());
    Ok(())
}

#[test]
fn obfuscated_auto_mode_never_claims_source_names() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "obfuscated")?;
    let report: RecoveryReport = recover_fixture(&build.artifact, ObfuscationHint::Auto)?;
    assert_ne!(report.name_mode, NameMode::Source);
    Ok(())
}

#[test]
fn unknown_version_returns_status_without_cluster_reads() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let bytes: Vec<u8> = fs::read(fixture(&build.artifact))?;
    let blobs: BTreeMap<DartBlobKind, SnapshotBlob<'_>> = locate_snapshot_blobs(&bytes)?;
    let vm_blob: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmData)?;
    let vm_instructions: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmInstructions)?;
    let isolate_blob: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::IsolateData)?;
    let isolate_instructions: SnapshotBlob<'_> =
        required_blob(&blobs, DartBlobKind::IsolateInstructions)?;
    let mut vm_data: Vec<u8> = vm_blob.bytes.to_vec();
    let mut isolate_data: Vec<u8> = isolate_blob.bytes.to_vec();
    let unknown_hash: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    vm_data[20..52].copy_from_slice(unknown_hash);
    isolate_data[20..52].copy_from_slice(unknown_hash);
    let report: RecoveryReport = recover_standalone(
        &vm_data,
        vm_instructions.bytes,
        &isolate_data,
        isolate_instructions.bytes,
        &RecoveryOptions::default(),
    )?;
    assert_eq!(report.status, RecoveryStatus::UnsupportedVersion);
    assert_eq!(report.name_mode, NameMode::Unavailable);
    assert!(report.vm_snapshot.is_none());
    assert!(report.isolate_snapshot.is_none());
    assert_eq!(report.inventory.counts.classes, 0);
    Ok(())
}

#[test]
fn unknown_feature_tuple_returns_status_without_cluster_reads() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let bytes: Vec<u8> = fs::read(fixture(&build.artifact))?;
    let blobs: BTreeMap<DartBlobKind, SnapshotBlob<'_>> = locate_snapshot_blobs(&bytes)?;
    let vm_blob: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmData)?;
    let vm_instructions: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::VmInstructions)?;
    let isolate_blob: SnapshotBlob<'_> = required_blob(&blobs, DartBlobKind::IsolateData)?;
    let isolate_instructions: SnapshotBlob<'_> =
        required_blob(&blobs, DartBlobKind::IsolateInstructions)?;
    let mut vm_data: Vec<u8> = vm_blob.bytes.to_vec();
    let mut isolate_data: Vec<u8> = isolate_blob.bytes.to_vec();
    let vm_header: SnapshotHeader = parse_snapshot_header(&vm_data)?;
    let isolate_header: SnapshotHeader = parse_snapshot_header(&isolate_data)?;
    let vm_last: usize = vm_header
        .clustered_offset
        .checked_sub(2)
        .ok_or_else(|| std::io::Error::other("VM feature string is empty"))?;
    let isolate_last: usize = isolate_header
        .clustered_offset
        .checked_sub(2)
        .ok_or_else(|| std::io::Error::other("isolate feature string is empty"))?;
    vm_data[vm_last] = b'x';
    isolate_data[isolate_last] = b'x';
    let report: RecoveryReport = recover_standalone(
        &vm_data,
        vm_instructions.bytes,
        &isolate_data,
        isolate_instructions.bytes,
        &RecoveryOptions::default(),
    )?;
    assert_eq!(report.status, RecoveryStatus::UnsupportedFeatures);
    assert!(report.vm_snapshot.is_none());
    assert!(report.isolate_snapshot.is_none());
    Ok(())
}

#[test]
fn cluster_limit_stops_real_snapshot_before_allocation() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let bytes: Vec<u8> = fs::read(fixture(&build.artifact))?;
    let mut options: RecoveryOptions = RecoveryOptions::default();
    options.limits.clusters = 1;
    let error: Error = recover_elf(&bytes, &options)
        .err()
        .ok_or_else(|| std::io::Error::other("cluster limit accepted the fixture"))?;
    assert!(matches!(
        error,
        Error::LimitExceeded {
            resource: "clusters",
            ..
        }
    ));
    Ok(())
}

#[test]
fn configured_limits_cannot_exceed_hard_ceiling() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle()?;
    let build: RecoveryBuild = oracle_build(&oracle, "source")?;
    let bytes: Vec<u8> = fs::read(fixture(&build.artifact))?;
    let mut options: RecoveryOptions = RecoveryOptions::default();
    options.limits.objects = 2_000_001;
    let error: Error = recover_elf(&bytes, &options)
        .err()
        .ok_or_else(|| std::io::Error::other("oversized configured limit was accepted"))?;
    assert!(matches!(
        error,
        Error::LimitExceeded {
            resource: "configured objects",
            actual: 2_000_001,
            limit: 2_000_000
        }
    ));
    Ok(())
}
