#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/pinned_dart_graph_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod pinned_dart_graph_fixture;

use std::error::Error as StdError;

use disrobe_pass_mobile::{
    DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES, DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
    DartGraphNameMode, DartGraphObfuscationHint, DartGraphRecoveryOptions, DartGraphRecoveryReport,
    DartGraphRecoveryStatus, DartPinnedClassInventory, DartPinnedFieldInventory,
    DartPinnedLibraryInventory, DartPinnedMethodInventory, Error, dart_isolate_data_bytes,
    dart_isolate_instruction_bytes, dart_vm_data_bytes, dart_vm_instruction_bytes,
    recover_dart_pinned_elf, recover_dart_pinned_standalone,
};

use pinned_dart_graph_fixture::{
    KnownMethod, RecoveryBuild, RecoveryOracle, oracle_build, read_tracked, recovery_oracle,
};

type TestResult<T = ()> = std::result::Result<T, Box<dyn StdError>>;

fn recover_fixture(
    name: &str,
    hint: DartGraphObfuscationHint,
) -> TestResult<DartGraphRecoveryReport> {
    let bytes: Vec<u8> = read_tracked(name);
    let options: DartGraphRecoveryOptions = DartGraphRecoveryOptions {
        obfuscation_hint: hint,
        ..DartGraphRecoveryOptions::default()
    };
    Ok(recover_dart_pinned_elf(&bytes, &options)?)
}

fn application_library<'report>(
    report: &'report DartGraphRecoveryReport,
    expected_url: &str,
) -> Option<&'report DartPinnedLibraryInventory> {
    report
        .inventory
        .libraries
        .iter()
        .find(|library: &&DartPinnedLibraryInventory| library.url.as_deref() == Some(expected_url))
}

fn named_class<'report>(
    library: &'report DartPinnedLibraryInventory,
    name: &str,
) -> Option<&'report DartPinnedClassInventory> {
    library
        .classes
        .iter()
        .find(|class: &&DartPinnedClassInventory| class.name.as_deref() == Some(name))
}

fn declaration_parts(value: &str) -> TestResult<(&str, &str)> {
    value
        .split_once('.')
        .ok_or_else(|| std::io::Error::other("declaration name has no owner").into())
}

#[test]
fn recovers_known_declarations_from_real_flutter_apk() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let report: DartGraphRecoveryReport =
        recover_fixture(&build.artifact, DartGraphObfuscationHint::SourceNames)?;
    assert_eq!(report.status, DartGraphRecoveryStatus::Recovered);
    assert_eq!(report.name_mode, DartGraphNameMode::Source);
    assert_eq!(
        report.snapshot_compatibility_hash,
        oracle.snapshot_compatibility_hash
    );
    assert_eq!(report.inventory.counts.classes, build.classes);
    assert_eq!(report.inventory.counts.methods, build.methods);
    assert_eq!(report.inventory.counts.fields, build.fields);

    let library: &DartPinnedLibraryInventory =
        application_library(&report, &oracle.application_library)
            .ok_or_else(|| std::io::Error::other("application library was not recovered"))?;
    let recovered_class_count: usize = build
        .known_classes
        .iter()
        .filter(|name: &&String| {
            library
                .classes
                .iter()
                .any(|class: &DartPinnedClassInventory| {
                    class.name.as_deref() == Some(name.as_str())
                })
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
            named_class(library, class_name).is_some_and(|class: &DartPinnedClassInventory| {
                class
                    .methods
                    .iter()
                    .any(|method: &DartPinnedMethodInventory| {
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
            named_class(library, class_name).is_some_and(|class: &DartPinnedClassInventory| {
                class.fields.iter().any(|field: &DartPinnedFieldInventory| {
                    field.name.as_deref() == Some(field_name)
                })
            })
        })
        .count();
    assert_eq!(recovered_field_count, build.known_fields.len());

    for expected in &build.known_methods {
        let (class_name, method_name): (&str, &str) = declaration_parts(&expected.name)?;
        let class: &DartPinnedClassInventory = named_class(library, class_name)
            .ok_or_else(|| std::io::Error::other("known class was not recovered"))?;
        let method: &DartPinnedMethodInventory = class
            .methods
            .iter()
            .find(|method: &&DartPinnedMethodInventory| method.name.as_deref() == Some(method_name))
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
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let vm_data: Vec<u8> = dart_vm_data_bytes(&bytes)?;
    let vm_instructions: Vec<u8> = dart_vm_instruction_bytes(&bytes)?;
    let isolate_data: Vec<u8> = dart_isolate_data_bytes(&bytes)?;
    let isolate_instructions: Vec<u8> = dart_isolate_instruction_bytes(&bytes)?;
    assert!(vm_data.len() > 16_000);
    assert!(isolate_data.len() > 800_000);
    let report: DartGraphRecoveryReport = recover_dart_pinned_standalone(
        &vm_data,
        &vm_instructions,
        &isolate_data,
        &isolate_instructions,
        &DartGraphRecoveryOptions::default(),
    )?;
    assert_eq!(report.status, DartGraphRecoveryStatus::Recovered);
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
    let oracle: RecoveryOracle = recovery_oracle();
    let source_build: RecoveryBuild = oracle_build(&oracle, "source");
    let renamed_build: RecoveryBuild = oracle_build(&oracle, "renamed");
    let source: DartGraphRecoveryReport = recover_fixture(
        &source_build.artifact,
        DartGraphObfuscationHint::SourceNames,
    )?;
    let renamed: DartGraphRecoveryReport = recover_fixture(
        &renamed_build.artifact,
        DartGraphObfuscationHint::SourceNames,
    )?;
    assert!(source.contains_class(&oracle.perturbation.from));
    assert!(!source.contains_class(&oracle.perturbation.to));
    assert!(!renamed.contains_class(&oracle.perturbation.from));
    assert!(renamed.contains_class(&oracle.perturbation.to));
    assert_eq!(source.inventory.counts, renamed.inventory.counts);
    Ok(())
}

#[test]
fn obfuscated_flutter_build_reports_structure_only() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "obfuscated");
    let report: DartGraphRecoveryReport =
        recover_fixture(&build.artifact, DartGraphObfuscationHint::OpaqueNames)?;
    assert_eq!(report.status, DartGraphRecoveryStatus::StructureOnly);
    assert_eq!(report.name_mode, DartGraphNameMode::Opaque);
    assert_eq!(
        report.features,
        DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES
    );
    assert_ne!(
        DART_3_12_2_ANDROID_ARM64_PRODUCT_DWARF_FEATURES,
        DART_3_12_2_ANDROID_ARM64_PRODUCT_FEATURES,
        "the dwarf and non-dwarf feature tuples must be pinned separately"
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
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "obfuscated");
    let report: DartGraphRecoveryReport =
        recover_fixture(&build.artifact, DartGraphObfuscationHint::Auto)?;
    assert_ne!(report.name_mode, DartGraphNameMode::Source);
    Ok(())
}

#[test]
fn unknown_version_returns_status_without_cluster_reads() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let mut vm_data: Vec<u8> = dart_vm_data_bytes(&bytes)?;
    let vm_instructions: Vec<u8> = dart_vm_instruction_bytes(&bytes)?;
    let mut isolate_data: Vec<u8> = dart_isolate_data_bytes(&bytes)?;
    let isolate_instructions: Vec<u8> = dart_isolate_instruction_bytes(&bytes)?;
    let unknown_hash: &[u8; 32] = b"0123456789abcdef0123456789abcdef";
    vm_data[20..52].copy_from_slice(unknown_hash);
    isolate_data[20..52].copy_from_slice(unknown_hash);
    let report: DartGraphRecoveryReport = recover_dart_pinned_standalone(
        &vm_data,
        &vm_instructions,
        &isolate_data,
        &isolate_instructions,
        &DartGraphRecoveryOptions::default(),
    )?;
    assert_eq!(report.status, DartGraphRecoveryStatus::UnsupportedVersion);
    assert_eq!(report.name_mode, DartGraphNameMode::Unavailable);
    assert!(report.vm_snapshot.is_none());
    assert!(report.isolate_snapshot.is_none());
    assert_eq!(report.inventory.counts.classes, 0);
    Ok(())
}

#[test]
fn unknown_feature_tuple_returns_status_without_cluster_reads() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let mut vm_data: Vec<u8> = dart_vm_data_bytes(&bytes)?;
    let vm_instructions: Vec<u8> = dart_vm_instruction_bytes(&bytes)?;
    let mut isolate_data: Vec<u8> = dart_isolate_data_bytes(&bytes)?;
    let isolate_instructions: Vec<u8> = dart_isolate_instruction_bytes(&bytes)?;
    let vm_feature_last: usize = feature_string_last_byte(&vm_data)?;
    let isolate_feature_last: usize = feature_string_last_byte(&isolate_data)?;
    vm_data[vm_feature_last] = b'x';
    isolate_data[isolate_feature_last] = b'x';
    let report: DartGraphRecoveryReport = recover_dart_pinned_standalone(
        &vm_data,
        &vm_instructions,
        &isolate_data,
        &isolate_instructions,
        &DartGraphRecoveryOptions::default(),
    )?;
    assert_eq!(report.status, DartGraphRecoveryStatus::UnsupportedFeatures);
    assert!(report.vm_snapshot.is_none());
    assert!(report.isolate_snapshot.is_none());
    Ok(())
}

fn feature_string_last_byte(bytes: &[u8]) -> TestResult<usize> {
    const FIXED_HEADER_SIZE: usize = 52;
    let terminator: usize = bytes
        .get(FIXED_HEADER_SIZE..)
        .and_then(|region: &[u8]| region.iter().position(|value: &u8| *value == 0))
        .ok_or_else(|| std::io::Error::other("feature string has no terminator"))?;
    terminator
        .checked_sub(1)
        .map(|offset: usize| offset.saturating_add(FIXED_HEADER_SIZE))
        .ok_or_else(|| std::io::Error::other("feature string is empty").into())
}

#[test]
fn cluster_limit_stops_real_snapshot_before_allocation() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let mut options: DartGraphRecoveryOptions = DartGraphRecoveryOptions::default();
    options.limits.clusters = 1;
    let error: Error = recover_dart_pinned_elf(&bytes, &options)
        .err()
        .ok_or_else(|| std::io::Error::other("cluster limit accepted the fixture"))?;
    assert!(matches!(
        error,
        Error::DartGraphLimitExceeded {
            resource: "clusters",
            ..
        }
    ));
    Ok(())
}

#[test]
fn configured_limits_cannot_exceed_hard_ceiling() -> TestResult {
    let oracle: RecoveryOracle = recovery_oracle();
    let build: RecoveryBuild = oracle_build(&oracle, "source");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let mut options: DartGraphRecoveryOptions = DartGraphRecoveryOptions::default();
    options.limits.objects = 2_000_001;
    let error: Error = recover_dart_pinned_elf(&bytes, &options)
        .err()
        .ok_or_else(|| std::io::Error::other("oversized configured limit was accepted"))?;
    assert!(matches!(
        error,
        Error::DartGraphConfiguredLimitExceeded {
            resource: "configured objects",
            actual: 2_000_001,
            limit: 2_000_000
        }
    ));
    Ok(())
}
