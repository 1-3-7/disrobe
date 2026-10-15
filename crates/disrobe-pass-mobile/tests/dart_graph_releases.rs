#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/dart_graph_releases_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod dart_graph_releases_fixture;

use disrobe_pass_mobile::flutter::{DartSdkRelease, dart_sdk_releases};
use disrobe_pass_mobile::{
    DartGraphObfuscationHint, DartGraphRecoveryOptions, DartGraphRecoveryReport,
    DartPinnedClassInventory, DartPinnedFieldInventory, DartPinnedLibraryInventory,
    DartPinnedMethodInventory, Error, dart_isolate_data_bytes, dart_isolate_instruction_bytes,
    dart_vm_data_bytes, dart_vm_instruction_bytes, recover_dart_pinned_elf,
    recover_dart_pinned_standalone,
};
use sha2::{Digest as _, Sha256};

use dart_graph_releases_fixture::{
    Release, ReleaseBuild, ReleaseOracle, ToolchainCluster, ToolchainReport, grade_walk,
    parse_toolchain_report, read_tracked, read_tracked_text, relative, release, release_oracle,
};

const FEATURES_OFFSET: usize = 52;

fn options() -> DartGraphRecoveryOptions {
    DartGraphRecoveryOptions {
        obfuscation_hint: DartGraphObfuscationHint::SourceNames,
        ..DartGraphRecoveryOptions::default()
    }
}

fn recover(build: &ReleaseBuild) -> DartGraphRecoveryReport {
    recover_dart_pinned_elf(&read_tracked(&build.artifact), &options()).unwrap_or_else(
        |error: Error| {
            panic!(
                "{} does not recover ({error}); a fixture that stops parsing grades nothing",
                relative(&build.artifact)
            )
        },
    )
}

fn builds(oracle: &ReleaseOracle) -> impl Iterator<Item = (&Release, &ReleaseBuild)> {
    oracle.releases.iter().flat_map(|release: &Release| {
        release
            .builds
            .iter()
            .map(move |build: &ReleaseBuild| (release, build))
    })
}

#[test]
fn release_fixtures_match_their_build_records() {
    let oracle: ReleaseOracle = release_oracle();
    let source: String = read_tracked_text(&oracle.source);
    for name in &oracle.known_classes {
        assert!(source.contains(&format!("class {name} ")));
    }
    for (release, build) in builds(&oracle) {
        let digest: String = format!("{:x}", Sha256::digest(read_tracked(&build.artifact)));
        assert_eq!(
            digest,
            build.sha256,
            "{} is not the file its build record describes",
            relative(&build.artifact)
        );
        let report: DartGraphRecoveryReport = recover(build);
        assert_eq!(
            report.snapshot_compatibility_hash,
            release.snapshot_compatibility_hash
        );
        assert_eq!(report.features, build.features);
        let releases: Vec<DartSdkRelease> = dart_sdk_releases(&report.snapshot_compatibility_hash);
        assert!(
            releases.iter().any(|candidate: &DartSdkRelease| {
                candidate.dart_version == release.dart_version
                    && candidate.dart_revision == release.dart_revision
            }),
            "the bundled snapshot hash table does not attribute {} to Dart {}",
            relative(&build.artifact),
            release.dart_version
        );
        assert_eq!(release.engine_revision.len(), 40);
        assert!(release.flutter_version.starts_with("3."));
    }
}

#[test]
fn cluster_walk_matches_gen_snapshot_on_every_release() {
    let oracle: ReleaseOracle = release_oracle();
    for (release, build) in builds(&oracle) {
        let expected: ToolchainReport = parse_toolchain_report(&build.cluster_report);
        assert!(expected.vm.len() > 4 && expected.isolate.len() > 30);
        let report: DartGraphRecoveryReport = recover(build);
        if let Err(reason) = grade_walk(&report, &expected) {
            panic!(
                "Dart {} {}: {reason}",
                release.dart_version,
                relative(&build.artifact)
            );
        }
    }
}

#[test]
fn inventory_accounts_for_every_declaration_gen_snapshot_wrote() {
    let oracle: ReleaseOracle = release_oracle();
    for (release, build) in builds(&oracle) {
        let expected: ToolchainReport = parse_toolchain_report(&build.cluster_report);
        let report: DartGraphRecoveryReport = recover(build);
        let declared = report.inventory.declared;
        let residue = report.inventory.residue;
        let counts = &report.inventory.counts;
        let context: String = format!("Dart {} {}", release.dart_version, build.name);
        assert_eq!(
            declared.libraries,
            expected.declared_total("Library"),
            "{context}"
        );
        assert_eq!(
            declared.classes,
            expected.declared_total("Class"),
            "{context}"
        );
        assert_eq!(
            declared.patch_classes,
            expected.declared_total("PatchClass"),
            "{context}"
        );
        assert_eq!(
            declared.functions,
            expected.declared_total("Function"),
            "{context}"
        );
        assert_eq!(
            declared.fields,
            expected.declared_total("Field"),
            "{context}"
        );
        assert!(
            declared.classes > 400 && declared.functions > 400,
            "{context}"
        );
        assert_eq!(
            counts.classes + residue.unattributed_classes,
            declared.classes,
            "{context}"
        );
        assert_eq!(
            counts.methods + residue.unattributed_methods,
            declared.functions,
            "{context}"
        );
        assert_eq!(
            counts.fields + residue.unattributed_fields,
            declared.fields,
            "{context}"
        );
        assert_eq!(
            counts.libraries,
            declared.libraries + residue.synthesized_libraries,
            "{context}"
        );
        assert_eq!(
            ToolchainReport::declared(&expected.vm, "Function"),
            residue.unattributed_methods,
            "{context}: the only unattributed functions are the VM snapshot's, which no class \
             in that snapshot owns"
        );
        assert_eq!(
            residue.synthesized_libraries, 1,
            "{context}: the one library no Library object backs is the Never class's null \
             library reference"
        );
        assert_eq!(residue.unattributed_classes, 0, "{context}");
        assert_eq!(residue.unattributed_fields, 0, "{context}");
        assert_eq!(counts.named_classes, counts.classes, "{context}");
        assert_eq!(counts.named_methods, counts.methods, "{context}");
        assert_eq!(counts.named_fields, counts.fields, "{context}");
    }
}

fn application_library<'report>(
    report: &'report DartGraphRecoveryReport,
    url: &str,
) -> &'report DartPinnedLibraryInventory {
    report
        .inventory
        .libraries
        .iter()
        .find(|library: &&DartPinnedLibraryInventory| library.url.as_deref() == Some(url))
        .unwrap_or_else(|| panic!("the application library {url} was not recovered"))
}

fn named_class<'library>(
    library: &'library DartPinnedLibraryInventory,
    name: &str,
) -> &'library DartPinnedClassInventory {
    library
        .classes
        .iter()
        .find(|class: &&DartPinnedClassInventory| class.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("class {name} was not recovered"))
}

#[test]
fn recovers_the_source_declarations_on_every_release() {
    let oracle: ReleaseOracle = release_oracle();
    for (release, build) in builds(&oracle) {
        let report: DartGraphRecoveryReport = recover(build);
        let library: &DartPinnedLibraryInventory =
            application_library(&report, &oracle.application_library);
        for name in &oracle.known_classes {
            let _class: &DartPinnedClassInventory = named_class(library, name);
        }
        for expected in &oracle.known_methods {
            let (owner, member): (&str, &str) =
                expected.name.split_once('.').expect("owner.member");
            let class: &DartPinnedClassInventory = named_class(library, owner);
            assert!(
                class
                    .methods
                    .iter()
                    .any(|method: &DartPinnedMethodInventory| {
                        method.name.as_deref() == Some(member)
                            && method.parameter_count == expected.parameter_count
                    }),
                "Dart {} {}: {} with {:?} parameters was not recovered",
                release.dart_version,
                build.name,
                expected.name,
                expected.parameter_count
            );
        }
        for expected in &oracle.known_fields {
            let (owner, member): (&str, &str) = expected.split_once('.').expect("owner.member");
            let class: &DartPinnedClassInventory = named_class(library, owner);
            assert!(
                class
                    .fields
                    .iter()
                    .any(|field: &DartPinnedFieldInventory| field.name.as_deref() == Some(member)),
                "Dart {} {}: field {expected} was not recovered",
                release.dart_version,
                build.name
            );
        }
    }
}

#[test]
fn a_perturbed_gen_snapshot_report_fails_the_grade() {
    let oracle: ReleaseOracle = release_oracle();
    for release in &oracle.releases {
        let build: &ReleaseBuild = &release.builds[0];
        let report: DartGraphRecoveryReport = recover(build);
        let expected: ToolchainReport = parse_toolchain_report(&build.cluster_report);
        assert!(grade_walk(&report, &expected).is_ok());
        let mutations: [fn(&mut ToolchainCluster); 3] = [
            |cluster: &mut ToolchainCluster| cluster.objects += 1,
            |cluster: &mut ToolchainCluster| cluster.fill_offset += 1,
            |cluster: &mut ToolchainCluster| cluster.name = "Instance".to_owned(),
        ];
        for mutate in mutations {
            let mut perturbed: ToolchainReport = expected.clone();
            let position: usize = perturbed
                .isolate
                .iter()
                .position(|cluster: &ToolchainCluster| cluster.name == "Field")
                .expect("a Field cluster");
            mutate(&mut perturbed.isolate[position]);
            assert!(
                grade_walk(&report, &perturbed).is_err(),
                "Dart {}: a perturbed gen_snapshot report still grades green",
                release.dart_version
            );
        }
    }
}

fn relabel(blob: &[u8], snapshot_hash: &str, features: &str) -> Vec<u8> {
    let terminator: usize = FEATURES_OFFSET
        + blob[FEATURES_OFFSET..]
            .iter()
            .position(|byte: &u8| *byte == 0)
            .expect("feature string terminator");
    let stored: i64 = i64::from_le_bytes(blob[4..12].try_into().expect("length field"));
    let old_length: i64 = i64::try_from(terminator - FEATURES_OFFSET).expect("feature length");
    let new_length: i64 = i64::try_from(features.len()).expect("feature length");
    let mut out: Vec<u8> = Vec::with_capacity(blob.len() + features.len());
    out.extend_from_slice(&blob[..4]);
    out.extend_from_slice(&(stored - old_length + new_length).to_le_bytes());
    out.extend_from_slice(&blob[12..20]);
    out.extend_from_slice(snapshot_hash.as_bytes());
    out.extend_from_slice(features.as_bytes());
    out.extend_from_slice(&blob[terminator..]);
    out
}

fn grade_relabelled(build: &ReleaseBuild, target: &Release) -> Result<(), String> {
    let target_build: &ReleaseBuild = target
        .builds
        .iter()
        .find(|candidate: &&ReleaseBuild| candidate.name == build.name)
        .expect("the relabel target has the same build kind");
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let vm_data: Vec<u8> = relabel(
        &dart_vm_data_bytes(&bytes).expect("vm data"),
        &target.snapshot_compatibility_hash,
        &target_build.features,
    );
    let isolate_data: Vec<u8> = relabel(
        &dart_isolate_data_bytes(&bytes).expect("isolate data"),
        &target.snapshot_compatibility_hash,
        &target_build.features,
    );
    let report: DartGraphRecoveryReport = recover_dart_pinned_standalone(
        &vm_data,
        &dart_vm_instruction_bytes(&bytes).expect("vm instructions"),
        &isolate_data,
        &dart_isolate_instruction_bytes(&bytes).expect("isolate instructions"),
        &options(),
    )
    .map_err(|error: Error| error.to_string())?;
    grade_walk(&report, &parse_toolchain_report(&build.cluster_report))
}

#[test]
fn a_release_relabelled_as_its_neighbour_fails_the_grade() {
    let oracle: ReleaseOracle = release_oracle();
    for (own, build) in builds(&oracle) {
        assert!(
            grade_relabelled(build, own).is_ok(),
            "Dart {} {}: rewriting the header with its own hash and features must stay green",
            own.dart_version,
            build.name
        );
        let neighbour: &Release = release(&oracle, &own.relabel_as);
        assert_ne!(neighbour.dart_version, own.dart_version);
        assert!(
            grade_relabelled(build, neighbour).is_err(),
            "Dart {} {} read with the Dart {} layout still grades green",
            own.dart_version,
            build.name,
            neighbour.dart_version
        );
    }
}
