#![allow(clippy::panic, clippy::unwrap_used)]

#[path = "support/fixture_manifest.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod fixture_manifest;

use disrobe_dart::{
    ClusterLayout, ClusterSummary, DeclaredObjects, LibraryInventory, RecoveryOptions,
    RecoveryReport, SnapshotSummary, recover_elf,
};

use fixture_manifest::{
    CountsProvenance, DeclaredSnapshot, RecoveryBuild, RecoveryOracle, read_tracked,
    recovery_oracle, relative,
};

fn recover(build: &RecoveryBuild) -> RecoveryReport {
    let bytes: Vec<u8> = read_tracked(&build.artifact);
    let options: RecoveryOptions = RecoveryOptions {
        obfuscation_hint: build.names.hint(),
        ..RecoveryOptions::default()
    };
    recover_elf(&bytes, &options).unwrap_or_else(|error: disrobe_dart::Error| {
        panic!(
            "{} does not recover ({error}); a fixture that stops parsing grades nothing and is \
             never a skip",
            relative(&build.artifact)
        )
    })
}

fn required_summary<'report>(
    summary: Option<&'report SnapshotSummary>,
    role: &str,
    artifact: &str,
) -> &'report SnapshotSummary {
    summary.unwrap_or_else(|| {
        panic!(
            "{} reports no {role} snapshot summary, so there are no cluster headers to count \
             against and every comparison below would hold over nothing",
            relative(artifact)
        )
    })
}

fn cluster_objects(summary: &SnapshotSummary, layout: ClusterLayout) -> usize {
    summary
        .clusters
        .iter()
        .filter(|cluster: &&ClusterSummary| cluster.layout == layout)
        .fold(0_usize, |total: usize, cluster: &ClusterSummary| {
            total.saturating_add(cluster.object_count)
        })
}

fn measured_declaration(summary: &SnapshotSummary) -> DeclaredSnapshot {
    DeclaredSnapshot {
        objects: summary.total_objects,
        base_objects: summary.base_objects,
        libraries: cluster_objects(summary, ClusterLayout::Library),
        classes: cluster_objects(summary, ClusterLayout::Class),
        patch_classes: cluster_objects(summary, ClusterLayout::PatchClass),
        functions: cluster_objects(summary, ClusterLayout::Function),
        fields: cluster_objects(summary, ClusterLayout::Field),
    }
}

const fn declared_across_snapshots(build: &RecoveryBuild) -> DeclaredObjects {
    let vm: DeclaredSnapshot = build.declared.vm;
    let isolate: DeclaredSnapshot = build.declared.isolate;
    DeclaredObjects {
        libraries: vm.libraries.saturating_add(isolate.libraries),
        classes: vm.classes.saturating_add(isolate.classes),
        patch_classes: vm.patch_classes.saturating_add(isolate.patch_classes),
        functions: vm.functions.saturating_add(isolate.functions),
        fields: vm.fields.saturating_add(isolate.fields),
    }
}

#[test]
fn cluster_headers_declare_the_pinned_object_totals() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        let report: RecoveryReport = recover(build);
        for (role, summary, pinned) in [
            ("vm", report.vm_snapshot.as_ref(), build.declared.vm),
            (
                "isolate",
                report.isolate_snapshot.as_ref(),
                build.declared.isolate,
            ),
        ] {
            let summary: &SnapshotSummary = required_summary(summary, role, &build.artifact);
            assert!(
                summary.cluster_count > 0,
                "the {role} snapshot of {} declares zero clusters, so summing its headers would \
                 agree with any inventory at all",
                relative(&build.artifact)
            );
            let clustered: usize = summary
                .clusters
                .iter()
                .fold(0_usize, |total: usize, cluster: &ClusterSummary| {
                    total.saturating_add(cluster.object_count)
                });
            assert_eq!(
                clustered,
                pinned.clustered_objects(),
                "the {role} cluster headers of {} account for {clustered} objects, but the \
                 snapshot declares {} objects above {} base objects; the per-cluster totals only \
                 pin anything while they add up to the declared total",
                relative(&build.artifact),
                pinned.objects,
                pinned.base_objects
            );
            assert_eq!(
                measured_declaration(summary),
                pinned,
                "the {role} cluster headers of {} do not declare the totals oracle.json pins for \
                 it; correct the pin only after measuring the snapshot, never the other way round",
                relative(&build.artifact)
            );
        }
    }
}

#[test]
fn inventory_walk_reaches_every_declaration_the_snapshot_declares() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        let report: RecoveryReport = recover(build);
        let declared: DeclaredObjects = report.inventory.declared;
        assert_eq!(
            declared,
            declared_across_snapshots(build),
            "the declaration totals {} reports do not match the per-snapshot cluster header totals \
             oracle.json pins",
            relative(&build.artifact)
        );
        assert!(
            declared.classes > 0 && declared.functions > 0 && declared.fields > 0,
            "{} declares no classes, functions or fields, so every identity below would hold at \
             zero",
            relative(&build.artifact)
        );
        assert_eq!(
            report.inventory.residue,
            build.attribution_residue,
            "the objects {} could not attach to an owner are not the ones oracle.json pins",
            relative(&build.artifact)
        );
        let residue: disrobe_dart::AttributionResidue = report.inventory.residue;
        assert_eq!(
            report
                .inventory
                .counts
                .classes
                .saturating_add(residue.unattributed_classes),
            declared.classes,
            "{} attaches {} classes and drops {}, which does not account for the {} the cluster \
             headers declare; a walk that stops early loses classes here",
            relative(&build.artifact),
            report.inventory.counts.classes,
            residue.unattributed_classes,
            declared.classes
        );
        assert_eq!(
            report
                .inventory
                .counts
                .methods
                .saturating_add(residue.unattributed_methods),
            declared.functions,
            "{} attaches {} methods and drops {}, which does not account for the {} functions the \
             cluster headers declare; a walk that stops early loses methods here",
            relative(&build.artifact),
            report.inventory.counts.methods,
            residue.unattributed_methods,
            declared.functions
        );
        assert_eq!(
            report
                .inventory
                .counts
                .fields
                .saturating_add(residue.unattributed_fields),
            declared.fields,
            "{} attaches {} fields and drops {}, which does not account for the {} the cluster \
             headers declare; a walk that stops early loses fields here",
            relative(&build.artifact),
            report.inventory.counts.fields,
            residue.unattributed_fields,
            declared.fields
        );
        assert_eq!(
            report.inventory.counts.libraries,
            declared
                .libraries
                .saturating_add(residue.synthesized_libraries),
            "{} reports {} libraries, which is not the {} the cluster headers declare plus the {} \
             the walk opens for classes with no library object",
            relative(&build.artifact),
            report.inventory.counts.libraries,
            declared.libraries,
            residue.synthesized_libraries
        );
    }
}

#[test]
fn the_only_unattributable_function_is_the_one_the_vm_snapshot_declares() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        let report: RecoveryReport = recover(build);
        let vm: DeclaredSnapshot = build.declared.vm;
        assert_eq!(
            vm.classes,
            0,
            "the VM snapshot of {} now declares classes, so a VM function can carry a real owner \
             and the residue below no longer follows from the snapshot layout",
            relative(&build.artifact)
        );
        assert_eq!(
            vm.patch_classes,
            0,
            "the VM snapshot of {} now declares patch classes, so a VM function owner can resolve \
             through one and the residue below no longer follows from the snapshot layout",
            relative(&build.artifact)
        );
        assert_eq!(
            build.declared.isolate.base_objects,
            vm.objects,
            "the isolate snapshot of {} does not start allocating above the VM object range, so a \
             VM function reference could reach an isolate class and the residue below would not \
             follow",
            relative(&build.artifact)
        );
        assert_eq!(
            report.inventory.residue.unattributed_methods,
            vm.functions,
            "{} drops {} functions, but the VM snapshot declares {}; every isolate function has an \
             owner to attach to, so any other dropped function is a gap in the walk",
            relative(&build.artifact),
            report.inventory.residue.unattributed_methods,
            vm.functions
        );
    }
}

#[test]
fn library_entries_without_a_url_are_exactly_the_synthesized_ones() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        let report: RecoveryReport = recover(build);
        let backed: usize = report
            .inventory
            .libraries
            .iter()
            .filter(|library: &&LibraryInventory| library.url.is_some())
            .count();
        let synthesized: usize = report
            .inventory
            .libraries
            .iter()
            .filter(|library: &&LibraryInventory| library.url.is_none())
            .count();
        assert_eq!(
            backed,
            report.inventory.declared.libraries,
            "{} recovers {backed} libraries carrying a url, but the cluster headers declare {} \
             library objects",
            relative(&build.artifact),
            report.inventory.declared.libraries
        );
        assert_eq!(
            synthesized,
            report.inventory.residue.synthesized_libraries,
            "{} holds {synthesized} library entries with no url, which is not the {} the walk \
             reports opening for classes with no library object",
            relative(&build.artifact),
            report.inventory.residue.synthesized_libraries
        );
    }
}

#[test]
fn pinned_inventory_counts_match_the_recovered_inventory() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        let report: RecoveryReport = recover(build);
        assert_eq!(
            report.inventory.counts.libraries,
            build.libraries,
            "{} recovers a different library count than oracle.json pins",
            relative(&build.artifact)
        );
        assert_eq!(
            report.inventory.counts.classes,
            build.classes,
            "{} recovers a different class count than oracle.json pins",
            relative(&build.artifact)
        );
        assert_eq!(
            report.inventory.counts.methods,
            build.methods,
            "{} recovers a different method count than oracle.json pins",
            relative(&build.artifact)
        );
        assert_eq!(
            report.inventory.counts.fields,
            build.fields,
            "{} recovers a different field count than oracle.json pins",
            relative(&build.artifact)
        );
    }
}

#[test]
fn the_manifest_records_where_the_counts_come_from() {
    let oracle: RecoveryOracle = recovery_oracle();
    let provenance: CountsProvenance = oracle.counts_provenance;
    assert!(
        !provenance.summary.trim().is_empty(),
        "{} carries pinned counts with no recorded derivation; a count whose origin is not written \
         down is one nobody can re-derive",
        relative("oracle.json")
    );
    assert!(
        !provenance.toolchain_alternative.trim().is_empty(),
        "{} does not record what a toolchain-side count would take, so a reader cannot tell \
         whether one was available",
        relative("oracle.json")
    );
    assert!(
        provenance.derivation.len() >= 3,
        "{} records {} derivation steps; the walk, the cluster headers and the residue each need \
         one",
        relative("oracle.json"),
        provenance.derivation.len()
    );
    for step in &provenance.derivation {
        assert!(
            !step.trim().is_empty(),
            "{} records an empty derivation step",
            relative("oracle.json")
        );
    }
}
