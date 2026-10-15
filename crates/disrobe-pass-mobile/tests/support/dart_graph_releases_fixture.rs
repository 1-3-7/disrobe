use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_mobile::{
    DartClusterBodyKind, DartGraphClusterSummary, DartGraphRecoveryReport, DartGraphRecoveryStatus,
    DartGraphSnapshotSummary,
};
use serde::Deserialize;

pub(crate) const FIXTURE_SET: &str = "versions";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReleaseOracle {
    pub(crate) source: String,
    pub(crate) application_library: String,
    pub(crate) known_classes: Vec<String>,
    pub(crate) known_methods: Vec<KnownMethod>,
    pub(crate) known_fields: Vec<String>,
    pub(crate) releases: Vec<Release>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KnownMethod {
    pub(crate) name: String,
    pub(crate) parameter_count: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Release {
    pub(crate) dart_version: String,
    pub(crate) dart_revision: String,
    pub(crate) flutter_version: String,
    pub(crate) engine_revision: String,
    pub(crate) snapshot_compatibility_hash: String,
    pub(crate) relabel_as: String,
    pub(crate) builds: Vec<ReleaseBuild>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReleaseBuild {
    pub(crate) name: String,
    pub(crate) artifact: String,
    pub(crate) sha256: String,
    pub(crate) features: String,
    pub(crate) cluster_report: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolchainCluster {
    pub(crate) name: String,
    pub(crate) objects: usize,
    pub(crate) allocation_offset: usize,
    pub(crate) allocation_bytes: usize,
    pub(crate) fill_offset: usize,
    pub(crate) fill_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolchainReport {
    pub(crate) vm: Vec<ToolchainCluster>,
    pub(crate) isolate: Vec<ToolchainCluster>,
}

impl ToolchainReport {
    pub(crate) fn declared(snapshot: &[ToolchainCluster], name: &str) -> usize {
        snapshot
            .iter()
            .filter(|cluster: &&ToolchainCluster| cluster.name == name)
            .map(|cluster: &ToolchainCluster| cluster.objects)
            .sum()
    }

    pub(crate) fn declared_total(&self, name: &str) -> usize {
        Self::declared(&self.vm, name) + Self::declared(&self.isolate, name)
    }
}

pub(crate) fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("mobile")
        .join("flutter")
        .join(FIXTURE_SET)
        .join(name)
}

pub(crate) fn relative(name: &str) -> String {
    format!("corpus/mobile/flutter/{FIXTURE_SET}/{name}")
}

pub(crate) fn read_tracked(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_path(name);
    let bytes: Vec<u8> = fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is tracked in this repository and every release grade is measured against it; \
             it cannot be read at {} ({error}), and a fixture that cannot be read fails rather \
             than skips. Restore it with `git checkout -- corpus/mobile/flutter/{FIXTURE_SET}` \
             or rebuild it with corpus/mobile/flutter/{FIXTURE_SET}/build.sh",
            relative(name),
            path.display()
        )
    });
    assert!(
        !bytes.is_empty(),
        "{} read back empty; a truncated fixture grades nothing",
        relative(name)
    );
    bytes
}

pub(crate) fn read_tracked_text(name: &str) -> String {
    String::from_utf8(read_tracked(name)).unwrap_or_else(|error: std::string::FromUtf8Error| {
        panic!("{} is not UTF-8 ({error})", relative(name))
    })
}

pub(crate) fn release_oracle() -> ReleaseOracle {
    let text: String = read_tracked_text("oracle.json");
    let oracle: ReleaseOracle = serde_json::from_str(&text)
        .unwrap_or_else(|error: serde_json::Error| panic!("oracle.json does not parse: {error}"));
    assert_eq!(
        oracle.releases.len(),
        9,
        "the release set pins one patch release of each Dart minor from 3.3 to 3.11"
    );
    oracle
}

pub(crate) fn release<'oracle>(
    oracle: &'oracle ReleaseOracle,
    dart_version: &str,
) -> &'oracle Release {
    oracle
        .releases
        .iter()
        .find(|release: &&Release| release.dart_version == dart_version)
        .unwrap_or_else(|| panic!("oracle.json names no Dart {dart_version} release"))
}

fn hex_field(line: &str, prefix: &str) -> Option<usize> {
    let start: usize = line.find(prefix)? + prefix.len();
    let digits: &str = line.get(start..)?.split_whitespace().next()?;
    usize::from_str_radix(digits.trim_start_matches("0x"), 16).ok()
}

fn paren_field(line: &str, after: &str) -> Option<usize> {
    let rest: &str = line.get(line.find(after)? + after.len()..)?;
    let open: usize = rest.find('(')?;
    let close: usize = rest.find(')')?;
    rest.get(open + 1..close)?.parse::<usize>().ok()
}

fn malformed(name: &str, line: &str) -> ! {
    panic!("{} has a malformed line: {line}", relative(name))
}

pub(crate) fn parse_toolchain_report(name: &str) -> ToolchainReport {
    let text: String = read_tracked_text(name);
    let mut snapshots: Vec<Vec<ToolchainCluster>> = Vec::new();
    let mut fills: usize = 0;
    let mut in_fill: bool = false;
    for line in text.lines() {
        if let Some(index) = line.find(": Alloc ") {
            if in_fill || snapshots.is_empty() {
                snapshots.push(Vec::new());
                fills = 0;
                in_fill = false;
            }
            let tail: &str = &line[index + ": Alloc ".len()..];
            let open: usize = tail.rfind(" (").unwrap_or_else(|| malformed(name, line));
            let cluster: ToolchainCluster = ToolchainCluster {
                name: tail[..open].to_owned(),
                objects: tail[open + 2..tail.len() - 1]
                    .parse::<usize>()
                    .unwrap_or_else(|_| malformed(name, line)),
                allocation_offset: hex_field(line, "Snapshot ")
                    .unwrap_or_else(|| malformed(name, line)),
                allocation_bytes: paren_field(line, "Snapshot ")
                    .unwrap_or_else(|| malformed(name, line)),
                fill_offset: 0,
                fill_bytes: 0,
            };
            snapshots
                .last_mut()
                .unwrap_or_else(|| malformed(name, line))
                .push(cluster);
        } else if let Some(index) = line.find(": Fill ") {
            in_fill = true;
            let snapshot: &mut Vec<ToolchainCluster> = snapshots
                .last_mut()
                .unwrap_or_else(|| malformed(name, line));
            let cluster: &mut ToolchainCluster = snapshot
                .get_mut(fills)
                .unwrap_or_else(|| malformed(name, line));
            assert_eq!(
                cluster.name,
                &line[index + ": Fill ".len()..],
                "{} fills clusters out of allocation order",
                relative(name)
            );
            cluster.fill_offset =
                hex_field(line, "Snapshot ").unwrap_or_else(|| malformed(name, line));
            cluster.fill_bytes =
                paren_field(line, "Snapshot ").unwrap_or_else(|| malformed(name, line));
            fills += 1;
        } else if !line.trim().is_empty() {
            malformed(name, line)
        }
    }
    assert_eq!(
        snapshots.len(),
        2,
        "{} must report the VM snapshot and then the isolate snapshot",
        relative(name)
    );
    let isolate: Vec<ToolchainCluster> = snapshots.pop().unwrap_or_default();
    let vm: Vec<ToolchainCluster> = snapshots.pop().unwrap_or_default();
    ToolchainReport { vm, isolate }
}

pub(crate) const fn toolchain_cluster_name(kind: DartClusterBodyKind) -> &'static str {
    match kind {
        DartClusterBodyKind::Array => "Array",
        DartClusterBodyKind::Class => "Class",
        DartClusterBodyKind::Closure => "Closure",
        DartClusterBodyKind::ClosureData => "ClosureData",
        DartClusterBodyKind::Code => "Code",
        DartClusterBodyKind::CodeSourceMap => "CodeSourceMap",
        DartClusterBodyKind::Double => "double",
        DartClusterBodyKind::ExceptionHandlers => "ExceptionHandlers",
        DartClusterBodyKind::Field => "Field",
        DartClusterBodyKind::Function => "Function",
        DartClusterBodyKind::FunctionType => "FunctionType",
        DartClusterBodyKind::GrowableObjectArray => "GrowableObjectArray",
        DartClusterBodyKind::Instance => "Instance",
        DartClusterBodyKind::Library => "Library",
        DartClusterBodyKind::LoadingUnit => "LoadingUnit",
        DartClusterBodyKind::Map => "Map",
        DartClusterBodyKind::Mint => "int",
        DartClusterBodyKind::ObjectPool => "ObjectPool",
        DartClusterBodyKind::PatchClass => "PatchClass",
        DartClusterBodyKind::PcDescriptors => "PcDescriptors",
        DartClusterBodyKind::Record => "Record",
        DartClusterBodyKind::RecordType => "RecordType",
        DartClusterBodyKind::Script => "Script",
        DartClusterBodyKind::Set => "Set",
        DartClusterBodyKind::String => "String",
        DartClusterBodyKind::SubtypeTestCache => "SubtypeTestCache",
        DartClusterBodyKind::Type => "Type",
        DartClusterBodyKind::TypeArguments => "TypeArguments",
        DartClusterBodyKind::TypedData => "TypedData",
        DartClusterBodyKind::TypeParameter => "TypeParameter",
        DartClusterBodyKind::TypeParameters => "TypeParameters",
        DartClusterBodyKind::UnlinkedCall => "UnlinkedCall",
        DartClusterBodyKind::WeakArray => "WeakArray",
    }
}

fn grade_snapshot(
    role: &str,
    recovered: Option<&DartGraphSnapshotSummary>,
    expected: &[ToolchainCluster],
) -> Result<(), String> {
    let summary: &DartGraphSnapshotSummary =
        recovered.ok_or_else(|| format!("no {role} snapshot was walked"))?;
    if summary.clusters.len() != expected.len() {
        return Err(format!(
            "the {role} walk read {} clusters, gen_snapshot wrote {}",
            summary.clusters.len(),
            expected.len()
        ));
    }
    for (cluster, want) in summary.clusters.iter().zip(expected) {
        let got: ToolchainCluster = measured(cluster);
        if got != *want {
            return Err(format!(
                "{role} cluster {} disagrees with gen_snapshot: walked {got:?}, wrote {want:?}",
                cluster.index
            ));
        }
    }
    Ok(())
}

fn measured(cluster: &DartGraphClusterSummary) -> ToolchainCluster {
    ToolchainCluster {
        name: toolchain_cluster_name(cluster.kind).to_owned(),
        objects: cluster.object_count,
        allocation_offset: cluster.allocation_offset,
        allocation_bytes: cluster.allocation_bytes,
        fill_offset: cluster.fill_offset,
        fill_bytes: cluster.fill_bytes,
    }
}

pub(crate) fn grade_walk(
    report: &DartGraphRecoveryReport,
    expected: &ToolchainReport,
) -> Result<(), String> {
    if report.status != DartGraphRecoveryStatus::Recovered {
        return Err(format!(
            "recovery reports {:?}: {}",
            report.status, report.name_mode_reason
        ));
    }
    grade_snapshot("vm", report.vm_snapshot.as_ref(), &expected.vm)?;
    grade_snapshot(
        "isolate",
        report.isolate_snapshot.as_ref(),
        &expected.isolate,
    )
}
