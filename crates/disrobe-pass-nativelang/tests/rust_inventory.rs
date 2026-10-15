#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use disrobe_pass_nativelang::rust_inventory::{
    AuditableEvidence, AuditableGraph, AuditableRefusal, CrateSource, DependencyKind, PathStart,
    RecoveredCrate, RustInventory, RustInventoryError, RustcCommit, release_for_commit,
    rust_inventory, stable_releases,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CRATES_IO_INDEX_HOST: &str = "index.crates.io";
const SHORT_REVISION: usize = 7;
const MUTATIONS_PER_ARTIFACT: usize = 24;
const HEADER_WINDOW: u64 = 4096;

#[derive(Debug, Deserialize)]
struct Manifest {
    artifacts: Vec<Artifact>,
}

#[derive(Debug, Clone, Deserialize)]
struct Artifact {
    path: String,
    sha256: String,
    toolchain: String,
    container: String,
    strip: String,
    auditable: bool,
    path_crates: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Lockfile {
    package: Vec<LockPackage>,
}

#[derive(Debug, Clone, Deserialize)]
struct LockPackage {
    name: String,
    version: String,
    source: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WorkspaceManifest {
    workspace: WorkspaceTable,
}

#[derive(Debug, Deserialize)]
struct WorkspaceTable {
    members: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditInfo {
    packages: Vec<AuditInfoPackage>,
}

#[derive(Debug, Clone, Deserialize)]
struct AuditInfoPackage {
    name: String,
    version: String,
    source: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    dependencies: Vec<usize>,
    #[serde(default)]
    root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustcReference {
    commit: String,
    release: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CrateIdentity {
    name: String,
    version: Option<String>,
    kind: &'static str,
    origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SymbolReference {
    legacy: u64,
    v0: u64,
    unattributed: u64,
    crates: BTreeMap<String, (u64, u64)>,
}

struct Loaded {
    artifact: Artifact,
    bytes: Vec<u8>,
    inventory: RustInventory,
}

fn corpus(relative: &str) -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/native/rust-inventory");
    path.push(relative);
    path
}

fn read(relative: &str) -> Vec<u8> {
    let path: PathBuf = corpus(relative);
    std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn read_text(relative: &str) -> String {
    String::from_utf8(read(relative)).expect("reference text is UTF-8")
}

fn manifest() -> Manifest {
    toml::from_str(&read_text("MANIFEST.toml")).expect("MANIFEST.toml parses")
}

fn lockfile() -> Lockfile {
    toml::from_str(&read_text("source/workspace/Cargo.lock")).expect("Cargo.lock parses")
}

fn loaded() -> &'static [Loaded] {
    static LOADED: OnceLock<Vec<Loaded>> = OnceLock::new();
    LOADED.get_or_init(|| {
        manifest()
            .artifacts
            .into_iter()
            .map(|artifact: Artifact| {
                let bytes: Vec<u8> = read(&artifact.path);
                let inventory: RustInventory = rust_inventory(&bytes)
                    .unwrap_or_else(|error| panic!("{}: {error}", artifact.path));
                Loaded {
                    artifact,
                    bytes,
                    inventory,
                }
            })
            .collect()
    })
}

fn rustc_reference(toolchain: &str) -> RustcReference {
    let text: String = read_text(&format!("reference/rustc-{toolchain}.txt"));
    let field = |key: &str| -> String {
        text.lines()
            .find_map(|line: &str| line.strip_prefix(key))
            .unwrap_or_else(|| panic!("rustc -vV of {toolchain} has no {key}"))
            .trim()
            .to_owned()
    };
    RustcReference {
        commit: field("commit-hash:"),
        release: field("release:"),
    }
}

fn evidence_matches(bytes: &[u8], offset: u64, text: &str) -> bool {
    let start: usize = usize::try_from(offset).expect("offset fits usize");
    bytes.get(start..start + text.len()) == Some(text.as_bytes())
}

fn grade_rustc(
    bytes: &[u8],
    recovered: &[RustcCommit],
    reference: &RustcReference,
) -> Result<(), String> {
    let [commit] = recovered else {
        return Err(format!(
            "{} rustc commits recovered, expected one",
            recovered.len()
        ));
    };
    if commit.commit != reference.commit {
        return Err(format!(
            "commit {} != rustc -vV {}",
            commit.commit, reference.commit
        ));
    }
    if commit.release.as_deref() != Some(reference.release.as_str()) {
        return Err(format!(
            "release {:?} != rustc -vV {}",
            commit.release, reference.release
        ));
    }
    if !evidence_matches(bytes, commit.evidence.offset, &commit.evidence.text)
        || !commit
            .evidence
            .text
            .starts_with(&format!("/rustc/{}", reference.commit))
    {
        return Err(format!(
            "rustc evidence {:?} is not backed by the bytes",
            commit.evidence
        ));
    }
    Ok(())
}

fn expected_crates(names: &[String]) -> BTreeSet<CrateIdentity> {
    let lock: Lockfile = lockfile();
    let members: Vec<String> =
        toml::from_str::<WorkspaceManifest>(&read_text("source/workspace/Cargo.toml"))
            .expect("workspace manifest parses")
            .workspace
            .members;
    names
        .iter()
        .map(|name: &String| {
            let package: &LockPackage = lock
                .package
                .iter()
                .find(|package: &&LockPackage| &package.name == name)
                .unwrap_or_else(|| panic!("{name} is not in Cargo.lock"));
            match package.source.as_deref() {
                Some(CRATES_IO) => CrateIdentity {
                    name: package.name.clone(),
                    version: Some(package.version.clone()),
                    kind: "registry",
                    origin: CRATES_IO_INDEX_HOST.to_owned(),
                },
                Some(git) if git.starts_with("git+") => {
                    let (url, commit): (&str, &str) =
                        git.split_once('#').expect("git source pins a commit");
                    let repository: &str = url
                        .rsplit('/')
                        .next()
                        .expect("git url has a path")
                        .trim_end_matches(".git");
                    CrateIdentity {
                        name: package.name.clone(),
                        version: None,
                        kind: "git",
                        origin: format!("{repository}@{}", &commit[..SHORT_REVISION]),
                    }
                }
                Some(other) => panic!("unexpected lock source {other}"),
                None if members.contains(&package.name) => CrateIdentity {
                    name: package.name.clone(),
                    version: None,
                    kind: "workspace",
                    origin: package.name.clone(),
                },
                None => CrateIdentity {
                    name: package.name.clone(),
                    version: None,
                    kind: "path",
                    origin: package.name.clone(),
                },
            }
        })
        .collect()
}

fn recovered_identity(recovered: &RecoveredCrate) -> CrateIdentity {
    let name: String = recovered.name.clone().unwrap_or_default();
    let directory = |root: &str| -> String {
        root.rsplit(['/', '\\'])
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let (kind, origin): (&'static str, String) = match &recovered.source {
        CrateSource::Registry { index } => (
            "registry",
            index
                .rsplit_once('-')
                .map_or_else(String::new, |(host, _)| host.to_owned()),
        ),
        CrateSource::Git {
            repository,
            revision,
            ..
        } => ("git", format!("{repository}@{revision}")),
        CrateSource::Vendored { root } => ("vendored", directory(root)),
        CrateSource::Path { root } => ("path", directory(root)),
        CrateSource::Workspace { root } => ("workspace", directory(root)),
    };
    CrateIdentity {
        name,
        version: recovered.version.clone(),
        kind,
        origin,
    }
}

fn grade_crates(
    bytes: &[u8],
    recovered: &[RecoveredCrate],
    expected: &BTreeSet<CrateIdentity>,
) -> Result<(), String> {
    for krate in recovered {
        if !evidence_matches(bytes, krate.evidence.offset, &krate.evidence.text) {
            return Err(format!(
                "crate evidence {:?} is not backed by the bytes",
                krate.evidence
            ));
        }
    }
    let actual: BTreeSet<CrateIdentity> = recovered.iter().map(recovered_identity).collect();
    if &actual != expected {
        let missing: Vec<&CrateIdentity> = expected.difference(&actual).collect();
        let extra: Vec<&CrateIdentity> = actual.difference(expected).collect();
        return Err(format!("missing {missing:?}, unexpected {extra:?}"));
    }
    Ok(())
}

fn grade_edges(graph: &AuditableGraph, reference: &AuditInfo) -> Result<(), String> {
    if graph.packages.len() != reference.packages.len() {
        return Err(format!(
            "{} packages recovered, rust-audit-info lists {}",
            graph.packages.len(),
            reference.packages.len()
        ));
    }
    for (index, (package, expected)) in graph.packages.iter().zip(&reference.packages).enumerate() {
        let kind: DependencyKind = match expected.kind.as_deref() {
            None | Some("runtime") => DependencyKind::Runtime,
            Some("build") => DependencyKind::Build,
            Some(other) => return Err(format!("reference kind {other}")),
        };
        if package.package.name != expected.name
            || package.package.version != expected.version
            || package.package.source.as_deref() != Some(expected.source.as_str())
            || package.kind != kind
            || package.root != expected.root
        {
            return Err(format!("package {index}: {package:?} != {expected:?}"));
        }
    }
    let expected_edges: BTreeSet<(usize, usize)> = reference
        .packages
        .iter()
        .enumerate()
        .flat_map(|(from, package): (usize, &AuditInfoPackage)| {
            package
                .dependencies
                .iter()
                .map(move |to: &usize| (from, *to))
        })
        .collect();
    let actual_edges: BTreeSet<(usize, usize)> = graph
        .dependencies
        .iter()
        .map(|edge| (edge.from, edge.to))
        .collect();
    if actual_edges != expected_edges {
        return Err(format!("edges {actual_edges:?} != {expected_edges:?}"));
    }
    Ok(())
}

fn symbol_reference(relative: &str) -> SymbolReference {
    let mut reference: SymbolReference = SymbolReference::default();
    for line in read_text(relative)
        .lines()
        .filter(|line: &&str| !line.starts_with('#'))
    {
        let fields: Vec<&str> = line.split('\t').collect();
        let number = |index: usize| -> u64 { fields[index].parse().expect("count parses") };
        match fields[0] {
            "total" => {
                reference.legacy = number(1);
                reference.v0 = number(2);
                reference.unattributed = number(3);
            }
            "crate" => {
                reference
                    .crates
                    .insert(fields[1].to_owned(), (number(2), number(3)));
            }
            other => panic!("unknown reference line {other}"),
        }
    }
    reference
}

fn recovered_symbols(inventory: &RustInventory) -> SymbolReference {
    SymbolReference {
        legacy: inventory.symbols.legacy,
        v0: inventory.symbols.v0,
        unattributed: inventory.symbols.unattributed,
        crates: inventory
            .symbols
            .crates
            .iter()
            .map(|krate| (krate.name.clone(), (krate.legacy, krate.v0)))
            .collect(),
    }
}

fn grade_symbols(recovered: &SymbolReference, reference: &SymbolReference) -> Result<(), String> {
    if recovered == reference {
        return Ok(());
    }
    let differing: Vec<String> = reference
        .crates
        .keys()
        .chain(recovered.crates.keys())
        .collect::<BTreeSet<&String>>()
        .into_iter()
        .filter(|name: &&String| reference.crates.get(*name) != recovered.crates.get(*name))
        .map(|name: &String| {
            format!(
                "{name}: recovered {:?}, llvm-nm {:?}",
                recovered.crates.get(name),
                reference.crates.get(name)
            )
        })
        .collect();
    Err(format!(
        "totals recovered {}/{}/{} llvm-nm {}/{}/{}; {differing:?}",
        recovered.legacy,
        recovered.v0,
        recovered.unattributed,
        reference.legacy,
        reference.v0,
        reference.unattributed
    ))
}

fn has_symbol_reference(artifact: &Artifact) -> bool {
    artifact.strip != "symbols" && artifact.container != "pe"
}

#[test]
fn committed_artifacts_match_their_recorded_sha256() {
    for loaded in loaded() {
        let digest: String = format!("{:x}", Sha256::digest(&loaded.bytes));
        assert_eq!(digest, loaded.artifact.sha256, "{}", loaded.artifact.path);
    }
}

#[test]
fn release_table_is_ordered_unique_and_agrees_with_rustc_vv() {
    let releases: Vec<(&str, &str)> = stable_releases().collect();
    assert!(releases.len() >= 140, "{} releases", releases.len());
    assert_eq!(releases.first().map(|(version, _)| *version), Some("1.0.0"));
    let mut commits: BTreeSet<&str> = BTreeSet::new();
    let mut previous: Option<(u64, u64, u64)> = None;
    for (version, commit) in &releases {
        let parts: Vec<u64> = version
            .split('.')
            .map(|part: &str| part.parse().expect("numeric version part"))
            .collect();
        let key: (u64, u64, u64) = (parts[0], parts[1], parts[2]);
        assert!(previous < Some(key), "{version} is out of order");
        previous = Some(key);
        assert_eq!(commit.len(), 40, "{version}");
        assert!(
            commit
                .bytes()
                .all(|byte: u8| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(commits.insert(commit), "{commit} repeats");
    }
    for toolchain in ["1.95.0", "1.96.1"] {
        let reference: RustcReference = rustc_reference(toolchain);
        assert_eq!(
            release_for_commit(&reference.commit),
            Some(reference.release.as_str()),
            "{toolchain}"
        );
    }
}

#[test]
fn rustc_release_matches_rustc_vv_for_every_artifact() {
    for loaded in loaded() {
        let reference: RustcReference = rustc_reference(&loaded.artifact.toolchain);
        grade_rustc(&loaded.bytes, &loaded.inventory.rustc, &reference)
            .unwrap_or_else(|error| panic!("{}: {error}", loaded.artifact.path));
    }
}

#[test]
fn rustc_grade_turns_red_on_a_changed_release() {
    let loaded: &Loaded = &loaded()[0];
    let mut reference: RustcReference = rustc_reference(&loaded.artifact.toolchain);
    reference.release = "1.95.1".to_owned();
    assert!(grade_rustc(&loaded.bytes, &loaded.inventory.rustc, &reference).is_err());
}

#[test]
fn unknown_commit_is_reported_by_its_hash() {
    let loaded: &Loaded = loaded()
        .iter()
        .find(|loaded: &&Loaded| loaded.artifact.container == "elf")
        .expect("an ELF artifact");
    let reference: RustcReference = rustc_reference(&loaded.artifact.toolchain);
    let unknown: String = format!("{}{}", "0".repeat(8), &reference.commit[8..]);
    let mut bytes: Vec<u8> = loaded.bytes.clone();
    let needle: &[u8] = reference.commit.as_bytes();
    let mut replaced: usize = 0;
    let mut at: usize = 0;
    while let Some(position) = bytes[at..]
        .windows(needle.len())
        .position(|window: &[u8]| window == needle)
    {
        let start: usize = at + position;
        bytes[start..start + needle.len()].copy_from_slice(unknown.as_bytes());
        replaced += 1;
        at = start + needle.len();
    }
    assert!(replaced > 0);
    let inventory: RustInventory = rust_inventory(&bytes).expect("patched ELF parses");
    let [commit] = inventory.rustc.as_slice() else {
        panic!("{:?}", inventory.rustc);
    };
    assert_eq!(commit.commit, unknown);
    assert_eq!(commit.release, None);
}

#[test]
fn crates_match_cargo_lock_for_every_artifact() {
    for loaded in loaded() {
        let expected: BTreeSet<CrateIdentity> = expected_crates(&loaded.artifact.path_crates);
        grade_crates(&loaded.bytes, &loaded.inventory.crates, &expected)
            .unwrap_or_else(|error| panic!("{}: {error}", loaded.artifact.path));
    }
}

#[test]
fn crate_grade_turns_red_on_one_changed_version() {
    let loaded: &Loaded = &loaded()[0];
    let mut expected: BTreeSet<CrateIdentity> = expected_crates(&loaded.artifact.path_crates);
    let regex: CrateIdentity = expected
        .iter()
        .find(|identity: &&CrateIdentity| identity.name == "regex")
        .cloned()
        .expect("regex is expected");
    expected.remove(&regex);
    expected.insert(CrateIdentity {
        version: Some("1.12.4".to_owned()),
        ..regex
    });
    assert!(grade_crates(&loaded.bytes, &loaded.inventory.crates, &expected).is_err());
}

#[test]
fn local_crates_keep_their_whole_path() {
    for loaded in loaded() {
        let path_roots: Vec<(&str, Option<PathStart>)> = loaded
            .inventory
            .crates
            .iter()
            .filter_map(|krate: &RecoveredCrate| match &krate.source {
                CrateSource::Path { root } => Some((root.as_str(), krate.path_start)),
                _ => None,
            })
            .collect();
        assert_eq!(
            path_roots,
            vec![("/build\\pathdep", Some(PathStart::LocationRecord))],
            "{}",
            loaded.artifact.path
        );
        let workspace_roots: Vec<&str> = loaded
            .inventory
            .crates
            .iter()
            .filter_map(|krate: &RecoveredCrate| match &krate.source {
                CrateSource::Workspace { root } => Some(root.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(workspace_roots, vec!["rustinv"], "{}", loaded.artifact.path);
    }
}

#[test]
fn auditable_graph_matches_rust_audit_info_and_cargo_lock() {
    let lock: Lockfile = lockfile();
    for loaded in loaded() {
        match (&loaded.inventory.auditable, loaded.artifact.auditable) {
            (AuditableEvidence::Present(graph), true) => {
                let reference: AuditInfo = serde_json::from_slice(&read(&format!(
                    "reference/{}.audit-info.json",
                    loaded.artifact.path.trim_start_matches("bin/")
                )))
                .expect("rust-audit-info JSON parses");
                grade_edges(graph, &reference)
                    .unwrap_or_else(|error| panic!("{}: {error}", loaded.artifact.path));
                for edge in &graph.dependencies {
                    let from: &str = &graph.packages[edge.from].package.name;
                    let to: &str = &graph.packages[edge.to].package.name;
                    let locked: &LockPackage = lock
                        .package
                        .iter()
                        .find(|package: &&LockPackage| package.name == from)
                        .expect("edge source is locked");
                    assert!(
                        locked
                            .dependencies
                            .iter()
                            .any(|dependency: &String| dependency == to),
                        "{from} -> {to} is not in Cargo.lock"
                    );
                }
            }
            (AuditableEvidence::Absent, false) => {}
            (other, auditable) => panic!(
                "{}: auditable {auditable} but recovered {other:?}",
                loaded.artifact.path
            ),
        }
    }
}

#[test]
fn edge_grade_turns_red_on_one_changed_version() {
    let loaded: &Loaded = loaded()
        .iter()
        .find(|loaded: &&Loaded| loaded.artifact.auditable)
        .expect("an auditable artifact");
    let AuditableEvidence::Present(graph) = &loaded.inventory.auditable else {
        panic!("no graph");
    };
    let mut reference: AuditInfo = serde_json::from_slice(&read(&format!(
        "reference/{}.audit-info.json",
        loaded.artifact.path.trim_start_matches("bin/")
    )))
    .expect("rust-audit-info JSON parses");
    let regex: &mut AuditInfoPackage = reference
        .packages
        .iter_mut()
        .find(|package: &&mut AuditInfoPackage| package.name == "regex")
        .expect("regex is listed");
    regex.version = "1.12.4".to_owned();
    assert!(grade_edges(graph, &reference).is_err());
}

#[test]
fn symbol_counts_match_llvm_nm_per_crate() {
    for loaded in loaded() {
        if !has_symbol_reference(&loaded.artifact) {
            assert!(
                !loaded.inventory.symbols.symbol_table,
                "{}",
                loaded.artifact.path
            );
            assert_eq!(
                loaded.inventory.symbols.legacy + loaded.inventory.symbols.v0,
                0,
                "{}",
                loaded.artifact.path
            );
            continue;
        }
        assert!(
            loaded.inventory.symbols.symbol_table,
            "{}",
            loaded.artifact.path
        );
        let reference: SymbolReference = symbol_reference(&format!(
            "reference/{}.symbols.tsv",
            loaded.artifact.path.trim_start_matches("bin/")
        ));
        grade_symbols(&recovered_symbols(&loaded.inventory), &reference)
            .unwrap_or_else(|error| panic!("{}: {error}", loaded.artifact.path));
    }
}

#[test]
fn symbol_grade_turns_red_on_one_changed_crate_count() {
    let loaded: &Loaded = loaded()
        .iter()
        .find(|loaded: &&Loaded| has_symbol_reference(&loaded.artifact))
        .expect("an artifact with symbols");
    let mut reference: SymbolReference = symbol_reference(&format!(
        "reference/{}.symbols.tsv",
        loaded.artifact.path.trim_start_matches("bin/")
    ));
    let counts: &mut (u64, u64) = reference.crates.get_mut("regex").expect("regex symbols");
    counts.0 += 1;
    assert!(grade_symbols(&recovered_symbols(&loaded.inventory), &reference).is_err());
}

#[test]
fn inventory_is_deterministic() {
    for loaded in loaded() {
        let again: RustInventory = rust_inventory(&loaded.bytes).expect("second inventory");
        assert_eq!(again, loaded.inventory);
        assert_eq!(
            serde_json::to_vec(&again).expect("serialize"),
            serde_json::to_vec(&loaded.inventory).expect("serialize")
        );
    }
}

#[test]
fn non_images_are_typed_errors() {
    for input in [
        &b""[..],
        b"MZ",
        b"\x7fELF",
        &[0u8; 4096][..],
        b"{\"packages\":[]}",
    ] {
        match rust_inventory(input) {
            Err(
                RustInventoryError::UnsupportedContainer
                | RustInventoryError::ContainerParse { .. },
            ) => {}
            other => panic!("{input:?}: {other:?}"),
        }
    }
    let mut universal: Vec<u8> = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1];
    universal.resize(64, 0);
    assert!(rust_inventory(&universal).is_err());
}

#[test]
fn corrupt_auditable_section_is_refused_not_fatal() {
    let loaded: &Loaded = loaded()
        .iter()
        .find(|loaded: &&Loaded| loaded.artifact.container == "elf" && loaded.artifact.auditable)
        .expect("an auditable ELF artifact");
    let AuditableEvidence::Present(graph) = &loaded.inventory.auditable else {
        panic!("no graph");
    };
    let offset: usize = usize::try_from(graph.section.offset.expect("the section has file data"))
        .expect("section offset fits usize");
    let mut bytes: Vec<u8> = loaded.bytes.clone();
    for byte in &mut bytes[offset..offset + 16] {
        *byte ^= 0xa5;
    }
    let inventory: RustInventory = rust_inventory(&bytes).expect("container still parses");
    assert!(
        matches!(
            inventory.auditable,
            AuditableEvidence::Refused {
                reason: AuditableRefusal::Inflate { .. } | AuditableRefusal::Json { .. },
                ..
            }
        ),
        "{:?}",
        inventory.auditable
    );
    assert_eq!(inventory.crates, loaded.inventory.crates);
}

#[test]
fn mutated_artifacts_never_panic() {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || -> u64 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for loaded in loaded() {
        for _ in 0..MUTATIONS_PER_ARTIFACT {
            let mut bytes: Vec<u8> = loaded.bytes.clone();
            let length: u64 = bytes.len() as u64;
            for _ in 0..64 {
                let offset: u64 = match next() % 3 {
                    0 => next() % HEADER_WINDOW,
                    1 => length - 1 - next() % HEADER_WINDOW,
                    _ => next() % length,
                };
                bytes[offset as usize] = next() as u8;
            }
            let cut: usize = (next() % length) as usize;
            let _ = rust_inventory(&bytes);
            let _ = rust_inventory(&bytes[..cut]);
        }
    }
}
