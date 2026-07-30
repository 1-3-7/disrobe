#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::PathBuf;

const BANNED_INFERENCE_FAMILIES: &[&str] = &[
    "burn",
    "candle",
    "ggml",
    "llama-cpp",
    "llama_cpp",
    "llm",
    "mistralrs",
    "onnxruntime",
    "openvino",
    "ort",
    "rten",
    "safetensors",
    "tensorflow",
    "tflite",
    "tokenizers",
    "torch",
    "tract",
    "whisper-rs",
];

const BANNED_INFERENCE_CRATES: &[&str] = &[
    "dfdx",
    "esaxx-rs",
    "hf-hub",
    "kalosm",
    "luminal",
    "rust-bert",
    "sentencepiece",
    "tch",
    "tflitec",
    "tiktoken-rs",
    "wonnx",
];

const MIN_LOCKED_PACKAGES: usize = 900;
const MIN_WORKSPACE_MEMBERS: usize = 60;
const MIN_DEPENDENCY_EDGES: usize = 3000;
const MAX_LOCKFILE_BYTES: usize = 8 * 1024 * 1024;
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedPackage {
    name: String,
    from_registry: bool,
    dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InferenceFinding {
    crate_name: String,
    rule: String,
    direct_pullers: Vec<String>,
    path_from_member: Vec<String>,
}

fn first_quoted(line: &str) -> Option<&str> {
    let open: usize = line.find('"')?;
    let rest: &str = line.get(open + 1..)?;
    let close: usize = rest.find('"')?;
    rest.get(..close)
}

fn parse_locked_packages(lockfile: &str) -> Vec<LockedPackage> {
    let mut packages: Vec<LockedPackage> = Vec::new();
    let mut current: Option<LockedPackage> = None;
    let mut in_dependencies: bool = false;
    for raw in lockfile.lines() {
        let line: &str = raw.trim();
        if line == "[[package]]" {
            if let Some(finished) = current.take() {
                packages.push(finished);
            }
            current = Some(LockedPackage {
                name: String::new(),
                from_registry: false,
                dependencies: Vec::new(),
            });
            in_dependencies = false;
            continue;
        }
        if line.starts_with('[') {
            if let Some(finished) = current.take() {
                packages.push(finished);
            }
            in_dependencies = false;
            continue;
        }
        let Some(package) = current.as_mut() else {
            continue;
        };
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
                continue;
            }
            if let Some(entry) = first_quoted(line)
                && let Some(name) = entry.split_whitespace().next()
            {
                package.dependencies.push(name.to_owned());
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("name = ").and_then(first_quoted) {
            value.clone_into(&mut package.name);
            continue;
        }
        if line.starts_with("source = ") {
            package.from_registry = true;
            continue;
        }
        if line.starts_with("dependencies = [") && !line.ends_with(']') {
            in_dependencies = true;
        }
    }
    if let Some(finished) = current.take() {
        packages.push(finished);
    }
    packages
}

fn is_family_member(package_name: &str, family_stem: &str) -> bool {
    if package_name == family_stem {
        return true;
    }
    package_name
        .strip_prefix(family_stem)
        .is_some_and(|tail| tail.starts_with('-') || tail.starts_with('_'))
}

fn banned_rule(package_name: &str) -> Option<String> {
    if BANNED_INFERENCE_CRATES.contains(&package_name) {
        return Some(format!("exact name `{package_name}`"));
    }
    BANNED_INFERENCE_FAMILIES
        .iter()
        .find(|stem| is_family_member(package_name, stem))
        .map(|stem| format!("family `{stem}`"))
}

fn dependency_edges(packages: &[LockedPackage]) -> BTreeMap<String, BTreeSet<String>> {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in packages {
        let outgoing: &mut BTreeSet<String> = edges.entry(package.name.clone()).or_default();
        for dependency in &package.dependencies {
            outgoing.insert(dependency.clone());
        }
    }
    edges
}

fn workspace_members(packages: &[LockedPackage]) -> BTreeSet<String> {
    packages
        .iter()
        .filter(|package| !package.from_registry)
        .map(|package| package.name.clone())
        .collect()
}

fn reachability_parents(
    edges: &BTreeMap<String, BTreeSet<String>>,
    members: &BTreeSet<String>,
) -> BTreeMap<String, Option<String>> {
    let mut parents: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    for member in members {
        parents.insert(member.clone(), None);
        queue.push_back(member.clone());
    }
    while let Some(node) = queue.pop_front() {
        let Some(children) = edges.get(&node) else {
            continue;
        };
        for child in children {
            if parents.contains_key(child) {
                continue;
            }
            parents.insert(child.clone(), Some(node.clone()));
            queue.push_back(child.clone());
        }
    }
    parents
}

fn path_from_member(parents: &BTreeMap<String, Option<String>>, target: &str) -> Vec<String> {
    let mut reversed: Vec<String> = vec![target.to_owned()];
    let mut cursor: &str = target;
    while let Some(Some(parent)) = parents.get(cursor) {
        reversed.push(parent.clone());
        cursor = parent.as_str();
    }
    reversed.reverse();
    reversed
}

fn scan_for_inference_dependencies(packages: &[LockedPackage]) -> Vec<InferenceFinding> {
    let edges: BTreeMap<String, BTreeSet<String>> = dependency_edges(packages);
    let members: BTreeSet<String> = workspace_members(packages);
    let parents: BTreeMap<String, Option<String>> = reachability_parents(&edges, &members);
    let mut findings: BTreeMap<String, InferenceFinding> = BTreeMap::new();
    for package in packages {
        let Some(rule) = banned_rule(&package.name) else {
            continue;
        };
        let direct_pullers: BTreeSet<String> = packages
            .iter()
            .filter(|candidate| candidate.dependencies.contains(&package.name))
            .map(|candidate| candidate.name.clone())
            .collect();
        findings.insert(
            package.name.clone(),
            InferenceFinding {
                crate_name: package.name.clone(),
                rule,
                direct_pullers: direct_pullers.into_iter().collect(),
                path_from_member: path_from_member(&parents, &package.name),
            },
        );
    }
    findings.into_values().collect()
}

fn render_findings(findings: &[InferenceFinding]) -> String {
    let mut lines: Vec<String> = vec![format!(
        "{} in-process inference or model-runtime package(s) are in the resolved dependency tree. README states that no model and no LLM runs anywhere in the pipeline, so either the dependency goes or the claim goes.",
        findings.len()
    )];
    for finding in findings {
        let pullers: String = if finding.direct_pullers.is_empty() {
            "no workspace or registry package lists it directly".to_owned()
        } else {
            finding.direct_pullers.join(", ")
        };
        lines.push(format!(
            "  `{}` banned by {}: pulled in directly by {}; reachable as {}",
            finding.crate_name,
            finding.rule,
            pullers,
            finding.path_from_member.join(" -> ")
        ));
    }
    lines.push(format!(
        "The banned names live in BANNED_INFERENCE_FAMILIES and BANNED_INFERENCE_CRATES in {}.",
        file!()
    ));
    lines.join("\n")
}

fn workspace_lockfile() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join("Cargo.lock")
}

fn mutation_fixture(deep_package: &str) -> String {
    format!(
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n\
         [[package]]\nname = \"disrobe-cli\"\nversion = \"0.1.0\"\ndependencies = [\n \"mid-a\",\n]\n\n\
         [[package]]\nname = \"mid-a\"\nversion = \"1.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"aa\"\ndependencies = [\n \"mid-b 2.0.0\",\n]\n\n\
         [[package]]\nname = \"mid-b\"\nversion = \"2.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"bb\"\ndependencies = [\n \"{deep_package}\",\n]\n\n\
         [[package]]\nname = \"{deep_package}\"\nversion = \"3.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"cc\"\n"
    )
}

#[test]
fn workspace_dependency_tree_carries_no_in_process_inference_crate() {
    let lockfile_path: PathBuf = workspace_lockfile();
    assert!(
        lockfile_path.is_file(),
        "Cargo.lock must be readable at {} for the no-model claim to be checkable at all",
        lockfile_path.display()
    );
    let lockfile: String = std::fs::read_to_string(&lockfile_path).expect("read Cargo.lock");
    assert!(
        lockfile.len() <= MAX_LOCKFILE_BYTES,
        "Cargo.lock is {} bytes, over the {MAX_LOCKFILE_BYTES}-byte read cap",
        lockfile.len()
    );

    let packages: Vec<LockedPackage> = parse_locked_packages(&lockfile);
    let header_count: usize = lockfile.matches("[[package]]").count();
    assert_eq!(
        packages.len(),
        header_count,
        "the reader must account for every [[package]] block in Cargo.lock, otherwise an offender could sit in an unparsed block"
    );
    assert!(
        packages.len() >= MIN_LOCKED_PACKAGES,
        "only {} locked packages were read, under the {MIN_LOCKED_PACKAGES} floor: the lockfile was truncated or the reader regressed",
        packages.len()
    );
    let edge_total: usize = packages
        .iter()
        .map(|package| package.dependencies.len())
        .sum();
    assert!(
        edge_total >= MIN_DEPENDENCY_EDGES,
        "only {edge_total} dependency edges were read, under the {MIN_DEPENDENCY_EDGES} floor: without edges a transitive offender could not be traced"
    );

    let members: BTreeSet<String> = workspace_members(&packages);
    assert!(
        members.len() >= MIN_WORKSPACE_MEMBERS,
        "only {} workspace members were identified, under the {MIN_WORKSPACE_MEMBERS} floor",
        members.len()
    );
    assert!(
        members.contains("disrobe-core"),
        "disrobe-core must be one of the identified workspace members"
    );
    assert!(
        members.contains("disrobe-cli"),
        "disrobe-cli must be one of the identified workspace members, it is the shipped entry point"
    );

    let edges: BTreeMap<String, BTreeSet<String>> = dependency_edges(&packages);
    let parents: BTreeMap<String, Option<String>> = reachability_parents(&edges, &members);
    let registry_packages: Vec<&LockedPackage> = packages
        .iter()
        .filter(|package| package.from_registry)
        .collect();
    let mut traced: usize = 0;
    let mut deepest: usize = 0;
    for package in &registry_packages {
        let path: Vec<String> = path_from_member(&parents, &package.name);
        if path.len() >= 2 && members.contains(&path[0]) {
            traced += 1;
        }
        deepest = deepest.max(path.len());
    }
    assert_eq!(
        traced,
        registry_packages.len(),
        "every one of the {} third-party packages must trace back to a workspace member, otherwise the walk inspects fewer packages than the lockfile resolves",
        registry_packages.len()
    );
    assert!(
        deepest >= 3,
        "the deepest traced chain was {deepest}, so the walk never got past direct dependencies and could not report a transitive offender"
    );

    let findings: Vec<InferenceFinding> = scan_for_inference_dependencies(&packages);
    assert!(findings.is_empty(), "{}", render_findings(&findings));
}

#[test]
fn mutation_control_transitive_inference_crate_is_caught_with_its_puller() {
    let clean: String = mutation_fixture("memchr");
    let mutated: String = mutation_fixture("ort");
    assert_eq!(
        clean.replace("memchr", "ort"),
        mutated,
        "the two fixtures must differ only in the deep package name, otherwise this control proves nothing"
    );

    let clean_findings: Vec<InferenceFinding> =
        scan_for_inference_dependencies(&parse_locked_packages(&clean));
    assert!(
        clean_findings.is_empty(),
        "the clean fixture must report nothing, it reported {clean_findings:?}"
    );

    let mutated_packages: Vec<LockedPackage> = parse_locked_packages(&mutated);
    assert_eq!(
        mutated_packages.len(),
        4,
        "the mutated fixture must parse as 4 packages, got {mutated_packages:?}"
    );
    let mutated_findings: Vec<InferenceFinding> =
        scan_for_inference_dependencies(&mutated_packages);
    assert_eq!(
        mutated_findings.len(),
        1,
        "the mutated fixture must report exactly one offender, got {mutated_findings:?}"
    );
    let finding: &InferenceFinding = &mutated_findings[0];
    assert_eq!(finding.crate_name, "ort");
    assert_eq!(finding.rule, "family `ort`");
    assert_eq!(
        finding.direct_pullers,
        vec!["mid-b".to_owned()],
        "the report must name the package that pulled the offender in"
    );
    assert_eq!(
        finding.path_from_member,
        vec![
            "disrobe-cli".to_owned(),
            "mid-a".to_owned(),
            "mid-b".to_owned(),
            "ort".to_owned(),
        ],
        "a three-hop transitive offender must be reported with its full path from the workspace member"
    );

    let rendered: String = render_findings(&mutated_findings);
    assert!(
        rendered.contains("`ort` banned by family `ort`"),
        "the failure text must name the offender: {rendered}"
    );
    assert!(
        rendered.contains("disrobe-cli -> mid-a -> mid-b -> ort"),
        "the failure text must show the full pull path: {rendered}"
    );
    assert!(
        rendered.contains("pulled in directly by mid-b"),
        "the failure text must name the direct puller: {rendered}"
    );
}

#[test]
fn mutation_control_real_lockfile_with_injected_offender_is_caught() {
    let lockfile_path: PathBuf = workspace_lockfile();
    assert!(
        lockfile_path.is_file(),
        "Cargo.lock must be readable at {} for this control to mean anything",
        lockfile_path.display()
    );
    let lockfile: String = std::fs::read_to_string(&lockfile_path).expect("read Cargo.lock");
    let mut packages: Vec<LockedPackage> = parse_locked_packages(&lockfile);
    assert!(
        packages.len() >= MIN_LOCKED_PACKAGES,
        "the real tree must be read in full before it is mutated, got {} packages",
        packages.len()
    );
    let baseline: Vec<InferenceFinding> = scan_for_inference_dependencies(&packages);
    assert!(
        baseline.is_empty(),
        "the unmutated real tree must report nothing, otherwise this control cannot attribute the hit to the injection: {baseline:?}"
    );

    let members: BTreeSet<String> = workspace_members(&packages);
    let parents: BTreeMap<String, Option<String>> =
        reachability_parents(&dependency_edges(&packages), &members);
    let host: String = packages
        .iter()
        .filter(|package| package.from_registry)
        .map(|package| {
            (
                package.name.clone(),
                path_from_member(&parents, &package.name).len(),
            )
        })
        .find(|(_, depth)| *depth >= 3)
        .map(|(name, _)| name)
        .expect("the real tree must contain a package at least three hops from a workspace member");
    for package in packages.iter_mut().filter(|package| package.name == host) {
        package.dependencies.push("ort".to_owned());
    }
    packages.push(LockedPackage {
        name: "ort".to_owned(),
        from_registry: true,
        dependencies: Vec::new(),
    });

    let findings: Vec<InferenceFinding> = scan_for_inference_dependencies(&packages);
    assert_eq!(
        findings.len(),
        1,
        "injecting one inference crate into the real tree must produce exactly one finding, got {findings:?}"
    );
    let finding: &InferenceFinding = &findings[0];
    assert_eq!(finding.crate_name, "ort");
    assert_eq!(finding.rule, "family `ort`");
    assert_eq!(
        finding.direct_pullers,
        vec![host.clone()],
        "the finding must name the real package that pulled the offender in"
    );
    let path: &[String] = &finding.path_from_member;
    assert!(
        path.len() >= 4,
        "the offender was injected at least three hops deep, so its reported path must be at least four names long, got {path:?}"
    );
    assert!(
        members.contains(&path[0]),
        "the reported path must start at a real workspace member, got {path:?}"
    );
    assert_eq!(path.last(), Some(&"ort".to_owned()));
    assert_eq!(
        path[path.len() - 2],
        host,
        "the hop before the offender must be the package that depends on it"
    );
    let rendered: String = render_findings(&findings);
    assert!(
        rendered.contains("`ort` banned by family `ort`"),
        "the failure text must name the offender: {rendered}"
    );
    assert!(
        rendered.contains(&format!("pulled in directly by {host}")),
        "the failure text must name the real puller: {rendered}"
    );
}

#[test]
fn mutation_control_direct_inference_dependency_is_caught() {
    let lockfile: String = format!(
        "version = 4\n\n[[package]]\nname = \"disrobe-cli\"\nversion = \"0.1.0\"\ndependencies = [\n \"candle-core 0.9.1\",\n]\n\n[[package]]\nname = \"candle-core\"\nversion = \"0.9.1\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"dd\"\n"
    );
    let findings: Vec<InferenceFinding> =
        scan_for_inference_dependencies(&parse_locked_packages(&lockfile));
    assert_eq!(
        findings.len(),
        1,
        "a direct dependency on an inference crate must be caught, got {findings:?}"
    );
    assert_eq!(findings[0].crate_name, "candle-core");
    assert_eq!(findings[0].rule, "family `candle`");
    assert_eq!(
        findings[0].path_from_member,
        vec!["disrobe-cli".to_owned(), "candle-core".to_owned()]
    );
}

#[test]
fn banned_lists_are_sorted_deduplicated_and_named() {
    for list in [BANNED_INFERENCE_FAMILIES, BANNED_INFERENCE_CRATES] {
        assert!(!list.is_empty(), "a banned list must not be empty");
        let unique: BTreeSet<&str> = list.iter().copied().collect();
        assert_eq!(
            unique.len(),
            list.len(),
            "a banned list carries a duplicate entry: {list:?}"
        );
        let sorted: Vec<&str> = unique.into_iter().collect();
        assert_eq!(
            sorted, *list,
            "a banned list must stay sorted so an addition is reviewable"
        );
        for entry in list {
            assert!(
                !entry.is_empty(),
                "an empty banned entry would match every package name"
            );
        }
    }
    assert_eq!(BANNED_INFERENCE_FAMILIES.len(), 18);
    assert_eq!(BANNED_INFERENCE_CRATES.len(), 11);
}

#[test]
fn every_named_inference_crate_is_matched() {
    let published: &[&str] = &[
        "burn",
        "burn-core",
        "burn-ndarray",
        "burn-tch",
        "burn-tensor",
        "candle-core",
        "candle-nn",
        "candle-onnx",
        "candle-transformers",
        "dfdx",
        "esaxx-rs",
        "ggml",
        "ggml-sys",
        "hf-hub",
        "kalosm",
        "llama-cpp-2",
        "llama-cpp-sys-2",
        "llama_cpp",
        "llama_cpp_rs",
        "llm",
        "llm-base",
        "llm-samplers",
        "luminal",
        "mistralrs",
        "mistralrs-core",
        "onnxruntime",
        "onnxruntime-sys",
        "openvino",
        "openvino-sys",
        "ort",
        "ort-sys",
        "rten",
        "rten-tensor",
        "rust-bert",
        "safetensors",
        "sentencepiece",
        "tch",
        "tensorflow",
        "tensorflow-sys",
        "tflite",
        "tflitec",
        "tiktoken-rs",
        "tokenizers",
        "torch-sys",
        "tract-core",
        "tract-hir",
        "tract-linalg",
        "tract-nnef",
        "tract-onnx",
        "tract-tensorflow",
        "whisper-rs",
        "whisper-rs-sys",
        "wonnx",
    ];
    let unmatched: Vec<&str> = published
        .iter()
        .copied()
        .filter(|name| banned_rule(name).is_none())
        .collect();
    assert!(
        unmatched.is_empty(),
        "these published inference crates are not covered by the banned lists: {unmatched:?}"
    );
    assert_eq!(
        published.len(),
        53,
        "the covered-name set is pinned so a shrunk list cannot pass by inspecting fewer names"
    );
}

#[test]
fn near_miss_dependency_names_are_not_flagged() {
    let benign: &[&str] = &[
        "disrobe-core",
        "disrobe-llm-metadata",
        "interpolator",
        "matchers",
        "nalgebra",
        "ndarray",
        "num-traits",
        "portable-atomic",
        "ratchet_core",
        "safe_arch",
        "supports-color",
        "tokio",
        "tokio-tungstenite",
        "tracing",
        "tracing-core",
        "tracing-subscriber",
        "zstd-safe",
    ];
    let flagged: Vec<(&str, String)> = benign
        .iter()
        .copied()
        .filter_map(|name| banned_rule(name).map(|rule| (name, rule)))
        .collect();
    assert!(
        flagged.is_empty(),
        "the matcher is anchored to whole package names, these benign names must not match: {flagged:?}"
    );
    assert_eq!(
        benign.len(),
        17,
        "the benign control set is pinned so it cannot be trimmed to dodge a false positive"
    );
}

#[test]
fn real_lockfile_reader_handles_both_dependency_entry_forms() {
    let lockfile: String = format!(
        "version = 4\n\n[[package]]\nname = \"root\"\nversion = \"0.1.0\"\ndependencies = [\n \"bare\",\n \"versioned 1.2.3\",\n]\n\n[[package]]\nname = \"bare\"\nversion = \"1.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\n\n[[package]]\nname = \"versioned\"\nversion = \"1.2.3\"\nsource = \"{REGISTRY_SOURCE}\"\n"
    );
    let packages: Vec<LockedPackage> = parse_locked_packages(&lockfile);
    assert_eq!(packages.len(), 3);
    assert_eq!(packages[0].name, "root");
    assert!(!packages[0].from_registry);
    assert_eq!(
        packages[0].dependencies,
        vec!["bare".to_owned(), "versioned".to_owned()],
        "a `name version` dependency entry must resolve to the bare package name"
    );
    assert!(packages[1].from_registry);
    assert!(packages[2].from_registry);
}
