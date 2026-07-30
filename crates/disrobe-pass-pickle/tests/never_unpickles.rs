#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_pickle::{
    Disassembly, PickleValue, SafetyReport, Severity, VmTrace, analyze_safety, disassemble, execute,
};

const PUBLISHED_CLAIM: &str = "never unpickles";

const ROOT_PACKAGE: &str = "disrobe-pass-pickle";
const MAX_LOCKFILE_BYTES: usize = 8 * 1024 * 1024;
const MIN_CLOSURE_PACKAGES: usize = 250;
const MIN_CLOSURE_EDGES: usize = 700;
const MIN_CLOSURE_DEPTH: usize = 5;
const REGISTRY_SOURCE: &str = "registry+https://github.com/rust-lang/crates.io-index";

const REQUIRED_CLOSURE_MEMBERS: [&str; 3] =
    ["disrobe-bytes", "disrobe-core", "disrobe-pass-pickle"];

const BANNED_PYTHON_RUNTIME_FAMILIES: [&str; 8] = [
    "cpython",
    "inline-python",
    "numpy",
    "pyembed",
    "pyo3",
    "python27-sys",
    "python3-sys",
    "rustpython",
];

const UNPICKLER_NAME_FRAGMENT: &str = "pickle";

#[derive(Debug, Clone, Copy)]
struct ExecutionPrimitive {
    token: &'static str,
    why: &'static str,
}

const EXECUTION_PRIMITIVES: [ExecutionPrimitive; 11] = [
    ExecutionPrimitive {
        token: "Command::new",
        why: "spawns a process, which is the shortest route from a pickle stream to the host \
              interpreter and its own pickle module",
    },
    ExecutionPrimitive {
        token: "std::process",
        why: "reaches the process API, so a stream-derived name could become an argv",
    },
    ExecutionPrimitive {
        token: "libloading",
        why: "loads a shared object at runtime, which is how a module name off the stream would \
              become real code",
    },
    ExecutionPrimitive {
        token: "dlopen",
        why: "opens a shared object at runtime",
    },
    ExecutionPrimitive {
        token: "dlsym",
        why: "resolves a symbol by name at runtime, turning a stream-supplied name into an address",
    },
    ExecutionPrimitive {
        token: "LoadLibraryA",
        why: "loads a module at runtime on Windows",
    },
    ExecutionPrimitive {
        token: "LoadLibraryW",
        why: "loads a module at runtime on Windows",
    },
    ExecutionPrimitive {
        token: "GetProcAddress",
        why: "resolves a symbol by name at runtime on Windows",
    },
    ExecutionPrimitive {
        token: "extern \"C\"",
        why: "declares a foreign callable the pass could enter",
    },
    ExecutionPrimitive {
        token: "transmute",
        why: "can forge a function pointer out of stream-supplied bytes",
    },
    ExecutionPrimitive {
        token: "dyn Fn",
        why: "would let the value model hold a callable rather than a name, which is the exact \
              shape the symbolic model exists to avoid",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct LockedPackage {
    name: String,
    from_registry: bool,
    dependencies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DependencyFinding {
    crate_name: String,
    rule: String,
    direct_pullers: Vec<String>,
    path_from_root: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceFinding {
    file: String,
    line: usize,
    token: String,
    why: String,
    text: String,
}

#[derive(Debug, Clone, Copy)]
struct Payload {
    module: &'static str,
    name: &'static str,
    overtly_malicious: bool,
}

const PAYLOADS: [Payload; 3] = [
    Payload {
        module: "os",
        name: "system",
        overtly_malicious: true,
    },
    Payload {
        module: "os",
        name: "remove",
        overtly_malicious: false,
    },
    Payload {
        module: "builtins",
        name: "eval",
        overtly_malicious: true,
    },
];

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
        .is_some_and(|tail: &str| tail.starts_with('-') || tail.starts_with('_'))
}

fn banned_rule(package: &LockedPackage) -> Option<String> {
    if let Some(stem) = BANNED_PYTHON_RUNTIME_FAMILIES
        .iter()
        .find(|stem: &&&str| is_family_member(&package.name, stem))
    {
        return Some(format!(
            "python runtime family `{stem}`, which exposes the interpreter's own pickle module"
        ));
    }
    if package.from_registry && package.name.contains(UNPICKLER_NAME_FRAGMENT) {
        return Some(format!(
            "third-party name containing `{UNPICKLER_NAME_FRAGMENT}`, so it materializes values \
             from a pickle stream rather than modeling them"
        ));
    }
    None
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

fn closure_parents(
    edges: &BTreeMap<String, BTreeSet<String>>,
    root: &str,
) -> BTreeMap<String, Option<String>> {
    let mut parents: BTreeMap<String, Option<String>> = BTreeMap::new();
    parents.insert(root.to_owned(), None);
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(root.to_owned());
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

fn path_from_root(parents: &BTreeMap<String, Option<String>>, target: &str) -> Vec<String> {
    let mut reversed: Vec<String> = vec![target.to_owned()];
    let mut cursor: &str = target;
    while let Some(Some(parent)) = parents.get(cursor) {
        reversed.push(parent.clone());
        cursor = parent.as_str();
    }
    reversed.reverse();
    reversed
}

fn deepest_chain(parents: &BTreeMap<String, Option<String>>) -> usize {
    parents
        .keys()
        .map(|name: &String| path_from_root(parents, name).len())
        .max()
        .unwrap_or(0)
}

fn dependency_findings(packages: &[LockedPackage], root: &str) -> Vec<DependencyFinding> {
    let edges: BTreeMap<String, BTreeSet<String>> = dependency_edges(packages);
    let parents: BTreeMap<String, Option<String>> = closure_parents(&edges, root);
    let mut findings: BTreeMap<String, DependencyFinding> = BTreeMap::new();
    for package in packages {
        if !parents.contains_key(&package.name) {
            continue;
        }
        let Some(rule) = banned_rule(package) else {
            continue;
        };
        let direct_pullers: BTreeSet<String> = packages
            .iter()
            .filter(|candidate: &&LockedPackage| {
                parents.contains_key(&candidate.name)
                    && candidate.dependencies.contains(&package.name)
            })
            .map(|candidate: &LockedPackage| candidate.name.clone())
            .collect();
        findings.insert(
            package.name.clone(),
            DependencyFinding {
                crate_name: package.name.clone(),
                rule,
                direct_pullers: direct_pullers.into_iter().collect(),
                path_from_root: path_from_root(&parents, &package.name),
            },
        );
    }
    findings.into_values().collect()
}

fn render_dependency_findings(findings: &[DependencyFinding]) -> Vec<String> {
    let mut lines: Vec<String> = vec![format!(
        "{} package(s) able to evaluate a pickle are reachable from {ROOT_PACKAGE}. Seven \
         documentation sites state that the pass {PUBLISHED_CLAIM}, so either the dependency goes \
         or the claim goes.",
        findings.len()
    )];
    for finding in findings {
        let pullers: String = if finding.direct_pullers.is_empty() {
            "nothing inside the closure lists it directly".to_owned()
        } else {
            finding.direct_pullers.join(", ")
        };
        lines.push(format!(
            "  `{}` banned by {}: pulled in directly by {}; reachable as {}",
            finding.crate_name,
            finding.rule,
            pullers,
            finding.path_from_root.join(" -> ")
        ));
    }
    lines
}

fn collect_rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries: std::fs::ReadDir =
        std::fs::read_dir(dir).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "the pass source tree must be readable at {} for the claim to be checkable at all: \
             {error}",
                dir.display()
            )
        });
    for entry in entries {
        let path: PathBuf = entry
            .unwrap_or_else(|error: std::io::Error| {
                panic!("reading an entry under {}: {error}", dir.display())
            })
            .path();
        if path.is_dir() {
            collect_rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

fn source_findings(files: &[(String, String)]) -> Vec<SourceFinding> {
    let mut findings: Vec<SourceFinding> = Vec::new();
    for (name, contents) in files {
        for (index, line) in contents.lines().enumerate() {
            for primitive in &EXECUTION_PRIMITIVES {
                if line.contains(primitive.token) {
                    findings.push(SourceFinding {
                        file: name.clone(),
                        line: index + 1,
                        token: primitive.token.to_owned(),
                        why: primitive.why.to_owned(),
                        text: line.trim().to_owned(),
                    });
                }
            }
        }
    }
    findings
}

fn render_source_findings(findings: &[SourceFinding]) -> Vec<String> {
    let mut lines: Vec<String> = vec![format!(
        "{} execution primitive(s) appear in the pass source. The claim that the pass \
         {PUBLISHED_CLAIM} rests on the stream never becoming code, so a primitive here is either \
         a defect or a claim that has to change.",
        findings.len()
    )];
    for finding in findings {
        lines.push(format!(
            "  {}:{} carries `{}` ({}): {}",
            finding.file, finding.line, finding.token, finding.why, finding.text
        ));
    }
    lines
}

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn proto2_reduce(module: &str, name: &str, argument: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(32 + argument.len());
    out.extend_from_slice(&[0x80, 0x02]);
    out.push(b'c');
    out.extend_from_slice(module.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(name.as_bytes());
    out.push(b'\n');
    out.push(b'(');
    out.push(b'X');
    let length: u32 = u32::try_from(argument.len()).expect("the payload argument fits u32");
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(argument.as_bytes());
    out.push(b't');
    out.push(b'R');
    out.push(b'.');
    out
}

fn symbolic_reduce(module: &str, name: &str, argument: &str) -> PickleValue {
    PickleValue::Reduce {
        callable: Box::new(PickleValue::Global {
            module: module.to_owned(),
            name: name.to_owned(),
        }),
        args: Box::new(PickleValue::Tuple(vec![PickleValue::Str(
            argument.to_owned(),
        )])),
    }
}

#[derive(Debug)]
struct LoadedGunScene {
    directory: PathBuf,
    victim: PathBuf,
    victim_bytes: Vec<u8>,
    markers: Vec<PathBuf>,
}

impl LoadedGunScene {
    fn stage() -> Self {
        static SCENE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let directory: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-never-unpickles-{}-{}",
            std::process::id(),
            SCENE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap_or_else(|error: std::io::Error| {
            panic!("staging {}: {error}", directory.display())
        });
        let victim: PathBuf = directory.join("victim.txt");
        let victim_bytes: Vec<u8> = b"a real file the payloads target".to_vec();
        std::fs::write(&victim, &victim_bytes).unwrap_or_else(|error: std::io::Error| {
            panic!("writing {}: {error}", victim.display())
        });
        let markers: Vec<PathBuf> = vec![directory.join("marker_a"), directory.join("marker_c")];
        Self {
            directory,
            victim,
            victim_bytes,
            markers,
        }
    }

    fn slashed(path: &Path) -> String {
        path.to_string_lossy().replace('\\', "/")
    }

    fn arguments(&self) -> Vec<String> {
        let create_marker: String = if cfg!(windows) {
            format!("cmd /c type nul > \"{}\"", Self::slashed(&self.markers[0]))
        } else {
            format!("touch '{}'", Self::slashed(&self.markers[0]))
        };
        vec![
            create_marker,
            Self::slashed(&self.victim),
            format!("open('{}', 'w').close()", Self::slashed(&self.markers[1])),
        ]
    }

    fn survival_defects(&self) -> Vec<String> {
        let mut defects: Vec<String> = Vec::new();
        for marker in &self.markers {
            let fired: bool = marker.is_file();
            if fired {
                defects.push(format!(
                    "{} exists after tracing, so a payload's callable ran; the pass {PUBLISHED_CLAIM}",
                    marker.display()
                ));
            }
        }
        let present: bool = self.victim.is_file();
        if present {
            let after: Vec<u8> =
                std::fs::read(&self.victim).unwrap_or_else(|error: std::io::Error| {
                    panic!("re-reading {}: {error}", self.victim.display())
                });
            if after != self.victim_bytes {
                defects.push(format!(
                    "{} changed under tracing, from {} bytes to {} bytes",
                    self.victim.display(),
                    self.victim_bytes.len(),
                    after.len()
                ));
            }
        } else {
            defects.push(format!(
                "{} was removed, so the os.remove payload's callable ran",
                self.victim.display()
            ));
        }
        defects
    }
}

impl Drop for LoadedGunScene {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&self.directory);
    }
}

fn payload_defects(scene: &LoadedGunScene) -> Vec<String> {
    let mut defects: Vec<String> = Vec::new();
    let arguments: Vec<String> = scene.arguments();
    for (payload, argument) in PAYLOADS.iter().zip(arguments.iter()) {
        let fqn: String = format!("{}.{}", payload.module, payload.name);
        let bytes: Vec<u8> = proto2_reduce(payload.module, payload.name, argument);
        let dis: Disassembly = disassemble(&bytes)
            .unwrap_or_else(|error| panic!("{fqn}: the staged payload must disassemble: {error}"));
        let trace: VmTrace = execute(&dis)
            .unwrap_or_else(|error| panic!("{fqn}: the staged payload must trace: {error}"));
        let expected: PickleValue = symbolic_reduce(payload.module, payload.name, argument);
        if trace.result != expected {
            defects.push(format!(
                "{fqn}: the traced value is not the symbolic reduce this model is built from. A \
                 resolved global has to stay a module and name pair with its arguments as data, \
                 because that is the structural reason the callable cannot be entered. Got {:?}",
                trace.result
            ));
        }
        let report: SafetyReport = analyze_safety(&trace);
        let flagged: bool = report.severity == Severity::OvertlyMalicious;
        if flagged != payload.overtly_malicious {
            defects.push(format!(
                "{fqn}: classification disagrees with this payload's own label; expected \
                 OvertlyMalicious={}, got {:?}",
                payload.overtly_malicious, report.severity
            ));
        }
    }
    defects
}

fn uncovered_ground() -> String {
    format!(
        "What this gate does not cover, stated here rather than in prose that would have to be \
         taken on trust. It is a name-based dependency check over the resolved closure, a \
         token-based scan of this crate's own source, and three staged payloads, so an evaluator \
         introduced under a name absent from BANNED_PYTHON_RUNTIME_FAMILIES, or reached through a \
         dependency's own internals, is outside what it rules out. It speaks only for \
         {ROOT_PACKAGE}: pyo3 is resolved elsewhere in this workspace for disrobe-python, \
         disrobe-pyarmor-cextract and disrobe-pyarmor-pytrace, and all this asserts is that none of \
         them is reachable from the pickle pass."
    )
}

#[test]
fn pickle_pass_carries_no_unpickler_dependency_and_no_evaluation_path() {
    let root: PathBuf = workspace_root();
    let lockfile_path: PathBuf = root.join("Cargo.lock");
    let lockfile: String =
        std::fs::read_to_string(&lockfile_path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "Cargo.lock must be readable at {} for the claim that the pass {PUBLISHED_CLAIM} \
                 to be checkable at all: {error}",
                lockfile_path.display()
            )
        });
    assert!(
        lockfile.len() <= MAX_LOCKFILE_BYTES,
        "Cargo.lock is {} bytes, over the {MAX_LOCKFILE_BYTES}-byte read cap",
        lockfile.len()
    );

    let packages: Vec<LockedPackage> = parse_locked_packages(&lockfile);
    assert_eq!(
        packages.len(),
        lockfile.matches("[[package]]").count(),
        "the reader must account for every [[package]] block, otherwise an evaluator could sit in \
         an unparsed block"
    );

    let edges: BTreeMap<String, BTreeSet<String>> = dependency_edges(&packages);
    let parents: BTreeMap<String, Option<String>> = closure_parents(&edges, ROOT_PACKAGE);
    let closure_edges: usize = parents
        .keys()
        .map(|name: &String| edges.get(name).map_or(0, BTreeSet::len))
        .sum();
    assert!(
        parents.len() >= MIN_CLOSURE_PACKAGES,
        "the walk reached {} packages from {ROOT_PACKAGE}, under the {MIN_CLOSURE_PACKAGES} floor; \
         a walk that inspects almost nothing would report a clean closure for the wrong reason",
        parents.len()
    );
    assert!(
        closure_edges >= MIN_CLOSURE_EDGES,
        "the closure carries {closure_edges} edges, under the {MIN_CLOSURE_EDGES} floor; without \
         edges a transitive evaluator could not be traced"
    );
    let depth: usize = deepest_chain(&parents);
    assert!(
        depth >= MIN_CLOSURE_DEPTH,
        "the deepest traced chain was {depth}, so the walk never got past shallow dependencies and \
         could not report a transitive evaluator"
    );
    for member in REQUIRED_CLOSURE_MEMBERS {
        assert!(
            parents.contains_key(member),
            "{member} must be inside the walked closure, otherwise the walk is not measuring the \
             pass this claim is about"
        );
    }

    let mut defects: Vec<String> = Vec::new();
    let dependency: Vec<DependencyFinding> = dependency_findings(&packages, ROOT_PACKAGE);
    if !dependency.is_empty() {
        defects.extend(render_dependency_findings(&dependency));
    }

    let source_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut source_paths: Vec<PathBuf> = Vec::new();
    collect_rust_sources(&source_dir, &mut source_paths);
    assert!(
        source_paths.len() >= 10,
        "only {} source files were read under {}, so the scan is looking at a fraction of the pass",
        source_paths.len(),
        source_dir.display()
    );
    let sources: Vec<(String, String)> = source_paths
        .iter()
        .map(|path: &PathBuf| {
            let text: String =
                std::fs::read_to_string(path).unwrap_or_else(|error: std::io::Error| {
                    panic!("reading {}: {error}", path.display())
                });
            (path.to_string_lossy().into_owned(), text)
        })
        .collect();
    let source: Vec<SourceFinding> = source_findings(&sources);
    if !source.is_empty() {
        defects.extend(render_source_findings(&source));
    }

    let scene: LoadedGunScene = LoadedGunScene::stage();
    defects.extend(payload_defects(&scene));
    defects.extend(scene.survival_defects());

    eprintln!(
        "{ROOT_PACKAGE}: {} packages and {closure_edges} edges walked at depth {depth} with no \
         evaluating unpickler; {} source files carry no execution primitive; {} staged payloads \
         traced symbolically with every targeted resource intact",
        parents.len(),
        sources.len(),
        PAYLOADS.len()
    );
    assert!(
        defects.is_empty(),
        "the published claim that this pass {PUBLISHED_CLAIM} is not holding:\n{}\n\n{}",
        defects.join("\n"),
        uncovered_ground()
    );
}

fn mutation_lockfile(deep_package: &str) -> String {
    format!(
        "# This file is automatically @generated by Cargo.\nversion = 4\n\n\
         [[package]]\nname = \"{ROOT_PACKAGE}\"\nversion = \"0.1.0\"\ndependencies = [\n \"mid-a\",\n]\n\n\
         [[package]]\nname = \"mid-a\"\nversion = \"1.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"aa\"\ndependencies = [\n \"mid-b 2.0.0\",\n]\n\n\
         [[package]]\nname = \"mid-b\"\nversion = \"2.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"bb\"\ndependencies = [\n \"{deep_package}\",\n]\n\n\
         [[package]]\nname = \"{deep_package}\"\nversion = \"3.0.0\"\nsource = \"{REGISTRY_SOURCE}\"\nchecksum = \"cc\"\n"
    )
}

#[test]
fn mutation_control_a_transitive_python_runtime_is_caught_with_its_puller() {
    let clean: String = mutation_lockfile("memchr");
    let mutated: String = mutation_lockfile("pyo3-ffi");
    assert_eq!(
        clean.replace("memchr", "pyo3-ffi"),
        mutated,
        "the two fixtures must differ only in the deep package name, or this control proves nothing"
    );

    let clean_findings: Vec<DependencyFinding> =
        dependency_findings(&parse_locked_packages(&clean), ROOT_PACKAGE);
    assert!(
        clean_findings.is_empty(),
        "the clean fixture must report nothing, it reported {clean_findings:?}"
    );

    let findings: Vec<DependencyFinding> =
        dependency_findings(&parse_locked_packages(&mutated), ROOT_PACKAGE);
    assert_eq!(
        findings.len(),
        1,
        "a three-hop transitive python runtime must be reported exactly once, got {findings:?}"
    );
    let finding: &DependencyFinding = &findings[0];
    assert_eq!(finding.crate_name, "pyo3-ffi");
    assert!(
        finding.rule.contains("python runtime family `pyo3`"),
        "the rule must name the family that matched, got {}",
        finding.rule
    );
    assert_eq!(
        finding.direct_pullers,
        vec!["mid-b".to_owned()],
        "the report must name the package that pulled the offender in"
    );
    assert_eq!(
        finding.path_from_root,
        vec![
            ROOT_PACKAGE.to_owned(),
            "mid-a".to_owned(),
            "mid-b".to_owned(),
            "pyo3-ffi".to_owned(),
        ],
        "a transitive offender must be reported with its full path from the pass"
    );
    let rendered: Vec<String> = render_dependency_findings(&findings);
    let text: String = rendered.join("\n");
    eprintln!("rejected:\n{text}");
    assert!(
        text.contains("disrobe-pass-pickle -> mid-a -> mid-b -> pyo3-ffi"),
        "the failure text must show the full pull path: {text}"
    );
    assert!(
        text.contains("pulled in directly by mid-b"),
        "the failure text must name the direct puller: {text}"
    );
}

#[test]
fn mutation_control_a_third_party_unpickler_is_caught_and_this_crate_is_not() {
    let mutated: String = mutation_lockfile("serde-pickle");
    let findings: Vec<DependencyFinding> =
        dependency_findings(&parse_locked_packages(&mutated), ROOT_PACKAGE);
    assert_eq!(
        findings.len(),
        1,
        "a third-party package whose name carries `pickle` must be reported, got {findings:?}"
    );
    assert_eq!(findings[0].crate_name, "serde-pickle");
    assert!(
        findings[0].rule.contains(UNPICKLER_NAME_FRAGMENT),
        "the rule must name the fragment that matched, got {}",
        findings[0].rule
    );

    let root_package: LockedPackage = LockedPackage {
        name: ROOT_PACKAGE.to_owned(),
        from_registry: false,
        dependencies: Vec::new(),
    };
    assert!(
        banned_rule(&root_package).is_none(),
        "the pass itself carries `pickle` in its name and is a workspace member, so the fragment \
         rule must not flag it"
    );
}

#[test]
fn mutation_control_an_execution_primitive_in_the_pass_source_is_caught() {
    let clean: Vec<(String, String)> = vec![(
        "src/vm.rs".to_owned(),
        "fn step(op: u8) -> u8 {\n    op.wrapping_add(1)\n}\n".to_owned(),
    )];
    assert!(
        source_findings(&clean).is_empty(),
        "the clean source must report nothing"
    );

    for primitive in &EXECUTION_PRIMITIVES {
        let seeded: Vec<(String, String)> = vec![(
            "src/vm.rs".to_owned(),
            format!("fn run() {{\n    let _ = {};\n}}\n", primitive.token),
        )];
        let findings: Vec<SourceFinding> = source_findings(&seeded);
        assert_eq!(
            findings.len(),
            1,
            "seeding `{}` must be reported exactly once, got {findings:?}",
            primitive.token
        );
        assert_eq!(findings[0].line, 2, "the report must name the line");
        assert_eq!(findings[0].token, primitive.token);
    }

    let seeded: Vec<(String, String)> = vec![(
        "src/vm.rs".to_owned(),
        "fn run() {\n    Command::new(\"python\").arg(\"-c\").spawn();\n}\n".to_owned(),
    )];
    let text: String = render_source_findings(&source_findings(&seeded)).join("\n");
    eprintln!("rejected:\n{text}");
    assert!(
        text.contains("src/vm.rs:2 carries `Command::new`"),
        "the failure text must name the file, line and token: {text}"
    );
    assert!(
        text.contains("route from a pickle stream to the host interpreter"),
        "the failure text must say why the primitive matters: {text}"
    );
}

#[test]
fn mutation_control_a_payload_that_fires_is_reported() {
    let scene: LoadedGunScene = LoadedGunScene::stage();
    assert!(
        scene.survival_defects().is_empty(),
        "the staged scene must start intact"
    );

    std::fs::write(&scene.markers[0], b"fired").expect("seeding a fired marker");
    let fired: Vec<String> = scene.survival_defects();
    eprintln!("rejected:\n{}", fired.join("\n"));
    assert!(
        fired
            .iter()
            .any(|d: &String| d.contains("a payload's callable ran")),
        "a marker appearing must be reported as the payload having run, got {fired:?}"
    );
    std::fs::remove_file(&scene.markers[0]).expect("clearing the seeded marker");

    std::fs::remove_file(&scene.victim).expect("seeding a removed victim");
    let removed: Vec<String> = scene.survival_defects();
    assert!(
        removed
            .iter()
            .any(|d: &String| d.contains("the os.remove payload's callable ran")),
        "the targeted file disappearing must be reported, got {removed:?}"
    );

    std::fs::write(&scene.victim, b"truncated").expect("restoring a changed victim");
    let changed: Vec<String> = scene.survival_defects();
    assert!(
        changed
            .iter()
            .any(|d: &String| d.contains("changed under tracing")),
        "the targeted file being rewritten must be reported, got {changed:?}"
    );
}

#[test]
fn the_staged_payloads_are_real_loaded_pickles() {
    let scene: LoadedGunScene = LoadedGunScene::stage();
    let arguments: Vec<String> = scene.arguments();
    assert_eq!(arguments.len(), PAYLOADS.len());
    for (payload, argument) in PAYLOADS.iter().zip(arguments.iter()) {
        let bytes: Vec<u8> = proto2_reduce(payload.module, payload.name, argument);
        let dis: Disassembly = disassemble(&bytes).expect("a staged payload disassembles");
        let opcodes: Vec<&str> = dis
            .instructions
            .iter()
            .map(|insn: &disrobe_pass_pickle::Insn| insn.name.as_str())
            .collect();
        assert_eq!(
            opcodes,
            vec![
                "PROTO",
                "GLOBAL",
                "MARK",
                "BINUNICODE",
                "TUPLE",
                "REDUCE",
                "STOP",
            ],
            "each staged payload must be a real GLOBAL plus REDUCE pickle, or it is not the loaded \
             gun this gate claims to be pointing at the pass"
        );
    }
}

#[test]
fn banned_lists_are_sorted_deduplicated_and_pinned() {
    let unique: BTreeSet<&str> = BANNED_PYTHON_RUNTIME_FAMILIES.iter().copied().collect();
    assert_eq!(
        unique.len(),
        BANNED_PYTHON_RUNTIME_FAMILIES.len(),
        "the banned family list carries a duplicate"
    );
    let sorted: Vec<&str> = unique.into_iter().collect();
    assert_eq!(
        sorted,
        BANNED_PYTHON_RUNTIME_FAMILIES.to_vec(),
        "the banned family list must stay sorted so an addition is reviewable"
    );
    for stem in BANNED_PYTHON_RUNTIME_FAMILIES {
        assert!(
            !stem.is_empty(),
            "an empty stem would match every package name"
        );
    }
    let tokens: BTreeSet<&str> = EXECUTION_PRIMITIVES
        .iter()
        .map(|primitive: &ExecutionPrimitive| primitive.token)
        .collect();
    assert_eq!(
        tokens.len(),
        EXECUTION_PRIMITIVES.len(),
        "the execution primitive list carries a duplicate token"
    );
    for primitive in &EXECUTION_PRIMITIVES {
        assert!(
            !primitive.token.is_empty() && !primitive.why.is_empty(),
            "every primitive must carry a token and a reason"
        );
    }
}

#[test]
fn family_matching_is_anchored_to_whole_package_names() {
    let banned: [&str; 9] = [
        "cpython",
        "inline-python",
        "numpy",
        "pyembed",
        "pyo3",
        "pyo3-ffi",
        "pyo3-macros",
        "python3-sys",
        "rustpython-vm",
    ];
    let unmatched: Vec<&str> = banned
        .iter()
        .copied()
        .filter(|name: &&str| {
            !BANNED_PYTHON_RUNTIME_FAMILIES
                .iter()
                .any(|stem: &&str| is_family_member(name, stem))
        })
        .collect();
    assert!(
        unmatched.is_empty(),
        "these python runtime packages are not covered: {unmatched:?}"
    );

    let benign: [&str; 8] = [
        "disrobe-pass-pickle",
        "numpy-like",
        "pyo3ish",
        "python-launcher",
        "pythonize",
        "typenum",
        "unicode-ident",
        "zerocopy",
    ];
    let flagged: Vec<&str> = benign
        .iter()
        .copied()
        .filter(|name: &&str| {
            BANNED_PYTHON_RUNTIME_FAMILIES
                .iter()
                .any(|stem: &&str| is_family_member(name, stem))
        })
        .collect();
    assert_eq!(
        flagged,
        vec!["numpy-like"],
        "the matcher is anchored to a separator, so only the hyphenated family sibling matches: \
         {flagged:?}"
    );
}
