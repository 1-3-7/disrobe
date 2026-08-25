use std::path::Path;
use std::path::PathBuf;
#[cfg(feature = "jvm")]
use std::{collections::BTreeSet, fs::File, io::Read};

use disrobe_ir::Envelope;
use disrobe_ir::payload::DisasmPayload;
#[cfg(feature = "jvm")]
use disrobe_pass_jvm::{
    HierarchyKind, HierarchyNode, classfile_hierarchy_node, dex_hierarchy_nodes, parse_classfile,
};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::{
    CallSiteMatch, CapabilitySiteMatch, DecoderMatch, FunctionMatch, JvmImplementorResult, Module,
    Query, QueryResult, XrefMatch,
};
#[cfg(feature = "jvm")]
use disrobe_query::{
    JvmHierarchyNode, JvmTypeKind, MAX_JVM_HIERARCHY_EDGES, MAX_JVM_HIERARCHY_NODES,
};

use crate::cli::output::{self, OutputFormat};

#[cfg(feature = "jvm")]
const MAX_JVM_QUERY_INPUT_BYTES: usize = 64 * 1024 * 1024;
#[cfg(feature = "jvm")]
const MAX_REJECTED_ARTIFACT_DIAGNOSTICS: usize = 1_024;
#[cfg(feature = "jvm")]
const MAX_REJECTED_ARTIFACT_DIAGNOSTIC_BYTES: usize = 65_536;

#[cfg(feature = "jvm")]
struct DirectoryHierarchy {
    nodes: Vec<JvmHierarchyNode>,
    rejected_artifacts: Vec<String>,
    rejected_artifacts_truncated: bool,
}

pub(crate) fn run(input: PathBuf, expr: String, fmt: OutputFormat) -> miette::Result<()> {
    let query: Query = disrobe_query::parse_query(&expr)
        .map_err(|e| miette::miette!("DR-CLI-0832: invalid query `{expr}`: {e}"))?;
    let result: QueryResult = if let Query::ConcreteImplementors { target } = &query {
        QueryResult::ConcreteImplementors(load_jvm_implementors(&input, target)?)
    } else {
        let module: Module = load_module(&input)?;
        disrobe_query::run(&module, &query)
    };
    output::emit(fmt, &result, || render_text(&result))
}

#[cfg(feature = "jvm")]
fn load_jvm_implementors(input: &Path, target: &str) -> miette::Result<JvmImplementorResult> {
    if !input.is_dir() {
        return Ok(disrobe_query::resolve_jvm_implementors(
            target,
            &jvm_file_nodes(input)?,
        ));
    }
    let hierarchy: DirectoryHierarchy = class_directory_nodes(input)?;
    let mut result: JvmImplementorResult =
        disrobe_query::resolve_jvm_implementors(target, &hierarchy.nodes);
    let mut diagnostics: BTreeSet<disrobe_query::JvmHierarchyDiagnostic> =
        result.diagnostics.into_iter().collect();
    diagnostics.extend(
        hierarchy
            .rejected_artifacts
            .into_iter()
            .map(
                |artifact: String| disrobe_query::JvmHierarchyDiagnostic::RejectedArtifact {
                    artifact,
                },
            ),
    );
    if hierarchy.rejected_artifacts_truncated {
        diagnostics.insert(
            disrobe_query::JvmHierarchyDiagnostic::RejectedArtifactDiagnosticLimit {
                max: MAX_REJECTED_ARTIFACT_DIAGNOSTICS,
                max_bytes: MAX_REJECTED_ARTIFACT_DIAGNOSTIC_BYTES,
            },
        );
    }
    result.diagnostics = diagnostics.into_iter().collect();
    Ok(result)
}

#[cfg(feature = "jvm")]
fn class_directory_nodes(input: &Path) -> miette::Result<DirectoryHierarchy> {
    const MAX_ARTIFACT_FILES: usize = 16_384;
    const MAX_DIRECTORY_ENTRIES: usize = 32_768;
    const MAX_DIRECTORY_DEPTH: usize = 64;
    const MAX_DIRECTORY_BYTES: u64 = 256 * 1024 * 1024;
    let mut entries: usize = 0;
    let mut bytes: u64 = 0;
    let mut nodes: Vec<JvmHierarchyNode> = Vec::new();
    let mut edges: usize = 0;
    let mut artifacts: usize = 0;
    let mut rejected_artifacts: Vec<String> = Vec::new();
    let mut rejected_artifact_bytes: usize = 0;
    let mut rejected_artifacts_truncated: bool = false;
    for entry in walkdir::WalkDir::new(input)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry: walkdir::DirEntry = entry.map_err(|error: walkdir::Error| {
            miette::miette!("DR-CLI-0838: cannot traverse {}: {error}", input.display())
        })?;
        entries += 1;
        if entries > MAX_DIRECTORY_ENTRIES {
            return Err(miette::miette!(
                "DR-CLI-0840: {} contains more than {MAX_DIRECTORY_ENTRIES} directory entries",
                input.display()
            ));
        }
        if entry.depth() > MAX_DIRECTORY_DEPTH {
            return Err(miette::miette!(
                "DR-CLI-0841: {} exceeds the {MAX_DIRECTORY_DEPTH} directory-depth limit",
                input.display()
            ));
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let path: PathBuf = entry.into_path();
        if path.extension().is_some_and(|extension| {
            extension.eq_ignore_ascii_case("class") || extension.eq_ignore_ascii_case("dex")
        }) {
            artifacts += 1;
            if artifacts > MAX_ARTIFACT_FILES {
                return Err(miette::miette!(
                    "DR-CLI-0837: {} contains more than {MAX_ARTIFACT_FILES} JVM artifacts",
                    input.display()
                ));
            }
            let size: u64 = std::fs::metadata(&path)
                .map_err(|error: std::io::Error| {
                    miette::miette!("DR-CLI-0830: cannot read {}: {error}", path.display())
                })?
                .len();
            bytes = bytes.saturating_add(size);
            if bytes > MAX_DIRECTORY_BYTES {
                return Err(miette::miette!(
                    "DR-CLI-0842: {} exceeds the {MAX_DIRECTORY_BYTES} byte JVM directory-input limit",
                    input.display()
                ));
            }
            let mut artifact_nodes: Vec<JvmHierarchyNode> = if let Ok(nodes) = jvm_file_nodes(&path)
            {
                nodes
            } else {
                let artifact: String = path
                    .strip_prefix(input)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if rejected_artifacts.len() < MAX_REJECTED_ARTIFACT_DIAGNOSTICS
                    && rejected_artifact_bytes.saturating_add(artifact.len())
                        <= MAX_REJECTED_ARTIFACT_DIAGNOSTIC_BYTES
                {
                    rejected_artifact_bytes += artifact.len();
                    rejected_artifacts.push(artifact);
                } else {
                    rejected_artifacts_truncated = true;
                }
                continue;
            };
            edges = edges.saturating_add(
                artifact_nodes
                    .iter()
                    .map(|node: &JvmHierarchyNode| node.parents.len())
                    .sum::<usize>(),
            );
            if edges > MAX_JVM_HIERARCHY_EDGES {
                return Err(miette::miette!(
                    "DR-CLI-0843: {} exceeds the {MAX_JVM_HIERARCHY_EDGES} JVM hierarchy-edge limit",
                    input.display()
                ));
            }
            nodes.append(&mut artifact_nodes);
            if nodes.len() > MAX_JVM_HIERARCHY_NODES {
                return Err(miette::miette!(
                    "DR-CLI-0844: {} exceeds the {MAX_JVM_HIERARCHY_NODES} JVM hierarchy-node limit",
                    input.display()
                ));
            }
        }
    }
    Ok(DirectoryHierarchy {
        nodes,
        rejected_artifacts,
        rejected_artifacts_truncated,
    })
}

#[cfg(feature = "jvm")]
fn jvm_file_nodes(input: &Path) -> miette::Result<Vec<JvmHierarchyNode>> {
    let file: File = File::open(input)
        .map_err(|e| miette::miette!("DR-CLI-0830: cannot read {}: {e}", input.display()))?;
    let mut bytes: Vec<u8> = Vec::new();
    file.take((MAX_JVM_QUERY_INPUT_BYTES.saturating_add(1)) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| miette::miette!("DR-CLI-0830: cannot read {}: {e}", input.display()))?;
    if bytes.len() > MAX_JVM_QUERY_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0839: {} exceeds the {} byte JVM query input limit",
            input.display(),
            MAX_JVM_QUERY_INPUT_BYTES
        ));
    }
    let nodes: Vec<JvmHierarchyNode> = if bytes.starts_with(b"\xCA\xFE\xBA\xBE") {
        let class = parse_classfile(&bytes).map_err(|e| {
            miette::miette!(
                "DR-CLI-0834: cannot parse JVM class {}: {e}",
                input.display()
            )
        })?;
        let node: HierarchyNode = classfile_hierarchy_node(&class).map_err(|e| {
            miette::miette!(
                "DR-CLI-0834: cannot read JVM hierarchy {}: {e}",
                input.display()
            )
        })?;
        vec![query_node(&node)]
    } else if bytes.starts_with(b"dex\n") {
        dex_hierarchy_nodes(&bytes)
            .map_err(|e| {
                miette::miette!(
                    "DR-CLI-0835: cannot parse DEX hierarchy {}: {e}",
                    input.display()
                )
            })?
            .iter()
            .map(query_node)
            .collect()
    } else {
        return Err(miette::miette!(
            "DR-CLI-0836: {} is not a JVM .class or Android .dex input",
            input.display()
        ));
    };
    Ok(nodes)
}

#[cfg(not(feature = "jvm"))]
fn load_jvm_implementors(_input: &Path, _target: &str) -> miette::Result<JvmImplementorResult> {
    Err(miette::miette!(
        "DR-CLI-0836: JVM query support is not enabled in this build"
    ))
}

#[cfg(feature = "jvm")]
fn query_node(node: &HierarchyNode) -> JvmHierarchyNode {
    JvmHierarchyNode {
        descriptor: node.descriptor.clone(),
        kind: match node.kind {
            HierarchyKind::Interface => JvmTypeKind::Interface,
            HierarchyKind::Abstract => JvmTypeKind::Abstract,
            HierarchyKind::Concrete => JvmTypeKind::Concrete,
        },
        parents: node.parents.clone(),
    }
}

fn load_module(input: &Path) -> miette::Result<Module> {
    let bytes: Vec<u8> = std::fs::read(input)
        .map_err(|e| miette::miette!("DR-CLI-0830: cannot read {}: {e}", input.display()))?;
    if let Ok(env) = Envelope::decode(&bytes) {
        return disrobe_query::module_from_envelope(&env).map_err(|e| {
            miette::miette!(
                "DR-CLI-0831: {} is a .dr envelope but not queryable: {e}",
                input.display()
            )
        });
    }
    let payload: DisasmPayload = build_disasm_payload(&bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0833: {} is neither a Disasm- or Mir-rung .dr envelope nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    Ok(Module::from_disasm(&payload))
}

fn render_text(result: &QueryResult) {
    match result {
        QueryResult::Functions { matches } => render_functions("functions", matches),
        QueryResult::ComplexityOver { threshold, matches } => {
            println!("functions with cyclomatic complexity > {threshold}:");
            render_functions("", matches);
        }
        QueryResult::CallsTo { target, matches } => render_calls(target, matches),
        QueryResult::XrefsTo { symbol, matches } => render_xrefs(symbol, matches),
        QueryResult::StringDecoders { matches } => render_decoders(matches),
        QueryResult::CapabilitySites {
            capability,
            matches,
        } => render_capability(capability.label(), matches),
        QueryResult::ConcreteImplementors(result) => render_implementors(result),
        QueryResult::Unsupported { message } => println!("query unavailable: {message}"),
    }
}

fn render_implementors(result: &JvmImplementorResult) {
    println!(
        "concrete implementors of `{}` ({} match(es)):",
        terminal_safe_text(&result.target),
        result.matches.len()
    );
    for item in &result.matches {
        let proof: String = item
            .proof_path
            .iter()
            .map(|descriptor: &String| terminal_safe_text(descriptor))
            .collect::<Vec<String>>()
            .join(" -> ");
        println!("  {}  {proof}", terminal_safe_text(&item.descriptor));
    }
    for diagnostic in &result.diagnostics {
        println!("  diagnostic: {}", hierarchy_diagnostic(diagnostic));
    }
}

fn hierarchy_diagnostic(diagnostic: &disrobe_query::JvmHierarchyDiagnostic) -> String {
    match diagnostic {
        disrobe_query::JvmHierarchyDiagnostic::InvalidTarget { descriptor } => {
            format!(
                "invalid target descriptor `{}`",
                terminal_safe_text(descriptor)
            )
        }
        disrobe_query::JvmHierarchyDiagnostic::MissingTarget { descriptor } => {
            format!(
                "target `{}` is missing from the hierarchy",
                terminal_safe_text(descriptor)
            )
        }
        disrobe_query::JvmHierarchyDiagnostic::ConcreteTarget { descriptor } => {
            format!("target `{}` is concrete", terminal_safe_text(descriptor))
        }
        disrobe_query::JvmHierarchyDiagnostic::MalformedDescriptor { descriptor } => {
            format!("malformed descriptor `{}`", terminal_safe_text(descriptor))
        }
        disrobe_query::JvmHierarchyDiagnostic::MissingDefinition { child, parent } => {
            format!(
                "`{}` references missing parent `{}`",
                terminal_safe_text(child),
                terminal_safe_text(parent)
            )
        }
        disrobe_query::JvmHierarchyDiagnostic::RejectedArtifact { artifact } => {
            format!("rejected JVM artifact `{}`", terminal_safe_text(artifact))
        }
        disrobe_query::JvmHierarchyDiagnostic::DuplicateDefinition { descriptor } => {
            format!("duplicate definition `{}`", terminal_safe_text(descriptor))
        }
        disrobe_query::JvmHierarchyDiagnostic::SelfEdge { descriptor } => {
            format!("self edge `{}`", terminal_safe_text(descriptor))
        }
        disrobe_query::JvmHierarchyDiagnostic::Cycle { descriptors } => {
            format!(
                "hierarchy cycle {}",
                descriptors
                    .iter()
                    .map(|descriptor: &String| terminal_safe_text(descriptor))
                    .collect::<Vec<String>>()
                    .join(" -> ")
            )
        }
        disrobe_query::JvmHierarchyDiagnostic::NodeLimit { max } => {
            format!("only the first {max} hierarchy definitions were considered")
        }
        disrobe_query::JvmHierarchyDiagnostic::EdgeLimit { max } => {
            format!("only the first {max} hierarchy edges were considered")
        }
        disrobe_query::JvmHierarchyDiagnostic::DescriptorBytesLimit { max } => {
            format!("hierarchy descriptors exceed the {max} byte limit")
        }
        disrobe_query::JvmHierarchyDiagnostic::TargetDescriptorBytesLimit { max } => {
            format!("the target descriptor exceeds the {max} byte limit")
        }
        disrobe_query::JvmHierarchyDiagnostic::MatchLimit { max } => {
            format!("only the first {max} implementors were returned")
        }
        disrobe_query::JvmHierarchyDiagnostic::ProofDepthLimit { max } => {
            format!("proof path exceeds the {max} node limit")
        }
        disrobe_query::JvmHierarchyDiagnostic::ProofElementsLimit { max } => {
            format!("proof paths exceed the {max} element limit")
        }
        disrobe_query::JvmHierarchyDiagnostic::ProofBytesLimit { max } => {
            format!("proof paths exceed the {max} byte limit")
        }
        disrobe_query::JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit {
            max,
            max_bytes,
        } => {
            format!(
                "missing-definition diagnostics were limited to {max} identities and {max_bytes} bytes"
            )
        }
        disrobe_query::JvmHierarchyDiagnostic::RejectedArtifactDiagnosticLimit {
            max,
            max_bytes,
        } => format!(
            "rejected-artifact diagnostics were limited to {max} identities and {max_bytes} bytes"
        ),
        disrobe_query::JvmHierarchyDiagnostic::MalformedDescriptorDiagnosticLimit {
            max,
            max_bytes,
        } => {
            format!(
                "malformed descriptor diagnostics were limited to {max} identities and {max_bytes} bytes"
            )
        }
    }
}

fn terminal_safe_text(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
}

fn render_functions(header: &str, matches: &[FunctionMatch]) {
    if !header.is_empty() {
        println!("{} ({} match(es)):", header, matches.len());
    }
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let tag: &str = if m.is_export { " [export]" } else { "" };
        println!(
            "  {:#018x}  {:>4} insn  cc={:<3}  {}{}",
            m.address, m.instruction_count, m.complexity, m.name, tag
        );
    }
}

fn render_calls(target: &str, matches: &[CallSiteMatch]) {
    println!("calls to `{target}` ({} site(s)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        println!(
            "  {:#018x}  in {} -> {} ({:#x})",
            m.call_offset, m.caller, m.target, m.target_address
        );
    }
}

fn render_xrefs(symbol: &str, matches: &[XrefMatch]) {
    println!("references to `{symbol}` ({} xref(s)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let from: &str = m.from_function.as_deref().unwrap_or("<unknown>");
        println!(
            "  {:#018x}  {:<8} in {} -> {} ({:#x})",
            m.from_offset, m.mnemonic, from, m.to_symbol, m.to_address
        );
    }
}

fn render_decoders(matches: &[DecoderMatch]) {
    println!(
        "string-decoder-shaped functions ({} match(es)):",
        matches.len()
    );
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        println!(
            "  {:#018x}  {}  (loops={}, byte-arith={}, mem-ops={})",
            m.address, m.name, m.loop_back_edges, m.byte_arith_ops, m.memory_ops
        );
    }
}

fn render_capability(label: &str, matches: &[CapabilitySiteMatch]) {
    println!("{label} capability sites ({} match(es)):", matches.len());
    if matches.is_empty() {
        println!("  (none)");
        return;
    }
    for m in matches {
        let func: &str = m.function.as_deref().unwrap_or("<unknown>");
        println!(
            "  {:#018x}  {:<8} in {} -> {}",
            m.offset, m.mnemonic, func, m.symbol
        );
    }
}

#[cfg(all(test, feature = "jvm"))]
#[allow(clippy::expect_used)]
mod tests {
    use std::path::PathBuf;

    use sha2::{Digest, Sha256};

    #[cfg(windows)]
    use super::class_directory_nodes;
    use super::{hierarchy_diagnostic, load_jvm_implementors, terminal_safe_text};

    fn fixture(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../disrobe-pass-jvm/tests/fixtures/implementors")
            .join(path)
    }

    fn sha256(path: &std::path::Path) -> String {
        let bytes = std::fs::read(path).expect("fixture bytes");
        format!("{:x}", Sha256::digest(bytes))
    }

    fn provenance_value<'a>(provenance: &'a str, key: &str) -> &'a str {
        provenance
            .lines()
            .find_map(|line: &str| {
                line.split_once('=')
                    .and_then(|(candidate, value): (&str, &str)| {
                        (candidate.trim() == key).then(|| value.trim().trim_matches('"'))
                    })
            })
            .expect("provenance key")
    }

    #[test]
    fn text_renderer_escapes_terminal_control_characters() {
        assert_eq!(terminal_safe_text("Lpkg/\u{1b}[2J;"), "Lpkg/\\u{1b}[2J;");
    }

    #[test]
    fn missing_definition_truncation_has_a_distinct_text_diagnostic() {
        let diagnostic = disrobe_query::JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit {
            max: 16_384,
            max_bytes: 1_048_576,
        };
        assert_eq!(
            hierarchy_diagnostic(&diagnostic),
            "missing-definition diagnostics were limited to 16384 identities and 1048576 bytes"
        );
    }

    #[test]
    fn directory_and_dex_inputs_emit_the_same_machine_readable_implementors() {
        let target: &str = "Limplementors/Root;";
        let directory =
            load_jvm_implementors(&fixture("classes"), target).expect("class directory");
        let dex = load_jvm_implementors(&fixture("Hierarchy-d8.dex"), target).expect("dex");
        for result in [&directory, &dex] {
            let names: Vec<&str> = result
                .matches
                .iter()
                .map(|item| item.descriptor.as_str())
                .collect();
            assert_eq!(names, vec!["Limplementors/Direct;", "Limplementors/Leaf;"]);
            let encoded: serde_json::Value = serde_json::to_value(result).expect("json");
            assert_eq!(encoded["matches"].as_array().map(Vec::len), Some(2));
        }
    }

    #[test]
    fn directory_set_combines_distinct_dex_implementors() {
        let directory = tempfile::tempdir().expect("directory");
        std::fs::copy(
            fixture("Hierarchy-d8.dex"),
            directory.path().join("one.dex"),
        )
        .expect("first dex");
        std::fs::copy(fixture("Extra-d8.dex"), directory.path().join("two.dex"))
            .expect("second dex");
        let result =
            load_jvm_implementors(directory.path(), "Limplementors/Root;").expect("directory set");
        let names: Vec<&str> = result
            .matches
            .iter()
            .map(|item| item.descriptor.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "Limplementors/Direct;",
                "Limplementors/Extra;",
                "Limplementors/Leaf;"
            ]
        );
    }

    #[test]
    fn fixture_provenance_and_implementor_numerators_are_bound_to_the_inputs() {
        let provenance =
            std::fs::read_to_string(fixture("provenance.toml")).expect("fixture provenance");
        assert_eq!(
            sha256(&fixture("Hierarchy-d8.dex")),
            provenance_value(&provenance, "dex_sha256")
        );
        assert_eq!(
            sha256(&fixture("Extra-d8.dex")),
            provenance_value(&provenance, "extra_dex_sha256")
        );
        for name in [
            "Base.class",
            "Direct.class",
            "Leaf.class",
            "Middle.class",
            "Root.class",
        ] {
            let digest = sha256(&fixture(&format!("classes/{name}")));
            assert!(provenance.contains(&format!("\"{name}\" = \"{digest}\"")));
        }

        let target = "Limplementors/Root;";
        let classes = load_jvm_implementors(&fixture("classes"), target).expect("class result");
        let dex = load_jvm_implementors(&fixture("Hierarchy-d8.dex"), target).expect("dex result");
        let multidex = tempfile::tempdir().expect("multidex directory");
        std::fs::copy(fixture("Hierarchy-d8.dex"), multidex.path().join("one.dex"))
            .expect("first dex");
        std::fs::copy(fixture("Extra-d8.dex"), multidex.path().join("two.dex"))
            .expect("second dex");
        let combined = load_jvm_implementors(multidex.path(), target).expect("multidex result");
        let expected = provenance_value(&provenance, "expected_concrete_implementors")
            .parse::<usize>()
            .expect("expected count");
        let class_matches = provenance_value(&provenance, "class_matches")
            .parse::<usize>()
            .expect("class count");
        let dex_matches = provenance_value(&provenance, "single_dex_matches")
            .parse::<usize>()
            .expect("dex count");
        let multidex_matches = provenance_value(&provenance, "multidex_matches")
            .parse::<usize>()
            .expect("multidex count");
        assert_eq!((classes.matches.len(), expected), (class_matches, expected));
        assert_eq!((dex.matches.len(), expected), (dex_matches, expected));
        assert_eq!(combined.matches.len(), multidex_matches);
    }

    #[test]
    fn directory_query_reports_a_rejected_artifact_without_losing_valid_siblings() {
        let directory = tempfile::tempdir().expect("directory");
        std::fs::copy(
            fixture("Hierarchy-d8.dex"),
            directory.path().join("valid.dex"),
        )
        .expect("valid dex");
        std::fs::write(directory.path().join("broken.dex"), b"dex\n039\0").expect("broken dex");

        let result = load_jvm_implementors(directory.path(), "Limplementors/Root;")
            .expect("partial directory result");
        assert_eq!(result.matches.len(), 2);
        assert!(result.diagnostics.contains(
            &disrobe_query::JvmHierarchyDiagnostic::RejectedArtifact {
                artifact: "broken.dex".to_owned(),
            }
        ));
    }

    #[cfg(windows)]
    #[test]
    fn directory_query_does_not_follow_file_or_directory_symlinks() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let directory = tempfile::tempdir().expect("directory");
        let classes = fixture("classes");
        for name in [
            "Root.class",
            "Middle.class",
            "Base.class",
            "Direct.class",
            "Leaf.class",
        ] {
            std::fs::copy(classes.join(name), directory.path().join(name)).expect("copy class");
        }
        symlink_file(
            classes.join("Direct.class"),
            directory.path().join("linked-direct.class"),
        )
        .expect("file symlink");
        symlink_dir(&classes, directory.path().join("linked-classes")).expect("directory symlink");
        let hierarchy = class_directory_nodes(directory.path()).expect("directory hierarchy");
        assert_eq!(hierarchy.nodes.len(), 5);
    }
}
