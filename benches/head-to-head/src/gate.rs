use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use disrobe_core::recon::{ReconCategory, ReconConfig, ReconFinding, ReconReport, report_tree};
use disrobe_pass_pickle::{
    DecodedArg, Disassembly, Insn, Severity, VmTrace, analyze_safety, disassemble, execute,
    to_python,
};
use eyre::Result;
use serde_json::{Value, json};

use crate::apkleaks_capture::sha256_hex;
use crate::tool::{
    MAX_FIXTURE_BYTES, MAX_PICKLE_DEPTH, MAX_PICKLE_FILES, MAX_TEXT_BYTES, read_bounded_file,
    read_bounded_string,
};

const REQUIRED_PLANTED_CATEGORIES: &[ReconCategory] = &[
    ReconCategory::Endpoint,
    ReconCategory::Manifest,
    ReconCategory::Url,
    ReconCategory::Ipv4,
    ReconCategory::Email,
    ReconCategory::Onion,
];
const EXPECTED_PICKLE_FIXTURES: usize = 102;
const MALICIOUS_PICKLE_FIXTURES: [&str; 6] = [
    "malicious/p0/reduce_os_system.pkl",
    "malicious/p1/reduce_os_system.pkl",
    "malicious/p2/reduce_os_system.pkl",
    "malicious/p3/reduce_os_system.pkl",
    "malicious/p4/reduce_os_system.pkl",
    "malicious/p5/reduce_os_system.pkl",
];

pub fn measure(root: &Path) -> Result<(String, Value)> {
    let id: String = "gate-harvest".to_owned();
    let gates: Vec<Value> = vec![frisk_gauntlet_gate(root)?, pickle_corpus_gate(root)?];
    let value: Value = json!({
        "id": id,
        "title": "Gate-test harvest: independently graded recovery checks",
        "status": "ok",
        "ecosystem": "cross-ecosystem",
        "note": "Both measurements run their grading logic over the complete named fixture population. A missing fixture, unreadable member, hash mismatch, absent reference, traversal failure, recovery failure, or classification mismatch fails regeneration.",
        "gates": gates,
    });
    Ok((id, value))
}

fn frisk_gauntlet_gate(root: &Path) -> Result<Value> {
    let planted: PathBuf = root.join("corpus").join("recon").join("planted");
    if !planted.is_dir() {
        return Err(eyre::eyre!(
            "{} is the required planted recon corpus",
            planted.display()
        ));
    }
    let report: ReconReport = report_tree(&planted, &ReconConfig::default())
        .map_err(|error| eyre::eyre!("frisk scan of {} failed: {error}", planted.display()))?;
    let found: usize = REQUIRED_PLANTED_CATEGORIES
        .iter()
        .filter(|category: &&ReconCategory| {
            report
                .findings
                .iter()
                .any(|finding: &ReconFinding| finding.category == **category)
        })
        .count();
    if found != REQUIRED_PLANTED_CATEGORIES.len() {
        return Err(eyre::eyre!(
            "frisk planted-corpus gate detected {found} of {} required categories",
            REQUIRED_PLANTED_CATEGORIES.len()
        ));
    }
    Ok(gate_measured(
        "frisk-planted-recall",
        "frisk recon category recall on the committed planted ground-truth tree",
        "deliberately planted findings (endpoint, manifest, URL, IPv4, email, .onion) committed under corpus/recon/planted",
        found,
        REQUIRED_PLANTED_CATEGORIES.len(),
        "% of planted IOC categories detected",
        "cargo test -p disrobe-core --test frisk_gauntlet",
    ))
}

#[derive(Debug)]
struct PickleReference {
    opcodes: BTreeMap<String, Vec<String>>,
    args: BTreeMap<String, Vec<Vec<String>>>,
}

#[derive(serde::Deserialize)]
struct PickleManifest {
    sample: Vec<PickleManifestSample>,
}

#[derive(serde::Deserialize)]
struct PickleManifestSample {
    name: String,
    sha256: String,
}

fn pickle_corpus_gate(root: &Path) -> Result<Value> {
    let corpus: PathBuf = root.join("corpus").join("pickle");
    if !corpus.is_dir() {
        return Err(eyre::eyre!(
            "{} is the required pickle corpus",
            corpus.display()
        ));
    }
    let manifest: BTreeMap<String, String> =
        load_pickle_manifest(&corpus).map_err(|reason: String| eyre::eyre!(reason))?;
    let expected: BTreeSet<String> = manifest.keys().cloned().collect();
    if expected.len() != EXPECTED_PICKLE_FIXTURES {
        return Err(eyre::eyre!(
            "corpus/pickle/MANIFEST.toml must name the fixed {EXPECTED_PICKLE_FIXTURES}-fixture population; it names {}",
            expected.len()
        ));
    }
    let discovered: BTreeSet<String> =
        discover_pkl(&corpus).map_err(|reason: String| eyre::eyre!(reason))?;
    require_exact_membership("corpus/pickle/MANIFEST.toml", &expected, &discovered)
        .map_err(|reason: String| eyre::eyre!(reason))?;
    let reference: PickleReference =
        load_pickle_reference(&corpus).map_err(|reason: String| eyre::eyre!(reason))?;
    require_exact_membership(
        "corpus/pickle/opcode_ref.json",
        &expected,
        &reference.opcodes.keys().cloned().collect(),
    )
    .map_err(|reason: String| eyre::eyre!(reason))?;
    require_exact_membership(
        "corpus/pickle/arg_ref.json",
        &expected,
        &reference.args.keys().cloned().collect(),
    )
    .map_err(|reason: String| eyre::eyre!(reason))?;
    for (relative, digest) in &manifest {
        grade_pickle_fixture(&corpus, relative, digest, &reference)
            .map_err(|reason: String| eyre::eyre!(reason))?;
    }
    let total: usize = manifest.len();
    Ok(gate_measured(
        "pickle-corpus-coverage",
        "pickle corpus recovery against the committed pickletools reference",
        "every manifest-declared fixture is verified by SHA-256, compared opcode-for-opcode and argument-for-argument with the committed CPython pickletools reference, symbolically executed, rendered, and classified from its manifest path",
        total,
        total,
        "% of manifest-declared pickle fixtures fully graded",
        "cargo test -p disrobe-pass-pickle --test corpus",
    ))
}

fn load_pickle_manifest(corpus: &Path) -> std::result::Result<BTreeMap<String, String>, String> {
    let path: PathBuf = corpus.join("MANIFEST.toml");
    let raw: String = read_bounded_string(&path, MAX_TEXT_BYTES)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    parse_pickle_manifest(&raw)
}

fn parse_pickle_manifest(raw: &str) -> std::result::Result<BTreeMap<String, String>, String> {
    let parsed: PickleManifest =
        toml::from_str(raw).map_err(|error| format!("invalid pickle manifest TOML: {error}"))?;
    if parsed.sample.len() > MAX_PICKLE_FILES {
        return Err(format!(
            "pickle manifest declares more than {MAX_PICKLE_FILES} samples"
        ));
    }
    let mut samples: BTreeMap<String, String> = BTreeMap::new();
    for sample in parsed.sample {
        insert_manifest_sample(&mut samples, sample.name, sample.sha256)?;
    }
    if samples.is_empty() {
        return Err("corpus/pickle/MANIFEST.toml declares no samples".to_owned());
    }
    Ok(samples)
}

fn insert_manifest_sample(
    samples: &mut BTreeMap<String, String>,
    name: String,
    digest: String,
) -> std::result::Result<(), String> {
    if !safe_pickle_relative_name(&name) {
        return Err(format!("pickle manifest sample has an unsafe name: {name}"));
    }
    if digest.len() != 64 || !digest.bytes().all(|byte: u8| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "pickle manifest sample {name} has an invalid SHA-256"
        ));
    }
    if samples
        .insert(name.clone(), digest.to_ascii_lowercase())
        .is_some()
    {
        return Err(format!("pickle manifest repeats sample {name}"));
    }
    Ok(())
}

fn safe_pickle_relative_name(name: &str) -> bool {
    let path: &Path = Path::new(name);
    path.extension().and_then(|extension| extension.to_str()) == Some("pkl")
        && !name.contains('\\')
        && path
            .components()
            .all(|component: Component<'_>| matches!(component, Component::Normal(_)))
}

fn load_pickle_reference(corpus: &Path) -> std::result::Result<PickleReference, String> {
    let opcode_path: PathBuf = corpus.join("opcode_ref.json");
    let argument_path: PathBuf = corpus.join("arg_ref.json");
    let opcode_raw: String = read_bounded_string(&opcode_path, MAX_TEXT_BYTES)
        .map_err(|error| format!("{} could not be read: {error}", opcode_path.display()))?;
    let argument_raw: String = read_bounded_string(&argument_path, MAX_TEXT_BYTES)
        .map_err(|error| format!("{} could not be read: {error}", argument_path.display()))?;
    Ok(PickleReference {
        opcodes: serde_json::from_str(&opcode_raw)
            .map_err(|error| format!("{} is invalid: {error}", opcode_path.display()))?,
        args: serde_json::from_str(&argument_raw)
            .map_err(|error| format!("{} is invalid: {error}", argument_path.display()))?,
    })
}

fn discover_pkl(corpus: &Path) -> std::result::Result<BTreeSet<String>, String> {
    let mut paths: BTreeSet<String> = BTreeSet::new();
    collect_pkl(corpus, corpus, &mut paths, 0)?;
    Ok(paths)
}

fn collect_pkl(
    corpus: &Path,
    dir: &Path,
    out: &mut BTreeSet<String>,
    depth: usize,
) -> std::result::Result<(), String> {
    if depth > MAX_PICKLE_DEPTH {
        return Err(format!(
            "pickle corpus nesting exceeds {MAX_PICKLE_DEPTH} levels"
        ));
    }
    let entries: std::fs::ReadDir = std::fs::read_dir(dir)
        .map_err(|error| format!("could not traverse {}: {error}", dir.display()))?;
    let mut sorted: Vec<(PathBuf, std::fs::FileType)> = Vec::new();
    for entry in entries {
        let entry: std::fs::DirEntry =
            entry.map_err(|error| format!("could not traverse {}: {error}", dir.display()))?;
        let path: PathBuf = entry.path();
        let kind: std::fs::FileType = entry
            .file_type()
            .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
        sorted.push((path, kind));
    }
    sorted.sort_by(|(left, _), (right, _)| left.cmp(right));
    for (path, kind) in sorted {
        if kind.is_dir() {
            collect_pkl(corpus, &path, out, depth.saturating_add(1))?;
        } else if kind.is_file() && path.extension().and_then(|value| value.to_str()) == Some("pkl")
        {
            if out.len() >= MAX_PICKLE_FILES {
                return Err(format!(
                    "pickle fixture count exceeds {MAX_PICKLE_FILES} files"
                ));
            }
            let relative: &Path = path
                .strip_prefix(corpus)
                .map_err(|error| format!("{} escaped the corpus: {error}", path.display()))?;
            let name: String = relative
                .components()
                .map(|component: Component<'_>| {
                    component.as_os_str().to_string_lossy().into_owned()
                })
                .collect::<Vec<_>>()
                .join("/");
            if !out.insert(name.clone()) {
                return Err(format!("pickle corpus repeats fixture {name}"));
            }
        } else if path.extension().and_then(|value| value.to_str()) == Some("pkl") {
            return Err(format!(
                "pickle corpus member is not a regular file: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn require_exact_membership(
    source: &str,
    expected: &BTreeSet<String>,
    actual: &BTreeSet<String>,
) -> std::result::Result<(), String> {
    if expected == actual {
        return Ok(());
    }
    let missing: Vec<&String> = expected.difference(actual).collect();
    let extra: Vec<&String> = actual.difference(expected).collect();
    Err(format!(
        "{source} names a different pickle population; missing {missing:?}, extra {extra:?}"
    ))
}

fn grade_pickle_fixture(
    corpus: &Path,
    relative: &str,
    expected_digest: &str,
    reference: &PickleReference,
) -> std::result::Result<(), String> {
    let path: PathBuf = corpus.join(relative);
    let bytes: Vec<u8> = read_bounded_file(&path, MAX_FIXTURE_BYTES)
        .map_err(|error| format!("{relative}: fixture could not be read: {error}"))?;
    let digest: String = sha256_hex(&bytes);
    if digest != expected_digest {
        return Err(format!(
            "{relative}: fixture hashes {digest}, but MANIFEST.toml records {expected_digest}"
        ));
    }
    let disassembly: Disassembly =
        disassemble(&bytes).map_err(|error| format!("{relative}: disassembly failed: {error}"))?;
    if disassembly.stop_offset.is_none() {
        return Err(format!("{relative}: opcode stream has no STOP"));
    }
    let actual_opcodes: Vec<String> = disassembly
        .instructions
        .iter()
        .map(|instruction: &Insn| instruction.name.clone())
        .collect();
    if reference.opcodes.get(relative) != Some(&actual_opcodes) {
        return Err(format!(
            "{relative}: opcode stream differs from the CPython pickletools reference"
        ));
    }
    let actual_args: Vec<Vec<String>> = disassembly
        .instructions
        .iter()
        .map(|instruction: &Insn| canon_arg(&instruction.name, &instruction.arg))
        .collect();
    if reference.args.get(relative) != Some(&actual_args) {
        return Err(format!(
            "{relative}: decoded arguments differ from the CPython pickletools reference"
        ));
    }
    let trace: VmTrace = execute(&disassembly)
        .map_err(|error| format!("{relative}: symbolic execution failed: {error}"))?;
    if to_python(&trace.result).is_empty() {
        return Err(format!(
            "{relative}: symbolic result rendered as empty Python"
        ));
    }
    let flagged: bool = analyze_safety(&trace).severity == Severity::OvertlyMalicious;
    let expected_flagged: bool = MALICIOUS_PICKLE_FIXTURES.contains(&relative);
    if flagged != expected_flagged {
        return Err(format!(
            "{relative}: classification mismatch; expected OvertlyMalicious={expected_flagged}, got OvertlyMalicious={flagged}"
        ));
    }
    Ok(())
}

fn canon_arg(name: &str, arg: &DecodedArg) -> Vec<String> {
    let mut out: Vec<String> = vec![name.to_owned()];
    match arg {
        DecodedArg::None => out.push("none".to_owned()),
        DecodedArg::Bool(value) => {
            out.push("int".to_owned());
            out.push(if *value { "1" } else { "0" }.to_owned());
        }
        DecodedArg::Int(value) => {
            out.push("int".to_owned());
            out.push(value.to_string());
        }
        DecodedArg::BigInt(value) => {
            out.push("int".to_owned());
            out.push(value.clone());
        }
        DecodedArg::Float(value) => {
            out.push("float".to_owned());
            out.push(hex_lower(&value.to_be_bytes()));
        }
        DecodedArg::Str(value) => {
            out.push("str".to_owned());
            out.push(value.clone());
        }
        DecodedArg::Bytes(value) => {
            out.push("bytes".to_owned());
            out.push(hex_lower(value));
        }
        DecodedArg::GlobalPair { module, name } => {
            out.push("pair".to_owned());
            out.push(module.clone());
            out.push(name.clone());
        }
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn gate_measured(
    id: &str,
    title: &str,
    reference: &str,
    ok: usize,
    total: usize,
    metric: &str,
    reproduce: &str,
) -> Value {
    let pct: f64 = 100.0 * ok as f64 / total.max(1) as f64;
    json!({
        "id": id,
        "title": title,
        "status": "ok",
        "oracle": reference,
        "metric": metric,
        "ok": ok,
        "total": total,
        "value": pct,
        "display": format!("{ok}/{total} ({pct:.1}%)"),
        "reproduce": reproduce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::published::checked_workspace_root;

    #[test]
    fn pickle_gate_grades_the_manifest_population() -> core::result::Result<(), String> {
        let gate: Value =
            pickle_corpus_gate(&checked_workspace_root()).map_err(|error| error.to_string())?;
        assert_eq!(gate["status"], "ok");
        assert_eq!(gate["ok"], gate["total"]);
        assert_eq!(gate["total"], EXPECTED_PICKLE_FIXTURES);
        Ok(())
    }

    #[test]
    fn manifest_parser_rejects_missing_hash_and_unsafe_name() {
        assert!(parse_pickle_manifest("[[sample]]\nname = \"benign/p0/int.pkl\"\n").is_err());
        let unsafe_name: &str = "[[sample]]\nname = \"../escape.pkl\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n";
        assert!(parse_pickle_manifest(unsafe_name).is_err());
        let normal_toml: &str = "# corpus\n[[sample]] # fixture\nname=\"benign/p0/int.pkl\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\" # digest\n";
        assert_eq!(
            parse_pickle_manifest(normal_toml).map(|samples| samples.len()),
            Ok(1)
        );
        let duplicate_name: &str = "[[sample]]\nname = \"same.pkl\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\n[[sample]]\nname = \"same.pkl\"\nsha256 = \"1111111111111111111111111111111111111111111111111111111111111111\"\n";
        assert!(parse_pickle_manifest(duplicate_name).is_err());
    }

    #[test]
    fn membership_check_rejects_unlisted_pickle() {
        let expected: BTreeSet<String> = BTreeSet::from(["listed.pkl".to_owned()]);
        let actual: BTreeSet<String> = ["listed.pkl".to_owned(), "extra.pkl".to_owned()]
            .into_iter()
            .collect();
        assert!(matches!(
            require_exact_membership("manifest", &expected, &actual),
            Err(error) if error.contains("extra.pkl")
        ));
    }
}
