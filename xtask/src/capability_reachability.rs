use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

use crate::facts::{attribute_spans, balanced_region, cited_function_region, function_is_ignored};
use crate::fileio::read_text_bounded;
use crate::health::workspace_members;

const MAX_LIB_RS_BYTES: u64 = 1 << 20;
const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

const PASS_CRATE_PREFIX: &str = "disrobe-pass-";
const EXTRA_PASS_CRATE: &str = "disrobe-binfmt";

const CHAIN_REGISTRY_SOURCE: &str = "crates/disrobe-passes/src/lib.rs";
const CHAIN_REGISTRY_FN: &str = "build_registry";
const CHAIN_REGISTER_CALL: &str = "r.register(&";
const CHAIN_DETECTOR_ANCHOR: &str = "::chain_detector::";
const PASSES_MANIFEST: &str = "crates/disrobe-passes/Cargo.toml";

const NAMED_CONSUMER_SURFACES: [(&str, &str); 4] = [
    ("cli", "disrobe-cli"),
    ("mcp", "disrobe-mcp"),
    ("python", "disrobe-python"),
    ("playground", "disrobe-playground"),
];
const OTHER_WORKSPACE_SURFACE: &str = "other-workspace";
const NON_CRATE_WORKSPACE_MEMBERS: &[&str] = &["xtask"];

const MIN_IN_SCOPE_CRATES: usize = 26;
const MIN_CHAIN_REGISTRATIONS: usize = 26;
const MIN_CANDIDATE_CAPABILITIES: usize = 1_100;
const MIN_GRADED_CAPABILITIES: usize = 920;
const MIN_CONSUMER_FILES: usize = 450;

const UNREACHABLE_CEILING: &[(&str, usize, &str)] = &[
    (
        "disrobe-binfmt",
        2,
        "clear_overrides and is_skip_magic are internal carve/external-tool helpers exercised only \
         by their own unit test; the carve and external-tool paths that would call them route \
         through a different function",
    ),
    (
        "disrobe-pass-as3",
        2,
        "detect_source_or_binary is a narrower sibling of the detector the chain and CLI call, and \
         render_as3_with_header is one of this workspace's per-language provenance-header \
         renderers, proven by a real test but never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-beam",
        3,
        "all three are per-dialect provenance-header renderers, proven by a real test but never \
         spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-dotnet",
        8,
        "decompile_method and emit_csharp are lower-level steps the real decompile entry point \
         wraps, plan_execution is a protector planner the CLI does not yet call ahead of \
         extraction, capture_observations is feature-gated parser instrumentation for the seed \
         reach harness, and four are per-dialect provenance-header renderers never spliced into \
         `--emit` output path",
    ),
    (
        "disrobe-pass-go",
        2,
        "probe_thunk_literals is a garble string-recovery helper only its own oracle drives \
         directly, and one is the per-language provenance-header renderer never spliced into the \
         `--emit` output path",
    ),
    (
        "disrobe-pass-js-deob",
        34,
        "most are jscrambler per-template deobfuscators and jsconfuser shape detectors exercised \
         one at a time by their own oracle rather than through a single dispatcher, plus bundler, \
         source-map and TypeScript-recovery helpers with the same shape and four per-dialect \
         provenance-header renderers never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-jvm",
        20,
        "most are convenience wrappers a sibling function already exposes to real callers \
         (assemble_jar, decompile_classfile_bytes, emit_method_body and friends), detector \
         variants proven by their own gauntlet test (detect_rasp_in_apk, \
         detect_allatori_watermarks, upstream_status), and two per-dialect provenance-header \
         renderers never spliced into the `--emit` output path; the JNI header emitter pair this \
         count once carried is now wired to `disrobe jvm jni`",
    ),
    (
        "disrobe-pass-lua",
        2,
        "both are per-dialect provenance-header renderers, proven by a real test but never spliced \
         into the `--emit` output path",
    ),
    (
        "disrobe-pass-mobile",
        18,
        "Dart, Flutter and Hermes parsing and demangling helpers each proven by their own oracle \
         but not yet called from the crate's own extraction entry points, one more of the same \
         shape added when the pinned Dart declaration graph moved into this crate from the \
         now-retired disrobe-dart, plus four per-dialect provenance-header renderers never \
         spliced into the `--emit` output path. One more entered this count only when per-version \
         opcode tables gave it its first grading test: hermes_opcode_label re-exports a label \
         lookup the crate resolves internally through opcode_label, and it is deliberately not \
         wired because it is hardcoded to the HBC96 table while the crate now decodes v76 and v84 \
         through their own tables, so calling it would label those versions wrongly",
    ),
    (
        "disrobe-pass-native",
        64,
        "the largest single group in this sweep: convenience wrappers over a sibling variant the \
         real caller uses (apply_patches over apply_patches_reported, collect_recovered_symbols \
         over the _with_oep form, discover_functions over discover_functions_with_status, and \
         more of the same shape), unpack_* entries for the 17 of 29 packer families \
         packer-roster's own count already states chain_detector does not dispatch to, \
         reconstruction and recovery helpers proven by a dedicated oracle test but not yet called \
         from the CLI's native subcommands, fixture builders exposed publicly for their own tests, \
         and three per-language provenance-header renderers never spliced into the `--emit` \
         output path, plus the public sparse integer arity adapter retained for library users",
    ),
    (
        "disrobe-pass-nuitka",
        13,
        "manifest, surface and constant-blob builders proven by their own test but not yet called \
         from the crate's extraction entry point, plus one provenance-header renderer never \
         spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-php",
        10,
        "CFG and protector-container builders proven by their own oracle, a tokenizer and a bcg \
         header reader with the same shape, plus two per-dialect provenance-header renderers \
         never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-pickle",
        2,
        "analyze_deep is a narrower sibling of the safety scan the real entry point calls, and \
         version is a crate-version getter exercised only by its own test",
    ),
    (
        "disrobe-pass-py-deob",
        5,
        "the hyperion v2v3 layer-peeling helpers and recover_pyc_zipper are proven by their own \
         oracle but not yet called from the crate's dispatch entry point, plus one \
         provenance-header renderer never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-py-disasm",
        5,
        "build_cfg, render_dot and the exception-table renderers are proven by their own test but \
         not yet called from the crate's disassembly entry point, plus one provenance-header \
         renderer never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-pyarmor",
        7,
        "bcc dispatch, lift, link and recovery helpers proven by their own oracle but not yet \
         called from the crate's extraction entry point, plus one provenance-header renderer \
         never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-pyfreeze",
        1,
        "the one finding is the provenance-header renderer, proven by a real test but never \
         spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-pyinstaller",
        7,
        "dependency-tree, manifest and pyz-extraction helpers proven by their own test but not yet \
         called from the crate's extraction entry point, plus one provenance-header renderer \
         never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-ruby",
        6,
        "yarv disassembly and opcode-table helpers proven by their own test but not yet called \
         from the crate's decompile entry point, plus two per-dialect provenance-header renderers \
         never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-scriptlang",
        2,
        "route_cross_target is proven by a real haxe fixture but the routing decision is not yet \
         made from the crate's own dispatch path, and one is the provenance-header renderer never \
         spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-shell",
        10,
        "PowerShell AST and obfuscation-bible parsers, a batch CFG resolver and reverser, and a \
         bash tokenizer, each proven by their own test but not yet called from the crate's \
         dispatch entry point, plus four per-dialect provenance-header renderers never spliced \
         into the `--emit` output path",
    ),
    (
        "disrobe-pass-sourcedefender",
        5,
        "decrypt, extract and recover helpers proven by their own oracle but not yet called from \
         the crate's dispatch entry point, plus one provenance-header renderer never spliced into \
         the `--emit` output path",
    ),
    (
        "disrobe-pass-swift-objc",
        9,
        "entitlement, import-thunk, selector-index and dyld-cache-reconstruction helpers proven by \
         their own oracle but not yet called from the crate's analyze entry point, plus two \
         per-dialect provenance-header renderers never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-wasm-deob",
        36,
        "the second-largest group in this sweep: per-obfuscator reverse, detect and lift helpers \
         (wasmixer, wobfuscator, jscrambler, tigress) and per-feature scanners (SIMD, threads, \
         tail calls, GC externals, custom page sizes) each proven by their own oracle but driven \
         one at a time rather than from a single dispatcher, plus four per-language \
         provenance-header renderers never spliced into the `--emit` output path",
    ),
    (
        "disrobe-pass-webview",
        2,
        "carve and detect_family are proven by a real electron oracle but never called from any \
         consumer surface; the crate's own chain_detector is registered in \
         crates/disrobe-passes/src/lib.rs and reaches `disrobe auto`, and carve_report is wired to \
         the dedicated `disrobe webview` command, so neither counts as uncalled here",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainStatus {
    Default,
    NonDefaultFeature,
    NotRegistered,
}

#[derive(Debug)]
struct CrateInfo {
    dir: String,
    mod_path: String,
    chain_status: ChainStatus,
    chain_feature: Option<String>,
}

#[derive(Debug, Clone)]
struct Capability {
    crate_dir: String,
    original_name: String,
    public_name: String,
    defining_file: String,
}

#[derive(Debug, Default, Clone, Copy)]
struct Surfaces {
    cli: bool,
    mcp: bool,
    python: bool,
    playground: bool,
    other_workspace: bool,
    internal: bool,
}

impl Surfaces {
    const fn any_external(self) -> bool {
        self.cli || self.mcp || self.python || self.playground || self.other_workspace
    }

    fn label(self) -> String {
        let mut on: Vec<&str> = Vec::with_capacity(6);
        if self.cli {
            on.push("cli");
        }
        if self.mcp {
            on.push("mcp");
        }
        if self.python {
            on.push("python");
        }
        if self.playground {
            on.push("playground");
        }
        if self.other_workspace {
            on.push(OTHER_WORKSPACE_SURFACE);
        }
        if self.internal {
            on.push("internal");
        }
        if on.is_empty() {
            "none".to_owned()
        } else {
            on.join("+")
        }
    }
}

struct ConsumerFile {
    production_text: String,
}

struct ConsumerIndex {
    surfaces: BTreeMap<String, Vec<ConsumerFile>>,
    total_files: usize,
    other_workspace_crates: Vec<String>,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let crate_dirs: Vec<String> = discover_in_scope_crates(root)?;
    if crate_dirs.len() < MIN_IN_SCOPE_CRATES {
        bail!(
            "the capability-reachability sweep resolved {} pass crate(s) under `crates/`, fewer \
             than the {MIN_IN_SCOPE_CRATES} this check requires; a walk that finds almost nothing \
             would silently evaluate almost nothing",
            crate_dirs.len()
        );
    }

    let registry_text: String = read_repo_text(root, CHAIN_REGISTRY_SOURCE)?;
    let full_features: BTreeSet<String> = parse_full_features(root)?;
    let registrations: BTreeMap<String, (String, bool)> =
        parse_chain_registrations(&registry_text, &full_features)?;
    if registrations.len() < MIN_CHAIN_REGISTRATIONS {
        bail!(
            "the capability-reachability sweep parsed {} chain registration(s) out of `fn \
             {CHAIN_REGISTRY_FN}` in {CHAIN_REGISTRY_SOURCE}, fewer than the \
             {MIN_CHAIN_REGISTRATIONS} this check requires; the anchor this sweep reads may have \
             moved, which would silently reclassify every pass as chain-unreachable",
            registrations.len()
        );
    }

    let crates: Vec<CrateInfo> = build_crate_infos(&crate_dirs, &registrations)?;

    let mut candidates: Vec<Capability> = Vec::new();
    for info in &crates {
        candidates.extend(discover_capabilities(root, &info.dir)?);
    }
    candidates.sort_by(|a: &Capability, b: &Capability| {
        (&a.crate_dir, &a.public_name).cmp(&(&b.crate_dir, &b.public_name))
    });
    if candidates.len() < MIN_CANDIDATE_CAPABILITIES {
        bail!(
            "the capability-reachability sweep enumerated {} public function(s) across every \
             in-scope pass crate's `src/lib.rs` surface, fewer than the \
             {MIN_CANDIDATE_CAPABILITIES} this check requires; the `pub use` and `pub fn` reader \
             may have broken, which would silently shrink the population this sweep grades",
            candidates.len()
        );
    }

    let consumer_index: ConsumerIndex = build_consumer_index(root, &crate_dirs)?;
    if consumer_index.total_files < MIN_CONSUMER_FILES {
        bail!(
            "the capability-reachability sweep indexed {} consumer source file(s) across cli, \
             mcp, python, playground and {} other workspace crate(s), fewer than the \
             {MIN_CONSUMER_FILES} this check requires; a walk that finds almost nothing on the \
             consumer side would report every capability unreachable or every capability \
             reachable, neither of which is measured",
            consumer_index.total_files,
            consumer_index.other_workspace_crates.len(),
        );
    }

    let crate_by_dir: BTreeMap<&str, &CrateInfo> = crates
        .iter()
        .map(|c: &CrateInfo| (c.dir.as_str(), c))
        .collect();

    let mut graded_count: usize = 0;
    let mut ungraded_count: usize = 0;
    let mut orphans: Vec<String> = Vec::new();
    let mut orphan_counts_by_crate: BTreeMap<String, usize> = BTreeMap::new();
    let mut dedicated_only: Vec<String> = Vec::new();
    let mut non_default_feature: Vec<String> = Vec::new();

    for candidate in &candidates {
        let Some(evidence) = grading_evidence(root, candidate)? else {
            ungraded_count += 1;
            continue;
        };
        graded_count += 1;

        let info: &CrateInfo = crate_by_dir
            .get(candidate.crate_dir.as_str())
            .ok_or_else(|| {
                eyre::eyre!(
                    "capability `{}` in `{}` has no matching CrateInfo, which the discovery step \
                 should never allow",
                    candidate.public_name,
                    candidate.crate_dir
                )
            })?;

        let mut surfaces: Surfaces = classify_surfaces(candidate, info, &consumer_index);
        surfaces.internal = internal_caller_exists(root, candidate)?;
        let auto_reachable: bool = info.chain_status == ChainStatus::Default && surfaces.internal;
        let reachable: bool = surfaces.any_external() || auto_reachable;

        if !reachable {
            *orphan_counts_by_crate
                .entry(candidate.crate_dir.clone())
                .or_insert(0) += 1;
            orphans.push(format!(
                "{}::{} (defined in {}, graded by {}) is public, tested and uncalled from CLI, \
                 MCP, python, playground, any other workspace crate or the auto-chain; \
                 surfaces=[{}], chain={}",
                candidate.crate_dir,
                candidate.public_name,
                candidate.defining_file,
                evidence.render(),
                surfaces.label(),
                chain_status_label(info),
            ));
        } else if surfaces.any_external() && !auto_reachable {
            dedicated_only.push(format!(
                "{}::{} is reachable via [{}] but not from `disrobe auto` (chain={})",
                candidate.crate_dir,
                candidate.public_name,
                surfaces.label(),
                chain_status_label(info),
            ));
        }

        if info.chain_status == ChainStatus::NonDefaultFeature && surfaces.internal {
            non_default_feature.push(format!(
                "{}::{} is used inside its own crate and the crate is chain-registered behind \
                 non-default feature `{}`",
                candidate.crate_dir,
                candidate.public_name,
                info.chain_feature.as_deref().unwrap_or("?"),
            ));
        }
    }

    if graded_count < MIN_GRADED_CAPABILITIES {
        bail!(
            "the capability-reachability sweep found {graded_count} public function(s) with a \
             passing, non-vacuous test out of {} candidate(s) across every in-scope pass crate, \
             fewer than the {MIN_GRADED_CAPABILITIES} this check requires; the test-body reader \
             may have broken, which would silently shrink this sweep's reachability population to \
             a fraction of what the tree actually carries",
            candidates.len()
        );
    }

    orphans.sort();
    dedicated_only.sort();
    non_default_feature.sort();

    let mut ceiling_issues: Vec<String> = Vec::new();
    for (ceiling_crate, declared, _) in UNREACHABLE_CEILING {
        if !crate_dirs.iter().any(|dir: &String| dir == ceiling_crate) {
            ceiling_issues.push(format!(
                "UNREACHABLE_CEILING names {ceiling_crate}, which is no longer an in-scope pass \
                 crate; drop the entry"
            ));
            continue;
        }
        let actual: usize = orphan_counts_by_crate
            .get(*ceiling_crate)
            .copied()
            .unwrap_or(0);
        match actual.cmp(declared) {
            std::cmp::Ordering::Greater => ceiling_issues.push(format!(
                "{ceiling_crate} carries {actual} uncalled graded capability(ies), above the \
                 declared ceiling of {declared}; a new one landed. Name it in the finding list \
                 above, decide whether to wire it up, and raise the ceiling in \
                 UNREACHABLE_CEILING with the reason if it stays uncalled on purpose"
            )),
            std::cmp::Ordering::Less => ceiling_issues.push(format!(
                "{ceiling_crate} carries {actual} uncalled graded capability(ies), below the \
                 declared ceiling of {declared}; something got wired up. Lower the ceiling in \
                 UNREACHABLE_CEILING so the gate keeps ratcheting"
            )),
            std::cmp::Ordering::Equal => {}
        }
    }
    for (orphan_crate, actual) in &orphan_counts_by_crate {
        if !UNREACHABLE_CEILING
            .iter()
            .any(|(ceiling_crate, _, _): &(&str, usize, &str)| ceiling_crate == orphan_crate)
        {
            ceiling_issues.push(format!(
                "{orphan_crate} carries {actual} uncalled graded capability(ies) and has no \
                 UNREACHABLE_CEILING entry, so its declared ceiling is zero; name it in the \
                 finding list above and add an entry with the reason"
            ));
        }
    }
    ceiling_issues.sort();

    println!(
        "xtask capability-reachability: {} pass crate(s), {} candidate public function(s), \
         {graded_count} graded by a passing non-vacuous test ({ungraded_count} carry no such \
         test and are excluded), {} public/tested/uncalled capability(ies) across {} crate(s), \
         {} reachable only from a dedicated surface and not `disrobe auto`, {} reachable only \
         behind a non-default feature, evaluated against disrobe-passes's `full` feature set \
         ({} feature(s)) and against {} other workspace crate(s) beyond cli/mcp/python/playground",
        crate_dirs.len(),
        candidates.len(),
        orphans.len(),
        orphan_counts_by_crate.len(),
        dedicated_only.len(),
        non_default_feature.len(),
        full_features.len(),
        consumer_index.other_workspace_crates.len(),
    );
    for line in &orphans {
        println!("  [uncalled] {line}");
    }
    for line in &dedicated_only {
        println!("  [dedicated-only] {line}");
    }

    if !ceiling_issues.is_empty() {
        bail!(
            "xtask capability-reachability: {} per-crate ceiling mismatch(es):\n  {}",
            ceiling_issues.len(),
            ceiling_issues.join("\n  ")
        );
    }
    Ok(())
}

const fn chain_status_label(info: &CrateInfo) -> &'static str {
    match info.chain_status {
        ChainStatus::Default => "registered (default feature set)",
        ChainStatus::NonDefaultFeature => "registered (non-default feature)",
        ChainStatus::NotRegistered => "not registered",
    }
}

fn read_repo_text(root: &Path, relative: &str) -> Result<String> {
    read_text_bounded(&root.join(relative), MAX_SOURCE_BYTES)
        .wrap_err_with(|| format!("reading {relative}"))
}

fn discover_in_scope_crates(root: &Path) -> Result<Vec<String>> {
    let crates_dir: PathBuf = root.join("crates");
    let mut found: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&crates_dir)
        .wrap_err_with(|| format!("reading {}", crates_dir.display()))?
    {
        let entry: std::fs::DirEntry = entry.wrap_err("walking crates/ for pass crates")?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !entry.path().is_dir() {
            continue;
        }
        if name.starts_with(PASS_CRATE_PREFIX) || name == EXTRA_PASS_CRATE {
            let lib_rs: PathBuf = crates_dir.join(&name).join("src").join("lib.rs");
            if !lib_rs.is_file() {
                bail!(
                    "{name} matches the pass-crate scope this sweep evaluates but has no \
                     src/lib.rs; a pass crate with no public surface cannot be graded for \
                     reachability"
                );
            }
            found.insert(name);
        }
    }
    Ok(found.into_iter().collect())
}

fn parse_full_features(root: &Path) -> Result<BTreeSet<String>> {
    let text: String = read_text_bounded(&root.join(PASSES_MANIFEST), MAX_MANIFEST_BYTES)
        .wrap_err_with(|| format!("reading {PASSES_MANIFEST}"))?;
    let doc: toml::Value =
        toml::from_str(&text).wrap_err_with(|| format!("parsing {PASSES_MANIFEST}"))?;
    let array: &Vec<toml::Value> = doc
        .get("features")
        .and_then(|f: &toml::Value| f.get("full"))
        .and_then(toml::Value::as_array)
        .ok_or_else(|| {
            eyre::eyre!(
                "{PASSES_MANIFEST} carries no [features] full = [...] array; the sweep cannot \
                 tell which chain registrations are active by default"
            )
        })?;
    let features: BTreeSet<String> = array
        .iter()
        .filter_map(|v: &toml::Value| v.as_str().map(str::to_owned))
        .collect();
    if features.is_empty() {
        bail!("{PASSES_MANIFEST}'s [features] full array parsed to zero entries");
    }
    Ok(features)
}

fn parse_chain_registrations(
    registry_text: &str,
    full_features: &BTreeSet<String>,
) -> Result<BTreeMap<String, (String, bool)>> {
    let region: &str =
        cited_function_region(registry_text, CHAIN_REGISTRY_FN).ok_or_else(|| {
            eyre::eyre!(
                "{CHAIN_REGISTRY_SOURCE} no longer defines a delimitable `fn {CHAIN_REGISTRY_FN}`, \
             so the chain registration surface every reachability verdict depends on is derived \
             from nothing"
            )
        })?;
    let spans: Vec<(usize, usize)> = attribute_spans(region);

    let mut out: BTreeMap<String, (String, bool)> = BTreeMap::new();
    for (at, _) in region.match_indices(CHAIN_REGISTER_CALL) {
        let after_call: &str = region
            .get(at + CHAIN_REGISTER_CALL.len()..)
            .ok_or_else(|| eyre::eyre!("truncated `{CHAIN_REGISTER_CALL}` call site"))?;
        let anchor: usize = after_call.find(CHAIN_DETECTOR_ANCHOR).ok_or_else(|| {
            eyre::eyre!(
                "a `{CHAIN_REGISTER_CALL}` call site in {CHAIN_REGISTRY_SOURCE} does not reach \
                 `{CHAIN_DETECTOR_ANCHOR}` before running out of text, so the registered crate's \
                 module path cannot be read"
            )
        })?;
        let mod_path: &str = after_call[..anchor].trim();
        if mod_path.is_empty()
            || !mod_path
                .chars()
                .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            bail!(
                "a `{CHAIN_REGISTER_CALL}` call site in {CHAIN_REGISTRY_SOURCE} names module path \
                 `{mod_path}`, which is not a plain Rust identifier this sweep can parse"
            );
        }

        let feature: Option<String> = nearest_preceding_attribute(region, &spans, at)
            .map(str::trim)
            .map(|attr: &str| extract_cfg_feature(attr))
            .transpose()?;
        let Some(feature) = feature else {
            out.insert(mod_path.to_owned(), (String::new(), true));
            continue;
        };
        let is_default: bool = full_features.contains(&feature);
        out.insert(mod_path.to_owned(), (feature, is_default));
    }
    Ok(out)
}

fn nearest_preceding_attribute<'a>(
    text: &'a str,
    spans: &[(usize, usize)],
    at: usize,
) -> Option<&'a str> {
    let head: &str = text.get(..at)?;
    let boundary: usize = head.trim_end().len();
    let &(start, end): &(usize, usize) = spans
        .iter()
        .rev()
        .find(|(_, end): &&(usize, usize)| *end == boundary)?;
    text.get(start..end)
}

fn extract_cfg_feature(attribute: &str) -> Result<String> {
    let needle: &str = "feature = \"";
    let at: usize = attribute.find(needle).ok_or_else(|| {
        eyre::eyre!(
            "chain registration attribute `{attribute}` is not a plain `#[cfg(feature = \"...\")]`, \
             which is the only shape this sweep parses"
        )
    })?;
    let rest: &str = &attribute[at + needle.len()..];
    let close: usize = rest.find('"').ok_or_else(|| {
        eyre::eyre!("chain registration attribute `{attribute}` never closes its feature string")
    })?;
    Ok(rest[..close].to_owned())
}

fn build_crate_infos(
    crate_dirs: &[String],
    registrations: &BTreeMap<String, (String, bool)>,
) -> Result<Vec<CrateInfo>> {
    let mut by_mod_path: BTreeSet<String> = BTreeSet::new();
    let mut infos: Vec<CrateInfo> = Vec::with_capacity(crate_dirs.len());
    for dir in crate_dirs {
        let mod_path: String = dir.replace('-', "_");
        let entry: Option<&(String, bool)> = registrations.get(&mod_path);
        let (chain_status, chain_feature): (ChainStatus, Option<String>) = match entry {
            None => (ChainStatus::NotRegistered, None),
            Some((feature, true)) => (
                ChainStatus::Default,
                (!feature.is_empty()).then(|| feature.clone()),
            ),
            Some((feature, false)) => (ChainStatus::NonDefaultFeature, Some(feature.clone())),
        };
        if entry.is_some() {
            by_mod_path.insert(mod_path.clone());
        }
        infos.push(CrateInfo {
            dir: dir.clone(),
            mod_path,
            chain_status,
            chain_feature,
        });
    }

    for mod_path in registrations.keys() {
        if !by_mod_path.contains(mod_path) {
            bail!(
                "`{CHAIN_REGISTRY_SOURCE}` registers module path `{mod_path}`, which does not \
                 match any in-scope pass crate directory this sweep discovered under `crates/`; \
                 either the crate is out of this sweep's scope or the module-path-to-directory \
                 transform (replace `-` with `_`) no longer holds"
            );
        }
    }
    Ok(infos)
}

fn discover_capabilities(root: &Path, crate_dir: &str) -> Result<Vec<Capability>> {
    let lib_rs_rel: String = format!("crates/{crate_dir}/src/lib.rs");
    let lib_rs: String = read_text_bounded(&root.join(&lib_rs_rel), MAX_LIB_RS_BYTES)
        .wrap_err_with(|| format!("reading {lib_rs_rel}"))?;

    let mut out: Vec<Capability> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for name in direct_pub_fns(&lib_rs) {
        if seen.insert(name.clone()) {
            out.push(Capability {
                crate_dir: crate_dir.to_owned(),
                original_name: name.clone(),
                public_name: name,
                defining_file: lib_rs_rel.clone(),
            });
        }
    }

    let src_files: Vec<PathBuf> = list_rs_files(&root.join("crates").join(crate_dir).join("src"))?;
    for (original_name, public_name) in reexported_names(&lib_rs)? {
        if !seen.insert(public_name.clone()) {
            continue;
        }
        let Some(defining_file) = find_definition_file(root, &src_files, &original_name)? else {
            continue;
        };
        out.push(Capability {
            crate_dir: crate_dir.to_owned(),
            original_name,
            public_name,
            defining_file,
        });
    }

    Ok(out)
}

fn direct_pub_fns(lib_rs: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (at, _) in lib_rs.match_indices("pub fn ") {
        let name: &str = lib_rs[at + "pub fn ".len()..]
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .next()
            .unwrap_or_default();
        if !name.is_empty() {
            names.push(name.to_owned());
        }
    }
    names
}

fn reexported_names(lib_rs: &str) -> Result<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut search_from: usize = 0;
    while let Some(rel) = lib_rs[search_from..].find("pub use ") {
        let start: usize = search_from + rel + "pub use ".len();
        let end: usize = find_top_level_semicolon(lib_rs, start)?;
        let statement: &str = &lib_rs[start..end];
        flatten_use_items(statement, &mut out)?;
        search_from = end + 1;
    }
    Ok(out)
}

fn find_top_level_semicolon(text: &str, from: usize) -> Result<usize> {
    let mut depth: i32 = 0;
    for (offset, ch) in text[from..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            ';' if depth == 0 => return Ok(from + offset),
            _ => {}
        }
    }
    bail!("a `pub use` statement starting at byte {from} never reaches a top-level `;`")
}

fn flatten_use_items(statement: &str, out: &mut Vec<(String, String)>) -> Result<()> {
    let Some(brace) = statement.find('{') else {
        let (original, public): (String, String) = split_use_leaf(statement.trim());
        out.push((original, public));
        return Ok(());
    };
    let close: usize = statement.rfind('}').ok_or_else(|| {
        eyre::eyre!("`pub use {statement}` opens a group with `{{` but never closes it with `}}`")
    })?;
    if close < brace {
        bail!("`pub use {statement}` closes a group before it opens one");
    }
    let inner: &str = &statement[brace + 1..close];
    for item in split_top_level_commas(inner) {
        let item: &str = item.trim();
        if item.is_empty() {
            continue;
        }
        if item.contains('{') {
            flatten_use_items(item, out)?;
        } else {
            let (original, public): (String, String) = split_use_leaf(item);
            out.push((original, public));
        }
    }
    Ok(())
}

fn split_top_level_commas(text: &str) -> Vec<&str> {
    let mut items: Vec<&str> = Vec::new();
    let mut depth: i32 = 0;
    let mut start: usize = 0;
    for (offset, ch) in text.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                items.push(&text[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    items.push(&text[start..]);
    items
}

fn split_use_leaf(item: &str) -> (String, String) {
    let (path, alias): (&str, Option<&str>) = match item.split_once(" as ") {
        Some((p, a)) => (p.trim(), Some(a.trim())),
        None => (item, None),
    };
    let original: &str = path.rsplit("::").next().unwrap_or(path).trim();
    let public: &str = alias.unwrap_or(original);
    (original.to_owned(), public.to_owned())
}

fn list_rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir).sort_by_file_name() {
        let entry: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", dir.display()))?;
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|e| e.to_str()) == Some("rs")
        {
            out.push(entry.into_path());
        }
    }
    Ok(out)
}

fn find_definition_file(root: &Path, src_files: &[PathBuf], name: &str) -> Result<Option<String>> {
    for path in src_files {
        let text: String = read_text_bounded(path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        if contains_definition(&text, name) {
            let relative: String = path.strip_prefix(root).map_or_else(
                |_| path.to_string_lossy().into_owned(),
                |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
            );
            return Ok(Some(relative));
        }
    }
    Ok(None)
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_fn_keyword_immediately_before(text: &str, at: usize) -> bool {
    let head: &str = text[..at].trim_end();
    let Some(before_fn) = head.strip_suffix("fn") else {
        return false;
    };
    before_fn
        .chars()
        .next_back()
        .is_none_or(|c: char| !is_ident_char(c))
}

fn contains_definition(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, _)| {
        let before_boundary: bool = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c: char| !is_ident_char(c));
        let after: &str = &text[at + name.len()..];
        let after_ok: bool = after
            .chars()
            .next()
            .is_some_and(|c: char| c == '(' || c == '<' || c.is_whitespace());
        before_boundary && after_ok && is_fn_keyword_immediately_before(text, at)
    })
}

fn contains_real_call(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(at, _)| {
        let before_boundary: bool = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c: char| !is_ident_char(c));
        let after: &str = &text[at + name.len()..];
        let after_ok: bool = after.trim_start().starts_with('(');
        before_boundary && after_ok && !is_fn_keyword_immediately_before(text, at)
    })
}

struct GradingEvidence {
    location: String,
    test_name: String,
}

impl GradingEvidence {
    fn render(&self) -> String {
        format!("{}::{}", self.location, self.test_name)
    }
}

fn grading_evidence(root: &Path, candidate: &Capability) -> Result<Option<GradingEvidence>> {
    let tests_dir: PathBuf = root.join("crates").join(&candidate.crate_dir).join("tests");
    if tests_dir.is_dir() {
        for path in list_rs_files(&tests_dir)? {
            let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
                .wrap_err_with(|| format!("reading {}", path.display()))?;
            if let Some(test_name) = find_grading_test(&text, candidate) {
                let relative: String = path.strip_prefix(root).map_or_else(
                    |_| path.to_string_lossy().into_owned(),
                    |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
                );
                return Ok(Some(GradingEvidence {
                    location: relative,
                    test_name,
                }));
            }
        }
    }

    let src_dir: PathBuf = root.join("crates").join(&candidate.crate_dir).join("src");
    for path in list_rs_files(&src_dir)? {
        let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        for block in cfg_test_blocks(&text)? {
            if let Some(test_name) = find_grading_test(block, candidate) {
                let relative: String = path.strip_prefix(root).map_or_else(
                    |_| path.to_string_lossy().into_owned(),
                    |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
                );
                return Ok(Some(GradingEvidence {
                    location: format!("{relative}#[cfg(test)]"),
                    test_name,
                }));
            }
        }
    }
    Ok(None)
}

fn find_grading_test(text: &str, candidate: &Capability) -> Option<String> {
    for (name, body) in test_functions(text) {
        let calls: bool = contains_real_call(body, &candidate.original_name)
            || contains_real_call(body, &candidate.public_name);
        if calls && body.contains("assert") {
            return Some(name);
        }
    }
    None
}

fn test_functions(text: &str) -> Vec<(String, &str)> {
    let spans: Vec<(usize, usize)> = attribute_spans(text);
    let mut out: Vec<(String, &str)> = Vec::new();
    for &(start, end) in &spans {
        let Some(attr) = text.get(start..end) else {
            continue;
        };
        if attr.trim() != "#[test]" {
            continue;
        }
        let Some(fn_at) = skip_to_fn_keyword(text, end) else {
            continue;
        };
        if function_is_ignored(text, &spans, fn_at) {
            continue;
        }
        let name_start: usize = fn_at + "fn ".len();
        let Some(name) = text.get(name_start..).and_then(|rest: &str| {
            let n: &str = rest
                .split(|c: char| !is_ident_char(c))
                .next()
                .unwrap_or_default();
            (!n.is_empty()).then(|| n.to_owned())
        }) else {
            continue;
        };
        let Some(open_rel) = text.get(fn_at..).and_then(|rest: &str| rest.find('{')) else {
            continue;
        };
        let Some(body) = balanced_region(text, fn_at + open_rel) else {
            continue;
        };
        out.push((name, body));
    }
    out
}

fn skip_attributes_and_whitespace(text: &str, from: usize) -> Option<usize> {
    let mut cursor: usize = from;
    loop {
        let rest: &str = text.get(cursor..)?;
        let trimmed: &str = rest.trim_start();
        cursor += rest.len() - trimmed.len();
        let rest: &str = text.get(cursor..)?;
        if rest.starts_with('#') {
            let (_, end): (usize, usize) = *attribute_spans(rest).first()?;
            cursor += end;
            continue;
        }
        return Some(cursor);
    }
}

fn skip_to_fn_keyword(text: &str, from: usize) -> Option<usize> {
    let cursor: usize = skip_attributes_and_whitespace(text, from)?;
    text.get(cursor..)?.starts_with("fn ").then_some(cursor)
}

fn skip_to_mod_keyword(text: &str, from: usize) -> Option<usize> {
    let cursor: usize = skip_attributes_and_whitespace(text, from)?;
    text.get(cursor..)?.starts_with("mod ").then_some(cursor)
}

enum CfgTestModule<'a> {
    Inline(&'a str),
    External(&'a str),
}

fn cfg_test_modules(text: &str) -> Result<Vec<(usize, usize, CfgTestModule<'_>)>> {
    let spans: Vec<(usize, usize)> = attribute_spans(text);
    let mut out: Vec<(usize, usize, CfgTestModule<'_>)> = Vec::new();
    for &(start, end) in &spans {
        let Some(attr) = text.get(start..end) else {
            continue;
        };
        if attr.trim() != "#[cfg(test)]" {
            continue;
        }
        let Some(mod_at) = skip_to_mod_keyword(text, end) else {
            continue;
        };
        let after_mod: &str = &text[mod_at + "mod ".len()..];
        let name_end: usize = after_mod
            .find(|c: char| !is_ident_char(c))
            .unwrap_or(after_mod.len());
        let name: &str = &after_mod[..name_end];
        let punct: &str = after_mod[name_end..].trim_start();
        if punct.starts_with(';') {
            out.push((start, end, CfgTestModule::External(name)));
            continue;
        }
        let Some(brace_rel) = after_mod.find('{') else {
            bail!(
                "`#[cfg(test)] mod {name}` neither opens a `{{` nor terminates with `;`, which \
                 are the only two module-declaration shapes this sweep parses"
            );
        };
        let open: usize = mod_at + "mod ".len() + brace_rel;
        let Some(body) = balanced_region(text, open) else {
            bail!("`#[cfg(test)] mod {name}` block at byte {open} never closes its `{{`");
        };
        out.push((start, open + body.len(), CfgTestModule::Inline(body)));
    }
    Ok(out)
}

fn cfg_test_blocks(text: &str) -> Result<Vec<&str>> {
    Ok(cfg_test_modules(text)?
        .into_iter()
        .filter_map(
            |(_, _, module): (usize, usize, CfgTestModule<'_>)| match module {
                CfgTestModule::Inline(body) => Some(body),
                CfgTestModule::External(_) => None,
            },
        )
        .collect())
}

pub(crate) fn strip_cfg_test(text: &str) -> Result<String> {
    let mut cuts: Vec<(usize, usize)> = cfg_test_modules(text)?
        .into_iter()
        .map(|(start, end, _): (usize, usize, CfgTestModule<'_>)| (start, end))
        .collect();
    cuts.sort_unstable();
    let mut production: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for (start, end) in cuts {
        if start < cursor {
            continue;
        }
        production.push_str(&text[cursor..start]);
        cursor = end;
    }
    production.push_str(&text[cursor..]);
    Ok(production)
}

fn cfg_test_external_module_names(text: &str) -> Result<Vec<String>> {
    Ok(cfg_test_modules(text)?
        .into_iter()
        .filter_map(
            |(_, _, module): (usize, usize, CfgTestModule<'_>)| match module {
                CfgTestModule::External(name) => Some(name.to_owned()),
                CfgTestModule::Inline(_) => None,
            },
        )
        .collect())
}

fn production_rs_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let all_files: Vec<PathBuf> = list_rs_files(dir)?;
    let mut excluded: BTreeSet<PathBuf> = BTreeSet::new();
    for path in &all_files {
        let text: String = read_text_bounded(path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        for name in cfg_test_external_module_names(&text)? {
            let parent: &Path = path.parent().unwrap_or(dir);
            let as_file: PathBuf = parent.join(format!("{name}.rs"));
            let as_dir_mod: PathBuf = parent.join(&name).join("mod.rs");
            if as_file.is_file() {
                excluded.insert(as_file);
            }
            if as_dir_mod.is_file() {
                excluded.insert(as_dir_mod);
            }
        }
    }
    Ok(all_files
        .into_iter()
        .filter(|path: &PathBuf| !excluded.contains(path))
        .collect())
}

fn workspace_member_dirs(root: &Path) -> Result<BTreeSet<String>> {
    let manifest_rel: &str = "Cargo.toml";
    let text: String = read_text_bounded(&root.join(manifest_rel), MAX_MANIFEST_BYTES)
        .wrap_err_with(|| format!("reading {manifest_rel}"))?;
    let doc: toml::Value =
        toml::from_str(&text).wrap_err_with(|| format!("parsing {manifest_rel}"))?;
    Ok(workspace_members(&doc))
}

fn index_surface(label: &str, dir: &Path) -> Result<(String, Vec<ConsumerFile>)> {
    if !dir.is_dir() {
        bail!(
            "consumer surface `{label}` names {}, which is not a directory",
            dir.display()
        );
    }
    let mut files: Vec<ConsumerFile> = Vec::new();
    for path in production_rs_files(dir)? {
        let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let production_text: String = strip_cfg_test(&text)
            .wrap_err_with(|| format!("stripping test regions from {}", path.display()))?;
        files.push(ConsumerFile { production_text });
    }
    Ok((label.to_owned(), files))
}

fn build_consumer_index(root: &Path, in_scope_crate_dirs: &[String]) -> Result<ConsumerIndex> {
    let mut surfaces: BTreeMap<String, Vec<ConsumerFile>> = BTreeMap::new();
    let mut total_files: usize = 0;
    let mut named_dirs: BTreeSet<&str> = BTreeSet::new();

    for (label, dir_name) in NAMED_CONSUMER_SURFACES {
        named_dirs.insert(dir_name);
        let (label, files): (String, Vec<ConsumerFile>) =
            index_surface(label, &root.join("crates").join(dir_name).join("src"))?;
        total_files += files.len();
        surfaces.insert(label, files);
    }

    let members: BTreeSet<String> = workspace_member_dirs(root)?;
    let in_scope: BTreeSet<&str> = in_scope_crate_dirs.iter().map(String::as_str).collect();
    let mut other_workspace_crates: Vec<String> = Vec::new();
    let mut other_files: Vec<ConsumerFile> = Vec::new();
    for member in &members {
        let basename: &str = member.rsplit('/').next().unwrap_or(member.as_str());
        if named_dirs.contains(basename)
            || in_scope.contains(basename)
            || NON_CRATE_WORKSPACE_MEMBERS.contains(&basename)
        {
            continue;
        }
        let src_dir: PathBuf = root.join(member).join("src");
        if !src_dir.is_dir() {
            continue;
        }
        other_workspace_crates.push(basename.to_owned());
        let (_, mut files): (String, Vec<ConsumerFile>) =
            index_surface(OTHER_WORKSPACE_SURFACE, &src_dir)?;
        other_files.append(&mut files);
    }
    total_files += other_files.len();
    surfaces.insert(OTHER_WORKSPACE_SURFACE.to_owned(), other_files);

    Ok(ConsumerIndex {
        surfaces,
        total_files,
        other_workspace_crates,
    })
}

fn classify_surfaces(candidate: &Capability, info: &CrateInfo, index: &ConsumerIndex) -> Surfaces {
    let mut surfaces: Surfaces = Surfaces::default();
    for (label, files) in &index.surfaces {
        let hit: bool = files.iter().any(|file: &ConsumerFile| {
            file.production_text.contains(&info.mod_path)
                && (contains_real_call(&file.production_text, &candidate.public_name)
                    || contains_real_call(&file.production_text, &candidate.original_name))
        });
        match label.as_str() {
            "cli" => surfaces.cli = hit,
            "mcp" => surfaces.mcp = hit,
            "python" => surfaces.python = hit,
            "playground" => surfaces.playground = hit,
            OTHER_WORKSPACE_SURFACE => surfaces.other_workspace = hit,
            _ => {}
        }
    }
    surfaces
}

fn internal_caller_exists(root: &Path, candidate: &Capability) -> Result<bool> {
    let src_dir: PathBuf = root.join("crates").join(&candidate.crate_dir).join("src");
    for path in production_rs_files(&src_dir)? {
        let text: String = read_text_bounded(&path, MAX_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let production_text: String = strip_cfg_test(&text)
            .wrap_err_with(|| format!("stripping test regions from {}", path.display()))?;
        if contains_real_call(&production_text, &candidate.original_name)
            || contains_real_call(&production_text, &candidate.public_name)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(name: &str) -> Capability {
        Capability {
            crate_dir: "disrobe-pass-example".to_owned(),
            original_name: name.to_owned(),
            public_name: name.to_owned(),
            defining_file: "crates/disrobe-pass-example/src/lib.rs".to_owned(),
        }
    }

    #[test]
    fn a_test_that_calls_and_asserts_is_grading_evidence() {
        let text: &str = "#[test]\nfn probe() {\n    let out = emit_prototypes(&[]);\n    \
                           assert!(out.is_empty());\n}\n";
        let cap: Capability = capability("emit_prototypes");
        assert_eq!(find_grading_test(text, &cap), Some("probe".to_owned()));
    }

    #[test]
    fn a_test_that_calls_but_never_asserts_is_not_grading_evidence() {
        let text: &str = "#[test]\nfn probe() {\n    let _out = emit_prototypes(&[]);\n}\n";
        let cap: Capability = capability("emit_prototypes");
        assert_eq!(find_grading_test(text, &cap), None);
    }

    #[test]
    fn an_ignored_test_is_not_grading_evidence() {
        let text: &str = "#[test]\n#[ignore]\nfn probe() {\n    let out = \
                           emit_prototypes(&[]);\n    assert!(out.is_empty());\n}\n";
        let cap: Capability = capability("emit_prototypes");
        assert_eq!(find_grading_test(text, &cap), None);
    }

    #[test]
    fn a_test_that_never_calls_the_candidate_is_not_grading_evidence() {
        let text: &str = "#[test]\nfn probe() {\n    let out = other_function(&[]);\n    assert!(out.is_empty());\n}\n";
        let cap: Capability = capability("emit_prototypes");
        assert_eq!(find_grading_test(text, &cap), None);
    }

    #[test]
    fn an_early_return_skip_before_a_real_assertion_still_grades() {
        let text: &str = "#[test]\nfn probe() {\n    if find_tool().is_none() {\n        \
                           return;\n    }\n    let out = emit_prototypes(&[]);\n    \
                           assert_eq!(out.len(), 0);\n}\n";
        let cap: Capability = capability("emit_prototypes");
        assert_eq!(find_grading_test(text, &cap), Some("probe".to_owned()));
    }

    #[test]
    fn a_definition_site_is_not_a_call_site() {
        let text: &str = "pub fn emit_prototypes(methods: &[Native]) -> Vec<Proto> { Vec::new() }";
        assert!(!contains_real_call(text, "emit_prototypes"));
        assert!(contains_definition(text, "emit_prototypes"));
    }

    #[test]
    fn a_call_with_a_trailing_generic_argument_is_still_a_definition_not_a_call() {
        let text: &str = "pub fn parse<T>(bytes: &[u8]) -> T { unimplemented!() }";
        assert!(contains_definition(text, "parse"));
        assert!(!contains_real_call(text, "parse"));
    }

    #[test]
    fn a_call_shaped_substring_inside_a_longer_identifier_does_not_match() {
        let text: &str = "let value = reemit_prototypes(bytes);";
        assert!(!contains_real_call(text, "emit_prototypes"));
    }

    #[test]
    fn use_group_flattening_resolves_aliases_and_nesting() -> Result<()> {
        let mut out: Vec<(String, String)> = Vec::new();
        flatten_use_items(
            "jni::{analyze as analyze_jni_surface, emit_prototypes as emit_jni_prototypes, \
             native_methods_from_class}",
            &mut out,
        )?;
        assert!(out.contains(&("analyze".to_owned(), "analyze_jni_surface".to_owned())));
        assert!(out.contains(&(
            "emit_prototypes".to_owned(),
            "emit_jni_prototypes".to_owned()
        )));
        assert!(out.contains(&(
            "native_methods_from_class".to_owned(),
            "native_methods_from_class".to_owned()
        )));
        Ok(())
    }

    #[test]
    fn strip_cfg_test_removes_the_module_and_keeps_production_code() -> Result<()> {
        let text: &str = "pub fn carve() {}\n\n#[cfg(test)]\nmod tests {\n    fn helper() {}\n}\n\npub fn carve_report() {}\n";
        let production: String = strip_cfg_test(text)?;
        assert!(production.contains("pub fn carve()"));
        assert!(production.contains("pub fn carve_report()"));
        assert!(!production.contains("fn helper"));
        Ok(())
    }

    #[test]
    fn extract_cfg_feature_reads_the_feature_name() -> Result<()> {
        assert_eq!(
            extract_cfg_feature("#[cfg(feature = \"webview\")]")?,
            "webview"
        );
        Ok(())
    }

    #[test]
    fn extract_cfg_feature_refuses_a_compound_cfg() {
        assert!(extract_cfg_feature("#[cfg(any(unix, windows))]").is_err());
    }

    #[test]
    fn an_external_cfg_test_module_declaration_does_not_break_stripping() -> Result<()> {
        let text: &str = "pub fn carve() {}\n\n#[cfg(test)]\nmod tests;\n";
        let production: String = strip_cfg_test(text)?;
        assert!(production.contains("pub fn carve()"));
        let externals: Vec<String> = cfg_test_external_module_names(text)?;
        assert_eq!(externals, vec!["tests".to_owned()]);
        assert!(cfg_test_blocks(text)?.is_empty());
        Ok(())
    }

    #[test]
    fn a_second_attribute_stacked_between_cfg_test_and_mod_still_strips_the_block() -> Result<()> {
        let text: &str = "pub fn emit_prototypes() {}\n\n#[cfg(test)]\n#[allow(clippy::unwrap_used)]\nmod tests {\n    fn probe() {\n        let _ = emit_prototypes();\n    }\n}\n";
        let production: String = strip_cfg_test(text)?;
        assert!(production.contains("pub fn emit_prototypes()"));
        assert!(!production.contains("fn probe"));
        assert!(!contains_real_call(&production, "emit_prototypes"));
        let blocks: Vec<&str> = cfg_test_blocks(text)?;
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].contains("fn probe"));
        Ok(())
    }
}
