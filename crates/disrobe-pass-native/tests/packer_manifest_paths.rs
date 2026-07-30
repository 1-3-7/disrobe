#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use std::path::{Path, PathBuf};

use packer_fixture::{FixtureRequirement, REQUIRE_FIXTURES_VAR, fixture_requirement, is_committed};
use toml::Value;

#[derive(Debug, Clone, Copy)]
struct PathKey {
    path: &'static str,
    provenance: &'static str,
    reason: &'static str,
}

const PATH_KEYS: [PathKey; 4] = [
    PathKey {
        path: "packed_path",
        provenance: "packed_provenance",
        reason: "packed_unobtainable_reason",
    },
    PathKey {
        path: "unpacked_path",
        provenance: "unpacked_provenance",
        reason: "unpacked_unobtainable_reason",
    },
    PathKey {
        path: "original_path",
        provenance: "original_provenance",
        reason: "original_unobtainable_reason",
    },
    PathKey {
        path: "disrobe_original_path",
        provenance: "disrobe_original_provenance",
        reason: "disrobe_original_unobtainable_reason",
    },
];

const CORPUS_PREFIX: &str = "corpus/native/packers/";
const COMMITTED_WORD: &str = "committed";
const LOCAL_WORD: &str = "local";
const UNOBTAINABLE_WORD: &str = "local-unobtainable";
const RECIPE_KEY: &str = "local_fixture_recipe";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[allow(clippy::panic)]
fn manifest() -> toml::Table {
    let path: PathBuf = repo_root().join("corpus/native/packers/MANIFEST.toml");
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e: std::io::Error| {
        panic!(
            "the packer manifest must be readable at {}: {e}",
            path.display()
        )
    });
    text.parse::<toml::Table>()
        .unwrap_or_else(|e: toml::de::Error| panic!("the packer manifest must be valid TOML: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Provenance {
    Committed,
    Local,
    Unobtainable,
}

fn parse_provenance(raw: &str) -> Option<Provenance> {
    match raw.trim() {
        COMMITTED_WORD => Some(Provenance::Committed),
        LOCAL_WORD => Some(Provenance::Local),
        UNOBTAINABLE_WORD => Some(Provenance::Unobtainable),
        _ => None,
    }
}

#[derive(Debug)]
struct DeclaredPath {
    label: String,
    key: &'static str,
    provenance_key: &'static str,
    reason_key: &'static str,
    declared: String,
    provenance: Option<String>,
    reason: Option<String>,
    recipe: Option<String>,
    absent_is_recorded: bool,
}

fn declared_paths(manifest: &toml::Table) -> Vec<DeclaredPath> {
    let packers: &[Value] = manifest
        .get("packers")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let mut out: Vec<DeclaredPath> = Vec::new();
    for packer in packers {
        let family: &str = packer
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unnamed packer>");
        let recipe: Option<String> = packer
            .get(RECIPE_KEY)
            .and_then(Value::as_str)
            .map(str::to_owned);
        let entries: &[Value] = packer
            .get("runs")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for run in entries {
            let input: &str = run
                .get("input")
                .and_then(Value::as_str)
                .unwrap_or("<no input recorded>");
            let absent_is_recorded: bool = run
                .get("fixture_absent")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            for key in PATH_KEYS {
                let Some(value): Option<&Value> = run.get(key.path) else {
                    continue;
                };
                out.push(DeclaredPath {
                    label: format!("{family} / {input}"),
                    key: key.path,
                    provenance_key: key.provenance,
                    reason_key: key.reason,
                    declared: value.as_str().unwrap_or("").to_owned(),
                    provenance: run
                        .get(key.provenance)
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    reason: run
                        .get(key.reason)
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    recipe: recipe.clone(),
                    absent_is_recorded,
                });
            }
        }
    }
    out
}

fn family_and_name(declared: &str) -> Option<(&str, &str)> {
    let rest: &str = declared.strip_prefix(CORPUS_PREFIX)?;
    let (family, name): (&str, &str) = rest.split_once('/')?;
    Some((family, name))
}

fn base_name(name: &str) -> &str {
    name.rsplit('/').next().unwrap_or(name)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProvenanceAudit {
    defects: Vec<String>,
    committed: usize,
    local: usize,
    unobtainable: usize,
}

fn audit_provenance(manifest: &toml::Table, root: &Path) -> ProvenanceAudit {
    let mut audit: ProvenanceAudit = ProvenanceAudit::default();
    for entry in declared_paths(manifest) {
        let Some((family, name)): Option<(&str, &str)> = family_and_name(&entry.declared) else {
            continue;
        };
        let Some(raw): Option<&String> = entry.provenance.as_ref() else {
            audit.defects.push(format!(
                "{}: {} = {:?} states no provenance; set {} to {COMMITTED_WORD:?}, {LOCAL_WORD:?} \
                 or {UNOBTAINABLE_WORD:?}",
                entry.label, entry.key, entry.declared, entry.provenance_key
            ));
            continue;
        };
        let Some(provenance): Option<Provenance> = parse_provenance(raw) else {
            audit.defects.push(format!(
                "{}: {} = {raw:?} is not a provenance this check knows; the only values are \
                 {COMMITTED_WORD:?}, {LOCAL_WORD:?} and {UNOBTAINABLE_WORD:?}",
                entry.label, entry.provenance_key
            ));
            continue;
        };
        match provenance {
            Provenance::Committed => {
                audit.committed += 1;
                if !is_committed(family, name) {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {COMMITTED_WORD}, but the committed-fixture \
                         registry carries no {family}/{name}. A renamed or mistyped path lands \
                         here, and so does a fixture that was never staged",
                        entry.label, entry.key, entry.declared
                    ));
                }
                let full: PathBuf = root.join(&entry.declared);
                if !full.is_file() {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {COMMITTED_WORD} but names no file at {}",
                        entry.label,
                        entry.key,
                        entry.declared,
                        full.display()
                    ));
                }
            }
            Provenance::Local | Provenance::Unobtainable => {
                let word: &str = if provenance == Provenance::Unobtainable {
                    audit.unobtainable += 1;
                    UNOBTAINABLE_WORD
                } else {
                    audit.local += 1;
                    LOCAL_WORD
                };
                if is_committed(family, name) {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {word}, but the committed-fixture registry \
                         tracks {family}/{name}; a tracked input reproduces for every reader and \
                         must say so",
                        entry.label, entry.key, entry.declared
                    ));
                    continue;
                }
                let Some(recipe): Option<&String> = entry
                    .recipe
                    .as_ref()
                    .filter(|r: &&String| !r.trim().is_empty())
                else {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {word}, but its packer carries no {RECIPE_KEY}, \
                         so nothing records where it came from",
                        entry.label, entry.key, entry.declared
                    ));
                    continue;
                };
                if !recipe.contains(base_name(name)) {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {word}, and its packer's {RECIPE_KEY} never \
                         names {}, so the recipe covers some other input",
                        entry.label,
                        entry.key,
                        entry.declared,
                        base_name(name)
                    ));
                }
                let stated: bool = entry
                    .reason
                    .as_ref()
                    .is_some_and(|r: &String| !r.trim().is_empty());
                if provenance == Provenance::Unobtainable && !stated {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {UNOBTAINABLE_WORD} but carries no {}. The \
                         weakest input a figure can rest on is one no reader can obtain, so that \
                         row must say in its own words why the recipe cannot be followed to the end",
                        entry.label, entry.key, entry.declared, entry.reason_key
                    ));
                }
                if provenance == Provenance::Local && stated {
                    audit.defects.push(format!(
                        "{}: {} = {:?} is declared {LOCAL_WORD}, which says a reader can obtain it, \
                         yet it carries {}. One of the two is wrong",
                        entry.label, entry.key, entry.declared, entry.reason_key
                    ));
                }
            }
        }
    }
    audit
}

#[test]
fn no_manifest_run_declares_an_empty_fixture_path() {
    let manifest: toml::Table = manifest();
    let offenders: Vec<String> = declared_paths(&manifest)
        .iter()
        .filter(|p: &&DeclaredPath| p.declared.trim().is_empty())
        .map(|p: &DeclaredPath| format!("{}: {} is present but empty", p.label, p.key))
        .collect();
    assert!(
        offenders.is_empty(),
        "a run that carries an empty fixture path reads as coverage while naming no input, which \
         is worse than omitting the key: nothing can ever be measured from it and no reader can \
         tell that from the row. A run the packer refused belongs in the manifest as \
         runtime_ok = false plus error, carrying no path key at all. Offending rows:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn every_manifest_path_points_inside_the_packer_corpus() {
    let manifest: toml::Table = manifest();
    let offenders: Vec<String> = declared_paths(&manifest)
        .iter()
        .filter(|p: &&DeclaredPath| {
            !p.declared.trim().is_empty() && family_and_name(&p.declared).is_none()
        })
        .map(|p: &DeclaredPath| format!("{}: {} = {:?}", p.label, p.key, p.declared))
        .collect();
    assert!(
        offenders.is_empty(),
        "every manifest fixture path must be repository-relative under {CORPUS_PREFIX} so it \
         resolves the same way from any checkout and can be matched against the committed-fixture \
         registry. Offending rows:\n  {}",
        offenders.join("\n  ")
    );
}

#[test]
fn no_manifest_path_resolves_to_nothing() {
    let manifest: toml::Table = manifest();
    let root: PathBuf = repo_root();
    let requirement: FixtureRequirement = fixture_requirement();
    let mut offenders: Vec<String> = Vec::new();
    let mut resolved: usize = 0;

    for entry in declared_paths(&manifest) {
        if entry.declared.trim().is_empty() {
            continue;
        }
        let Some((family, name)): Option<(&str, &str)> = family_and_name(&entry.declared) else {
            continue;
        };
        let full: PathBuf = root.join(&entry.declared);
        if full.is_file() {
            resolved += 1;
            continue;
        }
        let committed: bool = is_committed(family, name);
        let fatal: bool = match requirement {
            FixtureRequirement::Every => true,
            FixtureRequirement::Optional | FixtureRequirement::Committed => committed,
        };
        if !fatal || entry.absent_is_recorded {
            continue;
        }
        offenders.push(format!(
            "{}: {} = {:?} resolves to nothing at {} (tracked_in_git={committed})",
            entry.label,
            entry.key,
            entry.declared,
            full.display()
        ));
    }

    assert!(
        offenders.is_empty(),
        "a manifest row naming a fixture that is not there describes a sample nobody can grade, \
         and every figure beside it is a record of some earlier run rather than something this \
         tree can re-derive. Stage the file, or set fixture_absent = true with \
         fixture_absent_reason on that row so the gap is stated rather than implied. Set \
         {REQUIRE_FIXTURES_VAR}=all to apply this to local-only samples too. Offending rows:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        resolved > 0,
        "no manifest path resolved to a real file, so this check measured nothing; it must run \
         against a tree where the committed packer corpus is present"
    );
}

#[test]
fn every_manifest_path_says_whether_its_input_is_committed_or_local() {
    let manifest: toml::Table = manifest();
    let audit: ProvenanceAudit = audit_provenance(&manifest, &repo_root());
    assert!(
        audit.defects.is_empty(),
        "a row measured against an input nobody else has must be distinguishable from one measured \
         against a fixture in the tree, or a figure that no reader can reproduce reads exactly like \
         one that every reader can. Each declared path states one of three words beside it. \
         {COMMITTED_WORD:?}: the committed-fixture registry carries it and the file is here, so a \
         rename or a deletion fails this check. {LOCAL_WORD:?}: the file is deliberately out of the \
         tree but a reader can obtain it, accepted only when the packer's {RECIPE_KEY} names that \
         file and records how to rebuild or refetch it, so declaring an input local can never be a \
         way to silence this. {UNOBTAINABLE_WORD:?}: the recipe records where it came from but no \
         reader can follow it to the end, which additionally requires that path's own \
         *_unobtainable_reason. Offending paths:\n  {}",
        audit.defects.join("\n  ")
    );
    assert!(
        audit.committed > 0 && audit.local > 0 && audit.unobtainable > 0,
        "this check saw {} committed, {} local and {} unobtainable path(s), so one of its three \
         branches graded nothing; it must run against the real manifest, which carries all three",
        audit.committed,
        audit.local,
        audit.unobtainable
    );
}

#[test]
fn committed_fixture_registry_paths_are_reachable() {
    let root: PathBuf = repo_root();
    let corpus: PathBuf = root.join(CORPUS_PREFIX);
    let dir: &Path = corpus.as_path();
    assert!(
        dir.is_dir(),
        "the packer corpus directory {} must exist, because the committed fixtures live there and \
         every manifest path is relative to it",
        dir.display()
    );
}

const COMMITTED_SAMPLE: &str = "corpus/native/packers/upx/hello.packed.nrv2b.exe";
const ABSENT_SAMPLE: &str = "corpus/native/packers/upx/rg.packed.upx.exe";
const NOWHERE_SAMPLE: &str = "corpus/native/packers/upx/nothing.here.exe";

fn one_run(family_keys: &str, run_keys: &str) -> Result<toml::Table, toml::de::Error> {
    format!("[[packers]]\nname = \"UPX\"\n{family_keys}\n[[packers.runs]]\ninput = \"probe\"\n{run_keys}\n")
        .parse::<toml::Table>()
}

#[test]
fn a_path_with_no_provenance_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run("", &format!("packed_path = {COMMITTED_SAMPLE:?}\n"))?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("states no provenance"),
        "got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn an_unknown_provenance_word_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "",
        &format!("packed_path = {COMMITTED_SAMPLE:?}\npacked_provenance = \"nearby\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("not a provenance this check knows"),
        "got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn a_committed_claim_over_an_uncommitted_path_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "",
        &format!("packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"committed\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert!(
        audit
            .defects
            .iter()
            .any(|d: &String| d.contains("registry carries no")),
        "a path the registry does not track cannot claim to be committed, got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn a_committed_path_that_is_present_and_registered_is_clean() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "",
        &format!("packed_path = {COMMITTED_SAMPLE:?}\npacked_provenance = \"committed\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(
        audit,
        ProvenanceAudit {
            defects: Vec::new(),
            committed: 1,
            local: 0,
            unobtainable: 0
        }
    );
    Ok(())
}

#[test]
fn a_local_path_without_a_recipe_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "",
        &format!("packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"local\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains(RECIPE_KEY),
        "got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn a_local_path_a_recipe_never_names_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"rebuild hello.unpacked.exe with upx -d\"",
        &format!("packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"local\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("never names rg.packed.upx.exe"),
        "got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn a_local_path_its_recipe_names_is_clean_even_when_absent() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"nothing.here.exe is refetched from the upstream corpus\"",
        &format!("packed_path = {NOWHERE_SAMPLE:?}\npacked_provenance = \"local\"\n"),
    )?;
    assert!(
        !repo_root().join(NOWHERE_SAMPLE).is_file(),
        "this case only means something while {NOWHERE_SAMPLE} is absent from every checkout"
    );
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(
        audit,
        ProvenanceAudit {
            defects: Vec::new(),
            committed: 0,
            local: 1,
            unobtainable: 0
        },
        "an input the recipe names is clean whether or not this machine happens to hold it"
    );
    Ok(())
}

#[test]
fn an_unobtainable_path_without_a_reason_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"rg.packed.upx.exe came from a machine\"",
        &format!("packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"local-unobtainable\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("packed_unobtainable_reason"),
        "the weakest kind of input must state why nobody can obtain it, got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn an_unobtainable_path_with_a_reason_is_counted_apart_from_local() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"rg.packed.upx.exe came from a machine\"",
        &format!(
            "packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"local-unobtainable\"\npacked_unobtainable_reason = \"the packer input was never versioned\"\n"
        ),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(
        audit,
        ProvenanceAudit {
            defects: Vec::new(),
            committed: 0,
            local: 0,
            unobtainable: 1
        },
        "an unobtainable input is never counted as one a reader can fetch"
    );
    Ok(())
}

#[test]
fn a_local_path_claiming_a_reason_it_does_not_need_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"rg.packed.upx.exe is upx --best over ripgrep 15.1.0\"",
        &format!(
            "packed_path = {ABSENT_SAMPLE:?}\npacked_provenance = \"local\"\npacked_unobtainable_reason = \"nobody can get this\"\n"
        ),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("One of the two is wrong"),
        "a path cannot both be obtainable and carry a reason it is not, got {:?}",
        audit.defects
    );
    Ok(())
}

#[test]
fn a_committed_fixture_relabelled_local_is_a_defect() -> Result<(), toml::de::Error> {
    let table: toml::Table = one_run(
        "local_fixture_recipe = \"hello.packed.nrv2b.exe is upx --best over hello.exe\"",
        &format!("packed_path = {COMMITTED_SAMPLE:?}\npacked_provenance = \"local\"\n"),
    )?;
    let audit: ProvenanceAudit = audit_provenance(&table, &repo_root());
    assert_eq!(audit.defects.len(), 1, "got {:?}", audit.defects);
    assert!(
        audit.defects[0].contains("registry tracks"),
        "a tracked input relabelled local understates what a reader can reproduce, got {:?}",
        audit.defects
    );
    Ok(())
}
