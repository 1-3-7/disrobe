#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code, clippy::panic)]
mod packer_fixture;

use std::path::{Path, PathBuf};

use packer_fixture::{
    COMMITTED_FIXTURES, CommittedFixture, FixtureRequirement, REQUIRE_FIXTURES_VAR,
    fixture_requirement, is_committed,
};
use toml::Value;

const PATH_KEYS: [&str; 3] = ["packed_path", "unpacked_path", "original_path"];
const CORPUS_PREFIX: &str = "corpus/native/packers/";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn manifest() -> toml::Table {
    let path: PathBuf = repo_root().join("corpus/native/packers/MANIFEST.toml");
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "the packer manifest must be readable at {}: {e}",
            path.display()
        )
    });
    text.parse::<toml::Table>()
        .unwrap_or_else(|e| panic!("the packer manifest must be valid TOML: {e}"))
}

#[derive(Debug)]
struct DeclaredPath {
    label: String,
    key: &'static str,
    declared: String,
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
                let Some(value): Option<&Value> = run.get(key) else {
                    continue;
                };
                out.push(DeclaredPath {
                    label: format!("{family} / {input}"),
                    key,
                    declared: value.as_str().unwrap_or("").to_owned(),
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
fn a_manifest_row_never_points_at_a_renamed_committed_fixture() {
    let manifest: toml::Table = manifest();
    let root: PathBuf = repo_root();
    let mut offenders: Vec<String> = Vec::new();
    for entry in declared_paths(&manifest) {
        let Some((family, name)): Option<(&str, &str)> = family_and_name(&entry.declared) else {
            continue;
        };
        if root.join(&entry.declared).is_file() || entry.absent_is_recorded {
            continue;
        }
        let sibling: Option<&CommittedFixture> = COMMITTED_FIXTURES
            .iter()
            .find(|f: &&CommittedFixture| f.family == family && f.name != name);
        let Some(sibling): Option<&CommittedFixture> = sibling else {
            continue;
        };
        if is_committed(family, name) {
            continue;
        }
        offenders.push(format!(
            "{}: {} = {:?} names no file, in a family whose committed fixtures include {}/{}",
            entry.label, entry.key, entry.declared, sibling.family, sibling.name
        ));
    }
    assert!(
        offenders.is_empty(),
        "a row in a family that ships committed fixtures, pointing at a path that is neither on \
         disk nor in the committed registry, is how a renamed or mistyped fixture path turns a \
         graded row into one that silently measures nothing. Offending rows:\n  {}",
        offenders.join("\n  ")
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
