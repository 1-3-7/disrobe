use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::fileio::read_text_bounded;

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

const NON_MEMBER_CRATE_ALLOWLIST: &[(&str, &str)] = &[(
    "fuzz",
    "cargo-fuzz requires its own workspace, so it is built by `cargo fuzz`, never by the root workspace",
)];

const KNOWN_UNWIRED_CRATES: &[(&str, &str)] = &[
    (
        "disrobe-irsummary",
        "summarizes lifted Mir-rung IR; no consumer has been written yet, tracked as a wiring item",
    ),
    (
        "disrobe-plugin-host",
        "the wasmtime plugin sandbox is complete and tested but the CLI cannot dispatch a plugin pass yet, tracked as a wiring item",
    ),
    (
        "disrobe-semdiff",
        "semantic diff over NIR; no consumer has been written yet, tracked as a wiring item",
    ),
];

#[derive(Debug, Default)]
pub(crate) struct Report {
    findings: Vec<Finding>,
    facts: BTreeMap<String, Value>,
}

#[derive(Debug)]
struct Finding {
    check: &'static str,
    detail: String,
}

impl Report {
    fn fail(&mut self, check: &'static str, detail: String) {
        self.findings.push(Finding { check, detail });
    }

    fn fact(&mut self, key: &str, value: Value) {
        self.facts.insert(key.to_string(), value);
    }

    fn to_json(&self) -> Value {
        json!({
            "healthy": self.findings.is_empty(),
            "findings": self.findings.iter().map(|f: &Finding| json!({
                "check": f.check,
                "detail": f.detail,
            })).collect::<Vec<Value>>(),
            "facts": self.facts.iter().map(|(k, v)| (k.clone(), v.clone())).collect::<serde_json::Map<String, Value>>(),
        })
    }
}

pub(crate) fn run(root: &Path, as_json: bool) -> Result<()> {
    let mut report: Report = Report::default();

    let root_manifest: String = read_text_bounded(&root.join("Cargo.toml"), MAX_MANIFEST_BYTES)
        .wrap_err("reading the workspace manifest")?;
    let root_doc: toml::Value =
        toml::from_str(&root_manifest).wrap_err("parsing the workspace manifest")?;

    let members: BTreeSet<String> = workspace_members(&root_doc);
    let crate_dirs: BTreeSet<String> = discover_crate_dirs(root)?;

    check_membership(&members, &crate_dirs, &mut report);
    check_members_exist(root, &members, &mut report);

    let member_manifests: BTreeMap<String, toml::Value> = load_member_manifests(root, &members)?;
    let workspace_version: String = workspace_package_version(&root_doc);

    check_internal_versions(
        &root_doc,
        &member_manifests,
        &workspace_version,
        root,
        &mut report,
    );
    check_unused_workspace_deps(root, &root_doc, &member_manifests, &mut report);
    check_unwired_members(root, &member_manifests, &mut report);

    report.fact("workspace_members", json!(members.len()));
    report.fact("crate_directories", json!(crate_dirs.len()));
    report.fact("workspace_version", json!(workspace_version));

    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report.to_json())
                .wrap_err("rendering the health report")?
        );
    }

    if report.findings.is_empty() {
        if !as_json {
            println!(
                "xtask health: workspace coherent ({} member(s), {} crate directory(ies), every internal version at {}, no unused workspace dependency)",
                members.len(),
                crate_dirs.len(),
                workspace_version
            );
        }
        return Ok(());
    }

    let rendered: String = report
        .findings
        .iter()
        .map(|f: &Finding| format!("[{}] {}", f.check, f.detail))
        .collect::<Vec<String>>()
        .join("\n  ");
    bail!(
        "xtask health: {} coherence failure(s):\n  {rendered}",
        report.findings.len()
    )
}

fn workspace_members(root_doc: &toml::Value) -> BTreeSet<String> {
    root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("members"))
        .and_then(toml::Value::as_array)
        .map(|a: &Vec<toml::Value>| {
            a.iter()
                .filter_map(|v: &toml::Value| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn workspace_package_version(root_doc: &toml::Value) -> String {
    root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("package"))
        .and_then(|p: &toml::Value| p.get("version"))
        .and_then(toml::Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn discover_crate_dirs(root: &Path) -> Result<BTreeSet<String>> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    for entry in walkdir::WalkDir::new(root)
        .max_depth(3)
        .into_iter()
        .filter_entry(|e: &walkdir::DirEntry| {
            let name: &str = e.file_name().to_str().unwrap_or_default();
            !name.starts_with('.') && !matches!(name, "target" | "node_modules")
        })
    {
        let entry: walkdir::DirEntry = entry.wrap_err("walking the repository for crate dirs")?;
        if entry.file_name() != "Cargo.toml" {
            continue;
        }
        let Some(dir) = entry.path().parent() else {
            continue;
        };
        if dir == root {
            continue;
        }
        let Ok(rel) = dir.strip_prefix(root) else {
            continue;
        };
        found.insert(rel.to_string_lossy().replace('\\', "/"));
    }
    Ok(found)
}

fn check_membership(
    members: &BTreeSet<String>,
    crate_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    for dir in crate_dirs.difference(members) {
        let allowed: Option<&(&str, &str)> = NON_MEMBER_CRATE_ALLOWLIST
            .iter()
            .find(|(name, _)| name == dir);
        if allowed.is_none() {
            report.fail(
                "workspace-membership",
                format!(
                    "{dir}/Cargo.toml exists but {dir} is not a workspace member and is not on the allowlist; add it to members in Cargo.toml, or add it to NON_MEMBER_CRATE_ALLOWLIST in xtask/src/health.rs with the reason it stays out"
                ),
            );
        }
    }
}

fn check_members_exist(root: &Path, members: &BTreeSet<String>, report: &mut Report) {
    for member in members {
        let manifest: PathBuf = root.join(member).join("Cargo.toml");
        if !manifest.is_file() {
            report.fail(
                "member-missing",
                format!("Cargo.toml lists {member} as a workspace member but {member}/Cargo.toml does not exist"),
            );
        }
    }
}

fn load_member_manifests(
    root: &Path,
    members: &BTreeSet<String>,
) -> Result<BTreeMap<String, toml::Value>> {
    let mut out: BTreeMap<String, toml::Value> = BTreeMap::new();
    for member in members {
        let path: PathBuf = root.join(member).join("Cargo.toml");
        if !path.is_file() {
            continue;
        }
        let text: String = read_text_bounded(&path, MAX_MANIFEST_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let doc: toml::Value =
            toml::from_str(&text).wrap_err_with(|| format!("parsing {}", path.display()))?;
        out.insert(member.clone(), doc);
    }
    Ok(out)
}

fn package_version(doc: &toml::Value, workspace_version: &str) -> Option<String> {
    let package: &toml::Value = doc.get("package")?;
    let version: &toml::Value = package.get("version")?;
    if let Some(literal) = version.as_str() {
        return Some(literal.to_string());
    }
    if version
        .get("workspace")
        .and_then(toml::Value::as_bool)
        .unwrap_or(false)
    {
        return Some(workspace_version.to_string());
    }
    None
}

fn check_internal_versions(
    root_doc: &toml::Value,
    member_manifests: &BTreeMap<String, toml::Value>,
    workspace_version: &str,
    root: &Path,
    report: &mut Report,
) {
    let Some(deps) = root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };

    let mut by_dir: BTreeMap<String, String> = BTreeMap::new();
    for (dir, doc) in member_manifests {
        if let Some(v) = package_version(doc, workspace_version) {
            by_dir.insert(dir.clone(), v);
        }
    }

    for (name, spec) in deps {
        let Some(table) = spec.as_table() else {
            continue;
        };
        let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(declared) = table.get("version").and_then(toml::Value::as_str) else {
            continue;
        };
        let normalized: String = path.replace('\\', "/");
        let Some(actual) = by_dir.get(&normalized) else {
            if !root.join(path).join("Cargo.toml").is_file() {
                report.fail(
                    "path-dependency-missing",
                    format!("[workspace.dependencies] {name} points at {path}, which has no Cargo.toml"),
                );
            }
            continue;
        };
        if declared != actual {
            report.fail(
                "internal-version-drift",
                format!(
                    "[workspace.dependencies] {name} declares version {declared} but {path} is actually at {actual}"
                ),
            );
        }
    }
}

fn check_unused_workspace_deps(
    root: &Path,
    root_doc: &toml::Value,
    member_manifests: &BTreeMap<String, toml::Value>,
    report: &mut Report,
) {
    let Some(deps) = root_doc
        .get("workspace")
        .and_then(|w: &toml::Value| w.get("dependencies"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };

    let mut referenced: BTreeSet<String> = BTreeSet::new();
    for doc in member_manifests.values() {
        for section in [
            "dependencies",
            "dev-dependencies",
            "build-dependencies",
            "target",
        ] {
            collect_workspace_refs(doc.get(section), &mut referenced);
        }
    }

    for (name, spec) in deps {
        if referenced.contains(name) {
            continue;
        }
        let is_internal: bool = spec
            .as_table()
            .and_then(|t: &toml::map::Map<String, toml::Value>| t.get("path"))
            .is_some();
        if !is_internal {
            report.fail(
                "unused-workspace-dependency",
                format!(
                    "[workspace.dependencies] declares {name} but no workspace member takes it with `workspace = true`; remove the declaration or wire it to the crate that needs it"
                ),
            );
        }
    }

    let _ = root;
}

fn crate_name(doc: &toml::Value) -> Option<String> {
    doc.get("package")?
        .get("name")?
        .as_str()
        .map(str::to_string)
}

fn has_bin_target(root: &Path, dir: &str, doc: &toml::Value) -> bool {
    if doc.get("bin").and_then(toml::Value::as_array).is_some() {
        return true;
    }
    root.join(dir).join("src").join("main.rs").is_file()
        || root.join(dir).join("src").join("bin").is_dir()
}

fn is_consumed_outside_rust(doc: &toml::Value) -> bool {
    doc.get("lib")
        .and_then(|l: &toml::Value| l.get("crate-type"))
        .and_then(toml::Value::as_array)
        .is_some_and(|kinds: &Vec<toml::Value>| {
            kinds.iter().any(|k: &toml::Value| {
                matches!(k.as_str(), Some("cdylib" | "staticlib" | "dylib"))
            })
        })
}

fn declared_dependency_names(doc: &toml::Value) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    let visit = |section: Option<&toml::Value>, out: &mut BTreeSet<String>| {
        if let Some(table) = section.and_then(toml::Value::as_table) {
            for name in table.keys() {
                out.insert(name.clone());
            }
        }
    };
    visit(doc.get("dependencies"), &mut out);
    visit(doc.get("dev-dependencies"), &mut out);
    visit(doc.get("build-dependencies"), &mut out);
    if let Some(targets) = doc.get("target").and_then(toml::Value::as_table) {
        for spec in targets.values() {
            visit(spec.get("dependencies"), &mut out);
            visit(spec.get("dev-dependencies"), &mut out);
            visit(spec.get("build-dependencies"), &mut out);
        }
    }
    out
}

fn check_unwired_members(
    root: &Path,
    member_manifests: &BTreeMap<String, toml::Value>,
    report: &mut Report,
) {
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for (dir, doc) in member_manifests {
        if let Some(name) = crate_name(doc) {
            names.insert(name, dir.clone());
        }
    }

    let mut known_unwired: usize = 0;
    let mut depended_on: BTreeSet<String> = BTreeSet::new();
    for (dir, doc) in member_manifests {
        let self_name: Option<String> = crate_name(doc);
        for dep in declared_dependency_names(doc) {
            if names.contains_key(&dep) && Some(&dep) != self_name.as_ref() {
                depended_on.insert(dep);
            }
        }
        let _ = dir;
    }

    for (name, dir) in &names {
        if depended_on.contains(name) {
            continue;
        }
        let Some(doc) = member_manifests.get(dir) else {
            continue;
        };
        if has_bin_target(root, dir, doc) || is_consumed_outside_rust(doc) {
            continue;
        }
        if KNOWN_UNWIRED_CRATES
            .iter()
            .any(|(known, _)| known == name)
        {
            known_unwired += 1;
            continue;
        }
        report.fail(
            "unwired-crate",
            format!(
                "{name} ({dir}) has no binary target and no other workspace crate depends on it, so it compiles only because nothing exercises it. Wire it to a consumer, merge it, or move it out of the workspace, or add it to KNOWN_UNWIRED_CRATES in xtask/src/health.rs with the reason and the item tracking it"
            ),
        );
    }

    for (known, _) in KNOWN_UNWIRED_CRATES {
        if !names.contains_key(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_UNWIRED_CRATES names {known}, which is no longer a workspace crate; drop the entry"
                ),
            );
        } else if depended_on.contains(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_UNWIRED_CRATES still lists {known} but something now depends on it; drop the entry so the gate keeps ratcheting"
                ),
            );
        }
    }

    report.fact("known_unwired_crates", json!(known_unwired));
}

fn collect_workspace_refs(section: Option<&toml::Value>, out: &mut BTreeSet<String>) {
    let Some(value) = section else {
        return;
    };
    let Some(table) = value.as_table() else {
        return;
    };
    for (name, spec) in table {
        let takes_workspace: bool = spec
            .as_table()
            .and_then(|t: &toml::map::Map<String, toml::Value>| t.get("workspace"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if takes_workspace {
            out.insert(name.clone());
            continue;
        }
        if spec.as_table().is_some() && spec.get("workspace").is_none() {
            collect_workspace_refs(spec.get("dependencies"), out);
            collect_workspace_refs(spec.get("dev-dependencies"), out);
            collect_workspace_refs(spec.get("build-dependencies"), out);
        }
    }
}
