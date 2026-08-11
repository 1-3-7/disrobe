use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::fileio::read_text_bounded;

const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

const NON_MEMBER_CRATE_ALLOWLIST: &[(&str, &str)] = &[(
    "fuzz",
    "cargo-fuzz requires its own workspace, so it is built by `cargo fuzz`, never by the root workspace",
)];

const KNOWN_UNWIRED_CRATES: &[(&str, &str)] = &[(
    "disrobe-semdiff",
    "semantic diff over NIR; no consumer has been written yet, tracked as a wiring item",
)];

const KNOWN_STANDALONE_BINARIES: &[(&str, &str)] = &[
    (
        "disrobe-cli",
        "the product's own top-level CLI binary; users invoke it directly and no workspace member depends on it as a library",
    ),
    (
        "disrobe-transcode",
        "a standalone tool that rewrites a .dr envelope's hot segment in place; invoked directly, not linked by another crate",
    ),
    (
        "disrobe-validator",
        "the corpus-wide end-to-end validation and benchmark harness; run directly against the sample corpus, not linked by another crate",
    ),
    (
        "xtask",
        "the workspace's own dev-tooling binary (health, regen, release helpers); cargo invokes it directly via `cargo run -p xtask`",
    ),
    (
        "disrobe-bench-head-to-head",
        "a reproducible benchmark binary that runs disrobe against a competing tool and emits committed measured results; run directly, not linked by another crate",
    ),
    (
        "disrobe-bench-native-unpack",
        "a reproducible benchmark binary over the native packer corpus; run directly, not linked by another crate",
    ),
    (
        "disrobe-evidence-mba",
        "a ground-truth corpus generator for mixed-boolean-arithmetic recovery, deliberately linking no recovery crate so it cannot grade its own output; run directly, not linked by another crate",
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
    check_generator_disjointness(root, &mut report);

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

fn check_generator_disjointness(root: &Path, report: &mut Report) {
    const CHECK: &str = "corpus-generator-disjointness";
    let verdicts: Vec<crate::graph_disjointness::Verdict> =
        match crate::graph_disjointness::audit(root) {
            Ok(found) => found,
            Err(error) => {
                report.fail(
                    CHECK,
                    format!("could not resolve the dependency graph: {error}"),
                );
                return;
            }
        };
    let mut audited: Vec<Value> = Vec::with_capacity(verdicts.len());
    for verdict in &verdicts {
        let linked: Vec<String> = verdict
            .linked_recovery_packages
            .iter()
            .cloned()
            .collect::<Vec<String>>();
        if !linked.is_empty() {
            report.fail(
                CHECK,
                format!(
                    "{} resolves to the recovery package(s) it grades: {}",
                    verdict.generator,
                    linked.join(", ")
                ),
            );
        }
        audited.push(json!({
            "generator": verdict.generator,
            "resolved_dependencies": verdict.resolved_dependencies,
            "linked_recovery_packages": linked,
        }));
    }
    report.fact("corpus_generators", json!(audited));
}

pub(crate) fn workspace_members(root_doc: &toml::Value) -> BTreeSet<String> {
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

    let workspace_default_enabled_dirs: BTreeSet<String> = deps
        .values()
        .filter_map(|specification: &toml::Value| {
            let table: &toml::map::Map<String, toml::Value> = specification.as_table()?;
            let path: &str = table.get("path")?.as_str()?;
            let default_features_enabled: bool = table
                .get("default-features")
                .and_then(toml::Value::as_bool)
                .unwrap_or(true);
            default_features_enabled.then(|| path.replace('\\', "/"))
        })
        .collect();

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
                    format!(
                        "[workspace.dependencies] {name} points at {path}, which has no Cargo.toml"
                    ),
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

    for (member_dir, doc) in member_manifests {
        check_member_internal_version_pins(
            member_dir,
            doc,
            &by_dir,
            &workspace_default_enabled_dirs,
            report,
        );
    }
}

fn normalized_dependency_dir(member_dir: &str, dependency_path: &str) -> Option<String> {
    let joined: PathBuf = Path::new(member_dir).join(dependency_path);
    let mut components: Vec<String> = Vec::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(value) => components.push(value.to_string_lossy().into_owned()),
            Component::ParentDir => {
                components.pop()?;
            }
            Component::Prefix(_) | Component::RootDir => return None,
        }
    }
    Some(components.join("/"))
}

fn check_member_internal_version_pins(
    member_dir: &str,
    doc: &toml::Value,
    internal_dirs: &BTreeMap<String, String>,
    workspace_default_enabled_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        check_dependency_table_for_internal_version_pins(
            member_dir,
            section_name,
            doc.get(section_name),
            internal_dirs,
            workspace_default_enabled_dirs,
            report,
        );
    }
    let Some(targets) = doc.get("target").and_then(toml::Value::as_table) else {
        return;
    };
    for (target_name, target_doc) in targets {
        for section_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
            let location: String = format!("target.{target_name}.{section_name}");
            check_dependency_table_for_internal_version_pins(
                member_dir,
                &location,
                target_doc.get(section_name),
                internal_dirs,
                workspace_default_enabled_dirs,
                report,
            );
        }
    }
}

fn check_dependency_table_for_internal_version_pins(
    member_dir: &str,
    location: &str,
    section: Option<&toml::Value>,
    internal_dirs: &BTreeMap<String, String>,
    workspace_default_enabled_dirs: &BTreeSet<String>,
    report: &mut Report,
) {
    let Some(dependencies) = section.and_then(toml::Value::as_table) else {
        return;
    };
    for (dependency_name, specification) in dependencies {
        let Some(table) = specification.as_table() else {
            continue;
        };
        let Some(path) = table.get("path").and_then(toml::Value::as_str) else {
            continue;
        };
        let Some(dependency_dir) = normalized_dependency_dir(member_dir, path) else {
            continue;
        };
        if !internal_dirs.contains_key(&dependency_dir) {
            continue;
        }
        let disables_workspace_defaults: bool = table
            .get("default-features")
            .and_then(toml::Value::as_bool)
            .is_some_and(|enabled: bool| !enabled)
            && workspace_default_enabled_dirs.contains(&dependency_dir);
        if table.get("version").is_none() && disables_workspace_defaults {
            continue;
        }
        let check: &'static str = if table.get("version").and_then(toml::Value::as_str).is_some() {
            "internal-version-pin"
        } else {
            "internal-workspace-bypass"
        };
        report.fail(
            check,
            format!(
                "{member_dir}/Cargo.toml [{location}] {dependency_name} declares an internal path dependency outside [workspace.dependencies]; use `workspace = true`, except when a local path is required to disable workspace defaults"
            ),
        );
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
            kinds
                .iter()
                .any(|k: &toml::Value| matches!(k.as_str(), Some("cdylib" | "staticlib" | "dylib")))
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
    let mut known_standalone_binaries: usize = 0;
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
        if is_consumed_outside_rust(doc) {
            continue;
        }
        if has_bin_target(root, dir, doc) {
            if KNOWN_STANDALONE_BINARIES
                .iter()
                .any(|(known, _)| known == name)
            {
                known_standalone_binaries += 1;
                continue;
            }
            report.fail(
                "unwired-crate",
                format!(
                    "{name} ({dir}) has a binary target but no other workspace crate depends on it and it is not in KNOWN_STANDALONE_BINARIES in xtask/src/health.rs, so a bin-only crate can rot unnoticed. Add it there with the reason it stands alone, or wire it to a consumer"
                ),
            );
            continue;
        }
        if KNOWN_UNWIRED_CRATES.iter().any(|(known, _)| known == name) {
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

    for (known, _) in KNOWN_STANDALONE_BINARIES {
        let Some(dir) = names.get(*known) else {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES names {known}, which is no longer a workspace crate; drop the entry"
                ),
            );
            continue;
        };
        if depended_on.contains(*known) {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES still lists {known} but something now depends on it; drop the entry so the gate keeps ratcheting"
                ),
            );
        } else if let Some(doc) = member_manifests.get(dir)
            && !has_bin_target(root, dir, doc)
        {
            report.fail(
                "stale-unwired-allowlist",
                format!(
                    "KNOWN_STANDALONE_BINARIES still lists {known} but it no longer has a binary target; drop the entry"
                ),
            );
        }
    }

    report.fact("known_unwired_crates", json!(known_unwired));
    report.fact(
        "known_standalone_binaries",
        json!(known_standalone_binaries),
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn internal_version_report(member_manifest: &str) -> Result<Report, toml::de::Error> {
        let root_doc: toml::Value = toml::from_str(
            r#"
                [workspace.dependencies]
                disrobe-a = { path = "crates/disrobe-a", version = "0.10.5" }
                disrobe-b = { path = "crates/disrobe-b", version = "0.10.5" }
            "#,
        )?;
        let mut member_manifests: BTreeMap<String, toml::Value> = BTreeMap::new();
        member_manifests.insert(
            "crates/disrobe-a".to_owned(),
            toml::from_str(
                r#"
                    [package]
                    name = "disrobe-a"
                    version = "0.10.5"
                "#,
            )?,
        );
        member_manifests.insert(
            "crates/disrobe-b".to_owned(),
            toml::from_str(member_manifest)?,
        );
        let mut report: Report = Report::default();
        check_internal_versions(
            &root_doc,
            &member_manifests,
            "0.10.5",
            Path::new("."),
            &mut report,
        );
        Ok(report)
    }

    #[test]
    fn internal_literal_path_dependency_fails_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dev-dependencies.disrobe-a]
                path = "../disrobe-a"
                version = "0.10.4"
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-version-pin")
        );
        Ok(())
    }

    #[test]
    fn target_specific_internal_literal_path_dependency_fails_health() -> Result<(), toml::de::Error>
    {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [target.'cfg(windows)'.build-dependencies]
                disrobe-a = { path = "../disrobe-a", version = "0.10.4" }
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-version-pin")
        );
        Ok(())
    }

    #[test]
    fn workspace_internal_dependency_passes_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { workspace = true }
            "#,
        )?;
        assert!(report.findings.is_empty());
        Ok(())
    }

    #[test]
    fn internal_path_without_a_version_still_fails_health() -> Result<(), toml::de::Error> {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { path = "../disrobe-a" }
            "#,
        )?;
        assert!(
            report
                .findings
                .iter()
                .any(|finding: &Finding| finding.check == "internal-workspace-bypass")
        );
        Ok(())
    }

    #[test]
    fn local_path_can_disable_workspace_defaults_without_a_version() -> Result<(), toml::de::Error>
    {
        let report: Report = internal_version_report(
            r#"
                [package]
                name = "disrobe-b"
                version = "0.10.5"

                [dependencies]
                disrobe-a = { path = "../disrobe-a", default-features = false }
            "#,
        )?;
        assert!(report.findings.is_empty());
        Ok(())
    }
}
