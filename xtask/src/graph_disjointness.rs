use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::process::Command;

use eyre::{Result, WrapErr, bail};
use serde_json::Value;

pub(crate) const CORPUS_GENERATORS: &[&str] = &["disrobe-evidence-mba"];
pub(crate) const RECOVERY_PREFIX: &str = "disrobe-";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub(crate) generator: String,
    pub(crate) linked_recovery_packages: BTreeSet<String>,
    pub(crate) resolved_dependencies: usize,
}

pub(crate) fn audit(root: &Path) -> Result<Vec<Verdict>> {
    let metadata: Value = resolve_metadata(root)?;
    let names: BTreeMap<String, String> = package_names(&metadata);
    let edges: BTreeMap<String, Vec<String>> = normal_edges(&metadata)?;

    let mut verdicts: Vec<Verdict> = Vec::with_capacity(CORPUS_GENERATORS.len());
    for generator in CORPUS_GENERATORS {
        let Some((identifier, _)) = names
            .iter()
            .find(|(_, name): &(&String, &String)| name.as_str() == *generator)
        else {
            bail!("the workspace has no package named {generator}");
        };
        let reachable: BTreeSet<String> = reachable_from(identifier, &edges);
        let linked_recovery_packages: BTreeSet<String> = reachable
            .iter()
            .filter_map(|id: &String| names.get(id).cloned())
            .filter(|name: &String| name.starts_with(RECOVERY_PREFIX) && name != *generator)
            .collect();
        verdicts.push(Verdict {
            generator: (*generator).to_owned(),
            linked_recovery_packages,
            resolved_dependencies: reachable.len(),
        });
    }
    Ok(verdicts)
}

fn resolve_metadata(root: &Path) -> Result<Value> {
    let output: std::process::Output =
        Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
            .arg("metadata")
            .arg("--format-version")
            .arg("1")
            .arg("--all-features")
            .current_dir(root)
            .output()
            .wrap_err("resolving the workspace dependency graph")?;
    if !output.status.success() {
        bail!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    serde_json::from_slice::<Value>(&output.stdout)
        .wrap_err("parsing the resolved dependency graph")
}

fn package_names(metadata: &Value) -> BTreeMap<String, String> {
    metadata
        .get("packages")
        .and_then(Value::as_array)
        .map(|packages: &Vec<Value>| {
            packages
                .iter()
                .filter_map(|package: &Value| {
                    let id: &str = package.get("id")?.as_str()?;
                    let name: &str = package.get("name")?.as_str()?;
                    Some((id.to_owned(), name.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn normal_edges(metadata: &Value) -> Result<BTreeMap<String, Vec<String>>> {
    let Some(nodes) = metadata
        .get("resolve")
        .and_then(|resolve: &Value| resolve.get("nodes"))
        .and_then(Value::as_array)
    else {
        bail!("the resolved dependency graph carries no nodes");
    };
    let mut edges: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for node in nodes {
        let Some(id) = node.get("id").and_then(Value::as_str) else {
            continue;
        };
        let mut targets: Vec<String> = Vec::new();
        if let Some(deps) = node.get("deps").and_then(Value::as_array) {
            for dep in deps {
                let Some(pkg) = dep.get("pkg").and_then(Value::as_str) else {
                    continue;
                };
                if carries_normal_kind(dep) {
                    targets.push(pkg.to_owned());
                }
            }
        }
        edges.insert(id.to_owned(), targets);
    }
    Ok(edges)
}

fn carries_normal_kind(dep: &Value) -> bool {
    let Some(kinds) = dep.get("dep_kinds").and_then(Value::as_array) else {
        return true;
    };
    kinds
        .iter()
        .any(|kind: &Value| kind.get("kind").is_none_or(Value::is_null))
}

fn reachable_from(start: &str, edges: &BTreeMap<String, Vec<String>>) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();
    queue.push_back(start.to_owned());
    while let Some(current) = queue.pop_front() {
        let Some(targets) = edges.get(&current) else {
            continue;
        };
        for target in targets {
            if seen.insert(target.clone()) {
                queue.push_back(target.clone());
            }
        }
    }
    seen
}
