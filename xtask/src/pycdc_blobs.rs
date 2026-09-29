use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Output, Stdio};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

pub(crate) const LIST_PATH: &str = "xtask/data/pycdc_blobs.txt";
const MAX_LIST_BYTES: u64 = 64 * 1024;
const BLOB_ID_HEX: usize = 40;

pub(crate) fn load_list(root: &Path) -> Result<BTreeSet<String>> {
    let text: String = read_text_bounded(&root.join(LIST_PATH), MAX_LIST_BYTES)?;
    parse_list(&text)
}

pub(crate) fn parse_list(text: &str) -> Result<BTreeSet<String>> {
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let id: &str = line.trim();
        if id.len() != BLOB_ID_HEX
            || !id
                .bytes()
                .all(|byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!(
                "{LIST_PATH} line {} is not a lowercase 40-digit git blob id: {id:?}",
                index + 1
            );
        }
        ids.insert(id.to_owned());
    }
    if ids.is_empty() {
        bail!("{LIST_PATH} lists no blob id, so the guard would pass vacuously");
    }
    Ok(ids)
}

pub(crate) fn working_tree_blob_ids(root: &Path) -> Result<BTreeMap<String, String>> {
    let index: Vec<u8> = git_stdout(root, &["ls-files", "-s", "-z"])?;
    let mut blobs: BTreeMap<String, String> = BTreeMap::new();
    for entry in index.split(|byte: &u8| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let entry: &str =
            std::str::from_utf8(entry).wrap_err("git ls-files -s printed a non-UTF-8 entry")?;
        let (meta, path): (&str, &str) = entry
            .split_once('\t')
            .ok_or_else(|| eyre!("git ls-files -s entry has no path: {entry:?}"))?;
        let id: &str = meta
            .split(' ')
            .nth(1)
            .ok_or_else(|| eyre!("git ls-files -s entry has no object id: {entry:?}"))?;
        if root.join(path).is_file() {
            blobs.insert(path.to_owned(), id.to_owned());
        }
    }
    let changed: Vec<u8> = git_stdout(root, &["ls-files", "-m", "-o", "--exclude-standard", "-z"])?;
    let mut rehash: BTreeSet<String> = BTreeSet::new();
    for path in changed.split(|byte: &u8| *byte == 0) {
        let path: &str =
            std::str::from_utf8(path).wrap_err("git ls-files -m -o printed a non-UTF-8 path")?;
        if !path.is_empty() && !path.contains('\n') && root.join(path).is_file() {
            rehash.insert(path.to_owned());
        }
    }
    let paths: Vec<String> = rehash.into_iter().collect();
    for (path, id) in paths.iter().zip(hash_objects(root, &paths)?) {
        blobs.insert(path.clone(), id);
    }
    Ok(blobs)
}

#[must_use]
pub(crate) fn listed_files(
    blobs: &BTreeMap<String, String>,
    listed: &BTreeSet<String>,
) -> Vec<String> {
    blobs
        .iter()
        .filter(|(_, id): &(&String, &String)| listed.contains(*id))
        .map(|(path, id): (&String, &String)| format!("{path} ({id})"))
        .collect()
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output: Output = Command::new("git")
        .args(args)
        .current_dir(root)
        .stdin(Stdio::null())
        .output()
        .wrap_err_with(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!("git {} exited with {}", args.join(" "), output.status);
    }
    Ok(output.stdout)
}

fn hash_objects(root: &Path, paths: &[String]) -> Result<Vec<String>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let mut child: Child = Command::new("git")
        .args(["hash-object", "--stdin-paths"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err("starting git hash-object --stdin-paths")?;
    let mut stdin: ChildStdin = child
        .stdin
        .take()
        .ok_or_else(|| eyre!("git hash-object has no stdin"))?;
    let request: String = paths.iter().fold(String::new(), |mut acc: String, path| {
        acc.push_str(path);
        acc.push('\n');
        acc
    });
    let output: Output = std::thread::scope(|scope| -> Result<Output> {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            stdin.write_all(request.as_bytes())?;
            drop(stdin);
            Ok(())
        });
        let output: Output = child
            .wait_with_output()
            .wrap_err("waiting for git hash-object")?;
        writer
            .join()
            .map_err(|_| eyre!("the git hash-object writer thread panicked"))?
            .wrap_err("writing paths to git hash-object")?;
        Ok(output)
    })?;
    if !output.status.success() {
        bail!(
            "git hash-object --stdin-paths exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let ids: Vec<String> = String::from_utf8(output.stdout)
        .wrap_err("git hash-object printed non-UTF-8 output")?
        .lines()
        .map(str::to_owned)
        .collect();
    if ids.len() != paths.len() {
        bail!(
            "git hash-object returned {} ids for {} paths",
            ids.len(),
            paths.len()
        );
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_malformed_or_empty_list_is_refused() {
        assert!(parse_list("").is_err());
        assert!(parse_list("24CC0F2F81A267DFC0A819000EF4F8D51AF39DCD\n").is_err());
        assert!(parse_list("24cc0f2f\n").is_err());
    }
}
