use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use disrobe_core::chain::{ChildHandle, ChildMaterialization, ExtractedArtifact, NodeId};

const MAX_NAMESPACE_ATTEMPTS: usize = 1024;

pub(super) struct ExtractedWriter {
    root: PathBuf,
    claimed: BTreeMap<PathBuf, ChildMaterialization>,
    groups: BTreeMap<NodeId, PathBuf>,
    directory_modes: BTreeMap<PathBuf, u32>,
}

impl ExtractedWriter {
    pub(super) fn new(out_dir: &Path) -> Self {
        Self {
            root: out_dir.join("extracted"),
            claimed: BTreeMap::new(),
            groups: BTreeMap::new(),
            directory_modes: BTreeMap::new(),
        }
    }

    pub(super) fn write(
        &mut self,
        artifact: &ExtractedArtifact,
        siblings: &[ChildHandle],
    ) -> miette::Result<String> {
        let relative: PathBuf = sanitize_path(&artifact.relative_path)?;
        let base: PathBuf = if siblings.is_empty() {
            self.reserve_group(
                artifact.node_id,
                &[(relative.clone(), artifact.materialization)],
            )?
        } else if let Some(base) = self.groups.get(&artifact.node_id) {
            base.clone()
        } else {
            let members: Vec<(PathBuf, ChildMaterialization)> = siblings
                .iter()
                .map(|child: &ChildHandle| {
                    Ok((sanitize_path(&child.relative_path)?, child.materialization))
                })
                .collect::<miette::Result<_>>()?;
            let base: PathBuf = self.reserve_group(artifact.node_id, &members)?;
            self.groups.insert(artifact.node_id, base.clone());
            base
        };
        let destination: PathBuf = base.join(&relative);
        match artifact.materialization {
            ChildMaterialization::Directory { unix_mode } => {
                if !artifact.bytes.is_empty() {
                    return Err(miette::miette!(
                        "DR-CLI-0310: extracted directory carries file bytes: {}",
                        artifact.relative_path
                    ));
                }
                ensure_directory(&self.root, &destination)?;
                if let Some(mode) = unix_mode {
                    self.directory_modes.insert(destination.clone(), mode);
                }
            }
            ChildMaterialization::Regular { unix_mode } => {
                let parent: &Path = destination
                    .parent()
                    .ok_or_else(|| miette::miette!("DR-CLI-0309: extracted file has no parent"))?;
                ensure_directory(&self.root, parent)?;
                let mut file: std::fs::File = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&destination)
                    .map_err(|error: std::io::Error| {
                        miette::miette!(
                            "DR-CLI-0310: cannot create extracted file {}: {error}",
                            destination.display()
                        )
                    })?;
                file.write_all(&artifact.bytes)
                    .map_err(|error: std::io::Error| {
                        miette::miette!(
                            "DR-CLI-0310: cannot write extracted file {}: {error}",
                            destination.display()
                        )
                    })?;
                apply_mode(&destination, unix_mode)?;
            }
        }
        Ok(destination.display().to_string())
    }

    pub(super) fn finish(self) -> miette::Result<()> {
        let mut directories: Vec<(PathBuf, u32)> = self.directory_modes.into_iter().collect();
        directories.sort_by(|left: &(PathBuf, u32), right: &(PathBuf, u32)| {
            right
                .0
                .components()
                .count()
                .cmp(&left.0.components().count())
                .then_with(|| left.0.cmp(&right.0))
        });
        for (path, mode) in directories {
            apply_mode(&path, Some(mode))?;
        }
        Ok(())
    }

    fn reserve_group(
        &mut self,
        node: NodeId,
        members: &[(PathBuf, ChildMaterialization)],
    ) -> miette::Result<PathBuf> {
        validate_members(members)?;
        for attempt in 0..=MAX_NAMESPACE_ATTEMPTS {
            let base: PathBuf = match attempt {
                0 => self.root.clone(),
                1 => self.root.join(format!("node{node}")),
                _ => self.root.join(format!("node{node}-{}", attempt - 1)),
            };
            if attempt != 0 && (self.claimed.contains_key(&base) || existing_kind(&base)?.is_some())
            {
                continue;
            }
            let mut available: bool = true;
            for (relative, _) in members {
                if self.conflicts(&base.join(relative))? {
                    available = false;
                    break;
                }
            }
            if !available {
                continue;
            }
            for (relative, kind) in members {
                let destination: PathBuf = base.join(relative);
                self.claimed.insert(destination.clone(), *kind);
                for ancestor in destination.ancestors().skip(1) {
                    if ancestor == self.root {
                        break;
                    }
                    self.claimed
                        .entry(ancestor.to_path_buf())
                        .or_insert(ChildMaterialization::Directory { unix_mode: None });
                }
            }
            return Ok(base);
        }
        Err(miette::miette!(
            "DR-CLI-0310: no free extraction namespace for node {node} after {MAX_NAMESPACE_ATTEMPTS} attempts"
        ))
    }

    fn conflicts(&self, destination: &Path) -> miette::Result<bool> {
        if self.claimed.contains_key(destination) || existing_kind(destination)?.is_some() {
            return Ok(true);
        }
        for ancestor in destination.ancestors().skip(1) {
            if ancestor == self.root {
                break;
            }
            if self
                .claimed
                .get(ancestor)
                .is_some_and(|kind: &ChildMaterialization| !is_directory(*kind))
                || existing_kind(ancestor)?.is_some_and(|directory: bool| !directory)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn sanitize_path(raw: &str) -> miette::Result<PathBuf> {
    let mut path: PathBuf = PathBuf::new();
    for component in Path::new(raw).components() {
        if let Component::Normal(part) = component {
            path.push(part);
        }
    }
    if path.as_os_str().is_empty() {
        path.push("unnamed.bin");
    }
    disrobe_binfmt::quota::sanitize_entry_path(&path.to_string_lossy())
        .map(PathBuf::from)
        .map_err(|error| miette::miette!("DR-CLI-0310: unsafe extracted path: {error}"))
}

const fn is_directory(kind: ChildMaterialization) -> bool {
    matches!(kind, ChildMaterialization::Directory { .. })
}

fn validate_members(members: &[(PathBuf, ChildMaterialization)]) -> miette::Result<()> {
    let mut paths: BTreeMap<PathBuf, ChildMaterialization> = BTreeMap::new();
    for (path, kind) in members {
        if paths.insert(path.clone(), *kind).is_some() {
            return Err(miette::miette!(
                "DR-CLI-0310: duplicate extracted group path: {}",
                path.display()
            ));
        }
    }
    for (path, _) in members {
        for ancestor in path.ancestors().skip(1) {
            if paths
                .get(ancestor)
                .is_some_and(|kind: &ChildMaterialization| !is_directory(*kind))
            {
                return Err(miette::miette!(
                    "DR-CLI-0310: extracted group file is an ancestor of {}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

fn existing_kind(path: &Path) -> miette::Result<Option<bool>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => Ok(None),
        Err(error) => Err(miette::miette!(
            "DR-CLI-0309: cannot inspect extracted path {}: {error}",
            path.display()
        )),
    }
}

fn ensure_directory(root: &Path, destination: &Path) -> miette::Result<()> {
    let relative: &Path = destination.strip_prefix(root).map_err(|error| {
        miette::miette!("DR-CLI-0309: extracted directory escaped its root: {error}")
    })?;
    let mut current: PathBuf = root.to_path_buf();
    let mut directories: Vec<PathBuf> = vec![current.clone()];
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(miette::miette!("DR-CLI-0309: unsafe extracted directory"));
        };
        current.push(part);
        directories.push(current.clone());
    }
    for directory in directories {
        match existing_kind(&directory)? {
            Some(true) => {}
            Some(false) => {
                return Err(miette::miette!(
                    "DR-CLI-0309: extracted directory is a file or link: {}",
                    directory.display()
                ));
            }
            None => std::fs::create_dir(&directory).map_err(|error: std::io::Error| {
                miette::miette!(
                    "DR-CLI-0309: cannot create extracted directory {}: {error}",
                    directory.display()
                )
            })?,
        }
        let root_real: PathBuf = std::fs::canonicalize(root).map_err(|error| {
            miette::miette!("DR-CLI-0309: cannot resolve extraction root: {error}")
        })?;
        let resolved: PathBuf = std::fs::canonicalize(&directory).map_err(|error| {
            miette::miette!("DR-CLI-0309: cannot resolve extracted directory: {error}")
        })?;
        if !resolved.starts_with(&root_real) {
            return Err(miette::miette!(
                "DR-CLI-0309: extracted directory resolves outside its root"
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn apply_mode(path: &Path, mode: Option<u32>) -> miette::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if let Some(mode) = mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o777)).map_err(
            |error: std::io::Error| {
                miette::miette!(
                    "DR-CLI-0310: cannot set extracted mode for {}: {error}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
const fn apply_mode(_path: &Path, _mode: Option<u32>) -> miette::Result<()> {
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchDir;

    fn descriptor(path: &str, directory: bool, mode: u32) -> ChildHandle {
        ChildHandle {
            artifact_index: 0,
            relative_path: path.to_owned(),
            hint: None,
            materialization: if directory {
                ChildMaterialization::Directory {
                    unix_mode: Some(mode),
                }
            } else {
                ChildMaterialization::Regular {
                    unix_mode: Some(mode),
                }
            },
        }
    }

    fn artifact(node: NodeId, child: &ChildHandle, bytes: &[u8]) -> ExtractedArtifact {
        ExtractedArtifact {
            node_id: node,
            relative_path: child.relative_path.clone(),
            materialization: child.materialization,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn a_later_collision_moves_the_entire_group_before_its_first_write() {
        let scratch: ScratchDir = ScratchDir::create("chain-group-collision").expect("scratch");
        let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
        let occupied: ChildHandle = descriptor("tree/last.bin", false, 0o644);
        writer
            .write(&artifact(1, &occupied, b"existing"), &[])
            .expect("first group");
        let siblings: [ChildHandle; 3] = [
            descriptor("tree/first.bin", false, 0o755),
            descriptor("tree/empty", true, 0o755),
            descriptor("tree/last.bin", false, 0o644),
        ];
        writer
            .write(&artifact(2, &siblings[0], b"first"), &siblings)
            .expect("first sibling");
        writer
            .write(&artifact(2, &siblings[1], b""), &siblings)
            .expect("empty directory");
        writer
            .write(&artifact(2, &siblings[2], b"last"), &siblings)
            .expect("last sibling");
        writer.finish().expect("finish");
        let root: PathBuf = scratch.path().join("extracted");
        assert!(!root.join("tree/first.bin").exists());
        assert_eq!(
            std::fs::read(root.join("tree/last.bin")).expect("original"),
            b"existing"
        );
        assert_eq!(
            std::fs::read(root.join("node2/tree/first.bin")).expect("first"),
            b"first"
        );
        assert_eq!(
            std::fs::read(root.join("node2/tree/last.bin")).expect("last"),
            b"last"
        );
        assert!(root.join("node2/tree/empty").is_dir());
    }

    #[test]
    fn file_ancestors_and_occupied_namespaces_preserve_all_existing_bytes() {
        let scratch: ScratchDir = ScratchDir::create("chain-ancestor-collision").expect("scratch");
        let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
        for (node, path) in [(9, "tree"), (8, "node1/tree/file")] {
            let child: ChildHandle = descriptor(path, false, 0o644);
            writer
                .write(&artifact(node, &child, b"original"), &[])
                .expect("occupied path");
        }
        let child: ChildHandle = descriptor("tree/file", false, 0o644);
        writer
            .write(
                &artifact(1, &child, b"nested"),
                std::slice::from_ref(&child),
            )
            .expect("namespaced child");
        writer.finish().expect("finish");
        let root: PathBuf = scratch.path().join("extracted");
        assert_eq!(
            std::fs::read(root.join("tree")).expect("file ancestor"),
            b"original"
        );
        assert_eq!(
            std::fs::read(root.join("node1/tree/file")).expect("occupied namespace"),
            b"original"
        );
        assert_eq!(
            std::fs::read(root.join("node1-1/tree/file")).expect("fallback"),
            b"nested"
        );
    }

    #[test]
    fn internally_conflicting_groups_fail_before_writing_any_member() {
        let scratch: ScratchDir = ScratchDir::create("chain-invalid-group").expect("scratch");
        for siblings in [
            [
                descriptor("tree", false, 0o644),
                descriptor("tree/file", false, 0o644),
            ],
            [
                descriptor("tree/file", false, 0o644),
                descriptor("tree/./file", false, 0o644),
            ],
        ] {
            let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
            assert!(
                writer
                    .write(&artifact(1, &siblings[0], b"data"), &siblings)
                    .is_err()
            );
            assert!(!scratch.path().join("extracted").exists());
        }
    }

    #[cfg(unix)]
    #[test]
    fn modes_are_applied_after_contents_and_privileged_bits_are_removed() {
        use std::os::unix::fs::PermissionsExt as _;

        let scratch: ScratchDir = ScratchDir::create("chain-member-modes").expect("scratch");
        let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
        let siblings: [ChildHandle; 2] = [
            descriptor("readonly", true, 0o555),
            descriptor("readonly/program", false, 0o6755),
        ];
        writer
            .write(&artifact(1, &siblings[0], b""), &siblings)
            .expect("directory");
        writer
            .write(&artifact(1, &siblings[1], b"program"), &siblings)
            .expect("file after directory");
        writer.finish().expect("finish");
        let directory: PathBuf = scratch.path().join("extracted/readonly");
        let file: PathBuf = directory.join("program");
        assert_eq!(
            std::fs::metadata(&directory)
                .expect("directory metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            std::fs::metadata(&file)
                .expect("file metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
        assert_eq!(std::fs::read(file).expect("bytes"), b"program");
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))
            .expect("scratch cleanup permissions");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generic_children_preserve_case_distinct_linux_paths() {
        let scratch: ScratchDir = ScratchDir::create("chain-path-case").expect("scratch");
        let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
        let siblings: [ChildHandle; 2] = [
            descriptor("Name", false, 0o644),
            descriptor("name", false, 0o644),
        ];
        writer
            .write(&artifact(1, &siblings[0], b"upper"), &siblings)
            .expect("upper-case name");
        writer
            .write(&artifact(1, &siblings[1], b"lower"), &siblings)
            .expect("lower-case name");
        writer.finish().expect("finish");
        let root: PathBuf = scratch.path().join("extracted");
        assert_eq!(std::fs::read(root.join("Name")).expect("upper"), b"upper");
        assert_eq!(std::fs::read(root.join("name")).expect("lower"), b"lower");
    }

    #[cfg(unix)]
    #[test]
    fn an_existing_link_cannot_redirect_a_group_outside_the_output() {
        let scratch: ScratchDir = ScratchDir::create("chain-link-collision").expect("scratch");
        let outside: ScratchDir =
            ScratchDir::create("chain-link-outside").expect("outside scratch");
        let root: PathBuf = scratch.path().join("extracted");
        std::fs::create_dir(&root).expect("root");
        std::os::unix::fs::symlink(outside.path(), root.join("tree")).expect("link");
        let mut writer: ExtractedWriter = ExtractedWriter::new(scratch.path());
        let child: ChildHandle = descriptor("tree/file", false, 0o644);
        writer
            .write(
                &artifact(1, &child, b"contained"),
                std::slice::from_ref(&child),
            )
            .expect("contained fallback");
        writer.finish().expect("finish");
        assert!(!outside.path().join("file").exists());
        assert_eq!(
            std::fs::read(root.join("node1/tree/file")).expect("contained bytes"),
            b"contained"
        );
    }
}
