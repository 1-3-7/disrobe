use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LinkKind {
    Symlink,
    #[cfg_attr(not(windows), allow(dead_code))]
    Junction,
    Copy,
}

impl LinkKind {
    #[inline]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Symlink => "symlink",
            Self::Junction => "junction",
            Self::Copy => "copy",
        }
    }
}

#[cfg(windows)]
pub(crate) fn link_final(stage_dir: &Path, final_dir: &Path) -> miette::Result<LinkKind> {
    let stage_abs: std::path::PathBuf = std::fs::canonicalize(stage_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0231: cannot resolve stage dir {}: {e}",
            stage_dir.display()
        )
    })?;
    if final_dir.exists() {
        remove_dir_any(final_dir)?;
    }
    if let Some(parent) = final_dir.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            miette::miette!(
                "DR-CLI-0230: cannot create parent dir {}: {e}",
                parent.display()
            )
        })?;
    }
    if std::os::windows::fs::symlink_dir(&stage_abs, final_dir).is_ok() {
        return Ok(LinkKind::Symlink);
    }
    if mklink_junction(&stage_abs, final_dir).is_ok() {
        return Ok(LinkKind::Junction);
    }
    recursive_copy(&stage_abs, final_dir)?;
    Ok(LinkKind::Copy)
}

#[cfg(unix)]
pub(crate) fn link_final(stage_dir: &Path, final_dir: &Path) -> miette::Result<LinkKind> {
    let stage_abs: std::path::PathBuf = std::fs::canonicalize(stage_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0231: cannot resolve stage dir {}: {e}",
            stage_dir.display()
        )
    })?;
    if final_dir.exists() || final_dir.is_symlink() {
        remove_dir_any(final_dir)?;
    }
    if let Some(parent) = final_dir.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            miette::miette!(
                "DR-CLI-0230: cannot create parent dir {}: {e}",
                parent.display()
            )
        })?;
    }
    if std::os::unix::fs::symlink(&stage_abs, final_dir).is_ok() {
        Ok(LinkKind::Symlink)
    } else {
        recursive_copy(&stage_abs, final_dir)?;
        Ok(LinkKind::Copy)
    }
}

#[cfg(not(any(windows, unix)))]
pub(crate) fn link_final(stage_dir: &Path, final_dir: &Path) -> miette::Result<LinkKind> {
    if final_dir.exists() {
        remove_dir_any(final_dir)?;
    }
    recursive_copy(stage_dir, final_dir)?;
    Ok(LinkKind::Copy)
}

#[cfg(windows)]
fn mklink_junction(stage_dir: &Path, final_dir: &Path) -> std::io::Result<()> {
    use std::process::Command;
    let status: std::process::ExitStatus = Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &final_dir.display().to_string(),
            &stage_dir.display().to_string(),
        ])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "mklink /J exited with {:?}",
            status.code()
        )))
    }
}

fn remove_dir_any(target: &Path) -> miette::Result<()> {
    let meta: std::io::Result<std::fs::Metadata> = std::fs::symlink_metadata(target);
    match meta {
        Ok(m) if m.file_type().is_symlink() => std::fs::remove_file(target).map_err(|e| {
            miette::miette!(
                "DR-CLI-0231: cannot remove symlink {}: {e}",
                target.display()
            )
        }),
        Ok(m) if m.file_type().is_dir() => std::fs::remove_dir_all(target).map_err(|e| {
            miette::miette!("DR-CLI-0232: cannot remove dir {}: {e}", target.display())
        }),
        Ok(_) => std::fs::remove_file(target).map_err(|e| {
            miette::miette!("DR-CLI-0233: cannot remove file {}: {e}", target.display())
        }),
        Err(_) => Ok(()),
    }
}

fn recursive_copy(src: &Path, dst: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dst)
        .map_err(|e| miette::miette!("DR-CLI-0234: cannot create dst {}: {e}", dst.display()))?;
    let entries: std::fs::ReadDir = std::fs::read_dir(src)
        .map_err(|e| miette::miette!("DR-CLI-0235: cannot read src {}: {e}", src.display()))?;
    for entry_res in entries {
        let entry: std::fs::DirEntry = entry_res.map_err(|e| {
            miette::miette!("DR-CLI-0236: dir entry error in {}: {e}", src.display())
        })?;
        let entry_path: std::path::PathBuf = entry.path();
        let entry_name: std::ffi::OsString = entry.file_name();
        let target_path: std::path::PathBuf = dst.join(&entry_name);
        let file_type: std::fs::FileType = entry.file_type().map_err(|e| {
            miette::miette!(
                "DR-CLI-0237: file_type failed for {}: {e}",
                entry_path.display()
            )
        })?;
        if file_type.is_dir() {
            recursive_copy(&entry_path, &target_path)?;
        } else if file_type.is_symlink() {
            let link_target: std::path::PathBuf = std::fs::read_link(&entry_path).map_err(|e| {
                miette::miette!("DR-CLI-0238: read_link {}: {e}", entry_path.display())
            })?;
            let _ = std::fs::remove_file(&target_path);
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link_target, &target_path).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0239: symlink {} -> {}: {e}",
                    target_path.display(),
                    link_target.display()
                )
            })?;
            #[cfg(windows)]
            {
                let _: std::path::PathBuf = link_target.clone();
                let _: std::io::Result<()> = std::fs::copy(&entry_path, &target_path).map(|_| ());
            }
        } else {
            let _: u64 = std::fs::copy(&entry_path, &target_path).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0240: copy {} -> {}: {e}",
                    entry_path.display(),
                    target_path.display()
                )
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchDir;

    fn unique_tmp(stem: &str) -> ScratchDir {
        let purpose: String = format!("disrobe-link-{stem}");
        ScratchDir::create(&purpose).expect("create scratch directory")
    }

    #[test]
    fn link_kind_labels() {
        assert_eq!(LinkKind::Symlink.label(), "symlink");
        assert_eq!(LinkKind::Junction.label(), "junction");
        assert_eq!(LinkKind::Copy.label(), "copy");
    }

    #[test]
    fn link_final_creates_target_pointing_at_stage() {
        let root_scratch: ScratchDir = unique_tmp("root");
        let root: std::path::PathBuf = root_scratch.path().to_path_buf();
        let stage: std::path::PathBuf = root.join("stage");
        let final_dir: std::path::PathBuf = root.join("final");
        std::fs::create_dir_all(&stage).expect("mk stage");
        std::fs::write(stage.join("ok.txt"), b"hello").expect("write ok");
        let kind: LinkKind = link_final(&stage, &final_dir).expect("link");
        assert!(matches!(
            kind,
            LinkKind::Symlink | LinkKind::Junction | LinkKind::Copy
        ));
        let inside: std::path::PathBuf = final_dir.join("ok.txt");
        assert!(inside.exists(), "expected ok.txt visible via {kind:?}");
    }

    #[test]
    fn link_final_replaces_existing_target() {
        let root_scratch: ScratchDir = unique_tmp("replace");
        let root: std::path::PathBuf = root_scratch.path().to_path_buf();
        let stage: std::path::PathBuf = root.join("stage");
        let final_dir: std::path::PathBuf = root.join("final");
        std::fs::create_dir_all(&stage).expect("mk stage");
        std::fs::create_dir_all(&final_dir).expect("pre final");
        std::fs::write(final_dir.join("old.txt"), b"old").expect("write old");
        std::fs::write(stage.join("new.txt"), b"new").expect("write new");
        let _ = link_final(&stage, &final_dir).expect("link");
        assert!(final_dir.join("new.txt").exists());
    }
}
