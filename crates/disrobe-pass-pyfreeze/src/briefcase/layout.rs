use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub struct BriefcaseLayout {
    pub root: PathBuf,
    pub app_dir: Option<PathBuf>,
    pub app_packages_dir: Option<PathBuf>,
    pub python_stdlib_dir: Option<PathBuf>,
    pub briefcase_toml: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct BriefcaseSourceEntry {
    pub relative_name: String,
    pub disk_path: PathBuf,
    pub size: u64,
}

pub fn probe(binary_path: &Path) -> Result<BriefcaseLayout> {
    let dir: &Path = binary_path
        .parent()
        .ok_or_else(|| missing_sibling(binary_path, vec!["parent directory".to_owned()]))?;

    let candidates: [PathBuf; 4] = [
        dir.to_path_buf(),
        dir.join("Resources").join("app"),
        dir.join("..").join("Resources").join("app"),
        dir.join("app"),
    ];

    let mut layout: Option<BriefcaseLayout> = None;
    for cand in &candidates {
        let app_packages: PathBuf = cand.join("app_packages");
        let stdlib: PathBuf = cand.join("python-stdlib");
        let toml: PathBuf = cand.join("briefcase.toml");
        let manifest_yaml: PathBuf = cand.join("briefcase.yaml");
        if app_packages.is_dir() || stdlib.is_dir() || toml.is_file() || manifest_yaml.is_file() {
            layout = Some(BriefcaseLayout {
                root: cand.clone(),
                app_dir: if cand.join("app").is_dir() {
                    Some(cand.join("app"))
                } else {
                    Some(cand.clone())
                },
                app_packages_dir: app_packages.is_dir().then_some(app_packages),
                python_stdlib_dir: stdlib.is_dir().then_some(stdlib),
                briefcase_toml: toml.is_file().then_some(toml),
            });
            break;
        }
    }

    layout.ok_or_else(|| {
        missing_sibling(
            binary_path,
            vec![
                "app_packages/".to_owned(),
                "python-stdlib/".to_owned(),
                "briefcase.toml".to_owned(),
            ],
        )
    })
}

pub fn walk_python_sources(app_dir: &Path) -> Result<Vec<BriefcaseSourceEntry>> {
    if !app_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out: Vec<BriefcaseSourceEntry> = Vec::new();
    visit(app_dir, app_dir, &mut out)?;
    Ok(out)
}

fn visit(root: &Path, current: &Path, out: &mut Vec<BriefcaseSourceEntry>) -> Result<()> {
    let read: std::fs::ReadDir = std::fs::read_dir(current)?;
    for entry in read {
        let entry: std::fs::DirEntry = entry?;
        let path: PathBuf = entry.path();
        let file_type: std::fs::FileType = entry.file_type()?;
        if file_type.is_dir() {
            visit(root, &path, out)?;
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let meta: std::fs::Metadata = entry.metadata()?;
        let rel: String = path.strip_prefix(root).map_or_else(
            |_| path.display().to_string(),
            |p| p.to_string_lossy().replace('\\', "/"),
        );
        out.push(BriefcaseSourceEntry {
            relative_name: rel,
            disk_path: path,
            size: meta.len(),
        });
    }
    Ok(())
}

fn missing_sibling(binary_path: &Path, missing: Vec<String>) -> Error {
    Error::BriefcaseMissingSibling {
        binary: binary_path.display().to_string(),
        missing,
    }
}

pub fn counter() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_dir_without_briefcase_markers() {
        let tmp: PathBuf = tempdir();
        let bin: PathBuf = tmp.join("app.exe");
        std::fs::write(&bin, b"fake").expect("write");
        let err: Error = probe(&bin).expect_err("must fail");
        assert!(matches!(err, Error::BriefcaseMissingSibling { .. }));
    }

    #[test]
    fn probe_accepts_app_packages_sibling() {
        let tmp: PathBuf = tempdir();
        let bin: PathBuf = tmp.join("app.exe");
        std::fs::write(&bin, b"fake").expect("write");
        std::fs::create_dir_all(tmp.join("app_packages")).expect("mkdir");
        let layout: BriefcaseLayout = probe(&bin).expect("probe ok");
        assert!(layout.app_packages_dir.is_some());
    }

    #[test]
    fn probe_accepts_python_stdlib_sibling() {
        let tmp: PathBuf = tempdir();
        let bin: PathBuf = tmp.join("app.exe");
        std::fs::write(&bin, b"fake").expect("write");
        std::fs::create_dir_all(tmp.join("python-stdlib")).expect("mkdir");
        let layout: BriefcaseLayout = probe(&bin).expect("probe ok");
        assert!(layout.python_stdlib_dir.is_some());
    }

    #[test]
    fn probe_accepts_briefcase_toml_sibling() {
        let tmp: PathBuf = tempdir();
        let bin: PathBuf = tmp.join("app.exe");
        std::fs::write(&bin, b"fake").expect("write");
        std::fs::write(tmp.join("briefcase.toml"), b"[tool.briefcase]\n").expect("toml");
        let layout: BriefcaseLayout = probe(&bin).expect("probe ok");
        assert!(layout.briefcase_toml.is_some());
    }

    #[test]
    fn walk_collects_python_sources() {
        let tmp: PathBuf = tempdir();
        let app: PathBuf = tmp.join("app");
        std::fs::create_dir_all(app.join("pkg")).expect("mkdir");
        std::fs::write(app.join("main.py"), b"print('hi')").expect("write");
        std::fs::write(app.join("pkg").join("mod.py"), b"x=1").expect("write");
        let entries: Vec<BriefcaseSourceEntry> = walk_python_sources(&app).expect("walk");
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.relative_name == "main.py"));
        assert!(entries.iter().any(|e| e.relative_name == "pkg/mod.py"));
    }

    fn tempdir() -> PathBuf {
        let base: PathBuf = std::env::temp_dir();
        let unique: String = format!(
            "disrobe-briefcase-{}-{}",
            std::process::id(),
            super::counter()
        );
        let p: PathBuf = base.join(unique);
        std::fs::create_dir_all(&p).expect("mkdir tempdir");
        p
    }
}
