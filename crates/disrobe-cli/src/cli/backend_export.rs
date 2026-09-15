use std::path::{Component, Path, PathBuf};

use clap::ValueEnum;
#[cfg(any(feature = "jvm", feature = "flutter"))]
use disrobe_pass_native::backend_export::ExportFormat;

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BackendExportTarget {
    Ghidra,
    Ida,
    Json,
}

impl BackendExportTarget {
    #[cfg(any(feature = "jvm", feature = "flutter"))]
    pub(crate) const fn format(self) -> ExportFormat {
        match self {
            Self::Ghidra => ExportFormat::Ghidra,
            Self::Ida => ExportFormat::Ida,
            Self::Json => ExportFormat::Json,
        }
    }

    #[cfg(feature = "jvm")]
    pub(crate) fn standalone_path(self, stem: &str) -> PathBuf {
        PathBuf::from(format!(
            "{stem}.{extension}",
            extension = self.format().sidecar_extension()
        ))
    }

    #[cfg(feature = "jvm")]
    pub(crate) fn auto_path(self) -> PathBuf {
        let filename: &str = match self {
            Self::Ghidra => "symbols.ghidra.java",
            Self::Ida => "symbols.ida.py",
            Self::Json => "symbols.json",
        };
        PathBuf::from("exports").join("dalvik").join(filename)
    }

    #[cfg(feature = "flutter")]
    pub(crate) fn flutter_auto_path(self) -> PathBuf {
        let filename: &str = match self {
            Self::Ghidra => "symbols.ghidra.java",
            Self::Ida => "symbols.ida.py",
            Self::Json => "symbols.json",
        };
        PathBuf::from("exports").join("flutter").join(filename)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SupplementalOutput {
    relative_path: PathBuf,
    bytes: Vec<u8>,
}

impl SupplementalOutput {
    #[cfg(any(feature = "jvm", feature = "flutter"))]
    pub(crate) fn new(relative_path: PathBuf, bytes: Vec<u8>) -> miette::Result<Self> {
        validate_relative_path(&relative_path)?;
        Ok(Self {
            relative_path,
            bytes,
        })
    }

    pub(crate) fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn validate_relative_path(path: &Path) -> miette::Result<()> {
    let mut components: usize = 0;
    for component in path.components() {
        match component {
            Component::Normal(_) => components = components.saturating_add(1),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(miette::miette!(
                    "DR-CLI-0438: Dalvik symbol export path must be a normalized relative path: {}",
                    path.display()
                ));
            }
        }
    }
    if components == 0 {
        return Err(miette::miette!(
            "DR-CLI-0438: Dalvik symbol export path must not be empty"
        ));
    }
    Ok(())
}

pub(crate) fn write_supplemental_output(
    out_dir: &Path,
    output: &SupplementalOutput,
) -> miette::Result<PathBuf> {
    validate_relative_path(output.relative_path())?;
    let path: PathBuf = out_dir.join(output.relative_path());
    let parent: &Path = path.parent().ok_or_else(|| {
        miette::miette!(
            "DR-CLI-0438: Dalvik symbol export path has no parent: {}",
            path.display()
        )
    })?;
    std::fs::create_dir_all(parent).map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-CLI-0439: cannot create Dalvik symbol export directory {}: {error}",
            parent.display()
        )
    })?;
    std::fs::write(&path, output.bytes()).map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-CLI-0440: cannot write Dalvik symbol export {}: {error}",
            path.display()
        )
    })?;
    Ok(path)
}

#[cfg(all(test, feature = "jvm"))]
mod tests {
    use super::*;

    #[test]
    fn supplemental_paths_reject_escape_and_absolute_components() {
        for path in [
            PathBuf::from("../symbols.json"),
            PathBuf::from("/symbols.json"),
        ] {
            assert!(SupplementalOutput::new(path, Vec::new()).is_err());
        }
    }
}
