use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CheckClass {
    Regenerated,
    InputDigest,
    PinnedGenerator,
}

impl CheckClass {
    const ALL: [Self; 3] = [Self::Regenerated, Self::InputDigest, Self::PinnedGenerator];

    const fn label(self) -> &'static str {
        match self {
            Self::Regenerated => "regenerated-and-byte-compared",
            Self::InputDigest => "input-digest-stamped",
            Self::PinnedGenerator => "pinned-generator-source",
        }
    }

    const fn proves(self) -> &'static str {
        match self {
            Self::Regenerated => {
                "the committed bytes are what the generator produces from the committed input"
            }
            Self::InputDigest => {
                "the committed bytes were produced from the committed input, not that the input \
                 states a measured truth"
            }
            Self::PinnedGenerator => {
                "the out-of-process generator has not changed since the committed bytes were \
                 pinned to it"
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GeneratedArtifact {
    pub(crate) path: &'static str,
    pub(crate) classes: &'static [CheckClass],
    pub(crate) input: &'static str,
    pub(crate) checker: &'static str,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ArtifactFamily {
    pub(crate) dir: &'static str,
    pub(crate) classes: &'static [CheckClass],
    pub(crate) input: &'static str,
    pub(crate) checker: &'static str,
    pub(crate) orphan_guard: &'static str,
}

const CHART_CLASSES: &[CheckClass] = &[CheckClass::InputDigest, CheckClass::PinnedGenerator];
const RENDERED: &[CheckClass] = &[CheckClass::Regenerated];
const CHART_CHECKER: &str = "xtask/src/graphs.rs";
const CARD_CHECKER: &str = "xtask/src/card.rs";
const PLUGIN_CHECKER: &str = "xtask/src/plugins.rs";
const PLUGIN_INPUT: &str =
    "xtask/data/ecosystems.json and the plugin templates in xtask/src/plugins.rs";

const SWEPT_DIRS: [&str; 4] = ["docs/assets", "docs/src/assets", "docs/src/demo", "editors"];

const SWEEP_SKIPPED_DIR_NAMES: [&str; 6] = [
    ".git",
    "node_modules",
    "out",
    "dist",
    "target",
    ".vscode-test",
];

const GENERATED_ARTIFACTS: [GeneratedArtifact; 25] = [
    GeneratedArtifact {
        path: "docs/assets/architecture.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/architecture.json",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/ecosystems.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/ecosystems.json",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/ir-ladder.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/ir_ladder.json",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/python-versions.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/python_versions.json",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/recovery.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/recovery.json and evidence/descriptors",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/verification.svg",
        classes: CHART_CLASSES,
        input: "xtask/data/verification.json",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/social-card.svg",
        classes: RENDERED,
        input: "xtask/data/recovery.json, xtask/data/verification.json and the catalog tables the binary carries",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/social-card.png",
        classes: RENDERED,
        input: "the card SVG rasterized by xtask/graphgen/render_social_card.mjs",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/recovery.svg",
        classes: CHART_CLASSES,
        input: "docs/assets/recovery.svg, the copy mdbook serves",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/social-card.svg",
        classes: RENDERED,
        input: "the same render as docs/assets/social-card.svg",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/social-card.png",
        classes: RENDERED,
        input: "the same raster as docs/assets/social-card.png",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/demo/disrobe-demo.svg",
        classes: RENDERED,
        input: "docs/demo/disrobe.cast",
        checker: "xtask/src/demo.rs",
    },
    GeneratedArtifact {
        path: "editors/binja/README.md",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/binja/__init__.py",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/binja/plugin.json",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/ghidra/DisrobeAnalyzer.java",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/ghidra/README.md",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/ida/README.md",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/ida/disrobe_ida.py",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/install.ps1",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/install.sh",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/README.md",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/package.json",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/src/extension.ts",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/tsconfig.json",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
];

const ARTIFACT_FAMILIES: [ArtifactFamily; 5] = [
    ArtifactFamily {
        dir: "schemas/v0/json",
        classes: RENDERED,
        input: "the schema builders in xtask/src/main.rs",
        checker: "xtask/src/main.rs",
        orphan_guard: "whole-tree diff against a regenerated copy",
    },
    ArtifactFamily {
        dir: "bindings/python",
        classes: RENDERED,
        input: "schemas/v0/json",
        checker: "xtask/src/codegen.rs",
        orphan_guard: "flat diff over .pyi and .checksum.json",
    },
    ArtifactFamily {
        dir: "bindings/typescript",
        classes: RENDERED,
        input: "schemas/v0/json",
        checker: "xtask/src/codegen.rs",
        orphan_guard: "flat diff over .d.ts and .checksum.json",
    },
    ArtifactFamily {
        dir: "docs/errors",
        classes: RENDERED,
        input: "the error registry the binary parses",
        checker: "xtask/src/errdocs.rs",
        orphan_guard: "whole-tree diff against a regenerated copy",
    },
    ArtifactFamily {
        dir: "evidence/results",
        classes: RENDERED,
        input: "evidence/descriptors and the measurement files they name",
        checker: "xtask/src/evidence.rs",
        orphan_guard: "descriptor-driven render with an explicit orphan pass",
    },
];

pub(crate) fn run(root: &Path) -> Result<()> {
    let mut faults: Vec<String> = Vec::new();
    for artifact in &GENERATED_ARTIFACTS {
        let path: PathBuf = joined(root, artifact.path);
        if !path.is_file() {
            faults.push(format!(
                "{} is classified as {} against {} but is not committed",
                artifact.path,
                class_labels(artifact.classes),
                artifact.input
            ));
        }
    }
    for family in &ARTIFACT_FAMILIES {
        let path: PathBuf = joined(root, family.dir);
        if !path.is_dir() {
            faults.push(format!(
                "{} is classified as a generated family checked by {} but is not a directory",
                family.dir, family.checker
            ));
        }
    }
    for dir in SWEPT_DIRS {
        sweep(root, dir, &mut faults)?;
    }

    if !faults.is_empty() {
        bail!(
            "{} generated artifact(s) carry no check that would notice a change to their input; \
             every committed file under {} must appear in GENERATED_ARTIFACTS in \
             xtask/src/artifact_map.rs beside the check that guards it:\n  {}",
            faults.len(),
            SWEPT_DIRS.join(", "),
            faults.join("\n  ")
        )
    }

    let mut census: BTreeMap<CheckClass, usize> = BTreeMap::new();
    for classes in GENERATED_ARTIFACTS
        .iter()
        .map(|artifact: &GeneratedArtifact| artifact.classes)
        .chain(
            ARTIFACT_FAMILIES
                .iter()
                .map(|family: &ArtifactFamily| family.classes),
        )
    {
        for class in classes {
            *census.entry(*class).or_default() += 1;
        }
    }
    for artifact in &GENERATED_ARTIFACTS {
        println!(
            "xtask regen: {} is {}, checked by {} against {}",
            artifact.path,
            class_labels(artifact.classes),
            artifact.checker,
            artifact.input
        );
    }
    for family in &ARTIFACT_FAMILIES {
        println!(
            "xtask regen: {}/ is {}, checked by {} against {}, orphans caught by a {}",
            family.dir,
            class_labels(family.classes),
            family.checker,
            family.input,
            family.orphan_guard
        );
    }
    let coverage: String = CheckClass::ALL
        .iter()
        .map(|class: &CheckClass| {
            format!(
                "{} {} (proves {})",
                census.get(class).copied().unwrap_or_default(),
                class.label(),
                class.proves()
            )
        })
        .collect::<Vec<String>>()
        .join("; ");
    println!(
        "xtask regen: generated-artifact classification ok ({} committed artifact(s) and {} \
         generated family(ies) classified, nothing unlisted under {}): {coverage}",
        GENERATED_ARTIFACTS.len(),
        ARTIFACT_FAMILIES.len(),
        SWEPT_DIRS.join(", ")
    );
    Ok(())
}

fn class_labels(classes: &[CheckClass]) -> String {
    classes
        .iter()
        .map(|class: &CheckClass| class.label().to_owned())
        .collect::<Vec<String>>()
        .join(" + ")
}

fn joined(root: &Path, relative: &str) -> PathBuf {
    let mut path: PathBuf = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

fn skipped_dir(dirent: &walkdir::DirEntry) -> bool {
    dirent.file_type().is_dir()
        && dirent
            .file_name()
            .to_str()
            .is_some_and(|name: &str| SWEEP_SKIPPED_DIR_NAMES.contains(&name))
}

fn sweep(root: &Path, dir: &str, faults: &mut Vec<String>) -> Result<()> {
    let base: PathBuf = joined(root, dir);
    if !base.is_dir() {
        bail!(
            "{dir} is swept for unclassified generated artifacts but is not a directory, so a new \
             artifact there would reach a reader unchecked"
        );
    }
    let walker: walkdir::IntoIter = walkdir::WalkDir::new(&base).into_iter();
    for entry in walker.filter_entry(|dirent: &walkdir::DirEntry| !skipped_dir(dirent)) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", base.display()))?;
        let path: &Path = dirent.path();
        if !path.is_file() {
            continue;
        }
        let relative: String = path
            .strip_prefix(root)
            .wrap_err_with(|| format!("stripping prefix from {}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/");
        let classified: bool = GENERATED_ARTIFACTS
            .iter()
            .any(|artifact: &GeneratedArtifact| artifact.path == relative);
        if !classified {
            faults.push(format!(
                "{relative} sits under generated-artifact directory {dir} with no check \
                 classification"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_artifact_path_is_relative_and_unique() {
        let mut seen: Vec<&'static str> = Vec::new();
        for artifact in &GENERATED_ARTIFACTS {
            assert!(
                !artifact.path.starts_with('/') && !artifact.path.contains(".."),
                "{} must be a repository-relative path",
                artifact.path
            );
            assert!(
                !artifact.classes.is_empty(),
                "{} must carry at least one check class",
                artifact.path
            );
            assert!(
                !seen.contains(&artifact.path),
                "{} is classified twice",
                artifact.path
            );
            seen.push(artifact.path);
        }
    }

    #[test]
    fn every_classification_names_a_checker_that_exists() {
        let manifest: &str = env!("CARGO_MANIFEST_DIR");
        let root: &Path = Path::new(manifest)
            .parent()
            .unwrap_or_else(|| Path::new(manifest));
        for checker in GENERATED_ARTIFACTS
            .iter()
            .map(|artifact: &GeneratedArtifact| artifact.checker)
            .chain(
                ARTIFACT_FAMILIES
                    .iter()
                    .map(|family: &ArtifactFamily| family.checker),
            )
        {
            assert!(
                joined(root, checker).is_file(),
                "{checker} is named as the check that guards a generated artifact but does not exist"
            );
        }
    }

    #[test]
    fn every_swept_directory_holds_at_least_one_classified_artifact() {
        for dir in SWEPT_DIRS {
            let prefix: String = format!("{dir}/");
            assert!(
                GENERATED_ARTIFACTS
                    .iter()
                    .any(|artifact: &GeneratedArtifact| artifact.path.starts_with(&prefix)),
                "swept directory {dir} classifies nothing, so the sweep would reject every file it holds"
            );
        }
    }

    #[test]
    fn an_unclassified_file_in_a_swept_directory_is_reported() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let assets: PathBuf = dir.path().join("docs").join("assets");
        std::fs::create_dir_all(&assets)?;
        std::fs::write(assets.join("recovery.svg"), b"<svg></svg>")?;
        std::fs::write(assets.join("unlisted.svg"), b"<svg></svg>")?;
        let mut faults: Vec<String> = Vec::new();
        sweep(dir.path(), "docs/assets", &mut faults)?;
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(faults[0].contains("docs/assets/unlisted.svg"), "{faults:?}");
        Ok(())
    }

    #[test]
    fn a_skipped_build_directory_is_not_swept() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let modules: PathBuf = dir.path().join("editors").join("node_modules");
        std::fs::create_dir_all(&modules)?;
        std::fs::write(modules.join("index.js"), b"")?;
        std::fs::write(dir.path().join("editors").join("install.sh"), b"")?;
        let mut faults: Vec<String> = Vec::new();
        sweep(dir.path(), "editors", &mut faults)?;
        assert!(faults.is_empty(), "{faults:?}");
        Ok(())
    }
}
