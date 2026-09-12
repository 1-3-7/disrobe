use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, bail};

use crate::fileio::tracked_or_nonignored_files;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CheckClass {
    Regenerated,
    InputDigest,
    PinnedGenerator,
}

impl CheckClass {
    const fn label(self) -> &'static str {
        match self {
            Self::Regenerated => "regenerated-and-byte-compared",
            Self::InputDigest => "input-digest-stamped",
            Self::PinnedGenerator => "pinned-generator-source",
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
    pub(crate) checker: &'static str,
}

const CHART_CLASSES: &[CheckClass] = &[CheckClass::InputDigest, CheckClass::PinnedGenerator];
const RENDERED: &[CheckClass] = &[CheckClass::Regenerated];
const CHART_CHECKER: &str = "xtask/src/graphs.rs";
const CARD_CHECKER: &str = "xtask/src/card.rs";
const PLUGIN_CHECKER: &str = "xtask/src/plugins.rs";
const PLUGIN_INPUT: &str =
    "xtask/data/ecosystems.json and the plugin templates in xtask/src/plugins.rs";

const SWEPT_DIRS: [&str; 5] = [
    "docs/assets",
    "docs/src/assets",
    "docs/src/demo",
    "editors",
    "playground/public/brand",
];

const GENERATED_ARTIFACTS: [GeneratedArtifact; 43] = [
    GeneratedArtifact {
        path: "docs/assets/architecture.png",
        classes: RENDERED,
        input: "docs/assets/architecture.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/ecosystems.png",
        classes: RENDERED,
        input: "docs/assets/ecosystems.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/ir-ladder.png",
        classes: RENDERED,
        input: "docs/assets/ir-ladder.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/python-versions.png",
        classes: RENDERED,
        input: "docs/assets/python-versions.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/recovery.png",
        classes: RENDERED,
        input: "docs/assets/recovery.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/verification.png",
        classes: RENDERED,
        input: "docs/assets/verification.svg rasterized with pinned fonts; regenerated and byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/ir-ladder.svg",
        classes: RENDERED,
        input: "docs/assets/ir-ladder.svg; the mdbook copy is byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/ir-ladder.png",
        classes: RENDERED,
        input: "docs/assets/ir-ladder.png; the mdbook copy is byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/recovery.png",
        classes: RENDERED,
        input: "docs/assets/recovery.png; the mdbook copy is byte-compared by graphgen --check",
        checker: CHART_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/banner-light.svg",
        classes: RENDERED,
        input: "xtask/data/brand.json and pinned display fonts",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/banner-dark.svg",
        classes: RENDERED,
        input: "xtask/data/brand.json and pinned display fonts",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/brand-mark-light.svg",
        classes: RENDERED,
        input: "xtask/data/brand.json",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/src/assets/brand-mark-dark.svg",
        classes: RENDERED,
        input: "xtask/data/brand.json",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/theme/tokens.css",
        classes: RENDERED,
        input: "xtask/data/brand.json and pinned display fonts",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "playground/src/brand.css",
        classes: RENDERED,
        input: "xtask/data/brand.json and pinned display fonts",
        checker: CARD_CHECKER,
    },
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
        input: "xtask/data/brand.json and pinned display fonts",
        checker: CARD_CHECKER,
    },
    GeneratedArtifact {
        path: "docs/assets/social-card.png",
        classes: RENDERED,
        input: "the card SVG rasterized by xtask/graphgen/brand.mjs",
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
        path: "editors/vscode/LICENSE",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/.vscodeignore",
        classes: RENDERED,
        input: PLUGIN_INPUT,
        checker: PLUGIN_CHECKER,
    },
    GeneratedArtifact {
        path: "editors/vscode/build.mjs",
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

const ARTIFACT_FAMILIES: [ArtifactFamily; 11] = [
    ArtifactFamily {
        dir: "docs/assets/brand",
        checker: CARD_CHECKER,
    },
    ArtifactFamily {
        dir: "docs/src/assets/brand",
        checker: CARD_CHECKER,
    },
    ArtifactFamily {
        dir: "docs/src/assets/fonts",
        checker: CARD_CHECKER,
    },
    ArtifactFamily {
        dir: "docs/src/assets/walkthrough",
        checker: "docs/demo/render-media.mjs",
    },
    ArtifactFamily {
        dir: "editors/vscode/tests",
        checker: PLUGIN_CHECKER,
    },
    ArtifactFamily {
        dir: "playground/public/brand",
        checker: CARD_CHECKER,
    },
    ArtifactFamily {
        dir: "schemas/v0/json",
        checker: "xtask/src/main.rs",
    },
    ArtifactFamily {
        dir: "bindings/python",
        checker: "xtask/src/codegen.rs",
    },
    ArtifactFamily {
        dir: "bindings/typescript",
        checker: "xtask/src/codegen.rs",
    },
    ArtifactFamily {
        dir: "docs/errors",
        checker: "xtask/src/errdocs.rs",
    },
    ArtifactFamily {
        dir: "evidence/results",
        checker: "xtask/src/evidence.rs",
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
    let files: BTreeSet<String> = tracked_or_nonignored_files(root)?;
    for dir in SWEPT_DIRS {
        let path: PathBuf = joined(root, dir);
        if !path.is_dir() {
            faults.push(format!(
                "{dir} is swept for unclassified generated artifacts but is not a directory, so a new artifact there would reach a reader unchecked"
            ));
            continue;
        }
        sweep(dir, &files, &mut faults);
    }

    if !faults.is_empty() {
        bail!(
            "{} generated artifact(s) carry no check that would notice a change to their input; \
             every committed file under {} must have an artifact or family entry in \
             xtask/src/artifact_map.rs beside the check that guards it:\n  {}",
            faults.len(),
            SWEPT_DIRS.join(", "),
            faults.join("\n  ")
        )
    }

    let mut checker_counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for artifact in &GENERATED_ARTIFACTS {
        checker_counts.entry(artifact.checker).or_default().0 += 1;
    }
    for family in &ARTIFACT_FAMILIES {
        checker_counts.entry(family.checker).or_default().1 += 1;
    }
    for (checker, (artifacts, families)) in checker_counts {
        println!(
            "xtask regen: {checker} checks {artifacts} generated artifact(s) and {families} generated family(ies)"
        );
    }
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

fn sweep(dir: &str, files: &BTreeSet<String>, faults: &mut Vec<String>) {
    let prefix: String = format!("{dir}/");
    for relative in files
        .iter()
        .filter(|path: &&String| path.starts_with(&prefix))
    {
        let classified: bool = GENERATED_ARTIFACTS
            .iter()
            .any(|artifact: &GeneratedArtifact| artifact.path == relative)
            || ARTIFACT_FAMILIES.iter().any(|family: &ArtifactFamily| {
                relative
                    .strip_prefix(family.dir)
                    .is_some_and(|suffix: &str| suffix.starts_with('/'))
            });
        if !classified {
            faults.push(format!(
                "{relative} sits under generated-artifact directory {dir} with no check \
                 classification"
            ));
        }
    }
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
                    .any(|artifact: &GeneratedArtifact| artifact.path.starts_with(&prefix))
                    || ARTIFACT_FAMILIES
                        .iter()
                        .any(|family: &ArtifactFamily| family.dir == dir),
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
        let files: BTreeSet<String> = [
            "docs/assets/recovery.svg".to_owned(),
            "docs/assets/unlisted.svg".to_owned(),
        ]
        .into_iter()
        .collect();
        sweep("docs/assets", &files, &mut faults);
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(faults[0].contains("docs/assets/unlisted.svg"), "{faults:?}");
        Ok(())
    }

    #[test]
    fn ignored_files_absent_from_the_inventory_are_not_swept() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let modules: PathBuf = dir.path().join("editors").join("node_modules");
        std::fs::create_dir_all(&modules)?;
        std::fs::write(modules.join("index.js"), b"")?;
        std::fs::write(dir.path().join("editors").join("install.sh"), b"")?;
        let mut faults: Vec<String> = Vec::new();
        let files: BTreeSet<String> = BTreeSet::from(["editors/install.sh".to_owned()]);
        sweep("editors", &files, &mut faults);
        assert!(faults.is_empty(), "{faults:?}");
        Ok(())
    }

    #[test]
    fn a_family_owns_descendants_without_owning_similarly_named_siblings() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        let assets: PathBuf = dir.path().join("docs/assets");
        std::fs::create_dir_all(assets.join("brand/nested"))?;
        std::fs::create_dir_all(assets.join("branding"))?;
        std::fs::write(assets.join("brand/nested/mark.svg"), b"<svg></svg>")?;
        std::fs::write(assets.join("branding/unowned.svg"), b"<svg></svg>")?;
        let mut faults: Vec<String> = Vec::new();
        let files: BTreeSet<String> = [
            "docs/assets/brand/nested/mark.svg".to_owned(),
            "docs/assets/branding/unowned.svg".to_owned(),
        ]
        .into_iter()
        .collect();
        sweep("docs/assets", &files, &mut faults);
        assert_eq!(faults.len(), 1, "{faults:?}");
        assert!(
            faults[0].contains("docs/assets/branding/unowned.svg"),
            "{faults:?}"
        );
        Ok(())
    }
}
