use std::path::Path;

use eyre::{Result, bail};

use crate::sync::run_one;

const fn region_mode(check: bool) -> crate::doc_region::Mode {
    if check {
        crate::doc_region::Mode::Check
    } else {
        crate::doc_region::Mode::Write
    }
}

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let mut stale: Vec<String> = Vec::new();

    run_one("schemas", check, || crate::run_schemas(check), &mut stale)?;
    run_one(
        "gen-bindings",
        check,
        || crate::run_gen_bindings(None, check),
        &mut stale,
    )?;
    run_one(
        "gen-error-docs",
        check,
        || crate::run_gen_error_docs(check),
        &mut stale,
    )?;
    run_one("sync", check, || crate::sync::run(root, check), &mut stale)?;
    run_one(
        "readme-stats",
        check,
        || crate::readme_stats::run(root),
        &mut stale,
    )?;
    run_one(
        "attack-surface",
        check,
        || crate::attack_surface::run(root),
        &mut stale,
    )?;
    run_one(
        "fuzz-scope",
        check,
        || crate::fuzz_scope::run(root),
        &mut stale,
    )?;
    run_one(
        "fuzz-surface",
        check,
        || crate::fuzz_surface::run(root, check),
        &mut stale,
    )?;
    run_one(
        "tiered-results",
        check,
        || crate::evidence_tiers::run(root),
        &mut stale,
    )?;
    run_one(
        "claim-provenance",
        check,
        || crate::facts::run(root),
        &mut stale,
    )?;
    run_one(
        "local-tags",
        check,
        || crate::local_tags::run(root),
        &mut stale,
    )?;
    run_one(
        "cross-data",
        check,
        || crate::crossdata::run(root),
        &mut stale,
    )?;
    run_one(
        "published-floors",
        check,
        || crate::floors::run(root),
        &mut stale,
    )?;
    run_one(
        "catalog-counts",
        check,
        || crate::catalog_counts::run(root),
        &mut stale,
    )?;
    run_one(
        "packer-roster",
        check,
        || crate::packer_roster::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "roster-breadth",
        check,
        || crate::roster_breadth::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "typography",
        check,
        || crate::typography::run(root),
        &mut stale,
    )?;
    run_one(
        "source-comments",
        check,
        || crate::comments::run(root),
        &mut stale,
    )?;
    run_one(
        "dotnet-string-evidence",
        check,
        || crate::dotnet_string_evidence::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "capability-reachability",
        check,
        || crate::capability_reachability::run(root),
        &mut stale,
    )?;
    run_one(
        "artifact-classification",
        check,
        || crate::artifact_map::run(root),
        &mut stale,
    )?;
    run_one(
        "published-figures",
        check,
        || crate::figures::run(root),
        &mut stale,
    )?;

    if check {
        if stale.is_empty() {
            println!(
                "xtask regen --check: every generated artifact is byte-fresh (schemas, bindings, error docs, demo, card, plugins, evidence), every documentation count inside a marker span matches recovery.json or the catalog tables the binary carries, the charts match the digest of the data they were rendered from, render every cell that data states, and match the copies mdbook serves, the out-of-process chart renderer still hashes to the digest those charts were pinned to, every committed artifact under docs/assets, docs/src/assets, docs/src/demo and editors carries a check classification in xtask/src/artifact_map.rs, every published figure in a committed markdown file is inside a marker span or pinned in xtask/src/figures.rs, no published markdown document carries a long dash or an emoji, no rust source opens a comment, the README stat, attack-surface, fuzz-scope and tiered-results cross-checks all hold, and every pass crate's count of uncalled graded capabilities matches its declared ceiling in xtask/src/capability_reachability.rs"
            );
            Ok(())
        } else {
            bail!(
                "xtask regen --check: {} artifact group(s) stale; run `cargo run -p xtask -- regen` to regenerate:\n  {}",
                stale.len(),
                stale.join("\n  ")
            )
        }
    } else {
        println!(
            "xtask regen: schemas, bindings, error docs, graphs, demo, card, plugins, evidence, and the documentation counts inside marker spans regenerated; README stat, attack-surface, fuzz-scope, tiered-results, published-markdown typography, source-comment and capability-reachability cross-checks ok"
        );
        Ok(())
    }
}
