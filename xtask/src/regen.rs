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
        "skip-census",
        check,
        || crate::skip_census::run(root),
        &mut stale,
    )?;
    run_one(
        "denominator-floor",
        check,
        || crate::denominator_floor::run(root),
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
                "xtask regen --check: generated artifacts are current; publication and capability checks passed"
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
        println!("xtask regen: artifacts regenerated; publication and capability checks passed");
        Ok(())
    }
}
