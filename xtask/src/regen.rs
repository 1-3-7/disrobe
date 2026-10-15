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

    run_one("schemas", true, || crate::run_schemas(check), &mut stale)?;
    run_one(
        "gen-bindings",
        true,
        || crate::run_gen_bindings(None, check),
        &mut stale,
    )?;
    run_one(
        "gen-error-docs",
        true,
        || crate::run_gen_error_docs(check),
        &mut stale,
    )?;
    run_one(
        "errcodes",
        true,
        || crate::errcodes::run(root, check, false),
        &mut stale,
    )?;
    run_one("sync", true, || crate::sync::run(root, check), &mut stale)?;
    run_one(
        "attack-surface",
        true,
        || crate::attack_surface::run(root),
        &mut stale,
    )?;
    run_one(
        "fuzz-scope",
        true,
        || crate::fuzz_scope::run(root),
        &mut stale,
    )?;
    run_one(
        "fuzz-surface",
        true,
        || crate::fuzz_surface::run(root, check),
        &mut stale,
    )?;
    run_one(
        "claim-provenance",
        true,
        || crate::facts::run(root),
        &mut stale,
    )?;
    run_one(
        "local-tags",
        true,
        || crate::local_tags::run(root),
        &mut stale,
    )?;
    run_one(
        "cross-data",
        true,
        || crate::crossdata::run(root),
        &mut stale,
    )?;
    run_one(
        "published-floors",
        true,
        || crate::floors::run(root),
        &mut stale,
    )?;
    run_one(
        "catalog-counts",
        true,
        || crate::catalog_counts::run(root),
        &mut stale,
    )?;
    run_one(
        "packer-roster",
        true,
        || crate::packer_roster::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "roster-breadth",
        true,
        || crate::roster_breadth::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "typography",
        true,
        || crate::typography::run(root),
        &mut stale,
    )?;
    run_one(
        "source-comments",
        true,
        || crate::comments::run(root),
        &mut stale,
    )?;
    run_one(
        "dotnet-string-evidence",
        true,
        || crate::dotnet_string_evidence::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "capability-reachability",
        true,
        || crate::capability_reachability::run(root),
        &mut stale,
    )?;
    run_one(
        "skip-census",
        true,
        || crate::skip_census::run(root),
        &mut stale,
    )?;
    run_one(
        "denominator-floor",
        true,
        || crate::denominator_floor::run(root),
        &mut stale,
    )?;
    run_one(
        "artifact-classification",
        true,
        || crate::artifact_map::run(root),
        &mut stale,
    )?;
    run_one(
        "input-bounds",
        true,
        || crate::input_bounds::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "unsafe-inventory",
        true,
        || crate::unsafe_inventory::run(root, region_mode(check)),
        &mut stale,
    )?;
    run_one(
        "published-figures",
        true,
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
    } else if stale.is_empty() {
        println!("xtask regen: artifacts regenerated; publication and capability checks passed");
        Ok(())
    } else {
        bail!(
            "xtask regen: {} generation step(s) failed:\n  {}",
            stale.len(),
            stale.join("\n  ")
        )
    }
}
