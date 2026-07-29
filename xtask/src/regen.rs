use std::path::Path;

use eyre::{Result, bail};

use crate::sync::run_one;

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let mut stale: Vec<String> = Vec::new();

    run_one("schemas", check, || crate::run_schemas(check), &mut stale);
    run_one(
        "gen-bindings",
        check,
        || crate::run_gen_bindings(None, check),
        &mut stale,
    );
    run_one(
        "gen-error-docs",
        check,
        || crate::run_gen_error_docs(check),
        &mut stale,
    );
    run_one("sync", check, || crate::sync::run(root, check), &mut stale);
    run_one(
        "readme-stats",
        check,
        || crate::readme_stats::run(root),
        &mut stale,
    );
    run_one(
        "attack-surface",
        check,
        || crate::attack_surface::run(root),
        &mut stale,
    );
    run_one(
        "fuzz-scope",
        check,
        || crate::fuzz_scope::run(root),
        &mut stale,
    );
    run_one(
        "tiered-results",
        check,
        || crate::evidence_tiers::run(root),
        &mut stale,
    );
    run_one(
        "claim-provenance",
        check,
        || crate::facts::run(root),
        &mut stale,
    );
    run_one(
        "cross-data",
        check,
        || crate::crossdata::run(root),
        &mut stale,
    );

    if check {
        if stale.is_empty() {
            println!(
                "xtask regen --check: every generated artifact is byte-fresh (schemas, bindings, error docs, demo, card, plugins, evidence), the charts match the digest of the data they were rendered from and the copies mdbook serves, and the README stat, attack-surface, fuzz-scope and tiered-results cross-checks all hold"
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
            "xtask regen: schemas, bindings, error docs, graphs, demo, card, plugins, and evidence regenerated; README stat, attack-surface, fuzz-scope, and tiered-results cross-checks ok"
        );
        Ok(())
    }
}
