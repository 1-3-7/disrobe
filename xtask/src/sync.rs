use std::path::Path;

use eyre::Result;

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let mut stale: Vec<String> = Vec::new();

    run_one(
        "graphs",
        check,
        || crate::graphs::run(root, check),
        &mut stale,
    );
    run_one("card", check, || crate::card::run(root, check), &mut stale);
    run_one("demo", check, || crate::demo::run(root, check), &mut stale);
    run_one(
        "plugins",
        check,
        || crate::plugins::run(root, check),
        &mut stale,
    );
    run_one(
        "evidence",
        check,
        || crate::evidence::run(root, evidence_mode(check)),
        &mut stale,
    );

    if check {
        if stale.is_empty() {
            println!("xtask sync --check: all artifacts are byte-fresh");
            Ok(())
        } else {
            eyre::bail!(
                "xtask sync --check: {} artifact(s) stale; run `cargo run -p xtask -- sync` to regenerate:\n  {}",
                stale.len(),
                stale.join("\n  ")
            )
        }
    } else {
        println!("xtask sync: all artifacts regenerated");
        Ok(())
    }
}

const fn evidence_mode(check: bool) -> crate::evidence::Mode {
    if check {
        crate::evidence::Mode::Check
    } else {
        crate::evidence::Mode::Render
    }
}

pub(crate) fn run_one<F>(name: &str, check: bool, f: F, stale: &mut Vec<String>)
where
    F: FnOnce() -> Result<()>,
{
    match f() {
        Ok(()) => {}
        Err(err) => {
            if check {
                stale.push(format!("{name}: {err}"));
            } else {
                eprintln!("xtask sync: {name} failed: {err:?}");
            }
        }
    }
}
