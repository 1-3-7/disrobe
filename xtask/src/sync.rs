use std::path::Path;

use eyre::{Result, WrapErr};

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let mut stale: Vec<String> = Vec::new();

    run_one(
        "graphs",
        check,
        || crate::graphs::run(root, check),
        &mut stale,
    )?;
    run_one("card", check, || crate::card::run(root, check), &mut stale)?;
    run_one("demo", check, || crate::demo::run(root, check), &mut stale)?;
    run_one(
        "plugins",
        check,
        || crate::plugins::run(root, check),
        &mut stale,
    )?;
    run_one(
        "evidence",
        check,
        || crate::evidence::run(root, evidence_mode(check)),
        &mut stale,
    )?;
    run_one(
        "metrics",
        check,
        || crate::metrics::run(root, metrics_mode(check)),
        &mut stale,
    )?;

    if check {
        if stale.is_empty() {
            println!(
                "xtask sync --check: generated artifacts and documentation metrics are byte-fresh"
            );
            Ok(())
        } else {
            eyre::bail!(
                "xtask sync --check: {} synchronization step(s) stale; run `cargo run -p xtask -- sync` to regenerate:\n  {}",
                stale.len(),
                stale.join("\n  ")
            )
        }
    } else {
        println!("xtask sync: generated artifacts and documentation metrics regenerated");
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

const fn metrics_mode(check: bool) -> crate::metrics::Mode {
    if check {
        crate::metrics::Mode::Check
    } else {
        crate::metrics::Mode::Write
    }
}

pub(crate) fn run_one<F>(name: &str, check: bool, f: F, stale: &mut Vec<String>) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    match f() {
        Ok(()) => Ok(()),
        Err(error) if check => {
            stale.push(format!("{name}: {error}"));
            Ok(())
        }
        Err(error) => Err(error).wrap_err_with(|| format!("generation step `{name}` failed")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_mode_tracks_sync_mode() {
        assert!(matches!(metrics_mode(true), crate::metrics::Mode::Check));
        assert!(matches!(metrics_mode(false), crate::metrics::Mode::Write));
    }

    #[test]
    fn write_mode_propagates_an_injected_failure_with_its_step_name() -> Result<()> {
        let mut failures: Vec<String> = Vec::new();
        let result: Result<()> = run_one(
            "injected-writer",
            false,
            || Err(eyre::eyre!("sentinel write failure")),
            &mut failures,
        );
        let error: eyre::Report = match result {
            Ok(()) => eyre::bail!("write mode returned success after an injected failure"),
            Err(error) => error,
        };
        let message: String = format!("{error:?}");
        assert!(message.contains("generation step `injected-writer` failed"));
        assert!(message.contains("sentinel write failure"));
        assert!(failures.is_empty());
        Ok(())
    }

    #[test]
    fn check_mode_retains_two_failures_without_short_circuiting() {
        let mut failures: Vec<String> = Vec::new();
        let mut invocations: usize = 0;
        let first_result: Result<()> = run_one(
            "first-check",
            true,
            || {
                invocations += 1;
                Err(eyre::eyre!("first sentinel failure"))
            },
            &mut failures,
        );
        assert!(first_result.is_ok());
        let second_result: Result<()> = run_one(
            "second-check",
            true,
            || {
                invocations += 1;
                Err(eyre::eyre!("second sentinel failure"))
            },
            &mut failures,
        );
        assert!(second_result.is_ok());
        assert_eq!(invocations, 2);
        assert_eq!(
            failures,
            [
                "first-check: first sentinel failure".to_owned(),
                "second-check: second sentinel failure".to_owned()
            ]
        );
    }
}
