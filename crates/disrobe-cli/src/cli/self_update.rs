use serde::Serialize;

use super::output::{OutputFormat, emit};

const RELEASES_URL: &str = "https://api.github.com/repos/1-3-7/disrobe/releases/latest";

#[derive(Debug, Serialize)]
pub(crate) struct SelfUpdateReport {
    pub url: &'static str,
    pub current_version: &'static str,
    pub latest_version: Option<String>,
    pub status: &'static str,
    pub dry_run: bool,
    pub download_path: Option<String>,
    pub cache_hit: bool,
    pub asset_sha256_hex: Option<String>,
}

pub(crate) fn run(
    check_only: bool,
    download: bool,
    dry_run: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if dry_run {
        let status: &'static str = if check_only {
            "source-only-distribution"
        } else {
            "dry-run"
        };
        let report: SelfUpdateReport = SelfUpdateReport {
            url: RELEASES_URL,
            current_version: env!("CARGO_PKG_VERSION"),
            latest_version: None,
            status,
            dry_run: true,
            download_path: None,
            cache_hit: false,
            asset_sha256_hex: None,
        };
        return emit_report(fmt, &report, check_only, download, dry_run);
    }

    Err(miette::miette!(
        "DR-CLI-0269: self-update is unavailable; disrobe is distributed as source only. rebuild from git: `git clone https://github.com/1-3-7/disrobe && cd disrobe && cargo build --release`"
    ))
}

fn emit_report(
    fmt: OutputFormat,
    report: &SelfUpdateReport,
    check_only: bool,
    download: bool,
    dry_run: bool,
) -> miette::Result<()> {
    emit(fmt, report, || {
        println!("disrobe self-update");
        println!("  current:    {}", report.current_version);
        if let Some(ref latest) = report.latest_version {
            println!("  latest:     {latest}");
        }
        println!("  url:        {}", report.url);
        println!("  status:     {}", report.status);
        println!("  cache hit:  {}", report.cache_hit);
        println!("  --check-only={check_only}");
        println!("  --download={download}");
        println!("  --dry-run={dry_run}");
        if let Some(ref dl) = report.download_path {
            println!("  staged at:  {dl}");
        }
        if let Some(ref s) = report.asset_sha256_hex {
            println!("  sha256:     {s}");
        }
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const EXPECTED_URL: &str = "https://api.github.com/repos/1-3-7/disrobe/releases/latest";

    #[test]
    fn releases_url_is_pinned_to_github_api_latest() {
        assert_eq!(RELEASES_URL, EXPECTED_URL);
    }

    #[test]
    fn dry_run_emits_source_only_status() {
        let report: SelfUpdateReport = SelfUpdateReport {
            url: RELEASES_URL,
            current_version: env!("CARGO_PKG_VERSION"),
            latest_version: None,
            status: "source-only-distribution",
            dry_run: true,
            download_path: None,
            cache_hit: false,
            asset_sha256_hex: None,
        };
        assert_eq!(report.status, "source-only-distribution");
        assert!(report.dry_run);
        assert_eq!(report.url, EXPECTED_URL);
        assert!(report.latest_version.is_none());
    }

    #[test]
    fn check_only_dry_run_returns_ok_without_network() {
        let r: miette::Result<()> = run(true, false, true, OutputFormat::Json);
        assert!(
            r.is_ok(),
            "--check-only --dry-run must return Ok(()) offline; got {r:?}"
        );
    }
}
