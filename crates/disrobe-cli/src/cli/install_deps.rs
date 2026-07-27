#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Subcommand;
use serde::Serialize;
use sha2::Digest as _;

use super::output::{OutputFormat, emit};

const GHIDRA_RELEASES_API: &str =
    "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest";
const USER_AGENT: &str = concat!("disrobe-cli/", env!("CARGO_PKG_VERSION"));
const MAX_GHIDRA_DOWNLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GHIDRA_ARCHIVE_ENTRIES: usize = 200_000;
const MAX_GHIDRA_ENTRY_UNCOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_GHIDRA_TOTAL_UNCOMPRESSED_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const DOWNLOAD_PREALLOC_FALLBACK: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
struct InstallLimits {
    download_bytes: u64,
    archive_entries: usize,
    entry_uncompressed_bytes: u64,
    total_uncompressed_bytes: u64,
}

impl InstallLimits {
    #[must_use]
    const fn ghidra() -> Self {
        Self {
            download_bytes: MAX_GHIDRA_DOWNLOAD_BYTES,
            archive_entries: MAX_GHIDRA_ARCHIVE_ENTRIES,
            entry_uncompressed_bytes: MAX_GHIDRA_ENTRY_UNCOMPRESSED_BYTES,
            total_uncompressed_bytes: MAX_GHIDRA_TOTAL_UNCOMPRESSED_BYTES,
        }
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum InstallDepsCmd {
    Ghidra {
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallReport {
    pub tool: &'static str,
    pub status: &'static str,
    pub asset_url: Option<String>,
    pub asset_name: Option<String>,
    pub sha256_hex: Option<String>,
    pub install_dir: Option<String>,
    pub support_dir: Option<String>,
    pub path_export_line: Option<String>,
    pub bytes_downloaded: u64,
    pub dry_run: bool,
}

pub(crate) fn run(cmd: InstallDepsCmd, fmt: OutputFormat) -> miette::Result<()> {
    match cmd {
        InstallDepsCmd::Ghidra { dry_run } => install_ghidra(dry_run, fmt),
    }
}

pub(crate) fn run_all(dry_run: bool, fmt: OutputFormat) -> miette::Result<()> {
    install_ghidra(dry_run, fmt)
}

fn install_ghidra(dry_run: bool, fmt: OutputFormat) -> miette::Result<()> {
    let install_dir: PathBuf = ghidra_install_dir();
    if dry_run {
        let report: InstallReport = InstallReport {
            tool: "ghidra",
            status: "dry-run",
            asset_url: Some(GHIDRA_RELEASES_API.to_owned()),
            asset_name: None,
            sha256_hex: None,
            install_dir: Some(install_dir.display().to_string()),
            support_dir: None,
            path_export_line: None,
            bytes_downloaded: 0,
            dry_run: true,
        };
        return emit_install(fmt, &report);
    }

    let release: ReleaseInfo = fetch_latest_ghidra_release()?;
    let asset: ReleaseAsset = pick_ghidra_zip_asset(&release.assets)
        .ok_or_else(|| miette::miette!("DR-CLI-0250: no ghidra zip asset in latest release"))?;
    let expected_sha: Option<String> = release.sha256_for(&asset.name);

    let archive_bytes: Vec<u8> = download_with_progress(&asset.browser_download_url)?;
    let bytes_downloaded: u64 = archive_bytes.len() as u64;
    let actual_sha: String = sha256_hex(&archive_bytes);
    let Some(expected): Option<String> = expected_sha else {
        return Err(miette::miette!(
            "DR-CLI-0268: ghidra asset '{}' has no published sha256 in the release body; refusing to install unverified bytes (fail-closed). Verify the download manually or set the checksum in the release notes.",
            asset.name
        ));
    };
    if !expected.eq_ignore_ascii_case(&actual_sha) {
        return Err(miette::miette!(
            "DR-CLI-0251: ghidra asset sha256 mismatch: expected {expected}, got {actual_sha}"
        ));
    }

    std::fs::create_dir_all(&install_dir)
        .map_err(|e| miette::miette!("DR-CLI-0252: cannot create install dir: {e}"))?;
    extract_zip_to(&archive_bytes, &install_dir)?;

    let support_dir: PathBuf = locate_support_dir(&install_dir).ok_or_else(|| {
        miette::miette!(
            "DR-CLI-0253: extracted ghidra archive missing support/ in {}",
            install_dir.display()
        )
    })?;
    prepend_path_for_current_process(&support_dir);
    let export_line: String = path_export_line(&support_dir);

    let report: InstallReport = InstallReport {
        tool: "ghidra",
        status: "installed",
        asset_url: Some(asset.browser_download_url),
        asset_name: Some(asset.name),
        sha256_hex: Some(actual_sha),
        install_dir: Some(install_dir.display().to_string()),
        support_dir: Some(support_dir.display().to_string()),
        path_export_line: Some(export_line),
        bytes_downloaded,
        dry_run: false,
    };
    emit_install(fmt, &report)
}

fn emit_install(fmt: OutputFormat, report: &InstallReport) -> miette::Result<()> {
    emit(fmt, report, || {
        println!("disrobe install-deps {}", report.tool);
        println!("  status:        {}", report.status);
        if let Some(ref u) = report.asset_url {
            println!("  asset url:     {u}");
        }
        if let Some(ref n) = report.asset_name {
            println!("  asset name:    {n}");
        }
        if let Some(ref s) = report.sha256_hex {
            println!("  sha256:        {s}");
        }
        if let Some(ref d) = report.install_dir {
            println!("  install dir:   {d}");
        }
        if let Some(ref d) = report.support_dir {
            println!("  support dir:   {d}");
        }
        if let Some(ref e) = report.path_export_line {
            println!("  add to PATH:   {e}");
        }
        if !report.dry_run {
            println!("  downloaded:    {} bytes", report.bytes_downloaded);
        }
    })
}

#[derive(Debug, serde::Deserialize)]
struct ReleaseInfo {
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
    #[serde(default)]
    body: String,
}

impl ReleaseInfo {
    fn sha256_for(&self, asset_name: &str) -> Option<String> {
        for line in self.body.lines() {
            let trimmed: &str = line.trim();
            if !trimmed.contains(asset_name) {
                continue;
            }
            for tok in trimmed.split_whitespace() {
                if tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Some(tok.to_ascii_lowercase());
                }
            }
        }
        None
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct ReleaseAsset {
    name: String,
    browser_download_url: String,
}

fn fetch_latest_ghidra_release() -> miette::Result<ReleaseInfo> {
    let client: reqwest::blocking::Client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| miette::miette!("DR-CLI-0254: reqwest client: {e}"))?;
    let resp: reqwest::blocking::Response = client
        .get(GHIDRA_RELEASES_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .map_err(|e| miette::miette!("DR-CLI-0255: github GET: {e}"))?;
    if !resp.status().is_success() {
        return Err(miette::miette!(
            "DR-CLI-0256: github returned status {}",
            resp.status()
        ));
    }
    resp.json::<ReleaseInfo>()
        .map_err(|e| miette::miette!("DR-CLI-0257: parse release json: {e}"))
}

fn pick_ghidra_zip_asset(assets: &[ReleaseAsset]) -> Option<ReleaseAsset> {
    assets
        .iter()
        .find(|a| {
            a.name.to_ascii_lowercase().starts_with("ghidra_")
                && a.name.to_ascii_lowercase().ends_with(".zip")
        })
        .cloned()
}

#[expect(
    clippy::duration_suboptimal_units,
    reason = "from_mins is unstable (duration_constructors, rust#120301); from_secs is the stable form"
)]
fn download_with_progress(url: &str) -> miette::Result<Vec<u8>> {
    let client: reqwest::blocking::Client = reqwest::blocking::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(Duration::from_secs(900))
        .build()
        .map_err(|e| miette::miette!("DR-CLI-0258: download client: {e}"))?;
    let mut resp: reqwest::blocking::Response = client
        .get(url)
        .send()
        .map_err(|e| miette::miette!("DR-CLI-0259: download GET {url}: {e}"))?;
    if !resp.status().is_success() {
        return Err(miette::miette!(
            "DR-CLI-0260: download returned status {} for {url}",
            resp.status()
        ));
    }
    let declared_len: Option<u64> = resp.content_length();
    read_response_bounded(
        &mut resp,
        declared_len,
        url,
        InstallLimits::ghidra().download_bytes,
    )
}

fn read_response_bounded<R: std::io::Read>(
    reader: &mut R,
    declared_len: Option<u64>,
    url: &str,
    max_bytes: u64,
) -> miette::Result<Vec<u8>> {
    if let Some(len) = declared_len
        && len > max_bytes
    {
        return Err(miette::miette!(
            "DR-CLI-0320: download body for {url} declares {len} bytes, exceeding cap {max_bytes}"
        ));
    }
    let initial: u64 = declared_len
        .unwrap_or(DOWNLOAD_PREALLOC_FALLBACK)
        .min(max_bytes);
    let capacity: usize = usize::try_from(initial).unwrap_or(DOWNLOAD_PREALLOC_FALLBACK as usize);
    let mut buf: Vec<u8> = Vec::with_capacity(capacity);
    let read_limit: u64 = max_bytes.saturating_add(1);
    let mut limited: std::io::Take<&mut R> = reader.take(read_limit);
    limited
        .read_to_end(&mut buf)
        .map_err(|e| miette::miette!("DR-CLI-0261: read body {url}: {e}"))?;
    let actual_len: u64 = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if actual_len > max_bytes {
        return Err(miette::miette!(
            "DR-CLI-0320: download body for {url} exceeded cap {max_bytes}"
        ));
    }
    Ok(buf)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut hasher: sha2::Sha256 = sha2::Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut out: String = String::with_capacity(64);
    for b in digest {
        let _: core::fmt::Result = write!(out, "{b:02x}");
    }
    out
}

fn extract_zip_to(bytes: &[u8], dest: &Path) -> miette::Result<()> {
    extract_zip_to_with_limits(bytes, dest, InstallLimits::ghidra())
}

fn extract_zip_to_with_limits(
    bytes: &[u8],
    dest: &Path,
    limits: InstallLimits,
) -> miette::Result<()> {
    let cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| miette::miette!("DR-CLI-0262: zip open: {e}"))?;
    let total: usize = archive.len();
    if total > limits.archive_entries {
        return Err(miette::miette!(
            "DR-CLI-0321: ghidra archive has {total} entries, exceeding cap {}",
            limits.archive_entries
        ));
    }
    let mut total_uncompressed: u64 = 0;
    for i in 0..total {
        let mut entry: zip::read::ZipFile<'_> = archive
            .by_index(i)
            .map_err(|e| miette::miette!("DR-CLI-0263: zip entry {i}: {e}"))?;
        let Some(rel): Option<PathBuf> = entry.enclosed_name() else {
            continue;
        };
        let declared_size: u64 = entry.size();
        if declared_size > limits.entry_uncompressed_bytes {
            return Err(miette::miette!(
                "DR-CLI-0321: ghidra archive entry {} declares {declared_size} bytes, exceeding per-entry cap {}",
                rel.display(),
                limits.entry_uncompressed_bytes
            ));
        }
        let declared_total: u64 = total_uncompressed
            .checked_add(declared_size)
            .ok_or_else(|| miette::miette!("DR-CLI-0321: ghidra archive size total overflow"))?;
        if declared_total > limits.total_uncompressed_bytes {
            return Err(miette::miette!(
                "DR-CLI-0321: ghidra archive declared total {declared_total} bytes, exceeding cap {}",
                limits.total_uncompressed_bytes
            ));
        }
        let out_path: PathBuf = dest.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|e| miette::miette!("DR-CLI-0264: mkdir {}: {e}", out_path.display()))?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                miette::miette!("DR-CLI-0265: mkdir parent {}: {e}", parent.display())
            })?;
        }
        let mut out_file: std::fs::File = std::fs::File::create(&out_path)
            .map_err(|e| miette::miette!("DR-CLI-0266: create {}: {e}", out_path.display()))?;
        let remaining_total: u64 = limits
            .total_uncompressed_bytes
            .saturating_sub(total_uncompressed);
        let copy_limit: u64 = remaining_total.min(limits.entry_uncompressed_bytes);
        let read_limit: u64 = copy_limit.saturating_add(1);
        let mut limited: std::io::Take<&mut zip::read::ZipFile<'_>> =
            std::io::Read::by_ref(&mut entry).take(read_limit);
        let copied: u64 = match std::io::copy(&mut limited, &mut out_file) {
            Ok(n) => n,
            Err(e) => {
                let _: Result<(), std::io::Error> = std::fs::remove_file(&out_path);
                return Err(miette::miette!(
                    "DR-CLI-0267: write {}: {e}",
                    out_path.display()
                ));
            }
        };
        if copied > copy_limit {
            let _: Result<(), std::io::Error> = std::fs::remove_file(&out_path);
            return Err(miette::miette!(
                "DR-CLI-0321: ghidra archive entry {} expanded past cap",
                rel.display()
            ));
        }
        total_uncompressed = total_uncompressed.saturating_add(copied);
    }
    Ok(())
}

fn locate_support_dir(install_dir: &Path) -> Option<PathBuf> {
    let direct: PathBuf = install_dir.join("support");
    if direct.is_dir() {
        return Some(direct);
    }
    let entries: std::fs::ReadDir = std::fs::read_dir(install_dir).ok()?;
    for e in entries.flatten() {
        let p: PathBuf = e.path();
        let candidate: PathBuf = p.join("support");
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

fn ghidra_install_dir() -> PathBuf {
    if cfg!(windows)
        && let Some(v) = std::env::var_os("LOCALAPPDATA")
    {
        return PathBuf::from(v).join("disrobe").join("ghidra");
    }
    if cfg!(target_os = "macos")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("disrobe")
            .join("ghidra");
    }
    if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg).join("disrobe").join("ghidra");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("disrobe")
            .join("ghidra");
    }
    PathBuf::from("./.disrobe-deps/ghidra")
}

fn prepend_path_for_current_process(dir: &Path) {
    let sep: char = if cfg!(windows) { ';' } else { ':' };
    let old: std::ffi::OsString = std::env::var_os("PATH").unwrap_or_default();
    let mut new: std::ffi::OsString = dir.as_os_str().to_os_string();
    if !old.is_empty() {
        new.push(sep.to_string());
        new.push(&old);
    }
    unsafe {
        std::env::set_var("PATH", &new);
    }
}

fn path_export_line(dir: &Path) -> String {
    if cfg!(windows) {
        format!("$env:PATH = \"{};$env:PATH\"", dir.display())
    } else {
        format!("export PATH=\"{}:$PATH\"", dir.display())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        let s: String = sha256_hex(b"abc");
        assert_eq!(
            s,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn release_info_extracts_sha_from_body() {
        let body: &str = "Release notes\n\n## Checksums\nghidra_11.1_PUBLIC_20240607.zip  abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n";
        let info: ReleaseInfo = ReleaseInfo {
            assets: Vec::new(),
            body: body.to_owned(),
        };
        let got: Option<String> = info.sha256_for("ghidra_11.1_PUBLIC_20240607.zip");
        assert_eq!(
            got.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
        );
    }

    #[test]
    fn release_info_returns_none_when_checksum_absent() {
        let info: ReleaseInfo = ReleaseInfo {
            assets: Vec::new(),
            body: "Release notes with no checksum table at all.\n".to_owned(),
        };
        assert!(
            info.sha256_for("ghidra_11.1_PUBLIC_20240607.zip").is_none(),
            "absent checksum must yield None so install fails closed"
        );
    }

    #[test]
    fn pick_zip_asset_filters_non_zip() {
        let assets: Vec<ReleaseAsset> = vec![
            ReleaseAsset {
                name: "ghidra_11.1_PUBLIC_20240607.zip".into(),
                browser_download_url: "https://example/asset.zip".into(),
            },
            ReleaseAsset {
                name: "ghidra_sources.tar.gz".into(),
                browser_download_url: "https://example/src.tar.gz".into(),
            },
        ];
        let picked: ReleaseAsset = pick_ghidra_zip_asset(&assets).expect("zip picked");
        let ext_ok: bool = Path::new(&picked.name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("zip"));
        assert!(ext_ok);
    }

    #[test]
    fn path_export_line_is_shell_native() {
        let p: std::path::PathBuf = PathBuf::from("/opt/ghidra/support");
        let line: String = path_export_line(&p);
        if cfg!(windows) {
            assert!(line.starts_with("$env:PATH = "));
        } else {
            assert!(line.starts_with("export PATH="));
        }
    }

    #[test]
    fn install_dir_is_platform_specific() {
        let dir: std::path::PathBuf = ghidra_install_dir();
        let s: String = dir.display().to_string();
        assert!(s.contains("disrobe"));
        assert!(s.contains("ghidra"));
    }

    #[test]
    fn read_response_bounded_rejects_actual_body_over_limit() {
        let data: Vec<u8> = vec![0x41; 17];
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(data.as_slice());
        let err: miette::Report =
            read_response_bounded(&mut cursor, None, "https://example.invalid/ghidra.zip", 16)
                .expect_err("must reject body larger than the byte cap");
        let msg: String = err.to_string();
        assert!(msg.contains("DR-CLI-0320"));
        assert!(msg.contains("16"));
    }

    #[test]
    fn extract_zip_to_with_limits_rejects_total_uncompressed_over_limit() {
        let archive: Vec<u8> = stored_zip(&[("a.bin", &[0x41; 6]), ("b.bin", &[0x42; 6])]);
        let dest_scratch: disrobe_core::scratch::ScratchDir = temp_install_dir("total-cap");
        let dest: PathBuf = dest_scratch.path().to_path_buf();
        let limits: InstallLimits = InstallLimits {
            download_bytes: 1024,
            archive_entries: 8,
            entry_uncompressed_bytes: 16,
            total_uncompressed_bytes: 8,
        };
        let err: miette::Report = extract_zip_to_with_limits(&archive, &dest, limits)
            .expect_err("must reject total extracted bytes overrun");
        let msg: String = err.to_string();
        assert!(msg.contains("DR-CLI-0321"));
        assert!(!dest.join("b.bin").is_file());
    }

    fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer.start_file(*name, options).expect("start zip entry");
            writer.write_all(data).expect("write zip entry");
        }
        let out: std::io::Cursor<Vec<u8>> = writer.finish().expect("finish zip");
        out.into_inner()
    }

    fn temp_install_dir(tag: &str) -> disrobe_core::scratch::ScratchDir {
        let purpose: String = format!("disrobe-install-deps-{tag}");
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
    }
}
