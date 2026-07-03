use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::container::ContainerKind;
use crate::error::{Error, Result};
use crate::extract::{EntryCompression, ExtractedEntry, ExtractionResult, QuotaSummary};
use crate::quota::{ExtractionQuota, QuotaGuard, sanitize_entry_path};

const MAX_CAPTURE_OUTPUT: usize = 4 * 1024 * 1024;
const CAPTURE_READ_CHUNK: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExternalTool {
    Unrar,
    Pkgutil,
    Hdiutil,
    SevenZip,
    Bsdtar,
}

impl ExternalTool {
    #[must_use]
    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Unrar => "unrar",
            Self::Pkgutil => "pkgutil",
            Self::Hdiutil => "hdiutil",
            Self::SevenZip => "7z",
            Self::Bsdtar => "bsdtar",
        }
    }

    #[must_use]
    pub const fn version_flag(self) -> &'static str {
        match self {
            Self::Unrar => "--help",
            Self::SevenZip => "-version",
            Self::Pkgutil | Self::Hdiutil | Self::Bsdtar => "--version",
        }
    }

    #[must_use]
    pub const fn override_env(self) -> &'static str {
        match self {
            Self::Unrar => "DISROBE_EXTERNAL_UNRAR",
            Self::Pkgutil => "DISROBE_EXTERNAL_PKGUTIL",
            Self::Hdiutil => "DISROBE_EXTERNAL_HDIUTIL",
            Self::SevenZip => "DISROBE_EXTERNAL_7Z",
            Self::Bsdtar => "DISROBE_EXTERNAL_BSDTAR",
        }
    }

    #[must_use]
    pub const fn supported_on_host(self) -> bool {
        match self {
            Self::Unrar | Self::SevenZip | Self::Bsdtar => true,
            Self::Pkgutil | Self::Hdiutil => cfg!(target_os = "macos"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub found: bool,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
}

#[must_use]
pub fn probe_external_tools() -> BTreeMap<ExternalTool, ProbeResult> {
    let tools: [ExternalTool; 5] = [
        ExternalTool::Unrar,
        ExternalTool::Pkgutil,
        ExternalTool::Hdiutil,
        ExternalTool::SevenZip,
        ExternalTool::Bsdtar,
    ];
    let mut out: BTreeMap<ExternalTool, ProbeResult> = BTreeMap::new();
    for tool in tools {
        out.insert(tool, probe_single(tool));
    }
    out
}

fn probe_single(tool: ExternalTool) -> ProbeResult {
    let Some(resolved): Option<PathBuf> = resolve_tool(tool) else {
        return ProbeResult {
            found: false,
            path: None,
            version: None,
        };
    };
    let version: Option<String> =
        run_capture(&resolved, &[tool.version_flag()], Duration::from_secs(5))
            .ok()
            .and_then(|(_code, stdout, stderr): (i32, String, String)| {
                first_nonempty_line(&stdout).or_else(|| first_nonempty_line(&stderr))
            });
    ProbeResult {
        found: true,
        path: Some(resolved),
        version,
    }
}

#[derive(Debug, Default, Clone)]
pub struct ToolOverrides {
    pub disable_all: bool,
    pub paths: BTreeMap<ExternalTool, PathBuf>,
}

static OVERRIDES: std::sync::OnceLock<std::sync::RwLock<ToolOverrides>> =
    std::sync::OnceLock::new();

fn overrides() -> &'static std::sync::RwLock<ToolOverrides> {
    OVERRIDES.get_or_init(|| std::sync::RwLock::new(ToolOverrides::default()))
}

pub fn set_overrides(o: ToolOverrides) {
    let lock: &std::sync::RwLock<ToolOverrides> = overrides();
    let mut guard: std::sync::RwLockWriteGuard<'_, ToolOverrides> = lock
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = o;
}

pub fn clear_overrides() {
    set_overrides(ToolOverrides::default());
}

#[cfg(test)]
pub(crate) fn lock_overrides() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static OVERRIDE_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let mtx: &Mutex<()> = OVERRIDE_TEST_LOCK.get_or_init(|| Mutex::new(()));
    mtx.lock()
        .unwrap_or_else(|e: std::sync::PoisonError<std::sync::MutexGuard<'_, ()>>| e.into_inner())
}

fn resolve_tool(tool: ExternalTool) -> Option<PathBuf> {
    let (disable_all, override_path): (bool, Option<PathBuf>) = {
        let lock: &std::sync::RwLock<ToolOverrides> = overrides();
        let guard: std::sync::RwLockReadGuard<'_, ToolOverrides> = lock
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (guard.disable_all, guard.paths.get(&tool).cloned())
    };
    if disable_all {
        return None;
    }
    if let Some(p) = override_path
        && p.exists()
    {
        return Some(p);
    }
    if let Some(env_path) = std::env::var_os(tool.override_env()) {
        let p: PathBuf = PathBuf::from(env_path);
        if p.exists() {
            return Some(p);
        }
    }
    which_on_path(tool.binary_name())
}

fn which_on_path(binary: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exe_exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_owned())
            .split(';')
            .map(|s: &str| s.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in &exe_exts {
            let candidate: PathBuf = if ext.is_empty() {
                dir.join(binary)
            } else {
                let mut name: std::ffi::OsString = binary.into();
                name.push(ext);
                dir.join(&name)
            };
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn first_nonempty_line(s: &str) -> Option<String> {
    s.lines()
        .map(str::trim)
        .find(|l: &&str| !l.is_empty())
        .map(str::to_owned)
}

fn read_capped_output<R: std::io::Read>(mut reader: R) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut chunk: [u8; CAPTURE_READ_CHUNK] = [0u8; CAPTURE_READ_CHUNK];
    loop {
        let read: usize = match reader.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let remaining: usize = MAX_CAPTURE_OUTPUT.saturating_sub(out.len());
        if remaining > 0 {
            let keep: usize = read.min(remaining);
            out.extend_from_slice(&chunk[..keep]);
        }
    }
    out
}

fn run_capture(program: &Path, args: &[&str], timeout: Duration) -> Result<(i32, String, String)> {
    let mut spawn_attempt: u32 = 0;
    let mut child: std::process::Child = loop {
        match Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(spawned) => break spawned,
            Err(e) if e.raw_os_error() == Some(26) && spawn_attempt < 8 => {
                spawn_attempt += 1;
                std::thread::sleep(Duration::from_millis(20 * u64::from(spawn_attempt)));
            }
            Err(e) => return Err(Error::Io(e)),
        }
    };
    let stdout_handle: Option<std::process::ChildStdout> = child.stdout.take();
    let stderr_handle: Option<std::process::ChildStderr> = child.stderr.take();
    let stdout_join: std::thread::JoinHandle<Vec<u8>> = std::thread::spawn(move || {
        if let Some(s) = stdout_handle {
            return read_capped_output(s);
        }
        Vec::new()
    });
    let stderr_join: std::thread::JoinHandle<Vec<u8>> = std::thread::spawn(move || {
        if let Some(s) = stderr_handle {
            return read_capped_output(s);
        }
        Vec::new()
    });
    let waited: Option<std::process::ExitStatus> =
        wait_timeout::ChildExt::wait_timeout(&mut child, timeout).map_err(Error::Io)?;
    let Some(status): Option<std::process::ExitStatus> = waited else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = stdout_join.join();
        let _ = stderr_join.join();
        return Err(Error::ExternalToolTimeout {
            tool: "external",
            seconds: timeout.as_secs(),
        });
    };
    let stdout_buf: Vec<u8> = stdout_join.join().map_err(|_| Error::ExternalToolFailed {
        tool: "external",
        exit: -1,
        stderr: "stdout capture thread panicked".to_owned(),
    })?;
    let stderr_buf: Vec<u8> = stderr_join.join().map_err(|_| Error::ExternalToolFailed {
        tool: "external",
        exit: -1,
        stderr: "stderr capture thread panicked".to_owned(),
    })?;
    let code: i32 = status.code().map_or(-1, |value: i32| value);
    let stdout_s: String = String::from_utf8_lossy(&stdout_buf).into_owned();
    let stderr_s: String = String::from_utf8_lossy(&stderr_buf).into_owned();
    Ok((code, stdout_s, stderr_s))
}

const DEFAULT_TIMEOUT_SECS: u64 = 180;

pub fn wrap_external_extract(
    tool: ExternalTool,
    bytes: &[u8],
    out_dir: &Path,
) -> Result<ExtractionResult> {
    if !tool.supported_on_host() {
        return Err(Error::ExternalToolUnsupported {
            tool: tool.binary_name(),
            platform: std::env::consts::OS,
        });
    }
    let resolved: PathBuf = resolve_tool(tool).ok_or_else(|| Error::ExternalToolMissing {
        tool: tool.binary_name(),
    })?;
    std::fs::create_dir_all(out_dir)?;
    let staging: PathBuf = create_staging_dir(out_dir, bytes)?;
    let tmp_input: PathBuf = stage_input_tempfile(bytes, tool)?;
    let timeout: Duration = Duration::from_secs(DEFAULT_TIMEOUT_SECS);
    let result: Result<()> = match tool {
        ExternalTool::Unrar => invoke_unrar(&resolved, &tmp_input, &staging, timeout),
        ExternalTool::SevenZip => invoke_sevenz(&resolved, &tmp_input, &staging, timeout),
        ExternalTool::Pkgutil => invoke_pkgutil(&resolved, &tmp_input, &staging, timeout),
        ExternalTool::Hdiutil => invoke_hdiutil(&resolved, &tmp_input, &staging, timeout),
        ExternalTool::Bsdtar => invoke_bsdtar(&resolved, &tmp_input, &staging, timeout),
    };
    let input_cleanup: Result<()> = remove_file_if_exists(&tmp_input);
    let contained: Result<()> = result.and_then(|()| contain_staging_into(&staging, out_dir));
    let staging_cleanup: Result<()> = remove_dir_if_exists(&staging);
    contained?;
    input_cleanup?;
    staging_cleanup?;
    let kind: ContainerKind = match tool {
        ExternalTool::Unrar => ContainerKind::Rar,
        ExternalTool::SevenZip => ContainerKind::Iso,
        ExternalTool::Pkgutil | ExternalTool::Bsdtar => ContainerKind::Pkg,
        ExternalTool::Hdiutil => ContainerKind::Dmg,
    };
    collect_output_dir(kind, bytes.len() as u64, out_dir)
}

pub fn extract_via_tool(
    kind: ContainerKind,
    bytes: &[u8],
    out_dir: &Path,
) -> Result<ExtractionResult> {
    let probe: BTreeMap<ExternalTool, ProbeResult> = probe_external_tools();
    let order: Vec<ExternalTool> = match kind {
        ContainerKind::Rar => vec![ExternalTool::Unrar, ExternalTool::SevenZip],
        ContainerKind::Pkg => vec![ExternalTool::Pkgutil, ExternalTool::Bsdtar],
        ContainerKind::Dmg => vec![ExternalTool::Hdiutil],
        ContainerKind::Iso => vec![ExternalTool::SevenZip, ExternalTool::Bsdtar],
        _ => Vec::new(),
    };
    for tool in order {
        let probed: Option<&ProbeResult> = probe.get(&tool);
        let available: bool =
            probed.is_some_and(|p: &ProbeResult| p.found) && tool.supported_on_host();
        if !available {
            continue;
        }
        let result: ExtractionResult = wrap_external_extract(tool, bytes, out_dir)?;
        return Ok(result);
    }
    let kind_label: &'static str = match kind {
        ContainerKind::Rar => "rar",
        ContainerKind::Pkg => "pkg",
        ContainerKind::Dmg => "dmg",
        ContainerKind::Iso => "iso",
        _ => return Err(Error::UnsupportedContainer(kind.label())),
    };
    Err(Error::ExternalToolMissing { tool: kind_label })
}

fn stage_input_tempfile(bytes: &[u8], tool: ExternalTool) -> Result<PathBuf> {
    let base: PathBuf = std::env::temp_dir();
    let pid: u32 = std::process::id();
    let nonce: u128 = nonce_from_bytes(bytes);
    let ext: &str = match tool {
        ExternalTool::Unrar => "rar",
        ExternalTool::SevenZip => "iso",
        ExternalTool::Pkgutil | ExternalTool::Bsdtar => "pkg",
        ExternalTool::Hdiutil => "dmg",
    };
    let path: PathBuf = base.join(format!("disrobe-ext-{pid}-{nonce:032x}.{ext}"));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

const fn nonce_from_bytes(bytes: &[u8]) -> u128 {
    let mut acc: u128 = 0x517c_c1b7_2722_0a95_u128;
    let len: usize = if bytes.len() < 16 { bytes.len() } else { 16 };
    let mut i: usize = 0;
    while i < len {
        acc = acc
            .wrapping_mul(0x0100_0000_01b3)
            .wrapping_add(bytes[i] as u128);
        i += 1;
    }
    acc ^ (bytes.len() as u128).wrapping_mul(0x9e37_79b9_7f4a_7c15_u128)
}

fn create_staging_dir(out_dir: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let parent: &Path = out_dir.parent().map_or(out_dir, |value: &Path| value);
    let pid: u32 = std::process::id();
    let nonce: u128 = nonce_from_bytes(bytes);
    let counter: u64 = STAGING_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name: String = format!(".disrobe-stage-{pid}-{nonce:032x}-{counter}");
    let staging: PathBuf = parent.join(name);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    std::fs::create_dir_all(&staging)?;
    Ok(staging)
}

static STAGING_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn contain_staging_into(staging: &Path, out_dir: &Path) -> Result<()> {
    let staging_root: PathBuf = std::fs::canonicalize(staging).map_err(Error::Io)?;
    move_contained(&staging_root, &staging_root, out_dir)
}

fn move_contained(root: &Path, cur: &Path, out_dir: &Path) -> Result<()> {
    let read: std::fs::ReadDir = std::fs::read_dir(cur)?;
    for entry in read {
        let entry: std::fs::DirEntry = entry?;
        let entry_path: PathBuf = entry.path();
        let meta: std::fs::Metadata = std::fs::symlink_metadata(&entry_path)?;
        let file_type: std::fs::FileType = meta.file_type();
        if file_type.is_symlink() {
            return Err(reject_escape(root, &entry_path));
        }
        let real: PathBuf = std::fs::canonicalize(&entry_path).map_err(Error::Io)?;
        if !real.starts_with(root) {
            return Err(reject_escape(root, &entry_path));
        }
        let rel: &Path = real
            .strip_prefix(root)
            .map_or(real.as_path(), |value: &Path| value);
        let dest: PathBuf = out_dir.join(rel);
        if file_type.is_dir() {
            std::fs::create_dir_all(&dest)?;
            move_contained(root, &real, out_dir)?;
        } else if file_type.is_file() {
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            move_file(&real, &dest)?;
        }
    }
    Ok(())
}

fn move_file(src: &Path, dst: &Path) -> Result<()> {
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }
    std::fs::copy(src, dst).map_err(Error::Io)?;
    remove_file_if_exists(src)?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn remove_dir_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn reject_escape(root: &Path, offending: &Path) -> Error {
    let rel: String = offending.strip_prefix(root).map_or_else(
        |_| offending.to_string_lossy().into_owned(),
        |p: &Path| p.to_string_lossy().replace('\\', "/"),
    );
    Error::UnsafeEntryPath(rel)
}

fn invoke_unrar(program: &Path, archive: &Path, out_dir: &Path, timeout: Duration) -> Result<()> {
    let archive_s: String = archive.to_string_lossy().into_owned();
    let out_s: String = out_dir.to_string_lossy().into_owned();
    let trailing: String = format!(
        "{}{}",
        out_s.trim_end_matches(std::path::MAIN_SEPARATOR),
        std::path::MAIN_SEPARATOR
    );
    let args: Vec<&str> = vec!["x", "-y", "-inul", &archive_s, &trailing];
    expect_zero("unrar", program, &args, timeout)
}

fn invoke_sevenz(program: &Path, archive: &Path, out_dir: &Path, timeout: Duration) -> Result<()> {
    let archive_s: String = archive.to_string_lossy().into_owned();
    let out_flag: String = format!("-o{}", out_dir.to_string_lossy());
    let args: Vec<&str> = vec!["x", "-y", "-bd", &out_flag, &archive_s];
    expect_zero("7z", program, &args, timeout)
}

fn invoke_pkgutil(program: &Path, archive: &Path, out_dir: &Path, timeout: Duration) -> Result<()> {
    let archive_s: String = archive.to_string_lossy().into_owned();
    let out_s: String = out_dir.to_string_lossy().into_owned();
    let args: Vec<&str> = vec!["--expand-full", &archive_s, &out_s];
    expect_zero("pkgutil", program, &args, timeout)
}

fn invoke_hdiutil(program: &Path, archive: &Path, out_dir: &Path, timeout: Duration) -> Result<()> {
    let mount: PathBuf = out_dir.join(".mnt");
    std::fs::create_dir_all(&mount)?;
    let archive_s: String = archive.to_string_lossy().into_owned();
    let mount_s: String = mount.to_string_lossy().into_owned();
    let attach_args: Vec<&str> = vec!["attach", "-nobrowse", "-mountpoint", &mount_s, &archive_s];
    expect_zero("hdiutil", program, &attach_args, timeout)?;
    let copy_result: std::io::Result<()> = copy_dir_recursive(&mount, out_dir);
    let detach_args: Vec<&str> = vec!["detach", &mount_s];
    let detach_result: Result<()> = expect_zero("hdiutil", program, &detach_args, timeout);
    let cleanup_result: Result<()> = remove_dir_if_exists(&mount);
    copy_result.map_err(Error::Io)?;
    detach_result?;
    cleanup_result?;
    Ok(())
}

fn invoke_bsdtar(program: &Path, archive: &Path, out_dir: &Path, timeout: Duration) -> Result<()> {
    let archive_s: String = archive.to_string_lossy().into_owned();
    let out_s: String = out_dir.to_string_lossy().into_owned();
    let args: Vec<&str> = vec!["-x", "-f", &archive_s, "-C", &out_s];
    expect_zero("bsdtar", program, &args, timeout)
}

fn expect_zero(
    tool_name: &'static str,
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<()> {
    let (code, _stdout, stderr): (i32, String, String) = run_capture(program, args, timeout)
        .map_err(|e: Error| match e {
            Error::ExternalToolTimeout { seconds, .. } => Error::ExternalToolTimeout {
                tool: tool_name,
                seconds,
            },
            other => other,
        })?;
    if code != 0 {
        return Err(Error::ExternalToolFailed {
            tool: tool_name,
            exit: code,
            stderr,
        });
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry: std::fs::DirEntry = entry?;
        let file_type: std::fs::FileType = entry.file_type()?;
        let dest_path: PathBuf = dst.join(entry.file_name());
        if file_type.is_dir() {
            std::fs::create_dir_all(&dest_path)?;
            copy_dir_recursive(&entry.path(), &dest_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dest_path)?;
        }
    }
    Ok(())
}

fn collect_output_dir(
    kind: ContainerKind,
    compressed_total: u64,
    out_dir: &Path,
) -> Result<ExtractionResult> {
    let mut guard: QuotaGuard = QuotaGuard::new(ExtractionQuota::default_safe());
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut encoding: BTreeMap<String, EntryCompression> = BTreeMap::new();
    let violations: Vec<String> = Vec::new();
    walk_collect(out_dir, out_dir, &mut entries, &mut encoding, &mut guard)?;
    let report: QuotaSummary = QuotaSummary {
        entries_accepted: entries.len(),
        total_uncompressed_bytes: entries
            .iter()
            .map(|e: &ExtractedEntry| e.uncompressed_size)
            .sum(),
        total_compressed_bytes: compressed_total,
        max_observed_ratio: 0,
    };
    Ok(ExtractionResult {
        kind,
        entries,
        encoding,
        integrity_violations: violations,
        quota: report,
    })
}

fn walk_collect(
    root: &Path,
    cur: &Path,
    entries: &mut Vec<ExtractedEntry>,
    encoding: &mut BTreeMap<String, EntryCompression>,
    guard: &mut QuotaGuard,
) -> Result<()> {
    let read: std::fs::ReadDir = std::fs::read_dir(cur)?;
    for entry in read {
        let entry: std::fs::DirEntry = entry?;
        let ft: std::fs::FileType = entry.file_type()?;
        let path: PathBuf = entry.path();
        if ft.is_dir() {
            walk_collect(root, &path, entries, encoding, guard)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let rel: PathBuf = path
            .strip_prefix(root)
            .map_or(path.as_path(), |value: &Path| value)
            .to_path_buf();
        let rel_s: String = rel.to_string_lossy().replace('\\', "/");
        let safe: String = sanitize_entry_path(&rel_s).map_or(rel_s, std::convert::identity);
        let size: u64 = std::fs::metadata(&path)?.len();
        guard.admit_entry(&safe, size, size)?;
        encoding.insert(safe.clone(), EntryCompression::Other);
        entries.push(ExtractedEntry {
            name: safe,
            disk_path: Some(path),
            uncompressed_size: size,
            compressed_size: size,
            compression: EntryCompression::Other,
            is_executable: false,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn temp_dir(suffix: &str) -> PathBuf {
        let base: PathBuf = std::env::temp_dir();
        let pid: u32 = std::process::id();
        let dir: PathBuf = base.join(format!("disrobe-extwrap-{pid}-{suffix}"));
        if dir.exists() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        std::fs::create_dir_all(&dir).expect("mkdir tmp");
        dir
    }

    fn mock_bin_path() -> PathBuf {
        static RESOLVE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_disrobe-binfmt-mock-tool") {
            let p_buf: PathBuf = PathBuf::from(p);
            if p_buf.is_file() {
                return p_buf;
            }
        }
        let _resolve_guard: std::sync::MutexGuard<'_, ()> = RESOLVE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let exe_name: &str = if cfg!(windows) {
            "disrobe-binfmt-mock-tool.exe"
        } else {
            "disrobe-binfmt-mock-tool"
        };
        let target_dir: PathBuf = std::env::current_exe()
            .ok()
            .and_then(|p: PathBuf| {
                p.parent()
                    .and_then(|d: &Path| d.parent())
                    .map(Path::to_path_buf)
            })
            .unwrap_or_else(|| PathBuf::from("target/debug"));
        let candidate: PathBuf = target_dir.join(exe_name);
        if candidate.is_file() {
            return candidate;
        }
        let alt: PathBuf = target_dir.join("deps").join(exe_name);
        if alt.is_file() {
            return alt;
        }
        ensure_mock_bin_built(&candidate);
        candidate
    }

    fn ensure_mock_bin_built(expected: &Path) {
        if expected.is_file() {
            return;
        }
        let status: std::process::ExitStatus = std::process::Command::new("cargo")
            .args([
                "build",
                "-p",
                "disrobe-binfmt",
                "--bin",
                "disrobe-binfmt-mock-tool",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("spawn cargo build for mock");
        assert!(status.success(), "cargo build mock_tool failed");
        assert!(expected.is_file(), "mock binary not at expected path");
    }

    fn write_wrapper(dir: &Path, stem: &str, mode: &str) -> PathBuf {
        let mock: PathBuf = mock_bin_path();
        let mock_s: String = mock.to_string_lossy().into_owned();
        let body: String = if cfg!(windows) {
            format!("@echo off\r\n\"{mock_s}\" {mode} %*\r\nexit /b %errorlevel%\r\n")
        } else {
            format!("#!/bin/sh\nexec \"{mock_s}\" {mode} \"$@\"\n")
        };
        let path: PathBuf = if cfg!(windows) {
            dir.join(format!("{stem}.cmd"))
        } else {
            dir.join(stem)
        };
        let mut f: std::fs::File = std::fs::File::create(&path).expect("create wrapper");
        f.write_all(body.as_bytes()).expect("write wrapper");
        drop(f);
        if !cfg!(windows) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                let mut perms: std::fs::Permissions =
                    std::fs::metadata(&path).expect("meta").permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).expect("chmod");
            }
        }
        path
    }

    fn write_mock_unrar(dir: &Path) -> PathBuf {
        write_wrapper(dir, "mock_unrar", "unrar")
    }

    fn write_mock_sevenz(dir: &Path) -> PathBuf {
        write_wrapper(dir, "mock_7z", "sevenz")
    }

    fn install_path_override(tool: ExternalTool, path: &Path) {
        let mut o: ToolOverrides = ToolOverrides::default();
        o.paths.insert(tool, path.to_path_buf());
        set_overrides(o);
    }

    #[test]
    fn capture_reader_caps_stored_output() {
        let payload: Vec<u8> = vec![b'x'; MAX_CAPTURE_OUTPUT + 1024];
        let captured: Vec<u8> = read_capped_output(std::io::Cursor::new(payload));
        assert_eq!(captured.len(), MAX_CAPTURE_OUTPUT);
        assert!(captured.iter().all(|byte: &u8| *byte == b'x'));
    }

    #[test]
    fn cleanup_file_helper_removes_existing_file_and_accepts_missing_file() {
        let dir: PathBuf = temp_dir("cleanup-file");
        let path: PathBuf = dir.join("temp.bin");
        remove_file_if_exists(&path).expect("missing file ok");
        std::fs::write(&path, b"x").expect("write file");
        remove_file_if_exists(&path).expect("remove file");
        assert!(!path.exists());
        let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_dir_helper_removes_existing_dir_and_accepts_missing_dir() {
        let dir: PathBuf = temp_dir("cleanup-dir");
        let nested: PathBuf = dir.join("nested");
        std::fs::create_dir_all(&nested).expect("make nested dir");
        remove_dir_if_exists(&nested).expect("remove nested dir");
        assert!(!nested.exists());
        remove_dir_if_exists(&nested).expect("missing dir ok");
        let _: std::io::Result<()> = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_results_structure_contains_all_tools() {
        let _g: std::sync::MutexGuard<'_, ()> = super::lock_overrides();
        clear_overrides();
        let probe: BTreeMap<ExternalTool, ProbeResult> = probe_external_tools();
        clear_overrides();
        assert_eq!(probe.len(), 5);
        assert!(probe.contains_key(&ExternalTool::Unrar));
        assert!(probe.contains_key(&ExternalTool::SevenZip));
        assert!(probe.contains_key(&ExternalTool::Pkgutil));
        assert!(probe.contains_key(&ExternalTool::Hdiutil));
        assert!(probe.contains_key(&ExternalTool::Bsdtar));
    }

    #[test]
    fn missing_tool_returns_external_tool_missing_error() {
        let _g: std::sync::MutexGuard<'_, ()> = super::lock_overrides();
        set_overrides(ToolOverrides {
            disable_all: true,
            paths: BTreeMap::new(),
        });
        let out: PathBuf = temp_dir("rar-missing");
        let bytes: &[u8] = b"Rar!\x1a\x07\x00garbage";
        let r: Result<ExtractionResult> = extract_via_tool(ContainerKind::Rar, bytes, &out);
        clear_overrides();
        match r {
            Err(Error::ExternalToolMissing { tool }) => assert_eq!(tool, "rar"),
            Err(other) => panic!("wrong error: {other:?}"),
            Ok(_) => panic!("expected missing-tool"),
        }
    }

    #[test]
    fn synthetic_rar_through_unrar_mock() {
        let _g: std::sync::MutexGuard<'_, ()> = super::lock_overrides();
        let bin_dir: PathBuf = temp_dir("rar-mock-bin");
        let script: PathBuf = write_mock_unrar(&bin_dir);
        install_path_override(ExternalTool::Unrar, &script);
        let out: PathBuf = temp_dir("rar-mock-out");
        let bytes: &[u8] = b"Rar!\x1a\x07\x00fakecontent";
        let res: ExtractionResult =
            wrap_external_extract(ExternalTool::Unrar, bytes, &out).expect("wrap unrar");
        clear_overrides();
        assert_eq!(res.kind, ContainerKind::Rar);
        assert!(
            res.entries
                .iter()
                .any(|e: &ExtractedEntry| e.name.ends_with("mock.txt"))
        );
    }

    #[test]
    fn synthetic_iso_through_sevenz_mock() {
        let _g: std::sync::MutexGuard<'_, ()> = super::lock_overrides();
        let bin_dir: PathBuf = temp_dir("iso-mock-bin");
        let script: PathBuf = write_mock_sevenz(&bin_dir);
        install_path_override(ExternalTool::SevenZip, &script);
        let out: PathBuf = temp_dir("iso-mock-out");
        let bytes: &[u8] = b"CD001fakeiso";
        let res: ExtractionResult =
            wrap_external_extract(ExternalTool::SevenZip, bytes, &out).expect("wrap 7z");
        clear_overrides();
        assert_eq!(res.kind, ContainerKind::Iso);
        assert!(
            res.entries
                .iter()
                .any(|e: &ExtractedEntry| e.name.ends_with("iso.txt"))
        );
    }

    #[test]
    fn external_extract_writes_into_out_dir() {
        let _g: std::sync::MutexGuard<'_, ()> = super::lock_overrides();
        let bin_dir: PathBuf = temp_dir("write-mock-bin");
        let script: PathBuf = write_mock_unrar(&bin_dir);
        install_path_override(ExternalTool::Unrar, &script);
        let out: PathBuf = temp_dir("write-mock-out");
        let bytes: &[u8] = b"Rar!\x1a\x07\x00abc";
        let _ = wrap_external_extract(ExternalTool::Unrar, bytes, &out).expect("wrap");
        clear_overrides();
        let listing: Vec<PathBuf> = std::fs::read_dir(&out)
            .expect("readdir")
            .filter_map(|e: std::io::Result<std::fs::DirEntry>| {
                e.ok().map(|d: std::fs::DirEntry| d.path())
            })
            .collect();
        assert!(listing.iter().any(|p: &PathBuf| p.ends_with("mock.txt")));
    }

    #[test]
    fn external_extract_honors_timeout() {
        let mock: PathBuf = mock_bin_path();
        let timeout: Duration = Duration::from_millis(300);
        let result: Result<(i32, String, String)> = run_capture(&mock, &["sleep", "5"], timeout);
        match result {
            Err(Error::ExternalToolTimeout { seconds, .. }) => assert_eq!(seconds, 0),
            Err(other) => panic!("expected timeout, got {other:?}"),
            Ok(_) => panic!("mock did not actually block"),
        }
    }

    #[test]
    fn containment_accepts_normal_entries() {
        let staging: PathBuf = temp_dir("contain-ok-stage");
        let out: PathBuf = temp_dir("contain-ok-out");
        std::fs::create_dir_all(staging.join("sub")).expect("mkdir sub");
        std::fs::write(staging.join("top.txt"), b"top").expect("write top");
        std::fs::write(staging.join("sub").join("nested.txt"), b"nested").expect("write nested");
        contain_staging_into(&staging, &out).expect("containment must accept normal entries");
        assert!(out.join("top.txt").is_file());
        assert!(out.join("sub").join("nested.txt").is_file());
    }

    #[test]
    fn containment_rejects_symlink_escape() {
        let staging: PathBuf = temp_dir("contain-escape-stage");
        let out: PathBuf = temp_dir("contain-escape-out");
        let outside: PathBuf = temp_dir("contain-escape-outside");
        let secret: PathBuf = outside.join("secret.txt");
        std::fs::write(&secret, b"top-secret").expect("write secret");
        std::fs::write(staging.join("benign.txt"), b"benign").expect("write benign");
        let link: PathBuf = staging.join("escape");
        let made: bool = make_symlink(&secret, &link);
        if !made {
            return;
        }
        let r: Result<()> = contain_staging_into(&staging, &out);
        match r {
            Err(Error::UnsafeEntryPath(_)) => {}
            Err(other) => panic!("expected UnsafeEntryPath, got {other:?}"),
            Ok(()) => panic!("symlink escape was not rejected"),
        }
        assert!(
            !out.join("escape").exists(),
            "escaping symlink must not surface into out_dir"
        );
        assert!(secret.is_file(), "containment must not follow link out");
    }

    #[cfg(unix)]
    fn make_symlink(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[cfg(windows)]
    fn make_symlink(target: &Path, link: &Path) -> bool {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }

    #[cfg(not(any(unix, windows)))]
    fn make_symlink(_target: &Path, _link: &Path) -> bool {
        false
    }

    #[test]
    fn supported_on_host_matches_target_os() {
        assert!(ExternalTool::Unrar.supported_on_host());
        assert!(ExternalTool::SevenZip.supported_on_host());
        assert_eq!(
            ExternalTool::Pkgutil.supported_on_host(),
            cfg!(target_os = "macos")
        );
        assert_eq!(
            ExternalTool::Hdiutil.supported_on_host(),
            cfg!(target_os = "macos")
        );
    }
}
