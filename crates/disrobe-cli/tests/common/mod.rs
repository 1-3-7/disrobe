#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::ptr_arg,
    dead_code,
    unreachable_pub
)]

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

pub const REQUIRE_UNCOMMITTED_CORPUS: &str = "DISROBE_REQUIRE_UNCOMMITTED_CORPUS";
pub const REQUIRE_UPX: &str = "DISROBE_REQUIRE_UPX";

pub fn required_by_env(variable: &str) -> bool {
    let Some(raw): Option<OsString> = std::env::var_os(variable) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

pub fn unmeasured(graded: &str, absent: &str, variable: &str) {
    assert!(
        !required_by_env(variable),
        "{variable} makes this input mandatory for this run, so {graded} was measured against \
         nothing and this case must not report success: {absent}. To permit a run that grades \
         nothing here, clear {variable}."
    );
    eprintln!(
        "\nNOT MEASURED: {graded} graded nothing, because {absent}. Set {variable}=1 to fail \
         instead of skipping.\n"
    );
}

pub fn uncommitted_corpus_is_absent(path: &Path, graded: &str) -> bool {
    if path.exists() {
        return false;
    }
    unmeasured(
        graded,
        &format!(
            "{} is kept out of git by a blanket .gitignore rule and is not in this checkout",
            path.display()
        ),
        REQUIRE_UNCOMMITTED_CORPUS,
    );
    true
}

pub fn cli_binary() -> PathBuf {
    let mut p: PathBuf = env_target_dir();
    p.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    p
}

fn env_target_dir() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir
}

pub fn temp_path(stem: &str, ext: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-cli-flags-{stem}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory");
    let basename: &std::ffi::OsStr = scratch
        .path()
        .file_name()
        .expect("scratch directory has a basename");
    let filename: String = format!("{}.{ext}", basename.to_string_lossy());
    let path: PathBuf = scratch.path().join(filename);
    (scratch, path)
}

pub fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-cli-flags-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

pub fn write_bytes(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        let _: std::io::Result<()> = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, bytes).expect("write fixture");
}

#[derive(Debug)]
pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run_disrobe(args: &[&str]) -> Run {
    run_disrobe_env(args, &[])
}

pub fn run_disrobe_env(args: &[&str], env: &[(&str, &str)]) -> Run {
    let bin: PathBuf = cli_binary();
    assert!(
        bin.exists(),
        "disrobe binary not built at {} -- run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    let mut cmd: Command = Command::new(&bin);
    cmd.args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output: std::process::Output = cmd.output().expect("spawn disrobe");
    Run {
        code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

pub fn minimal_wasm() -> Vec<u8> {
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}

pub const STDIO_SERVER_DEADLINE: Duration = Duration::from_secs(45);

const SERVE_LOCK_STALE_AFTER: Duration = Duration::from_secs(90);
const SERVE_LOCK_BACKOFF: Duration = Duration::from_millis(25);

#[derive(Debug)]
pub struct ServeSpawnLock {
    path: PathBuf,
}

impl ServeSpawnLock {
    pub fn acquire() -> Self {
        let root: PathBuf = disrobe_core::scratch::scratch_root();
        std::fs::create_dir_all(&root).expect("create scratch root");
        let path: PathBuf = root.join("disrobe-serve-e2e-spawn.lock");
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_file) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Self::reap_if_stale(&path) {
                        continue;
                    }
                    thread::sleep(SERVE_LOCK_BACKOFF);
                }
                Err(_) => {
                    thread::sleep(SERVE_LOCK_BACKOFF);
                }
            }
        }
    }

    fn reap_if_stale(path: &Path) -> bool {
        let Ok(meta): std::io::Result<std::fs::Metadata> = std::fs::metadata(path) else {
            return false;
        };
        let Ok(modified): std::io::Result<std::time::SystemTime> = meta.modified() else {
            return false;
        };
        let aged: bool = modified
            .elapsed()
            .is_ok_and(|age: Duration| age >= SERVE_LOCK_STALE_AFTER);
        if aged {
            return std::fs::remove_file(path).is_ok();
        }
        false
    }
}

impl Drop for ServeSpawnLock {
    fn drop(&mut self) {
        let _: std::io::Result<()> = std::fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
pub fn kill_by_pid(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
}

#[cfg(windows)]
pub fn kill_by_pid(pid: u32) {
    let _ = Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .status();
}

#[derive(Debug)]
pub struct StdioServer {
    label: String,
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: Arc<Mutex<Vec<u8>>>,
    finished: Arc<AtomicBool>,
}

impl StdioServer {
    pub fn spawn(label: &str, args: &[&str], env: &[(&str, &str)]) -> Self {
        let bin: PathBuf = cli_binary();
        assert!(
            bin.exists(),
            "disrobe binary not built at {}: run `cargo build -p disrobe-cli` first",
            bin.display()
        );
        let mut cmd: Command = Command::new(&bin);
        cmd.args(args)
            .env_remove("RUST_LOG")
            .env_remove("DISROBE_LOG")
            .env_remove("DISROBE_DEBUG")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            cmd.env(key, value);
        }
        let spawned: std::io::Result<Child> = cmd.spawn();
        let mut child: Child = match spawned {
            Ok(c) => c,
            Err(e) => panic!("{label}: cannot spawn `disrobe {}`: {e}", args.join(" ")),
        };
        let stdin: ChildStdin = child.stdin.take().expect("piped stdin");
        let stdout: ChildStdout = child.stdout.take().expect("piped stdout");
        let child_stderr: ChildStderr = child.stderr.take().expect("piped stderr");
        let stderr: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let drain: Arc<Mutex<Vec<u8>>> = Arc::clone(&stderr);
        thread::spawn(move || {
            let mut reader: BufReader<ChildStderr> = BufReader::new(child_stderr);
            let mut captured: Vec<u8> = Vec::new();
            let _ = reader.read_to_end(&mut captured);
            if let Ok(mut sink) = drain.lock() {
                sink.extend_from_slice(&captured);
            }
        });
        let finished: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let watchdog: Arc<AtomicBool> = Arc::clone(&finished);
        let pid: u32 = child.id();
        let watchdog_label: String = label.to_owned();
        thread::spawn(move || {
            let start: Instant = Instant::now();
            while start.elapsed() < STDIO_SERVER_DEADLINE {
                if watchdog.load(Ordering::SeqCst) {
                    return;
                }
                thread::sleep(Duration::from_millis(250));
            }
            if !watchdog.load(Ordering::SeqCst) {
                eprintln!(
                    "TIMEOUT: {watchdog_label} exceeded the stdio deadline; killing pid={pid}"
                );
                kill_by_pid(pid);
            }
        });
        Self {
            label: label.to_owned(),
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            stderr,
            finished,
        }
    }

    pub fn send(&mut self, bytes: &[u8]) {
        let label: String = self.label.clone();
        let stdin: &mut ChildStdin = self
            .stdin
            .as_mut()
            .unwrap_or_else(|| panic!("{label}: stdin was already closed"));
        let written: std::io::Result<()> = stdin.write_all(bytes).and_then(|()| stdin.flush());
        if let Err(e) = written {
            panic!(
                "{label}: writing {} bytes to the server failed: {e}; stderr={}",
                bytes.len(),
                self.stderr_text()
            );
        }
    }

    pub fn read_line_bytes(&mut self) -> Vec<u8> {
        let mut line: Vec<u8> = Vec::new();
        let read: std::io::Result<usize> = self.stdout.read_until(b'\n', &mut line);
        let count: usize = match read {
            Ok(n) => n,
            Err(e) => panic!(
                "{}: reading a line from the server failed: {e}; stderr={}",
                self.label,
                self.stderr_text()
            ),
        };
        assert!(
            count > 0,
            "{}: the server closed stdout before sending a line; stderr={}",
            self.label,
            self.stderr_text()
        );
        line
    }

    pub fn read_exact_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut body: Vec<u8> = vec![0u8; len];
        let read: std::io::Result<()> = self.stdout.read_exact(&mut body);
        if let Err(e) = read {
            panic!(
                "{}: the server promised {len} body bytes and did not send them: {e}; stderr={}",
                self.label,
                self.stderr_text()
            );
        }
        body
    }

    pub fn stderr_text(&self) -> String {
        self.stderr.lock().map_or_else(
            |_| String::from("<stderr capture poisoned>"),
            |bytes: std::sync::MutexGuard<'_, Vec<u8>>| {
                String::from_utf8_lossy(&bytes).into_owned()
            },
        )
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn close_stdin(&mut self) {
        drop(self.stdin.take());
    }

    pub fn wait_for_exit(&mut self) -> i32 {
        self.close_stdin();
        let status: std::io::Result<std::process::ExitStatus> = self.child.wait();
        self.finished.store(true, Ordering::SeqCst);
        match status {
            Ok(s) => s.code().unwrap_or(-1),
            Err(e) => panic!(
                "{}: waiting for the server to exit failed: {e}; stderr={}",
                self.label,
                self.stderr_text()
            ),
        }
    }
}

impl Drop for StdioServer {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        drop(self.stdin.take());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
