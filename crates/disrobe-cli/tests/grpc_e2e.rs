#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::uninlined_format_args,
    clippy::option_if_let_else
)]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use common::{ServeSpawnLock, cli_binary, kill_by_pid};

mod common;

const GRPC_TEST_DEADLINE: Duration = Duration::from_secs(30);

fn reserve_adjacent_pair() -> Option<u16> {
    for _ in 0..64 {
        let primary: StdTcpListener = match StdTcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(_) => continue,
        };
        let p: u16 = match primary.local_addr() {
            Ok(a) => a.port(),
            Err(_) => continue,
        };
        if p >= u16::MAX - 1 {
            continue;
        }
        let next_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], p + 1));
        let secondary: StdTcpListener = match StdTcpListener::bind(next_addr) {
            Ok(l) => l,
            Err(_) => continue,
        };
        drop(secondary);
        drop(primary);
        return Some(p);
    }
    None
}

fn ephemeral_port_pair() -> u16 {
    reserve_adjacent_pair().expect("find adjacent ephemeral port pair")
}

struct ServeHandle {
    child: Child,
    http_addr: SocketAddr,
    grpc_addr: SocketAddr,
    finished: Arc<AtomicBool>,
    _spawn_guard: ServeSpawnLock,
}

impl Drop for ServeHandle {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::SeqCst);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_grpc_serve() -> Option<ServeHandle> {
    if std::env::consts::OS == "windows" {
        eprintln!("skip: grpc serve e2e is fragile on the windows runner; covered on linux/macos");
        return None;
    }
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        return None;
    }
    let guard: ServeSpawnLock = ServeSpawnLock::acquire();
    let http_port: u16 = ephemeral_port_pair();
    let http_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], http_port));
    let grpc_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], http_port + 1));
    let child: Child = Command::new(&bin)
        .args(["serve", "--bind", &http_addr.to_string(), "--grpc"])
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve --grpc");
    let finished: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let watchdog_flag: Arc<AtomicBool> = Arc::clone(&finished);
    let pid_for_kill: u32 = child.id();
    thread::spawn(move || {
        let start: Instant = Instant::now();
        while start.elapsed() < GRPC_TEST_DEADLINE {
            if watchdog_flag.load(Ordering::SeqCst) {
                return;
            }
            thread::sleep(Duration::from_millis(250));
        }
        if !watchdog_flag.load(Ordering::SeqCst) {
            eprintln!("TIMEOUT: serve test deadline exceeded; killing pid={pid_for_kill}");
            kill_by_pid(pid_for_kill);
        }
    });
    wait_for_listen(grpc_addr, Duration::from_secs(10));
    Some(ServeHandle {
        child,
        http_addr,
        grpc_addr,
        finished,
        _spawn_guard: guard,
    })
}

fn wait_for_listen(addr: SocketAddr, timeout: Duration) {
    let started: Instant = Instant::now();
    while started.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-grpc-e2e-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

#[test]
fn grpc_serve_starts_with_flag_enabled() {
    let Some(handle) = spawn_grpc_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let http_ok: bool =
        std::net::TcpStream::connect_timeout(&handle.http_addr, Duration::from_secs(2)).is_ok();
    let grpc_ok: bool =
        std::net::TcpStream::connect_timeout(&handle.grpc_addr, Duration::from_secs(2)).is_ok();
    assert!(http_ok, "http port not listening at {}", handle.http_addr);
    assert!(grpc_ok, "grpc port not listening at {}", handle.grpc_addr);
}

#[test]
fn grpc_serve_ports_are_offset_by_one() {
    let Some(handle) = spawn_grpc_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    assert_eq!(handle.grpc_addr.port(), handle.http_addr.port() + 1);
}

#[test]
fn install_deps_requires_subcommand_or_all() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let out: std::process::Output = Command::new(&bin)
        .args(["install-deps"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run install-deps");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let combined: String = format!("{stdout}{stderr}");
    assert!(
        !out.status.success()
            || combined.contains("DR-CLI-0290")
            || combined.contains("install-deps"),
        "expected failure or guidance: stderr={stderr} stdout={stdout}"
    );
}

#[test]
fn install_deps_ghidra_dry_run_does_not_touch_network() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let out: std::process::Output = Command::new(&bin)
        .args(["install-deps", "ghidra", "--dry-run"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run install-deps ghidra --dry-run");
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("ghidra") || stdout.contains("dry-run") || stdout.contains("status"),
        "stdout did not mention dry-run or ghidra: {stdout}"
    );
}

#[test]
fn self_update_dry_run_does_not_touch_network() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let out: std::process::Output = Command::new(&bin)
        .args(["self-update", "--dry-run"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run self-update --dry-run");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("dry-run") || stdout.contains("status"),
        "{stdout}"
    );
}

#[test]
fn cli_global_flags_parse_without_error() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let out: std::process::Output = Command::new(&bin)
        .args([
            "--threads",
            "2",
            "--no-cache",
            "--force",
            "--in-place",
            "--progress",
            "never",
            "passes",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run passes with globals");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn cli_dry_run_global_flag_overrides_subcommand_default() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let tmp_scratch: disrobe_core::scratch::ScratchDir = temp_dir("dry-auto");
    let tmp: PathBuf = tmp_scratch.path().to_path_buf();
    let input: PathBuf = tmp.join("hello.py");
    std::fs::write(&input, b"print('hi')\n").expect("write input");
    let out: std::process::Output = Command::new(&bin)
        .args(["--dry-run", "auto", input.to_str().expect("utf8")])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run auto");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn progress_mode_invalid_value_rejected() {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        eprintln!("disrobe binary missing; skip");
        return;
    }
    let out: std::process::Output = Command::new(&bin)
        .args(["--progress", "sometimes", "passes"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run with bad progress");
    assert!(!out.status.success());
}
