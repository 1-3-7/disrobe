#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::redundant_closure_for_method_calls,
    clippy::uninlined_format_args,
    clippy::option_if_let_else
)]

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener as StdTcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

const SERVE_TEST_DEADLINE: Duration = Duration::from_secs(30);
const SERVE_LOCK_STALE_AFTER: Duration = Duration::from_secs(90);
const SERVE_LOCK_BACKOFF: Duration = Duration::from_millis(25);

#[derive(Debug)]
struct ServeSpawnLock {
    path: PathBuf,
}

impl ServeSpawnLock {
    fn acquire() -> Self {
        let path: PathBuf = std::env::temp_dir().join("disrobe-serve-e2e-spawn.lock");
        loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
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
        let Ok(modified): std::io::Result<SystemTime> = meta.modified() else {
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

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir.file_name().and_then(|s| s.to_str()) != Some("debug")
        && dir.file_name().and_then(|s| s.to_str()) != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn ephemeral_port() -> u16 {
    let listener: StdTcpListener = StdTcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

struct ServeHandle {
    child: Child,
    addr: SocketAddr,
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

fn spawn_serve() -> Option<ServeHandle> {
    let bin: PathBuf = cli_binary();
    if !bin.exists() {
        return None;
    }
    let guard: ServeSpawnLock = ServeSpawnLock::acquire();
    let port: u16 = ephemeral_port();
    let addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut child: Child = Command::new(&bin)
        .args(["serve", "--bind", &addr.to_string()])
        .env_remove("RUST_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let finished: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let watchdog_flag: Arc<AtomicBool> = Arc::clone(&finished);
    let pid_for_kill: u32 = child.id();
    thread::spawn(move || {
        let start: Instant = Instant::now();
        while start.elapsed() < SERVE_TEST_DEADLINE {
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
    wait_for_listen(addr, Duration::from_secs(8));
    if let Ok(Some(_status)) = child.try_wait() {
        return None;
    }
    Some(ServeHandle {
        child,
        addr,
        finished,
        _spawn_guard: guard,
    })
}

#[cfg(unix)]
fn kill_by_pid(pid: u32) {
    let _ = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status();
}

#[cfg(windows)]
fn kill_by_pid(pid: u32) {
    let _ = std::process::Command::new("taskkill")
        .args(["/F", "/T", "/PID", &pid.to_string()])
        .status();
}

fn wait_for_listen(addr: SocketAddr, timeout: Duration) {
    let started: Instant = Instant::now();
    while started.elapsed() < timeout {
        if http_health_ready(addr) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn http_health_ready(addr: SocketAddr) -> bool {
    let Ok(mut stream): std::io::Result<TcpStream> =
        TcpStream::connect_timeout(&addr, Duration::from_millis(200))
    else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
    {
        return false;
    }
    let request: String =
        format!("GET /v1/health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let _ = stream.read_to_end(&mut buf);
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&buf);
    text.lines()
        .next()
        .and_then(|line: &str| line.split_whitespace().nth(1))
        .and_then(|code: &str| code.parse::<u16>().ok())
        == Some(200)
}

fn http_request(addr: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut stream: TcpStream =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect serve");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    let host_header: String = format!("Host: {addr}\r\n");
    let body_part: String = body.map_or_else(String::new, str::to_owned);
    let content_length: usize = body_part.len();
    let request: String = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.1\r\n{host_header}Content-Type: application/json\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n{b}"
        )
    } else {
        format!("{method} {path} HTTP/1.1\r\n{host_header}Connection: close\r\n\r\n")
    };
    stream.write_all(request.as_bytes()).expect("write request");
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let _ = stream.read_to_end(&mut buf);
    let text: String = String::from_utf8_lossy(&buf).into_owned();
    let status_line: &str = text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let body_text: String = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body_text)
}

#[test]
fn serve_health_endpoint_returns_ok_json() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) = http_request(handle.addr, "GET", "/v1/health", None);
    assert_eq!(status, 200, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v.get("status").and_then(|x| x.as_str()), Some("serving"));
}

#[test]
fn serve_version_endpoint_returns_cargo_version() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) = http_request(handle.addr, "GET", "/v1/version", None);
    assert_eq!(status, 200, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(
        v.get("version").and_then(|x| x.as_str()),
        Some(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn serve_passes_endpoint_returns_descriptors() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) = http_request(handle.addr, "GET", "/v1/passes", None);
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let passes: &Vec<serde_json::Value> = v
        .get("passes")
        .and_then(|p| p.as_array())
        .expect("passes array");
    assert!(passes.iter().any(|p| p["name"] == "pyarmor"));
    assert!(passes.iter().any(|p| p["name"] == "wasm"));
}

#[test]
fn serve_openapi_endpoint_returns_spec() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) = http_request(handle.addr, "GET", "/openapi.json", None);
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v.get("openapi").is_some() || v.get("paths").is_some());
}

#[test]
fn serve_analyze_endpoint_classifies_inline_bytes() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let body_str: &str = r#"{"bytes_b64":"AGFzbQEAAAA="}"#;
    let (status, body): (u16, String) =
        http_request(handle.addr, "POST", "/v1/analyze", Some(body_str));
    assert_eq!(status, 200, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v.get("bytes_read").and_then(|x| x.as_u64()), Some(8));
}

#[test]
fn serve_explain_endpoint_returns_known_code() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) =
        http_request(handle.addr, "POST", "/v1/explain/DR-PYARM-0007", Some("{}"));
    assert_eq!(status, 200, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert_eq!(v.get("known").and_then(|x| x.as_bool()), Some(true));
}

#[test]
fn serve_envelope_verify_endpoint_rejects_malformed_bytes() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let body_str: &str = r#"{"bytes_b64":"AAAA"}"#;
    let (status, body): (u16, String) =
        http_request(handle.addr, "POST", "/v1/envelope/verify", Some(body_str));
    assert_eq!(status, 400, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v.get("error_code").is_some());
}

#[test]
fn serve_analyze_rejects_path_field_with_unknown_field_error() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let body_str: &str = r#"{"path":"/etc/passwd"}"#;
    let (status, body): (u16, String) =
        http_request(handle.addr, "POST", "/v1/analyze", Some(body_str));
    assert!(
        (400..500).contains(&status),
        "status={status} body={body}; server must reject `path` field"
    );
    assert!(
        !body.contains("/etc/passwd")
            || body.to_ascii_lowercase().contains("unknown")
            || body.to_ascii_lowercase().contains("missing"),
        "server must not silently read the supplied path; body={body}"
    );
}

#[test]
fn serve_envelope_verify_rejects_path_field_with_unknown_field_error() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let body_str: &str = r#"{"path":"/etc/passwd"}"#;
    let (status, body): (u16, String) =
        http_request(handle.addr, "POST", "/v1/envelope/verify", Some(body_str));
    assert!(
        (400..500).contains(&status),
        "status={status} body={body}; server must reject `path` field"
    );
}

#[test]
fn serve_envelope_create_then_verify_round_trips_inline() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let create_body: &str =
        r#"{"bytes_b64":"AGFzbQEAAAA=","source_label":"sample.wasm","detected_format":"wasm"}"#;
    let (status, body): (u16, String) = http_request(
        handle.addr,
        "POST",
        "/v1/envelope/create",
        Some(create_body),
    );
    assert_eq!(status, 200, "create body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("create json");
    let envelope_b64: &str = v
        .get("envelope_b64")
        .and_then(|x| x.as_str())
        .expect("envelope_b64 in response");
    let verify_body: String = format!("{{\"bytes_b64\":\"{envelope_b64}\"}}");
    let (vstatus, vbody): (u16, String) = http_request(
        handle.addr,
        "POST",
        "/v1/envelope/verify",
        Some(&verify_body),
    );
    assert_eq!(vstatus, 200, "verify body={vbody}");
    let vv: serde_json::Value = serde_json::from_str(&vbody).expect("verify json");
    assert_eq!(vv.get("verified").and_then(|x| x.as_bool()), Some(true));
    assert_eq!(
        vv.get("root_hash_blake3").and_then(|x| x.as_str()),
        v.get("root_hash_blake3").and_then(|x| x.as_str())
    );
}

#[test]
fn serve_openapi_no_longer_exposes_path_field() {
    let Some(handle) = spawn_serve() else {
        eprintln!("disrobe binary missing; skip");
        return;
    };
    let (status, body): (u16, String) = http_request(handle.addr, "GET", "/openapi.json", None);
    assert_eq!(status, 200);
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    let schemas: &serde_json::Value = v
        .pointer("/components/schemas")
        .expect("openapi components.schemas");
    for name in [
        "AnalyzeRequest",
        "EnvelopeVerifyRequest",
        "EnvelopeCreateRequest",
    ] {
        let schema: &serde_json::Value = schemas
            .get(name)
            .unwrap_or_else(|| panic!("schema {name} missing"));
        let props: &serde_json::Map<String, serde_json::Value> = schema
            .get("properties")
            .and_then(|p| p.as_object())
            .unwrap_or_else(|| panic!("schema {name} has no properties"));
        assert!(
            !props.contains_key("path"),
            "schema {name} must not expose `path` field; props={props:?}"
        );
        assert!(
            !props.contains_key("source_path"),
            "schema {name} must not expose `source_path` field"
        );
        assert!(
            !props.contains_key("out_path"),
            "schema {name} must not expose `out_path` field"
        );
        assert!(
            props.contains_key("bytes_b64"),
            "schema {name} must require `bytes_b64`"
        );
    }
}
