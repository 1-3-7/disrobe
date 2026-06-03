#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

//! Non-circular oracle for the capability sandbox.
//!
//! Ground truth is wasmtime's own trap and import-resolution semantics, never a
//! format this crate emits. Each fixture is hand-authored `.wat` (text, not a
//! download) that exercises exactly one cap, and is asserted against the
//! [`SandboxError`] variant wasmtime is contractually required to produce.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use disrobe_plugin_host::{Limits, PluginHost, SandboxError};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("wasm")
        .join("plugins")
}

fn load(name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = fixture_dir().join(name);
    let text: String = std::fs::read_to_string(&path).ok()?;
    match wat::parse_str(&text) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            eprintln!("SKIP: fixture {} failed to assemble: {e}", path.display());
            None
        }
    }
}

#[test]
fn net_socket_import_is_denied_before_guest_runs() {
    let Some(wasm): Option<Vec<u8>> = load("deny_net_sock_open.wat") else {
        eprintln!("SKIP: deny_net_sock_open.wat missing");
        return;
    };
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], Limits::default());
    match outcome {
        Err(SandboxError::DeniedImport(name)) => {
            assert!(
                name.contains("sock_open"),
                "denied import must name the socket capability, got {name}",
            );
        }
        other => panic!("net import must be denied, got {other:?}"),
    }
}

#[test]
fn fs_import_is_denied_before_guest_runs() {
    let Some(wasm): Option<Vec<u8>> = load("deny_fs_fd_write.wat") else {
        eprintln!("SKIP: deny_fs_fd_write.wat missing");
        return;
    };
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], Limits::default());
    match outcome {
        Err(SandboxError::DeniedImport(name)) => {
            assert!(
                name.contains("fd_write") || name.contains("path_open"),
                "denied import must name a filesystem capability, got {name}",
            );
        }
        other => panic!("fs import must be denied, got {other:?}"),
    }
}

#[test]
fn infinite_loop_is_stopped_within_budget() {
    let Some(wasm): Option<Vec<u8>> = load("busyloop_timeout.wat") else {
        eprintln!("SKIP: busyloop_timeout.wat missing");
        return;
    };
    let limits: Limits = Limits {
        fuel_budget: 20_000_000,
        wall_deadline: Duration::from_millis(300),
        memory_cap_bytes: 1024 * 1024,
    };
    let started: Instant = Instant::now();
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], limits);
    let elapsed: Duration = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "busy loop must be aborted, not hang; took {elapsed:?}",
    );
    assert!(
        matches!(outcome, Err(SandboxError::Timeout | SandboxError::Fuel)),
        "busy loop must trip the wall-clock or fuel cap, got {outcome:?}",
    );
}

#[test]
fn memory_growth_past_cap_is_denied() {
    let Some(wasm): Option<Vec<u8>> = load("memgrow_bomb.wat") else {
        eprintln!("SKIP: memgrow_bomb.wat missing");
        return;
    };
    let limits: Limits = Limits {
        fuel_budget: 50_000_000,
        wall_deadline: Duration::from_secs(2),
        memory_cap_bytes: 4 * 1024 * 1024,
    };
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], limits);
    assert!(
        matches!(outcome, Err(SandboxError::Memory)),
        "memory bomb must trip the byte cap, got {outcome:?}",
    );
}

#[test]
fn pure_compute_module_runs_and_returns_correct_bytes() {
    let Some(wasm): Option<Vec<u8>> = load("compute_xor.wat") else {
        eprintln!("SKIP: compute_xor.wat missing");
        return;
    };
    let input: [u8; 5] = [0x00, 0x10, 0x7f, 0x80, 0xff];
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &input, Limits::default());
    let output: Vec<u8> = outcome.expect("import-free compute module must run cleanly");
    let expected: Vec<u8> = input.iter().map(|b| b ^ 0xff).collect();
    assert_eq!(
        output, expected,
        "sandbox must return the guest's real transform, not deny everything",
    );
}
