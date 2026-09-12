#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
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

fn load(name: &str) -> Vec<u8> {
    let path: PathBuf = fixture_dir().join(name);
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is tracked in git and this case is a sandbox deny-by-default proof, so its absence \
             is a damaged checkout rather than an optional dependency: {error}",
            path.display()
        )
    });
    wat::parse_str(&text).unwrap_or_else(|error: wat::Error| {
        panic!(
            "{} is tracked and must assemble; a capability case that cannot build its guest proves \
             nothing about what the host denies: {error}",
            path.display()
        )
    })
}

#[test]
fn net_socket_import_is_denied_before_guest_runs() {
    let wasm: Vec<u8> = load("deny_net_sock_open.wat");
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
    let wasm: Vec<u8> = load("deny_fs_fd_write.wat");
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
    let wasm: Vec<u8> = load("busyloop_timeout.wat");
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
    let wasm: Vec<u8> = load("memgrow_bomb.wat");
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
fn initial_memory_past_cap_is_denied_as_memory() {
    let wasm: Vec<u8> = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "run") (param i32) (result i32)
            i32.const 0))
        "#,
    )
    .expect("initial memory module must assemble");
    let limits: Limits = Limits {
        fuel_budget: 50_000,
        wall_deadline: Duration::from_secs(1),
        memory_cap_bytes: 1024,
    };
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], limits);
    assert!(
        matches!(outcome, Err(SandboxError::Memory)),
        "initial memory above cap must be reported as memory, got {outcome:?}",
    );
}

#[test]
fn oversized_output_length_is_denied_before_host_allocation() {
    let wasm: Vec<u8> = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "run") (param i32) (result i32)
            i32.const 2147483647))
        "#,
    )
    .expect("oversized output module must assemble");
    let limits: Limits = Limits {
        fuel_budget: 50_000,
        wall_deadline: Duration::from_secs(1),
        memory_cap_bytes: 64 * 1024,
    };
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], limits);
    assert!(
        matches!(outcome, Err(SandboxError::Memory)),
        "oversized output must trip the host output cap before allocation, got {outcome:?}",
    );
}

#[test]
fn input_past_guest_memory_is_denied_before_guest_write() {
    let wasm: Vec<u8> = wat::parse_str(
        r#"
        (module
          (memory (export "memory") 1)
          (func (export "run") (param i32) (result i32)
            i32.const 0))
        "#,
    )
    .expect("small guest memory module must assemble");
    let input: Vec<u8> = vec![0u8; 64 * 1024 + 1];
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &input, Limits::default());
    assert!(
        matches!(outcome, Err(SandboxError::Memory)),
        "input past guest memory must trip the byte cap before write, got {outcome:?}",
    );
}

#[test]
fn nonempty_input_requires_exported_memory() {
    let wasm: Vec<u8> = wat::parse_str(
        r#"
        (module
          (func (export "run") (param i32) (result i32)
            i32.const 0))
        "#,
    )
    .expect("no-memory input module must assemble");
    let outcome: Result<Vec<u8>, SandboxError> =
        PluginHost::run(&wasm, b"input", Limits::default());
    match outcome {
        Err(SandboxError::Trap(message)) => {
            assert!(
                message.contains("exports no memory"),
                "error must name the missing memory export, got {message}",
            );
        }
        other => panic!("nonempty input without guest memory must fail, got {other:?}"),
    }
}

#[test]
fn pure_compute_module_runs_and_returns_correct_bytes() {
    let wasm: Vec<u8> = load("compute_xor.wat");
    let input: [u8; 5] = [0x00, 0x10, 0x7f, 0x80, 0xff];
    let outcome: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &input, Limits::default());
    let output: Vec<u8> = outcome.expect("import-free compute module must run cleanly");
    let expected: Vec<u8> = input.iter().map(|b| b ^ 0xff).collect();
    assert_eq!(
        output, expected,
        "sandbox must return the guest's real transform, not deny everything",
    );
}
