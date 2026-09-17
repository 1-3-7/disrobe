#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use disrobe_core::scratch::ScratchDir;
use minisign::{KeyPair, PublicKey, SecretKey, SignatureBox};

mod common;

use common::{Run, run_disrobe, write_bytes};

const REVERSE_COMPONENT: &str = r#"
(component
  (core module $guest
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 16))
    (func $alloc (export "cabi_realloc")
      (param $old_ptr i32) (param $old_len i32) (param $align i32) (param $new_len i32)
      (result i32)
      (local $ptr i32)
      (local $mask i32)
      (local.set $mask (i32.sub (local.get $align) (i32.const 1)))
      (local.set $ptr
        (i32.and
          (i32.add (global.get $bump) (local.get $mask))
          (i32.xor (local.get $mask) (i32.const -1))))
      (global.set $bump (i32.add (local.get $ptr) (local.get $new_len)))
      (local.get $ptr))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (local $out i32)
      (local $ret i32)
      (local $i i32)
      (local.set $out
        (call $alloc (i32.const 0) (i32.const 0) (i32.const 1) (local.get $len)))
      (block $done
        (loop $copy
          (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
          (i32.store8
            (i32.add (local.get $out) (local.get $i))
            (i32.load8_u
              (i32.add
                (local.get $ptr)
                (i32.sub (i32.sub (local.get $len) (i32.const 1)) (local.get $i)))))
          (local.set $i (i32.add (local.get $i) (i32.const 1)))
          (br $copy)))
      (local.set $ret
        (call $alloc (i32.const 0) (i32.const 0) (i32.const 4) (i32.const 8)))
      (i32.store (local.get $ret) (local.get $out))
      (i32.store offset=4 (local.get $ret) (local.get $len))
      (local.get $ret)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

const SPINNING_COMPONENT: &str = r#"
(component
  (core module $guest
    (memory (export "memory") 1)
    (func (export "cabi_realloc")
      (param i32 i32 i32 i32) (result i32)
      (i32.const 16))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (loop $spin (br $spin))
      (unreachable)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

const MEMGROW_COMPONENT: &str = r#"
(component
  (core module $guest
    (memory (export "memory") 1 65536)
    (func (export "cabi_realloc")
      (param i32 i32 i32 i32) (result i32)
      (i32.const 16))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (local $page i32)
      (loop $grow
        (local.set $page (memory.grow (i32.const 1)))
        (br_if $grow (i32.ne (local.get $page) (i32.const -1))))
      (unreachable)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

const IMPORTING_COMPONENT: &str = r#"
(component
  (import "host:log/logger" (instance (export "emit" (func))))
  (core module $guest
    (memory (export "memory") 1)
    (func (export "cabi_realloc")
      (param i32 i32 i32 i32) (result i32)
      (i32.const 16))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (i32.const 8)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

const NO_RUN_EXPORT_COMPONENT: &str = r#"
(component
  (core module $guest
    (memory (export "memory") 1)
    (func (export "cabi_realloc")
      (param i32 i32 i32 i32) (result i32)
      (i32.const 16))
    (func (export "other") (param $ptr i32) (param $len i32) (result i32)
      (i32.const 8)))
  (core instance $g (instantiate $guest))
  (func (export "other") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "other")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

const WRONG_TYPE_RUN_COMPONENT: &str = r#"
(component
  (core module $guest
    (memory (export "memory") 1)
    (func (export "cabi_realloc")
      (param i32 i32 i32 i32) (result i32)
      (i32.const 16))
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (i32.const 8)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" string) (result string)
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc"))
      string-encoding=utf8)))
"#;

const RUN_WITHOUT_GUEST_MEMORY_COMPONENT: &str = r#"
(component
  (core module $guest
    (func (export "run") (param $ptr i32) (param $len i32) (result i32)
      (i32.const 8)))
  (core instance $g (instantiate $guest))
  (func (export "run") (param "input" (list u8)) (result (list u8))
    (canon lift
      (core func $g "run")
      (memory $g "memory")
      (realloc (func $g "cabi_realloc")))))
"#;

fn flat(text: &str) -> String {
    text.chars()
        .filter(|c: &char| *c != '│')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

fn scratch(stem: &str) -> (ScratchDir, PathBuf) {
    let dir: ScratchDir =
        ScratchDir::create(&format!("disrobe-plugin-e2e-{stem}")).expect("scratch dir");
    let path: PathBuf = dir.path().to_path_buf();
    (dir, path)
}

fn component_bytes(source: &str) -> Vec<u8> {
    wat::parse_str(source).expect("component fixture assembles")
}

fn keypair() -> KeyPair {
    KeyPair::generate_unencrypted_keypair().expect("keypair generates")
}

fn sign(secret: &SecretKey, bytes: &[u8]) -> Vec<u8> {
    let signature: SignatureBox =
        minisign::sign(None, secret, std::io::Cursor::new(bytes), None, None)
            .expect("signing succeeds");
    signature.into_string().into_bytes()
}

fn write_trusted_key(dir: &Path, pk: &PublicKey) -> PathBuf {
    let path: PathBuf = dir.join("trusted.pub");
    let boxed: String = pk.to_box().expect("public key boxes").into_string();
    write_bytes(&path, boxed.as_bytes());
    path
}

struct Bundle {
    component_path: PathBuf,
    trusted_key_path: PathBuf,
}

fn write_bundle(
    dir: &Path,
    stem: &str,
    source: &str,
    manifest_toml: &str,
    signer: &SecretKey,
    trusted: &PublicKey,
) -> Bundle {
    let component: Vec<u8> = component_bytes(source);
    let component_path: PathBuf = dir.join(format!("{stem}.wasm"));
    write_bytes(&component_path, &component);
    let signature: Vec<u8> = sign(signer, &component);
    let mut sig_path: PathBuf = component_path.clone();
    sig_path.as_mut_os_string().push(".minisig");
    write_bytes(&sig_path, &signature);
    let manifest_path: PathBuf = component_path.with_extension("toml");
    write_bytes(&manifest_path, manifest_toml.as_bytes());
    let trusted_key_path: PathBuf = write_trusted_key(dir, trusted);
    Bundle {
        component_path,
        trusted_key_path,
    }
}

#[test]
fn run_reverses_bytes_through_the_signed_component_fixture() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("reverse");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "reverse",
        REVERSE_COMPONENT,
        "name = \"reverse-plugin\"\nversion = \"1.0.0\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let input_path: PathBuf = dir.join("input.bin");
    write_bytes(&input_path, b"disrobe");
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--input",
        input_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    let output: Vec<u8> = std::fs::read(&out_path).expect("read output");
    let expected: Vec<u8> = b"disrobe".iter().rev().copied().collect();
    assert_eq!(output, expected);
}

#[test]
fn run_json_provenance_names_the_manifest_declared_plugin_and_version() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("provenance");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "prov",
        REVERSE_COMPONENT,
        "name = \"provenance-plugin\"\nversion = \"9.9.9\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    let value: serde_json::Value =
        serde_json::from_str(run.stdout.trim()).expect("run emits one json object");
    assert_eq!(
        value
            .get("manifest_name")
            .and_then(serde_json::Value::as_str),
        Some("provenance-plugin")
    );
    assert_eq!(
        value
            .get("manifest_version")
            .and_then(serde_json::Value::as_str),
        Some("9.9.9")
    );
    assert_eq!(
        value.get("manifest_version_authenticated"),
        Some(&serde_json::Value::Bool(false))
    );
    assert!(
        value
            .get("component_blake3")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s: &str| s.len() == 64),
        "component_blake3 must be a real 32-byte hash, got {value}"
    );
    assert!(
        value
            .get("signing_key_id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s: &str| !s.is_empty()),
        "signing_key_id must be present, got {value}"
    );
}

#[test]
fn run_rejects_a_component_with_no_signature_sibling() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("unsigned");
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let component_path: PathBuf = dir.join("unsigned.wasm");
    write_bytes(&component_path, &component);
    write_bytes(
        &component_path.with_extension("toml"),
        b"name = \"unsigned\"\ncapabilities = []",
    );
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        component_path.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("signature not found"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_signature_from_an_untrusted_key() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("untrusted");
    let signer: KeyPair = keypair();
    let trusted: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "untrusted",
        REVERSE_COMPONENT,
        "name = \"untrusted\"\ncapabilities = []",
        &signer.sk,
        &trusted.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("untrusted"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_an_oversized_component() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("oversize-component");
    let pair: KeyPair = keypair();
    let component: Vec<u8> = vec![0u8; 16 * 1024 * 1024 + 1];
    let component_path: PathBuf = dir.join("big.wasm");
    write_bytes(&component_path, &component);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let mut sig_path: PathBuf = component_path.clone();
    sig_path.as_mut_os_string().push(".minisig");
    write_bytes(&sig_path, &signature);
    write_bytes(
        &component_path.with_extension("toml"),
        b"name = \"big\"\ncapabilities = []",
    );
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        component_path.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("too large"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_an_oversized_signature() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("oversize-sig");
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let component_path: PathBuf = dir.join("plugin.wasm");
    write_bytes(&component_path, &component);
    let oversized_signature: Vec<u8> = vec![b'a'; 16 * 1024 + 1];
    let mut sig_path: PathBuf = component_path.clone();
    sig_path.as_mut_os_string().push(".minisig");
    write_bytes(&sig_path, &oversized_signature);
    write_bytes(
        &component_path.with_extension("toml"),
        b"name = \"plugin\"\ncapabilities = []",
    );
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        component_path.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("too large"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_non_utf8_signature() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("non-utf8-sig");
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let component_path: PathBuf = dir.join("plugin.wasm");
    write_bytes(&component_path, &component);
    let mut sig_path: PathBuf = component_path.clone();
    sig_path.as_mut_os_string().push(".minisig");
    write_bytes(&sig_path, &[0xFFu8, 0xFE, 0x00, 0xFF]);
    write_bytes(
        &component_path.with_extension("toml"),
        b"name = \"plugin\"\ncapabilities = []",
    );
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        component_path.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("utf-8") || flat(&run.stderr).contains("utf8"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_missing_manifest() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("no-manifest");
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let component_path: PathBuf = dir.join("plugin.wasm");
    write_bytes(&component_path, &component);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let mut sig_path: PathBuf = component_path.clone();
    sig_path.as_mut_os_string().push(".minisig");
    write_bytes(&sig_path, &signature);
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        component_path.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("manifest not found"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_malformed_manifest() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("bad-manifest");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "plugin",
        REVERSE_COMPONENT,
        "this is not [ valid toml",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("invalid"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_capability_imported_but_not_granted() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("capability-denied");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "importer",
        IMPORTING_COMPONENT,
        "name = \"importer\"\ncapabilities = [\"host:other/thing\"]",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("host:log/logger"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_fuel_cap_terminates_a_runaway_guest() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("fuel-cap");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "spin",
        SPINNING_COMPONENT,
        "name = \"spin\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--fuel",
        "200000",
        "--wall-deadline-ms",
        "20000",
    ]);
    assert_ne!(run.code, 0);
    assert!(flat(&run.stderr).contains("fuel"), "stderr={}", run.stderr);
}

#[test]
fn run_wall_deadline_cap_terminates_a_runaway_guest() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("wall-cap");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "spin",
        SPINNING_COMPONENT,
        "name = \"spin\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--fuel",
        "1000000000",
        "--wall-deadline-ms",
        "50",
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("deadline") || flat(&run.stderr).contains("wall"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_memory_cap_terminates_a_runaway_guest() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("memory-cap");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "memgrow",
        MEMGROW_COMPONENT,
        "name = \"memgrow\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
        "--fuel",
        "1000000000",
        "--wall-deadline-ms",
        "20000",
        "--memory-cap-bytes",
        "4194304",
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("memory"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_component_with_no_run_export() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("no-run-export");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "norun",
        NO_RUN_EXPORT_COMPONENT,
        "name = \"norun\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("does not export a `run`"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_wrongly_typed_run_export() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("wrong-type-run");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "wrongtype",
        WRONG_TYPE_RUN_COMPONENT,
        "name = \"wrongtype\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("wrong signature"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_component_that_would_need_guest_memory_it_lacks() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("no-guest-memory");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "nomem",
        RUN_WITHOUT_GUEST_MEMORY_COMPONENT,
        "name = \"nomem\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("malformed") || flat(&run.stderr).contains("Malformed"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_directory_given_as_the_component() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("component-is-dir");
    let pair: KeyPair = keypair();
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        dir.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("found a directory"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn run_rejects_a_missing_component() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("component-missing");
    let pair: KeyPair = keypair();
    let trusted_key_path: PathBuf = write_trusted_key(&dir, &pair.pk);
    let out_path: PathBuf = dir.join("output.bin");
    let missing: PathBuf = dir.join("nope.wasm");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        missing.to_str().unwrap(),
        "--trusted-key",
        trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("component not found"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn verify_accepts_a_valid_bundle_without_running_it() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("verify-ok");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "verifyme",
        REVERSE_COMPONENT,
        "name = \"verifyme\"\nversion = \"0.1.0\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );

    let run: Run = run_disrobe(&[
        "plugin",
        "verify",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    assert!(run.stdout.contains("verifyme"), "stdout={}", run.stdout);
}

#[test]
fn list_reports_every_bundle_and_marks_one_malformed_entry() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("list");
    let pair: KeyPair = keypair();
    let _good: Bundle = write_bundle(
        &dir,
        "good",
        REVERSE_COMPONENT,
        "name = \"good-plugin\"\nversion = \"3.0.0\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let bad_component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let bad_path: PathBuf = dir.join("bad.wasm");
    write_bytes(&bad_path, &bad_component);
    write_bytes(&bad_path.with_extension("toml"), b"not [ valid toml");

    let run: Run = run_disrobe(&["plugin", "list", dir.to_str().unwrap(), "--format", "json"]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);
    let value: serde_json::Value =
        serde_json::from_str(run.stdout.trim()).expect("list emits one json object");
    let plugins: &Vec<serde_json::Value> = value
        .get("plugins")
        .and_then(serde_json::Value::as_array)
        .expect("plugins array");
    assert_eq!(plugins.len(), 2, "value={value}");
    let has_good_plugin: bool = plugins.iter().any(|p: &serde_json::Value| {
        p.get("manifest_name").and_then(serde_json::Value::as_str) == Some("good-plugin")
    });
    assert!(has_good_plugin, "value={value}");
    let has_error: bool = plugins
        .iter()
        .any(|p: &serde_json::Value| p.get("error").is_some());
    assert!(
        has_error,
        "malformed manifest entry must be reported, not fail the whole listing: {value}"
    );
}

#[test]
fn list_rejects_a_missing_directory() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("list-missing");
    let missing: PathBuf = dir.join("does-not-exist");

    let run: Run = run_disrobe(&["plugin", "list", missing.to_str().unwrap()]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("directory not found"),
        "stderr={}",
        run.stderr
    );
}

#[test]
fn list_rejects_a_file_given_as_the_directory() {
    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("list-is-file");
    let file_path: PathBuf = dir.join("not-a-dir.txt");
    write_bytes(&file_path, b"hello");

    let run: Run = run_disrobe(&["plugin", "list", file_path.to_str().unwrap()]);
    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("found a file"),
        "stderr={}",
        run.stderr
    );
}

#[cfg(unix)]
#[test]
fn run_rejects_a_component_with_no_read_permission() {
    use std::os::unix::fs::PermissionsExt;

    let (_scratch, dir): (ScratchDir, PathBuf) = scratch("no-read-perm");
    let pair: KeyPair = keypair();
    let bundle: Bundle = write_bundle(
        &dir,
        "locked",
        REVERSE_COMPONENT,
        "name = \"locked\"\ncapabilities = []",
        &pair.sk,
        &pair.pk,
    );
    let out_path: PathBuf = dir.join("output.bin");

    let mut perms: std::fs::Permissions = std::fs::metadata(&bundle.component_path)
        .expect("stat component")
        .permissions();
    perms.set_mode(0o000);
    std::fs::set_permissions(&bundle.component_path, perms).expect("chmod component");

    let run: Run = run_disrobe(&[
        "plugin",
        "run",
        bundle.component_path.to_str().unwrap(),
        "--trusted-key",
        bundle.trusted_key_path.to_str().unwrap(),
        "--out",
        out_path.to_str().unwrap(),
    ]);

    let mut restore: std::fs::Permissions = std::fs::metadata(&bundle.component_path)
        .expect("stat component")
        .permissions();
    restore.set_mode(0o644);
    std::fs::set_permissions(&bundle.component_path, restore).expect("restore perms");

    assert_ne!(run.code, 0);
    assert!(
        flat(&run.stderr).contains("cannot read"),
        "stderr={}",
        run.stderr
    );
}
