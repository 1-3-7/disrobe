#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    unreachable_pub,
    dead_code
)]

use std::collections::BTreeSet;
use std::time::Duration;

use disrobe_plugin_host::{
    Limits, LoaderError, Manifest, PluginError, PluginHost, PublicKey, SandboxError,
};
use minisign::{KeyPair, SecretKey, SignatureBox};

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

fn manifest_granting(names: &[&str]) -> Manifest {
    let grants: BTreeSet<String> = names.iter().map(|name: &&str| (*name).to_owned()).collect();
    Manifest::new("end-to-end-plugin", grants).expect("manifest is valid")
}

#[test]
fn a_signed_component_verifies_loads_and_runs_under_the_sandbox() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");

    let input: &[u8] = b"disrobe plugin path";
    let output: Vec<u8> = host
        .load_and_run(
            &component,
            &signature,
            &pair.pk,
            &manifest,
            input,
            Limits::default(),
        )
        .expect("signed plugin runs end to end");

    let reversed: Vec<u8> = input.iter().rev().copied().collect();
    assert_eq!(
        output, reversed,
        "the guest must have read every input byte and written the transformed result back"
    );
}

#[test]
fn a_signature_over_a_different_component_is_refused_before_execution() {
    let pair: KeyPair = keypair();
    let signed_component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &signed_component);
    let substituted: Vec<u8> = component_bytes(SPINNING_COMPONENT);
    assert_ne!(signed_component, substituted);
    let manifest: Manifest = manifest_granting(&[]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");

    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &substituted,
        &signature,
        &pair.pk,
        &manifest,
        b"input",
        Limits::default(),
    );
    match outcome {
        Err(PluginError::Rejected(LoaderError::BadSignature(_))) => {}
        other => panic!("expected a refused substitution, got {other:?}"),
    }
}

#[test]
fn an_untrusted_signing_key_is_refused() {
    let signer: KeyPair = keypair();
    let trusted: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let signature: Vec<u8> = sign(&signer.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");

    let trusted_key: PublicKey = trusted.pk;
    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &component,
        &signature,
        &trusted_key,
        &manifest,
        b"input",
        Limits::default(),
    );
    assert!(
        matches!(outcome, Err(PluginError::Rejected(LoaderError::Untrusted))),
        "expected Untrusted, got {outcome:?}"
    );
}

#[test]
fn an_ungranted_import_is_denied_before_execution() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(IMPORTING_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&["host:other/thing"]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");

    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &component,
        &signature,
        &pair.pk,
        &manifest,
        b"input",
        Limits::default(),
    );
    match outcome {
        Err(PluginError::Rejected(LoaderError::CapabilityDenied { capability })) => {
            assert_eq!(capability, "host:log/logger");
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn a_granted_import_still_finds_no_ambient_host_function() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(IMPORTING_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&["host:log/logger"]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");

    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &component,
        &signature,
        &pair.pk,
        &manifest,
        b"input",
        Limits::default(),
    );
    match outcome {
        Err(PluginError::Sandbox(SandboxError::Trap(reason))) => {
            assert!(reason.starts_with("instantiate:"), "got: {reason}");
        }
        other => panic!("expected instantiation to find an empty linker, got {other:?}"),
    }
}

#[test]
fn component_code_is_fuel_metered() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(SPINNING_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");
    let limits: Limits = Limits {
        fuel_budget: 200_000,
        wall_deadline: Duration::from_secs(20),
        memory_cap_bytes: 1024 * 1024,
    };

    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &component, &signature, &pair.pk, &manifest, b"input", limits,
    );
    assert!(
        matches!(outcome, Err(PluginError::Sandbox(SandboxError::Fuel))),
        "expected the fuel budget to stop the spin, got {outcome:?}"
    );
}

#[test]
fn an_expired_wall_deadline_rejects_the_run() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = component_bytes(REVERSE_COMPONENT);
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);
    let host: PluginHost = PluginHost::new().expect("host engine builds");
    let limits: Limits = Limits {
        fuel_budget: 50_000,
        wall_deadline: Duration::ZERO,
        memory_cap_bytes: 1024 * 1024,
    };

    let outcome: Result<Vec<u8>, PluginError> = host.load_and_run(
        &component, &signature, &pair.pk, &manifest, b"input", limits,
    );
    assert!(
        matches!(outcome, Err(PluginError::Sandbox(SandboxError::Timeout))),
        "expected Timeout, got {outcome:?}"
    );
}
