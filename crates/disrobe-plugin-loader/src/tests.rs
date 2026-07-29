use std::collections::BTreeSet;

use minisign::{KeyPair, PublicKey, SecretKey, SignatureBox};
use wasmtime::Engine;

use crate::{
    LoaderError, MAX_SIGNATURE_BYTES, MAX_SIGNED_COMPONENT_BYTES, Manifest, ManifestError,
    load_signed,
};

const IMPORT_NAME: &str = "host:log/logger";

fn empty_component() -> Vec<u8> {
    wat::parse_str("(component)").expect("empty component wat compiles")
}

fn importing_component() -> Vec<u8> {
    let source: String = format!(
        r#"(component
            (import "{IMPORT_NAME}" (instance
                (export "emit" (func))
            ))
        )"#
    );
    wat::parse_str(&source).expect("importing component wat compiles")
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
    Manifest::new("test-plugin", grants).expect("manifest is valid")
}

fn load_outcome(
    component: &[u8],
    signature: &[u8],
    trusted_key: &PublicKey,
    manifest: &Manifest,
) -> Result<(), LoaderError> {
    let engine: Engine = Engine::default();
    load_signed(&engine, component, signature, trusted_key, manifest).map(|_component| ())
}

#[test]
fn the_component_actually_imports_the_capability() {
    let engine: Engine = Engine::default();
    let component: wasmtime::component::Component =
        wasmtime::component::Component::from_binary(&engine, &importing_component())
            .expect("fixture is a valid component");
    let names: Vec<String> = component
        .component_type()
        .imports(&engine)
        .map(|(name, _ty): (&str, _)| name.to_owned())
        .collect();
    assert_eq!(names, vec![IMPORT_NAME.to_owned()]);
}

#[test]
fn accepts_trusted_signature_over_valid_component() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = empty_component();
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);

    let loaded: Result<(), LoaderError> = load_outcome(&component, &signature, &pair.pk, &manifest);
    assert!(loaded.is_ok(), "expected accept, got {loaded:?}");
}

#[test]
fn accepts_when_every_import_is_granted() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = importing_component();
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[IMPORT_NAME]);

    let loaded: Result<(), LoaderError> = load_outcome(&component, &signature, &pair.pk, &manifest);
    assert!(loaded.is_ok(), "expected accept, got {loaded:?}");
}

#[test]
fn oversized_component_is_rejected_before_signature_parse() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = vec![0u8; MAX_SIGNED_COMPONENT_BYTES + 1];
    let manifest: Manifest = manifest_granting(&[]);

    let loaded: Result<(), LoaderError> =
        load_outcome(&component, b"not a signature", &pair.pk, &manifest);
    assert!(matches!(
        loaded,
        Err(LoaderError::ComponentTooLarge { len, limit })
            if len == MAX_SIGNED_COMPONENT_BYTES + 1 && limit == MAX_SIGNED_COMPONENT_BYTES
    ));
}

#[test]
fn oversized_signature_is_rejected_before_signature_parse() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = empty_component();
    let signature: Vec<u8> = vec![b'a'; MAX_SIGNATURE_BYTES + 1];
    let manifest: Manifest = manifest_granting(&[]);

    let loaded: Result<(), LoaderError> = load_outcome(&component, &signature, &pair.pk, &manifest);
    assert!(matches!(
        loaded,
        Err(LoaderError::SignatureTooLarge { len, limit })
            if len == MAX_SIGNATURE_BYTES + 1 && limit == MAX_SIGNATURE_BYTES
    ));
}

#[test]
fn flipped_signature_byte_is_bad_signature() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = empty_component();
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let tampered: Vec<u8> = flip_ed25519_signature_bit(&signature);

    let manifest: Manifest = manifest_granting(&[]);
    let loaded: Result<(), LoaderError> = load_outcome(&component, &tampered, &pair.pk, &manifest);
    assert!(
        matches!(loaded, Err(LoaderError::BadSignature(_))),
        "expected BadSignature, got {loaded:?}"
    );

    let trusted_keynum: Vec<u8> = pair.pk.keynum().to_vec();
    let parsed: SignatureBox =
        SignatureBox::from_string(std::str::from_utf8(&tampered).expect("utf8"))
            .expect("tampered signature still parses");
    assert_eq!(
        parsed.keynum(),
        trusted_keynum.as_slice(),
        "tamper must preserve the key id so the failure is BadSignature, not Untrusted"
    );
}

fn flip_ed25519_signature_bit(minisig: &[u8]) -> Vec<u8> {
    use base64::Engine as _;
    let text: &str = std::str::from_utf8(minisig).expect("signature is utf-8");
    let lines: Vec<&str> = text.lines().collect();
    let engine: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let mut payload: Vec<u8> = engine
        .decode(lines[1])
        .expect("second line is base64 sig payload");
    let ed25519_offset: usize = 2 + 8;
    payload[ed25519_offset] ^= 0x01;
    let reencoded: String = engine.encode(&payload);
    let mut rebuilt: Vec<&str> = lines.clone();
    rebuilt[1] = reencoded.as_str();
    let mut out: String = rebuilt.join("\n");
    out.push('\n');
    out.into_bytes()
}

#[test]
fn signature_from_a_different_key_is_untrusted() {
    let signer: KeyPair = keypair();
    let trusted: KeyPair = keypair();
    let component: Vec<u8> = empty_component();
    let signature: Vec<u8> = sign(&signer.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);

    let trusted_key: PublicKey = trusted.pk;
    let loaded: Result<(), LoaderError> =
        load_outcome(&component, &signature, &trusted_key, &manifest);
    assert!(
        matches!(loaded, Err(LoaderError::Untrusted)),
        "expected Untrusted, got {loaded:?}"
    );
}

#[test]
fn missing_capability_grant_is_denied() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = importing_component();
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&["host:other/thing"]);

    let loaded: Result<(), LoaderError> = load_outcome(&component, &signature, &pair.pk, &manifest);
    match loaded {
        Err(LoaderError::CapabilityDenied { capability }) => {
            assert_eq!(capability, IMPORT_NAME);
        }
        other => panic!("expected CapabilityDenied, got {other:?}"),
    }
}

#[test]
fn malformed_component_bytes_are_rejected() {
    let pair: KeyPair = keypair();
    let component: Vec<u8> = b"\0asm not really a component at all".to_vec();
    let signature: Vec<u8> = sign(&pair.sk, &component);
    let manifest: Manifest = manifest_granting(&[]);

    let loaded: Result<(), LoaderError> = load_outcome(&component, &signature, &pair.pk, &manifest);
    assert!(
        matches!(loaded, Err(LoaderError::Malformed(_))),
        "expected Malformed, got {loaded:?}"
    );
}

#[test]
fn manifest_round_trips_through_toml() {
    let source: &str = r#"
        name = "example"
        capabilities = ["wasi:io/streams", "host:log/logger"]
    "#;
    let manifest: Manifest = Manifest::from_toml(source).expect("manifest parses");
    assert_eq!(manifest.name, "example");
    assert!(manifest.grants("wasi:io/streams"));
    assert!(manifest.grants("host:log/logger"));
    assert!(!manifest.grants("host:fs/write"));
}

#[test]
fn manifest_rejects_empty_name() {
    let source: &str = r#"
        name = ""
        capabilities = []
    "#;
    let parsed: Result<Manifest, ManifestError> = Manifest::from_toml(source);
    assert!(matches!(parsed, Err(ManifestError::EmptyName)));
}

#[test]
fn manifest_rejects_control_name() {
    let source: &str = r#"
        name = "bad\nname"
        capabilities = []
    "#;
    let parsed: Result<Manifest, ManifestError> = Manifest::from_toml(source);
    assert!(matches!(parsed, Err(ManifestError::NameControl { .. })));
}

#[test]
fn manifest_rejects_oversized_source_before_parse() {
    let source: String = " ".repeat(64 * 1024 + 1);
    let parsed: Result<Manifest, ManifestError> = Manifest::from_toml(&source);
    assert!(matches!(
        parsed,
        Err(ManifestError::ManifestTooLarge {
            len: 65537,
            limit: 65536
        })
    ));
}

#[test]
fn manifest_rejects_whitespace_capability() {
    let source: &str = r#"
        name = "example"
        capabilities = [" host:log/logger"]
    "#;
    let parsed: Result<Manifest, ManifestError> = Manifest::from_toml(source);
    assert!(matches!(
        parsed,
        Err(ManifestError::CapabilityWhitespace { .. })
    ));
}

#[test]
fn manifest_rejects_too_many_capabilities() {
    let capabilities: String = (0..129)
        .map(|idx: usize| format!("\"host:test/cap{idx}\""))
        .collect::<Vec<String>>()
        .join(", ");
    let source: String = format!("name = \"example\"\ncapabilities = [{capabilities}]");
    let parsed: Result<Manifest, ManifestError> = Manifest::from_toml(&source);
    assert!(matches!(
        parsed,
        Err(ManifestError::TooManyCapabilities {
            len: 129,
            limit: 128
        })
    ));
}
