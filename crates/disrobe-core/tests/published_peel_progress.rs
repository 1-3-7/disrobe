#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_core::codec::{
    CascadeHit, CascadeRecovery, CustomB64Match, Scheme, ValidationReason, blind_cascade,
    cascade_or_wall, decode, try_known_custom_b64,
};

const CHAIN_DOC: &str = "docs/src/chain.md";
const PUBLISHED_NO_ADVANCE: &str = "so a decode never advances on garbage";
const PUBLISHED_STRUCTURAL_CHECK: &str = "A structural check gates every step (compression magic, a loadable marshal object, a valid \
     parse, a validated crib)";
const PUBLISHED_CASCADE_RULE: &str =
    "A blind cascade keeps only decodes a structural validator accepts";

#[derive(Debug, Clone, Copy)]
struct GarbageInput {
    name: &'static str,
    encoded: &'static str,
    why_it_is_garbage: &'static str,
}

const GARBAGE: [GarbageInput; 6] = [
    GarbageInput {
        name: "random-bytes-base64",
        encoded: "j1Mw7ss7TE0Br5B+2SkTiuWrjbxT5ZVDHZBnYPcje25JDdOxVGVdbb34vVvz/CzXTgyyz+gl7/BkiPg3p/jw9vCXUVnUmJrS93ca7lSx86dbyPXLh4xO0NAkpVNccGFI",
        why_it_is_garbage: "a well-formed base64 body whose plaintext is 96 bytes of noise",
    },
    GarbageInput {
        name: "wordless-printable-base64",
        encoded: "cXF6eiB2dmJiIGpqa2sgbW1wcCBsbG5uIGhoZ2cgdHRyciB5eXV1IHh4d3cgcHBxcSB6em1t",
        why_it_is_garbage: "decodes to fully printable ASCII carrying no vocabulary the validator recognizes, so \
             only the word requirement separates it from recovered text",
    },
    GarbageInput {
        name: "percent-escaped-random",
        encoded: "%8FS0%EE%CB%3BLM%01%AF%90~%D9%29%13%8A%E5%AB%8D%BCS%E5%95C%1D%90g%60%F7%23%7BnI%0D%D3%B1Te%5Dm%BD%F8%BD%5B%F3%FC%2C%D7",
        why_it_is_garbage: "a valid percent-escaped body over the same noise",
    },
    GarbageInput {
        name: "near-miss-container-magic",
        encoded: "TViRAI9TMO7LO0xNAa+QftkpE4rlq428U+WVQx2QZ2D3I3tuSQ3TsVRlXW29+L1b",
        why_it_is_garbage: "decodes to bytes one character away from the DOS header, so a magic list widened by a \
             byte would start accepting it",
    },
    GarbageInput {
        name: "truncated-marshal-header",
        encoded: "yw0NCo9TMO7LO0xN",
        why_it_is_garbage: "decodes to a pyc-shaped prefix too short to be a loadable code object",
    },
    GarbageInput {
        name: "raw-base58-token",
        encoded: "3vQB7B6MrGQZaxCuFg4oh",
        why_it_is_garbage: "a bare alphanumeric token several alphabets will decode to noise",
    },
];

#[derive(Debug, Clone, Copy)]
struct RealLayer {
    name: &'static str,
    encoded: &'static str,
    scheme: Scheme,
    reason: ValidationReason,
    plaintext_head: &'static [u8],
}

const REAL_LAYERS: [RealLayer; 3] = [
    RealLayer {
        name: "base64-wrapped-pe-stub",
        encoded: "TVqQAAMAAAAEAAAA//8AALgAAACPUzDuyztMTQGvkH7ZKROK5auNvFPllUM=",
        scheme: Scheme::Base64Standard,
        reason: ValidationReason::NestedMagic,
        plaintext_head: b"MZ\x90\x00",
    },
    RealLayer {
        name: "base64-wrapped-marshal-header",
        encoded: "yw0NCgAAAACcjypnFAIAAI9TMO7LO0xNAa+QftkpE4o=",
        scheme: Scheme::Base64Standard,
        reason: ValidationReason::PyMarshal,
        plaintext_head: b"\xcb\x0d\x0d\x0a",
    },
    RealLayer {
        name: "base64-wrapped-python-source",
        encoded: "aW1wb3J0IG9zCmNvbmZpZyA9ICd0aGUgdG9rZW4nCmZvciBwcm9jZXNzIGluIHN5c3RlbS53aW5kb3dzOiBwYXNzCg==",
        scheme: Scheme::Base64Standard,
        reason: ValidationReason::PrintableText,
        plaintext_head: b"import os",
    },
];

const CRIB_LAYER: &str = "HJeE++A++++2++++zzw++9U+++0DIn1imnhAHE4jY5vN8FC8tOiBj3DZZIA";
const CRIB_ALPHABET: &str = "darkgate-v1";
const CRIB_NAME: &str = "pe-mz";
const CRIB_PLAINTEXT_HEAD: &[u8] = b"MZ\x90\x00\x03\x00\x00\x00";

const DOCUMENTED_REASONS: [ValidationReason; 3] = [
    ValidationReason::NestedMagic,
    ValidationReason::PyMarshal,
    ValidationReason::PrintableText,
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the crate sits two levels below the repository root")
        .to_path_buf()
}

fn published_chain_doc() -> String {
    let path: PathBuf = repo_root().join(CHAIN_DOC);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{} is the page this gate holds; a run that cannot read it has compared nothing and \
             must fail rather than report a pass: {error}",
            path.display()
        )
    })
}

const fn reason_label(reason: ValidationReason) -> &'static str {
    match reason {
        ValidationReason::NestedMagic => "nested-magic",
        ValidationReason::PyMarshal => "py-marshal",
        ValidationReason::PrintableText => "printable-text",
    }
}

fn schemes_that_decode(input: &[u8]) -> BTreeSet<&'static str> {
    let mut out: BTreeSet<&'static str> = BTreeSet::new();
    for &scheme in Scheme::all() {
        let Ok(decoded): Result<Vec<u8>, _> = decode(input, scheme) else {
            continue;
        };
        if !decoded.is_empty() && decoded != input {
            out.insert(scheme.label());
        }
    }
    out
}

#[test]
fn garbage_never_advances_past_the_structural_check() {
    for item in GARBAGE {
        let hits: Vec<CascadeHit> = blind_cascade(item.encoded.as_bytes());
        let described: Vec<String> = hits
            .iter()
            .map(|hit: &CascadeHit| {
                format!(
                    "{} accepted as {} -> {:?}",
                    hit.scheme.label(),
                    reason_label(hit.reason),
                    String::from_utf8_lossy(&hit.decoded[..hit.decoded.len().min(48)])
                )
            })
            .collect();
        assert!(
            hits.is_empty(),
            "{} is {}, and the cascade advanced on it: {described:?}",
            item.name,
            item.why_it_is_garbage
        );
        let recovery: CascadeRecovery = cascade_or_wall(item.encoded.as_bytes());
        assert!(
            !matches!(recovery, CascadeRecovery::Decoded(_)),
            "{} must not reach a caller as a decoded layer, got {recovery:?}",
            item.name
        );
    }
}

#[test]
fn the_structural_check_is_the_only_thing_stopping_the_garbage() {
    for item in GARBAGE {
        let decoders: BTreeSet<&'static str> = schemes_that_decode(item.encoded.as_bytes());
        assert!(
            !decoders.is_empty(),
            "{} never reaches the structural check, so the refusal above proves nothing about the \
             check; replace it with an input at least one scheme decodes",
            item.name
        );
    }
}

#[test]
fn real_layers_still_advance_and_exercise_every_documented_check() {
    let mut reasons_seen: BTreeSet<&'static str> = BTreeSet::new();
    for layer in REAL_LAYERS {
        let hits: Vec<CascadeHit> = blind_cascade(layer.encoded.as_bytes());
        let matched: &CascadeHit = hits
            .iter()
            .find(|hit: &&CascadeHit| hit.scheme == layer.scheme && hit.reason == layer.reason)
            .unwrap_or_else(|| {
                panic!(
                    "{} must be accepted by {} on the {} check, got {:?}",
                    layer.name,
                    layer.scheme.label(),
                    reason_label(layer.reason),
                    hits.iter()
                        .map(|hit: &CascadeHit| (hit.scheme.label(), reason_label(hit.reason)))
                        .collect::<Vec<(&str, &str)>>()
                )
            });
        assert!(
            matched.decoded.starts_with(layer.plaintext_head),
            "{} decoded to {:?}, which does not start with the payload it wraps",
            layer.name,
            String::from_utf8_lossy(&matched.decoded[..matched.decoded.len().min(32)])
        );
        reasons_seen.insert(reason_label(layer.reason));
    }
    let documented: BTreeSet<&'static str> = DOCUMENTED_REASONS
        .iter()
        .map(|&reason: &ValidationReason| reason_label(reason))
        .collect();
    assert_eq!(
        reasons_seen, documented,
        "every structural check the page describes must be exercised by a layer this gate carries"
    );
}

#[test]
fn the_validated_crib_recovers_a_custom_alphabet_layer_and_refuses_garbage() {
    let matches: Vec<CustomB64Match> = try_known_custom_b64(CRIB_LAYER.as_bytes());
    let found: &CustomB64Match = matches
        .iter()
        .find(|hit: &&CustomB64Match| hit.alphabet_label == CRIB_ALPHABET)
        .unwrap_or_else(|| {
            panic!(
                "the {CRIB_ALPHABET} alphabet must recover the wrapped image, got {:?}",
                matches
                    .iter()
                    .map(|hit: &CustomB64Match| (hit.alphabet_label, hit.crib_name))
                    .collect::<Vec<(&str, &str)>>()
            )
        });
    assert_eq!(
        found.crib_name, CRIB_NAME,
        "the recovered layer must be validated by the crib the payload actually carries"
    );
    assert!(
        found.decoded.starts_with(CRIB_PLAINTEXT_HEAD),
        "the crib fired without the payload behind it: {:?}",
        String::from_utf8_lossy(&found.decoded[..found.decoded.len().min(32)])
    );
    for item in GARBAGE {
        let matches: Vec<CustomB64Match> = try_known_custom_b64(item.encoded.as_bytes());
        assert!(
            matches.is_empty(),
            "{} is {}, and a custom alphabet claimed it: {:?}",
            item.name,
            item.why_it_is_garbage,
            matches
                .iter()
                .map(|hit: &CustomB64Match| (hit.alphabet_label, hit.crib_name))
                .collect::<Vec<(&str, &str)>>()
        );
    }
}

#[test]
fn the_published_page_states_the_property_this_gate_holds() {
    let doc: String = published_chain_doc();
    for sentence in [
        PUBLISHED_NO_ADVANCE,
        PUBLISHED_STRUCTURAL_CHECK,
        PUBLISHED_CASCADE_RULE,
    ] {
        assert!(
            doc.contains(sentence),
            "{CHAIN_DOC} no longer states {sentence:?}, so this gate and the page have parted ways"
        );
    }
}
