#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use disrobe_core::codec::alphabets::{
    base45_encode, base58_encode, base62_encode, base91_encode, base92_encode,
};
use disrobe_core::codec::framed::{ascii85_encode, uuencode, xxencode, yenc_encode, z85_encode};
use disrobe_core::codec::web_escape::percent_encode;
use disrobe_core::codec::{Base58Variant, CascadeHit, Scheme, blind_cascade, decode};

#[derive(Debug, Clone)]
struct Fixture {
    scheme: Scheme,
    plaintext: Vec<u8>,
    encoded: Vec<u8>,
}

fn realistic_payloads() -> Vec<Vec<u8>> {
    vec![
        b"https://evil.example.com/c2?token=abcd config import process".to_vec(),
        b"powershell -enc download system kernel windows admin password".to_vec(),
        b"MZ\x90\x00\x03the quick brown fox jumps over the lazy dog 0123456789".to_vec(),
        b"PK\x03\x04nested archive content bytes here padding xyz function".to_vec(),
        b"the function class def import select for var and com www exe dll".to_vec(),
    ]
}

fn encode_for(scheme: Scheme, plaintext: &[u8]) -> Option<Vec<u8>> {
    match scheme {
        Scheme::Base58Bitcoin => {
            Some(base58_encode(plaintext, Base58Variant::Bitcoin).into_bytes())
        }
        Scheme::Base58Ripple => Some(base58_encode(plaintext, Base58Variant::Ripple).into_bytes()),
        Scheme::Base62 => Some(base62_encode(plaintext).into_bytes()),
        Scheme::Base45 => Some(base45_encode(plaintext).into_bytes()),
        Scheme::Base91 => Some(base91_encode(plaintext).into_bytes()),
        Scheme::Base92 => Some(base92_encode(plaintext).into_bytes()),
        Scheme::Ascii85 => Some(ascii85_encode(plaintext).into_bytes()),
        Scheme::Z85 => z85_encode(plaintext).ok().map(String::into_bytes),
        Scheme::UuEncode => Some(uuencode(plaintext, "payload.bin").into_bytes()),
        Scheme::XxEncode => Some(xxencode(plaintext, "payload.bin").into_bytes()),
        Scheme::YEnc => Some(yenc_encode(plaintext, "payload.bin")),
        Scheme::PercentUrl => Some(percent_encode(plaintext).into_bytes()),
        Scheme::Base122
        | Scheme::HtmlEntity
        | Scheme::Punycode
        | Scheme::Base64Standard
        | Scheme::Base64Url => None,
    }
}

fn build_fixtures() -> Vec<Fixture> {
    let mut fixtures: Vec<Fixture> = Vec::new();
    for plaintext in realistic_payloads() {
        for &scheme in Scheme::all() {
            let Some(encoded): Option<Vec<u8>> = encode_for(scheme, &plaintext) else {
                continue;
            };
            let Ok(roundtrip): Result<Vec<u8>, _> = decode(&encoded, scheme) else {
                continue;
            };
            if roundtrip != plaintext {
                continue;
            }
            fixtures.push(Fixture {
                scheme,
                plaintext: plaintext.clone(),
                encoded,
            });
        }
    }
    assert!(
        fixtures.len() >= 30,
        "expected a broad codec fixture set, got {n}",
        n = fixtures.len(),
    );
    fixtures
}

#[test]
fn raw_decode_first_application_recovers_plaintext_oracle() {
    let fixtures: Vec<Fixture> = build_fixtures();
    for f in &fixtures {
        let out: Vec<u8> = decode(&f.encoded, f.scheme).unwrap_or_else(|e| {
            panic!(
                "scheme {label} must decode its own encoding, got {e}",
                label = f.scheme.label(),
            )
        });
        assert_eq!(
            out,
            f.plaintext,
            "non-circular oracle: encode->decode must recover the known plaintext for {label}",
            label = f.scheme.label(),
        );
    }
}

#[test]
fn raw_decode_second_application_is_a_stable_fixed_point_or_rejects() {
    let fixtures: Vec<Fixture> = build_fixtures();
    let mut idempotent: usize = 0;
    let mut rejects_second: usize = 0;
    let mut over_decodes: Vec<&'static str> = Vec::new();
    for f in &fixtures {
        let first: Vec<u8> = decode(&f.encoded, f.scheme).expect("first decode");
        match decode(&first, f.scheme) {
            Err(_) => rejects_second += 1,
            Ok(second) => {
                if second == first {
                    idempotent += 1;
                } else {
                    over_decodes.push(f.scheme.label());
                }
            }
        }
    }
    assert!(
        idempotent >= 1,
        "expected at least one scheme whose decoder is a byte-identical fixed point on its own output",
    );
    assert_eq!(
        idempotent + rejects_second,
        fixtures.len(),
        "raw decode over-decoded already-recovered plaintext for schemes {over_decodes:?}; \
         a raw single-scheme decoder is NOT safe to re-apply blindly, which is why the \
         production chain gates re-decoding through the validated blind_cascade",
    );
}

fn cascade_signature(hits: &[CascadeHit]) -> Vec<(Scheme, Vec<u8>)> {
    let mut sig: Vec<(Scheme, Vec<u8>)> = hits
        .iter()
        .map(|h: &CascadeHit| (h.scheme, h.decoded.clone()))
        .collect();
    sig.sort_by(|a: &(Scheme, Vec<u8>), b: &(Scheme, Vec<u8>)| {
        a.0.label().cmp(b.0.label()).then_with(|| a.1.cmp(&b.1))
    });
    sig
}

#[test]
fn blind_cascade_is_idempotent_on_validated_recovery() {
    let fixtures: Vec<Fixture> = build_fixtures();
    let mut covered: usize = 0;
    let mut non_idempotent: Vec<(&'static str, usize)> = Vec::new();
    for f in &fixtures {
        let want_scheme: Scheme = f.scheme;
        let want_plaintext: &[u8] = f.plaintext.as_slice();
        let first_hits: Vec<CascadeHit> = blind_cascade(&f.encoded);
        let Some(recovery): Option<&CascadeHit> = first_hits.iter().find(|h: &&CascadeHit| {
            h.scheme == want_scheme && h.decoded.as_slice() == want_plaintext
        }) else {
            continue;
        };
        covered += 1;
        let recovered: &[u8] = &recovery.decoded;
        let second_hits: Vec<CascadeHit> = blind_cascade(recovered);
        let still_recovers_same: bool = second_hits.iter().any(|h: &CascadeHit| {
            h.scheme == want_scheme && h.decoded.as_slice() == want_plaintext
        });
        let advances_past_plaintext: bool = second_hits
            .iter()
            .any(|h: &CascadeHit| h.decoded.as_slice() != want_plaintext && h.decoded != recovered);
        if advances_past_plaintext && !still_recovers_same {
            non_idempotent.push((f.scheme.label(), second_hits.len()));
        }
        let third_hits: Vec<CascadeHit> = blind_cascade(recovered);
        assert_eq!(
            cascade_signature(&second_hits),
            cascade_signature(&third_hits),
            "blind_cascade must be deterministic across repeated runs on the recovered fixed point for {label}",
            label = f.scheme.label(),
        );
    }
    assert!(
        covered >= 10,
        "expected the validated cascade to recover a meaningful share of fixtures, got {covered}",
    );
    assert!(
        non_idempotent.is_empty(),
        "blind_cascade kept transforming an already-validated recovery (non-idempotent): {non_idempotent:?}",
    );
}

#[test]
fn cascade_on_plain_recovered_text_does_not_diverge_from_itself() {
    let payload: &[u8] = b"https://malware.example.com/payload powershell download system";
    let encoded: Vec<u8> = base91_encode(payload).into_bytes();
    let first: Vec<CascadeHit> = blind_cascade(&encoded);
    let recovery: &CascadeHit = first
        .iter()
        .find(|h: &&CascadeHit| h.scheme == Scheme::Base91 && h.decoded == payload)
        .expect("base91 recovery present");
    let once: Vec<CascadeHit> = blind_cascade(&recovery.decoded);
    let twice: Vec<CascadeHit> = blind_cascade(&recovery.decoded);
    assert_eq!(cascade_signature(&once), cascade_signature(&twice));
    for hit in &once {
        let nested: Vec<CascadeHit> = blind_cascade(&hit.decoded);
        let loops_back: bool = nested.iter().any(|h: &CascadeHit| h.decoded == payload);
        assert!(
            !loops_back,
            "applying the cascade to a cascade output recovered the original plaintext, \
             indicating an unstable decode loop via {label}",
            label = hit.scheme.label(),
        );
    }
}
