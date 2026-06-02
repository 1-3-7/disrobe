#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use disrobe_core::Capability;
use disrobe_ir::{Envelope, RawPayload, Rung, Sidecar, compute_root_hash, decode_raw, encode_raw};

const PAYLOAD_SIZE: usize = 64 * 1024;

fn main() {
    divan::main();
}

fn sample_raw_payload() -> RawPayload {
    let mut bytes: Vec<u8> = Vec::with_capacity(PAYLOAD_SIZE);
    for i in 0..PAYLOAD_SIZE {
        bytes.push(i.to_le_bytes()[0]);
    }
    let source_hash: [u8; 32] = *blake3::hash(&bytes).as_bytes();
    RawPayload {
        source_path: "bench-fixture.wasm".to_owned(),
        source_bytes: bytes,
        source_hash,
        detected_format: Some("wasm".to_owned()),
    }
}

fn sample_sidecar() -> Sidecar {
    let mut provenance: BTreeMap<String, String> = BTreeMap::new();
    provenance.insert("source_size".to_owned(), PAYLOAD_SIZE.to_string());
    Sidecar {
        produced_by: "disrobe-bench".to_owned(),
        produced_by_version: env!("CARGO_PKG_VERSION").to_owned(),
        capabilities: vec![
            Capability::requires("wasm-raw", 1),
            Capability::produces("wasm-cfg", 1),
        ],
        provenance,
    }
}

#[divan::bench]
fn rkyv_encode_64kb(bencher: divan::Bencher) {
    let payload: RawPayload = sample_raw_payload();
    bencher.bench_local(|| {
        let bytes: Vec<u8> = encode_raw(divan::black_box(&payload)).expect("encode");
        divan::black_box(bytes);
    });
}

#[divan::bench]
fn rkyv_decode_64kb(bencher: divan::Bencher) {
    let payload: RawPayload = sample_raw_payload();
    let bytes: Vec<u8> = encode_raw(&payload).expect("encode");
    bencher.bench_local(|| {
        let decoded: RawPayload = decode_raw(divan::black_box(&bytes)).expect("decode");
        divan::black_box(decoded);
    });
}

#[divan::bench]
fn postcard_encode_sidecar(bencher: divan::Bencher) {
    let sidecar: Sidecar = sample_sidecar();
    bencher.bench_local(|| {
        let bytes: Vec<u8> = divan::black_box(&sidecar).encode().expect("encode");
        divan::black_box(bytes);
    });
}

#[divan::bench]
fn blake3_root_hash_64kb(bencher: divan::Bencher) {
    let payload: RawPayload = sample_raw_payload();
    let hot: Vec<u8> = encode_raw(&payload).expect("encode");
    let cold: Vec<u8> = sample_sidecar().encode().expect("encode");
    bencher.bench_local(|| {
        let h: [u8; 32] = compute_root_hash(divan::black_box(&hot), divan::black_box(&cold));
        divan::black_box(h);
    });
}

#[divan::bench]
fn envelope_encode_round_trip_64kb(bencher: divan::Bencher) {
    let payload: RawPayload = sample_raw_payload();
    let sidecar: Sidecar = sample_sidecar();
    bencher.bench_local(|| {
        let hot: Vec<u8> = encode_raw(divan::black_box(&payload)).expect("encode hot");
        let cold: Vec<u8> = divan::black_box(&sidecar).encode().expect("encode cold");
        let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
        let bytes: Vec<u8> = env.encode().expect("encode env");
        let decoded: Envelope = Envelope::decode(&bytes).expect("decode");
        divan::black_box(decoded);
    });
}

#[divan::bench]
fn envelope_decode_only_64kb(bencher: divan::Bencher) {
    let payload: RawPayload = sample_raw_payload();
    let sidecar: Sidecar = sample_sidecar();
    let hot: Vec<u8> = encode_raw(&payload).expect("encode hot");
    let cold: Vec<u8> = sidecar.encode().expect("encode cold");
    let env: Envelope = Envelope::new(Rung::Raw, hot, cold);
    let bytes: Vec<u8> = env.encode().expect("encode env");
    bencher.bench_local(|| {
        let decoded: Envelope = Envelope::decode(divan::black_box(&bytes)).expect("decode");
        divan::black_box(decoded);
    });
}
