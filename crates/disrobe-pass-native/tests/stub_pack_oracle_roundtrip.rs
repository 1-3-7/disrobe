#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation
)]

use disrobe_pass_native::packers::emulated_unpack::{
    EmulatedUnpack, EmulationConfig, emulate_unpack_stub,
};
use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::packers::stub_pack_oracle::{
    PackedImage, SectionSpec, StubKind, build_packed,
};

fn sample_text() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    let line: &[u8] =
        b"the quick brown fox jumps over the lazy dog; pack me and recover me byte-exact. ";
    while body.len() < 2048 {
        body.extend_from_slice(line);
    }
    body.truncate(2048);
    body
}

fn run(packed: &PackedImage, stub_name: &[u8]) -> EmulatedUnpack {
    let img: PeImage = parse_pe_image(&packed.bytes).expect("packed pe parses");
    let cfg: EmulationConfig<'_> = EmulationConfig {
        stub_section_names: &[stub_name],
        content_exclude: &[],
        step_cap: 50_000_000,
    };
    emulate_unpack_stub(
        &packed.bytes,
        &img,
        packed.stub_rva,
        Some(&packed.original),
        &cfg,
    )
    .expect("emulation succeeds")
}

#[test]
fn lz_decompress_stub_recovers_text_byte_exact() {
    let body: Vec<u8> = sample_text();
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: body.clone(),
    }];
    let packed: PackedImage = build_packed(&secs, 0x1000, b".nPack", StubKind::LzDecompress);
    assert!(
        packed.bytes.len() < 0x1000 + body.len(),
        "packed image must be smaller than a flat copy (compression happened)"
    );
    let out: EmulatedUnpack = run(&packed, b".nPack");
    println!(
        "LZ: oep={:?} mutated={} content={:?} whole={:?} steps={}",
        out.oep_rva,
        out.content_bytes_mutated_by_stub,
        out.content_recovery_pct,
        out.whole_image_recovery_pct,
        out.steps_executed
    );
    assert!(
        out.reached_oep(),
        "stub must reach the OEP after decompressing"
    );
    assert!(
        (out.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
        "LZ decompressor stub must recover .text byte-exact; got {:?}",
        out.content_recovery_pct
    );
    let recovered_text: &[u8] = &out.recovered_memory_image[0x1000..0x1000 + body.len()];
    assert_eq!(
        recovered_text,
        &body[..],
        "decompressed bytes must match original"
    );
}

#[test]
fn stream_decrypt_stub_recovers_text_byte_exact() {
    let body: Vec<u8> = sample_text();
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: body.clone(),
    }];
    let packed: PackedImage = build_packed(
        &secs,
        0x1000,
        b".aspr",
        StubKind::StreamDecrypt {
            key0: 0x5A,
            key_step: 0x13,
        },
    );
    let out: EmulatedUnpack = run(&packed, b".aspr");
    println!(
        "DECRYPT: oep={:?} mutated={} content={:?} steps={}",
        out.oep_rva,
        out.content_bytes_mutated_by_stub,
        out.content_recovery_pct,
        out.steps_executed
    );
    assert!(out.reached_oep(), "decrypt stub must reach the OEP");
    assert!(
        (out.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
        "stream-decrypt stub must recover .text byte-exact; got {:?}",
        out.content_recovery_pct
    );
    let recovered_text: &[u8] = &out.recovered_memory_image[0x1000..0x1000 + body.len()];
    assert_eq!(recovered_text, &body[..]);
}

#[test]
fn polymorphic_decrypt_stub_recovers_text_byte_exact_across_seeds() {
    let body: Vec<u8> = sample_text();
    for seed in 0u8..4 {
        let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
            name: b".text",
            rva: 0x1000,
            body: body.clone(),
        }];
        let packed: PackedImage = build_packed(
            &secs,
            0x1000,
            b".aspr",
            StubKind::StreamDecryptPoly {
                key0: 0x5Au8.wrapping_add(seed.wrapping_mul(7)),
                key_step: 0x13u8.wrapping_add(seed.wrapping_mul(11)),
                seed,
            },
        );
        let out: EmulatedUnpack = run(&packed, b".aspr");
        println!(
            "POLY seed={seed}: oep={:?} mutated={} content={:?} steps={}",
            out.oep_rva,
            out.content_bytes_mutated_by_stub,
            out.content_recovery_pct,
            out.steps_executed
        );
        assert!(
            out.reached_oep(),
            "seed {seed}: polymorphic stub must reach the OEP via push/ret",
        );
        assert!(
            (out.content_recovery_pct.unwrap_or(0.0) - 100.0).abs() < f64::EPSILON,
            "seed {seed}: polymorphic decrypt stub must recover .text byte-exact; got {:?}",
            out.content_recovery_pct,
        );
        let recovered_text: &[u8] = &out.recovered_memory_image[0x1000..0x1000 + body.len()];
        assert_eq!(
            recovered_text,
            &body[..],
            "seed {seed}: recovered bytes must match original",
        );
    }
}

#[test]
fn packed_image_does_not_contain_plaintext_before_emulation() {
    let secs: Vec<SectionSpec<'_>> = vec![SectionSpec {
        name: b".text",
        rva: 0x1000,
        body: sample_text(),
    }];
    let packed: PackedImage = build_packed(
        &secs,
        0x1000,
        b".aspr",
        StubKind::StreamDecrypt {
            key0: 0x5A,
            key_step: 0x13,
        },
    );
    let needle: &[u8] = b"the quick brown fox jumps over the lazy dog";
    let present: bool = packed
        .bytes
        .windows(needle.len())
        .any(|w: &[u8]| w == needle);
    assert!(
        !present,
        "encrypted packed image must NOT contain the plaintext; recovery must come from emulation, not a copy",
    );
}
