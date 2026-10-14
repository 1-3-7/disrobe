#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/forge_specs.rs"]
mod forge_specs;
#[path = "common/forge_writer.rs"]
mod forge_writer;
#[path = "common/oodle_encoder/mod.rs"]
mod oodle_encoder;
#[path = "common/oodle_fixtures.rs"]
mod oodle_fixtures;

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::forge::{
    ForgeEntryKind, forge_entry_bytes, parse_descriptor, parse_fast_load_toc, parse_forge,
};
use disrobe_binfmt::containers::forge_block::{BlockDecoder, parse_block};
use disrobe_binfmt::containers::forge_depgraph::parse_depgraph;
use disrobe_binfmt::containers::forge_flat::{parse_flat_archive, parse_subfile_index};
use disrobe_binfmt::containers::oodle::{MAX_OUTPUT_BYTES, OodleCensus, OodleError, decode};
use disrobe_binfmt::extract_to;
use forge_specs::{DEPGRAPH_FIXTURES, FORGE_FIXTURES, Xorshift64, depgraph_for, spec_for};
use forge_writer::write_forge;
use oodle_fixtures::{OODLE_FIXTURES, payload_for, stream_for};

const CAP: u64 = 64 * 1024 * 1024;

fn mutate(seed: &[u8], rng: &mut Xorshift64) -> Vec<u8> {
    let mut out: Vec<u8> = seed.to_vec();
    match rng.next_u64() % 6 {
        0 => {
            let idx: usize = rng.next_usize(out.len());
            out[idx] ^= 1u8 << rng.next_usize(8);
        }
        1 => out.truncate(rng.next_usize(out.len())),
        2 => {
            for _ in 0..=rng.next_usize(16) {
                let idx: usize = rng.next_usize(out.len());
                out[idx] = rng.next_byte();
            }
        }
        3 => {
            let idx: usize = rng.next_usize(out.len().saturating_sub(4));
            out[idx..idx + 4].copy_from_slice(&[0xFF; 4]);
        }
        4 => {
            let idx: usize = rng.next_usize(out.len().saturating_sub(8));
            out[idx..idx + 8].fill(0);
        }
        _ => {
            let idx: usize = rng.next_usize(out.len());
            for byte in &mut out[idx..] {
                *byte = rng.next_byte();
            }
        }
    }
    out
}

fn exercise(bytes: &[u8]) {
    if let Ok(archive) = parse_forge(bytes) {
        let mut decoder: BlockDecoder = BlockDecoder::new();
        for entry in &archive.entries {
            let Ok(container) = forge_entry_bytes(bytes, entry) else {
                continue;
            };
            match entry.kind {
                ForgeEntryKind::Descriptor => {
                    let _ = parse_descriptor(container);
                }
                ForgeEntryKind::FastLoadToc => {
                    let _ = parse_fast_load_toc(container);
                }
                _ => {}
            }
            if let Ok(block) = parse_block(container)
                && let Ok(meta) = decoder.decode(container, &block, "a", CAP)
            {
                let _ = parse_subfile_index(&meta);
                if let Ok(second) = parse_block(&container[block.total_len..])
                    && let Ok(payload) =
                        decoder.decode(&container[block.total_len..], &second, "b", CAP)
                {
                    let _ = parse_flat_archive(&payload, "b");
                }
            }
        }
    }
    let _ = parse_depgraph(bytes, CAP);
}

#[test]
fn mutated_forge_archives_and_depgraphs_are_typed_refusals_never_panics() {
    let mut rng: Xorshift64 = Xorshift64::new(0x464F_5247_4531_3233);
    let mut seeds: Vec<Vec<u8>> = FORGE_FIXTURES
        .iter()
        .map(|name: &&str| write_forge(&spec_for(name)))
        .collect();
    seeds.extend(
        DEPGRAPH_FIXTURES
            .iter()
            .map(|name: &&str| depgraph_for(name)),
    );
    let dir: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("forge-never-panic").expect("scratch dir");
    let mut refusals: BTreeSet<String> = BTreeSet::new();
    for (index, seed) in seeds.iter().enumerate() {
        for round in 0..300 {
            let mutated: Vec<u8> = mutate(seed, &mut rng);
            exercise(&mutated);
            if round % 25 == 0 {
                let out: PathBuf = dir.path().join(format!("{index}-{round}"));
                let kind: ContainerKind =
                    detect_container(&mutated).unwrap_or(ContainerKind::Forge);
                if matches!(kind, ContainerKind::Forge | ContainerKind::ScimitarBlock) {
                    match extract_to(kind, &mutated, &out) {
                        Ok(result) => {
                            for violation in result.integrity_violations {
                                refusals
                                    .insert(violation.split(':').next().unwrap_or("").to_owned());
                            }
                        }
                        Err(e) => {
                            refusals
                                .insert(e.to_string().split(':').next().unwrap_or("").to_owned());
                        }
                    }
                }
            }
        }
        for cut in (0..seed.len()).step_by(37) {
            exercise(&seed[..cut]);
        }
    }
    assert!(!refusals.is_empty(), "mutations must reach typed refusals");
}

fn try_decode(stream: &[u8], len: usize) -> Result<Vec<u8>, OodleError> {
    let mut census: OodleCensus = OodleCensus::default();
    decode(stream, len, &mut census)
}

#[test]
fn truncated_oodle_streams_are_refused_at_every_length() {
    for name in OODLE_FIXTURES {
        let stream: Vec<u8> = stream_for(name);
        let len: usize = payload_for(name).len();
        for cut in 0..stream.len() {
            assert!(
                try_decode(&stream[..cut], len).is_err(),
                "{name} truncated to {cut} bytes was accepted"
            );
        }
    }
}

#[test]
fn random_oodle_bytes_behind_valid_headers_never_panic() {
    let mut rng: Xorshift64 = Xorshift64::new(0x4F4F_444C_4532_3031);
    let mut attempts: usize = 0;
    let mut refused: usize = 0;
    for decoder in [6u8, 10, 12] {
        for _ in 0..3000 {
            let mut stream: Vec<u8> = vec![0x8C, decoder];
            let body: usize = 4 + rng.next_usize(600);
            stream.extend((0..body).map(|_| rng.next_byte()));
            if rng.next_u64().is_multiple_of(2) {
                let size: u32 = (stream.len() - 5) as u32 - 1;
                stream[2..5].copy_from_slice(&size.to_be_bytes()[1..]);
            }
            let len: usize = 1 + rng.next_usize(70_000);
            attempts += 1;
            if try_decode(&stream, len).is_err() {
                refused += 1;
            }
        }
    }
    for name in OODLE_FIXTURES {
        let seed: Vec<u8> = stream_for(name);
        let len: usize = payload_for(name).len();
        for _ in 0..200 {
            let mutated: Vec<u8> = mutate(&seed, &mut rng);
            let _ = try_decode(&mutated, len);
        }
    }
    assert!(attempts >= 9000, "only {attempts} random streams ran");
    assert!(
        refused * 100 >= attempts * 99,
        "only {refused} of {attempts} random streams were refused"
    );
}

#[test]
fn oversize_declarations_and_ratio_bombs_are_bounded() {
    assert_eq!(
        try_decode(&[0x8C, 0x0C], MAX_OUTPUT_BYTES + 1),
        Err(OodleError::OutputTooLarge {
            declared: MAX_OUTPUT_BYTES + 1,
            cap: MAX_OUTPUT_BYTES
        })
    );
    let memset: [u8; 6] = [0x8C, 0x0C, 0x07, 0xFF, 0xFF, 0x00];
    assert!(try_decode(&memset, MAX_OUTPUT_BYTES).is_err());
    let mut bomb: Vec<u8> = Vec::new();
    for _ in 0..8 {
        bomb.extend_from_slice(&memset);
    }
    assert_eq!(try_decode(&bomb, 8 * 0x4_0000).unwrap().len(), 8 * 0x4_0000);
    assert!(try_decode(&bomb, 9 * 0x4_0000).is_err());
    for name in OODLE_FIXTURES {
        let stream: Vec<u8> = stream_for(name);
        assert!(
            try_decode(&stream, MAX_OUTPUT_BYTES).is_err(),
            "{name} accepted an inflated declared length"
        );
    }
}
