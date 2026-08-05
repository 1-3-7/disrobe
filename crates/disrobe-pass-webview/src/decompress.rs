use disrobe_binfmt::containers::bare_stream::{
    GzipMember, decompress_gzip_members, decompress_zstd, detect_gzip, detect_zstd,
    try_decompress_brotli_oracle,
};

use crate::model::Compression;

const PRINTABLE_GATE_PERCENT: usize = 85;
const COMPRESSED_SAMPLE_CAP: usize = 4096;
const MIN_TRIAL_LEN: usize = 4;

pub(crate) const CODEC_TRIAL_ORDER: [Compression; 3] =
    [Compression::Gzip, Compression::Zstd, Compression::Brotli];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decoded {
    Bytes {
        data: Vec<u8>,
        compression: Compression,
    },
    QuotaRefused {
        compression: Compression,
        reason: String,
    },
    Corrupt {
        compression: Compression,
        detail: String,
    },
}

pub(crate) fn decode_blob(raw: &[u8], cap: u64) -> Decoded {
    for codec in CODEC_TRIAL_ORDER {
        if let Some(outcome) = try_codec(codec, raw, cap) {
            return outcome;
        }
    }
    Decoded::Bytes {
        data: raw.to_vec(),
        compression: Compression::None,
    }
}

fn try_codec(codec: Compression, raw: &[u8], cap: u64) -> Option<Decoded> {
    match codec {
        Compression::Gzip => detect_gzip(raw).then(|| match decompress_gzip_members(raw, cap) {
            Ok(members) => Decoded::Bytes {
                data: join_members(&members),
                compression: Compression::Gzip,
            },
            Err(failure) => classify_failure(Compression::Gzip, &failure),
        }),
        Compression::Zstd => detect_zstd(raw).then(|| match decompress_zstd(raw, cap) {
            Ok(data) => Decoded::Bytes {
                data,
                compression: Compression::Zstd,
            },
            Err(failure) => classify_failure(Compression::Zstd, &failure),
        }),
        Compression::Brotli => looks_compressed(raw)
            .then(|| try_decompress_brotli_oracle(raw, cap))
            .flatten()
            .map(|data: Vec<u8>| Decoded::Bytes {
                data,
                compression: Compression::Brotli,
            }),
        Compression::None => None,
    }
}

fn join_members(members: &[GzipMember]) -> Vec<u8> {
    let total: usize = members
        .iter()
        .map(|member: &GzipMember| member_data(member).len())
        .sum();
    let mut data: Vec<u8> = Vec::with_capacity(total);
    for member in members {
        data.extend_from_slice(member_data(member));
    }
    data
}

fn classify_failure(compression: Compression, failure: &disrobe_binfmt::Error) -> Decoded {
    match failure {
        disrobe_binfmt::Error::QuotaExceeded { reason, .. } => Decoded::QuotaRefused {
            compression,
            reason: reason.clone(),
        },
        other => Decoded::Corrupt {
            compression,
            detail: other.to_string(),
        },
    }
}

const fn member_data(member: &GzipMember) -> &[u8] {
    member.data.as_slice()
}

fn looks_compressed(raw: &[u8]) -> bool {
    if raw.len() < MIN_TRIAL_LEN {
        return false;
    }
    let sample_len: usize = raw.len().min(COMPRESSED_SAMPLE_CAP);
    let printable: usize = raw[..sample_len]
        .iter()
        .filter(|&&b: &&u8| matches!(b, 0x09 | 0x0a | 0x0d | 0x20..=0x7e))
        .count();
    printable * 100 < sample_len * PRINTABLE_GATE_PERCENT
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::Write;

    use super::*;

    const AMPLE_CAP: u64 = 8 * 1024 * 1024;

    fn payload() -> Vec<u8> {
        "export function render(state){return state.items.map(i=>i.id);}"
            .repeat(24)
            .into_bytes()
    }

    fn gzip(raw: &[u8]) -> Vec<u8> {
        let mut encoder: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(raw).unwrap();
        encoder.finish().unwrap()
    }

    fn zstd(raw: &[u8]) -> Vec<u8> {
        zstd::encode_all(raw, 19).unwrap()
    }

    fn brotli(raw: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        let mut input: &[u8] = raw;
        brotli::BrotliCompress(
            &mut input,
            &mut out,
            &brotli::enc::BrotliEncoderParams::default(),
        )
        .unwrap();
        out
    }

    fn decoded(outcome: Decoded) -> (Vec<u8>, Compression) {
        match outcome {
            Decoded::Bytes { data, compression } => (data, compression),
            other => panic!("expected decoded bytes, got {other:?}"),
        }
    }

    #[test]
    fn the_codec_trial_order_is_the_declared_one() {
        assert_eq!(
            CODEC_TRIAL_ORDER,
            [Compression::Gzip, Compression::Zstd, Compression::Brotli],
            "the trial order decides which codec claims an ambiguous blob, so it is pinned"
        );
        let raw: Vec<u8> = payload();
        let order: Vec<Compression> = [gzip(&raw), zstd(&raw), brotli(&raw)]
            .iter()
            .map(|blob: &Vec<u8>| decoded(decode_blob(blob, AMPLE_CAP)).1)
            .collect();
        assert_eq!(order, CODEC_TRIAL_ORDER.to_vec());
    }

    #[test]
    fn a_gzip_wrapped_zstd_frame_is_claimed_by_the_first_codec_in_the_order() {
        let raw: Vec<u8> = payload();
        let inner: Vec<u8> = zstd(&raw);
        let blob: Vec<u8> = gzip(&inner);
        let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&blob, AMPLE_CAP));
        assert_eq!(compression, Compression::Gzip);
        assert_eq!(
            data, inner,
            "the outer codec wins, so one peel is reported and the caller sees the inner frame"
        );
    }

    #[test]
    fn every_codec_branch_round_trips_the_bytes_the_encoder_was_given() {
        let raw: Vec<u8> = payload();
        for (blob, expected) in [
            (gzip(&raw), Compression::Gzip),
            (zstd(&raw), Compression::Zstd),
            (brotli(&raw), Compression::Brotli),
        ] {
            let (data, compression): (Vec<u8>, Compression) =
                decoded(decode_blob(&blob, AMPLE_CAP));
            assert_eq!(compression, expected);
            assert_eq!(
                data, raw,
                "{expected:?} decoded to bytes the encoder was never given"
            );
        }
    }

    #[test]
    fn the_passthrough_branch_reports_no_compression() {
        let raw: Vec<u8> = payload();
        let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&raw, AMPLE_CAP));
        assert_eq!(compression, Compression::None);
        assert_eq!(data, raw);
    }

    #[test]
    fn multi_member_gzip_concatenates_every_member() {
        let first: Vec<u8> = b"<html><body>".to_vec();
        let second: Vec<u8> = b"</body></html>".to_vec();
        let mut blob: Vec<u8> = gzip(&first);
        blob.extend_from_slice(&gzip(&second));
        let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&blob, AMPLE_CAP));
        assert_eq!(compression, Compression::Gzip);
        let mut joined: Vec<u8> = first;
        joined.extend_from_slice(&second);
        assert_eq!(data, joined);
    }

    #[test]
    fn a_gzip_run_whose_second_member_is_corrupt_never_returns_the_first_member_alone() {
        let first: Vec<u8> = b"<html><body>".to_vec();
        let second: Vec<u8> = b"</body></html>".to_vec();
        let mut blob: Vec<u8> = gzip(&first);
        let mut tail: Vec<u8> = gzip(&second);
        let midpoint: usize = tail.len() / 2;
        tail[midpoint] ^= 0xFF;
        blob.extend_from_slice(&tail);
        match decode_blob(&blob, AMPLE_CAP) {
            Decoded::Corrupt { compression, .. } => assert_eq!(compression, Compression::Gzip),
            Decoded::Bytes { data, .. } => assert_ne!(
                data, first,
                "concatenating members must never hand back only the members that happened to \
                 inflate, labelled gzip"
            ),
            refusal @ Decoded::QuotaRefused { .. } => panic!("unexpected refusal {refusal:?}"),
        }
    }

    #[test]
    fn a_corrupt_member_is_reported_as_corruption_not_as_raw_bytes() {
        let raw: Vec<u8> = payload();
        for mut blob in [gzip(&raw), zstd(&raw)] {
            let expected: Compression = if detect_gzip(&blob) {
                Compression::Gzip
            } else {
                Compression::Zstd
            };
            let last: usize = blob.len() - 1;
            blob[last] ^= 0xFF;
            blob[last / 2] ^= 0xFF;
            match decode_blob(&blob, AMPLE_CAP) {
                Decoded::Corrupt { compression, .. } => assert_eq!(compression, expected),
                Decoded::Bytes { data, compression } => {
                    assert_eq!(compression, expected);
                    assert_ne!(
                        data, raw,
                        "a flipped byte must not decode back to the original payload"
                    );
                }
                refusal @ Decoded::QuotaRefused { .. } => {
                    panic!("expected corruption or altered bytes, got {refusal:?}")
                }
            }
        }
    }

    #[test]
    fn a_truncated_stream_never_returns_partial_bytes_under_a_codec_label() {
        let raw: Vec<u8> = payload();
        for blob in [gzip(&raw), zstd(&raw)] {
            let truncated: &[u8] = &blob[..blob.len() / 2];
            match decode_blob(truncated, AMPLE_CAP) {
                Decoded::Corrupt { detail, .. } => assert!(!detail.is_empty()),
                other => panic!("a truncated stream must be typed as corrupt, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_bomb_is_refused_by_the_cap_and_named_as_a_quota_outcome() {
        let bomb_source: Vec<u8> = vec![0u8; 4 * 1024 * 1024];
        for blob in [gzip(&bomb_source), zstd(&bomb_source)] {
            let cap: u64 = blob.len() as u64 * 4;
            match decode_blob(&blob, cap) {
                Decoded::QuotaRefused { reason, .. } => assert!(
                    reason.contains(&cap.to_string()),
                    "the refusal must name the cap it enforced, got {reason}"
                ),
                other => panic!("a bomb must be refused by the cap, got {other:?}"),
            }
        }
    }

    #[test]
    fn the_printable_gate_admits_binary_and_skips_text_shaped_input() {
        assert!(!looks_compressed(b"abc"));
        assert!(!looks_compressed(b""));
        assert!(!looks_compressed(b"abcd"));
        assert!(looks_compressed(&[0u8; 4]));
        assert!(
            !looks_compressed(
                "console.log(\"a mostly printable stream\");"
                    .repeat(200)
                    .as_bytes()
            ),
            "a printable payload is never trial-decoded, which is what makes the gate cheap"
        );
    }

    #[test]
    fn a_brotli_stream_with_printable_leading_bytes_is_left_raw_by_the_gate() {
        let mut blob: Vec<u8> = b"                                        ".repeat(120);
        blob.extend_from_slice(&brotli(&payload()));
        assert!(
            !looks_compressed(&blob),
            "printable leading bytes hold the gate shut, which is the recorded false-negative case"
        );
        let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&blob, AMPLE_CAP));
        assert_eq!(
            compression,
            Compression::None,
            "the gate refuses the trial decode, so the blob is reported raw rather than mislabelled"
        );
        assert_eq!(data, blob);
    }

    #[test]
    fn size_classes_at_and_around_the_trial_floor_never_panic() {
        for len in 0..=MIN_TRIAL_LEN + 1 {
            let raw: Vec<u8> = vec![0xE7u8; len];
            let outcome: Decoded = decode_blob(&raw, AMPLE_CAP);
            assert_eq!(decoded(outcome).0, raw);
        }
    }

    #[test]
    fn a_stream_landing_exactly_on_the_cap_is_admitted_and_one_byte_over_is_refused() {
        let raw: Vec<u8> = payload();
        let exact: u64 = raw.len() as u64;
        for (blob, expected) in [
            (gzip(&raw), Compression::Gzip),
            (zstd(&raw), Compression::Zstd),
        ] {
            let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&blob, exact));
            assert_eq!(compression, expected);
            assert_eq!(
                data, raw,
                "{expected:?}: an asset whose decoded size equals the cap is inside the budget and \
                 must be returned whole"
            );
            match decode_blob(&blob, exact - 1) {
                Decoded::QuotaRefused {
                    compression,
                    reason,
                } => {
                    assert_eq!(compression, expected);
                    assert!(
                        reason.contains(&(exact - 1).to_string()),
                        "the refusal must name the cap it enforced, got {reason}"
                    );
                }
                other => panic!(
                    "{expected:?}: one byte past the cap must be a quota outcome, got {other:?}"
                ),
            }
        }
    }

    #[test]
    fn high_entropy_bytes_under_no_codec_pass_through_unchanged() {
        let mut raw: Vec<u8> = Vec::with_capacity(8192);
        let mut state: u32 = 0x9E37_79B9;
        for _ in 0..8192 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            raw.push((state >> 24) as u8);
        }
        assert!(
            looks_compressed(&raw),
            "high-entropy bytes open the gate, which is the recorded false-positive case"
        );
        let (data, compression): (Vec<u8>, Compression) = decoded(decode_blob(&raw, AMPLE_CAP));
        assert_eq!(
            compression,
            Compression::None,
            "no codec claims the blob, so it must be reported raw rather than under a codec label"
        );
        assert_eq!(data, raw);
    }

    #[test]
    fn a_zero_cap_refuses_a_framed_blob_instead_of_reporting_it_raw() {
        let blob: Vec<u8> = zstd(&payload());
        match decode_blob(&blob, 0) {
            Decoded::QuotaRefused { compression, .. } => {
                assert_eq!(compression, Compression::Zstd);
            }
            other => panic!("a zero cap must refuse, got {other:?}"),
        }
    }
}
