use disrobe_binfmt::containers::bare_stream::{
    GzipMember, decompress_gzip_members, decompress_zstd, detect_gzip, detect_zstd,
    try_decompress_brotli_oracle,
};

use crate::model::Compression;

const PRINTABLE_GATE_PERCENT: usize = 85;
const COMPRESSED_SAMPLE_CAP: usize = 4096;
const MIN_TRIAL_LEN: usize = 4;

pub(crate) fn decode_blob(raw: &[u8], cap: u64) -> (Vec<u8>, Compression) {
    if detect_gzip(raw)
        && let Ok(members) = decompress_gzip_members(raw, cap)
    {
        let mut out: Vec<u8> = Vec::new();
        for member in &members {
            out.extend_from_slice(member_data(member));
        }
        return (out, Compression::Gzip);
    }
    if detect_zstd(raw)
        && let Ok(out) = decompress_zstd(raw, cap)
    {
        return (out, Compression::Zstd);
    }
    if looks_compressed(raw)
        && let Some(out) = try_decompress_brotli_oracle(raw, cap)
    {
        return (out, Compression::Brotli);
    }
    (raw.to_vec(), Compression::None)
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
