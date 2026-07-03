#![allow(
    dead_code,
    unreachable_pub,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

use std::io::Write;

use flate2::Compression;
use flate2::write::ZlibEncoder;

pub fn build_chunk(tag: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(8 + data.len() + 3);
    out.extend_from_slice(tag);
    let len: u32 = u32::try_from(data.len()).expect("chunk fits in u32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    let pad: usize = (4 - (data.len() % 4)) % 4;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

pub fn build_beam(chunks: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = chunks.iter().flatten().copied().collect();
    let mut out: Vec<u8> = Vec::with_capacity(12 + body.len());
    out.extend_from_slice(b"FOR1");
    let form_len: u32 = u32::try_from(4 + body.len()).expect("form fits in u32");
    out.extend_from_slice(&form_len.to_be_bytes());
    out.extend_from_slice(b"BEAM");
    out.extend_from_slice(&body);
    out
}

pub fn build_atu8(atoms: &[&str]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let count: u32 = u32::try_from(atoms.len()).expect("atom count fits");
    data.extend_from_slice(&count.to_be_bytes());
    for a in atoms {
        let bytes: &[u8] = a.as_bytes();
        let len: u8 = u8::try_from(bytes.len()).expect("atom under 255 bytes");
        data.push(len);
        data.extend_from_slice(bytes);
    }
    data
}

pub fn build_expt(entries: &[(u32, u32, u32)]) -> Vec<u8> {
    build_triplet_table(entries)
}

pub fn build_impt(entries: &[(u32, u32, u32)]) -> Vec<u8> {
    build_triplet_table(entries)
}

pub fn build_loct(entries: &[(u32, u32, u32)]) -> Vec<u8> {
    build_triplet_table(entries)
}

fn build_triplet_table(entries: &[(u32, u32, u32)]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    let count: u32 = u32::try_from(entries.len()).expect("count fits");
    data.extend_from_slice(&count.to_be_bytes());
    for (a, b, c) in entries {
        data.extend_from_slice(&a.to_be_bytes());
        data.extend_from_slice(&b.to_be_bytes());
        data.extend_from_slice(&c.to_be_bytes());
    }
    data
}

pub fn encode_compact_small(tag: u8, value: u32) -> Vec<u8> {
    if value < 16 {
        return vec![(tag) | ((value as u8) << 4)];
    }
    if value < 0x800 {
        let high: u8 = ((value >> 8) & 0x07) as u8;
        let low: u8 = (value & 0xff) as u8;
        return vec![tag | 0b1000 | (high << 5), low];
    }
    let bytes: [u8; 4] = value.to_be_bytes();
    let trimmed: &[u8] = strip_leading_zero(&bytes);
    let nbytes: usize = trimmed.len();
    let mut out: Vec<u8> = Vec::with_capacity(1 + nbytes);
    let high_nibble: u8 = u8::try_from(nbytes - 2).expect("size fits") << 5;
    out.push(tag | 0b1_1000 | high_nibble);
    out.extend_from_slice(trimmed);
    out
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    let mut start: usize = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    if start == 0 { bytes } else { &bytes[start..] }
}

pub fn build_code_chunk(num_labels: u32, num_functions: u32, code: &[u8]) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::with_capacity(24 + code.len());
    data.extend_from_slice(&16u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&181u32.to_be_bytes());
    data.extend_from_slice(&num_labels.to_be_bytes());
    data.extend_from_slice(&num_functions.to_be_bytes());
    data.extend_from_slice(code);
    data
}

pub fn etf_atom(name: &str) -> Vec<u8> {
    let bytes: &[u8] = name.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(2 + bytes.len());
    out.push(119);
    out.push(u8::try_from(bytes.len()).expect("atom under 256"));
    out.extend_from_slice(bytes);
    out
}

pub fn etf_small_int(v: u8) -> Vec<u8> {
    vec![97, v]
}

pub fn etf_int(v: i32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(5);
    out.push(98);
    out.extend_from_slice(&v.to_be_bytes());
    out
}

pub fn etf_nil() -> Vec<u8> {
    vec![106]
}

pub fn etf_binary(bytes: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(5 + bytes.len());
    out.push(109);
    let len: u32 = u32::try_from(bytes.len()).expect("binary fits");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

pub fn etf_small_tuple(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(2 + items.iter().map(Vec::len).sum::<usize>());
    out.push(104);
    out.push(u8::try_from(items.len()).expect("tuple arity under 256"));
    for it in items {
        out.extend_from_slice(it);
    }
    out
}

pub fn etf_list(elements: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.push(108);
    let len: u32 = u32::try_from(elements.len()).expect("list len fits");
    out.extend_from_slice(&len.to_be_bytes());
    for e in elements {
        out.extend_from_slice(e);
    }
    out.extend_from_slice(tail);
    out
}

pub fn etf_map(pairs: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.push(116);
    let arity: u32 = u32::try_from(pairs.len()).expect("map arity fits");
    out.extend_from_slice(&arity.to_be_bytes());
    for (k, v) in pairs {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    out
}

pub fn wrap_etf(payload: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(1 + payload.len());
    out.push(131);
    out.extend_from_slice(payload);
    out
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib write");
    encoder.finish().expect("zlib finish")
}
