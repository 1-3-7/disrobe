use std::io::Read;

use disrobe_py_marshal::{Object, PyVersion, load, pyversion_from_magic};
use flate2::read::ZlibDecoder;
use serde::{Deserialize, Serialize};

use crate::debug::{dbg_kv, dbg_line, dbg_section};

const MAX_RECOVERED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CANDIDATE_CONSTS: usize = 4096;
const MAX_CANDIDATE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DECOMPRESS_ATTEMPTS: usize = 1024;
const MAX_CODE_WALK_DEPTH: usize = 64;

#[derive(Debug, Clone, Copy)]
struct ZipperLimits {
    candidate_consts: usize,
    candidate_bytes: u64,
    decode_attempts: usize,
    recovered_bytes: u64,
}

impl ZipperLimits {
    #[must_use]
    const fn default() -> Self {
        Self {
            candidate_consts: MAX_CANDIDATE_CONSTS,
            candidate_bytes: MAX_CANDIDATE_BYTES,
            decode_attempts: MAX_DECOMPRESS_ATTEMPTS,
            recovered_bytes: MAX_RECOVERED_BYTES,
        }
    }
}

#[derive(Debug)]
struct CandidateBudget {
    remaining_consts: usize,
    remaining_bytes: u64,
    exhausted: bool,
}

impl CandidateBudget {
    #[must_use]
    const fn new(limits: ZipperLimits) -> Self {
        Self {
            remaining_consts: limits.candidate_consts,
            remaining_bytes: limits.candidate_bytes,
            exhausted: false,
        }
    }

    fn admit(&mut self, len: usize) -> bool {
        if self.remaining_consts == 0 {
            self.exhausted = true;
            return false;
        }
        let len_result: Result<u64, std::num::TryFromIntError> = u64::try_from(len);
        let len_u64: u64 = if let Ok(value) = len_result {
            value
        } else {
            self.exhausted = true;
            return false;
        };
        if len_u64 > self.remaining_bytes {
            self.exhausted = true;
            return false;
        }
        self.remaining_consts -= 1;
        self.remaining_bytes -= len_u64;
        true
    }
}

#[derive(Debug, Clone, Copy)]
struct DecodeBudget {
    remaining: usize,
}

impl DecodeBudget {
    #[must_use]
    const fn new(limits: ZipperLimits) -> Self {
        Self {
            remaining: limits.decode_attempts,
        }
    }

    const fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }

    #[must_use]
    const fn exhausted(self) -> bool {
        self.remaining == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ZipperCompression {
    Zlib,
    Bz2,
    LzmaXz,
    LzmaAlone,
    Brotli,
}

impl ZipperCompression {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Bz2 => "bz2",
            Self::LzmaXz => "lzma-xz",
            Self::LzmaAlone => "lzma-alone",
            Self::Brotli => "brotli",
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnzippedPyc {
    pub pyc_bytes: Vec<u8>,
    pub compression: ZipperCompression,
    pub py_version: PyVersion,
    pub wrapper_const_len: usize,
    pub recovered_body_len: usize,
}

#[must_use]
pub fn looks_like_pyc(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    pyversion_from_magic(magic).is_some()
}

pub fn unzip_pyc(pyc_bytes: &[u8]) -> Option<UnzippedPyc> {
    unzip_pyc_with_limits(pyc_bytes, ZipperLimits::default())
}

fn unzip_pyc_with_limits(pyc_bytes: &[u8], limits: ZipperLimits) -> Option<UnzippedPyc> {
    dbg_section("pyc_zipper.unzip");
    if pyc_bytes.len() < 4 {
        return None;
    }
    let magic: u32 = u32::from_le_bytes([pyc_bytes[0], pyc_bytes[1], pyc_bytes[2], pyc_bytes[3]]);
    let py_version: PyVersion = pyversion_from_magic(magic)?;
    let header_len: usize = py_version.pyc_header_len();
    if pyc_bytes.len() <= header_len {
        return None;
    }
    let header: &[u8] = &pyc_bytes[..header_len];
    let body: &[u8] = &pyc_bytes[header_len..];
    let top: Object = load(body, py_version).ok()?;

    let mut candidates: Vec<&[u8]> = Vec::new();
    let mut candidate_budget: CandidateBudget = CandidateBudget::new(limits);
    collect_byte_consts(&top, 0, &mut candidate_budget, &mut candidates);
    if candidates.is_empty() {
        dbg_line(|| "no byte constants in wrapper: not a pyc-zipper payload".to_owned());
        return None;
    }
    dbg_kv("candidate_consts", || candidates.len().to_string());

    let mut decode_budget: DecodeBudget = DecodeBudget::new(limits);
    for blob in &candidates {
        let Some((decompressed, compression)): Option<(Vec<u8>, ZipperCompression)> =
            try_decompress_any(blob, &mut decode_budget, limits.recovered_bytes)
        else {
            if decode_budget.exhausted() {
                break;
            }
            continue;
        };
        if load(&decompressed, py_version).is_err() {
            if decode_budget.exhausted() {
                break;
            }
            continue;
        }
        let mut recovered: Vec<u8> =
            Vec::with_capacity(recovered_pyc_capacity(header.len(), decompressed.len()));
        recovered.extend_from_slice(header);
        recovered.extend_from_slice(&decompressed);
        dbg_kv("compression", || compression.label().to_owned());
        dbg_kv("recovered_len", || recovered.len().to_string());
        return Some(UnzippedPyc {
            pyc_bytes: recovered,
            compression,
            py_version,
            wrapper_const_len: blob.len(),
            recovered_body_len: decompressed.len(),
        });
    }
    dbg_line(|| {
        "byte constants present but none decompress to a valid marshal code object".to_owned()
    });
    None
}

const fn recovered_pyc_capacity(header_len: usize, body_len: usize) -> usize {
    header_len.saturating_add(body_len)
}

fn collect_byte_consts<'a>(
    obj: &'a Object,
    depth: usize,
    budget: &mut CandidateBudget,
    out: &mut Vec<&'a [u8]>,
) {
    if depth > MAX_CODE_WALK_DEPTH || budget.exhausted {
        return;
    }
    match obj {
        Object::Bytes(b) if !b.is_empty() && budget.admit(b.len()) => {
            out.push(b.as_slice());
        }
        Object::Tuple(items) | Object::List(items) | Object::FrozenSet(items) => {
            for item in items {
                if budget.exhausted {
                    return;
                }
                collect_byte_consts(item, depth + 1, budget, out);
            }
        }
        Object::Code(code) => {
            for c in &code.consts {
                if budget.exhausted {
                    return;
                }
                collect_byte_consts(c, depth + 1, budget, out);
            }
        }
        _ => {}
    }
}

fn try_decompress_any(
    blob: &[u8],
    budget: &mut DecodeBudget,
    recovered_limit: u64,
) -> Option<(Vec<u8>, ZipperCompression)> {
    if let Some(out) = inflate_zlib(blob, budget, recovered_limit) {
        return Some((out, ZipperCompression::Zlib));
    }
    if starts_with(blob, b"BZh")
        && let Some(out) = inflate_bz2(blob, budget, recovered_limit)
    {
        return Some((out, ZipperCompression::Bz2));
    }
    if starts_with(blob, &[0xFD, b'7', b'z', b'X', b'Z', 0x00])
        && let Some(out) = inflate_xz(blob, budget, recovered_limit)
    {
        return Some((out, ZipperCompression::LzmaXz));
    }
    if let Some(out) = inflate_lzma_alone(blob, budget, recovered_limit) {
        return Some((out, ZipperCompression::LzmaAlone));
    }
    if let Some(out) = inflate_brotli(blob, budget, recovered_limit) {
        return Some((out, ZipperCompression::Brotli));
    }
    None
}

fn starts_with(blob: &[u8], prefix: &[u8]) -> bool {
    blob.len() >= prefix.len() && &blob[..prefix.len()] == prefix
}

fn inflate_zlib(blob: &[u8], budget: &mut DecodeBudget, recovered_limit: u64) -> Option<Vec<u8>> {
    if blob.len() < 2 || blob[0] != 0x78 {
        return None;
    }
    if !budget.take() {
        return None;
    }
    read_capped(ZlibDecoder::new(blob), recovered_limit)
}

fn inflate_bz2(blob: &[u8], budget: &mut DecodeBudget, recovered_limit: u64) -> Option<Vec<u8>> {
    if !budget.take() {
        return None;
    }
    read_capped(bzip2_rs::DecoderReader::new(blob), recovered_limit)
}

fn inflate_xz(blob: &[u8], budget: &mut DecodeBudget, recovered_limit: u64) -> Option<Vec<u8>> {
    if !budget.take() {
        return None;
    }
    read_capped(liblzma::read::XzDecoder::new(blob), recovered_limit)
}

fn inflate_lzma_alone(
    blob: &[u8],
    budget: &mut DecodeBudget,
    recovered_limit: u64,
) -> Option<Vec<u8>> {
    if blob.len() < 13 || blob[0] > 0xE0 {
        return None;
    }
    if !budget.take() {
        return None;
    }
    let stream: liblzma::stream::Stream =
        liblzma::stream::Stream::new_lzma_decoder(u64::MAX).ok()?;
    read_capped(
        liblzma::read::XzDecoder::new_stream(blob, stream),
        recovered_limit,
    )
}

fn inflate_brotli(blob: &[u8], budget: &mut DecodeBudget, recovered_limit: u64) -> Option<Vec<u8>> {
    if !budget.take() {
        return None;
    }
    let mut reader: brotli::Decompressor<&[u8]> = brotli::Decompressor::new(blob, 4096);
    read_capped(&mut reader, recovered_limit)
}

fn read_capped<R: Read>(reader: R, recovered_limit: u64) -> Option<Vec<u8>> {
    let mut limited: std::io::Take<R> = reader.take(recovered_limit.saturating_add(1));
    let mut out: Vec<u8> = Vec::new();
    limited.read_to_end(&mut out).ok()?;
    let out_len: u64 = u64::try_from(out.len()).ok()?;
    if out.is_empty() || out_len > recovered_limit {
        return None;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write as _;
    use std::path::PathBuf;

    use super::*;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("freezers")
            .join("pyc_zipper")
    }

    fn read_fixture(name: &str) -> Option<Vec<u8>> {
        std::fs::read(fixture_dir().join(name)).ok()
    }

    fn assert_recovers(packed: &str) {
        let original: Vec<u8> = read_fixture("original.pyc.bin")
            .expect("pyc_zipper original.pyc.bin fixture must be committed");
        let wrapped: Vec<u8> =
            read_fixture(packed).unwrap_or_else(|| panic!("pyc_zipper fixture {packed} missing"));
        let recovered: UnzippedPyc =
            unzip_pyc(&wrapped).expect("pyc-zipper wrapper must be recovered");
        assert_eq!(
            recovered.pyc_bytes, original,
            "recovered .pyc bytes must equal the original pre-zip .pyc for {packed}",
        );
        let parsed: Object = load(
            &recovered.pyc_bytes[recovered.py_version.pyc_header_len()..],
            recovered.py_version,
        )
        .expect("recovered body must marshal-parse cleanly");
        assert!(
            matches!(parsed, Object::Code(_)),
            "recovered .pyc body must be a code object",
        );
    }

    #[test]
    fn recovers_zlib_wrapper_to_original_bytes() {
        assert_recovers("packed_zlib.pyc.bin");
    }

    #[test]
    fn recovers_bz2_wrapper_to_original_bytes() {
        assert_recovers("packed_bz2.pyc.bin");
    }

    #[test]
    fn recovers_lzma_xz_wrapper_to_original_bytes() {
        assert_recovers("packed_lzma_xz.pyc.bin");
    }

    #[test]
    fn recovers_lzma_alone_wrapper_to_original_bytes() {
        assert_recovers("packed_lzma_alone.pyc.bin");
    }

    #[test]
    fn compression_method_is_reported_per_fixture() {
        let cases: [(&str, ZipperCompression); 4] = [
            ("packed_zlib.pyc.bin", ZipperCompression::Zlib),
            ("packed_bz2.pyc.bin", ZipperCompression::Bz2),
            ("packed_lzma_xz.pyc.bin", ZipperCompression::LzmaXz),
            ("packed_lzma_alone.pyc.bin", ZipperCompression::LzmaAlone),
        ];
        for (name, expected) in cases {
            let wrapped: Vec<u8> = read_fixture(name)
                .unwrap_or_else(|| panic!("pyc_zipper fixture {name} must be committed"));
            let recovered: UnzippedPyc = unzip_pyc(&wrapped).expect("must recover");
            assert_eq!(
                recovered.compression, expected,
                "compression method mislabelled for {name}",
            );
        }
    }

    #[test]
    fn plain_pyc_is_not_misreported_as_zipped() {
        let original: Vec<u8> = read_fixture("original.pyc.bin")
            .expect("pyc_zipper original.pyc.bin fixture must be committed");
        assert!(
            unzip_pyc(&original).is_none(),
            "an ordinary .pyc with no compressed marshal constant must not be reported as zipped",
        );
    }

    #[test]
    fn recovered_pyc_capacity_saturates() {
        assert_eq!(recovered_pyc_capacity(16usize, 32usize), 48usize);
        assert_eq!(recovered_pyc_capacity(usize::MAX, 1usize), usize::MAX);
    }

    #[test]
    fn brotli_wrapper_recovers_round_trip() {
        let original: Vec<u8> = read_fixture("original.pyc.bin")
            .expect("pyc_zipper original.pyc.bin fixture must be committed");
        let header_len: usize = 16;
        let body: &[u8] = &original[header_len..];
        let mut packed: Vec<u8> = Vec::new();
        {
            let mut writer: brotli::CompressorWriter<&mut Vec<u8>> =
                brotli::CompressorWriter::new(&mut packed, 4096, 9, 22);
            writer.write_all(body).expect("brotli compress");
        }
        let mut wrapper_code: disrobe_py_marshal::CodeObject =
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        wrapper_code.consts = vec![Object::Bytes(packed)];
        wrapper_code.filename = Object::ShortAscii {
            value: "<pyc-zipper-brotli>".to_owned(),
            interned: false,
        };
        wrapper_code.name = Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: false,
        };
        wrapper_code.qualname = wrapper_code.name.clone();
        let file: disrobe_py_marshal::PycFile = disrobe_py_marshal::PycFile {
            header: disrobe_py_marshal::PycHeader::deterministic(PyVersion::PY314).expect("header"),
            code: Object::Code(Box::new(wrapper_code)),
        };
        let wrapper_bytes: Vec<u8> = disrobe_py_marshal::write_pyc(&file).expect("write wrapper");
        let recovered: UnzippedPyc =
            unzip_pyc(&wrapper_bytes).expect("brotli wrapper must recover");
        assert_eq!(recovered.compression, ZipperCompression::Brotli);
        assert_eq!(
            recovered.pyc_bytes, original,
            "brotli-wrapped recovery must equal the original .pyc bytes",
        );
    }

    #[test]
    fn candidate_byte_budget_stops_before_valid_payload() {
        let original: Vec<u8> = read_fixture("original.pyc.bin")
            .expect("pyc_zipper original.pyc.bin fixture must be committed");
        let header_len: usize = 16;
        let body: &[u8] = &original[header_len..];
        let packed: Vec<u8> = zlib_compress(body);
        let wrapper_bytes: Vec<u8> =
            wrapper_with_consts(vec![Object::Bytes(vec![0x41; 8]), Object::Bytes(packed)]);
        let limits: ZipperLimits = ZipperLimits {
            candidate_consts: 16,
            candidate_bytes: 4,
            decode_attempts: 16,
            recovered_bytes: MAX_RECOVERED_BYTES,
        };
        assert!(unzip_pyc_with_limits(&wrapper_bytes, limits).is_none());
    }

    #[test]
    fn decode_attempt_budget_stops_before_valid_payload() {
        let original: Vec<u8> = read_fixture("original.pyc.bin")
            .expect("pyc_zipper original.pyc.bin fixture must be committed");
        let header_len: usize = 16;
        let body: &[u8] = &original[header_len..];
        let invalid_zlib: Vec<u8> = zlib_compress(b"not a marshal body");
        let valid_zlib: Vec<u8> = zlib_compress(body);
        let wrapper_bytes: Vec<u8> =
            wrapper_with_consts(vec![Object::Bytes(invalid_zlib), Object::Bytes(valid_zlib)]);
        let limits: ZipperLimits = ZipperLimits {
            candidate_consts: 16,
            candidate_bytes: MAX_CANDIDATE_BYTES,
            decode_attempts: 1,
            recovered_bytes: MAX_RECOVERED_BYTES,
        };
        assert!(unzip_pyc_with_limits(&wrapper_bytes, limits).is_none());
    }

    #[test]
    fn random_bytes_are_not_recovered() {
        let mut junk: Vec<u8> = Vec::with_capacity(256);
        for i in 0..256u32 {
            junk.push((i.wrapping_mul(31).wrapping_add(7) & 0xFF) as u8);
        }
        junk[0] = 0x2B;
        junk[1] = 0x0E;
        junk[2] = 0x0D;
        junk[3] = 0x0A;
        assert!(unzip_pyc(&junk).is_none());
    }

    #[test]
    fn looks_like_pyc_gate() {
        assert!(looks_like_pyc(&[0x2B, 0x0E, 0x0D, 0x0A, 0, 0, 0, 0]));
        assert!(!looks_like_pyc(&[0x00, 0x00, 0x00, 0x00]));
        assert!(!looks_like_pyc(&[0x2B]));
    }

    fn wrapper_with_consts(consts: Vec<Object>) -> Vec<u8> {
        let mut wrapper_code: disrobe_py_marshal::CodeObject =
            disrobe_py_marshal::CodeObject::new(disrobe_py_marshal::CodeEra::Py311Plus);
        wrapper_code.consts = consts;
        wrapper_code.filename = Object::ShortAscii {
            value: "<pyc-zipper-budget>".to_owned(),
            interned: false,
        };
        wrapper_code.name = Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: false,
        };
        wrapper_code.qualname = wrapper_code.name.clone();
        let file: disrobe_py_marshal::PycFile = disrobe_py_marshal::PycFile {
            header: disrobe_py_marshal::PycHeader::deterministic(PyVersion::PY314).expect("header"),
            code: Object::Code(Box::new(wrapper_code)),
        };
        disrobe_py_marshal::write_pyc(&file).expect("write wrapper")
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        let mut enc: flate2::write::ZlibEncoder<Vec<u8>> =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }
}
