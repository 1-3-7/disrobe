use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeObject, Object, PyVersion, PycFile, read_pyc, write_pyc};

use crate::codec::{bz2_decompress, lzma_decompress, zlib_decompress};
use crate::error::{Error, Result};
use crate::marshal::{decompile_code_object_with_status, load_code_from_marshal};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

mod reverse;

use reverse::ObfuscationReversal;

#[derive(Debug, Clone, Copy)]
pub struct PycZipperPass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compressor {
    Zlib,
    Bz2,
    Lzma,
}

impl Compressor {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Bz2 => "bz2",
            Self::Lzma => "lzma",
        }
    }

    #[inline]
    fn matches_magic(self, payload: &[u8]) -> bool {
        match self {
            Self::Zlib => matches!(payload.first(), Some(0x78)),
            Self::Bz2 => payload.starts_with(b"BZh"),
            Self::Lzma => payload.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]),
        }
    }

    #[inline]
    fn decompress(self, payload: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Zlib => zlib_decompress(payload),
            Self::Bz2 => bz2_decompress(payload),
            Self::Lzma => lzma_decompress(payload),
        }
    }
}

const LOADER_NAMES: [&str; 3] = ["marshal", "loads", "decompress"];
const DETECTABLE_MODULES: [Compressor; 3] = [Compressor::Bz2, Compressor::Lzma, Compressor::Zlib];
const MAX_LOADER_BYTECODE: usize = 256;

const fn object_name(obj: &Object) -> Option<&str> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

fn loader_code(file: &PycFile) -> Option<&CodeObject> {
    match &file.code {
        Object::Code(co) => Some(co.as_ref()),
        _ => None,
    }
}

fn collect_names(code: &CodeObject) -> Vec<&str> {
    code.names.iter().filter_map(object_name).collect()
}

fn declared_compressor(names: &[&str]) -> Option<Compressor> {
    DETECTABLE_MODULES
        .into_iter()
        .find(|c: &Compressor| names.contains(&c.label()))
}

fn first_bytes_const(code: &CodeObject) -> Option<&[u8]> {
    code.consts.iter().find_map(|c: &Object| match c {
        Object::Bytes(b) => Some(b.as_slice()),
        _ => None,
    })
}

fn looks_like_loader(code: &CodeObject) -> bool {
    if code.code.len() > MAX_LOADER_BYTECODE {
        return false;
    }
    let names: Vec<&str> = collect_names(code);
    if !LOADER_NAMES.iter().all(|n: &&str| names.contains(n)) {
        return false;
    }
    if declared_compressor(&names).is_none() {
        return false;
    }
    first_bytes_const(code).is_some()
}

fn select_compressor(declared: Compressor, payload: &[u8]) -> Compressor {
    if declared.matches_magic(payload) {
        return declared;
    }
    DETECTABLE_MODULES
        .into_iter()
        .find(|c: &Compressor| c.matches_magic(payload))
        .unwrap_or(declared)
}

struct LoaderLayer {
    compressor: Compressor,
    payload_len: usize,
    marshal_len: usize,
}

struct PyczDecode {
    layer: Option<LoaderLayer>,
    reversal: Option<ObfuscationReversal>,
    inner: CodeObject,
    inner_version: PyVersion,
    header_version: PyVersion,
    recovered_pyc: Vec<u8>,
}

fn unpack_loader(code: &CodeObject) -> Result<(CodeObject, PyVersion, LoaderLayer)> {
    let names: Vec<&str> = collect_names(code);
    let declared: Compressor = declared_compressor(&names).ok_or(Error::NoFamilyMatched)?;
    let payload: &[u8] = first_bytes_const(code).ok_or(Error::LiteralNotFound)?;
    let compressor: Compressor = select_compressor(declared, payload);
    let marshal_bytes: Vec<u8> = compressor.decompress(payload)?;
    let (inner, inner_version): (CodeObject, PyVersion) = load_code_from_marshal(&marshal_bytes)
        .ok_or_else(|| Error::Marshal("decompressed payload held no code object".to_owned()))?;
    let layer: LoaderLayer = LoaderLayer {
        compressor,
        payload_len: payload.len(),
        marshal_len: marshal_bytes.len(),
    };
    Ok((inner, inner_version, layer))
}

fn decode_pyc_zipper(source: &[u8]) -> Result<PyczDecode> {
    let file: PycFile = read_pyc(source).map_err(|e| Error::Marshal(format!("{e}")))?;
    let code: &CodeObject = loader_code(&file)
        .ok_or_else(|| Error::Marshal("pyc top object is not code".to_owned()))?;
    let header_version: PyVersion = file.header.version;
    let (mut inner, inner_version, layer): (CodeObject, PyVersion, Option<LoaderLayer>) =
        if looks_like_loader(code) {
            let (inner, inner_version, layer): (CodeObject, PyVersion, LoaderLayer) =
                unpack_loader(code)?;
            (inner, inner_version, Some(layer))
        } else if reverse::is_obfuscated(code, header_version) {
            (code.clone(), header_version, None)
        } else {
            return Err(Error::NoFamilyMatched);
        };
    let reversal: Option<ObfuscationReversal> = reverse::is_obfuscated(&inner, inner_version)
        .then(|| reverse::reverse(&mut inner, inner_version));

    let rewrapped: PycFile = PycFile {
        header: file.header.clone(),
        code: Object::Code(Box::new(inner.clone())),
    };
    let recovered_pyc: Vec<u8> =
        write_pyc(&rewrapped).map_err(|e| Error::Marshal(format!("{e}")))?;

    Ok(PyczDecode {
        layer,
        reversal,
        inner,
        inner_version,
        header_version,
        recovered_pyc,
    })
}

pub fn recover_pyc(source: &[u8]) -> Result<Vec<u8>> {
    let decoded: PyczDecode = decode_pyc_zipper(source)?;
    Ok(decoded.recovered_pyc)
}

impl ObfuscatorPass for PycZipperPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::PycZipper
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let Ok(file): core::result::Result<PycFile, _> = read_pyc(source) else {
            return miss(self.id());
        };
        let Some(code): Option<&CodeObject> = loader_code(&file) else {
            return miss(self.id());
        };
        if !looks_like_loader(code) {
            if reverse::is_obfuscated(code, file.header.version) {
                return DetectReport {
                    obfuscator: self.id(),
                    matched: true,
                    confidence: 0.9,
                    markers: vec![
                        "pyc-obfuscation".to_owned(),
                        "empty-filename".to_owned(),
                        "no-line-table".to_owned(),
                        "dead-trailing-return".to_owned(),
                    ],
                };
            }
            return miss(self.id());
        }
        let names: Vec<&str> = collect_names(code);
        let Some(declared): Option<Compressor> = declared_compressor(&names) else {
            return miss(self.id());
        };
        let mut markers: Vec<String> = vec![
            "pyc-loader".to_owned(),
            format!("{}-decompress", declared.label()),
            "marshal-loads".to_owned(),
        ];
        if let Some(payload) = first_bytes_const(code) {
            markers.push(format!("payload-{}-bytes", payload.len()));
        }
        DetectReport {
            obfuscator: self.id(),
            matched: true,
            confidence: 0.92,
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let decoded: PyczDecode = decode_pyc_zipper(source)?;
        let mut stages: Vec<String> = vec!["pyc-header".to_owned(), "marshal".to_owned()];
        if let Some(layer) = &decoded.layer {
            stages.push(layer.compressor.label().to_owned());
            stages.push("marshal".to_owned());
        }
        if decoded.reversal.is_some() {
            stages.push("strip-dead-return".to_owned());
            stages.push("restore-def-names".to_owned());
        }
        stages.push("decompile".to_owned());
        let (recovered, complete_source): (String, bool) =
            decompile_code_object_with_status(&decoded.inner, decoded.inner_version)?;
        let real_source: bool = !recovered.trim().is_empty()
            && !recovered.starts_with("# disrobe: marshal code object");
        let placeholders_left: usize = decoded
            .reversal
            .as_ref()
            .map_or(0, |r: &ObfuscationReversal| r.placeholders_left.len());
        let reversal_depth_limited: bool = decoded
            .reversal
            .as_ref()
            .is_some_and(|reversal: &ObfuscationReversal| reversal.depth_limited);
        let quality: Quality = if real_source
            && complete_source
            && placeholders_left == 0
            && !reversal_depth_limited
        {
            Quality::Full
        } else {
            Quality::Partial
        };
        let confidence: f32 = if real_source { 0.95 } else { 0.85 };

        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        if let Some(layer) = &decoded.layer {
            diagnostics.insert("compressor".to_owned(), layer.compressor.label().to_owned());
            diagnostics.insert("payload_bytes".to_owned(), layer.payload_len.to_string());
            diagnostics.insert("marshal_bytes".to_owned(), layer.marshal_len.to_string());
        }
        diagnostics.insert(
            "recovered_pyc_bytes".to_owned(),
            decoded.recovered_pyc.len().to_string(),
        );
        diagnostics.insert(
            "python_version".to_owned(),
            format!(
                "{}.{}",
                decoded.header_version.major, decoded.header_version.minor
            ),
        );

        let mut lossy_notes: Vec<String> = Vec::new();
        if !real_source {
            lossy_notes.push("pyc-zipper wrapper fully stripped (pyc header + loader marshal + compression + inner marshal); inner code object recovered but source-level decompile fell back to disassembly.".to_owned());
        }
        if real_source && !complete_source {
            lossy_notes.push("source-level decompilation contains refused scopes; the recovered bytecode remains available.".to_owned());
        }
        if let Some(reversal) = &decoded.reversal {
            diagnostics.insert(
                "dead_returns_stripped".to_owned(),
                reversal.junk_returns_stripped.to_string(),
            );
            diagnostics.insert(
                "names_restored".to_owned(),
                reversal.names_restored.len().to_string(),
            );
            diagnostics.insert(
                "placeholder_names_left".to_owned(),
                placeholders_left.to_string(),
            );
            diagnostics.insert(
                "reverse_depth_limited".to_owned(),
                reversal.depth_limited.to_string(),
            );
            lossy_notes.push("pyc-zipper obfuscation deleted the line table and the file name; neither is recoverable.".to_owned());
            if reversal.depth_limited {
                lossy_notes.push("pyc-zipper reversal stopped at the nested-code depth limit, so deeper scopes were not inspected.".to_owned());
            }
            if placeholders_left > 0 {
                let names: Vec<&str> = reversal
                    .placeholders_left
                    .iter()
                    .map(String::as_str)
                    .collect();
                lossy_notes.push(format!(
                    "{placeholders_left} variable name(s) keep their pyc-zipper placeholder because the bytecode holds no trace of the original: {}",
                    names.join(", ")
                ));
            }
        }

        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence,
            quality,
            lossy_notes,
            diagnostics,
        })
    }
}

const fn miss(obfuscator: Obfuscator) -> DetectReport {
    DetectReport {
        obfuscator,
        matched: false,
        confidence: 0.0,
        markers: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;
    use std::path::PathBuf;

    use flate2::Compression;
    use flate2::write::ZlibEncoder;

    use super::*;

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("python")
            .join("pyc_zipper")
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        let mut e: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(input).expect("zlib write");
        e.finish().expect("zlib finish")
    }

    #[test]
    fn compressor_magic_anchors() {
        assert!(Compressor::Zlib.matches_magic(&[0x78, 0x9c]));
        assert!(Compressor::Bz2.matches_magic(b"BZh91"));
        assert!(Compressor::Lzma.matches_magic(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]));
        assert!(!Compressor::Zlib.matches_magic(b"BZh"));
    }

    #[test]
    fn clean_pyc_does_not_match() {
        let dir: PathBuf = fixture_dir();
        let clean: Vec<u8> = std::fs::read(dir.join("sample_orig.pyc")).expect("orig fixture");
        assert!(
            !PycZipperPass.detect(&clean).matched,
            "an unpacked pyc must not be flagged as pyc-zipper"
        );
    }

    #[test]
    fn random_bytes_do_not_match() {
        assert!(
            !PycZipperPass
                .detect(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9])
                .matched
        );
    }

    #[test]
    fn synthetic_zlib_payload_magic_is_zlib() {
        let blob: Vec<u8> = zlib_compress(b"hello marshal blob padding padding");
        assert!(Compressor::Zlib.matches_magic(&blob));
    }
}
