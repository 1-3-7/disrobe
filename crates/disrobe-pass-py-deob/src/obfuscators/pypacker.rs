use std::collections::BTreeMap;

use disrobe_py_marshal::{CodeObject, Object, PyVersion};

use crate::codec::{
    bz2_decompress, extract_largest_python_bytes_literal, gzip_decompress, lzma_decompress,
    zlib_decompress,
};
use crate::error::{Error, Result};
use crate::marshal::{decompile_code_object_with_status, load_code_from_marshal};
use crate::obfuscators::{DetectReport, Obfuscator, ObfuscatorPass, PeelOutcome, Quality};

#[derive(Debug, Clone, Copy)]
pub struct PypackerPass;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compressor {
    Bz2,
    Gzip,
    Zlib,
    Lzma,
}

impl Compressor {
    #[inline]
    const fn label(self) -> &'static str {
        match self {
            Self::Bz2 => "bz2",
            Self::Gzip => "gzip",
            Self::Zlib => "zlib",
            Self::Lzma => "lzma",
        }
    }

    #[inline]
    fn decompress(self, input: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Bz2 => bz2_decompress(input),
            Self::Gzip => gzip_decompress(input),
            Self::Zlib => zlib_decompress(input),
            Self::Lzma => lzma_decompress(input),
        }
    }
}

const HYPERION_AUTHOR: &str = "billythegoat356";
const MAX_NESTED_CODE_DEPTH: usize = 32;

fn detect_compressor(text: &str) -> Option<Compressor> {
    if text.contains("bz2.decompress(") {
        return Some(Compressor::Bz2);
    }
    if text.contains("gzip.decompress(") {
        return Some(Compressor::Gzip);
    }
    if text.contains("zlib.decompress(") {
        return Some(Compressor::Zlib);
    }
    if text.contains("lzma.decompress(") {
        return Some(Compressor::Lzma);
    }
    None
}

impl ObfuscatorPass for PypackerPass {
    fn id(&self) -> Obfuscator {
        Obfuscator::Pypacker
    }

    fn detect(&self, source: &[u8]) -> DetectReport {
        let head: &[u8] = &source[..source.len().min(16 * 1024)];
        let text: &str = std::str::from_utf8(head).unwrap_or("");
        let has_marshal_loads: bool = text.contains("marshal.loads(");
        let compressor: Option<Compressor> = detect_compressor(text);
        let has_exec: bool = text.contains("exec(");
        let hyperion: bool = text.contains(HYPERION_AUTHOR);
        let matched: bool = has_marshal_loads && compressor.is_some() && has_exec && !hyperion;
        let mut markers: Vec<String> = Vec::new();
        if has_marshal_loads {
            markers.push("marshal-loads".to_owned());
        }
        if let Some(comp) = compressor {
            markers.push(format!("{}-decompress", comp.label()));
        }
        DetectReport {
            obfuscator: self.id(),
            matched,
            confidence: if matched { 0.9 } else { 0.0 },
            markers,
        }
    }

    fn peel(&self, source: &[u8]) -> Result<PeelOutcome> {
        let text: &str = std::str::from_utf8(source).map_err(Error::from)?;
        let compressor: Compressor = detect_compressor(text).ok_or(Error::NoFamilyMatched)?;
        let literal: &str =
            extract_largest_python_bytes_literal(text).ok_or(Error::LiteralNotFound)?;
        let raw: Vec<u8> = crate::codec::decode_python_bytes_literal(literal)?;
        let mut stages: Vec<String> = Vec::with_capacity(3);
        let inflated: Vec<u8> = compressor.decompress(&raw)?;
        stages.push(compressor.label().to_owned());
        let (top_code, version): (CodeObject, PyVersion) = load_code_from_marshal(&inflated)
            .ok_or_else(|| {
                Error::Marshal(
                    "the decompressed payload is not a marshalled code object for any CPython version disrobe reads".to_owned(),
                )
            })?;
        stages.push("marshal".to_owned());
        let (recovered, complete): (String, bool) =
            decompile_code_object_with_status(&top_code, version)?;
        stages.push("decompile".to_owned());

        let mut count: usize = 0;
        count_code_objects(&top_code, &mut count, 0);
        let entry_name: String = object_to_string(&top_code.name);
        let mut diagnostics: BTreeMap<String, String> = BTreeMap::new();
        diagnostics.insert("compressor".to_owned(), compressor.label().to_owned());
        diagnostics.insert("payload_bytes".to_owned(), raw.len().to_string());
        diagnostics.insert("marshal_bytes".to_owned(), inflated.len().to_string());
        diagnostics.insert("code_objects".to_owned(), count.to_string());
        diagnostics.insert("entry_code_object".to_owned(), entry_name);
        diagnostics.insert(
            "python_version".to_owned(),
            format!("{}.{}", version.major, version.minor),
        );
        let (quality, lossy_notes): (Quality, Vec<String>) = if complete {
            (Quality::Full, Vec::new())
        } else {
            (
                Quality::Partial,
                vec!["py-decompile could not lift every code object of the marshalled module; the scopes it could not lift are emitted as disassembly.".to_owned()],
            )
        };
        Ok(PeelOutcome {
            obfuscator: self.id(),
            stages_applied: stages,
            recovered_source: recovered,
            confidence: 0.9,
            quality,
            lossy_notes,
            diagnostics,
        })
    }
}

fn count_code_objects(code: &CodeObject, count: &mut usize, depth: usize) {
    *count += 1;
    if depth >= MAX_NESTED_CODE_DEPTH {
        return;
    }
    for konst in &code.consts {
        if let Object::Code(inner) = konst {
            count_code_objects(inner, count, depth + 1);
        }
    }
}

fn object_to_string(obj: &Object) -> String {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        Object::None => String::new(),
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use disrobe_py_marshal::{CodeEra, dump as marshal_dump};
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use liblzma::write::XzEncoder;

    use super::*;
    use crate::codec::python_bytes_literal;

    fn build_code_object(name: &str) -> CodeObject {
        let mut co: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        co.name = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.qualname = Object::ShortAscii {
            value: name.to_owned(),
            interned: false,
        };
        co.filename = Object::ShortAscii {
            value: format!("<{name}>"),
            interned: false,
        };
        co.firstlineno = 1;
        co.code = vec![0x97, 0x00, 0x64, 0x00, 0x53, 0x00];
        co.consts = vec![Object::None, Object::Int(7)];
        co
    }

    fn marshalled_entry() -> Vec<u8> {
        let co: CodeObject = build_code_object("entry");
        marshal_dump(&Object::Code(Box::new(co)), PyVersion::PY311).expect("marshal dump")
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        let mut e: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        e.write_all(input).expect("zlib write");
        e.finish().expect("zlib finish")
    }

    fn gzip_compress(input: &[u8]) -> Vec<u8> {
        let mut e: GzEncoder<Vec<u8>> = GzEncoder::new(Vec::new(), Compression::best());
        e.write_all(input).expect("gzip write");
        e.finish().expect("gzip finish")
    }

    fn xz_compress(input: &[u8]) -> Vec<u8> {
        let mut e: XzEncoder<Vec<u8>> = XzEncoder::new(Vec::new(), 6);
        e.write_all(input).expect("xz write");
        e.finish().expect("xz finish")
    }

    fn wrap(module: &str, blob: &[u8]) -> String {
        let literal: String = python_bytes_literal(blob);
        format!("import marshal, {module}\nexec(marshal.loads({module}.decompress({literal})))\n")
    }

    #[test]
    fn detects_zlib_marshal_wrapper() {
        let stub: String = wrap("zlib", &zlib_compress(&marshalled_entry()));
        let det: DetectReport = PypackerPass.detect(stub.as_bytes());
        assert_eq!(det.obfuscator, Obfuscator::Pypacker);
        assert!(det.matched, "zlib+marshal wrapper must match: {det:?}");
        assert!(det.markers.iter().any(|m: &String| m == "zlib-decompress"));
    }

    #[test]
    fn peels_zlib_marshal_through_the_decompiler() {
        let stub: String = wrap("zlib", &zlib_compress(&marshalled_entry()));
        let out: PeelOutcome = PypackerPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.stages_applied, vec!["zlib", "marshal", "decompile"]);
        assert_eq!(
            out.diagnostics.get("code_objects").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            out.diagnostics.get("entry_code_object").map(String::as_str),
            Some("entry")
        );
    }

    #[test]
    fn peels_gzip_marshal_wrapper() {
        let stub: String = wrap("gzip", &gzip_compress(&marshalled_entry()));
        let det: DetectReport = PypackerPass.detect(stub.as_bytes());
        assert!(det.matched);
        let out: PeelOutcome = PypackerPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.stages_applied.first().map(String::as_str), Some("gzip"));
        assert_eq!(
            out.diagnostics.get("entry_code_object").map(String::as_str),
            Some("entry")
        );
    }

    #[test]
    fn peels_lzma_marshal_wrapper() {
        let stub: String = wrap("lzma", &xz_compress(&marshalled_entry()));
        let det: DetectReport = PypackerPass.detect(stub.as_bytes());
        assert!(det.matched);
        let out: PeelOutcome = PypackerPass.peel(stub.as_bytes()).expect("peel");
        assert_eq!(out.stages_applied.first().map(String::as_str), Some("lzma"));
    }

    #[test]
    fn ignores_hyperion_authored_lzma_stub() {
        let stub: String = format!(
            "# billythegoat356 Hyperion\nimport marshal, lzma\nexec(marshal.loads(lzma.decompress({})))\n",
            python_bytes_literal(&xz_compress(&marshalled_entry()))
        );
        assert!(
            !PypackerPass.detect(stub.as_bytes()).matched,
            "hyperion-authored stubs belong to the hyperion pass, not pypacker"
        );
    }

    #[test]
    fn clean_python_does_not_match() {
        let src: &[u8] = b"import os\nprint(os.getcwd())\n";
        assert!(!PypackerPass.detect(src).matched);
    }
}
