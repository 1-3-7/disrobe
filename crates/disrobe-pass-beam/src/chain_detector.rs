#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    CatalogEntry, DetectContext, DetectVerdict, Detector, DetectorOutput,
    FAMILY_INTERPRETER_BYTECODE, ObfuscatorCatalog, OutputKind, Pass, SupportQuality,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;
use disrobe_core::provenance::Language;

use crate::ez::EzArchive;
use crate::file::BeamFile;
use crate::surface::{self, ErlangSurface};

pub const PASS_ID: PassId = "beam.classify";

const TAG_BEAM: &str = "beam-file";
const TAG_EZ: &str = "ez-archive";
const BEAM_MAGIC_IFF: &[u8; 4] = b"FOR1";
const BEAM_MAGIC_TAG: &[u8; 4] = b"BEAM";

#[derive(Debug)]
pub struct BeamDetector;

impl Detector for BeamDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if is_beam_file(bytes) {
            return Some(verdict(TAG_BEAM, "FOR1+BEAM iff header"));
        }
        if is_ez_archive(bytes) {
            return Some(verdict(TAG_EZ, "EZ archive (zip wrapping .beam entries)"));
        }
        None
    }
}

#[derive(Debug)]
pub struct BeamPass;

impl Pass for BeamPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &BeamDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Source {
            language: Language::Erlang,
            formatted: false,
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: &[u8] = artifact.envelope.as_slice();
        let ctx: DetectContext<'_> = DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        };
        let Some(verdict): Option<DetectVerdict> = Detector::detect(&BeamDetector, &ctx) else {
            return Err(CoreError::PassFailure(
                "DR-BEAM-0901: beam.classify: input is neither a BEAM file nor an EZ archive"
                    .to_string(),
            ));
        };
        let source: String = if verdict.format_tag == TAG_EZ {
            recover_ez_source(bytes)?
        } else {
            recover_beam_source(bytes)?
        };
        Ok(Artifact::new(
            Rung::Disasm,
            source.into_bytes(),
            artifact.root_hash,
        ))
    }
}

fn recover_beam_source(bytes: &[u8]) -> CoreResult<String> {
    crate::debug::dbg_section("beam analyze");
    crate::debug::dbg_kv("input_len", || bytes.len().to_string());
    crate::debug::dbg_hex("input_magic", bytes, 12);
    crate::debug::dbg_kv("classify", || match bytes.first_chunk::<4>() {
        Some(b"FOR1") => "beam (FOR1/BEAM IFF container)".to_owned(),
        Some(other) => format!("unrecognized magic {other:02x?}"),
        None => "truncated: fewer than 4 bytes".to_owned(),
    });
    let beam: BeamFile = BeamFile::parse(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-BEAM-0903: beam parse: {e}"))
    })?;
    crate::debug::dbg_kv("chunks", || {
        format!(
            "atoms={} exports={} imports={} locals={} funs={} code={} dbgi={} docs={} attrs={} literals={} line={}",
            beam.chunks.atoms.atoms.len(),
            beam.chunks.exports.len(),
            beam.chunks.imports.len(),
            beam.chunks.locals.len(),
            beam.chunks.funs.len(),
            beam.chunks.code.is_some(),
            beam.chunks.dbgi.is_some(),
            beam.chunks.docs.is_some(),
            beam.chunks.attributes.is_some(),
            beam.chunks.literals.is_some(),
            beam.chunks.line.is_some(),
        )
    });
    let instruction_count: u32 = beam
        .chunks
        .code
        .as_ref()
        .and_then(|c| match crate::disassemble(c) {
            Ok(d) => Some(u32::try_from(d.instructions.len()).unwrap_or(u32::MAX)),
            Err(e) => {
                crate::debug::dbg_line(|| format!("beam disassemble failed: {e}"));
                None
            }
        })
        .unwrap_or(0);
    crate::debug::dbg_kv("instruction_count", || instruction_count.to_string());
    let symbolic_disasm: Option<String> = beam.chunks.code.as_ref().and_then(|_| {
        crate::symbolic::symbolic_disassemble(&beam)
            .map(|m| crate::symbolic::render_symbolic(&m))
            .ok()
    });
    crate::debug::dbg_kv("symbolic_disasm", || match &symbolic_disasm {
        Some(s) => format!("bytes={}", s.len()),
        None => "none".to_owned(),
    });
    let recovered: ErlangSurface = surface::recover(&beam).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-BEAM-0904: beam recover: {e}"))
    })?;
    crate::debug::dbg_kv("recovered", || {
        format!(
            "module={} from={:?} source_bytes={}",
            recovered.module,
            recovered.recovered_from,
            recovered.source.len()
        )
    });
    Ok(recovered.source)
}

fn recover_ez_source(bytes: &[u8]) -> CoreResult<String> {
    let archive: EzArchive = EzArchive::parse(bytes).map_err(|e: crate::error::Error| {
        CoreError::PassFailure(format!("DR-BEAM-0906: ez parse: {e}"))
    })?;
    let mut out: String = String::new();
    for entry in archive.entries.values() {
        if entry.is_dir || !entry.path.ends_with(".beam") {
            continue;
        }
        let beam: BeamFile = BeamFile::parse(&entry.data).map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!(
                "DR-BEAM-0908: ez member {} beam parse: {e}",
                entry.path
            ))
        })?;
        let recovered: surface::ErlangSurface =
            surface::recover(&beam).map_err(|e: crate::error::Error| {
                CoreError::PassFailure(format!(
                    "DR-BEAM-0909: ez member {} beam recover: {e}",
                    entry.path
                ))
            })?;
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format!("%% {}\n", entry.path));
        out.push_str(&recovered.source);
    }
    if out.is_empty() {
        return Err(CoreError::PassFailure(
            "DR-BEAM-0907: ez archive yielded no recoverable .beam source".to_string(),
        ));
    }
    Ok(out)
}

pub static BEAM_PASS: BeamPass = BeamPass;

fn is_beam_file(bytes: &[u8]) -> bool {
    bytes.len() >= 12 && &bytes[0..4] == BEAM_MAGIC_IFF && &bytes[8..12] == BEAM_MAGIC_TAG
}

fn is_ez_archive(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    bytes.windows(5).take(8192).any(|w: &[u8]| w == b".beam")
}

fn verdict(tag: &'static str, marker: &'static str) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_INTERPRETER_BYTECODE,
        0.97,
        30,
        vec![marker],
        format!("beam classify: {tag}"),
    )
}

#[derive(Debug)]
pub struct BeamCatalogEntry {
    tag: &'static str,
    id: &'static str,
    display_name: &'static str,
    aliases: &'static [&'static str],
    quality: SupportQuality,
}

impl CatalogEntry for BeamCatalogEntry {
    #[inline]
    fn id(&self) -> &'static str {
        self.id
    }
    #[inline]
    fn display_name(&self) -> &'static str {
        self.display_name
    }
    #[inline]
    fn aliases(&self) -> &'static [&'static str] {
        self.aliases
    }
    #[inline]
    fn support_quality(&self) -> SupportQuality {
        self.quality
    }
}

const CATALOG_COUNT: usize = 2;

static CATALOG: [BeamCatalogEntry; CATALOG_COUNT] = [
    BeamCatalogEntry {
        tag: TAG_BEAM,
        id: "beam-file",
        display_name: "BEAM file (Erlang / Elixir compiled module)",
        aliases: &["beam", "erlang", "elixir"],
        quality: SupportQuality::Full,
    },
    BeamCatalogEntry {
        tag: TAG_EZ,
        id: "beam-ez-archive",
        display_name: "EZ archive (zip-wrapped .beam modules)",
        aliases: &["ez", "escript"],
        quality: SupportQuality::Full,
    },
];

fn catalog_id_for_tag(tag: &str) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|e: &&BeamCatalogEntry| e.tag == tag)
        .map(|e: &BeamCatalogEntry| e.id)
}

impl ObfuscatorCatalog for BeamDetector {
    #[inline]
    fn pass_id(&self) -> PassId {
        PASS_ID
    }

    fn catalog(&self) -> Vec<&'static dyn CatalogEntry> {
        CATALOG
            .iter()
            .map(|e: &'static BeamCatalogEntry| e as &'static dyn CatalogEntry)
            .collect()
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectorOutput> {
        let verdict: DetectVerdict = Detector::detect(self, ctx)?;
        let entry_id: &'static str = catalog_id_for_tag(verdict.format_tag)?;
        let markers: Vec<String> = verdict
            .markers
            .iter()
            .map(|m: &&str| (*m).to_owned())
            .collect();
        Some(DetectorOutput::new(entry_id, verdict.confidence, markers))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(BeamDetector.id(), PASS_ID);
    }

    #[test]
    fn catalog_lists_beam_and_ez() {
        let entries: Vec<&'static dyn CatalogEntry> = ObfuscatorCatalog::catalog(&BeamDetector);
        assert_eq!(entries.len(), CATALOG_COUNT);
        let ids: Vec<&'static str> = entries.iter().map(|e| e.id()).collect();
        assert!(ids.contains(&"beam-file"), "got {ids:?}");
        assert!(ids.contains(&"beam-ez-archive"), "got {ids:?}");
    }

    #[test]
    fn catalog_detect_maps_beam_magic() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(BEAM_MAGIC_IFF);
        bytes.extend_from_slice(&[0, 0, 0, 4]);
        bytes.extend_from_slice(BEAM_MAGIC_TAG);
        let out: DetectorOutput =
            ObfuscatorCatalog::detect(&BeamDetector, &ctx(&bytes)).expect("beam catalog detect");
        assert_eq!(out.entry_id, "beam-file");
    }

    #[test]
    fn catalog_detect_misses_random_bytes() {
        assert!(ObfuscatorCatalog::detect(&BeamDetector, &ctx(&[0u8; 32])).is_none());
    }

    #[test]
    fn detects_beam_file() {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(BEAM_MAGIC_IFF);
        bytes.extend_from_slice(&[0, 0, 0, 4]);
        bytes.extend_from_slice(BEAM_MAGIC_TAG);
        let v: DetectVerdict = Detector::detect(&BeamDetector, &ctx(&bytes)).expect("beam magic");
        assert_eq!(v.format_tag, TAG_BEAM);
    }

    #[test]
    fn rejects_for1_without_beam_tag() {
        let bytes: Vec<u8> = b"FOR1\x00\x00\x00\x04AIFF".to_vec();
        assert!(Detector::detect(&BeamDetector, &ctx(&bytes)).is_none());
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(Detector::detect(&BeamDetector, &ctx(&[0u8; 32])).is_none());
    }

    const HELLO_BEAM: &[u8] = include_bytes!("../../../corpus/beam/erlang/hello.beam");

    #[test]
    fn run_emits_recovered_erlang_source_not_raw_bytes() {
        let artifact: Artifact = Artifact::new(Rung::Raw, HELLO_BEAM.to_vec(), [0u8; 32]);
        let out: Artifact = BEAM_PASS.run(&artifact).expect("run recovers source");
        assert_ne!(
            out.envelope.as_slice(),
            HELLO_BEAM,
            "must not echo the raw input bytes"
        );
        let source: String = String::from_utf8(out.envelope).expect("utf8 source");
        assert!(
            source.contains("-module"),
            "expected recovered erlang module, got: {source}"
        );
    }

    #[test]
    fn ez_chain_rejects_mixed_invalid_beam_member() {
        let mut bytes: Vec<u8> = Vec::new();
        {
            let cursor: std::io::Cursor<&mut Vec<u8>> = std::io::Cursor::new(&mut bytes);
            let mut writer: ZipWriter<std::io::Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let options: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            writer
                .start_file("app-1.0/ebin/hello.beam", options)
                .expect("start valid member");
            writer.write_all(HELLO_BEAM).expect("write valid member");
            writer
                .start_file("app-1.0/ebin/corrupt.beam", options)
                .expect("start invalid member");
            writer
                .write_all(b"FOR1\x00\x00\x00\x04BEAM")
                .expect("write invalid member");
            writer.finish().expect("finish ez");
        }

        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let err: CoreError = BEAM_PASS
            .run(&artifact)
            .expect_err("mixed corrupt ez member must fail");
        let message: String = err.to_string();
        assert!(
            message.contains("DR-BEAM-0908"),
            "expected member parse error, got {message}"
        );
        assert!(
            message.contains("app-1.0/ebin/corrupt.beam"),
            "expected corrupt member path, got {message}"
        );
    }
}
