#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

pub const PASS_ID: PassId = "binfmt.container";

const TAG_ZIP: &str = "zip";
const TAG_TAR: &str = "tar";
const TAG_AR: &str = "ar";
const TAG_GZIP: &str = "gzip";
const TAG_XZ: &str = "xz";
const TAG_ZSTD: &str = "zstd";
const TAG_BZIP2: &str = "bzip2";
const TAG_SEVENZIP: &str = "7z";
const TAG_CAB: &str = "cab";
const TAG_RAR: &str = "rar";
const TAG_ISO: &str = "iso";

#[derive(Debug)]
pub struct ContainerDetector;

impl Detector for ContainerDetector {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let bytes: &[u8] = ctx.bytes;
        if bytes.len() < 4 {
            return None;
        }
        let tag: Option<&'static str> = sniff_container_tag(bytes);
        tag.map(|t: &'static str| {
            DetectVerdict::new(
                PASS_ID,
                t,
                FAMILY_CONTAINER,
                0.90,
                50,
                vec!["container-magic"],
                format!("container format: {t}"),
            )
        })
    }
}

#[derive(Debug)]
pub struct ContainerPass;

const MANIFEST_FORMAT_TAG: &str = "container-manifest";

impl Pass for ContainerPass {
    #[inline]
    fn id(&self) -> PassId {
        PASS_ID
    }

    #[inline]
    fn detector(&self) -> &'static dyn Detector {
        &ContainerDetector
    }

    #[inline]
    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Bytes {
            format_tag: MANIFEST_FORMAT_TAG,
            family: FAMILY_CONTAINER,
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
        if ContainerDetector.detect(&ctx).is_none() {
            return Err(CoreError::PassFailure(
                "DR-BINFMT-0901: binfmt.container: input is not a recognised container".to_string(),
            ));
        }
        let Some(tag): Option<&'static str> = sniff_container_tag(bytes) else {
            return Err(CoreError::PassFailure(
                "DR-BINFMT-0901: binfmt.container: input is not a recognised container".to_string(),
            ));
        };
        let manifest: String = render_container_manifest(tag, bytes);
        Ok(Artifact::new(
            Rung::Disasm,
            manifest.into_bytes(),
            artifact.root_hash,
        ))
    }
}

pub static CONTAINER_PASS: ContainerPass = ContainerPass;

fn render_container_manifest(tag: &str, bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(256);
    let _ = writeln!(s, "binfmt.container");
    let _ = writeln!(s, "format={tag} size={size}", size = bytes.len());
    match inventory_entries(tag, bytes) {
        Inventory::Listed(entries) => {
            let _ = writeln!(s, "entries={n} listing=read-only", n = entries.len());
            for (name, entry_size) in &entries {
                let _ = writeln!(s, "{name}\tbytes={entry_size}");
            }
        }
        Inventory::ExtractionRequired => {
            let _ = writeln!(
                s,
                "entries=unlisted listing=requires-extraction (run `disrobe extract` for full entry decode)"
            );
        }
        Inventory::Unreadable(reason) => {
            let _ = writeln!(s, "entries=unreadable reason={reason}");
        }
    }
    s
}

#[derive(Debug)]
enum Inventory {
    Listed(Vec<(String, u64)>),
    ExtractionRequired,
    Unreadable(String),
}

fn inventory_entries(tag: &str, bytes: &[u8]) -> Inventory {
    match tag {
        TAG_ZIP => zip_inventory(bytes),
        TAG_TAR => tar_inventory(bytes),
        _ => Inventory::ExtractionRequired,
    }
}

fn zip_inventory(bytes: &[u8]) -> Inventory {
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        match zip::ZipArchive::new(std::io::Cursor::new(bytes)) {
            Ok(a) => a,
            Err(e) => return Inventory::Unreadable(e.to_string()),
        };
    let mut entries: Vec<(String, u64)> = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let file: zip::read::ZipFile<'_> = match archive.by_index(i) {
            Ok(f) => f,
            Err(e) => return Inventory::Unreadable(e.to_string()),
        };
        if file.is_dir() {
            continue;
        }
        entries.push((file.name().to_owned(), file.size()));
    }
    Inventory::Listed(entries)
}

fn tar_inventory(bytes: &[u8]) -> Inventory {
    let mut archive: tar::Archive<std::io::Cursor<&[u8]>> =
        tar::Archive::new(std::io::Cursor::new(bytes));
    let raw_entries: tar::Entries<'_, std::io::Cursor<&[u8]>> = match archive.entries() {
        Ok(e) => e,
        Err(e) => return Inventory::Unreadable(e.to_string()),
    };
    let mut entries: Vec<(String, u64)> = Vec::new();
    for entry_result in raw_entries {
        let entry: tar::Entry<'_, std::io::Cursor<&[u8]>> = match entry_result {
            Ok(e) => e,
            Err(e) => return Inventory::Unreadable(e.to_string()),
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name: String = match entry.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => return Inventory::Unreadable(e.to_string()),
        };
        entries.push((name, entry.size()));
    }
    Inventory::Listed(entries)
}

fn sniff_container_tag(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08")
    {
        return Some(TAG_ZIP);
    }
    if bytes.len() >= 262 && &bytes[257..262] == b"ustar" {
        return Some(TAG_TAR);
    }
    if bytes.starts_with(b"!<arch>\n") {
        return Some(TAG_AR);
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        return Some(TAG_GZIP);
    }
    if bytes.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return Some(TAG_XZ);
    }
    if bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(TAG_ZSTD);
    }
    if bytes.starts_with(&[0x42, 0x5a, 0x68]) {
        return Some(TAG_BZIP2);
    }
    if bytes.starts_with(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]) {
        return Some(TAG_SEVENZIP);
    }
    if bytes.starts_with(b"MSCF") {
        return Some(TAG_CAB);
    }
    if bytes.starts_with(b"Rar!\x1a\x07") {
        return Some(TAG_RAR);
    }
    if bytes.len() >= 0x8006 && &bytes[0x8001..0x8006] == b"CD001" {
        return Some(TAG_ISO);
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

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
        assert_eq!(ContainerDetector.id(), PASS_ID);
    }

    #[test]
    fn detects_zip() {
        let v: DetectVerdict = ContainerDetector
            .detect(&ctx(b"PK\x03\x04rest"))
            .expect("zip magic");
        assert_eq!(v.format_tag, TAG_ZIP);
    }

    #[test]
    fn detects_gzip() {
        let v: DetectVerdict = ContainerDetector
            .detect(&ctx(&[0x1f, 0x8b, 0x08, 0x00]))
            .expect("gzip magic");
        assert_eq!(v.format_tag, TAG_GZIP);
    }

    #[test]
    fn rejects_random_bytes() {
        assert!(ContainerDetector.detect(&ctx(&[0u8; 32])).is_none());
    }

    #[test]
    fn rejects_short_input() {
        assert!(ContainerDetector.detect(&ctx(b"PK")).is_none());
    }

    fn synth_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut zw: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        for (name, body) in files {
            zw.start_file(*name, opts).expect("start");
            zw.write_all(body).expect("write");
        }
        zw.finish().expect("finish").into_inner()
    }

    #[test]
    fn pass_produces_real_manifest_not_byte_echo() {
        let zip_bytes: Vec<u8> = synth_zip(&[("a.txt", b"alpha"), ("dir/b.bin", b"bravobravo")]);
        let artifact: Artifact = Artifact::new(Rung::Raw, zip_bytes.clone(), [0u8; 32]);
        let out: Artifact = CONTAINER_PASS.run(&artifact).expect("container pass runs");
        assert_eq!(out.rung, Rung::Disasm, "must progress past Raw");
        assert_ne!(
            out.envelope, zip_bytes,
            "must not echo input bytes (self-cycling no-op regression)"
        );
        let manifest: &str = std::str::from_utf8(&out.envelope).expect("utf8 manifest");
        assert!(manifest.contains("format=zip"), "manifest: {manifest}");
        assert!(manifest.contains("entries=2"), "manifest: {manifest}");
        assert!(manifest.contains("a.txt\tbytes=5"), "manifest: {manifest}");
        assert!(
            manifest.contains("dir/b.bin\tbytes=10"),
            "manifest: {manifest}"
        );
    }

    #[test]
    fn pass_output_kind_is_manifest_not_reentrant_container() {
        let zip_bytes: Vec<u8> = synth_zip(&[("a.txt", b"alpha")]);
        let artifact: Artifact = Artifact::new(Rung::Raw, zip_bytes, [0u8; 32]);
        let out: Artifact = CONTAINER_PASS.run(&artifact).expect("runs");
        match CONTAINER_PASS.output_kind(&out) {
            OutputKind::Bytes { format_tag, .. } => {
                assert_eq!(format_tag, MANIFEST_FORMAT_TAG);
            }
            other => panic!("expected manifest bytes, got {other:?}"),
        }
        assert!(
            sniff_container_tag(&out.envelope).is_none(),
            "manifest output must not re-detect as a container (cycle guard)"
        );
    }

    #[test]
    fn pass_rejects_non_container_input() {
        let artifact: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let err: CoreError = CONTAINER_PASS
            .run(&artifact)
            .expect_err("must reject non-container");
        assert!(matches!(err, CoreError::PassFailure(_)));
    }

    #[test]
    fn compressed_container_reports_extraction_required_honestly() {
        let mut gz: Vec<u8> = vec![0x1f, 0x8b, 0x08, 0x00];
        gz.extend(std::iter::repeat_n(0u8, 32));
        let artifact: Artifact = Artifact::new(Rung::Raw, gz, [0u8; 32]);
        let out: Artifact = CONTAINER_PASS.run(&artifact).expect("runs");
        let manifest: &str = std::str::from_utf8(&out.envelope).expect("utf8");
        assert!(manifest.contains("format=gzip"), "manifest: {manifest}");
        assert!(
            manifest.contains("requires-extraction"),
            "compressed container must honestly defer entry listing: {manifest}"
        );
    }
}
