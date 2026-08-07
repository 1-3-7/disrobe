#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER,
    OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

pub const PASS_ID: PassId = "binfmt.container";

const TAG_ASAR: &str = "asar";
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
const TAG_SQUASHFS: &str = "squashfs";
const TAG_DOTNET_SINGLE_FILE: &str = "dotnet-single-file";

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
                tag_specificity(t),
                vec![tag_marker(t)],
                format!("container format: {t}"),
            )
        })
    }
}

const SPECIFICITY_PREFIX_MAGIC: u16 = 50;
const SPECIFICITY_VERIFIED_SIGNATURE: u16 = 20;

const fn tag_specificity(tag: &str) -> u16 {
    if matches!(tag.as_bytes(), b"dotnet-single-file") {
        SPECIFICITY_VERIFIED_SIGNATURE
    } else {
        SPECIFICITY_PREFIX_MAGIC
    }
}

const fn tag_marker(tag: &str) -> &'static str {
    if matches!(tag.as_bytes(), b"dotnet-single-file") {
        "bundle-signature+header"
    } else {
        "container-magic"
    }
}

#[derive(Debug)]
pub struct ContainerPass;

impl Pass for ContainerPass {
    #[inline]
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        META
    }
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
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn extract_children(&self, input: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: &[u8] = input.envelope.as_slice();
        let Some(tag): Option<&'static str> = sniff_container_tag(bytes) else {
            return Ok(Vec::new());
        };
        let members: Vec<(String, Vec<u8>)> =
            extract_members(tag, bytes).map_err(|e: CoreError| match e {
                CoreError::PassFailure(msg) => CoreError::PassFailure(format!(
                    "DR-BINFMT-0903: binfmt.container extract: {msg}"
                )),
                other @ CoreError::RungMismatch { .. } => other,
            })?;
        let children: Vec<ChildArtifact> = members
            .into_iter()
            .enumerate()
            .map(
                |(index, (name, data)): (usize, (String, Vec<u8>))| ChildArtifact {
                    handle: ChildHandle {
                        artifact_index: u32::try_from(index).map_or(u32::MAX, |value: u32| value),
                        relative_path: name,
                        hint: Some(tag.to_string()),
                    },
                    bytes: data,
                },
            )
            .collect();
        Ok(children)
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
                "DR-BINFMT-0901: binfmt.container: input is not a recognized container".to_string(),
            ));
        }
        let Some(tag): Option<&'static str> = sniff_container_tag(bytes) else {
            return Err(CoreError::PassFailure(
                "DR-BINFMT-0901: binfmt.container: input is not a recognized container".to_string(),
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

pub const META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    PASS_ID,
    disrobe_core::chain::Ecosystem::Container,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static CONTAINER_PASS: ContainerPass = ContainerPass;

fn render_container_manifest(tag: &str, bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(256);
    push_line(&mut s, "binfmt.container");
    push_line(&mut s, &format!("format={tag} size={}", bytes.len()));
    match inventory_entries(tag, bytes) {
        Inventory::Listed(entries) => {
            push_line(
                &mut s,
                &format!("entries={} listing=read-only", entries.len()),
            );
            for (name, entry_size) in &entries {
                push_line(&mut s, &format!("{name}\tbytes={entry_size}"));
            }
        }
        Inventory::ExtractionRequired => {
            push_line(
                &mut s,
                "entries=unlisted listing=requires-extraction (run `disrobe extract` for full entry decode)",
            );
        }
        Inventory::Unreadable(reason) => {
            push_line(&mut s, &format!("entries=unreadable reason={reason}"));
        }
    }
    s
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
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
    let count: usize = archive.len();
    if count > crate::quota::DEFAULT_MAX_ENTRIES {
        return Inventory::Unreadable(format!(
            "zip entry count {count} exceeds cap {}",
            crate::quota::DEFAULT_MAX_ENTRIES
        ));
    }
    let mut entries: Vec<(String, u64)> = Vec::with_capacity(count);
    for i in 0..count {
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
    tar_inventory_with_cap(bytes, crate::quota::DEFAULT_MAX_ENTRIES)
}

fn tar_inventory_with_cap(bytes: &[u8], max_entries: usize) -> Inventory {
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
        if entries.len() >= max_entries {
            return Inventory::Unreadable(format!("tar entry count exceeds cap {max_entries}"));
        }
        let name: String = match entry.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => return Inventory::Unreadable(e.to_string()),
        };
        entries.push((name, entry.size()));
    }
    Inventory::Listed(entries)
}

const MAX_MEMBER_COUNT: usize = 100_000;
const MAX_MEMBER_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_STREAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn extract_members(tag: &str, bytes: &[u8]) -> CoreResult<Vec<(String, Vec<u8>)>> {
    match tag {
        TAG_ZIP => extract_zip_members(bytes),
        TAG_TAR => extract_tar_members(bytes),
        TAG_GZIP => extract_single_stream(bytes, "gzip", decode_gzip),
        TAG_XZ => extract_single_stream(bytes, "xz", decode_xz),
        TAG_ZSTD => extract_single_stream(bytes, "zstd", decode_zstd),
        TAG_BZIP2 => extract_single_stream(bytes, "bz2", decode_bzip2),
        TAG_DOTNET_SINGLE_FILE => extract_dotnet_single_file_members(bytes),
        _ => Ok(Vec::new()),
    }
}

fn extract_dotnet_single_file_members(bytes: &[u8]) -> CoreResult<Vec<(String, Vec<u8>)>> {
    let entries: Vec<crate::containers::DotnetBundleEntry> =
        crate::containers::extract_dotnet_bundle(
            bytes,
            crate::quota::ExtractionQuota::default_safe(),
        )
        .map_err(|e: crate::error::Error| {
            CoreError::PassFailure(format!("dotnet single-file bundle: {e}"))
        })?;
    Ok(entries
        .into_iter()
        .map(|entry: crate::containers::DotnetBundleEntry| (entry.relative_path, entry.data))
        .collect())
}

const fn fail(msg: String) -> CoreError {
    CoreError::PassFailure(msg)
}

fn read_capped<R: std::io::Read>(
    reader: &mut R,
    max_bytes: u64,
    capacity: usize,
    context: &str,
) -> CoreResult<Vec<u8>> {
    use std::io::Read as _;

    let mut data: Vec<u8> = Vec::with_capacity(capacity);
    let mut limited: std::io::Take<&mut R> = reader.take(max_bytes.saturating_add(1));
    limited
        .read_to_end(&mut data)
        .map_err(|e: std::io::Error| fail(format!("{context}: {e}")))?;
    let actual: u64 = u64::try_from(data.len())
        .map_err(|_| fail(format!("{context}: output length is not addressable")))?;
    if actual > max_bytes {
        return Err(fail(format!("{context}: output exceeds {max_bytes} bytes")));
    }
    Ok(data)
}

fn extract_zip_members(bytes: &[u8]) -> CoreResult<Vec<(String, Vec<u8>)>> {
    let mut archive: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|e: zip::result::ZipError| fail(format!("zip open: {e}")))?;
    let count: usize = archive.len();
    if count > MAX_MEMBER_COUNT {
        return Err(fail(format!("zip member count {count} exceeds cap")));
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::with_capacity(count);
    for i in 0..count {
        let mut file: zip::read::ZipFile<'_> = archive
            .by_index(i)
            .map_err(|e: zip::result::ZipError| fail(format!("zip entry {i}: {e}")))?;
        if file.is_dir() {
            continue;
        }
        let name: String = file.name().to_owned();
        let declared: u64 = file.size();
        if declared > MAX_MEMBER_BYTES {
            return Err(fail(format!(
                "zip entry `{name}` declares {declared} bytes, over cap"
            )));
        }
        let context: String = format!("zip entry `{name}` read");
        let data: Vec<u8> = read_capped(
            &mut file,
            MAX_MEMBER_BYTES,
            crate::quota::bounded_prealloc(declared),
            &context,
        )?;
        out.push((name, data));
    }
    Ok(out)
}

fn extract_tar_members(bytes: &[u8]) -> CoreResult<Vec<(String, Vec<u8>)>> {
    let mut archive: tar::Archive<std::io::Cursor<&[u8]>> =
        tar::Archive::new(std::io::Cursor::new(bytes));
    let raw_entries: tar::Entries<'_, std::io::Cursor<&[u8]>> = archive
        .entries()
        .map_err(|e: std::io::Error| fail(format!("tar entries: {e}")))?;
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for entry_result in raw_entries {
        let mut entry: tar::Entry<'_, std::io::Cursor<&[u8]>> =
            entry_result.map_err(|e: std::io::Error| fail(format!("tar entry: {e}")))?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        if out.len() >= MAX_MEMBER_COUNT {
            return Err(fail("tar member count exceeds cap".to_owned()));
        }
        let name: String = entry
            .path()
            .map_err(|e: std::io::Error| fail(format!("tar path: {e}")))?
            .to_string_lossy()
            .into_owned();
        let declared: u64 = entry.size();
        if declared > MAX_MEMBER_BYTES {
            return Err(fail(format!(
                "tar entry `{name}` declares {declared} bytes, over cap"
            )));
        }
        let context: String = format!("tar entry `{name}` read");
        let data: Vec<u8> = read_capped(
            &mut entry,
            MAX_MEMBER_BYTES,
            crate::quota::bounded_prealloc(declared),
            &context,
        )?;
        out.push((name, data));
    }
    Ok(out)
}

fn extract_single_stream(
    bytes: &[u8],
    suffix: &str,
    decode: fn(&[u8]) -> CoreResult<Vec<u8>>,
) -> CoreResult<Vec<(String, Vec<u8>)>> {
    let data: Vec<u8> = decode(bytes)?;
    let name: String = stream_member_name(suffix);
    Ok(vec![(name, data)])
}

fn stream_member_name(suffix: &str) -> String {
    format!("payload.{suffix}.out")
}

fn decode_gzip(bytes: &[u8]) -> CoreResult<Vec<u8>> {
    let mut decoder: flate2::read::MultiGzDecoder<&[u8]> = flate2::read::MultiGzDecoder::new(bytes);
    read_capped(
        &mut decoder,
        MAX_STREAM_BYTES,
        crate::quota::bounded_prealloc(bytes.len() as u64),
        "gzip decode",
    )
}

fn decode_xz(bytes: &[u8]) -> CoreResult<Vec<u8>> {
    let mut decoder: liblzma::read::XzDecoder<&[u8]> = liblzma::read::XzDecoder::new(bytes);
    read_capped(
        &mut decoder,
        MAX_STREAM_BYTES,
        crate::quota::bounded_prealloc(bytes.len() as u64),
        "xz decode",
    )
}

fn decode_zstd(bytes: &[u8]) -> CoreResult<Vec<u8>> {
    let mut decoder: zstd::stream::read::Decoder<'_, std::io::BufReader<&[u8]>> =
        zstd::stream::read::Decoder::new(bytes)
            .map_err(|e: std::io::Error| fail(format!("zstd init: {e}")))?;
    read_capped(
        &mut decoder,
        MAX_STREAM_BYTES,
        crate::quota::bounded_prealloc(bytes.len() as u64),
        "zstd decode",
    )
}

fn decode_bzip2(bytes: &[u8]) -> CoreResult<Vec<u8>> {
    let mut decoder: bzip2_rs::DecoderReader<&[u8]> = bzip2_rs::DecoderReader::new(bytes);
    read_capped(
        &mut decoder,
        MAX_STREAM_BYTES,
        crate::quota::bounded_prealloc(bytes.len() as u64),
        "bzip2 decode",
    )
}

fn looks_like_asar(bytes: &[u8]) -> bool {
    const JSON_START: usize = 16usize;
    if bytes.len() < 32 {
        return false;
    }
    let pickle_len: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if pickle_len != 4 {
        return false;
    }
    let header_size: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if header_size < 8 {
        return false;
    }
    bytes.len() > JSON_START && bytes[JSON_START..].starts_with(b"{\"files\":")
}

fn sniff_container_tag(bytes: &[u8]) -> Option<&'static str> {
    if looks_like_asar(bytes) {
        return Some(TAG_ASAR);
    }
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
    if crate::containers::squashfs::parse_squashfs_superblock(bytes, 0).is_ok() {
        return Some(TAG_SQUASHFS);
    }
    if crate::containers::detect_dotnet_bundle(bytes).is_some() {
        return Some(TAG_DOTNET_SINGLE_FILE);
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

    fn synth_asar_header(json: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(16 + json.len());
        out.extend_from_slice(&4u32.to_le_bytes());
        let header_size: u32 = u32::try_from(json.len()).unwrap() + 8u32;
        out.extend_from_slice(&header_size.to_le_bytes());
        out.extend_from_slice(&u32::try_from(json.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&u32::try_from(json.len()).unwrap().to_le_bytes());
        out.extend_from_slice(json);
        out
    }

    #[test]
    fn detects_asar_before_zip() {
        let bytes: Vec<u8> = synth_asar_header(b"{\"files\":{\"index.js\":{}}}");
        assert_eq!(sniff_container_tag(&bytes), Some(TAG_ASAR));
        let v: DetectVerdict = ContainerDetector.detect(&ctx(&bytes)).expect("asar detect");
        assert_eq!(v.format_tag, TAG_ASAR);
    }

    #[test]
    fn plain_zip_still_detects_zip_not_asar() {
        assert_eq!(sniff_container_tag(b"PK\x03\x04rest-of-zip"), Some(TAG_ZIP));
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

    fn synth_stored_zip(name: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut zw: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zw.start_file(name, opts).expect("start");
        zw.write_all(body).expect("write");
        zw.finish().expect("finish").into_inner()
    }

    fn patch_first_u32(bytes: &mut [u8], signature: &[u8], field_offset: usize, value: u32) {
        let start: usize = bytes
            .windows(signature.len())
            .position(|w: &[u8]| w == signature)
            .expect("signature present");
        let at: usize = start + field_offset;
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn zip_member_declaring_4gib_does_not_prereserve_gigabytes() {
        const NEAR_4GIB: u64 = 0xFFFF_FFF0;
        const REAL_BODY: &[u8] = b"tiny actual payload";
        let mut zip_bytes: Vec<u8> = synth_stored_zip("bomb.bin", REAL_BODY);
        patch_first_u32(&mut zip_bytes, b"PK\x03\x04", 22, NEAR_4GIB as u32);
        patch_first_u32(&mut zip_bytes, b"PK\x01\x02", 24, NEAR_4GIB as u32);

        let clamped: usize = crate::quota::bounded_prealloc(NEAR_4GIB);
        assert!(
            (clamped as u64) < NEAR_4GIB,
            "prealloc hint {clamped} must be clamped far below the declared {NEAR_4GIB}"
        );

        let members: Vec<(String, Vec<u8>)> = match extract_members(TAG_ZIP, &zip_bytes) {
            Ok(m) => m,
            Err(_) => return,
        };
        for (name, data) in &members {
            assert!(
                (data.len() as u64) < NEAR_4GIB && data.capacity() <= clamped.max(data.len()),
                "member `{name}` must be bounded, not gigabytes: len={} cap={}",
                data.len(),
                data.capacity()
            );
        }
    }

    #[test]
    fn capped_reader_rejects_output_past_limit() {
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abcd");
        let err: CoreError = read_capped(&mut cursor, 3, 0, "cap test").expect_err("over cap");
        assert!(matches!(err, CoreError::PassFailure(_)));
    }

    #[test]
    fn capped_reader_accepts_exact_limit() {
        let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(b"abc");
        let out: Vec<u8> = read_capped(&mut cursor, 3, 0, "cap test").expect("exact cap");
        assert_eq!(out, b"abc");
    }

    #[test]
    fn tar_inventory_rejects_entry_count_over_cap() {
        let tar_bytes: Vec<u8> = synth_tar(&[("a.txt", b"a"), ("b.txt", b"b")]);
        let inventory: Inventory = tar_inventory_with_cap(&tar_bytes, 1);
        let Inventory::Unreadable(reason) = inventory else {
            panic!("expected unreadable cap result");
        };
        assert!(
            reason.contains("tar entry count exceeds cap 1"),
            "reason: {reason}"
        );
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
    fn pass_output_kind_is_mixed_so_chain_extracts_children() {
        let zip_bytes: Vec<u8> = synth_zip(&[("a.txt", b"alpha")]);
        let artifact: Artifact = Artifact::new(Rung::Raw, zip_bytes, [0u8; 32]);
        let out: Artifact = CONTAINER_PASS.run(&artifact).expect("runs");
        assert!(
            CONTAINER_PASS.output_kind(&out).is_mixed(),
            "container pass must report Mixed so the chain runner harvests members"
        );
        assert!(
            sniff_container_tag(&out.envelope).is_none(),
            "manifest output must not re-detect as a container (cycle guard)"
        );
    }

    #[test]
    fn extract_children_carves_each_zip_member_with_correct_bytes() {
        let zip_bytes: Vec<u8> = synth_zip(&[
            ("a.txt", b"alpha"),
            ("dir/b.bin", b"bravobravo"),
            ("c", b""),
        ]);
        let artifact: Artifact = Artifact::new(Rung::Raw, zip_bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract children");
        assert_eq!(children.len(), 3, "one child per non-dir member");
        let by_name = |name: &str| -> &ChildArtifact {
            children
                .iter()
                .find(|c: &&ChildArtifact| c.handle.relative_path == name)
                .unwrap_or_else(|| panic!("member {name} missing"))
        };
        assert_eq!(by_name("a.txt").bytes, b"alpha");
        assert_eq!(by_name("dir/b.bin").bytes, b"bravobravo");
        assert_eq!(by_name("c").bytes, b"");
        for child in &children {
            assert_eq!(child.handle.hint.as_deref(), Some("zip"));
        }
    }

    fn synth_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder: tar::Builder<Vec<u8>> = tar::Builder::new(Vec::new());
        for (name, body) in files {
            let mut header: tar::Header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *body)
                .expect("tar append");
        }
        builder.into_inner().expect("tar finish")
    }

    #[test]
    fn extract_children_carves_each_tar_member_with_correct_bytes() {
        let tar_bytes: Vec<u8> = synth_tar(&[
            ("one.txt", b"first member"),
            ("nested/two.dat", b"second-member-bytes"),
        ]);
        let artifact: Artifact = Artifact::new(Rung::Raw, tar_bytes, [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract tar children");
        assert_eq!(children.len(), 2);
        let one: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "one.txt")
            .expect("one.txt");
        assert_eq!(one.bytes, b"first member");
        let two: &ChildArtifact = children
            .iter()
            .find(|c: &&ChildArtifact| c.handle.relative_path == "nested/two.dat")
            .expect("nested/two.dat");
        assert_eq!(two.bytes, b"second-member-bytes");
    }

    #[test]
    fn extract_children_decodes_gzip_single_stream_to_original_bytes() {
        use std::io::Write as _;
        let original: &[u8] = b"gzip single-stream payload that round-trips exactly 0123456789";
        let mut enc: flate2::write::GzEncoder<Vec<u8>> =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).expect("gz write");
        let gz: Vec<u8> = enc.finish().expect("gz finish");
        let artifact: Artifact = Artifact::new(Rung::Raw, gz, [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract gzip child");
        assert_eq!(children.len(), 1);
        assert_eq!(
            children[0].bytes, original,
            "gzip child must equal original"
        );
    }

    #[test]
    fn extract_children_returns_empty_for_non_container() {
        let artifact: Artifact = Artifact::new(Rung::Raw, vec![0u8; 64], [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("non-container yields no children");
        assert!(children.is_empty());
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
