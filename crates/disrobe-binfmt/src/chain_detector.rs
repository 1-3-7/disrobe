#![cfg(feature = "chain")]
#![allow(clippy::module_name_repetitions)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{
    ChildArtifact, ChildHandle, DetectContext, DetectVerdict, Detector, FAMILY_CONTAINER,
    FAMILY_NATIVE_FORMAT, OutputKind, Pass,
};
use disrobe_core::error::{CoreError, Result as CoreResult};
use disrobe_core::pass::PassId;

pub const PASS_ID: PassId = "binfmt.container";
pub const NE_PASS_ID: PassId = "native.ne-structure";

#[derive(Debug)]
pub struct NeDetector;

impl Detector for NeDetector {
    fn id(&self) -> PassId {
        NE_PASS_ID
    }

    fn detect(&self, ctx: &DetectContext<'_>) -> Option<DetectVerdict> {
        let parsed: crate::NativeFile = crate::parse_native(ctx.bytes).ok()?;
        if !matches!(
            parsed.format,
            crate::ParsedNativeFormat::NeWindows | crate::ParsedNativeFormat::NeOs2
        ) {
            return None;
        }
        Some(DetectVerdict::new(
            NE_PASS_ID,
            parsed.format.label(),
            FAMILY_NATIVE_FORMAT,
            1.0,
            10,
            vec!["mz-ne-header+validated-tables"],
            "parsed 16-bit new executable structure".to_owned(),
        ))
    }
}

#[derive(Debug)]
pub struct NePass;

impl Pass for NePass {
    fn meta(&self) -> disrobe_core::chain::PassMeta {
        NE_META
    }

    fn id(&self) -> PassId {
        NE_PASS_ID
    }

    fn detector(&self) -> &'static dyn Detector {
        &NeDetector
    }

    fn output_kind(&self, _output: &Artifact) -> OutputKind {
        OutputKind::Mixed {
            children: Vec::new(),
        }
    }

    fn run(&self, artifact: &Artifact) -> CoreResult<Artifact> {
        let bytes: Vec<u8> = render_ne(artifact)?;
        Ok(Artifact::new(Rung::Disasm, bytes, artifact.root_hash))
    }

    fn extract_children(&self, artifact: &Artifact) -> CoreResult<Vec<ChildArtifact>> {
        let bytes: Vec<u8> = render_ne(artifact)?;
        Ok(vec![ChildArtifact {
            handle: ChildHandle {
                artifact_index: 0,
                relative_path: "ne-structure.json".to_owned(),
                hint: Some(disrobe_core::chain::detection::TERMINAL_HINT.to_owned()),
            },
            bytes,
        }])
    }
}

fn render_ne(artifact: &Artifact) -> CoreResult<Vec<u8>> {
    let parsed: crate::NativeFile =
        crate::parse_native(&artifact.envelope).map_err(|error: crate::Error| {
            CoreError::PassFailure(format!("DR-BINFMT-0904: native.ne-structure: {error}"))
        })?;
    if !matches!(
        parsed.format,
        crate::ParsedNativeFormat::NeWindows | crate::ParsedNativeFormat::NeOs2
    ) {
        return Err(CoreError::PassFailure(
            "DR-BINFMT-0905: native.ne-structure: input is not a parsed NE file".to_owned(),
        ));
    }
    serde_json::to_vec_pretty(&parsed).map_err(|error: serde_json::Error| {
        CoreError::PassFailure(format!("DR-BINFMT-0906: native.ne-structure: {error}"))
    })
}

pub const NE_META: disrobe_core::chain::PassMeta = disrobe_core::chain::PassMeta::new(
    NE_PASS_ID,
    disrobe_core::chain::Ecosystem::Native,
    disrobe_core::chain::SupportQuality::Full,
    disrobe_core::chain::Determinism::Deterministic,
    disrobe_core::chain::SafetyClass::Static,
);

pub static NE_PASS: NePass = NePass;

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
const TAG_RPM: &str = "rpm";
const TAG_ARC: &str = "arc";
const TAG_ARJ: &str = "arj";
const TAG_LZH: &str = "lzh";
const TAG_STUFFIT: &str = "stuffit";
const TAG_INNOSETUP: &str = "inno-setup";
const TAG_APPIMAGE: &str = "appimage";
const TAG_ISO: &str = "iso";
const TAG_SQUASHFS: &str = "squashfs";
const TAG_DOTNET_SINGLE_FILE: &str = "dotnet-single-file";
const TAG_UEFI_FV: &str = "uefi-fv";
const TAG_EROFS: &str = "erofs";
const TAG_INSTALLSHIELD: &str = "installshield";

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
    if matches!(
        tag.as_bytes(),
        b"dotnet-single-file"
            | b"inno-setup"
            | b"appimage"
            | b"uefi-fv"
            | b"erofs"
            | b"installshield"
    ) {
        SPECIFICITY_VERIFIED_SIGNATURE
    } else {
        SPECIFICITY_PREFIX_MAGIC
    }
}

const fn tag_marker(tag: &str) -> &'static str {
    match tag.as_bytes() {
        b"dotnet-single-file" => "bundle-signature+header",
        b"inno-setup" => "pe-resource+setup-data-header",
        b"appimage" => "elf+validated-filesystem",
        b"uefi-fv" => "fv-header+checksum",
        b"erofs" => "superblock+root-inode",
        b"installshield" => "isc-signature+cabinet-descriptor",
        _ => "container-magic",
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
        let extraction: MemberExtraction =
            extract_members(tag, bytes).map_err(|e: CoreError| match e {
                CoreError::PassFailure(msg) => CoreError::PassFailure(format!(
                    "DR-BINFMT-0903: binfmt.container extract: {msg}"
                )),
                other @ CoreError::RungMismatch { .. } => other,
            })?;
        let children: Vec<ChildArtifact> = extraction
            .members
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

    fn chain_refusals(&self, artifact: &Artifact) -> CoreResult<Vec<String>> {
        let Some(tag): Option<&'static str> = sniff_container_tag(&artifact.envelope) else {
            return Ok(Vec::new());
        };
        Ok(extract_members(tag, &artifact.envelope)?.refusals)
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
    if let Ok(extraction) = extract_members(tag, bytes) {
        for refusal in extraction.refusals {
            push_line(&mut s, &format!("refusal={refusal}"));
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
        TAG_ARC => arc_inventory(bytes),
        TAG_ARJ => arj_inventory(bytes),
        TAG_INSTALLSHIELD => installshield_inventory(bytes),
        _ => Inventory::ExtractionRequired,
    }
}

fn arj_inventory(bytes: &[u8]) -> Inventory {
    let archive: crate::containers::ArjArchive =
        match crate::containers::arj::parse_arj_with_entry_limit(bytes, MAX_MEMBER_COUNT) {
            Ok(archive) => archive,
            Err(error) => return Inventory::Unreadable(error.to_string()),
        };
    Inventory::Listed(
        archive
            .entries
            .into_iter()
            .map(|entry: crate::containers::ArjEntry| (entry.name, u64::from(entry.original_size)))
            .collect(),
    )
}

fn arc_inventory(bytes: &[u8]) -> Inventory {
    let archive: crate::containers::ArcArchive =
        match crate::containers::arc::parse_arc_with_entry_limit(bytes, MAX_MEMBER_COUNT) {
            Ok(archive) => archive,
            Err(error) => return Inventory::Unreadable(error.to_string()),
        };
    Inventory::Listed(
        archive
            .entries
            .into_iter()
            .map(|entry: crate::containers::ArcEntry| (entry.name, u64::from(entry.original_size)))
            .collect(),
    )
}

fn installshield_inventory(bytes: &[u8]) -> Inventory {
    let defaults: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota::default_safe();
    let quota: crate::quota::ExtractionQuota = crate::quota::ExtractionQuota {
        max_aggregate_ratio: defaults.max_aggregate_ratio.max(1000),
        max_per_entry_ratio: defaults.max_per_entry_ratio.max(1000),
        ..defaults
    };
    match crate::containers::walk_installshield(bytes, quota) {
        Ok(archive) => Inventory::Listed(
            archive
                .recovered()
                .map(|file: &crate::containers::InstallShieldFile| {
                    (file.path.clone(), file.expanded_size)
                })
                .collect(),
        ),
        Err(error) => Inventory::Unreadable(error.to_string()),
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
const MAX_STREAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug)]
struct MemberExtraction {
    members: Vec<(String, Vec<u8>)>,
    refusals: Vec<String>,
}

impl MemberExtraction {
    const fn complete(members: Vec<(String, Vec<u8>)>) -> Self {
        Self {
            members,
            refusals: Vec::new(),
        }
    }
}

fn extract_members(tag: &str, bytes: &[u8]) -> CoreResult<MemberExtraction> {
    match tag {
        TAG_ZIP
        | TAG_TAR
        | TAG_RAR
        | TAG_RPM
        | TAG_ARC
        | TAG_ARJ
        | TAG_LZH
        | TAG_STUFFIT
        | TAG_INNOSETUP
        | TAG_INSTALLSHIELD
        | TAG_APPIMAGE
        | TAG_DOTNET_SINGLE_FILE
        | TAG_UEFI_FV
        | TAG_EROFS => extract_members_with_direct_policy(tag, bytes),
        TAG_GZIP => {
            extract_single_stream(bytes, "gzip", decode_gzip).map(MemberExtraction::complete)
        }
        TAG_XZ => extract_single_stream(bytes, "xz", decode_xz).map(MemberExtraction::complete),
        TAG_ZSTD => {
            extract_single_stream(bytes, "zstd", decode_zstd).map(MemberExtraction::complete)
        }
        TAG_BZIP2 => {
            extract_single_stream(bytes, "bz2", decode_bzip2).map(MemberExtraction::complete)
        }
        _ => Ok(MemberExtraction::complete(Vec::new())),
    }
}

fn extract_members_with_direct_policy(tag: &str, bytes: &[u8]) -> CoreResult<MemberExtraction> {
    let kind: crate::container::ContainerKind = match tag {
        TAG_ZIP => crate::container::ContainerKind::Zip,
        TAG_TAR => crate::container::ContainerKind::Tar,
        TAG_RAR => crate::container::ContainerKind::Rar,
        TAG_RPM => crate::container::ContainerKind::Rpm,
        TAG_ARC => crate::container::ContainerKind::Arc,
        TAG_ARJ => crate::container::ContainerKind::Arj,
        TAG_LZH => crate::container::ContainerKind::Lzh,
        TAG_STUFFIT => crate::container::ContainerKind::StuffIt,
        TAG_INNOSETUP => crate::container::ContainerKind::InnoSetup,
        TAG_INSTALLSHIELD => crate::container::ContainerKind::InstallShield,
        TAG_APPIMAGE => crate::container::ContainerKind::AppImage,
        TAG_DOTNET_SINGLE_FILE => crate::container::ContainerKind::DotnetSingleFile,
        TAG_UEFI_FV => crate::container::ContainerKind::UefiFv,
        TAG_EROFS => crate::container::ContainerKind::Erofs,
        _ => return Ok(MemberExtraction::complete(Vec::new())),
    };
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-chain-extract")
            .map_err(|error: std::io::Error| fail(format!("{tag} scratch: {error}")))?;
    let result: crate::extract::ExtractionResult = crate::extract::extract_to_with_quota(
        kind,
        bytes,
        scratch.path(),
        crate::quota::ExtractionQuota::default_safe(),
    )
    .map_err(|error: crate::error::Error| fail(format!("{tag} payload: {error}")))?;
    let mut members: Vec<(String, Vec<u8>)> = Vec::with_capacity(result.entries.len());
    for entry in result.entries {
        if entry.origin == crate::extract::ExtractedEntryOrigin::GeneratedSidecar {
            continue;
        }
        let Some(path) = entry.disk_path else {
            continue;
        };
        let data: Vec<u8> = std::fs::read(&path).map_err(|error: std::io::Error| {
            fail(format!("{tag} member `{}` read: {error}", entry.name))
        })?;
        members.push((entry.name, data));
    }
    Ok(MemberExtraction {
        members,
        refusals: result.integrity_violations,
    })
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
    if bytes.starts_with(&[0xed, 0xab, 0xee, 0xdb]) {
        return Some(TAG_RPM);
    }
    if crate::containers::detect_arj(bytes) {
        return Some(TAG_ARJ);
    }
    if crate::containers::arc::parse_arc_with_entry_limit(bytes, MAX_MEMBER_COUNT).is_ok() {
        return Some(TAG_ARC);
    }
    if crate::containers::detect_lzh(bytes) {
        return Some(TAG_LZH);
    }
    if crate::containers::detect_stuffit(bytes).is_some() {
        return Some(TAG_STUFFIT);
    }
    if crate::containers::detect_innosetup(bytes).is_some() {
        return Some(TAG_INNOSETUP);
    }
    if crate::containers::detect_installshield(bytes).is_some() {
        return Some(TAG_INSTALLSHIELD);
    }
    if crate::containers::detect_uefi_fv(bytes) {
        return Some(TAG_UEFI_FV);
    }
    if crate::containers::erofs::validate_erofs_image(bytes) {
        return Some(TAG_EROFS);
    }
    if crate::containers::detect_appimage(bytes).is_some() {
        return Some(TAG_APPIMAGE);
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

    const REAL_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_ne.exe");
    const REAL_OS2_NE: &[u8] = include_bytes!("../../../corpus/native/formats/hello_os2_ne.exe");
    const REAL_LZH_LEVEL3: &[u8] = include_bytes!("../tests/fixtures/lzh/level3/h3_subdir.lzh");
    const REAL_RAR3_FILTER: &[u8] = include_bytes!("../../../corpus/binfmt/rar/filter-e8-rar3.rar");
    const REAL_STUFFIT: &[u8] = include_bytes!("../tests/fixtures/stuffit/stuffit45-method13.sit");
    const REAL_INNOSETUP: &[u8] = include_bytes!("../tests/fixtures/innosetup/innosetup-6.3.3.exe");
    const REAL_EROFS: &[u8] = include_bytes!("../tests/fixtures/erofs/lzma-compact-mixed.erofs");

    fn ctx(bytes: &[u8]) -> DetectContext<'_> {
        DetectContext {
            bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        }
    }

    #[test]
    fn a_filtered_rar3_member_reaches_the_container_chain() {
        assert_eq!(sniff_container_tag(REAL_RAR3_FILTER), Some(TAG_RAR));
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_RAR, REAL_RAR3_FILTER)
            .expect("extract rar3 filter members")
            .members;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, "bsdcat.exe");
        assert_eq!(members[0].1.len(), 204_288);
        assert_eq!(
            crc32fast::hash(&members[0].1),
            0x4db1_0349,
            "the chain must publish the bytes the archive header declares"
        );
    }

    #[test]
    fn the_container_chain_publishes_the_bytes_direct_extraction_publishes() {
        let archive: crate::containers::RarArchive =
            crate::containers::rar::parse_rar(REAL_RAR3_FILTER).expect("parse rar");
        let entry: &crate::containers::RarEntry = archive
            .entries
            .iter()
            .find(|candidate: &&crate::containers::RarEntry| !candidate.is_dir)
            .expect("one file member");
        let direct: Vec<u8> = crate::containers::rar_entry_bytes(REAL_RAR3_FILTER, entry, 1 << 30)
            .expect("direct extraction");
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_RAR, REAL_RAR3_FILTER)
            .expect("chain extraction")
            .members;
        assert_eq!(members[0].1, direct);
    }

    #[test]
    fn the_container_pass_emits_the_rar_member_as_a_child_artifact() {
        let artifact: Artifact = Artifact::new(Rung::Raw, REAL_RAR3_FILTER.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("rar child artifacts");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].handle.relative_path, "bsdcat.exe");
        assert_eq!(children[0].handle.hint.as_deref(), Some(TAG_RAR));
        assert_eq!(children[0].bytes.len(), 204_288);
    }

    #[test]
    fn level3_lzh_reaches_the_container_chain() {
        assert_eq!(sniff_container_tag(REAL_LZH_LEVEL3), Some(TAG_LZH));
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_LZH, REAL_LZH_LEVEL3)
            .expect("extract level-3 LZH members")
            .members;
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, "subdir/subdir2/HELLO.TXT");
        assert_eq!(members[0].1, b"hello world!\r\n");
    }

    #[test]
    fn method13_stuffit_reaches_the_container_chain() {
        assert_eq!(sniff_container_tag(REAL_STUFFIT), Some(TAG_STUFFIT));
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_STUFFIT, REAL_STUFFIT)
            .expect("extract StuffIt members")
            .members;
        assert_eq!(members.len(), 9);
        assert!(members.iter().any(|(name, bytes): &(String, Vec<u8>)| {
            name == "testfile.txt" && bytes.len() == 12
        }));
    }

    #[test]
    fn arc_reaches_the_container_chain_with_verified_member_bytes() {
        let archive: Vec<u8> =
            crate::containers::arc::synth_stored_arc("hello.txt", b"verified ARC child bytes")
                .expect("build ARC fixture");
        assert_eq!(sniff_container_tag(&archive), Some(TAG_ARC));
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_ARC, &archive)
            .expect("extract ARC members")
            .members;
        assert_eq!(
            members,
            vec![("hello.txt".to_owned(), b"verified ARC child bytes".to_vec())]
        );
        let manifest: String = render_container_manifest(TAG_ARC, &archive);
        assert!(manifest.contains("entries=1 listing=read-only"));
        assert!(manifest.contains("hello.txt\tbytes=24"));
    }

    #[test]
    fn arc_chain_records_a_bad_member_instead_of_silently_skipping_it() {
        let mut archive: Vec<u8> = crate::containers::arc::build_entry(2, "bad.bin", b"bad", 3);
        archive[23..25].copy_from_slice(&0x1234_u16.to_le_bytes());
        archive.extend_from_slice(&crate::containers::arc::build_entry(
            2,
            "good.bin",
            b"verified",
            8,
        ));
        archive.extend_from_slice(&[crate::containers::arc::ARC_MARKER, 0]);
        let recovery: MemberExtraction =
            extract_members(TAG_ARC, &archive).expect("recover the verified ARC sibling");
        assert_eq!(recovery.members.len(), 1);
        assert_eq!(recovery.members[0].0, "good.bin");
        assert_eq!(recovery.refusals.len(), 1);
        assert!(recovery.refusals[0].contains("bad.bin"));
        assert!(recovery.refusals[0].contains("CRC"));
    }

    #[test]
    fn arc_chain_sniff_requires_a_complete_structural_archive() {
        let truncated: Vec<u8> =
            crate::containers::arc::build_entry(2, "short.bin", b"abc", 3)[..24].to_vec();
        assert!(crate::containers::detect_arc(&truncated));
        assert_ne!(sniff_container_tag(&truncated), Some(TAG_ARC));
    }

    #[test]
    fn detector_id_is_stable() {
        assert_eq!(ContainerDetector.id(), PASS_ID);
    }

    #[test]
    fn ne_pass_reaches_real_win16_structure() {
        let verdict: DetectVerdict = NeDetector.detect(&ctx(REAL_NE)).expect("NE detect");
        assert_eq!(verdict.pass_id, NE_PASS_ID);
        assert_eq!(verdict.format_tag, "ne");

        let artifact: Artifact = Artifact::new(Rung::Raw, REAL_NE.to_vec(), [0u8; 32]);
        let output: Artifact = NE_PASS.run(&artifact).expect("NE pass");
        let parsed: crate::NativeFile =
            serde_json::from_slice(&output.envelope).expect("NE structure JSON");
        assert_eq!(parsed.format, crate::ParsedNativeFormat::NeWindows);
        assert_eq!(parsed.segments.len(), 2);
        assert!(
            parsed
                .imports
                .iter()
                .any(|import: &crate::ImportInfo| import.library == "KERNEL")
        );

        let children: Vec<ChildArtifact> = NE_PASS
            .extract_children(&artifact)
            .expect("NE structure child");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].handle.relative_path, "ne-structure.json");
        assert_eq!(children[0].bytes, output.envelope);
    }

    #[test]
    fn ne_detector_rejects_non_ne_mz() {
        let mut bytes: Vec<u8> = vec![0u8; 0x80];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x42].copy_from_slice(b"PE");
        assert!(NeDetector.detect(&ctx(&bytes)).is_none());
    }

    #[test]
    fn ne_pass_reaches_real_os2_structure() {
        let verdict: DetectVerdict = NeDetector
            .detect(&ctx(REAL_OS2_NE))
            .expect("OS/2 NE detect");
        assert_eq!(verdict.pass_id, NE_PASS_ID);
        let artifact: Artifact = Artifact::new(Rung::Raw, REAL_OS2_NE.to_vec(), [0u8; 32]);
        let output: Artifact = NE_PASS.run(&artifact).expect("OS/2 NE pass");
        let parsed: crate::NativeFile =
            serde_json::from_slice(&output.envelope).expect("OS/2 NE structure JSON");
        assert_eq!(parsed.format, crate::ParsedNativeFormat::NeOs2);
        assert_eq!(parsed.imports.len(), 6);
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
    fn inno_setup_real_members_reach_the_container_pass() {
        assert_eq!(sniff_container_tag(REAL_INNOSETUP), Some(TAG_INNOSETUP));
        let members: Vec<(String, Vec<u8>)> = extract_members(TAG_INNOSETUP, REAL_INNOSETUP)
            .expect("Inno Setup members")
            .members;
        assert_eq!(members.len(), 94);
        let compiler: &(String, Vec<u8>) = members
            .iter()
            .find(|(path, _data): &&(String, Vec<u8>)| path == "app/Compil32.exe")
            .expect("compiler member");
        assert_eq!(compiler.1.len(), 3_940_272);
        assert!(compiler.1.starts_with(b"MZ"));
    }

    #[test]
    fn uefi_brotli_guided_firmware_reaches_the_chain_with_exact_driver_bytes() {
        const FIRMWARE: &[u8] = include_bytes!("../tests/fixtures/uefi_fv/edk2_brotli_guided.fv");
        const DRIVER: &[u8] = include_bytes!("../tests/fixtures/uefi_fv/hello_a.efi");
        assert_eq!(sniff_container_tag(FIRMWARE), Some("uefi-fv"));

        let artifact: Artifact = Artifact::new(Rung::Raw, FIRMWARE.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract UEFI firmware children");
        let driver: &ChildArtifact = children
            .iter()
            .find(|child: &&ChildArtifact| child.handle.relative_path == "BrotliDriver")
            .expect("BrotliDriver chain child");
        assert_eq!(driver.bytes, DRIVER);
    }

    #[test]
    fn compact_erofs_reaches_the_chain_with_exact_regular_file_bytes() {
        use sha2::{Digest as _, Sha256};

        assert_eq!(sniff_container_tag(REAL_EROFS), Some(TAG_EROFS));
        let artifact: Artifact = Artifact::new(Rung::Raw, REAL_EROFS.to_vec(), [0u8; 32]);
        let children: Vec<ChildArtifact> = CONTAINER_PASS
            .extract_children(&artifact)
            .expect("extract erofs children");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].handle.relative_path, "payload.txt");
        assert_eq!(
            format!("{:x}", Sha256::digest(&children[0].bytes)),
            "ff288b1f999038b715ef29b34313251f031250e6f2ad2a0cf4291d832f6b1b20"
        );

        let truncated: &[u8] = &REAL_EROFS[..REAL_EROFS.len() - 4096];
        assert_ne!(sniff_container_tag(truncated), Some(TAG_EROFS));
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
            Ok(m) => m.members,
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
