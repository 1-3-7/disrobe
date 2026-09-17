#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Deserialize;

use disrobe_binfmt::asar;
use disrobe_binfmt::container::{ContainerKind, detect_container};
use disrobe_binfmt::containers::romfs::{RomfsWalk, walk_romfs};
use disrobe_binfmt::containers::squashfs::{SquashfsSuperblock, parse_squashfs_superblock};
use disrobe_binfmt::containers::uzip::{UzipImage, parse_uzip};
use disrobe_binfmt::error::Error;
use disrobe_binfmt::extract::{ExtractionResult, extract_to_with_quota};
use disrobe_binfmt::native_image::parse_native_image;
use disrobe_binfmt::quota::ExtractionQuota;

const MEMBER_WALL_CLOCK_CAP: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_MEMBERS: usize = 4;
const ROMFS_WALK_CAP: u64 = 64 * 1024 * 1024;
const UZIP_PARSE_CAP: u64 = 64 * 1024 * 1024;
const MANIFEST_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Shape {
    TruncatedHeader,
    DeclaredSizeExceedsFile,
    OverlappingSections,
    SelfReferentialOffset,
    CyclicOffset,
    ZeroLengthMember,
    ExpansionRatioBomb,
    DeclaredCountNearTypeMax,
    MagicMatchesBodyIsAnotherFormat,
    ValidButEmpty,
    PathTraversalName,
    UnsupportedDeclaredVersion,
}

const EVERY_SHAPE: [Shape; 12] = [
    Shape::TruncatedHeader,
    Shape::DeclaredSizeExceedsFile,
    Shape::OverlappingSections,
    Shape::SelfReferentialOffset,
    Shape::CyclicOffset,
    Shape::ZeroLengthMember,
    Shape::ExpansionRatioBomb,
    Shape::DeclaredCountNearTypeMax,
    Shape::MagicMatchesBodyIsAnotherFormat,
    Shape::ValidButEmpty,
    Shape::PathTraversalName,
    Shape::UnsupportedDeclaredVersion,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ErrorId {
    AsarHeader,
    AsarOutOfBounds,
    Zip,
    Decompression,
    QuotaExceeded,
    Romfs,
    Uzip,
    NativeParse,
    UnsafeEntryPath,
}

const fn identify(error: &Error) -> Option<ErrorId> {
    match error {
        Error::AsarHeader(_) => Some(ErrorId::AsarHeader),
        Error::AsarOutOfBounds { .. } => Some(ErrorId::AsarOutOfBounds),
        Error::Zip(_) => Some(ErrorId::Zip),
        Error::Decompression(_) => Some(ErrorId::Decompression),
        Error::QuotaExceeded { .. } => Some(ErrorId::QuotaExceeded),
        Error::Romfs(_) => Some(ErrorId::Romfs),
        Error::Uzip(_) => Some(ErrorId::Uzip),
        Error::NativeParse(_) => Some(ErrorId::NativeParse),
        Error::UnsafeEntryPath(_) => Some(ErrorId::UnsafeEntryPath),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OutcomeKind {
    Refuse,
    UnsupportedVersion,
    Partial,
    DetectOnly,
}

const EVERY_OUTCOME_KIND: [OutcomeKind; 4] = [
    OutcomeKind::Refuse,
    OutcomeKind::UnsupportedVersion,
    OutcomeKind::Partial,
    OutcomeKind::DetectOnly,
];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReasonMatch {
    Contains(String),
    Equals(String),
}

impl ReasonMatch {
    fn matches(&self, message: &str) -> bool {
        match self {
            Self::Contains(reason) => message.contains(reason.as_str()),
            Self::Equals(reason) => message == reason,
        }
    }

    fn value(&self) -> &str {
        match self {
            Self::Contains(reason) | Self::Equals(reason) => reason,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case", tag = "outcome")]
enum Outcome {
    Refuse {
        error: ErrorId,
        reason: ReasonMatch,
    },
    UnsupportedVersion {
        error: ErrorId,
        reason: ReasonMatch,
    },
    Partial {
        entries: usize,
        violations: Vec<String>,
    },
    DetectOnly {
        detected_as: String,
        error: ErrorId,
        reason: ReasonMatch,
    },
}

impl Outcome {
    const fn kind(&self) -> OutcomeKind {
        match *self {
            Self::Refuse { .. } => OutcomeKind::Refuse,
            Self::UnsupportedVersion { .. } => OutcomeKind::UnsupportedVersion,
            Self::Partial { .. } => OutcomeKind::Partial,
            Self::DetectOnly { .. } => OutcomeKind::DetectOnly,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Target {
    AsarParse,
    ZipExtract,
    ZipDetectThenExtract,
    RomfsWalk,
    UzipParse,
    NativeImageParse,
    SquashfsSuperblockParse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Builder {
    AsarTruncatedPrefix,
    AsarJsonLengthPastEnd,
    Pe64SectionsOverlap,
    RomfsNodeNextPointsAtItself,
    RomfsDirectoryChildCycle,
    EmptyFile,
    ZipDeclaredRatioBomb,
    UzipBlockCountNearU32Max,
    ZipDeclaredCountNearMax,
    ZipMagicBodyIsElf,
    ZipValidEmptyArchive,
    ZipEntryNameParentTraversal,
    SquashfsUnsupportedMajorVersion,
}

fn build(builder: Builder) -> Vec<u8> {
    match builder {
        Builder::AsarTruncatedPrefix => asar_truncated_prefix(),
        Builder::AsarJsonLengthPastEnd => asar_json_length_past_end(),
        Builder::Pe64SectionsOverlap => pe64_sections_overlap(),
        Builder::RomfsNodeNextPointsAtItself => romfs_node_next_points_at_itself(),
        Builder::RomfsDirectoryChildCycle => romfs_directory_child_cycle(),
        Builder::EmptyFile => Vec::new(),
        Builder::ZipDeclaredRatioBomb => zip_declared_ratio_bomb(),
        Builder::UzipBlockCountNearU32Max => uzip_block_count_near_u32_max(),
        Builder::ZipDeclaredCountNearMax => zip_declared_count_near_max(),
        Builder::ZipMagicBodyIsElf => zip_magic_body_is_elf(),
        Builder::ZipValidEmptyArchive => zip_valid_empty_archive(),
        Builder::ZipEntryNameParentTraversal => zip_entry_name_parent_traversal(),
        Builder::SquashfsUnsupportedMajorVersion => squashfs_unsupported_major_version(),
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    id: String,
    file: String,
    blake3: String,
    shape: Shape,
    target: Target,
    builder: Builder,
    authored_reason: String,
    accepted: Vec<Outcome>,
    multiple_outcome_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    members: Vec<Member>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Observed {
    Refused {
        error: Option<ErrorId>,
        message: String,
    },
    Recovered {
        entries: usize,
        violations: Vec<String>,
    },
    DetectedThenRefused {
        detected_as: String,
        error: Option<ErrorId>,
        message: String,
    },
    DetectedThenRecovered {
        detected_as: String,
        entries: usize,
    },
    NotDetected,
    Panicked {
        payload: String,
    },
}

fn satisfies(expected: &Outcome, observed: &Observed) -> bool {
    match (expected, observed) {
        (
            Outcome::Refuse { error, reason } | Outcome::UnsupportedVersion { error, reason },
            Observed::Refused {
                error: seen,
                message,
            },
        ) => *seen == Some(*error) && reason.matches(message),
        (
            Outcome::Partial {
                entries,
                violations,
            },
            Observed::Recovered {
                entries: seen,
                violations: seen_violations,
            },
        ) => {
            *entries == *seen
                && violations.len() == seen_violations.len()
                && violations
                    .iter()
                    .zip(seen_violations.iter())
                    .all(|(want, have): (&String, &String)| have.contains(want.as_str()))
        }
        (
            Outcome::DetectOnly {
                detected_as,
                error,
                reason,
            },
            Observed::DetectedThenRefused {
                detected_as: seen_kind,
                error: seen,
                message,
            },
        ) => detected_as == seen_kind && *seen == Some(*error) && reason.matches(message),
        _ => false,
    }
}

fn refusal(error: &Error) -> Observed {
    Observed::Refused {
        error: identify(error),
        message: error.to_string(),
    }
}

fn run_target(target: Target, bytes: &[u8], out_dir: &Path) -> Observed {
    match target {
        Target::AsarParse => match asar::parse(bytes) {
            Ok(layout) => Observed::Recovered {
                entries: layout.entries.len(),
                violations: Vec::new(),
            },
            Err(error) => refusal(&error),
        },
        Target::ZipExtract => run_zip_extract(bytes, out_dir),
        Target::ZipDetectThenExtract => {
            let Some(kind): Option<ContainerKind> = detect_container(bytes) else {
                return Observed::NotDetected;
            };
            let detected_as: String = format!("{kind:?}");
            match extract_to_with_quota(kind, bytes, out_dir, ExtractionQuota::default_safe()) {
                Ok(result) => Observed::DetectedThenRecovered {
                    detected_as,
                    entries: result.entries.len(),
                },
                Err(error) => Observed::DetectedThenRefused {
                    detected_as,
                    error: identify(&error),
                    message: error.to_string(),
                },
            }
        }
        Target::RomfsWalk => match walk_romfs(bytes, ROMFS_WALK_CAP) {
            Ok(walk) => {
                let walk: RomfsWalk = walk;
                Observed::Recovered {
                    entries: walk.files.len(),
                    violations: Vec::new(),
                }
            }
            Err(error) => refusal(&error),
        },
        Target::UzipParse => match parse_uzip(bytes, UZIP_PARSE_CAP) {
            Ok(image) => {
                let image: UzipImage = image;
                Observed::Recovered {
                    entries: image.block_count as usize,
                    violations: Vec::new(),
                }
            }
            Err(error) => refusal(&error),
        },
        Target::NativeImageParse => match parse_native_image(bytes) {
            Ok(image) => Observed::Recovered {
                entries: image.sections().len(),
                violations: Vec::new(),
            },
            Err(error) => refusal(&error),
        },
        Target::SquashfsSuperblockParse => match parse_squashfs_superblock(bytes, 0) {
            Ok(superblock) => {
                let superblock: SquashfsSuperblock = superblock;
                Observed::Recovered {
                    entries: superblock.inode_count as usize,
                    violations: Vec::new(),
                }
            }
            Err(error) => refusal(&error),
        },
    }
}

fn run_zip_extract(bytes: &[u8], out_dir: &Path) -> Observed {
    match extract_to_with_quota(
        ContainerKind::Zip,
        bytes,
        out_dir,
        ExtractionQuota::default_safe(),
    ) {
        Ok(result) => {
            let result: ExtractionResult = result;
            Observed::Recovered {
                entries: result.entries.len(),
                violations: result.integrity_violations,
            }
        }
        Err(error) => refusal(&error),
    }
}

#[derive(Debug)]
enum Verdict {
    Observed(Observed),
    TimedOut,
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "<non-string panic payload>".to_owned())
        },
        |text: &&str| (*text).to_owned(),
    )
}

fn repository_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn corpus_root() -> PathBuf {
    repository_root()
        .join("corpus")
        .join("negative")
        .join("binfmt")
}

fn load_manifest() -> Manifest {
    let path: PathBuf = corpus_root().join("manifest.json");
    let raw: String = std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "the labelled negative corpus manifest must be readable at {}: {error}",
            path.display()
        )
    });
    let manifest: Manifest = serde_json::from_str(&raw).unwrap_or_else(|error| {
        panic!(
            "{} is not a valid negative-corpus manifest: {error}",
            path.display()
        )
    });
    assert_eq!(
        manifest.schema_version, MANIFEST_SCHEMA_VERSION,
        "the manifest schema version must match the harness that reads it"
    );
    assert!(
        !manifest.members.is_empty(),
        "an empty negative corpus grades nothing and must never pass"
    );
    manifest
}

#[test]
fn every_member_produces_exactly_the_outcome_its_label_declares() {
    let manifest: Manifest = load_manifest();
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("binfmt-negative-corpus")
            .expect("create the negative-corpus scratch directory");
    let root: &Path = scratch.path();
    let mut failures: Vec<String> = Vec::new();

    for chunk in manifest.members.chunks(MAX_CONCURRENT_MEMBERS) {
        let started: Instant = Instant::now();
        let mut pending: Vec<(&Member, Receiver<Observed>, JoinHandle<()>)> =
            Vec::with_capacity(chunk.len());
        for member in chunk {
            let bytes: Vec<u8> = load_member_bytes(member);
            let out_dir: PathBuf = root.join(&member.id);
            let (sender, receiver): (Sender<Observed>, Receiver<Observed>) = channel();
            let target: Target = member.target;
            let handle: JoinHandle<()> = std::thread::spawn(move || {
                let observed: Observed =
                    match catch_unwind(AssertUnwindSafe(|| run_target(target, &bytes, &out_dir))) {
                        Ok(value) => value,
                        Err(payload) => Observed::Panicked {
                            payload: panic_text(payload.as_ref()),
                        },
                    };
                drop(sender.send(observed));
            });
            pending.push((member, receiver, handle));
        }
        for (member, receiver, handle) in pending {
            let remaining: Duration = MEMBER_WALL_CLOCK_CAP.saturating_sub(started.elapsed());
            let verdict: Verdict = match receiver.recv_timeout(remaining) {
                Ok(observed) => {
                    drop(handle.join());
                    Verdict::Observed(observed)
                }
                Err(RecvTimeoutError::Timeout) => Verdict::TimedOut,
                Err(RecvTimeoutError::Disconnected) => Verdict::Observed(Observed::Panicked {
                    payload: "the worker thread ended without reporting an outcome".to_owned(),
                }),
            };
            if let Some(failure) = grade(member, &verdict) {
                failures.push(failure);
            }
        }
    }

    assert_containment(root, &manifest);

    assert!(
        failures.is_empty(),
        "{} of {} labelled negative-corpus members did not produce their declared outcome:\n{}",
        failures.len(),
        manifest.members.len(),
        failures.join("\n")
    );
}

fn grade(member: &Member, verdict: &Verdict) -> Option<String> {
    match verdict {
        Verdict::TimedOut => Some(format!(
            "  [TIMEOUT] `{}` did not finish within {:?}; a hostile input that hangs is a failure, never a skip",
            member.id, MEMBER_WALL_CLOCK_CAP
        )),
        Verdict::Observed(Observed::Panicked { payload }) => Some(format!(
            "  [PANIC] `{}` panicked: {payload}. A panic is never an acceptable outcome for any member",
            member.id
        )),
        Verdict::Observed(observed) => {
            if member
                .accepted
                .iter()
                .any(|expected: &Outcome| satisfies(expected, observed))
            {
                return None;
            }
            Some(format!(
                "  [WRONG OUTCOME] `{}` (shape {:?}, target {:?})\n      declared: {:?}\n      observed: {observed:?}",
                member.id, member.shape, member.target, member.accepted
            ))
        }
    }
}

fn load_member_bytes(member: &Member) -> Vec<u8> {
    let path: PathBuf = corpus_root().join(&member.file);
    std::fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "member `{}` must be committed at {}: {error}",
            member.id,
            path.display()
        )
    })
}

fn assert_containment(root: &Path, manifest: &Manifest) {
    let permitted: BTreeSet<PathBuf> = manifest
        .members
        .iter()
        .map(|member: &Member| root.join(&member.id))
        .collect();
    let mut stray: Vec<PathBuf> = Vec::new();
    collect_paths(root, &mut stray);
    for path in &stray {
        let inside: bool = permitted
            .iter()
            .any(|allowed: &PathBuf| path.starts_with(allowed));
        assert!(
            inside,
            "a member wrote outside its own scratch directory: {}",
            path.display()
        );
    }
    let escape_targets: [PathBuf; 2] = [
        root.join("escape.txt"),
        root.parent().map_or_else(
            || root.join("escape.txt"),
            |parent: &Path| parent.join("escape.txt"),
        ),
    ];
    for candidate in &escape_targets {
        assert!(
            !candidate.exists(),
            "a path-traversal member escaped its extraction root and wrote {}",
            candidate.display()
        );
    }
}

fn collect_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_paths(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn every_member_matches_the_digest_its_label_pins_and_the_builder_that_produced_it() {
    let manifest: Manifest = load_manifest();
    for member in &manifest.members {
        let pinned: &str = member.blake3.as_str();
        let on_disk: Vec<u8> = load_member_bytes(member);
        assert_eq!(
            blake3::hash(&on_disk).to_hex().as_str(),
            pinned,
            "the committed bytes of `{}` drifted from the digest its label pins",
            member.id
        );
        let rebuilt: Vec<u8> = build(member.builder);
        assert_eq!(
            blake3::hash(&rebuilt).to_hex().as_str(),
            pinned,
            "builder {:?} no longer reproduces the pinned bytes of `{}`",
            member.builder,
            member.id
        );
    }
}

#[test]
fn the_roster_covers_every_declared_shape_and_every_outcome_in_the_vocabulary() {
    let manifest: Manifest = load_manifest();
    let covered_shapes: BTreeSet<Shape> = manifest
        .members
        .iter()
        .map(|member: &Member| member.shape)
        .collect();
    for shape in EVERY_SHAPE {
        assert!(
            covered_shapes.contains(&shape),
            "hostile shape {shape:?} has no member, so nothing proves the tool refuses it"
        );
    }
    let covered_outcomes: BTreeSet<OutcomeKind> = manifest
        .members
        .iter()
        .flat_map(|member: &Member| member.accepted.iter().map(Outcome::kind))
        .collect();
    for kind in EVERY_OUTCOME_KIND {
        assert!(
            covered_outcomes.contains(&kind),
            "outcome {kind:?} is in the vocabulary but no member exercises it, so it is an unproven claim"
        );
    }
}

#[test]
fn every_label_is_well_formed_and_no_member_accepts_an_open_set_of_outcomes() {
    let manifest: Manifest = load_manifest();
    let mut ids: BTreeSet<&str> = BTreeSet::new();
    let mut files: BTreeSet<&str> = BTreeSet::new();
    for member in &manifest.members {
        assert!(
            ids.insert(member.id.as_str()),
            "member id `{}` is used twice, so a failure cannot be traced to one member",
            member.id
        );
        assert!(
            files.insert(member.file.as_str()),
            "member file `{}` is claimed twice",
            member.file
        );
        assert!(
            !member.accepted.is_empty(),
            "member `{}` accepts nothing, which no observation can satisfy",
            member.id
        );
        assert!(
            !member.authored_reason.trim().is_empty(),
            "member `{}` must record why it was authored",
            member.id
        );
        if member.accepted.len() > 1 {
            assert!(
                member
                    .multiple_outcome_reason
                    .as_deref()
                    .is_some_and(|reason: &str| !reason.trim().is_empty()),
                "member `{}` accepts {} outcomes and must state why more than one is correct",
                member.id,
                member.accepted.len()
            );
        } else {
            assert!(
                member.multiple_outcome_reason.is_none(),
                "member `{}` accepts one outcome, so it must not carry a multiple-outcome reason",
                member.id
            );
        }
        for outcome in &member.accepted {
            match outcome {
                Outcome::Refuse { reason, .. }
                | Outcome::UnsupportedVersion { reason, .. }
                | Outcome::DetectOnly { reason, .. } => assert!(
                    !reason.value().trim().is_empty(),
                    "member `{}` must declare one nonempty contains or equals reason",
                    member.id
                ),
                Outcome::Partial { violations, .. } => {
                    for violation in violations {
                        assert!(
                            !violation.trim().is_empty(),
                            "member `{}` must name each violation it expects",
                            member.id
                        );
                    }
                }
            }
        }
    }
}

fn asar_truncated_prefix() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(12);
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&32u32.to_le_bytes());
    out.extend_from_slice(&28u32.to_le_bytes());
    out
}

fn asar_json_length_past_end() -> Vec<u8> {
    let json_len: u32 = 1024;
    let string_pickle: u32 = json_len + 4;
    let header_pickle: u32 = string_pickle + 4;
    let mut out: Vec<u8> = Vec::with_capacity(64);
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&header_pickle.to_le_bytes());
    out.extend_from_slice(&string_pickle.to_le_bytes());
    out.extend_from_slice(&json_len.to_le_bytes());
    out.extend_from_slice(br#"{"files":{"a.txt":{"size":3,"offset":"0"}}}"#);
    out.resize(64, 0);
    out
}

const ROMFS_MAGIC: &[u8; 8] = b"-rom1fs-";
const ROMFS_TYPE_DIRECTORY: u32 = 1;
const ROMFS_TYPE_REGULAR_FILE: u32 = 2;

fn romfs_prologue() -> Vec<u8> {
    let mut image: Vec<u8> = Vec::with_capacity(32);
    image.extend_from_slice(ROMFS_MAGIC);
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(b"rom");
    image.resize(32, 0);
    image
}

fn pad_to_16(image: &mut Vec<u8>) {
    while !image.len().is_multiple_of(16) {
        image.push(0);
    }
}

fn romfs_node_next_points_at_itself() -> Vec<u8> {
    let body: &[u8] = b"self-referential romfs node payload";
    let node_at: u32 = 32;
    let next_raw: u32 = node_at | ROMFS_TYPE_REGULAR_FILE;
    let mut image: Vec<u8> = romfs_prologue();
    image.extend_from_slice(&next_raw.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&(body.len() as u32).to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(b"hostile.bin");
    image.push(0);
    pad_to_16(&mut image);
    image.extend_from_slice(body);
    pad_to_16(&mut image);
    let full_size: u32 = image.len() as u32;
    image[8..12].copy_from_slice(&full_size.to_be_bytes());
    image
}

fn romfs_directory_child_cycle() -> Vec<u8> {
    let node_at: u32 = 32;
    let mut image: Vec<u8> = romfs_prologue();
    image.extend_from_slice(&ROMFS_TYPE_DIRECTORY.to_be_bytes());
    image.extend_from_slice(&node_at.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(&0u32.to_be_bytes());
    image.extend_from_slice(b"sub");
    image.push(0);
    pad_to_16(&mut image);
    let full_size: u32 = image.len() as u32;
    image[8..12].copy_from_slice(&full_size.to_be_bytes());
    image
}

fn squashfs_unsupported_major_version() -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; 96];
    image[0..4].copy_from_slice(b"hsqs");
    image[4..8].copy_from_slice(&1u32.to_le_bytes());
    image[12..16].copy_from_slice(&131_072u32.to_le_bytes());
    image[28..30].copy_from_slice(&7u16.to_le_bytes());
    image[30..32].copy_from_slice(&0u16.to_le_bytes());
    image
}

struct ZipMember {
    name: &'static str,
    body: &'static [u8],
    declared_uncompressed: u32,
    declared_compressed: u32,
}

fn zip_image(members: &[ZipMember], declared_total_entries: u16) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut directory: Vec<u8> = Vec::new();
    for member in members {
        let local_offset: u32 = out.len() as u32;
        let crc: u32 = crc32fast::hash(member.body);
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&member.declared_compressed.to_le_bytes());
        out.extend_from_slice(&member.declared_uncompressed.to_le_bytes());
        out.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(member.name.as_bytes());
        out.extend_from_slice(member.body);

        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&20u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&member.declared_compressed.to_le_bytes());
        directory.extend_from_slice(&member.declared_uncompressed.to_le_bytes());
        directory.extend_from_slice(&(member.name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes());
        directory.extend_from_slice(&0u32.to_le_bytes());
        directory.extend_from_slice(&local_offset.to_le_bytes());
        directory.extend_from_slice(member.name.as_bytes());
    }
    let directory_offset: u32 = out.len() as u32;
    let directory_size: u32 = directory.len() as u32;
    out.extend_from_slice(&directory);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&declared_total_entries.to_le_bytes());
    out.extend_from_slice(&declared_total_entries.to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn zip_declared_ratio_bomb() -> Vec<u8> {
    zip_image(
        &[ZipMember {
            name: "bomb.bin",
            body: b"0123456789012345678901234567890123456789012345678901234567890123",
            declared_uncompressed: 1_048_576,
            declared_compressed: 64,
        }],
        1,
    )
}

fn zip_declared_count_near_max() -> Vec<u8> {
    zip_image(&[], u16::MAX - 1)
}

const UZIP_MAGIC_LEN: usize = 128;
const UZIP_COMPRESSOR_OFFSET: usize = 0x0b;
const UZIP_VERSION_OFFSET: usize = 0x0c;
const UZIP_BLOCK_COUNT_NEAR_U32_MAX: u32 = u32::MAX - 1;

fn uzip_block_count_near_u32_max() -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; UZIP_MAGIC_LEN + 8 + 32];
    image[0..10].copy_from_slice(b"#!/bin/sh\n");
    image[UZIP_COMPRESSOR_OFFSET] = b'V';
    image[UZIP_VERSION_OFFSET] = 2;
    image[UZIP_MAGIC_LEN..UZIP_MAGIC_LEN + 4].copy_from_slice(&65_536u32.to_be_bytes());
    image[UZIP_MAGIC_LEN + 4..UZIP_MAGIC_LEN + 8]
        .copy_from_slice(&UZIP_BLOCK_COUNT_NEAR_U32_MAX.to_be_bytes());
    image
}

fn zip_valid_empty_archive() -> Vec<u8> {
    zip_image(&[], 0)
}

fn zip_entry_name_parent_traversal() -> Vec<u8> {
    zip_image(
        &[ZipMember {
            name: "../escape.txt",
            body: b"this payload must never land outside the extraction root",
            declared_uncompressed: 56,
            declared_compressed: 56,
        }],
        1,
    )
}

fn zip_magic_body_is_elf() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(256);
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&[0x7f]);
    out.extend_from_slice(b"ELF");
    out.extend_from_slice(&[2, 1, 1, 0]);
    out.resize(16, 0);
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&0x3eu16.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out.resize(256, 0);
    out
}

const PE_HEADER_SPAN: usize = 0x200;
const PE_TOTAL_LEN: usize = 0x600;

fn pe64_sections_overlap() -> Vec<u8> {
    let mut image: Vec<u8> = vec![0u8; PE_TOTAL_LEN];
    image[0..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    image[0x40..0x44].copy_from_slice(b"PE\0\0");

    let coff: usize = 0x44;
    image[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
    image[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
    image[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
    image[coff + 18..coff + 20].copy_from_slice(&0x0022u16.to_le_bytes());

    let opt: usize = coff + 20;
    image[opt..opt + 2].copy_from_slice(&0x020bu16.to_le_bytes());
    image[opt + 2] = 14;
    image[opt + 4..opt + 8].copy_from_slice(&0x200u32.to_le_bytes());
    image[opt + 8..opt + 12].copy_from_slice(&0x200u32.to_le_bytes());
    image[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    image[opt + 20..opt + 24].copy_from_slice(&0x1000u32.to_le_bytes());
    image[opt + 24..opt + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
    image[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    image[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes());
    image[opt + 40..opt + 42].copy_from_slice(&6u16.to_le_bytes());
    image[opt + 48..opt + 50].copy_from_slice(&6u16.to_le_bytes());
    image[opt + 56..opt + 60].copy_from_slice(&0x4000u32.to_le_bytes());
    image[opt + 60..opt + 64].copy_from_slice(&(PE_HEADER_SPAN as u32).to_le_bytes());
    image[opt + 68..opt + 70].copy_from_slice(&3u16.to_le_bytes());
    image[opt + 72..opt + 80].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    image[opt + 80..opt + 88].copy_from_slice(&0x1000u64.to_le_bytes());
    image[opt + 88..opt + 96].copy_from_slice(&0x0010_0000u64.to_le_bytes());
    image[opt + 96..opt + 104].copy_from_slice(&0x1000u64.to_le_bytes());
    image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());

    let sections: usize = opt + 240;
    write_section_header(
        &mut image,
        sections,
        *b".text\0\0\0",
        0x1000,
        0x1000,
        0x200,
        0x200,
        0x6000_0020,
    );
    write_section_header(
        &mut image,
        sections + 40,
        *b".data\0\0\0",
        0x1000,
        0x1800,
        0x200,
        0x400,
        0xc000_0040,
    );
    image
}

#[allow(clippy::too_many_arguments)]
fn write_section_header(
    image: &mut [u8],
    at: usize,
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    characteristics: u32,
) {
    image[at..at + 8].copy_from_slice(&name);
    image[at + 8..at + 12].copy_from_slice(&virtual_size.to_le_bytes());
    image[at + 12..at + 16].copy_from_slice(&virtual_address.to_le_bytes());
    image[at + 16..at + 20].copy_from_slice(&raw_size.to_le_bytes());
    image[at + 20..at + 24].copy_from_slice(&raw_offset.to_le_bytes());
    image[at + 36..at + 40].copy_from_slice(&characteristics.to_le_bytes());
}
