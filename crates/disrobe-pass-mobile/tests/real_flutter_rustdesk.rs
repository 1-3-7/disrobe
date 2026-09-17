#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::print_stderr,
    clippy::single_match_else,
    clippy::uninlined_format_args,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::single_char_pattern
)]

use std::any::Any;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::io::{Cursor, Read as _};
use std::panic::UnwindSafe;
use std::path::PathBuf;

use disrobe_core::scratch::scratch_root;
use disrobe_pass_mobile::{
    DART_ISOLATE_DATA_SYMBOL, DART_ISOLATE_INSTR_SYMBOL, DART_SNAPSHOT_MAGIC, DART_VM_DATA_SYMBOL,
    DART_VM_INSTR_SYMBOL, DartGraphRecoveryOptions, DartGraphRecoveryReport,
    DartGraphRecoveryStatus, DartSnapshotHeader, DartSnapshotKind, DartSnapshotStructure,
    DartStaticRecovery, LibAppLayout, SnapshotSection, decompile_libapp_so,
    decompile_libapp_so_structured, parse_dart_snapshot, parse_libapp_so, recover_dart_pinned_elf,
};
use sha2::{Digest, Sha256};

const RUSTDESK_RELEASE_TAG: &str = "1.4.9";
const RUSTDESK_APK_NAME: &str = "rustdesk-1.4.9-aarch64-signed.apk";
const RUSTDESK_APK_URL: &str = "https://github.com/rustdesk/rustdesk/releases/download/1.4.9/rustdesk-1.4.9-aarch64-signed.apk";
const RUSTDESK_APK_SIZE_BYTES: u64 = 26_871_021;
const RUSTDESK_APK_SHA256: &str =
    "285b4f0735c000e5155b9a6f087b57744e46c960f4332963f51add1804982102";
const RUSTDESK_LIBAPP_ENTRY: &str = "lib/arm64-v8a/libapp.so";
const RUSTDESK_LIBFLUTTER_ENTRY: &str = "lib/arm64-v8a/libflutter.so";
const REQUIRE_CORPUS_VAR: &str = "DISROBE_REQUIRE_RUSTDESK_FLUTTER";
const CORPUS_MANIFEST_NAME: &str = "rustdesk/rustdesk-1.4.9-aarch64-signed.apk";

const PINNED_FUNCTION_BOUNDARIES: usize = 23_471;
const PINNED_RAW_CLASS_NAME_STRINGS: usize = 10_351;
const PINNED_RAW_METHOD_NAME_STRINGS: usize = 28_952;
const PINNED_RAW_LIBRARY_URIS: usize = 1_489;
const PINNED_INDEPENDENT_ORACLE_DART_URIS: usize = 1_271;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CorpusRequirement {
    Optional,
    Mandatory,
}

fn requirement_from_value(value: Option<&OsStr>) -> CorpusRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return CorpusRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" => CorpusRequirement::Optional,
        _ => CorpusRequirement::Mandatory,
    }
}

fn corpus_requirement() -> CorpusRequirement {
    let raw: Option<OsString> = std::env::var_os(REQUIRE_CORPUS_VAR);
    requirement_from_value(raw.as_deref())
}

fn cache_root() -> PathBuf {
    scratch_root().join("rustdesk-flutter-cache")
}

fn cached_apk_path() -> PathBuf {
    cache_root().join(RUSTDESK_APK_NAME)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(bytes);
    let digest: sha2::digest::Output<Sha256> = hasher.finalize();
    let mut out: String = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _: std::fmt::Result = write!(out, "{byte:02x}");
    }
    out
}

fn declared_apk_defect(bytes: &[u8]) -> Option<String> {
    if bytes.len() as u64 != RUSTDESK_APK_SIZE_BYTES {
        return Some(format!(
            "cached {RUSTDESK_APK_NAME} is {} bytes, expected {RUSTDESK_APK_SIZE_BYTES}",
            bytes.len()
        ));
    }
    let digest: String = sha256_hex(bytes);
    (digest != RUSTDESK_APK_SHA256).then(|| {
        format!("cached {RUSTDESK_APK_NAME} has sha256 {digest}, expected {RUSTDESK_APK_SHA256}")
    })
}

fn fetch_command() -> String {
    format!(
        "mkdir -p \"{cache}\" && curl -sSL -o \"{apk}\" \"{url}\"",
        cache = cache_root().display(),
        apk = cached_apk_path().display(),
        url = RUSTDESK_APK_URL,
    )
}

fn announce_ungraded(case: &str) {
    println!(
        "\nUNGRADED {case}: RustDesk {RUSTDESK_RELEASE_TAG} ({RUSTDESK_APK_NAME}, AGPL-3.0, \
         {url}) is absent from the local cache at {apk}. It is {RUSTDESK_APK_SIZE_BYTES} bytes, \
         pinned by sha256 {RUSTDESK_APK_SHA256}, and is never fetched automatically or tracked in \
         this repository because of its size, not its licence. Populate the cache reproducibly \
         with:\n  {cmd}\nthen re-run this test. Set {REQUIRE_CORPUS_VAR}=1 to fail instead of \
         skipping when the corpus is absent. This result is [local] only: no CI job populates the \
         cache, so it never runs there.\n",
        url = RUSTDESK_APK_URL,
        apk = cached_apk_path().display(),
        cmd = fetch_command(),
    );
}

fn enforce_requirement(case: &str, requirement: CorpusRequirement) {
    assert!(
        requirement == CorpusRequirement::Optional,
        "{REQUIRE_CORPUS_VAR} makes the RustDesk Flutter sample mandatory for {case}, so it \
         cannot be graded and must not report success. Populate the cache with:\n  {}\nor clear \
         {REQUIRE_CORPUS_VAR} to permit a run that grades nothing here.",
        fetch_command(),
    );
    announce_ungraded(case);
}

fn ensure_rustdesk_apk(case: &str) -> Option<Vec<u8>> {
    let apk_path: PathBuf = cached_apk_path();
    match std::fs::read(&apk_path) {
        Ok(bytes) => {
            if let Some(defect) = declared_apk_defect(&bytes) {
                let _: std::io::Result<()> = std::fs::remove_file(&apk_path);
                panic!(
                    "{case}: {apk_path} did not match the pinned RustDesk release asset and was \
                     removed: {defect}. Re-populate with:\n  {cmd}",
                    apk_path = apk_path.display(),
                    cmd = fetch_command(),
                );
            }
            Some(bytes)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            enforce_requirement(case, corpus_requirement());
            None
        }
        Err(err) => panic!(
            "{case}: {} exists but could not be read ({err}); an unreadable cache entry is never \
             a skip",
            apk_path.display()
        ),
    }
}

fn extract_zip_member(apk_bytes: &[u8], entry_name: &str) -> Vec<u8> {
    let cursor: Cursor<&[u8]> = Cursor::new(apk_bytes);
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).expect("open cached rustdesk apk as a zip archive");
    let mut entry: zip::read::ZipFile<'_> =
        archive
            .by_name(entry_name)
            .unwrap_or_else(|err: zip::result::ZipError| {
                panic!("{entry_name} missing from cached rustdesk apk: {err}")
            });
    let mut bytes: Vec<u8> = Vec::with_capacity(entry.size() as usize);
    entry
        .read_to_end(&mut bytes)
        .unwrap_or_else(|err: std::io::Error| panic!("read {entry_name} from rustdesk apk: {err}"));
    bytes
}

fn load_libapp(case: &str) -> Option<Vec<u8>> {
    let apk: Vec<u8> = ensure_rustdesk_apk(case)?;
    Some(extract_zip_member(&apk, RUSTDESK_LIBAPP_ENTRY))
}

fn load_libflutter(case: &str) -> Option<Vec<u8>> {
    let apk: Vec<u8> = ensure_rustdesk_apk(case)?;
    Some(extract_zip_member(&apk, RUSTDESK_LIBFLUTTER_ENTRY))
}

#[test]
fn rustdesk_libapp_so_is_elf() {
    let bytes: Vec<u8> = match load_libapp("rustdesk_libapp_so_is_elf") {
        Some(b) => b,
        None => return,
    };
    assert!(bytes.len() > 1024);
    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
    assert_eq!(bytes[4], 2, "expected ELF64");
}

#[test]
fn rustdesk_libflutter_so_is_elf() {
    let bytes: Vec<u8> = match load_libflutter("rustdesk_libflutter_so_is_elf") {
        Some(b) => b,
        None => return,
    };
    assert!(bytes.len() > 1024);
    assert_eq!(&bytes[..4], &[0x7f, b'E', b'L', b'F']);
}

fn assert_recovered(section: Option<&SnapshotSection>, expected_symbol: &str) -> SnapshotSection {
    let s: &SnapshotSection = section.unwrap_or_else(|| {
        panic!("Dart snapshot symbol {expected_symbol} not recovered (was MISSING regression)")
    });
    assert_eq!(s.symbol, expected_symbol, "symbol name mismatch");
    assert!(
        s.address > 0,
        "{expected_symbol} must have a nonzero virtual address, got {:#x}",
        s.address
    );
    assert!(
        s.size > 0,
        "{expected_symbol} must have a nonzero size, got {}",
        s.size
    );
    s.clone()
}

#[test]
fn rustdesk_libapp_parse_finds_dart_snapshot_symbols() {
    let bytes: Vec<u8> = match load_libapp("rustdesk_libapp_parse_finds_dart_snapshot_symbols") {
        Some(b) => b,
        None => return,
    };
    let layout: LibAppLayout = parse_libapp_so(&bytes).expect("parse libapp.so");
    assert!(
        !layout.section_names.is_empty(),
        "expected ELF sections enumerated"
    );
    assert!(
        layout.section_names.iter().any(|n: &String| n == ".dynsym"),
        "expected .dynsym present in real stripped libapp.so"
    );

    let vm_data: SnapshotSection =
        assert_recovered(layout.vm_snapshot_data.as_ref(), DART_VM_DATA_SYMBOL);
    let vm_instr: SnapshotSection = assert_recovered(
        layout.vm_snapshot_instructions.as_ref(),
        DART_VM_INSTR_SYMBOL,
    );
    let iso_data: SnapshotSection = assert_recovered(
        layout.isolate_snapshot_data.as_ref(),
        DART_ISOLATE_DATA_SYMBOL,
    );
    let iso_instr: SnapshotSection = assert_recovered(
        layout.isolate_snapshot_instructions.as_ref(),
        DART_ISOLATE_INSTR_SYMBOL,
    );

    assert!(
        iso_data.size > 4_000_000,
        "rustdesk isolate snapshot data is a few MB, got {}",
        iso_data.size
    );
    assert!(
        iso_instr.size > 7_000_000,
        "rustdesk isolate instructions are several MB, got {}",
        iso_instr.size
    );

    for sec in [&vm_data, &iso_data] {
        let magic: u32 = u32::from_le_bytes([
            sec.bytes_preview[0],
            sec.bytes_preview[1],
            sec.bytes_preview[2],
            sec.bytes_preview[3],
        ]);
        assert_eq!(
            magic, DART_SNAPSHOT_MAGIC,
            "{} payload must begin with the Dart snapshot magic",
            sec.symbol
        );
    }

    let header: DartSnapshotHeader =
        parse_dart_snapshot(&vm_data.bytes_preview).expect("parse VM snapshot header");
    assert_eq!(header.magic, DART_SNAPSHOT_MAGIC);
    assert_eq!(header.kind, DartSnapshotKind::FullAot);
    assert_eq!(header.version_hash.len(), 32);
    assert!(
        header
            .version_hash
            .bytes()
            .all(|b: u8| b.is_ascii_hexdigit()),
        "version hash must be ascii-hex, got {}",
        header.version_hash
    );

    eprintln!(
        "recovered 4/4 Dart symbols: vm_data@{:#x}({}) vm_instr@{:#x}({}) iso_data@{:#x}({}) iso_instr@{:#x}({}); snapshot kind={:?} version={}",
        vm_data.address,
        vm_data.size,
        vm_instr.address,
        vm_instr.size,
        iso_data.address,
        iso_data.size,
        iso_instr.address,
        iso_instr.size,
        header.kind,
        header.version_hash
    );
}

#[test]
fn rustdesk_static_recovery_reports_raw_counts() {
    let bytes: Vec<u8> = match load_libapp("rustdesk_static_recovery_reports_raw_counts") {
        Some(b) => b,
        None => return,
    };
    let recovery: DartStaticRecovery =
        decompile_libapp_so(&bytes).expect("decompile real libapp.so");
    eprintln!(
        "rustdesk flutter aot RAW recovery (measured against the binary's own isolate snapshot): function_boundaries={} classes={} methods={} library_uris={} bodies_recovered=0 (arm64 register-erasure wall)",
        recovery.function_boundary_count,
        recovery.class_names.len(),
        recovery.method_names.len(),
        recovery.library_uris.len()
    );
    assert_eq!(
        recovery.function_boundary_count, PINNED_FUNCTION_BOUNDARIES,
        "the published `function boundaries recovered` count for RustDesk {RUSTDESK_RELEASE_TAG} \
         in docs/src/languages/mobile.md and xtask/data/recovery.json is pinned here; the cached \
         apk is checked byte-for-byte against RUSTDESK_APK_SHA256 before this runs, so a count that \
         moves means the RAW recovery path changed, not the input; re-measure and move every \
         citation of this figure in the same change"
    );
    assert_eq!(recovery.class_names.len(), PINNED_RAW_CLASS_NAME_STRINGS);
    assert_eq!(recovery.method_names.len(), PINNED_RAW_METHOD_NAME_STRINGS);
    assert_eq!(recovery.library_uris.len(), PINNED_RAW_LIBRARY_URIS);
}

fn independent_uri_oracle(elf_bytes: &[u8]) -> std::collections::BTreeSet<String> {
    let mut found: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let needle: &[u8] = b"package:";
    let mut i: usize = 0;
    while i + needle.len() <= elf_bytes.len() {
        if &elf_bytes[i..i + needle.len()] == needle {
            let mut end: usize = i;
            while end < elf_bytes.len() {
                let b: u8 = elf_bytes[end];
                let printable: bool = b.is_ascii_alphanumeric()
                    || matches!(b, b'_' | b'.' | b'/' | b':' | b'-' | b'<' | b'>');
                if !printable {
                    break;
                }
                end += 1;
            }
            if let Ok(s) = std::str::from_utf8(&elf_bytes[i..end])
                && s.ends_with(".dart")
            {
                found.insert(s.to_owned());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    found
}

#[test]
fn rustdesk_structured_recovery_vs_independent_uri_oracle() {
    let bytes: Vec<u8> = match load_libapp("rustdesk_structured_recovery_vs_independent_uri_oracle")
    {
        Some(b) => b,
        None => return,
    };

    let structure: DartSnapshotStructure =
        decompile_libapp_so_structured(&bytes).expect("structured decompile of real libapp.so");

    let independent: std::collections::BTreeSet<String> = independent_uri_oracle(&bytes);
    assert!(
        !independent.is_empty(),
        "independent whole-file strings scan must find at least one package: uri in a real flutter binary"
    );
    assert_eq!(
        independent.len(),
        PINNED_INDEPENDENT_ORACLE_DART_URIS,
        "the independent whole-file `package:*.dart` uri count published beside the structured \
         recovery figure in docs/src/languages/mobile.md is pinned here; the cached apk is checked \
         byte-for-byte against RUSTDESK_APK_SHA256 before this runs, so a count that moves means \
         independent_uri_oracle's own scan logic changed, not the input; re-measure and move the \
         published figure in the same change"
    );

    let uri_is_literal_in_binary = |uri: &str| -> bool {
        let needle: &[u8] = uri.as_bytes();
        !needle.is_empty() && bytes.windows(needle.len()).any(|w: &[u8]| w == needle)
    };
    for uri in &structure.library_uris {
        assert!(
            uri_is_literal_in_binary(uri),
            "structured recovery surfaced library uri {uri} that does not appear as a literal byte string anywhere in the real binary (possible fabrication)"
        );
    }

    let attributed_methods: usize = structure
        .classes
        .iter()
        .map(|c| c.methods.len())
        .sum::<usize>();

    assert!(
        !structure.class_fields_recoverable,
        "fields must be reported version-keyed-unrecoverable, never fabricated"
    );
    assert!(
        !structure.method_signatures_recoverable,
        "signatures must be reported version-keyed-unrecoverable"
    );

    eprintln!(
        "rustdesk STRUCTURED recovery (classes/methods graded against independent whole-file uri oracle): \
         classes={} attributed_methods={} unattributed_methods={} functions={} library_uris={} (independent_oracle_uris={}) \
         framing_status={:?} clusters_declared={} clusters_version_keyed_unparsed={} fields_recoverable=false sigs_recoverable=false",
        structure.classes.len(),
        attributed_methods,
        structure.unattributed_methods.len(),
        structure.functions.len(),
        structure.library_uris.len(),
        independent.len(),
        structure.framing.status,
        structure.framing.num_clusters,
        structure.framing.version_keyed_clusters_unparsed,
    );

    if let Some(traversal) = &structure.instruction_traversal {
        eprintln!(
            "rustdesk ARM64 recursive traversal: entries={} reachable_insns={} direct_call_targets={} resolved_branches={} indirect_unresolved={} linear_decode={}",
            traversal.entry_count,
            traversal.reachable_instruction_count,
            traversal.direct_call_targets.len(),
            traversal.resolved_branch_targets.len(),
            traversal.indirect_target_count(),
            traversal.linear_decode_count,
        );
    }
}

#[test]
fn rustdesk_declaration_graph_reports_unsupported_version_on_a_real_unpinned_build() {
    let bytes: Vec<u8> = match load_libapp(
        "rustdesk_declaration_graph_reports_unsupported_version_on_a_real_unpinned_build",
    ) {
        Some(b) => b,
        None => return,
    };
    let report: DartGraphRecoveryReport =
        recover_dart_pinned_elf(&bytes, &DartGraphRecoveryOptions::default())
            .expect("declaration-graph recovery attempt on a real libapp.so must not error");
    assert_eq!(
        report.status,
        DartGraphRecoveryStatus::UnsupportedVersion,
        "RustDesk {RUSTDESK_RELEASE_TAG} ships a Dart snapshot version outside the pinned Dart \
         3.12.2 android-arm64 product tuple, so the declaration-graph path (`flutter inventory`) \
         must name that limit rather than guess at a cluster layout it has no pin for; a status \
         other than UnsupportedVersion here means either this real build now matches the pinned \
         tuple (update the docs) or the version fence stopped fencing"
    );
}

fn corpus_manifest_path() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("corpus");
    path.push("mobile");
    path.push("flutter");
    path.push("MANIFEST.toml");
    path
}

fn manifest_sample_block<'a>(manifest: &'a str, name: &str) -> Option<&'a str> {
    let needle: String = format!("name = \"{name}\"\n");
    let start: usize = manifest.find(&needle)?;
    let rest: &str = &manifest[start..];
    let end: usize = rest.find("\n[[sample]]").unwrap_or(rest.len());
    Some(&rest[..end])
}

#[test]
fn corpus_manifest_declares_the_exact_sample_this_file_grades() {
    let path: PathBuf = corpus_manifest_path();
    let manifest: String = std::fs::read_to_string(&path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "{} must be readable, because it is the tracked declaration of the rustdesk sample \
             this file fetches and grades ({err})",
            path.display()
        )
    });
    let block: &str = manifest_sample_block(&manifest, CORPUS_MANIFEST_NAME).unwrap_or_else(|| {
        panic!(
            "{} must declare the sample `{CORPUS_MANIFEST_NAME}`, because that declaration is the \
             only tracked record of the url and hash this file pins",
            path.display()
        )
    });
    let url_line: String = format!("source_url = \"{RUSTDESK_APK_URL}\"");
    assert!(
        block.contains(&url_line),
        "the manifest entry for `{CORPUS_MANIFEST_NAME}` must declare `{url_line}`, matching the \
         url this file pins; entry was:\n{block}"
    );
    let size_line: String = format!("size_bytes = {RUSTDESK_APK_SIZE_BYTES}");
    assert!(
        block.contains(&size_line),
        "the manifest entry for `{CORPUS_MANIFEST_NAME}` must declare `{size_line}`, matching the \
         size this file pins; entry was:\n{block}"
    );
    let digest_line: String = format!("sha256 = \"{RUSTDESK_APK_SHA256}\"");
    assert!(
        block.contains(&digest_line),
        "the manifest entry for `{CORPUS_MANIFEST_NAME}` must declare `{digest_line}`, matching \
         the digest this file pins; entry was:\n{block}"
    );
    assert!(
        block.contains("AGPL-3.0"),
        "the manifest entry for `{CORPUS_MANIFEST_NAME}` must keep recording its AGPL-3.0 \
         licence, which is why the fetch-by-url pattern is legitimate here rather than a wall; \
         entry was:\n{block}"
    );
}

fn message_from_seeded_defect(what: &str, check: impl FnOnce() + UnwindSafe) -> String {
    eprintln!("seeding a defect ({what}); the failure below is the expected outcome");
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(check);
    let payload: Box<dyn Any + Send> = outcome.expect_err(
        "a seeded defect must make this gate fail; a check that accepts the seeded state pins \
         nothing",
    );
    let owned: Option<String> = payload.downcast_ref::<String>().cloned();
    owned
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|message: &&str| (*message).to_owned())
        })
        .unwrap_or_else(|| panic!("the failure must carry a message naming what regressed"))
}

#[test]
fn an_absent_rustdesk_apk_fails_instead_of_skipping_when_the_run_demands_it() {
    let message: String = message_from_seeded_defect("an absent rustdesk apk cache entry", || {
        enforce_requirement("a probe case", CorpusRequirement::Mandatory);
    });
    assert!(
        message.contains(REQUIRE_CORPUS_VAR),
        "the failure must name the variable that made the sample mandatory: {message}"
    );
    assert!(
        message.contains(RUSTDESK_APK_URL) || message.contains(&fetch_command()),
        "the failure must name the exact fetch command that reproduces the sample: {message}"
    );
}

#[test]
fn the_requirement_variable_reads_every_documented_spelling() {
    assert_eq!(
        requirement_from_value(None),
        CorpusRequirement::Optional,
        "unset must leave the corpus optional"
    );
    for off in ["", "0", "false", "no", "off", "  OFF  "] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(off))),
            CorpusRequirement::Optional,
            "`{off}` must leave the corpus optional"
        );
    }
    for on in ["1", "true", "yes", "mandatory", "1 "] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(on))),
            CorpusRequirement::Mandatory,
            "`{on}` must make an absent corpus fatal"
        );
    }
}
