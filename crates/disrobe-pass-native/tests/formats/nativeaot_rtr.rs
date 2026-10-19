#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use disrobe_pass_native::packers::pe_sections::{PeImage, parse_pe_image};
use disrobe_pass_native::{EvidenceKind, FileIdReport, SupportRoute, identify_file};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const NOW_SECS: u64 = 1_798_761_600;
const NATIVEAOT_PE_FIXTURES: [&str; 3] = [
    "dotnet/HelloAppAot.exe",
    "dotnet/aot/aot_maps_net10_x86_64/aot_maps_net10_x86_64.exe",
    "dotnet/megafile/EdgeCases.nativeaot.exe",
];

fn corpus(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "committed corpus sample missing: {}: {error}",
            path.display()
        )
    })
}

#[test]
fn nativeaot_debug_export_routes_to_native_aot() {
    let path: PathBuf = corpus_path("dotnet/HelloAppAot.exe");
    let reference: ToolOutput = tool_output(
        CommandSpec::new("llvm-readobj", Duration::from_secs(30))
            .arg("--coff-exports")
            .arg(&path)
            .capture_limits(1 << 20, 1 << 20),
    )
    .unwrap_or_else(|error| {
        panic!("required independent reference tool llvm-readobj is not callable: {error}")
    });
    assert!(
        !reference.timed_out && reference.exit_code == Some(0),
        "llvm-readobj --coff-exports failed for {}: {}",
        path.display(),
        String::from_utf8_lossy(&reference.stderr)
    );
    let reference_text: String = String::from_utf8(reference.stdout)
        .expect("llvm-readobj export listing must be valid UTF-8");
    assert!(
        reference_text.contains("Name: DotNetRuntimeDebugHeader"),
        "independent export listing lacks the NativeAOT debug header: {reference_text}"
    );

    let bytes: Vec<u8> = fs::read(&path).expect("read committed NativeAOT executable");
    let (_, dndh_offset): (usize, usize) = native_aot_export(&bytes);
    let rtr_offset: usize = native_aot_ready_to_run(&bytes);
    let report: FileIdReport = identify_file(&bytes, NOW_SECS);
    let finding = report
        .findings
        .iter()
        .find(|finding| finding.family == "nativeaot")
        .unwrap_or_else(|| panic!("NativeAOT finding missing: {:?}", report.findings));
    assert_eq!(finding.version, None);
    assert_eq!(finding.support, SupportRoute::DotnetNativeAot);
    assert_eq!(finding.support.command(), "disrobe dotnet native-aot");
    assert!(finding.evidence.iter().any(|evidence| {
        evidence.kind == EvidenceKind::DataDirectory && evidence.locus == "PE export table"
    }));
    assert!(
        finding
            .evidence
            .iter()
            .any(|evidence| evidence.detail.contains("ReadyToRun v10.1 has 34 sections")),
        "NativeAOT finding must carry the independently inspected ReadyToRun header: {finding:?}"
    );

    let (name_offset, _): (usize, usize) = native_aot_export(&bytes);
    let mut mutated_name: Vec<u8> = bytes.clone();
    mutated_name[name_offset] ^= 1;
    assert_no_native_aot(&mutated_name, "export-name mutation");

    let mut mutated_magic: Vec<u8> = bytes;
    mutated_magic[dndh_offset] ^= 1;
    assert_no_native_aot(&mutated_magic, "DNDH mutation");

    let mut mutated_rtr: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    mutated_rtr[rtr_offset] ^= 1;
    assert_no_native_aot(&mutated_rtr, "ReadyToRun magic mutation");
}

#[test]
fn net10_debug_header_accepts_version_five_and_compatible_minor_changes() {
    let bytes: Vec<u8> = corpus("dotnet/aot/aot_maps_net10_x86_64/aot_maps_net10_x86_64.exe");
    let (_, header): (usize, usize) = native_aot_export(&bytes);
    assert_eq!(&bytes[header + 4..header + 8], &[5, 0, 0, 0]);
    let report: FileIdReport = identify_file(&bytes, NOW_SECS);
    assert!(report.findings.iter().any(|finding| {
        finding.family == "nativeaot"
            && finding.evidence.iter().any(|evidence| {
                evidence.detail.contains("DNDH v5.0")
                    && evidence.detail.contains("ReadyToRun v16.0 has 33 sections")
            })
    }));
    let mut minor: Vec<u8> = bytes.clone();
    minor[header + 6..header + 8].copy_from_slice(&1u16.to_le_bytes());
    assert!(
        identify_file(&minor, NOW_SECS)
            .findings
            .iter()
            .any(|finding| finding.family == "nativeaot")
    );
    for major in [0u16, 6u16] {
        let mut unsupported: Vec<u8> = bytes.clone();
        unsupported[header + 4..header + 6].copy_from_slice(&major.to_le_bytes());
        assert_no_native_aot(&unsupported, "unsupported DNDH major version");
    }
}

#[test]
fn malformed_nativeaot_export_metadata_is_not_a_verdict() {
    let bytes: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    let image: PeImage = parse_pe_image(&bytes).expect("reference PE parse");
    let directory = image
        .data_directories
        .first()
        .expect("export directory row");
    let export: usize = image
        .file_offset_for_rva(directory.virtual_address, bytes.len())
        .expect("export directory mapped");

    let mut oversized_names: Vec<u8> = bytes.clone();
    oversized_names[export + 24..export + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_no_native_aot(&oversized_names, "oversized export-name count");

    let mut truncated: Vec<u8> = bytes;
    truncated.truncate(export + 39);
    assert_no_native_aot(&truncated, "truncated export directory");
}

#[test]
fn ready_to_run_rows_follow_end_pointer_flags_and_allow_empty_spans() {
    let bytes: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    let table: usize = native_aot_ready_to_run(&bytes) + 16;
    let row_offset = |id: u32| -> usize {
        (0..34usize)
            .map(|index: usize| table + index * 24)
            .find(|offset: &usize| read_u32(&bytes, *offset) == id)
            .expect("compiler-emitted ReadyToRun section")
    };
    let singleton: usize = row_offset(204);
    let empty: usize = row_offset(325);
    assert_eq!(read_u32(&bytes, singleton + 4), 0);
    assert_eq!(&bytes[singleton + 16..singleton + 24], &[0; 8]);
    assert_eq!(read_u32(&bytes, empty + 4), 1);
    assert_eq!(
        &bytes[empty + 8..empty + 16],
        &bytes[empty + 16..empty + 24]
    );
    assert!(
        identify_file(&bytes, NOW_SECS)
            .findings
            .iter()
            .any(|finding| finding.family == "nativeaot")
    );

    let mut unused_end: Vec<u8> = bytes.clone();
    unused_end[singleton + 16..singleton + 24].fill(0xff);
    assert!(
        identify_file(&unused_end, NOW_SECS)
            .findings
            .iter()
            .any(|finding| finding.family == "nativeaot")
    );

    let mut invalid_flags: Vec<u8> = bytes.clone();
    invalid_flags[singleton + 4..singleton + 8].copy_from_slice(&2u32.to_le_bytes());
    assert_no_native_aot(&invalid_flags, "unknown ReadyToRun row flag");

    let mut reversed_extent: Vec<u8> = bytes;
    reversed_extent[empty + 16..empty + 24].fill(0);
    assert_no_native_aot(&reversed_extent, "reversed ReadyToRun extent");
}

#[test]
fn ready_to_run_decoy_probe_budget_refuses_without_a_nativeaot_verdict() {
    let bytes: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    let image: PeImage = parse_pe_image(&bytes).expect("reference PE parse");
    let rdata = image
        .sections
        .iter()
        .find(|section| section.name_trimmed() == b".rdata")
        .expect("read-only data section");
    let start: usize = usize::try_from(rdata.raw_pointer).expect("rdata file offset");
    let real: usize = native_aot_ready_to_run(&bytes);
    assert!(
        start + 257 * 4 < real,
        "decoys must precede the real RTR header"
    );

    let mut below_budget: Vec<u8> = bytes.clone();
    for offset in (0..255usize).map(|index| start + index * 4) {
        below_budget[offset..offset + 4].copy_from_slice(b"RTR\0");
    }
    assert!(
        identify_file(&below_budget, NOW_SECS)
            .findings
            .iter()
            .any(|finding| finding.family == "nativeaot"),
        "decoys below the probe budget must retain the valid later ReadyToRun header"
    );

    let mut exhausted: Vec<u8> = bytes;
    for offset in (0..257usize).map(|index| start + index * 4) {
        exhausted[offset..offset + 4].copy_from_slice(b"RTR\0");
    }
    assert_no_native_aot(&exhausted, "ReadyToRun decoy probe budget");
}

#[test]
fn nativeaot_and_installshield_stay_absent_from_other_committed_pes() {
    let root: PathBuf = corpus_root();
    let mut pending: Vec<PathBuf> = vec![root.clone()];
    let mut seen_nativeaot: BTreeSet<PathBuf> = BTreeSet::new();
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir).expect("read committed corpus directory") {
            let entry: fs::DirEntry = entry.expect("read committed corpus entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let bytes: Vec<u8> = fs::read(&path).expect("read committed corpus file");
            if !bytes.starts_with(b"MZ") {
                continue;
            }
            let report: FileIdReport = identify_file(&bytes, NOW_SECS);
            let native_aot: bool = NATIVEAOT_PE_FIXTURES
                .iter()
                .any(|fixture: &&str| path == root.join(fixture));
            if native_aot {
                let relative: PathBuf = path
                    .strip_prefix(&root)
                    .expect("corpus entry must be rooted in the corpus directory")
                    .to_path_buf();
                seen_nativeaot.insert(relative);
            }
            assert_eq!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.family == "nativeaot"),
                native_aot,
                "{} NativeAOT classification differs from its compiler provenance: {:?}",
                path.display(),
                report.findings
            );
            assert!(
                report
                    .findings
                    .iter()
                    .all(|finding| finding.family != "installshield"),
                "{} falsely matched installshield: {:?}",
                path.display(),
                report.findings
            );
        }
    }
    let expected_nativeaot: BTreeSet<PathBuf> = NATIVEAOT_PE_FIXTURES
        .iter()
        .map(|fixture: &&str| PathBuf::from(*fixture))
        .collect();
    assert_eq!(
        seen_nativeaot, expected_nativeaot,
        "NativeAOT fixture list must exactly match committed NativeAOT PE corpus files"
    );
}

#[test]
fn installshield_cabinet_magic_requires_the_pe_overlay_start() {
    let bytes: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    let mut overlay: Vec<u8> = bytes.clone();
    overlay.extend_from_slice(b"ISc(");
    assert!(
        identify_file(&overlay, NOW_SECS)
            .findings
            .iter()
            .any(|finding| finding.family == "installshield"),
        "legacy cabinet magic at the overlay start must be recognized"
    );

    let mut shifted: Vec<u8> = bytes;
    shifted.extend_from_slice(b"xISc(");
    assert!(
        identify_file(&shifted, NOW_SECS)
            .findings
            .iter()
            .all(|finding| finding.family != "installshield"),
        "cabinet magic away from the overlay start must not be recognized"
    );

    let mut literal_only: Vec<u8> = corpus("dotnet/HelloAppAot.exe");
    literal_only.extend_from_slice(b"InstallShield ISSetupStream");
    assert!(
        identify_file(&literal_only, NOW_SECS)
            .findings
            .iter()
            .all(|finding| finding.family != "installshield"),
        "unanchored product-name strings must not identify an InstallShield container"
    );
}

fn corpus_root() -> PathBuf {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("corpus");
    path
}

fn corpus_path(rel: &str) -> PathBuf {
    let mut path: PathBuf = corpus_root();
    path.push(rel);
    path
}

fn native_aot_export(bytes: &[u8]) -> (usize, usize) {
    let image: PeImage = parse_pe_image(bytes).expect("reference PE parse");
    let directory = image
        .data_directories
        .first()
        .expect("export directory row");
    let export: usize = image
        .file_offset_for_rva(directory.virtual_address, bytes.len())
        .expect("export directory mapped");
    let names: usize = image
        .file_offset_for_rva(read_u32(bytes, export + 32), bytes.len())
        .expect("name pointer table mapped");
    let ordinals: usize = image
        .file_offset_for_rva(read_u32(bytes, export + 36), bytes.len())
        .expect("ordinal table mapped");
    let functions_rva: u32 = read_u32(bytes, export + 28);
    let names_count: usize = read_u32(bytes, export + 24) as usize;
    for index in 0..names_count {
        let name_rva: u32 = read_u32(bytes, names + index * 4);
        let name_offset: usize = image
            .file_offset_for_rva(name_rva, bytes.len())
            .expect("export name mapped");
        if bytes[name_offset..].starts_with(b"DotNetRuntimeDebugHeader\0") {
            let ordinal: usize =
                u16::from_le_bytes([bytes[ordinals + index * 2], bytes[ordinals + index * 2 + 1]])
                    as usize;
            let target_rva: u32 = read_u32(
                bytes,
                image
                    .file_offset_for_rva(functions_rva, bytes.len())
                    .expect("function table mapped")
                    + ordinal * 4,
            );
            let dndh_offset: usize = image
                .file_offset_for_rva(target_rva, bytes.len())
                .expect("DNDH target mapped");
            assert_eq!(&bytes[dndh_offset..dndh_offset + 4], b"DNDH");
            return (name_offset, dndh_offset);
        }
    }
    panic!("reference export parser did not find DotNetRuntimeDebugHeader");
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("u32 field"))
}

fn native_aot_ready_to_run(bytes: &[u8]) -> usize {
    let marker: &[u8] = b"RTR\0\x0A\0\x01\0\0\0\0\0\x22\0\x18\x01";
    let matches: Vec<usize> = bytes
        .windows(marker.len())
        .enumerate()
        .filter_map(|(offset, window): (usize, &[u8])| (window == marker).then_some(offset))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "independent RTR header marker must be unique"
    );
    matches[0]
}

fn assert_no_native_aot(bytes: &[u8], label: &str) {
    assert!(
        identify_file(bytes, NOW_SECS)
            .findings
            .iter()
            .all(|finding| finding.family != "nativeaot"),
        "{label} unexpectedly retained NativeAOT"
    );
}
