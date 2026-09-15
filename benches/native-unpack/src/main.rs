#![deny(unreachable_pub)]
use std::collections::BTreeSet;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic};
use object::{Object, ObjectSection, SectionFlags};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use disrobe_pass_native::packers::{
    GranuleRecovery, NspackLayout, NspackSection, PeImage as ParsedPeImage,
    PeSection as ParsedPeSection, SectionRole, build_loaded_image, parse_nspack_layout,
    parse_pe_image,
};
use disrobe_pass_native::{
    Arch, FsgUnpackOutput, MpressRecoveryStatus, MpressUnpackOutput, NspackEmulatedReport,
    PetitePhase2EmulatedOutput, RebuiltImage, SectionRecoveryReport, UpxUnpackOutput,
    YodasCrypterReport, YodasProtectorPhase2, disassemble, rebuild_passthrough,
    rebuild_unpacked_pe, section_recovery_report, unpack_aspack_phase2_emulated, unpack_fsg,
    unpack_kkrunchy_phase2_emulated, unpack_mew_rebuilt, unpack_mpress,
    unpack_nspack_emulated_with_baseline, unpack_pecompact_phase2_emulated,
    unpack_petite_phase2_emulated, unpack_upx, unpack_yodas_crypter, unpack_yodas_protector_phase2,
};

const IMAGE_SCN_MEM_EXECUTE: u64 = 0x2000_0000;
const UPX_IMAGE_BASE_RVA: usize = 0x1000;
const MAX_BENCH_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TEXT_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PE_SECTIONS: usize = 256;
const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn main() -> std::process::ExitCode {
    let check: bool = std::env::args().any(|a: String| a == "--check");
    match run(check) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("disrobe-bench-native-unpack: {err:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(check: bool) -> Result<()> {
    let bench_dir: PathBuf = manifest_dir();
    let root: PathBuf = workspace_root(&bench_dir)?;
    let corpus_root: PathBuf = root.join("corpus").join("native").join("packers");

    let unpack_rows: Vec<UnpackRow> = measure_unpack(&corpus_root);
    require_committed_family_measurements(&unpack_rows)?;
    let unpack_md: String = render_unpack(&unpack_rows);

    let recovery_doc: RecoveryDoc =
        load_recovery(&root.join("xtask").join("data").join("recovery.json"))?;
    let quality_md: String = render_quality(&recovery_doc)?;

    let unpack_out: PathBuf = bench_dir.join("results.md");
    let quality_out: PathBuf = root
        .join("benches")
        .join("decompile-quality")
        .join("results.md");

    if check {
        verify(&unpack_out, &unpack_md)?;
        verify(&quality_out, &quality_md)?;
        println!("disrobe-bench-native-unpack --check: both results.md match regeneration");
    } else {
        write_file(&unpack_out, &unpack_md)?;
        write_file(&quality_out, &quality_md)?;
        println!(
            "disrobe-bench-native-unpack: wrote {}",
            unpack_out.display()
        );
        println!(
            "disrobe-bench-native-unpack: wrote {}",
            quality_out.display()
        );
    }
    Ok(())
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root(bench_dir: &Path) -> Result<PathBuf> {
    let Some(benches): Option<&Path> = bench_dir.parent() else {
        bail!("bench manifest dir has no parent: {}", bench_dir.display());
    };
    let Some(root): Option<&Path> = benches.parent() else {
        bail!("benches dir has no parent: {}", benches.display());
    };
    Ok(root.to_path_buf())
}

#[derive(Debug)]
struct ExecMetrics {
    entropy: f64,
    instructions: usize,
    intra_calls: usize,
}

#[derive(Debug)]
enum ByteIdentity {
    Measured {
        section: &'static str,
        pct: f64,
        diff: usize,
        total: usize,
    },
    NotApplicable(&'static str),
}

#[derive(Debug)]
enum RowState {
    Measured {
        binary: String,
        packed: Option<ExecMetrics>,
        unpacked: ExecMetrics,
        identity: ByteIdentity,
        note: String,
    },
    Walled {
        binary: String,
        note: String,
    },
    Skipped {
        reason: String,
    },
    Error {
        binary: String,
        message: String,
    },
}

#[derive(Debug)]
struct UnpackRow {
    packer: &'static str,
    state: RowState,
}

fn read_corpus(corpus_root: &Path, family: &str, name: &str) -> Option<Vec<u8>> {
    read_bounded_file(&corpus_root.join(family).join(name), MAX_BENCH_FILE_BYTES).ok()
}

#[allow(clippy::suboptimal_flops)]
fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts: [u64; 256] = [0u64; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len: f64 = bytes.len() as f64;
    let mut h: f64 = 0.0;
    for &c in &counts {
        if c > 0 {
            let p: f64 = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

fn instruction_count(code: &[u8], base: u64, arch: Arch) -> usize {
    let Ok(insns): Result<Vec<_>, _> = disassemble(arch, base, code) else {
        return 0;
    };
    insns
        .iter()
        .filter(|i: &&disrobe_pass_native::DisasmInsn| !i.bytes.is_empty())
        .count()
}

#[cfg(test)]
fn distinct_intra_call_targets(code: &[u8], base: u64) -> usize {
    distinct_intra_call_targets_for_arch(code, base, Arch::X86)
}

fn distinct_intra_call_targets_for_arch(code: &[u8], base: u64, arch: Arch) -> usize {
    let lo: u64 = base;
    let hi: u64 = base + code.len() as u64;
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    let bitness: u32 = if arch == Arch::X86_64 { 64 } else { 32 };
    for start in 0..code.len() {
        let mut decoder: Decoder<'_> = Decoder::with_ip(
            bitness,
            &code[start..],
            base + start as u64,
            DecoderOptions::NONE,
        );
        let mut insn: Instruction = Instruction::default();
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            continue;
        }
        if matches!(insn.mnemonic(), Mnemonic::Call)
            && matches!(insn.flow_control(), FlowControl::Call)
            && insn.is_call_near()
        {
            let target: u64 = insn.near_branch_target();
            if target >= lo && target < hi {
                targets.insert(target);
            }
        }
    }
    targets.len()
}

fn executable_section(pe: &[u8]) -> Option<(u64, Vec<u8>)> {
    let file: object::File<'_> = object::File::parse(pe).ok()?;
    for section in file.sections() {
        let executable: bool = match section.flags() {
            SectionFlags::Coff { characteristics } => {
                characteristics & IMAGE_SCN_MEM_EXECUTE as u32 != 0
            }
            _ => false,
        };
        if !executable {
            continue;
        }
        let Ok(data): Result<&[u8], _> = section.data() else {
            continue;
        };
        if !data.is_empty() {
            return Some((section.address(), data.to_vec()));
        }
    }
    None
}

fn metrics_for(base: u64, code: &[u8]) -> ExecMetrics {
    metrics_for_arch(base, code, Arch::X86)
}

fn metrics_for_arch(base: u64, code: &[u8], arch: Arch) -> ExecMetrics {
    ExecMetrics {
        entropy: shannon_entropy(code),
        instructions: instruction_count(code, base, arch),
        intra_calls: distinct_intra_call_targets_for_arch(code, base, arch),
    }
}

fn measure_unpack(corpus_root: &Path) -> Vec<UnpackRow> {
    let mut rows: Vec<UnpackRow> = Vec::new();
    rows.push(row_upx(corpus_root));
    rows.extend(rows_aspack(corpus_root));
    rows.extend(rows_pecompact(corpus_root));
    rows.extend(rows_mew(corpus_root));
    rows.push(row_kkrunchy(corpus_root));
    rows.extend(rows_yodas_crypter(corpus_root));
    rows.extend(rows_yodas_protector(corpus_root));
    rows.extend(rows_committed_families(corpus_root));
    rows
}

fn row_upx(corpus_root: &Path) -> UnpackRow {
    let binary: String = "hello (Rust x64)".to_owned();
    let Some(packed): Option<Vec<u8>> = read_corpus(corpus_root, "upx", "hello.packed.nrv2b.exe")
    else {
        return UnpackRow {
            packer: "UPX",
            state: RowState::Skipped {
                reason: "hello.packed.nrv2b.exe not committed".to_owned(),
            },
        };
    };
    let original: Option<Vec<u8>> = read_corpus(corpus_root, "upx", "hello.original.exe");
    let out: UpxUnpackOutput = match unpack_upx(&packed) {
        Ok(o) => o,
        Err(e) => {
            return UnpackRow {
                packer: "UPX",
                state: RowState::Error {
                    binary,
                    message: e.to_string(),
                },
            };
        }
    };
    let packed_exec: Option<ExecMetrics> = executable_section(&packed)
        .map(|(b, c): (u64, Vec<u8>)| metrics_for_arch(b, &c, Arch::X86_64));
    let unpacked: ExecMetrics =
        upx_recovered_text_metrics(&out.recovered_image, original.as_deref()).unwrap_or_else(
            || {
                metrics_for_arch(
                    UPX_IMAGE_BASE_RVA as u64,
                    &out.recovered_image,
                    Arch::X86_64,
                )
            },
        );
    let identity: ByteIdentity = match original.as_deref() {
        Some(orig) => upx_text_identity(&out.recovered_image, orig),
        None => ByteIdentity::NotApplicable("original.exe not committed"),
    };
    let note: String = format!(
        "{} method, CT filter {:#04x}, UCL adler {}",
        upx_method_label(out.method),
        out.filter_id,
        if out.adler_verified {
            "verified"
        } else {
            "unverified"
        },
    );
    UnpackRow {
        packer: "UPX",
        state: RowState::Measured {
            binary,
            packed: packed_exec,
            unpacked,
            identity,
            note,
        },
    }
}

const fn upx_method_label(method: disrobe_pass_native::UpxMethod) -> &'static str {
    match method {
        disrobe_pass_native::UpxMethod::Nrv2b => "NRV2B",
        disrobe_pass_native::UpxMethod::Nrv2d => "NRV2D",
        disrobe_pass_native::UpxMethod::Nrv2e => "NRV2E",
        disrobe_pass_native::UpxMethod::Lzma => "LZMA",
    }
}

fn upx_text_identity(recovered: &[u8], original: &[u8]) -> ByteIdentity {
    let Some(sections): Option<Vec<PeSection>> = parse_pe_sections(original) else {
        return ByteIdentity::NotApplicable("could not parse original PE");
    };
    let Some(text): Option<&PeSection> = sections.iter().find(|s: &&PeSection| s.name == ".text")
    else {
        return ByteIdentity::NotApplicable("original has no .text section");
    };
    let img_off: usize = text.rva.wrapping_sub(UPX_IMAGE_BASE_RVA);
    if img_off + text.content_len > recovered.len()
        || text.disk_off + text.content_len > original.len()
    {
        return ByteIdentity::NotApplicable("recovered image shorter than .text extent");
    }
    let rec: &[u8] = &recovered[img_off..img_off + text.content_len];
    let orig: &[u8] = &original[text.disk_off..text.disk_off + text.content_len];
    let diff: usize = byte_diff(rec, orig);
    let total: usize = text.content_len;
    let pct: f64 = if total == 0 {
        0.0
    } else {
        100.0 * (total - diff) as f64 / total as f64
    };
    ByteIdentity::Measured {
        section: ".text",
        pct,
        diff,
        total,
    }
}

fn upx_recovered_text_metrics(recovered: &[u8], original: Option<&[u8]>) -> Option<ExecMetrics> {
    let sections: Vec<PeSection> = parse_pe_sections(original?)?;
    let text: &PeSection = sections.iter().find(|s: &&PeSection| s.name == ".text")?;
    let img_off: usize = text.rva.wrapping_sub(UPX_IMAGE_BASE_RVA);
    let slice: &[u8] = recovered.get(img_off..img_off + text.content_len)?;
    Some(metrics_for_arch(text.rva as u64, slice, Arch::X86_64))
}

fn rows_aspack(corpus_root: &Path) -> Vec<UnpackRow> {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.aspack.exe"),
        ("AccessEnum", "AccessEnum.packed.aspack.exe"),
    ];
    let mut rows: Vec<UnpackRow> = Vec::with_capacity(cases.len());
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = read_corpus(corpus_root, "aspack", packed_name) else {
            rows.push(UnpackRow {
                packer: "ASPack",
                state: RowState::Skipped {
                    reason: format!("{packed_name} not committed"),
                },
            });
            continue;
        };
        let binary: String = format!("{label} (Sysinternals)");
        let row: RowState = match unpack_aspack_phase2_emulated(&packed, None).and_then(|out| {
            rebuild_unpacked_pe(&packed, &out.recovered_memory_image, out.oep_estimate)
        }) {
            Ok(rebuilt) => overlay_row(binary, &packed, &rebuilt),
            Err(e) => RowState::Error {
                binary,
                message: e.to_string(),
            },
        };
        rows.push(UnpackRow {
            packer: "ASPack",
            state: row,
        });
    }
    rows
}

fn rows_pecompact(corpus_root: &Path) -> Vec<UnpackRow> {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.pecompact.exe"),
        ("AccessEnum", "AccessEnum.packed.pecompact.exe"),
    ];
    let mut rows: Vec<UnpackRow> = Vec::with_capacity(cases.len());
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = read_corpus(corpus_root, "pecompact", packed_name)
        else {
            rows.push(UnpackRow {
                packer: "PECompact",
                state: RowState::Skipped {
                    reason: format!("{packed_name} not committed"),
                },
            });
            continue;
        };
        let binary: String = format!("{label} (Sysinternals)");
        let row: RowState = match unpack_pecompact_phase2_emulated(&packed, None).and_then(|out| {
            rebuild_unpacked_pe(&packed, &out.recovered_memory_image, out.oep_estimate)
        }) {
            Ok(rebuilt) => overlay_row(binary, &packed, &rebuilt),
            Err(e) => RowState::Error {
                binary,
                message: e.to_string(),
            },
        };
        rows.push(UnpackRow {
            packer: "PECompact",
            state: row,
        });
    }
    rows
}

fn overlay_row(binary: String, packed: &[u8], rebuilt: &RebuiltImage) -> RowState {
    let packed_exec: Option<ExecMetrics> =
        executable_section(packed).map(|(b, c): (u64, Vec<u8>)| metrics_for(b, &c));
    let Some((base, code)): Option<(u64, Vec<u8>)> = executable_section(&rebuilt.bytes) else {
        return RowState::Error {
            binary,
            message: "rebuilt PE exposed no executable section".to_owned(),
        };
    };
    RowState::Measured {
        binary,
        packed: packed_exec,
        unpacked: metrics_for(base, &code),
        identity: ByteIdentity::NotApplicable("decompressed-image overlay, no disk-aligned ref"),
        note: "phase-2 stub emulation overlays decompressed section at load RVA".to_owned(),
    }
}

fn rows_mew(corpus_root: &Path) -> Vec<UnpackRow> {
    let cases: &[(&str, &str)] = &[
        ("Clockres", "Clockres.packed.mew.exe"),
        ("AccessEnum", "AccessEnum.packed.mew.exe"),
        ("Autologon", "Autologon.packed.mew.exe"),
    ];
    let mut rows: Vec<UnpackRow> = Vec::with_capacity(cases.len());
    for (label, packed_name) in cases {
        let Some(packed): Option<Vec<u8>> = read_corpus(corpus_root, "mew", packed_name) else {
            rows.push(UnpackRow {
                packer: "MEW",
                state: RowState::Skipped {
                    reason: format!("{packed_name} not committed"),
                },
            });
            continue;
        };
        let binary: String = format!("{label} (Sysinternals)");
        let row: RowState = match unpack_mew_rebuilt(&packed)
            .and_then(|rebuilt| rebuild_passthrough(&rebuilt.file_image))
        {
            Ok(image) => {
                let packed_exec: Option<ExecMetrics> =
                    executable_section(&packed).map(|(b, c): (u64, Vec<u8>)| metrics_for(b, &c));
                match executable_section(&image.bytes) {
                    Some((base, code)) => RowState::Measured {
                        binary,
                        packed: packed_exec,
                        unpacked: metrics_for(base, &code),
                        identity: ByteIdentity::NotApplicable(
                            "flat-dumped image, no disk-aligned ref",
                        ),
                        note: "aPLib + LZMA1 rebuild of flat dumped PE32, OEP stamped".to_owned(),
                    },
                    None => RowState::Error {
                        binary,
                        message: "rebuilt MEW image exposed no executable section".to_owned(),
                    },
                }
            }
            Err(e) => RowState::Error {
                binary,
                message: e.to_string(),
            },
        };
        rows.push(UnpackRow {
            packer: "MEW",
            state: row,
        });
    }
    rows
}

fn row_kkrunchy(corpus_root: &Path) -> UnpackRow {
    let binary: String = "hello (NASM PE32, classic)".to_owned();
    let Some(packed): Option<Vec<u8>> =
        read_corpus(corpus_root, "kkrunchy", "hello.packed.kkrunchy_classic.exe")
    else {
        return UnpackRow {
            packer: "kkrunchy",
            state: RowState::Skipped {
                reason: "hello.packed.kkrunchy_classic.exe not committed".to_owned(),
            },
        };
    };
    let row: RowState = match unpack_kkrunchy_phase2_emulated(&packed)
        .and_then(|out| rebuild_passthrough(&out.recovered_file_image))
    {
        Ok(image) => {
            let packed_exec: Option<ExecMetrics> =
                executable_section(&packed).map(|(b, c): (u64, Vec<u8>)| metrics_for(b, &c));
            match executable_section(&image.bytes) {
                Some((base, code)) => RowState::Measured {
                    binary,
                    packed: packed_exec,
                    unpacked: metrics_for(base, &code),
                    identity: ByteIdentity::NotApplicable(
                        "decompressed standalone PE, no disk-aligned ref",
                    ),
                    note: "classic CCA range-coder decode, standalone PE emitted".to_owned(),
                },
                None => RowState::Error {
                    binary,
                    message: "rebuilt kkrunchy image exposed no executable section".to_owned(),
                },
            }
        }
        Err(e) => RowState::Error {
            binary,
            message: e.to_string(),
        },
    };
    UnpackRow {
        packer: "kkrunchy",
        state: row,
    }
}

fn rows_yodas_crypter(corpus_root: &Path) -> Vec<UnpackRow> {
    let cases: &[(&str, &str, &str)] = &[
        (
            "Clockres",
            "Clockres.packed.yodascrypter.exe",
            "Clockres.original.exe",
        ),
        (
            "AccessEnum",
            "AccessEnum.packed.yodascrypter.exe",
            "AccessEnum.original.exe",
        ),
    ];
    let mut rows: Vec<UnpackRow> = Vec::with_capacity(cases.len());
    for (label, packed_name, orig_name) in cases {
        let (Some(packed), Some(original)): (Option<Vec<u8>>, Option<Vec<u8>>) = (
            read_corpus(corpus_root, "yodas_crypter", packed_name),
            read_corpus(corpus_root, "yodas_crypter", orig_name),
        ) else {
            rows.push(UnpackRow {
                packer: "Yoda's Crypter",
                state: RowState::Skipped {
                    reason: format!("{packed_name} / {orig_name} not committed"),
                },
            });
            continue;
        };
        let binary: String = format!("{label} (Sysinternals)");
        let row: RowState = match unpack_yodas_crypter(&packed, &original) {
            Ok(report) => yodas_crypter_row(binary, &packed, &original, &report),
            Err(e) => RowState::Error {
                binary,
                message: e.to_string(),
            },
        };
        rows.push(UnpackRow {
            packer: "Yoda's Crypter",
            state: row,
        });
    }
    rows
}

fn yodas_crypter_section<'a>(
    report: &'a YodasCrypterReport,
    name: &[u8],
) -> Option<&'a disrobe_pass_native::YodasRecoveredSection> {
    report
        .recovered_sections
        .iter()
        .find(|s: &&disrobe_pass_native::YodasRecoveredSection| s.name == name)
}

fn yodas_crypter_row(
    binary: String,
    packed: &[u8],
    _original: &[u8],
    report: &YodasCrypterReport,
) -> RowState {
    let rsrc: Option<&disrobe_pass_native::YodasRecoveredSection> =
        yodas_crypter_section(report, b".rsrc");
    let identity: ByteIdentity = match rsrc {
        Some(sec) if sec.compared_bytes > 0 => ByteIdentity::Measured {
            section: ".rsrc",
            pct: sec.plaintext_pct(),
            diff: sec.compared_bytes - sec.matching_bytes,
            total: sec.compared_bytes,
        },
        _ => ByteIdentity::NotApplicable("unpacker reported no comparable .rsrc"),
    };
    let text_pct: f64 = yodas_crypter_section(report, b".text").map_or(
        0.0,
        disrobe_pass_native::YodasRecoveredSection::plaintext_pct,
    );
    let packed_exec: Option<ExecMetrics> =
        executable_section(packed).map(|(b, c): (u64, Vec<u8>)| metrics_for(b, &c));
    let unpacked: ExecMetrics = match yodas_crypter_section(report, b".text") {
        Some(sec) if !sec.bytes.is_empty() => {
            metrics_for(u64::from(sec.virtual_address), &sec.bytes)
        }
        _ => ExecMetrics {
            entropy: 0.0,
            instructions: 0,
            intra_calls: 0,
        },
    };
    RowState::Measured {
        binary,
        packed: packed_exec,
        unpacked,
        identity,
        note: format!(
            ".rsrc recovers byte-identical; .text decrypts to {text_pct:.2}% plaintext \
             through the stub emulator"
        ),
    }
}

fn rows_yodas_protector(corpus_root: &Path) -> Vec<UnpackRow> {
    let cases: &[(&str, &str, &str)] = &[
        (
            "Clockres",
            "Clockres.packed.yodasprotector.exe",
            "Clockres.original.exe",
        ),
        (
            "AccessEnum",
            "AccessEnum.packed.yodasprotector.exe",
            "AccessEnum.original.exe",
        ),
    ];
    let mut rows: Vec<UnpackRow> = Vec::with_capacity(cases.len());
    for (label, packed_name, orig_name) in cases {
        let (Some(packed), Some(original)): (Option<Vec<u8>>, Option<Vec<u8>>) = (
            read_corpus(corpus_root, "yodas_protector", packed_name),
            read_corpus(corpus_root, "yodas_protector", orig_name),
        ) else {
            rows.push(UnpackRow {
                packer: "Yoda's Protector",
                state: RowState::Skipped {
                    reason: format!("{packed_name} / {orig_name} not committed"),
                },
            });
            continue;
        };
        let binary: String = format!("{label} (Sysinternals)");
        let row: RowState = match unpack_yodas_protector_phase2(&packed, Some(&original)) {
            Ok(out) => yodas_protector_row(binary, out),
            Err(e) => RowState::Error {
                binary,
                message: e.to_string(),
            },
        };
        rows.push(UnpackRow {
            packer: "Yoda's Protector",
            state: row,
        });
    }
    rows
}

fn yodas_protector_row(binary: String, out: YodasProtectorPhase2) -> RowState {
    RowState::Walled {
        binary,
        note: format!(
            "runtime key unavailable; the stub emulator mutates {} content bytes; \
             resources recover {:.1}% in place",
            out.content_bytes_mutated_by_stub, out.resource_recovery_pct,
        ),
    }
}

const REQUIRED_COMMITTED_FAMILIES: [&str; 4] = ["FSG", "NSPack", "Petite", "MPRESS"];

#[derive(Clone, Copy)]
struct RequiredFixture {
    family: &'static str,
    name: &'static str,
    size_bytes: usize,
    sha256: &'static str,
}

const FSG_PACKED: RequiredFixture = RequiredFixture {
    family: "fsg",
    name: "Hash.packed.fsg.exe",
    size_bytes: 16_624,
    sha256: "2476e7a8cbeaae8a826060daf28b9031e188285cb79b814dfe26eb39bd133bb4",
};
const FSG_ORIGINAL: RequiredFixture = RequiredFixture {
    family: "fsg",
    name: "Hash.original.exe",
    size_bytes: 29_184,
    sha256: "43c5182f830865247d98f53dd488b02c3235d25d0c2179f48b3f8adcf6fa8e38",
};
const NSPACK_PACKED: RequiredFixture = RequiredFixture {
    family: "nspack",
    name: "hash.packed.nspack.exe",
    size_bytes: 19_068,
    sha256: "527903a5e0957c4565fa1ebcd5665c6f96e3ef2f5a403ab9970d0be12bec9946",
};
const NSPACK_ORIGINAL: RequiredFixture = RequiredFixture {
    family: "nspack",
    name: "hash.original.exe",
    size_bytes: 29_184,
    sha256: "43c5182f830865247d98f53dd488b02c3235d25d0c2179f48b3f8adcf6fa8e38",
};
const PETITE_PACKED: RequiredFixture = RequiredFixture {
    family: "petite",
    name: "hello.exe",
    size_bytes: 52_144,
    sha256: "4022e6a82ad782a94da07da46ec4af3e721af111b456e5f0e3b05331d510ac8d",
};
const PETITE_ORIGINAL: RequiredFixture = RequiredFixture {
    family: "petite",
    name: "hello.original.exe",
    size_bytes: 94_720,
    sha256: "3b263798b36403015c20cc778b4e8831f911ea2514995c17d8bdb8a30f9b8554",
};
const MPRESS_PACKED: RequiredFixture = RequiredFixture {
    family: "mpress",
    name: "gauntlet/gauntlet_target.packed.mpress219.exe",
    size_bytes: 50_176,
    sha256: "aa0c292ee175da3d554b3b25859ac501ba9e6e816a789f0897178010cd129ee8",
};
const MPRESS_ORIGINAL: RequiredFixture = RequiredFixture {
    family: "mpress",
    name: "gauntlet/gauntlet_target.original.exe",
    size_bytes: 104_448,
    sha256: "37d55b50d63cc0005e0ec2b3070e4d16019f8358ac48c54b4f8e71fc114ee70a",
};

fn rows_committed_families(corpus_root: &Path) -> Vec<UnpackRow> {
    vec![
        required_family_row(
            "FSG",
            "Hash (PackingData x86)",
            measure_fsg_hash(corpus_root),
        ),
        required_family_row(
            "NSPack",
            "hash (PackingData x86)",
            measure_nspack_hash(corpus_root),
        ),
        required_family_row(
            "Petite",
            "hello (Rust x86)",
            measure_petite_hello(corpus_root),
        ),
        required_family_row(
            "MPRESS",
            "gauntlet_target (Rust x64)",
            measure_mpress_gauntlet(corpus_root),
        ),
    ]
}

fn required_family_row(
    packer: &'static str,
    binary: &'static str,
    measured: Result<RowState>,
) -> UnpackRow {
    UnpackRow {
        packer,
        state: measured.unwrap_or_else(|error: eyre::Report| RowState::Error {
            binary: binary.to_owned(),
            message: format!("{error:#}"),
        }),
    }
}

fn require_committed_family_measurements(rows: &[UnpackRow]) -> Result<()> {
    for family in REQUIRED_COMMITTED_FAMILIES {
        let mut matching = rows.iter().filter(|row: &&UnpackRow| row.packer == family);
        let Some(row): Option<&UnpackRow> = matching.next() else {
            bail!("required committed {family} measurement is absent");
        };
        if matching.next().is_some() {
            bail!("required committed {family} measurement appears more than once");
        }
        match &row.state {
            RowState::Measured { .. } => {}
            RowState::Error { message, .. } => {
                bail!("required committed {family} measurement failed: {message}");
            }
            RowState::Skipped { reason } => {
                bail!("required committed {family} measurement was skipped: {reason}");
            }
            RowState::Walled { note, .. } => {
                bail!("required committed {family} measurement was walled: {note}");
            }
        }
    }
    Ok(())
}

fn measure_fsg_hash(corpus_root: &Path) -> Result<RowState> {
    let packed: Vec<u8> = read_required_corpus(corpus_root, FSG_PACKED)?;
    let original: Vec<u8> = read_required_corpus(corpus_root, FSG_ORIGINAL)?;
    let output: FsgUnpackOutput = unpack_fsg(&packed).wrap_err("unpacking committed FSG Hash")?;
    measured_memory_row(
        "Hash (PackingData x86)",
        &packed,
        &original,
        output.raw_image,
        &[],
        Arch::X86,
        "FSG 2.0 aPLib block recovery",
    )
}

fn measure_nspack_hash(corpus_root: &Path) -> Result<RowState> {
    let packed: Vec<u8> = read_required_corpus(corpus_root, NSPACK_PACKED)?;
    let original: Vec<u8> = read_required_corpus(corpus_root, NSPACK_ORIGINAL)?;
    let output: NspackEmulatedReport = unpack_nspack_emulated_with_baseline(&packed, None)
        .wrap_err("unpacking committed NSPack hash")?;
    let layout: NspackLayout<'_> =
        parse_nspack_layout(&packed).wrap_err("parsing committed NSPack hash layout")?;
    let nsp0: &NspackSection<'_> = layout
        .sections
        .iter()
        .find(|section: &&NspackSection<'_>| section.name.starts_with(b"nsp0"))
        .ok_or_else(|| eyre::eyre!("committed NSPack hash has no nsp0 section"))?;
    let prefix: usize = usize::try_from(nsp0.virtual_address)
        .wrap_err("converting committed NSPack nsp0 virtual address")?;
    let recovered_len: usize = prefix
        .checked_add(output.decompressed_image.len())
        .ok_or_else(|| eyre::eyre!("committed NSPack recovered image length overflows"))?;
    if u64::try_from(recovered_len).unwrap_or(u64::MAX) > MAX_BENCH_FILE_BYTES {
        bail!("committed NSPack recovered image exceeds {MAX_BENCH_FILE_BYTES} bytes");
    }
    let mut recovered: Vec<u8> = vec![0u8; prefix];
    recovered.extend_from_slice(&output.decompressed_image);
    measured_memory_row(
        "hash (PackingData x86)",
        &packed,
        &original,
        recovered,
        &[b"nsp0", b"nsp1"],
        Arch::X86,
        "NSPack 3.7 range-decoder recovery",
    )
}

fn measure_petite_hello(corpus_root: &Path) -> Result<RowState> {
    let packed: Vec<u8> = read_required_corpus(corpus_root, PETITE_PACKED)?;
    let original: Vec<u8> = read_required_corpus(corpus_root, PETITE_ORIGINAL)?;
    let output: PetitePhase2EmulatedOutput =
        unpack_petite_phase2_emulated(&packed).wrap_err("unpacking committed Petite hello")?;
    measured_memory_row(
        "hello (Rust x86)",
        &packed,
        &original,
        output.recovered_memory_image,
        &[b"petite"],
        Arch::X86,
        "Petite 2.4 bounded stub emulation",
    )
}

fn measure_mpress_gauntlet(corpus_root: &Path) -> Result<RowState> {
    let packed: Vec<u8> = read_required_corpus(corpus_root, MPRESS_PACKED)?;
    let original: Vec<u8> = read_required_corpus(corpus_root, MPRESS_ORIGINAL)?;
    let output: MpressUnpackOutput =
        unpack_mpress(&packed).wrap_err("unpacking committed MPRESS gauntlet_target")?;
    if output.recovery_status != MpressRecoveryStatus::LzmatDecoded {
        bail!(
            "committed MPRESS gauntlet_target stopped at {:?} instead of LZMAT decoding",
            output.recovery_status
        );
    }
    measured_memory_row(
        "gauntlet_target (Rust x64)",
        &packed,
        &original,
        output.decompressed_image,
        &[],
        Arch::X86_64,
        "MPRESS 2.19 LZMAT decode and branch unfilter",
    )
}

fn read_required_corpus(corpus_root: &Path, fixture: RequiredFixture) -> Result<Vec<u8>> {
    let path: PathBuf = corpus_root.join(fixture.family).join(fixture.name);
    let bytes: Vec<u8> = read_bounded_file(&path, MAX_BENCH_FILE_BYTES)
        .wrap_err_with(|| format!("required committed fixture {}", path.display()))?;
    validate_required_fixture(fixture, &bytes)?;
    Ok(bytes)
}

fn validate_required_fixture(fixture: RequiredFixture, bytes: &[u8]) -> Result<()> {
    if bytes.len() != fixture.size_bytes {
        bail!(
            "required committed fixture {}/{} is {} bytes, expected {}",
            fixture.family,
            fixture.name,
            bytes.len(),
            fixture.size_bytes
        );
    }
    let actual_sha256: String = format!("{:x}", Sha256::digest(bytes));
    if actual_sha256 != fixture.sha256 {
        bail!(
            "required committed fixture {}/{} has sha256 {actual_sha256}, expected {}",
            fixture.family,
            fixture.name,
            fixture.sha256
        );
    }
    Ok(())
}

fn complete_loaded_span(mut recovered: Vec<u8>, original: &[u8]) -> Result<(Vec<u8>, usize)> {
    let recovered_len: usize = recovered.len();
    let image: ParsedPeImage =
        parse_pe_image(original).wrap_err("parsing committed original PE")?;
    if image.sections.len() > MAX_PE_SECTIONS {
        bail!(
            "committed original PE has {} sections, above the {MAX_PE_SECTIONS} section limit",
            image.sections.len()
        );
    }
    let section_end: u64 = image
        .sections
        .iter()
        .try_fold(0u64, |highest: u64, section: &ParsedPeSection| {
            let end: u64 = u64::from(section.virtual_address)
                .checked_add(u64::from(section.virtual_size.max(section.raw_size)))?;
            Some(highest.max(end))
        })
        .ok_or_else(|| eyre::eyre!("committed original PE section span overflows"))?;
    let span: u64 = u64::from(image.size_of_image).max(section_end);
    if span > MAX_BENCH_FILE_BYTES {
        bail!("committed original loaded span {span} exceeds {MAX_BENCH_FILE_BYTES} bytes");
    }
    if u64::try_from(recovered.len()).unwrap_or(u64::MAX) > MAX_BENCH_FILE_BYTES {
        bail!(
            "recovered loaded image {} exceeds {MAX_BENCH_FILE_BYTES} bytes",
            recovered.len()
        );
    }
    let span: usize =
        usize::try_from(span).wrap_err("converting committed original loaded span")?;
    if recovered.len() < span {
        recovered.resize(span, 0u8);
    }
    Ok((recovered, recovered_len))
}

fn recovery_report_with_presence(
    original: &[u8],
    recovered: Vec<u8>,
    stub_names: &[&[u8]],
) -> Result<(Vec<u8>, SectionRecoveryReport)> {
    let (recovered, recovered_len): (Vec<u8>, usize) = complete_loaded_span(recovered, original)?;
    let reference: Vec<u8> = build_loaded_image(original, recovered.len())
        .wrap_err("building committed original loaded image")?;
    let mut report: SectionRecoveryReport =
        section_recovery_report(original, &recovered, stub_names)
            .wrap_err("comparing recovered memory with committed original")?;
    for section in &mut report.sections {
        let start: usize = usize::try_from(section.virtual_address)
            .wrap_err("converting original section virtual address")?;
        let end: usize = start
            .checked_add(section.compared)
            .ok_or_else(|| eyre::eyre!("original section span overflows"))?;
        let missing_start: usize = recovered_len.max(start).min(end);
        let missing_reference: &[u8] = reference
            .get(missing_start..end)
            .ok_or_else(|| eyre::eyre!("original loaded image does not cover section span"))?;
        let padded_matches: usize = memchr::memchr_iter(0, missing_reference).count();
        section.matching = section
            .matching
            .checked_sub(padded_matches)
            .ok_or_else(|| eyre::eyre!("presence adjustment exceeds section matches"))?;
    }
    report.content_matching = report
        .sections
        .iter()
        .filter(|section: &&GranuleRecovery| section.role == SectionRole::Content)
        .map(|section: &GranuleRecovery| section.matching)
        .sum();
    report.content_compared = report
        .sections
        .iter()
        .filter(|section: &&GranuleRecovery| section.role == SectionRole::Content)
        .map(|section: &GranuleRecovery| section.compared)
        .sum();
    Ok((recovered, report))
}

fn entry_section(pe: &[u8]) -> Result<(u64, &[u8])> {
    let file: object::File<'_> = object::File::parse(pe).wrap_err("parsing committed packed PE")?;
    let entry: u64 = file.entry();
    for section in file.sections() {
        let base: u64 = section.address();
        let Some(offset): Option<u64> = entry.checked_sub(base) else {
            continue;
        };
        if offset < section.size() {
            let bytes: &[u8] = section
                .data()
                .wrap_err("reading packed entry-point section")?;
            if offset >= u64::try_from(bytes.len()).unwrap_or(u64::MAX) {
                bail!("committed packed PE entry point has no file-backed bytes");
            }
            return Ok((base, bytes));
        }
    }
    bail!("committed packed PE entry point is outside every section")
}

fn measured_memory_row(
    binary: &str,
    packed: &[u8],
    original: &[u8],
    recovered: Vec<u8>,
    stub_names: &[&[u8]],
    arch: Arch,
    method: &str,
) -> Result<RowState> {
    let recovered_len: usize = recovered.len();
    let (recovered, report): (Vec<u8>, SectionRecoveryReport) =
        recovery_report_with_presence(original, recovered, stub_names)?;
    if report.content_compared == 0 {
        bail!("committed original exposes no comparable content bytes");
    }
    let text: &GranuleRecovery = report
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .ok_or_else(|| eyre::eyre!("committed original exposes no .text section"))?;
    if text.compared == 0 {
        bail!("committed original .text section has no comparable bytes");
    }
    let text_start: usize = usize::try_from(text.virtual_address)
        .wrap_err("converting committed original .text virtual address")?;
    let text_end: usize = text_start
        .checked_add(text.compared)
        .ok_or_else(|| eyre::eyre!("committed original .text span overflows"))?;
    let recovered_text: &[u8] = recovered
        .get(text_start.min(recovered_len)..text_end.min(recovered_len))
        .ok_or_else(|| eyre::eyre!("recovered image does not cover committed original .text"))?;
    let (packed_base, packed_code): (u64, &[u8]) = entry_section(packed)?;
    let text_diff: usize = text.compared - text.matching;
    Ok(RowState::Measured {
        binary: binary.to_owned(),
        packed: Some(metrics_for_arch(packed_base, packed_code, arch)),
        unpacked: metrics_for_arch(u64::from(text.virtual_address), recovered_text, arch),
        identity: ByteIdentity::Measured {
            section: ".text",
            pct: text.recovery_pct(),
            diff: text_diff,
            total: text.compared,
        },
        note: format!(
            "{method}; packed metrics cover the entry-point section; content recovery {}/{} ({:.2}%) against the committed original",
            report.content_matching,
            report.content_compared,
            report.content_recovery_pct()
        ),
    })
}

struct PeSection {
    name: String,
    rva: usize,
    content_len: usize,
    disk_off: usize,
}

fn parse_pe_sections(image: &[u8]) -> Option<Vec<PeSection>> {
    let pe_off: usize = u32::from_le_bytes([
        *image.get(0x3c)?,
        *image.get(0x3d)?,
        *image.get(0x3e)?,
        *image.get(0x3f)?,
    ]) as usize;
    if image.get(pe_off..pe_off + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = pe_off + 4;
    let num_sections: usize =
        u16::from_le_bytes([*image.get(coff + 2)?, *image.get(coff + 3)?]) as usize;
    if num_sections > MAX_PE_SECTIONS {
        return None;
    }
    let opt_size: usize =
        u16::from_le_bytes([*image.get(coff + 16)?, *image.get(coff + 17)?]) as usize;
    let sect_table: usize = coff + 20 + opt_size;
    let table_bytes: usize = num_sections.checked_mul(40)?;
    let table_end: usize = sect_table.checked_add(table_bytes)?;
    image.get(sect_table..table_end)?;
    let mut out: Vec<PeSection> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let entry: usize = sect_table + i * 40;
        let name: String = String::from_utf8_lossy(image.get(entry..entry + 8)?)
            .trim_end_matches('\0')
            .to_owned();
        let vsize: usize = read_u32(image, entry + 8)? as usize;
        let rva: usize = read_u32(image, entry + 12)? as usize;
        let rsize: usize = read_u32(image, entry + 16)? as usize;
        let disk_off: usize = read_u32(image, entry + 20)? as usize;
        out.push(PeSection {
            name,
            rva,
            content_len: vsize.min(rsize),
            disk_off,
        });
    }
    Some(out)
}

fn read_u32(image: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *image.get(at)?,
        *image.get(at + 1)?,
        *image.get(at + 2)?,
        *image.get(at + 3)?,
    ]))
}

fn byte_diff(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .filter(|(x, y): &(&u8, &u8)| x != y)
        .count()
}

fn render_unpack(rows: &[UnpackRow]) -> String {
    let mut md: String = String::with_capacity(8192);
    md.push_str("# Native unpacking measurements\n\n");
    md.push_str(
        "The samples below are statically recovered through `disrobe-pass-native`'s unpack API. \
         Section bytes are compared with committed originals where an aligned reference exists. \
         Entropy, instruction counts, and call targets describe the selected code span. The four \
         FSG, NSPack, Petite, and MPRESS packed spans are their file-backed entry-point sections; \
         FSG's section has no execute flag. Instruction counts use \
         `disrobe_pass_native::disassemble`, and call targets use iced-x86 decoding.\n\n",
    );
    md.push_str(
        "Regenerate with `cargo run -p disrobe-bench-native-unpack`; \
                 `--check` fails if the committed table drifts from a fresh run.\n\n",
    );

    md.push_str("## Signals\n\n");
    md.push_str(
        "- byte-identity: percentage of the named recovered section that is byte-for-byte the \
         committed original section. Loaded-memory outputs are compared at the original section \
         RVAs with the original section span as the denominator; rows without an independent, \
         aligned original remain `n/a`.\n",
    );
    md.push_str(
        "- entropy (bits/byte): Shannon entropy of the selected span, from 0 for identical bytes \
         to 8 for a uniform byte distribution. Padding and compressed data affect this value.\n",
    );
    md.push_str(
        "- instructions: linear-sweep count decoded using each fixture's x86 or x86-64 \
         architecture. Data in the selected span can also decode as instructions.\n",
    );
    md.push_str(
        "- intra-calls: distinct near-`call` targets inside the selected span. This counts \
         candidate function entries, not confirmed functions.\n\n",
    );

    md.push_str(
        "| packer | binary | byte-identity | entropy (packed -> unpacked) | instructions (packed -> unpacked) | intra-calls (packed -> unpacked) | notes |\n",
    );
    md.push_str("|---|---|---|---|---|---|---|\n");
    for row in rows {
        md.push_str(&render_unpack_row(row));
    }
    md.push('\n');

    md.push_str("## Reading the table\n\n");
    md.push_str(
        "- UPX: the recovered `.text` is byte-identical to the committed original. Both packed \
         and recovered spans are decoded as x86-64.\n",
    );
    md.push_str(
        "- ASPack / PECompact: the packed `.text` is near-random with zero resolvable calls; after \
         the phase-2 overlay the same section at the same RVA decodes to dozens to hundreds of real \
         intra-code calls with entropy below 6.6.\n",
    );
    md.push_str(
        "- MEW: the packed image carries no analyzable executable section (the `MEW` section is \
         virtual-only, shown as `n/a`); the rebuilt PE exposes a large `.text` that decodes to tens \
         of thousands of instructions with hundreds of intra-code calls.\n",
    );
    md.push_str(
        "- kkrunchy classic: the decompressed `hello` is tiny and calls imports directly, so the \
         call signal is zero on both sides; the entropy collapse and recovered instruction count \
         are the recovery signal.\n",
    );
    md.push_str(
        "- Yoda's Crypter: `.rsrc` recovers byte-identical to the committed original (the \
         byte-identity column) and `.text` decrypts to full plaintext through the stub emulator (the \
         note's plaintext fraction), its entropy dropping from near-random to code-like. This is \
         asserted in `crates/disrobe-pass-native/tests/packer_real_samples.rs`.\n",
    );
    md.push_str(
        "- Yoda's Protector: the stream key is a runtime value absent from the file. The bounded \
         stub emulator mutates zero content bytes; resources recover in place, while encrypted \
         code remains unavailable for byte-identity comparison.\n",
    );
    md.push_str(
        "- FSG, NSPack, Petite, and MPRESS: one committed packed/original pair per family is \
         measured through the public in-process recovery API. The fixed population is FSG \
         `Hash.packed.fsg.exe` / `Hash.original.exe`, NSPack `hash.packed.nspack.exe` / \
         `hash.original.exe`, Petite `hello.exe` / `hello.original.exe`, and MPRESS \
         `gauntlet/gauntlet_target.packed.mpress219.exe` / \
         `gauntlet/gauntlet_target.original.exe`. Each input is checked against its pinned size and \
         SHA-256 before recovery. A missing, unreadable, malformed, mutated, or unrecoverable \
         member fails regeneration rather than shrinking this population.\n\n",
    );
    md.push_str(
        "The benchmark's `committed_family_population_is_measured_from_known_originals` test \
         checks the four added families. Related recovery checks live in \
         `crates/disrobe-pass-native/tests/native_unpack_disasm.rs`, \
         `crates/disrobe-pass-native/tests/packer_real_samples.rs`, and \
         `crates/disrobe-pass-native/tests/upx_unpack_all.rs`.\n",
    );
    md
}

fn render_unpack_row(row: &UnpackRow) -> String {
    match &row.state {
        RowState::Measured {
            binary,
            packed,
            unpacked,
            identity,
            note,
        } => {
            let identity_cell: String = render_identity(identity);
            let entropy_cell: String = render_pair_f(
                packed.as_ref().map(|m: &ExecMetrics| m.entropy),
                unpacked.entropy,
            );
            let insn_cell: String = render_pair_u(
                packed.as_ref().map(|m: &ExecMetrics| m.instructions),
                unpacked.instructions,
            );
            let call_cell: String = render_pair_u(
                packed.as_ref().map(|m: &ExecMetrics| m.intra_calls),
                unpacked.intra_calls,
            );
            format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                row.packer,
                binary,
                identity_cell,
                entropy_cell,
                insn_cell,
                call_cell,
                esc_cell(note),
            )
        }
        RowState::Walled { binary, note } => format!(
            "| {} | {} | walled (no key in artifact) | n/a | n/a | n/a | {} |\n",
            row.packer,
            binary,
            esc_cell(note),
        ),
        RowState::Skipped { reason } => format!(
            "| {} | not committed | skipped | - | - | - | {} |\n",
            row.packer,
            esc_cell(reason),
        ),
        RowState::Error { binary, message } => format!(
            "| {} | {} | error | - | - | - | {} |\n",
            row.packer,
            binary,
            esc_cell(message),
        ),
    }
}

fn render_identity(identity: &ByteIdentity) -> String {
    match identity {
        ByteIdentity::Measured {
            section,
            pct,
            diff,
            total,
        } => {
            if *diff == 0 {
                format!("{section} {pct:.2}% ({total} B, 0 diff)")
            } else {
                format!("{section} {pct:.2}% ({diff}/{total} B diff)")
            }
        }
        ByteIdentity::NotApplicable(why) => format!("n/a ({why})"),
    }
}

fn render_pair_f(packed: Option<f64>, unpacked: f64) -> String {
    packed.map_or_else(
        || format!("n/a -> {unpacked:.2}"),
        |p: f64| format!("{p:.2} -> {unpacked:.2}"),
    )
}

fn render_pair_u(packed: Option<usize>, unpacked: usize) -> String {
    packed.map_or_else(
        || format!("n/a -> {unpacked}"),
        |p: usize| format!("{p} -> {unpacked}"),
    )
}

fn esc_cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

#[derive(Debug, Deserialize)]
struct RecoveryDoc {
    title: String,
    subtitle: String,
    note: String,
    groups: Vec<RecoveryGroup>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGroup {
    heading: String,
    kind: String,
    bars: Vec<RecoveryBar>,
}

#[derive(Debug, Deserialize)]
struct RecoveryBar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    delivered: Option<u64>,
    #[serde(default)]
    delivered_label: Option<String>,
    #[serde(default)]
    denominator_label: Option<String>,
    source: String,
}

fn load_recovery(path: &Path) -> Result<RecoveryDoc> {
    let raw: String = read_bounded_string(path, MAX_TEXT_FILE_BYTES)?;
    let recovery: RecoveryDoc =
        serde_json::from_str(&raw).wrap_err_with(|| format!("parsing {}", path.display()))?;
    validate_recovery(&recovery)?;
    Ok(recovery)
}

fn validate_recovery(recovery: &RecoveryDoc) -> Result<()> {
    for group in &recovery.groups {
        for bar in &group.bars {
            if group.kind == "count_pair" {
                let Some(delivered): Option<u64> = bar.delivered else {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry delivered and detected counts for a count_pair",
                        group.heading,
                        bar.label
                    );
                };
                let Some(detected): Option<u64> = bar.detected else {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry delivered and detected counts for a count_pair",
                        group.heading,
                        bar.label
                    );
                };
                if delivered > MAX_JAVASCRIPT_SAFE_INTEGER || detected > MAX_JAVASCRIPT_SAFE_INTEGER
                {
                    bail!(
                        "recovery.json: `{}` / `{}` exceeds the JavaScript safe-integer ceiling",
                        group.heading,
                        bar.label
                    );
                }
                if detected == 0 || delivered > detected {
                    bail!(
                        "recovery.json: `{}` / `{}` must carry a positive detected count no smaller than delivered",
                        group.heading,
                        bar.label
                    );
                }
            }
            validate_count_pair_label(
                group,
                bar,
                "delivered_label",
                bar.delivered_label.as_deref(),
            )?;
            validate_count_pair_label(
                group,
                bar,
                "denominator_label",
                bar.denominator_label.as_deref(),
            )?;
        }
    }
    Ok(())
}

fn validate_count_pair_label(
    group: &RecoveryGroup,
    bar: &RecoveryBar,
    field: &str,
    value: Option<&str>,
) -> Result<()> {
    let Some(label): Option<&str> = value else {
        return Ok(());
    };
    if group.kind != "count_pair" {
        bail!(
            "recovery.json: `{}` / `{}` has {field} outside a count_pair group",
            group.heading,
            bar.label
        );
    }
    let unsafe_cell: bool = label
        .chars()
        .any(|character: char| character.is_control() || character == '|');
    if label.is_empty() || label.trim() != label || unsafe_cell {
        bail!(
            "recovery.json: `{}` / `{}` has an invalid {field}",
            group.heading,
            bar.label
        );
    }
    Ok(())
}

fn read_bounded_string(path: &Path, limit: u64) -> Result<String> {
    let bytes: Vec<u8> = read_bounded_file(path, limit)?;
    String::from_utf8(bytes).wrap_err_with(|| format!("reading utf-8 {}", path.display()))
}

fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file: fs::File =
        fs::File::open(path).wrap_err_with(|| format!("reading {}", path.display()))?;
    let reserve: usize = file
        .metadata()
        .map(|metadata: fs::Metadata| metadata.len().min(limit))
        .ok()
        .and_then(|len: u64| usize::try_from(len).ok())
        .unwrap_or(0);
    let mut reader: std::io::Take<fs::File> = file.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::with_capacity(reserve);
    reader
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("reading {}", path.display()))?;
    let len: u64 = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if len > limit {
        bail!("{} exceeds {limit} bytes", path.display());
    }
    Ok(bytes)
}

fn render_quality(doc: &RecoveryDoc) -> Result<String> {
    const FOCUS: &[&str] = &["Python", "JVM", "Dalvik", ".NET", "WebAssembly"];
    let mut md: String = String::with_capacity(8192);
    md.push_str("# Decompile and recovery quality (CI-gated numbers)\n\n");
    push_line(&mut md, &doc.title);
    md.push('\n');
    push_line(&mut md, &doc.subtitle);
    md.push('\n');
    push_line(&mut md, &doc.note);
    md.push('\n');
    md.push_str(
        "Figures and their verification commands come from `xtask/data/recovery.json`, which also \
         supplies the recovery chart. Values are reproduced without rounding. Regenerate with \
         `cargo run -p disrobe-bench-native-unpack`.\n\n",
    );

    md.push_str("## Headline ecosystems (Python, JVM/Dalvik, .NET, WebAssembly)\n\n");
    md.push_str("| ecosystem | metric | measured | gate / source |\n");
    md.push_str("|---|---|---|---|\n");
    for group in &doc.groups {
        for bar in &group.bars {
            let hit: bool = FOCUS
                .iter()
                .any(|f: &&str| group.heading.contains(f) || bar.label.contains(f));
            if hit {
                md.push_str(&render_quality_row(group, bar)?);
            }
        }
    }
    md.push('\n');

    md.push_str("## Full measured set (every ecosystem in recovery.json)\n\n");
    md.push_str("| ecosystem | metric | measured | gate / source |\n");
    md.push_str("|---|---|---|---|\n");
    for group in &doc.groups {
        for bar in &group.bars {
            md.push_str(&render_quality_row(group, bar)?);
        }
    }
    md.push('\n');
    md.push_str(
        "The headline section is a filtered view of the full set; both are generated from the same \
         committed JSON in one pass, so they cannot disagree.\n",
    );
    Ok(md)
}

fn push_line(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

fn render_quality_row(group: &RecoveryGroup, bar: &RecoveryBar) -> Result<String> {
    let value_cell: String = quality_value(group, bar)?;
    let source_cell: String = esc_cell(&bar.source);
    Ok(format!(
        "| {} | {} | {} | {} |\n",
        esc_cell(&group.heading),
        esc_cell(&bar.label),
        value_cell,
        source_cell,
    ))
}

fn quality_value(group: &RecoveryGroup, bar: &RecoveryBar) -> Result<String> {
    let base: String = match group.kind.as_str() {
        "percent" => bar
            .value
            .map_or_else(|| "n/a".to_owned(), |v: f64| format!("{v:.2}%")),
        "count" => bar.value.map_or_else(
            || "n/a".to_owned(),
            |v: f64| {
                let amount: i64 = v as i64;
                let unit: &str = if amount == 1 { "family" } else { "families" };
                format!("{amount} {unit}")
            },
        ),
        "scalar" => bar
            .value
            .map_or_else(|| "n/a".to_owned(), |v: f64| format!("{} fns", v as i64)),
        "count_pair" => {
            let delivered: u64 = bar.delivered.ok_or_else(|| {
                eyre::eyre!(
                    "recovery.json: `{}` / `{}` has no delivered count for a count_pair",
                    group.heading,
                    bar.label
                )
            })?;
            let detected: u64 = bar.detected.ok_or_else(|| {
                eyre::eyre!(
                    "recovery.json: `{}` / `{}` has no detected count for a count_pair",
                    group.heading,
                    bar.label
                )
            })?;
            let verb: &str = bar.delivered_label.as_deref().unwrap_or("delivered");
            let denominator: &str = bar.denominator_label.as_deref().unwrap_or("detected");
            format!("{delivered} {verb} / {detected} {denominator}")
        }
        other => format!("({other})"),
    };
    match &bar.detail {
        Some(detail) => Ok(format!("{base} - {}", esc_cell(detail))),
        None => Ok(base),
    }
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, content.as_bytes()).wrap_err_with(|| format!("writing {}", path.display()))
}

fn verify(path: &Path, expected: &str) -> Result<()> {
    match read_bounded_string(path, MAX_TEXT_FILE_BYTES) {
        Ok(on_disk) if on_disk == expected => Ok(()),
        Ok(_) => bail!(
            "{} is stale; run `cargo run -p disrobe-bench-native-unpack`",
            path.display()
        ),
        Err(err) => bail!("{} unreadable: {err}", path.display()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn committed_family_population_is_measured_from_known_originals() -> Result<()> {
        let bench_dir: PathBuf = manifest_dir();
        let root: PathBuf = workspace_root(&bench_dir).unwrap();
        let corpus_root: PathBuf = root.join("corpus").join("native").join("packers");
        let all_rows: Vec<UnpackRow> = measure_unpack(&corpus_root);
        require_committed_family_measurements(&all_rows).unwrap();
        let rows: Vec<&UnpackRow> = all_rows
            .iter()
            .filter(|row: &&UnpackRow| REQUIRED_COMMITTED_FAMILIES.contains(&row.packer))
            .collect();
        assert_eq!(
            rows.iter()
                .map(|row: &&UnpackRow| row.packer)
                .collect::<Vec<_>>(),
            REQUIRED_COMMITTED_FAMILIES,
            "the fixed population is one committed pair from each required family"
        );

        let expected_text_bytes: [usize; 4] = [18_188, 18_188, 70_796, 73_160];
        for (row, expected_total) in rows.iter().zip(expected_text_bytes) {
            let RowState::Measured {
                unpacked,
                identity:
                    ByteIdentity::Measured {
                        section,
                        pct,
                        diff,
                        total,
                    },
                ..
            } = &row.state
            else {
                bail!("{} must produce a measured row", row.packer);
            };
            assert_eq!(*section, ".text", "{} comparison section", row.packer);
            assert_eq!(*total, expected_total, "{} .text denominator", row.packer);
            assert_eq!(*diff, 0, "{} recovered .text byte differences", row.packer);
            assert_eq!(*pct, 100.0, "{} recovered .text identity", row.packer);
            assert!(
                unpacked.instructions > 0,
                "{} recovered .text must disassemble into instructions",
                row.packer
            );
        }
        Ok(())
    }

    #[test]
    fn missing_required_family_population_fails_closed() {
        let missing_root: PathBuf = manifest_dir().join("absent-required-corpus");
        let rows: Vec<UnpackRow> = rows_committed_families(&missing_root);
        let error: eyre::Report = require_committed_family_measurements(&rows).unwrap_err();
        let message: String = format!("{error:#}");
        assert!(
            message.contains("required committed FSG measurement failed")
                && message.contains("Hash.packed.fsg.exe"),
            "a missing required fixture must name its family and file: {message}"
        );
    }

    #[test]
    fn same_size_fixture_mutation_is_rejected() {
        let bench_dir: PathBuf = manifest_dir();
        let root: PathBuf = workspace_root(&bench_dir).unwrap();
        let corpus_root: PathBuf = root.join("corpus").join("native").join("packers");
        let mut bytes: Vec<u8> = read_required_corpus(&corpus_root, FSG_ORIGINAL).unwrap();
        bytes[0] ^= 0xff;
        assert_eq!(bytes.len(), FSG_ORIGINAL.size_bytes);
        let error: eyre::Report = validate_required_fixture(FSG_ORIGINAL, &bytes).unwrap_err();
        let message: String = format!("{error:#}");
        assert!(
            message.contains("sha256")
                && message.contains(
                    "expected 43c5182f830865247d98f53dd488b02c3235d25d0c2179f48b3f8adcf6fa8e38"
                ),
            "a same-size fixture mutation must fail its declared hash: {message}"
        );
    }

    #[test]
    fn absent_recovered_zero_bytes_count_as_mismatches() {
        let original: Vec<u8> = benign_zero_text_pe();
        let (_, empty): (Vec<u8>, SectionRecoveryReport) =
            recovery_report_with_presence(&original, Vec::new(), &[]).unwrap();
        let empty_text: &GranuleRecovery = empty
            .sections
            .iter()
            .find(|section: &&GranuleRecovery| section.name == ".text")
            .unwrap();
        assert_eq!((empty_text.matching, empty_text.compared), (0, 4));
        assert_eq!((empty.content_matching, empty.content_compared), (0, 4));

        let mut one_present: Vec<u8> = vec![0u8; 0x1001];
        one_present[0x1000] = 0;
        let (_, truncated): (Vec<u8>, SectionRecoveryReport) =
            recovery_report_with_presence(&original, one_present, &[]).unwrap();
        let truncated_text: &GranuleRecovery = truncated
            .sections
            .iter()
            .find(|section: &&GranuleRecovery| section.name == ".text")
            .unwrap();
        assert_eq!((truncated_text.matching, truncated_text.compared), (1, 4));
        assert_eq!(
            (truncated.content_matching, truncated.content_compared),
            (1, 4)
        );
    }

    fn benign_zero_text_pe() -> Vec<u8> {
        let mut image: Vec<u8> = vec![0u8; 0x204];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0x00e0u16.to_le_bytes());
        image[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());
        image[0xb4..0xb8].copy_from_slice(&0x0040_0000u32.to_le_bytes());
        image[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes());
        image[0xbc..0xc0].copy_from_slice(&0x200u32.to_le_bytes());
        image[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        image[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        let section: usize = 0x178;
        image[section..section + 8].copy_from_slice(b".text\0\0\0");
        image[section + 8..section + 12].copy_from_slice(&4u32.to_le_bytes());
        image[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[section + 16..section + 20].copy_from_slice(&4u32.to_le_bytes());
        image[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[section + 36..section + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        image
    }

    #[test]
    fn entropy_is_zero_for_uniform_bytes_and_eight_for_full_spread() {
        let flat: Vec<u8> = vec![0u8; 4096];
        assert_eq!(shannon_entropy(&flat), 0.0);
        let spread: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let h: f64 = shannon_entropy(&spread);
        assert!(
            (h - 8.0).abs() < 1e-6,
            "uniform 256-symbol stream is 8 bits/byte, got {h}"
        );
    }

    #[test]
    fn byte_diff_counts_mismatches() {
        assert_eq!(byte_diff(b"abcd", b"abcd"), 0);
        assert_eq!(byte_diff(b"abcd", b"abXd"), 1);
        assert_eq!(byte_diff(b"abcd", b"ab"), 0);
    }

    #[test]
    fn instruction_count_uses_in_house_disassembler() {
        let code: [u8; 3] = [0x90, 0x90, 0xC3];
        assert_eq!(instruction_count(&code, 0x1000, Arch::X86), 3);
    }

    #[test]
    fn upx_text_metrics_decode_rex_prefixes_as_x64() {
        let original: Vec<u8> = benign_zero_text_pe();
        let code: [u8; 4] = [0x48, 0x89, 0xc8, 0xc3];
        let measured: ExecMetrics = upx_recovered_text_metrics(&code, Some(&original)).unwrap();
        assert_eq!(measured.instructions, 2);
        assert_eq!(metrics_for_arch(0x1000, &code, Arch::X86).instructions, 3);
    }

    #[test]
    fn distinct_intra_call_targets_resolves_a_near_call() {
        let mut code: Vec<u8> = vec![0xCCu8; 0x40];
        let base: i64 = 0x1000;
        let at: i64 = 0x10;
        let target: i64 = 0x1000;
        let next: i64 = base + at + 5;
        let rel: i32 = (target - next) as i32;
        let at_idx: usize = at as usize;
        code[at_idx] = 0xE8;
        code[at_idx + 1..at_idx + 5].copy_from_slice(&rel.to_le_bytes());
        assert_eq!(distinct_intra_call_targets(&code, base as u64), 1);
    }

    #[test]
    fn pe_section_count_above_cap_is_rejected_before_allocation() {
        let mut image: Vec<u8> = vec![0u8; 0x200];
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x86..0x88].copy_from_slice(&257u16.to_le_bytes());
        assert!(parse_pe_sections(&image).is_none());
    }

    #[test]
    fn bounded_file_reader_rejects_oversized_file() {
        let base: PathBuf = std::env::temp_dir().join("disrobe_native_unpack_bound_test");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let path: PathBuf = base.join("large.bin");
        fs::write(&path, b"abcd").unwrap();
        let err: eyre::Report = read_bounded_file(&path, 3).unwrap_err();
        assert!(
            err.to_string().contains("exceeds 3 bytes"),
            "oversized read must report the cap, got {err:?}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn render_identity_marks_clean_recovery_and_na() {
        let clean: ByteIdentity = ByteIdentity::Measured {
            section: ".text",
            pct: 100.0,
            diff: 0,
            total: 73160,
        };
        assert_eq!(render_identity(&clean), ".text 100.00% (73160 B, 0 diff)");
        let partial: ByteIdentity = ByteIdentity::Measured {
            section: ".rsrc",
            pct: 50.0,
            diff: 10,
            total: 20,
        };
        assert_eq!(render_identity(&partial), ".rsrc 50.00% (10/20 B diff)");
        let na: ByteIdentity = ByteIdentity::NotApplicable("no ref");
        assert_eq!(render_identity(&na), "n/a (no ref)");
    }

    #[test]
    fn render_pairs_handle_missing_packed_side() {
        assert_eq!(render_pair_f(Some(7.99), 6.48), "7.99 -> 6.48");
        assert_eq!(render_pair_f(None, 4.27), "n/a -> 4.27");
        assert_eq!(render_pair_u(Some(0), 201), "0 -> 201");
        assert_eq!(render_pair_u(None, 81101), "n/a -> 81101");
    }

    #[test]
    fn esc_cell_escapes_pipes_and_newlines() {
        assert_eq!(esc_cell("a|b\nc"), "a\\|b c");
    }

    #[test]
    fn quality_value_formats_each_kind_from_committed_fields() -> Result<()> {
        let percent: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "percent".to_owned(),
            bars: Vec::new(),
        };
        let bar: RecoveryBar = RecoveryBar {
            label: "l".to_owned(),
            value: Some(92.76),
            detail: None,
            detected: None,
            delivered: None,
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        };
        assert_eq!(quality_value(&percent, &bar)?, "92.76%");

        let count: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "count".to_owned(),
            bars: Vec::new(),
        };
        let one_family: RecoveryBar = RecoveryBar {
            label: "one".to_owned(),
            value: Some(1.0),
            detail: None,
            detected: None,
            delivered: None,
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        };
        let two_families: RecoveryBar = RecoveryBar {
            label: "two".to_owned(),
            value: Some(2.0),
            detail: None,
            detected: None,
            delivered: None,
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        };
        assert_eq!(quality_value(&count, &one_family)?, "1 family");
        assert_eq!(quality_value(&count, &two_families)?, "2 families");

        let pair: RecoveryGroup = RecoveryGroup {
            heading: "h".to_owned(),
            kind: "count_pair".to_owned(),
            bars: Vec::new(),
        };
        let pair_bar: RecoveryBar = RecoveryBar {
            label: "Containers".to_owned(),
            value: None,
            detail: None,
            detected: Some(47),
            delivered: Some(44),
            delivered_label: Some("extracted".to_owned()),
            denominator_label: None,
            source: "s".to_owned(),
        };
        assert_eq!(
            quality_value(&pair, &pair_bar)?,
            "44 extracted / 47 detected"
        );
        let custom_pair_bar: RecoveryBar = RecoveryBar {
            denominator_label: Some("manifest-named trial wrappers".to_owned()),
            ..pair_bar
        };
        assert_eq!(
            quality_value(&pair, &custom_pair_bar)?,
            "44 extracted / 47 manifest-named trial wrappers"
        );
        assert_eq!(
            render_quality_row(&pair, &custom_pair_bar)?,
            "| h | Containers | 44 extracted / 47 manifest-named trial wrappers | s |\n"
        );
        Ok(())
    }

    #[test]
    fn recovery_validation_rejects_unsafe_denominator_labels() {
        for label in [
            "  ",
            "named\rwrappers",
            "named\nwrappers",
            "named\twrappers",
            "named|wrappers",
        ] {
            let bar: RecoveryBar = RecoveryBar {
                label: "pair".to_owned(),
                value: None,
                detail: None,
                detected: Some(1),
                delivered: Some(1),
                delivered_label: None,
                denominator_label: Some(label.to_owned()),
                source: "s".to_owned(),
            };
            let recovery: RecoveryDoc = RecoveryDoc {
                title: "t".to_owned(),
                subtitle: "s".to_owned(),
                note: "n".to_owned(),
                groups: vec![RecoveryGroup {
                    heading: "h".to_owned(),
                    kind: "count_pair".to_owned(),
                    bars: vec![bar],
                }],
            };
            assert!(validate_recovery(&recovery).is_err(), "{label:?}");
        }
    }

    #[test]
    fn recovery_validation_rejects_unsafe_delivered_label() {
        let bar: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detail: None,
            detected: Some(1),
            delivered: Some(1),
            delivered_label: Some("decoded\tobjects".to_owned()),
            denominator_label: None,
            source: "s".to_owned(),
        };
        let recovery: RecoveryDoc = RecoveryDoc {
            title: "t".to_owned(),
            subtitle: "s".to_owned(),
            note: "n".to_owned(),
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![bar],
            }],
        };
        assert!(validate_recovery(&recovery).is_err());
    }

    #[test]
    fn recovery_validation_rejects_denominator_label_outside_count_pair() {
        let bar: RecoveryBar = RecoveryBar {
            label: "percent".to_owned(),
            value: Some(1.0),
            detail: None,
            detected: None,
            delivered: None,
            delivered_label: None,
            denominator_label: Some("trial wrappers".to_owned()),
            source: "s".to_owned(),
        };
        let recovery: RecoveryDoc = RecoveryDoc {
            title: "t".to_owned(),
            subtitle: "s".to_owned(),
            note: "n".to_owned(),
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "percent".to_owned(),
                bars: vec![bar],
            }],
        };
        assert!(validate_recovery(&recovery).is_err());
    }

    #[test]
    fn recovery_validation_rejects_count_pair_without_both_counts() {
        let missing_delivered: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detail: None,
            detected: Some(1),
            delivered: None,
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        };
        let missing_delivered_doc: RecoveryDoc = RecoveryDoc {
            title: "t".to_owned(),
            subtitle: "s".to_owned(),
            note: "n".to_owned(),
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![missing_delivered],
            }],
        };
        assert!(validate_recovery(&missing_delivered_doc).is_err());

        let missing_detected: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detail: None,
            detected: None,
            delivered: Some(1),
            delivered_label: None,
            denominator_label: None,
            source: "s".to_owned(),
        };
        let missing_detected_doc: RecoveryDoc = RecoveryDoc {
            title: "t".to_owned(),
            subtitle: "s".to_owned(),
            note: "n".to_owned(),
            groups: vec![RecoveryGroup {
                heading: "h".to_owned(),
                kind: "count_pair".to_owned(),
                bars: vec![missing_detected],
            }],
        };
        assert!(validate_recovery(&missing_detected_doc).is_err());
    }

    #[test]
    fn recovery_validation_rejects_invalid_count_pair_values() {
        for (delivered, detected) in [
            (Some(0), Some(0)),
            (Some(2), Some(1)),
            (Some(1), Some(MAX_JAVASCRIPT_SAFE_INTEGER + 1)),
        ] {
            let bar: RecoveryBar = RecoveryBar {
                label: "pair".to_owned(),
                value: None,
                detail: None,
                detected,
                delivered,
                delivered_label: None,
                denominator_label: None,
                source: "s".to_owned(),
            };
            let recovery: RecoveryDoc = RecoveryDoc {
                title: "t".to_owned(),
                subtitle: "s".to_owned(),
                note: "n".to_owned(),
                groups: vec![RecoveryGroup {
                    heading: "h".to_owned(),
                    kind: "count_pair".to_owned(),
                    bars: vec![bar],
                }],
            };
            assert!(validate_recovery(&recovery).is_err());
        }
    }

    #[test]
    #[cfg_attr(
        not(target_os = "linux"),
        ignore = "regen-idempotency is gated to the canonical linux ci platform; rendered metrics vary across host libm/float"
    )]
    fn committed_results_match_regeneration() {
        let bench_dir: PathBuf = manifest_dir();
        let root: PathBuf = workspace_root(&bench_dir).unwrap();
        let corpus_root: PathBuf = root.join("corpus").join("native").join("packers");

        let unpack_rows: Vec<UnpackRow> = measure_unpack(&corpus_root);
        require_committed_family_measurements(&unpack_rows).unwrap();
        let unpack_md: String = render_unpack(&unpack_rows);
        let recovery: RecoveryDoc =
            load_recovery(&root.join("xtask").join("data").join("recovery.json")).unwrap();
        let quality_md: String = render_quality(&recovery).unwrap();

        let unpack_disk: String = fs::read_to_string(bench_dir.join("results.md")).unwrap();
        let quality_disk: String = fs::read_to_string(
            root.join("benches")
                .join("decompile-quality")
                .join("results.md"),
        )
        .unwrap();
        assert_regenerated("benches/native-unpack/results.md", &unpack_disk, &unpack_md);
        assert_regenerated(
            "benches/decompile-quality/results.md",
            &quality_disk,
            &quality_md,
        );
    }

    #[test]
    fn a_stale_document_is_reported_by_line_rather_than_dumped_whole() {
        let disk: String = format!("header\nsame\n{}\ntail\n", "x".repeat(50_000));
        let fresh: String = format!("header\nsame\n{}\ntail\n", "y".repeat(50_000));
        let failure: Box<dyn std::any::Any + Send> =
            std::panic::catch_unwind(|| assert_regenerated("results.md", &disk, &fresh))
                .unwrap_err();
        let message: &str = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap();
        assert!(
            message.contains("first difference at line 3"),
            "the message must name the first differing line: {message}"
        );
        assert!(
            message.contains("committed lines 4, regenerated lines 4"),
            "the message must give both line counts: {message}"
        );
        assert!(
            message.len() < 3_000,
            "two 50,000-byte lines must not reach the log; a whole-document dump is what stalled \
             the ubuntu leg for over two hours. message length {}",
            message.len()
        );
        assert!(
            message.contains("(50000 bytes)"),
            "a truncated line must say how long the real line was: {message}"
        );
    }

    #[test]
    fn a_document_that_ends_early_is_named_rather_than_indexed_out_of_bounds() {
        let disk: String = "header\nsame\n".to_owned();
        let fresh: String = "header\nsame\nextra\n".to_owned();
        let failure: Box<dyn std::any::Any + Send> =
            std::panic::catch_unwind(|| assert_regenerated("results.md", &disk, &fresh))
                .unwrap_err();
        let message: &str = failure
            .downcast_ref::<String>()
            .map(String::as_str)
            .unwrap();
        assert!(
            message.contains("the committed file ends here"),
            "a document that runs out of lines must say so: {message}"
        );
        assert!(
            message.contains("first difference at line 3"),
            "the difference is the line past the end of the committed file: {message}"
        );
    }

    #[test]
    fn an_identical_document_does_not_panic() {
        assert_regenerated("results.md", "header\nsame\n", "header\nsame\n");
    }

    const DIFF_EXCERPT: usize = 200;

    fn excerpt(line: &str) -> String {
        let trimmed: String = line.chars().take(DIFF_EXCERPT).collect();
        if trimmed.len() < line.len() {
            format!("{trimmed}... ({} bytes)", line.len())
        } else {
            trimmed
        }
    }

    fn assert_regenerated(path: &str, disk: &str, regenerated: &str) {
        if disk == regenerated {
            return;
        }
        let on_disk: Vec<&str> = disk.lines().collect();
        let fresh: Vec<&str> = regenerated.lines().collect();
        let first: usize = on_disk
            .iter()
            .zip(fresh.iter())
            .position(|(left, right): (&&str, &&str)| left != right)
            .unwrap_or_else(|| on_disk.len().min(fresh.len()));
        let disk_line: String = on_disk.get(first).map_or_else(
            || "(the committed file ends here)".to_owned(),
            |line: &&str| excerpt(line),
        );
        let fresh_line: String = fresh.get(first).map_or_else(
            || "(the regenerated document ends here)".to_owned(),
            |line: &&str| excerpt(line),
        );
        assert_eq!(
            (&disk_line, on_disk.len(), disk.len()),
            (&fresh_line, fresh.len(), regenerated.len()),
            "{path} is stale; run `cargo run -p disrobe-bench-native-unpack`; \
             first difference at line {}; committed lines {}, regenerated lines {}",
            first + 1,
            on_disk.len(),
            fresh.len()
        );
    }
}
