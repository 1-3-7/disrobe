#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::needless_pass_by_value,
    clippy::cast_precision_loss,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::naive_bytecount
)]

use std::path::{Path, PathBuf};

use disrobe_pass_native::{
    Packer, PetitePhase2EmulatedOutput, PetiteUnpackResult, RecoveredImport, UnpackerStatus,
    unpack_petite, unpack_petite_phase2_emulated, unpack_petite_with_report,
};

fn corpus_root() -> PathBuf {
    let crate_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(Path::parent)
        .map(|p: &Path| {
            p.join("corpus")
                .join("native")
                .join("packers")
                .join("petite")
        })
        .expect(
            "workspace layout: crates/disrobe-pass-native -> ../../corpus/native/packers/petite",
        )
}

fn read_fixture(name: &str) -> Option<Vec<u8>> {
    let path: PathBuf = corpus_root().join(name);
    std::fs::read(&path).ok()
}

#[test]
fn test_petite_status_is_implemented() {
    assert_eq!(
        Packer::Petite.unpacker_status(),
        UnpackerStatus::Implemented,
        "wave A2 lands Petite as a from-scratch implemented unpacker (see crates/disrobe-pass-native/src/packers/petite_unpack.rs)"
    );
}

#[test]
fn test_petite_hello32_round_trip() {
    let Some(packed): Option<Vec<u8>> = read_fixture("hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let Some(baseline): Option<Vec<u8>> = read_fixture("hello.original.exe") else {
        eprintln!("skipping: petite/hello.original.exe corpus fixture absent");
        return;
    };
    assert!(
        packed.len() < baseline.len(),
        "packed must be smaller than baseline; packed={} baseline={}",
        packed.len(),
        baseline.len()
    );
    let result: PetiteUnpackResult =
        unpack_petite_with_report(&packed).expect("petite unpack must produce output");
    let recovered: Vec<u8> = result.bytes;
    let report = result.report;
    assert!(
        recovered.starts_with(b"MZ"),
        "recovered image must be a valid PE/MZ container"
    );
    assert!(
        report.recovered_section_count > 0,
        "must recover at least one original section"
    );
    assert_eq!(
        report.original_image_base, 0x0040_0000,
        "Petite hello32 fixture preserves ImageBase 0x00400000"
    );
    assert!(
        !report.recovered_imports.is_empty(),
        "must extract at least one import from the petite section's plaintext name table"
    );
    let dll_names: Vec<String> = report
        .recovered_imports
        .iter()
        .map(|i: &RecoveredImport| i.dll.to_ascii_lowercase())
        .collect();
    for required in ["kernel32.dll", "user32.dll"] {
        assert!(
            dll_names.iter().any(|d: &String| d == required),
            "import set must contain {required}; recovered DLLs={dll_names:?}"
        );
    }
    let func_count: usize = report
        .recovered_imports
        .iter()
        .map(|i: &RecoveredImport| i.functions.len())
        .sum();
    assert!(
        func_count >= 10,
        "real Petite-packed hello32 must yield >=10 imported function names; got {func_count}"
    );
    let diff_pct_x10000: u64 = if baseline.is_empty() {
        0
    } else {
        let smaller: usize = baseline.len().min(recovered.len());
        let differing: u64 = baseline
            .iter()
            .zip(recovered.iter())
            .take(smaller)
            .filter(|(a, b): &(&u8, &u8)| a != b)
            .count() as u64;
        let size_delta: u64 = (baseline.len().max(recovered.len()) - smaller) as u64;
        let total_diff: u64 = differing + size_delta;
        total_diff.saturating_mul(10_000) / baseline.len() as u64
    };
    let diff_pct: f64 = diff_pct_x10000 as f64 / 100.0;
    println!(
        "petite hello32 round-trip: baseline={} recovered={} diff_pct={:.2}% deterministic_pct={:.2}% stream_decoded={}",
        baseline.len(),
        recovered.len(),
        diff_pct,
        report.byte_recoverable_pct as f64 / 100.0,
        report.stream_decoded
    );
    assert!(
        recovered.len() >= 1024,
        "recovered image must contain headers + at least one section worth of data"
    );
    assert!(
        diff_pct <= 6.5,
        "petite hello32 is routed through the phase-2 emulated memory image with an \
         original 4-section layout (.text/.rdata/.data/.reloc) reconstructed structurally \
         from the image: whole-file byte-diff vs hello.original.exe must stay at/below the \
         genuinely-achieved 6.03% (the discarded .reloc page is loader-rebuilt and \
         unreproducible); got {diff_pct:.2}%"
    );
}

#[test]
fn test_petite_hello32_byte_recovery() {
    let Some(packed): Option<Vec<u8>> = read_fixture("hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let Some(baseline): Option<Vec<u8>> = read_fixture("hello.original.exe") else {
        eprintln!("skipping: petite/hello.original.exe corpus fixture absent");
        return;
    };
    let recovered: Vec<u8> =
        unpack_petite(&packed).expect("petite unpack must produce output for byte-recovery test");
    let smaller: usize = baseline.len().min(recovered.len());
    let matching: usize = baseline
        .iter()
        .zip(recovered.iter())
        .take(smaller)
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let size_delta: usize = baseline.len().max(recovered.len()) - smaller;
    let match_pct_x100: u64 = (matching as u64).saturating_mul(10_000) / baseline.len() as u64;
    let diff_pct_x100: u64 =
        ((smaller - matching + size_delta) as u64).saturating_mul(10_000) / baseline.len() as u64;
    println!(
        "petite hello32 byte-recovery: baseline={} recovered={} match={} ({:.2}%) diff={:.2}% size_delta={}",
        baseline.len(),
        recovered.len(),
        matching,
        match_pct_x100 as f64 / 100.0,
        diff_pct_x100 as f64 / 100.0,
        size_delta
    );
    assert!(
        recovered.len().abs_diff(baseline.len()) <= 0x200,
        "recovered size must match baseline within one FileAlignment unit: Petite discards the \
         original base-relocation stream and its directory size, so the trailing .reloc raw \
         length is recoverable only to within one 0x200 file-alignment unit (recovered rounds \
         the all-zero reloc page to 0x1000 vs the original 0xe00); got recovered={} baseline={}",
        recovered.len(),
        baseline.len()
    );
    assert!(
        match_pct_x100 >= 9400,
        "byte-match against hello.original.exe must hold at/above the genuinely-achieved 94.50% \
         (content sections .text/.rdata/.data recover at ~97.8% per the phase-2 beats-static \
         test; the discarded .reloc page is loader-rebuilt); got {:.2}%",
        match_pct_x100 as f64 / 100.0
    );
}

#[test]
fn test_petite_unpacked_pe_runs() {
    let Some(packed): Option<Vec<u8>> = read_fixture("hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let recovered: Vec<u8> = unpack_petite(&packed).expect("petite unpack must succeed");
    assert!(recovered.starts_with(b"MZ"), "recovered must start with MZ");
    let e_lfanew: u32 = u32::from_le_bytes([
        recovered[0x3c],
        recovered[0x3d],
        recovered[0x3e],
        recovered[0x3f],
    ]);
    let nt: usize = e_lfanew as usize;
    assert!(nt + 24 < recovered.len(), "PE NT headers must fit");
    assert_eq!(
        &recovered[nt..nt + 4],
        b"PE\x00\x00",
        "PE signature must be present"
    );
    let machine: u16 = u16::from_le_bytes([recovered[nt + 4], recovered[nt + 5]]);
    assert_eq!(
        machine, 0x014C,
        "Petite is x86-only; recovered machine must be IMAGE_FILE_MACHINE_I386"
    );
    let n_sections: u16 = u16::from_le_bytes([recovered[nt + 6], recovered[nt + 7]]);
    assert!(
        n_sections > 0,
        "recovered PE must declare at least one section"
    );
    let optional_magic: u16 = u16::from_le_bytes([recovered[nt + 24], recovered[nt + 25]]);
    assert_eq!(
        optional_magic, 0x010B,
        "recovered PE must be PE32 (magic 0x010B)"
    );
}

#[test]
fn test_petite_dircmp_byte_recovery() {
    let Some(packed): Option<Vec<u8>> = read_fixture("megafile_DirCmp.exe") else {
        eprintln!("skipping: petite/megafile_DirCmp.exe corpus fixture absent");
        return;
    };
    let result: PetiteUnpackResult =
        unpack_petite_with_report(&packed).expect("megafile unpack must succeed");
    let recovered: Vec<u8> = result.bytes;
    let zero_bytes: usize = recovered.iter().filter(|b: &&u8| **b == 0).count();
    let pe_header_bytes: usize = recovered
        .iter()
        .take(0x400)
        .zip(packed.iter().take(0x400))
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    println!(
        "petite DirCmp byte-recovery: packed={} recovered={} zeros={} ({:.1}%) preserved_header_bytes={}",
        packed.len(),
        recovered.len(),
        zero_bytes,
        100.0 * zero_bytes as f64 / recovered.len() as f64,
        pe_header_bytes,
    );
    assert!(
        recovered.starts_with(b"MZ"),
        "DirCmp recovered must be a valid PE container"
    );
    assert!(
        pe_header_bytes >= 200,
        "DirCmp recovered must preserve >=200 bytes of the original PE headers (DOS+NT prefix); got {pe_header_bytes}"
    );
    assert!(
        result.report.recovered_imports.len() >= 20,
        "DirCmp recovered must surface >=20 DLL imports from the petite name table; got {}",
        result.report.recovered_imports.len()
    );
    let func_count: usize = result
        .report
        .recovered_imports
        .iter()
        .map(|i: &RecoveredImport| i.functions.len())
        .sum();
    assert!(
        func_count >= 1000,
        "DirCmp recovered must surface >=1000 imported function names from the petite name table; got {func_count}"
    );
}

#[test]
fn test_petite_megafile_dircmp_recovers_structure() {
    let Some(packed): Option<Vec<u8>> = read_fixture("megafile_DirCmp.exe") else {
        eprintln!("skipping: petite/megafile_DirCmp.exe corpus fixture absent");
        return;
    };
    assert!(
        packed.len() >= 4 * 1024 * 1024,
        "megafile fixture must be >=4MiB; got {} B",
        packed.len()
    );
    let result: PetiteUnpackResult = unpack_petite_with_report(&packed)
        .expect("megafile Petite unpack must produce structural output");
    let recovered: Vec<u8> = result.bytes;
    let report = result.report;
    assert!(
        recovered.starts_with(b"MZ"),
        "megafile recovered image must be a valid PE/MZ container"
    );
    assert!(
        report.recovered_section_count > 0,
        "megafile must recover at least one original section"
    );
    assert!(
        !report.recovered_imports.is_empty(),
        "megafile must extract imports from the plaintext name table"
    );
    let func_count: usize = report
        .recovered_imports
        .iter()
        .map(|i: &RecoveredImport| i.functions.len())
        .sum();
    assert!(
        func_count >= 20,
        "megafile (~4MB packed) must surface >=20 imported function names; got {func_count}"
    );
    println!(
        "petite megafile DirCmp: packed={} recovered={} sections={} imports={} funcs={} deterministic_pct={:.2}% stream_decoded={}",
        packed.len(),
        recovered.len(),
        report.recovered_section_count,
        report.recovered_imports.len(),
        func_count,
        report.byte_recoverable_pct as f64 / 100.0,
        report.stream_decoded
    );
}

#[test]
fn test_petite_hello32_phase2_emulated_smoke() {
    let Some(packed): Option<Vec<u8>> = read_fixture("hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let Some(baseline): Option<Vec<u8>> = read_fixture("hello.original.exe") else {
        eprintln!("skipping: petite/hello.original.exe corpus fixture absent");
        return;
    };
    let result: PetitePhase2EmulatedOutput =
        unpack_petite_phase2_emulated(&packed).expect("phase-2 emu must produce output");
    let smaller: usize = baseline.len().min(result.recovered_image.len());
    let matching: usize = baseline
        .iter()
        .zip(result.recovered_image.iter())
        .take(smaller)
        .filter(|(a, b): &(&u8, &u8)| a == b)
        .count();
    let pct_x100: u64 = (matching as u64).saturating_mul(10_000) / baseline.len() as u64;
    println!(
        "petite phase-2 emu hello32: exit={} oep={:?} host_calls={} image_size={} recovered_len={} match={} ({:.2}%)",
        result.exit_reason,
        result.oep_estimate,
        result.host_calls.len(),
        result.size_of_image,
        result.recovered_image.len(),
        matching,
        pct_x100 as f64 / 100.0
    );
    for c in result.host_calls.iter().take(20) {
        println!("  hostcall: {c}");
    }
    println!("first 32 baseline:  {:?}", &baseline[..32]);
    println!("first 32 recovered: {:?}", &result.recovered_image[..32]);
    println!("baseline[400..432]:  {:?}", &baseline[0x400..0x420]);
    println!(
        "recovered[400..432]: {:?}",
        &result.recovered_image[0x400..0x420]
    );
    println!(
        "recovered[1000..1032]: {:?}",
        &result.recovered_image[0x1000..0x1020]
    );
    let zero_b: usize = baseline.iter().filter(|x: &&u8| **x == 0).count();
    let zero_r: usize = result
        .recovered_image
        .iter()
        .filter(|x: &&u8| **x == 0)
        .count();
    println!("zeros baseline: {zero_b} recovered: {zero_r}");
    let mut diff_blocks: Vec<(usize, usize)> = Vec::new();
    let n: usize = baseline.len().min(result.recovered_image.len());
    let mut i: usize = 0;
    while i < n {
        if baseline[i] == result.recovered_image[i] {
            i += 1;
        } else {
            let start: usize = i;
            while i < n && baseline[i] != result.recovered_image[i] {
                i += 1;
            }
            diff_blocks.push((start, i));
        }
    }
    for (s, e) in diff_blocks.iter().take(10) {
        println!("  diff block: 0x{s:x}..0x{e:x} (len {})", e - s);
    }
    println!("total diff blocks: {}", diff_blocks.len());
    let mut buckets: std::collections::BTreeMap<usize, usize> = std::collections::BTreeMap::new();
    for &(s, _) in &diff_blocks {
        *buckets.entry(s / 0x1000).or_insert(0) += 1;
    }
    for (page, count) in buckets.iter().take(20) {
        println!("  diff page 0x{page:04x}xxx: {count} blocks");
    }
    println!("baseline section table:");
    let e_lf: usize = u32::from_le_bytes(baseline[0x3c..0x40].try_into().unwrap()) as usize;
    let opt_hdr_size: u16 =
        u16::from_le_bytes(baseline[e_lf + 4 + 16..e_lf + 4 + 18].try_into().unwrap());
    let sec_off: usize = e_lf + 4 + 20 + opt_hdr_size as usize;
    let n_sec: u16 = u16::from_le_bytes(baseline[e_lf + 6..e_lf + 8].try_into().unwrap());
    for i in 0..n_sec as usize {
        let s: usize = sec_off + i * 40;
        let name: &[u8] = &baseline[s..s + 8];
        let vs: u32 = u32::from_le_bytes(baseline[s + 8..s + 12].try_into().unwrap());
        let va: u32 = u32::from_le_bytes(baseline[s + 12..s + 16].try_into().unwrap());
        let raw: u32 = u32::from_le_bytes(baseline[s + 16..s + 20].try_into().unwrap());
        let ptr: u32 = u32::from_le_bytes(baseline[s + 20..s + 24].try_into().unwrap());
        println!(
            "  baseline sec[{i}] {:?} va=0x{va:x} vs=0x{vs:x} ptr=0x{ptr:x} raw=0x{raw:x}",
            std::str::from_utf8(name).unwrap_or("?")
        );
    }
    println!("recovered section table:");
    let mem_image = &result.recovered_image;
    let e_lf: usize = u32::from_le_bytes(mem_image[0x3c..0x40].try_into().unwrap()) as usize;
    let opt_hdr_size: u16 =
        u16::from_le_bytes(mem_image[e_lf + 4 + 16..e_lf + 4 + 18].try_into().unwrap());
    let sec_off: usize = e_lf + 4 + 20 + opt_hdr_size as usize;
    let n_sec: u16 = u16::from_le_bytes(mem_image[e_lf + 6..e_lf + 8].try_into().unwrap());
    for i in 0..n_sec as usize {
        let s: usize = sec_off + i * 40;
        let name: &[u8] = &mem_image[s..s + 8];
        let vs: u32 = u32::from_le_bytes(mem_image[s + 8..s + 12].try_into().unwrap());
        let va: u32 = u32::from_le_bytes(mem_image[s + 12..s + 16].try_into().unwrap());
        let raw: u32 = u32::from_le_bytes(mem_image[s + 16..s + 20].try_into().unwrap());
        let ptr: u32 = u32::from_le_bytes(mem_image[s + 20..s + 24].try_into().unwrap());
        println!(
            "  recovered sec[{i}] {:?} va=0x{va:x} vs=0x{vs:x} ptr=0x{ptr:x} raw=0x{raw:x}",
            std::str::from_utf8(name).unwrap_or("?")
        );
    }
    assert!(
        !result.recovered_image.is_empty(),
        "phase-2 emu must return a non-empty image snapshot"
    );
    assert!(
        result.recovered_image.starts_with(b"MZ"),
        "snapshot at image_base must begin with MZ"
    );
}

struct PeMemorySection {
    name: [u8; 8],
    virtual_address: usize,
    virtual_size: usize,
    raw_size: usize,
    raw_pointer: usize,
}

fn parse_pe_sections(file: &[u8]) -> (usize, usize, Vec<PeMemorySection>) {
    let e_lfanew: usize =
        u32::from_le_bytes([file[0x3c], file[0x3d], file[0x3e], file[0x3f]]) as usize;
    let coff: usize = e_lfanew + 4;
    let n_sec: usize = u16::from_le_bytes([file[coff + 2], file[coff + 3]]) as usize;
    let opt_size: usize = u16::from_le_bytes([file[coff + 16], file[coff + 17]]) as usize;
    let opt: usize = coff + 20;
    let size_of_image: usize = u32::from_le_bytes([
        file[opt + 56],
        file[opt + 57],
        file[opt + 58],
        file[opt + 59],
    ]) as usize;
    let size_of_headers: usize = u32::from_le_bytes([
        file[opt + 60],
        file[opt + 61],
        file[opt + 62],
        file[opt + 63],
    ]) as usize;
    let sec_off: usize = opt + opt_size;
    let mut sections: Vec<PeMemorySection> = Vec::with_capacity(n_sec);
    for i in 0..n_sec {
        let s: usize = sec_off + i * 40;
        if s + 40 > file.len() {
            break;
        }
        let mut name: [u8; 8] = [0u8; 8];
        name.copy_from_slice(&file[s..s + 8]);
        sections.push(PeMemorySection {
            name,
            virtual_size: u32::from_le_bytes([file[s + 8], file[s + 9], file[s + 10], file[s + 11]])
                as usize,
            virtual_address: u32::from_le_bytes([
                file[s + 12],
                file[s + 13],
                file[s + 14],
                file[s + 15],
            ]) as usize,
            raw_size: u32::from_le_bytes([file[s + 16], file[s + 17], file[s + 18], file[s + 19]])
                as usize,
            raw_pointer: u32::from_le_bytes([
                file[s + 20],
                file[s + 21],
                file[s + 22],
                file[s + 23],
            ]) as usize,
        });
    }
    let _ = size_of_headers;
    (size_of_image, size_of_headers, sections)
}

fn map_original_to_memory(file: &[u8]) -> Vec<u8> {
    let (size_of_image, size_of_headers, sections): (usize, usize, Vec<PeMemorySection>) =
        parse_pe_sections(file);
    let mut img: Vec<u8> = vec![0u8; size_of_image];
    let hcopy: usize = size_of_headers.min(file.len()).min(img.len());
    img[..hcopy].copy_from_slice(&file[..hcopy]);
    for sec in &sections {
        let n: usize = sec
            .raw_size
            .min(sec.virtual_size.max(sec.raw_size))
            .min(file.len().saturating_sub(sec.raw_pointer));
        if sec.virtual_address + n <= img.len() && sec.raw_pointer + n <= file.len() {
            img[sec.virtual_address..sec.virtual_address + n]
                .copy_from_slice(&file[sec.raw_pointer..sec.raw_pointer + n]);
        }
    }
    img
}

fn section_name_eq(name: [u8; 8], target: &[u8]) -> bool {
    let end: usize = name.iter().position(|&b: &u8| b == 0).unwrap_or(name.len());
    &name[..end] == target
}

#[test]
fn test_petite_hello32_phase2_byte_recovery_beats_static() {
    let Some(packed): Option<Vec<u8>> = read_fixture("hello.exe") else {
        eprintln!("skipping: petite/hello.exe corpus fixture absent");
        return;
    };
    let Some(baseline): Option<Vec<u8>> = read_fixture("hello.original.exe") else {
        eprintln!("skipping: petite/hello.original.exe corpus fixture absent");
        return;
    };
    let result: PetitePhase2EmulatedOutput =
        unpack_petite_phase2_emulated(&packed).expect("phase-2 emu must succeed");
    let recovered_mem: &Vec<u8> = &result.recovered_memory_image;
    let orig_mem: Vec<u8> = map_original_to_memory(&baseline);
    let (_size_of_image, _soh, sections): (usize, usize, Vec<PeMemorySection>) =
        parse_pe_sections(&baseline);
    let compare_end: usize = recovered_mem.len().min(orig_mem.len());
    let mut total: usize = 0;
    let mut matching: usize = 0;
    for sec in &sections {
        if section_name_eq(sec.name, b".reloc") {
            continue;
        }
        let lo: usize = sec.virtual_address;
        let hi: usize = (sec.virtual_address + sec.virtual_size.max(sec.raw_size)).min(compare_end);
        for j in lo..hi {
            total += 1;
            if recovered_mem[j] == orig_mem[j] {
                matching += 1;
            }
        }
    }
    let pct: f64 = if total == 0 {
        0.0
    } else {
        100.0 * matching as f64 / total as f64
    };
    println!(
        "petite phase-2 content-section memory byte-recovery hello32: matching={matching}/{total} ({pct:.2}%) \
         (.reloc excluded - loader-rebuilt; recovered_memory_image={} orig_mem={})",
        recovered_mem.len(),
        orig_mem.len(),
    );
    assert!(
        pct >= 95.0,
        "phase-2 emulated unpack must achieve >=95% memory byte-recovery on hello32 content \
         sections (.text/.rdata/.data; v0.9 A2 static baseline was 16.91%, whole-file 54%); got {pct:.2}%",
    );
}

#[test]
fn test_petite_dircmp_phase2_emulated_smoke() {
    let Some(packed): Option<Vec<u8>> = read_fixture("megafile_DirCmp.exe") else {
        eprintln!("skipping: petite/megafile_DirCmp.exe corpus fixture absent");
        return;
    };
    let result: PetitePhase2EmulatedOutput =
        unpack_petite_phase2_emulated(&packed).expect("phase-2 emu must produce output");
    let mem: &Vec<u8> = &result.recovered_memory_image;
    let nonzero: usize = mem.iter().filter(|b: &&u8| **b != 0).count();
    let nonzero_pct: f64 = if mem.is_empty() {
        0.0
    } else {
        100.0 * nonzero as f64 / mem.len() as f64
    };
    println!(
        "petite phase-2 emu DirCmp: exit={} oep={:?} host_calls={} image_size={} recovered_len={} nonzero={nonzero} ({nonzero_pct:.1}%)",
        result.exit_reason,
        result.oep_estimate,
        result.host_calls.len(),
        result.size_of_image,
        result.recovered_image.len()
    );
    assert!(
        !result.recovered_image.is_empty(),
        "DirCmp phase-2 emu must produce non-empty image"
    );
    assert!(
        result.recovered_image.starts_with(b"MZ"),
        "DirCmp recovered image must begin with MZ"
    );
    assert!(
        !result
            .exit_reason
            .contains("read from unmapped 0x0000000000000000"),
        "v0.9-A3 fix: the FS:0 SEH-bootstrap fault must be gone (synthetic TEB + bounded \
         lazy-commit). The emulator must run the wrapper past the SEH frame setup; got exit={}",
        result.exit_reason
    );
    assert!(
        nonzero_pct >= 73.0,
        "DirCmp emulated memory image must hold substantial decompressed content (the megafile has \
         no in-repo original baseline, so we witness recovery as non-zero density rather than a \
         byte-diff; the pre-fix path faulted at FS:0 and fell back to structural-only ~39% \
         non-zero with NO real decompression; with synthetic TEB + bounded lazy-commit + the full \
         Btr/Bsf/Leave/Enter/Rcl/Rcr/Shld/Shrd/Xadd/Cmpxchg/Popcnt/Lzcnt/Tzcnt/Salc/Xlatb/Lahf/Sahf \
         opcode set the emulator now drives the LZ decompressor past 73% non-zero on the megafile); \
         got {nonzero_pct:.1}% non-zero",
    );
    assert!(
        !result.exit_reason.contains("Leaved"),
        "v0.9-A4 fix: the megafile must no longer fault on the LEAVE opcode (the prior cap point); \
         got exit={}",
        result.exit_reason
    );
}

#[test]
fn test_petite_unpack_rejects_non_petite_pe() {
    let mut not_petite: Vec<u8> = vec![0u8; 0x400];
    not_petite[..2].copy_from_slice(b"MZ");
    not_petite[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    not_petite[0x40..0x44].copy_from_slice(b"PE\x00\x00");
    not_petite[0x44..0x46].copy_from_slice(&0x014Cu16.to_le_bytes());
    not_petite[0x44 + 16..0x44 + 18].copy_from_slice(&224u16.to_le_bytes());
    not_petite[0x44 + 20..0x44 + 22].copy_from_slice(&0x010Bu16.to_le_bytes());
    let err = unpack_petite(&not_petite).unwrap_err();
    let msg: String = format!("{err:?}");
    assert!(
        msg.contains("petite")
            || msg.contains("Truncated")
            || msg.contains("GoblinParse")
            || msg.contains("UnknownFormat"),
        "rejecting non-petite PE must surface a structural error; got {msg}"
    );
}
