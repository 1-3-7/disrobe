#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation
)]

use disrobe_pass_native::{
    Packer, UpxMethod, UpxUnpackOutput, detect_packers, packed_upx_elf64_marker, unpack_upx,
};

const PACKED_NRV2B: &[u8] =
    include_bytes!("../../../corpus/native/packers/upx/hello.packed.nrv2b.exe");
const ORIGINAL: &[u8] = include_bytes!("../../../corpus/native/packers/upx/hello.original.exe");

const IMAGE_BASE_RVA: usize = 0x1000;

#[test]
fn baked_upx_elf64_marker_detected() {
    let bytes: Vec<u8> = packed_upx_elf64_marker();
    let hits = detect_packers(&bytes);
    assert!(hits.iter().any(|h| h.packer == Packer::Upx));
}

struct OriginalSection {
    name: String,
    rva: usize,
    content_len: usize,
    disk_off: usize,
}

fn parse_original_sections(image: &[u8]) -> Vec<OriginalSection> {
    let pe_off: usize =
        u32::from_le_bytes([image[0x3c], image[0x3d], image[0x3e], image[0x3f]]) as usize;
    assert_eq!(&image[pe_off..pe_off + 4], b"PE\0\0", "valid PE signature");
    let coff: usize = pe_off + 4;
    let num_sections: usize = u16::from_le_bytes([image[coff + 2], image[coff + 3]]) as usize;
    let opt_size: usize = u16::from_le_bytes([image[coff + 16], image[coff + 17]]) as usize;
    let sect_table: usize = coff + 20 + opt_size;
    let mut out: Vec<OriginalSection> = Vec::new();
    for i in 0..num_sections {
        let entry: usize = sect_table + i * 40;
        let name: String = String::from_utf8_lossy(&image[entry..entry + 8])
            .trim_end_matches('\0')
            .to_owned();
        let vsize: usize = u32::from_le_bytes([
            image[entry + 8],
            image[entry + 9],
            image[entry + 10],
            image[entry + 11],
        ]) as usize;
        let rva: usize = u32::from_le_bytes([
            image[entry + 12],
            image[entry + 13],
            image[entry + 14],
            image[entry + 15],
        ]) as usize;
        let rsize: usize = u32::from_le_bytes([
            image[entry + 16],
            image[entry + 17],
            image[entry + 18],
            image[entry + 19],
        ]) as usize;
        let disk_off: usize = u32::from_le_bytes([
            image[entry + 20],
            image[entry + 21],
            image[entry + 22],
            image[entry + 23],
        ]) as usize;
        out.push(OriginalSection {
            name,
            rva,
            content_len: vsize.min(rsize),
            disk_off,
        });
    }
    out
}

fn section_by_name<'a>(sections: &'a [OriginalSection], name: &str) -> &'a OriginalSection {
    sections
        .iter()
        .find(|s: &&OriginalSection| s.name == name)
        .unwrap_or_else(|| panic!("original PE is missing the {name} section"))
}

fn recovered_section<'a>(rec: &'a [u8], sec: &OriginalSection) -> &'a [u8] {
    let img_off: usize = sec.rva - IMAGE_BASE_RVA;
    assert!(
        img_off + sec.content_len <= rec.len(),
        "recovered image too short to hold {} (need {:#x}, have {:#x})",
        sec.name,
        img_off + sec.content_len,
        rec.len()
    );
    &rec[img_off..img_off + sec.content_len]
}

fn original_section_disk(sec: &OriginalSection) -> &'static [u8] {
    &ORIGINAL[sec.disk_off..sec.disk_off + sec.content_len]
}

fn byte_diff_count(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b.iter())
        .filter(|(x, y): &(&u8, &u8)| x != y)
        .count()
}

#[test]
fn nrv2b_real_fixture_unpacks_with_verified_integrity() {
    let out: UpxUnpackOutput =
        unpack_upx(PACKED_NRV2B).expect("NRV2B unpack must succeed on committed fixture");
    assert_eq!(out.method, UpxMethod::Nrv2b);
    assert!(
        out.adler_verified,
        "UCL adler32 over recovered image must match PackHeader u_adler"
    );
    assert!(out.block_count >= 1);
    assert_eq!(
        out.filter_id, 0x49,
        "fixture uses the x86-64 CT call filter 0x49"
    );
}

#[test]
fn nrv2b_recovered_text_is_byte_identical_to_committed_original() {
    let out: UpxUnpackOutput = unpack_upx(PACKED_NRV2B).expect("unpack committed UPX fixture");
    let sections: Vec<OriginalSection> = parse_original_sections(ORIGINAL);

    let text: &OriginalSection = section_by_name(&sections, ".text");
    let recovered_text: &[u8] = recovered_section(&out.recovered_image, text);
    let original_text: &[u8] = original_section_disk(text);
    let diffs: usize = byte_diff_count(recovered_text, original_text);
    assert_eq!(
        diffs, 0,
        "recovered .text must be BYTE-IDENTICAL to the committed original ({} bytes); the CT \
         call filter (0x49) reversal recovers the executable code exactly. measured diffs={diffs}",
        text.content_len
    );

    let pdata: &OriginalSection = section_by_name(&sections, ".pdata");
    let recovered_pdata: &[u8] = recovered_section(&out.recovered_image, pdata);
    let original_pdata: &[u8] = original_section_disk(pdata);
    assert_eq!(
        byte_diff_count(recovered_pdata, original_pdata),
        0,
        "recovered .pdata (exception unwind data, {} bytes) must be byte-identical to the original",
        pdata.content_len
    );
}

#[test]
fn nrv2b_content_section_byte_recovery_meets_floor() {
    const FLOOR_PCT: f64 = 96.0;

    let out: UpxUnpackOutput = unpack_upx(PACKED_NRV2B).expect("unpack committed UPX fixture");
    let sections: Vec<OriginalSection> = parse_original_sections(ORIGINAL);

    let mut total: usize = 0;
    let mut matched: usize = 0;
    for sec in &sections {
        if sec.content_len == 0 || sec.disk_off + sec.content_len > ORIGINAL.len() {
            continue;
        }
        let img_off: usize = sec.rva - IMAGE_BASE_RVA;
        if img_off + sec.content_len > out.recovered_image.len() {
            continue;
        }
        let recovered: &[u8] = recovered_section(&out.recovered_image, sec);
        let original: &[u8] = original_section_disk(sec);
        let diffs: usize = byte_diff_count(recovered, original);
        total += sec.content_len;
        matched += sec.content_len - diffs;
        println!(
            "  {name:8} rva={rva:#x} len={len:#x} diffs={diffs} ({pct:.2}% identical)",
            name = sec.name,
            rva = sec.rva,
            len = sec.content_len,
            pct = 100.0 * (sec.content_len - diffs) as f64 / sec.content_len as f64
        );
    }
    assert!(total > 0, "no original sections witnessed");
    let recovery_pct: f64 = 100.0 * matched as f64 / total as f64;
    println!("UPX nrv2b whole-image content recovery: {matched}/{total} = {recovery_pct:.2}%");
    assert!(
        recovery_pct >= FLOOR_PCT,
        "UPX content-section byte recovery {recovery_pct:.2}% fell below the {FLOOR_PCT:.2}% floor"
    );
}

#[test]
fn nrv2b_residual_diff_is_confined_to_loader_rebuilt_zones() {
    let out: UpxUnpackOutput = unpack_upx(PACKED_NRV2B).expect("unpack committed UPX fixture");
    let sections: Vec<OriginalSection> = parse_original_sections(ORIGINAL);

    let mut total_diffs: usize = 0;
    let mut diffs_outside_loader_zones: usize = 0;
    for sec in &sections {
        if sec.content_len == 0 || sec.disk_off + sec.content_len > ORIGINAL.len() {
            continue;
        }
        let img_off: usize = sec.rva - IMAGE_BASE_RVA;
        if img_off + sec.content_len > out.recovered_image.len() {
            continue;
        }
        let recovered: &[u8] = recovered_section(&out.recovered_image, sec);
        let original: &[u8] = original_section_disk(sec);
        for (j, (a, b)) in recovered.iter().zip(original.iter()).enumerate() {
            if a == b {
                continue;
            }
            total_diffs += 1;
            let in_loader_zone: bool = sec.name == ".reloc"
                || sec.name == ".rdata"
                || sec.name == ".data"
                || sec.name == ".idata";
            if !in_loader_zone {
                diffs_outside_loader_zones += 1;
                println!(
                    "  unexpected diff in {name} at rva {rva:#x}",
                    name = sec.name,
                    rva = sec.rva + j
                );
            }
        }
    }
    println!(
        "UPX nrv2b residual: {total_diffs} diffs, {diffs_outside_loader_zones} outside .reloc/.rdata/.data"
    );
    assert!(
        total_diffs > 0,
        "the loaded-image vs on-disk comparison is expected to carry a loader-rebuilt residual"
    );
    assert_eq!(
        diffs_outside_loader_zones, 0,
        "every UPX recovery residual must fall in a loader-rebuilt section (.reloc relocations, \
         or the import/IAT-patched .rdata/.data). the executable code (.text) and exception data \
         (.pdata) carry zero residual. these zones are reconstructed by the OS loader at run time \
         and are not byte-present in the packed stream, so they are not a depacker defect"
    );
}

#[test]
fn non_upx_input_is_rejected() {
    let buf: Vec<u8> = vec![0x55u8; 4096];
    assert!(unpack_upx(&buf).is_err());
}

const PACKED_LZMA: &[u8] =
    include_bytes!("../../../corpus/native/packers/upx/hello.packed.lzma.exe");

#[test]
fn lzma_real_fixture_unpacks_with_verified_adler() {
    let out: UpxUnpackOutput =
        unpack_upx(PACKED_LZMA).expect("UPX-LZMA unpack must succeed on committed fixture");
    assert_eq!(out.method, UpxMethod::Lzma);
    assert!(
        out.adler_verified,
        "UCL adler32 over the recovered image must match PackHeader u_adler; the UPX 2-byte LZMA \
         property layout (pb=src[0]&7, lp=src[1]>>4, lc=src[1]&15) differs from the MEW/MPRESS \
         (pb<<4|lp, lc) framing, so parsing it with the wrong layout silently produces garbage"
    );
    assert!(out.block_count >= 1);
}

#[test]
fn lzma_recovered_text_is_byte_identical_to_committed_original() {
    let out: UpxUnpackOutput = unpack_upx(PACKED_LZMA).expect("unpack committed UPX-LZMA fixture");
    let sections: Vec<OriginalSection> = parse_original_sections(ORIGINAL);

    let text: &OriginalSection = section_by_name(&sections, ".text");
    let recovered_text: &[u8] = recovered_section(&out.recovered_image, text);
    let original_text: &[u8] = original_section_disk(text);
    assert_eq!(
        byte_diff_count(recovered_text, original_text),
        0,
        "UPX-LZMA recovered .text ({} bytes) must be byte-identical to the committed original",
        text.content_len
    );

    let pdata: &OriginalSection = section_by_name(&sections, ".pdata");
    let recovered_pdata: &[u8] = recovered_section(&out.recovered_image, pdata);
    let original_pdata: &[u8] = original_section_disk(pdata);
    assert_eq!(
        byte_diff_count(recovered_pdata, original_pdata),
        0,
        "UPX-LZMA recovered .pdata ({} bytes) must be byte-identical to the original",
        pdata.content_len
    );
}

fn run_large_fixture(name: &str) -> Option<(UpxUnpackOutput, f64)> {
    let packed_path: String = format!("../../corpus/native/packers/upx/{name}.packed.upx.exe");
    let orig_path: String = format!("../../corpus/native/packers/upx/{name}.unpacked.upx.exe");
    let packed: Vec<u8> = std::fs::read(&packed_path).ok()?;
    let orig: Vec<u8> = std::fs::read(&orig_path).ok()?;
    let out: UpxUnpackOutput = unpack_upx(&packed).unwrap_or_else(|e| {
        panic!("{name}: unpack_upx must succeed on the >1MB nrv2e fixture: {e:?}")
    });
    let sections: Vec<OriginalSection> = parse_original_sections(&orig);
    let mut total: usize = 0;
    let mut matched: usize = 0;
    for sec in &sections {
        if sec.content_len == 0 || sec.disk_off + sec.content_len > orig.len() {
            continue;
        }
        let img_off: usize = sec.rva - IMAGE_BASE_RVA;
        if img_off + sec.content_len > out.recovered_image.len() {
            continue;
        }
        let recovered: &[u8] = &out.recovered_image[img_off..img_off + sec.content_len];
        let original: &[u8] = &orig[sec.disk_off..sec.disk_off + sec.content_len];
        let diffs: usize = byte_diff_count(recovered, original);
        total += sec.content_len;
        matched += sec.content_len - diffs;
    }
    assert!(total > 0, "{name}: no sections witnessed");
    let pct: f64 = 100.0 * matched as f64 / total as f64;
    println!(
        "{name}: method={:?} blocks={} adler={} content_recovery={pct:.2}%",
        out.method, out.block_count, out.adler_verified
    );
    Some((out, pct))
}

#[test]
fn large_nrv2e_rg_recovers_with_verified_adler() {
    let Some((out, pct)): Option<(UpxUnpackOutput, f64)> = run_large_fixture("rg") else {
        eprintln!("skip: rg.packed.upx.exe missing");
        return;
    };
    assert_eq!(out.method, UpxMethod::Nrv2e);
    assert!(
        out.adler_verified,
        "rg: the 4MB nrv2e block must round-trip to the PackHeader u_adler"
    );
    assert!(
        out.recovered_image.iter().any(|&b: &u8| b != 0),
        "rg: recovered image must not be all zeros"
    );
    assert!(
        pct >= 96.0,
        "rg content-section byte recovery {pct:.2}% fell below the 96.0% floor"
    );
}

#[test]
fn large_nrv2e_git_recovers_with_verified_adler() {
    let Some((out, pct)): Option<(UpxUnpackOutput, f64)> = run_large_fixture("git") else {
        eprintln!("skip: git.packed.upx.exe missing");
        return;
    };
    assert_eq!(out.method, UpxMethod::Nrv2e);
    assert!(
        out.adler_verified,
        "git: the 4.5MB nrv2e block must round-trip to the PackHeader u_adler"
    );
    assert!(
        pct >= 98.0,
        "git content-section byte recovery {pct:.2}% fell below the 98.0% floor"
    );
}
