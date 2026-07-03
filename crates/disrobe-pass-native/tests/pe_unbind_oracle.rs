#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{
    SectionRecoveryReport, UnbindReport, build_loaded_image, section_recovery_report, unbind_pe,
};

fn corpus_pe(name: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("unbind");
    p.push(name);
    fs::read(&p).ok()
}

fn read_u16(image: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([image[off], image[off + 1]])
}

fn read_u32(image: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([image[off], image[off + 1], image[off + 2], image[off + 3]])
}

fn read_u64(image: &[u8], off: usize) -> u64 {
    let mut a: [u8; 8] = [0u8; 8];
    a.copy_from_slice(&image[off..off + 8]);
    u64::from_le_bytes(a)
}

struct PeFacts {
    is_pe32_plus: bool,
    image_base: u64,
    reloc_rva: u32,
    reloc_size: u32,
    import_rva: u32,
}

fn pe_facts(original: &[u8]) -> PeFacts {
    let e_lfanew: usize = read_u32(original, 0x3C) as usize;
    let coff: usize = e_lfanew + 4;
    let opt: usize = coff + 20;
    let magic: u16 = read_u16(original, opt);
    let is_pe32_plus: bool = magic == 0x020B;
    let (image_base, dir_base): (u64, usize) = if is_pe32_plus {
        (read_u64(original, opt + 24), opt + 112)
    } else {
        (u64::from(read_u32(original, opt + 28)), opt + 96)
    };
    PeFacts {
        is_pe32_plus,
        image_base,
        reloc_rva: read_u32(original, dir_base + 5 * 8),
        reloc_size: read_u32(original, dir_base + 5 * 8 + 4),
        import_rva: read_u32(original, dir_base + 8),
    }
}

fn walk_relocs(mapped: &[u8], dir_rva: u32, dir_size: u32) -> Vec<(u32, u16)> {
    let mut out: Vec<(u32, u16)> = Vec::new();
    let end: usize = dir_rva as usize + dir_size as usize;
    let mut cursor: usize = dir_rva as usize;
    while cursor + 8 <= end {
        let page: u32 = read_u32(mapped, cursor);
        let block: u32 = read_u32(mapped, cursor + 4);
        if block < 8 {
            break;
        }
        let block_end: usize = (cursor + block as usize).min(end);
        let mut e: usize = cursor + 8;
        while e + 2 <= block_end {
            let packed: u16 = read_u16(mapped, e);
            let kind: u16 = packed >> 12;
            let off: u16 = packed & 0x0FFF;
            if kind != 0 {
                out.push((page.wrapping_add(u32::from(off)), kind));
            }
            e += 2;
        }
        cursor += block as usize;
    }
    out
}

fn rebase_in_place(mapped: &mut [u8], relocs: &[(u32, u16)], delta: u64) {
    for (rva, kind) in relocs {
        let off: usize = *rva as usize;
        match kind {
            3 => {
                let v: u32 = read_u32(mapped, off).wrapping_add(delta as u32);
                mapped[off..off + 4].copy_from_slice(&v.to_le_bytes());
            }
            10 => {
                let v: u64 = read_u64(mapped, off).wrapping_add(delta);
                mapped[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
            _ => {}
        }
    }
}

fn bind_imports(mapped: &mut [u8], import_rva: u32, is_pe32_plus: bool, load_base: u64) -> usize {
    if import_rva == 0 {
        return 0;
    }
    let ptr: usize = if is_pe32_plus { 8 } else { 4 };
    let mut bound: usize = 0;
    let mut descriptor: usize = import_rva as usize;
    loop {
        let oft: u32 = read_u32(mapped, descriptor);
        let ft: u32 = read_u32(mapped, descriptor + 16);
        let name: u32 = read_u32(mapped, descriptor + 12);
        if oft == 0 && ft == 0 && name == 0 {
            break;
        }
        let mut slot: usize = 0;
        loop {
            let ilt_off: usize = oft as usize + slot * ptr;
            let iat_off: usize = ft as usize + slot * ptr;
            let lookup: u64 = if is_pe32_plus {
                read_u64(mapped, ilt_off)
            } else {
                u64::from(read_u32(mapped, ilt_off))
            };
            if lookup == 0 {
                break;
            }
            let resolved: u64 = load_base
                .wrapping_add(0x9000_0000)
                .wrapping_add((bound as u64) * 0x40);
            if is_pe32_plus {
                mapped[iat_off..iat_off + 8].copy_from_slice(&resolved.to_le_bytes());
            } else {
                mapped[iat_off..iat_off + 4].copy_from_slice(&(resolved as u32).to_le_bytes());
            }
            bound += 1;
            slot += 1;
        }
        descriptor += 20;
    }
    bound
}

fn whole_image_parity(unbound: &[u8], baseline: &[u8]) -> (usize, usize) {
    let len: usize = unbound.len().min(baseline.len());
    let mut matching: usize = 0;
    for i in 0..len {
        if unbound[i] == baseline[i] {
            matching += 1;
        }
    }
    (matching, len)
}

struct UnbindOutcome {
    pre_whole_pct: f64,
    post_whole_pct: f64,
    post_whole_match: usize,
    post_whole_total: usize,
    post_content_pct: f64,
    report: UnbindReport,
    bound_imports: usize,
}

fn run_unbind(original: &[u8], load_base: u64) -> UnbindOutcome {
    let facts: PeFacts = pe_facts(original);
    let cap: usize = original.len().max(1 << 22);
    let baseline: Vec<u8> = build_loaded_image(original, cap).expect("baseline map");

    let mut loaded: Vec<u8> = baseline.clone();
    let delta: u64 = load_base.wrapping_sub(facts.image_base);
    let relocs: Vec<(u32, u16)> = walk_relocs(&loaded, facts.reloc_rva, facts.reloc_size);
    assert!(
        !relocs.is_empty(),
        "oracle requires a real on-disk base-relocation table to rebase against",
    );
    rebase_in_place(&mut loaded, &relocs, delta);
    let bound: usize = bind_imports(&mut loaded, facts.import_rva, facts.is_pe32_plus, load_base);
    assert!(bound > 0, "oracle requires a walkable import table to bind");

    let (pre_match, pre_total): (usize, usize) = whole_image_parity(&loaded, &baseline);
    let pre_whole_pct: f64 = 100.0 * pre_match as f64 / pre_total as f64;

    let report: UnbindReport = unbind_pe(&mut loaded, load_base).expect("unbind");

    let (post_match, post_total): (usize, usize) = whole_image_parity(&loaded, &baseline);
    let post_whole_pct: f64 = 100.0 * post_match as f64 / post_total as f64;
    let content: SectionRecoveryReport =
        section_recovery_report(original, &loaded, &[]).expect("content report");

    UnbindOutcome {
        pre_whole_pct,
        post_whole_pct,
        post_whole_match: post_match,
        post_whole_total: post_total,
        post_content_pct: content.content_recovery_pct(),
        report,
        bound_imports: bound,
    }
}

#[test]
fn unbind_notepad_pe64_restores_whole_image_parity() {
    let Some(original): Option<Vec<u8>> = corpus_pe("notepad.pe64.exe") else {
        eprintln!("skip: corpus/native/unbind/notepad.pe64.exe missing");
        return;
    };
    let load_base: u64 = 0x0007_3210_0000;
    let outcome: UnbindOutcome = run_unbind(&original, load_base);
    println!(
        "notepad pe64: pre_whole={:.4}% post_whole={:.4}% post_content={:.4}% relocs={}/{} iat_thunks={}/{} bound={} rsrc={}/{}",
        outcome.pre_whole_pct,
        outcome.post_whole_pct,
        outcome.post_content_pct,
        outcome.report.relocations_unapplied,
        outcome.report.relocations_walked,
        outcome.report.iat_thunks_restored,
        outcome.bound_imports,
        outcome.bound_imports,
        outcome.report.resource_offsets_restored,
        outcome.report.resource_data_entries_walked,
    );
    assert!(
        outcome.report.relocations_walked > 100,
        "notepad must carry a populated reloc table; walked {}",
        outcome.report.relocations_walked
    );
    assert_eq!(
        outcome.report.iat_thunks_restored, outcome.bound_imports,
        "every loader-bound IAT thunk must be restored from the import lookup table",
    );
    assert_eq!(
        outcome.post_whole_match, outcome.post_whole_total,
        "post-unbind whole-image RVA-aligned parity must be byte-exact; {} of {} bytes matched (pre {:.4}%)",
        outcome.post_whole_match, outcome.post_whole_total, outcome.pre_whole_pct,
    );
    assert!(
        outcome.post_whole_pct >= 100.0,
        "post-unbind whole-image parity percent must read 100%; got {:.4}%",
        outcome.post_whole_pct,
    );
    assert!(
        (outcome.post_content_pct - 100.0).abs() < f64::EPSILON,
        "content sections must be byte-identical after unbind; got {:.4}%",
        outcome.post_content_pct,
    );
}

#[test]
fn unbind_kernel32_pe32_restores_whole_image_parity() {
    let Some(original): Option<Vec<u8>> = corpus_pe("kernel32.pe32.dll") else {
        eprintln!("skip: corpus/native/unbind/kernel32.pe32.dll missing");
        return;
    };
    let load_base: u64 = 0x6F00_0000;
    let outcome: UnbindOutcome = run_unbind(&original, load_base);
    println!(
        "kernel32 pe32: pre_whole={:.4}% post_whole={:.4}% post_content={:.4}% relocs={}/{} iat_thunks={}/{} bound={} rsrc={}/{}",
        outcome.pre_whole_pct,
        outcome.post_whole_pct,
        outcome.post_content_pct,
        outcome.report.relocations_unapplied,
        outcome.report.relocations_walked,
        outcome.report.iat_thunks_restored,
        outcome.bound_imports,
        outcome.bound_imports,
        outcome.report.resource_offsets_restored,
        outcome.report.resource_data_entries_walked,
    );
    assert!(
        outcome.report.relocations_walked > 100,
        "kernel32 must carry a populated reloc table; walked {}",
        outcome.report.relocations_walked
    );
    assert_eq!(
        outcome.report.iat_thunks_restored, outcome.bound_imports,
        "every loader-bound IAT thunk must be restored from the import lookup table",
    );
    assert_eq!(
        outcome.post_whole_match, outcome.post_whole_total,
        "post-unbind whole-image RVA-aligned parity must be byte-exact; {} of {} bytes matched (pre {:.4}%)",
        outcome.post_whole_match, outcome.post_whole_total, outcome.pre_whole_pct,
    );
    assert!(
        outcome.post_whole_pct >= 100.0,
        "post-unbind whole-image parity percent must read 100%; got {:.4}%",
        outcome.post_whole_pct,
    );
    assert!(
        (outcome.post_content_pct - 100.0).abs() < f64::EPSILON,
        "content sections must be byte-identical after unbind; got {:.4}%",
        outcome.post_content_pct,
    );
}
