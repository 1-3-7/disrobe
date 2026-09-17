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
use std::path::{Path, PathBuf};
use std::process::Command;

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

const LIEF_RSRC_ORACLE: &str = r#"from __future__ import annotations

import json
import sys

import lief


def resource_tuples(b):
    rd = b.resources
    if rd is None:
        return []
    out = []

    def rec(node, path):
        if node.is_directory:
            for c in node.childs:
                cid = c.name if c.has_name else c.id
                rec(c, path + [str(cid)])
        else:
            out.append([list(path), int(node.offset), len(bytes(node.content))])

    rec(rd, [])
    out.sort(key=lambda e: (e[0], e[1], e[2]))
    return out


def dirs(b):
    d = {}
    for entry in b.data_directories:
        d[entry.type.name] = [int(entry.rva), int(entry.size)]
    return d


def imports(b):
    out = []
    for imp in b.imports:
        for e in imp.entries:
            key = e.ordinal if e.is_ordinal else e.name
            out.append([imp.name.lower(), str(key), int(e.iat_value)])
    out.sort()
    return out


def main():
    recovered = lief.PE.parse(sys.argv[1])
    clean = lief.PE.parse(sys.argv[2])
    if recovered is None or clean is None:
        print(json.dumps({"parse_ok": False}))
        return 0
    r_res = resource_tuples(recovered)
    c_res = resource_tuples(clean)
    r_imp = imports(recovered)
    c_imp = imports(clean)
    print(json.dumps({
        "parse_ok": True,
        "rsrc_count": len(c_res),
        "rsrc_match": sum(1 for a, b in zip(r_res, c_res) if a == b),
        "rsrc_equal": r_res == c_res,
        "dirs_equal": dirs(recovered) == dirs(clean),
        "import_entry_count": len(c_imp),
        "imports_equal": r_imp == c_imp,
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
"#;

fn corpus_native(rel: &str) -> Option<Vec<u8>> {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    for part in rel.split('/') {
        p.push(part);
    }
    fs::read(&p).ok()
}

fn python_with_lief() -> Option<PathBuf> {
    for candidate in ["python", "python3", "py"] {
        let ready: bool = Command::new(candidate)
            .args(["-c", "import lief"])
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success());
        if ready {
            return Some(PathBuf::from(candidate));
        }
    }
    None
}

struct SectionSpan {
    virtual_address: u32,
    virtual_size: u32,
    raw_pointer: u32,
    raw_size: u32,
}

struct PeLayout {
    is_pe32_plus: bool,
    image_base: u64,
    import_rva: u32,
    reloc_rva: u32,
    reloc_size: u32,
    resource_rva: u32,
    sections: Vec<SectionSpan>,
}

fn read_layout(original: &[u8]) -> PeLayout {
    let e_lfanew: usize = read_u32(original, 0x3C) as usize;
    let coff: usize = e_lfanew + 4;
    let n_sections: usize = read_u16(original, coff + 2) as usize;
    let opt_size: usize = read_u16(original, coff + 16) as usize;
    let opt: usize = coff + 20;
    let is_pe32_plus: bool = read_u16(original, opt) == 0x020B;
    let (image_base, dir_base): (u64, usize) = if is_pe32_plus {
        (read_u64(original, opt + 24), opt + 112)
    } else {
        (u64::from(read_u32(original, opt + 28)), opt + 96)
    };
    let sec_table: usize = opt + opt_size;
    let mut sections: Vec<SectionSpan> = Vec::with_capacity(n_sections);
    for i in 0..n_sections {
        let off: usize = sec_table + i * 40;
        sections.push(SectionSpan {
            virtual_size: read_u32(original, off + 8),
            virtual_address: read_u32(original, off + 12),
            raw_size: read_u32(original, off + 16),
            raw_pointer: read_u32(original, off + 20),
        });
    }
    PeLayout {
        is_pe32_plus,
        image_base,
        import_rva: read_u32(original, dir_base + 8),
        reloc_rva: read_u32(original, dir_base + 5 * 8),
        reloc_size: read_u32(original, dir_base + 5 * 8 + 4),
        resource_rva: read_u32(original, dir_base + 2 * 8),
        sections,
    }
}

fn resource_leaves(mapped: &[u8], resource_rva: u32) -> Vec<usize> {
    let mut leaves: Vec<usize> = Vec::new();
    if resource_rva != 0 {
        let base: usize = resource_rva as usize;
        collect_resource_leaves(mapped, base, base, 0, &mut leaves);
    }
    leaves
}

fn collect_resource_leaves(
    mapped: &[u8],
    table_off: usize,
    section_base: usize,
    depth: u32,
    out: &mut Vec<usize>,
) {
    if depth > 8 || table_off + 16 > mapped.len() {
        return;
    }
    let total: usize =
        read_u16(mapped, table_off + 12) as usize + read_u16(mapped, table_off + 14) as usize;
    for i in 0..total {
        let entry_off: usize = table_off + 16 + i * 8;
        if entry_off + 8 > mapped.len() {
            break;
        }
        let offset_to_data: u32 = read_u32(mapped, entry_off + 4);
        if offset_to_data & 0x8000_0000 != 0 {
            let child: usize = section_base + (offset_to_data & 0x7FFF_FFFF) as usize;
            collect_resource_leaves(mapped, child, section_base, depth + 1, out);
        } else {
            let data_entry: usize = section_base + offset_to_data as usize;
            if data_entry + 16 <= mapped.len() {
                out.push(data_entry);
            }
        }
    }
}

fn bind_resource_offsets(mapped: &mut [u8], resource_rva: u32, image_base: u64) -> usize {
    if image_base == 0 || image_base > u64::from(u32::MAX) {
        return 0;
    }
    let base32: u32 = image_base as u32;
    let leaves: Vec<usize> = resource_leaves(mapped, resource_rva);
    let mut bound: usize = 0;
    for data_entry in leaves {
        let rva: u32 = read_u32(mapped, data_entry);
        let Some(va): Option<u32> = base32.checked_add(rva) else {
            continue;
        };
        mapped[data_entry..data_entry + 4].copy_from_slice(&va.to_le_bytes());
        bound += 1;
    }
    bound
}

fn de_map(original: &[u8], mapped: &[u8], layout: &PeLayout) -> Vec<u8> {
    let mut out: Vec<u8> = original.to_vec();
    let hdr: usize = 0x1000.min(original.len()).min(mapped.len());
    out[..hdr].copy_from_slice(&mapped[..hdr]);
    for sec in &layout.sections {
        let va: usize = sec.virtual_address as usize;
        let raw_ptr: usize = sec.raw_pointer as usize;
        if raw_ptr >= out.len() || va >= mapped.len() {
            continue;
        }
        let raw_avail: usize = (sec.raw_size as usize).min(out.len() - raw_ptr);
        let n: usize = raw_avail
            .min(sec.virtual_size as usize)
            .min(mapped.len() - va);
        if n == 0 {
            continue;
        }
        out[raw_ptr..raw_ptr + n].copy_from_slice(&mapped[va..va + n]);
    }
    out
}

struct RecoveredPe {
    disk: Vec<u8>,
    report: UnbindReport,
    resources_bound: usize,
    relocs_bound: usize,
    imports_bound: usize,
}

fn bind_then_unbind(original: &[u8], load_base: u64) -> RecoveredPe {
    let layout: PeLayout = read_layout(original);
    let cap: usize = original.len().max(1 << 22);
    let mut mapped: Vec<u8> = build_loaded_image(original, cap).expect("map");
    let delta: u64 = load_base.wrapping_sub(layout.image_base);
    let relocs: Vec<(u32, u16)> = walk_relocs(&mapped, layout.reloc_rva, layout.reloc_size);
    rebase_in_place(&mut mapped, &relocs, delta);
    let imports_bound: usize = bind_imports(
        &mut mapped,
        layout.import_rva,
        layout.is_pe32_plus,
        load_base,
    );
    let resources_bound: usize =
        bind_resource_offsets(&mut mapped, layout.resource_rva, layout.image_base);
    let report: UnbindReport = unbind_pe(&mut mapped, load_base).expect("unbind");
    let disk: Vec<u8> = de_map(original, &mapped, &layout);
    RecoveredPe {
        disk,
        report,
        resources_bound,
        relocs_bound: relocs.len(),
        imports_bound,
    }
}

fn lief_grade(python: &Path, recovered: &[u8], clean: &[u8]) -> serde_json::Value {
    let dir: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let script: PathBuf = dir.path().join("rsrc_oracle.py");
    let recovered_path: PathBuf = dir.path().join("recovered.bin");
    let clean_path: PathBuf = dir.path().join("clean.bin");
    fs::write(&script, LIEF_RSRC_ORACLE).expect("write script");
    fs::write(&recovered_path, recovered).expect("write recovered");
    fs::write(&clean_path, clean).expect("write clean");
    let out: std::process::Output = Command::new(python)
        .arg(&script)
        .arg(&recovered_path)
        .arg(&clean_path)
        .output()
        .expect("run lief grader");
    let stdout: String = String::from_utf8_lossy(&out.stdout).to_string();
    let line: &str = stdout
        .lines()
        .map(str::trim)
        .rfind(|l: &&str| l.starts_with('{'))
        .unwrap_or("");
    serde_json::from_str(line).unwrap_or(serde_json::Value::Null)
}

fn assert_recovered_tree_matches_clean(tag: &str, python: &Path, rec: &RecoveredPe, clean: &[u8]) {
    let verdict: serde_json::Value = lief_grade(python, &rec.disk, clean);
    println!("{tag} lief verdict: {verdict}");
    assert_eq!(
        verdict["parse_ok"],
        serde_json::json!(true),
        "{tag}: LIEF must parse both the recovered and clean images",
    );
    let rsrc_count: u64 = verdict["rsrc_count"].as_u64().unwrap_or(0);
    assert!(rsrc_count > 0, "{tag}: clean image must carry resources");
    assert_eq!(
        verdict["rsrc_match"].as_u64(),
        Some(rsrc_count),
        "{tag}: every resource tuple must match the clean tree",
    );
    assert_eq!(
        verdict["rsrc_equal"],
        serde_json::json!(true),
        "{tag}: recovered resource tree must equal the clean tree",
    );
    assert_eq!(
        verdict["dirs_equal"],
        serde_json::json!(true),
        "{tag}: recovered data directories must equal the clean image",
    );
    assert_eq!(
        verdict["imports_equal"],
        serde_json::json!(true),
        "{tag}: restored IAT must equal the clean import table",
    );
    assert_eq!(
        rec.resources_bound as u64, rsrc_count,
        "{tag}: bound resource leaves must equal LIEF's resource-data-entry count",
    );
    assert_eq!(
        rec.report.resource_offsets_restored, rec.resources_bound,
        "{tag}: unbind must fold every bound resource VA back to an RVA",
    );
}

#[test]
fn unbind_restores_rsrc_tree_graded_by_lief_accessenum() {
    let Some(python): Option<PathBuf> = python_with_lief() else {
        eprintln!("skip: python with lief unavailable");
        return;
    };
    let Some(original): Option<Vec<u8>> = corpus_native("packers/mew/AccessEnum.original.exe")
    else {
        eprintln!("skip: corpus/native/packers/mew/AccessEnum.original.exe missing");
        return;
    };
    let load_base: u64 = 0x0040_0000;
    let rec: RecoveredPe = bind_then_unbind(&original, load_base);
    assert!(
        rec.resources_bound >= 30,
        "accessenum must bind its full resource tree; bound {}",
        rec.resources_bound
    );
    assert!(
        rec.imports_bound > 0,
        "accessenum must bind its import address table; bound {}",
        rec.imports_bound
    );
    assert_eq!(
        rec.report.iat_thunks_restored, rec.imports_bound,
        "every bound IAT thunk must be restored from the import lookup table",
    );
    assert_recovered_tree_matches_clean("accessenum", &python, &rec, &original);
}

#[test]
fn unbind_restores_rsrc_tree_graded_by_lief_autologon() {
    let Some(python): Option<PathBuf> = python_with_lief() else {
        eprintln!("skip: python with lief unavailable");
        return;
    };
    let Some(original): Option<Vec<u8>> = corpus_native("packers/mew/Autologon.original.exe")
    else {
        eprintln!("skip: corpus/native/packers/mew/Autologon.original.exe missing");
        return;
    };
    let load_base: u64 = 0x1000_0000;
    let rec: RecoveredPe = bind_then_unbind(&original, load_base);
    assert!(
        rec.relocs_bound > 100,
        "autologon must carry a populated relocation table; walked {}",
        rec.relocs_bound
    );
    assert_eq!(
        rec.report.relocations_unapplied, rec.report.relocations_walked,
        "unbind must un-apply every walked relocation to the preferred base",
    );
    assert!(rec.resources_bound > 0, "autologon must bind resources");
    assert_eq!(
        rec.report.iat_thunks_restored, rec.imports_bound,
        "every bound IAT thunk must be restored from the import lookup table",
    );
    assert_recovered_tree_matches_clean("autologon", &python, &rec, &original);
}

#[test]
fn corrupted_rsrc_rva_diverges_from_lief_tree() {
    let Some(python): Option<PathBuf> = python_with_lief() else {
        eprintln!("skip: python with lief unavailable");
        return;
    };
    let Some(original): Option<Vec<u8>> = corpus_native("packers/mew/AccessEnum.original.exe")
    else {
        eprintln!("skip: corpus/native/packers/mew/AccessEnum.original.exe missing");
        return;
    };
    let layout: PeLayout = read_layout(&original);
    let cap: usize = original.len().max(1 << 22);
    let mut mapped: Vec<u8> = build_loaded_image(&original, cap).expect("map");
    let bound: usize = bind_resource_offsets(&mut mapped, layout.resource_rva, layout.image_base);
    assert!(bound > 0, "must bind at least one resource VA");
    unbind_pe(&mut mapped, layout.image_base).expect("unbind");

    let clean_disk: Vec<u8> = de_map(&original, &mapped, &layout);
    let clean_verdict: serde_json::Value = lief_grade(&python, &clean_disk, &original);
    assert_eq!(
        clean_verdict["rsrc_equal"],
        serde_json::json!(true),
        "sanity: an uncorrupted restore must equal the clean tree first",
    );

    let leaves: Vec<usize> = resource_leaves(&mapped, layout.resource_rva);
    let first: usize = *leaves.first().expect("at least one resource leaf");
    let restored: u32 = read_u32(&mapped, first);
    mapped[first..first + 4].copy_from_slice(&restored.wrapping_add(0x40).to_le_bytes());
    let corrupt_disk: Vec<u8> = de_map(&original, &mapped, &layout);

    let verdict: serde_json::Value = lief_grade(&python, &corrupt_disk, &original);
    println!("corruption verdict: {verdict}");
    let parse_ok: bool = verdict["parse_ok"] == serde_json::json!(true);
    let rsrc_equal: bool = verdict["rsrc_equal"] == serde_json::json!(true);
    assert!(
        !(parse_ok && rsrc_equal),
        "corrupting one restored resource RVA must break LIEF tree equality; got {verdict}",
    );
}
