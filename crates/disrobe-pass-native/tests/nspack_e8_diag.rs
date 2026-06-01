#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::needless_range_loop
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use disrobe_pass_native::{
    NspackEmulatedReport, unpack_nspack_emulated_with_baseline,
    unpack_nspack_emulated_with_baseline_raw,
};

fn corpus_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("corpus");
    p.push("native");
    p.push("packers");
    p.push("nspack");
    p
}

#[derive(Debug, Clone, Copy)]
struct E8Site {
    pos: usize,
    #[allow(dead_code)]
    op: u8,
    raw_disp_le: u32,
    bl_disp_le: u32,
    needs_fix: bool,
}

fn collect_sites(raw: &[u8], bl: &[u8]) -> Vec<E8Site> {
    let n: usize = raw.len().min(bl.len());
    if n < 5 {
        return Vec::new();
    }
    let mut sites: Vec<E8Site> = Vec::new();
    let mut i: usize = 0;
    while i + 4 < n {
        let op: u8 = raw[i];
        if op == 0xE8 || op == 0xE9 {
            let raw_disp_le: u32 =
                u32::from_le_bytes([raw[i + 1], raw[i + 2], raw[i + 3], raw[i + 4]]);
            let bl_disp_le: u32 = u32::from_le_bytes([bl[i + 1], bl[i + 2], bl[i + 3], bl[i + 4]]);
            let same_op: bool = bl[i] == op;
            let needs_fix: bool = same_op && raw_disp_le != bl_disp_le;
            sites.push(E8Site {
                pos: i,
                op,
                raw_disp_le,
                bl_disp_le,
                needs_fix,
            });
        }
        i += 1;
    }
    sites
}

fn run_one(name: &str) {
    let mut packed_p: PathBuf = corpus_dir();
    packed_p.push(format!("{name}.packed.nspack.exe"));
    let mut orig_p: PathBuf = corpus_dir();
    orig_p.push(format!("{name}.original.exe"));
    let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
        println!("SKIP {name}: packed missing");
        return;
    };
    let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
        println!("SKIP {name}: original missing");
        return;
    };
    let (rep, raw): (NspackEmulatedReport, Vec<u8>) =
        unpack_nspack_emulated_with_baseline_raw(&packed, Some(&orig)).unwrap();
    let fix_rep: NspackEmulatedReport =
        unpack_nspack_emulated_with_baseline(&packed, Some(&orig)).unwrap();
    let fixed: &[u8] = &fix_rep.decompressed_image;
    let bl: &[u8] = rep.original_image_baseline.as_ref().unwrap();
    let dsize: usize = rep.decompressed_size_bytes;
    let n_common0: usize = fixed.len().min(bl.len());
    let mut fixed_diff: usize = 0;
    let mut fixed_diff_regions: Vec<(usize, usize)> = Vec::new();
    let mut cur_fr: Option<usize> = None;
    for i in 0..n_common0 {
        if fixed[i] != bl[i] {
            fixed_diff += 1;
            if cur_fr.is_none() {
                cur_fr = Some(i);
            }
        } else if let Some(s) = cur_fr {
            fixed_diff_regions.push((s, i));
            cur_fr = None;
        }
    }
    if let Some(s) = cur_fr {
        fixed_diff_regions.push((s, n_common0));
    }
    println!(
        "  POST-FIXUP diff = {fixed_diff} bytes  ({} regions)  pct={:.3}%",
        fixed_diff_regions.len(),
        fixed_diff as f64 * 100.0 / dsize.max(1) as f64
    );
    let mut sample_step_fr: usize = fixed_diff_regions.len().max(1) / 8;
    if sample_step_fr == 0 {
        sample_step_fr = 1;
    }
    for (idx, (rs, re)) in fixed_diff_regions.iter().enumerate() {
        if idx != 0 && idx % sample_step_fr != 0 {
            continue;
        }
        let lo: usize = rs.saturating_sub(4);
        let hi: usize = (*re + 8).min(n_common0);
        println!(
            "    fix-region#{idx} [{rs:#x}..{re:#x}] len={:5}  fixed={:02x?}  bl={:02x?}",
            re - rs,
            &fixed[lo..hi.min(lo + 24)],
            &bl[lo..hi.min(lo + 24)]
        );
    }
    let mut last_nonzero: usize = 0;
    for i in 0..raw.len() {
        if raw[i] != 0 {
            last_nonzero = i;
        }
    }
    let mut last_nonzero_bl: usize = 0;
    for i in 0..bl.len() {
        if bl[i] != 0 {
            last_nonzero_bl = i;
        }
    }
    println!(
        "  PRE-RAW last-nonzero-raw={last_nonzero:#x}  last-nonzero-bl={last_nonzero_bl:#x}  raw.len={}  bl.len={}",
        raw.len(),
        bl.len()
    );
    let sites: Vec<E8Site> = collect_sites(&raw, bl);
    let total: usize = sites.len();
    let needs_fix: usize = sites.iter().filter(|s: &&E8Site| s.needs_fix).count();
    let skip: usize = total - needs_fix;
    println!("===== {name} =====");
    println!(
        "  dsize={dsize}  E8/E9-sites total={total}  needs_fix={needs_fix}  skip-as-is={skip}"
    );

    let mut hyp_correct: usize = 0;
    let mut hyp_wrong: usize = 0;
    let mut hyp_false_negative: usize = 0;
    let mut hyp_false_positive: usize = 0;
    let mut hyp_wrong_samples: Vec<(usize, u32, u32, u32)> = Vec::new();
    for s in &sites {
        let recovered: u32 = recover_disp(s.raw_disp_le, s.pos);
        let abs_target: i64 = (s.pos as i64) + 5 + (recovered as i32 as i64);
        let in_image: bool = abs_target >= 0 && (abs_target as usize) < dsize;
        let predicted_le: u32 = recovered;
        if in_image && predicted_le == s.bl_disp_le {
            hyp_correct += 1;
        } else if in_image && predicted_le != s.bl_disp_le {
            hyp_wrong += 1;
            if hyp_wrong_samples.len() < 12 {
                hyp_wrong_samples.push((s.pos, s.raw_disp_le, s.bl_disp_le, predicted_le));
            }
        } else if !in_image && s.needs_fix {
            hyp_false_negative += 1;
        } else if !in_image && !s.needs_fix && s.raw_disp_le == s.bl_disp_le {
        } else if in_image && !s.needs_fix && predicted_le != s.raw_disp_le {
            hyp_false_positive += 1;
        }
    }
    println!("  wrong-formula samples:");
    for (pos, raw_le, bl_le, pred_le) in &hyp_wrong_samples {
        println!("    pos={pos:#x}  raw={raw_le:08x}  bl={bl_le:08x}  predicted={pred_le:08x}");
    }
    println!(
        "  HYPOTHESIS (in-image-target): correct={hyp_correct}  wrong-formula={hyp_wrong}  false-neg(missed-real-fix)={hyp_false_negative}  false-pos(over-applied)={hyp_false_positive}"
    );

    let n_common: usize = raw.len().min(bl.len());
    let mut total_byte_diff_raw: usize = 0;
    for i in 0..n_common {
        if raw[i] != bl[i] {
            total_byte_diff_raw += 1;
        }
    }
    let mut diff_regions: Vec<(usize, usize)> = Vec::new();
    let mut cur: Option<usize> = None;
    for i in 0..n_common {
        if raw[i] != bl[i] {
            if cur.is_none() {
                cur = Some(i);
            }
        } else if let Some(s) = cur {
            diff_regions.push((s, i));
            cur = None;
        }
    }
    if let Some(s) = cur {
        diff_regions.push((s, n_common));
    }
    let mut e8_explained: usize = 0;
    let mut non_e8_diff_bytes: usize = 0;
    let mut non_e8_regions: Vec<(usize, usize)> = Vec::new();
    let mut site_starts: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    for s in &sites {
        if s.needs_fix {
            site_starts.insert(s.pos);
        }
    }
    for (rs, re) in &diff_regions {
        let mut classified_e8: bool = false;
        for off in (rs.saturating_sub(4))..*re {
            if site_starts.contains(&off) && off + 5 >= *rs && off <= *re {
                classified_e8 = true;
                break;
            }
        }
        if classified_e8 {
            e8_explained += re - rs;
        } else {
            non_e8_diff_bytes += re - rs;
            if non_e8_regions.len() < 8 {
                non_e8_regions.push((*rs, *re));
            }
        }
    }
    println!(
        "  RAW (no fixup) diff bytes total = {total_byte_diff_raw}  ({} regions)",
        diff_regions.len()
    );
    println!("    e8/e9-explained-diff = {e8_explained}  non-e8-diff = {non_e8_diff_bytes}");
    let mut shown_kinds: usize = 0;
    let mut last_shown_region: usize = 0;
    let mut sample_step: usize = diff_regions.len().max(1) / 12;
    if sample_step == 0 {
        sample_step = 1;
    }
    for (idx, (rs, re)) in diff_regions.iter().enumerate() {
        if idx != 0 && idx - last_shown_region < sample_step {
            continue;
        }
        last_shown_region = idx;
        let lo: usize = rs.saturating_sub(4);
        let hi: usize = (*re + 8).min(n_common);
        println!(
            "    region#{idx} [{rs:#x}..{re:#x}] len={:5}  raw={:02x?}  bl={:02x?}",
            re - rs,
            &raw[lo..hi.min(lo + 24)],
            &bl[lo..hi.min(lo + 24)]
        );
        shown_kinds += 1;
        if shown_kinds >= 16 {
            break;
        }
    }

    let mut pos_first_fix: Option<usize> = None;
    let mut pos_last_fix: Option<usize> = None;
    let mut pos_first_skip_in_fixregion: Option<usize> = None;
    for s in &sites {
        if s.needs_fix {
            if pos_first_fix.is_none() {
                pos_first_fix = Some(s.pos);
            }
            pos_last_fix = Some(s.pos);
        }
    }
    if let (Some(lo), Some(hi)) = (pos_first_fix, pos_last_fix) {
        for s in &sites {
            if s.pos > lo && s.pos < hi && !s.needs_fix {
                pos_first_skip_in_fixregion = Some(s.pos);
                break;
            }
        }
        println!(
            "  fix-window: [{lo:#x} .. {hi:#x}]  (span {} bytes)",
            hi - lo
        );
        if let Some(fs) = pos_first_skip_in_fixregion {
            println!("  first skip-in-window at {fs:#x}");
        }
    }

    let mut high_byte_hist_raw: BTreeMap<u8, usize> = BTreeMap::new();
    let mut high_byte_hist_bl: BTreeMap<u8, usize> = BTreeMap::new();
    for s in &sites {
        if !s.needs_fix {
            continue;
        }
        let raw_b3: u8 = (s.raw_disp_le >> 24) as u8;
        let bl_b3: u8 = (s.bl_disp_le >> 24) as u8;
        *high_byte_hist_raw.entry(raw_b3).or_insert(0) += 1;
        *high_byte_hist_bl.entry(bl_b3).or_insert(0) += 1;
    }
    println!("  raw-high-byte hist (fix sites): {high_byte_hist_raw:?}");
    println!("  bl -high-byte hist (fix sites): {high_byte_hist_bl:?}");

    let mut matched_formula: usize = 0;
    let mut not_matched: Vec<(usize, u32, u32)> = Vec::new();
    for s in sites.iter().filter(|s: &&E8Site| s.needs_fix) {
        let predicted_le: u32 = derive_target(s.raw_disp_le, s.pos);
        if predicted_le == s.bl_disp_le {
            matched_formula += 1;
        } else if not_matched.len() < 10 {
            not_matched.push((s.pos, s.raw_disp_le, s.bl_disp_le));
        }
    }
    println!("  current-formula match on needed-fix sites: {matched_formula}/{needs_fix}");
    for (pos, raw_le, bl_le) in &not_matched {
        let raw_be: u32 = raw_le.swap_bytes();
        let bl_be: u32 = bl_le.swap_bytes();
        println!(
            "    pos={pos:#x}  raw_le={raw_le:08x} raw_be={raw_be:08x}  bl_le={bl_le:08x} bl_be={bl_be:08x}  bl_signed={}",
            *bl_le as i32
        );
    }

    let mut wrong_apply: Vec<(usize, u32, u32, u32)> = Vec::new();
    for s in sites.iter().filter(|s: &&E8Site| !s.needs_fix) {
        let predicted_le: u32 = derive_target(s.raw_disp_le, s.pos);
        if predicted_le != s.raw_disp_le {
            wrong_apply.push((s.pos, s.raw_disp_le, s.bl_disp_le, predicted_le));
            if wrong_apply.len() >= 10 {
                break;
            }
        }
    }
    println!(
        "  current-formula would WRONGLY rewrite {} skip-sites (sample):",
        wrong_apply.len()
    );
    for (pos, raw_le, bl_le, pred_le) in &wrong_apply {
        println!(
            "    pos={pos:#x}  raw_le={raw_le:08x} bl_le={bl_le:08x}  predicted_le={pred_le:08x}"
        );
    }

    let mut hb_match: BTreeMap<u8, (usize, usize)> = BTreeMap::new();
    for s in &sites {
        let hb_raw: u8 = (s.raw_disp_le >> 24) as u8;
        let e: &mut (usize, usize) = hb_match.entry(hb_raw).or_insert((0, 0));
        if s.needs_fix {
            e.1 += 1;
        } else {
            e.0 += 1;
        }
    }
    println!("  high-byte-of-raw-disp -> (skip_count, fix_count):");
    for (hb, (sk, fx)) in &hb_match {
        if *sk + *fx >= 4 {
            println!("    {hb:#04x} -> skip={sk}  fix={fx}");
        }
    }

    let text_end_guess: usize = pos_first_fix.unwrap_or(0);
    let _ = text_end_guess;
}

#[test]
fn diag_pe_layout() {
    let names: [&str; 6] = ["hash", "ftp", "cmd", "calc", "psexec", "handle"];
    for name in &names {
        let mut packed_p: PathBuf = corpus_dir();
        packed_p.push(format!("{name}.packed.nspack.exe"));
        let mut orig_p: PathBuf = corpus_dir();
        orig_p.push(format!("{name}.original.exe"));
        let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
            continue;
        };
        let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
            continue;
        };
        println!("===== {name} packed =====");
        dump_pe_sections(&packed);
        println!("===== {name} original =====");
        dump_pe_sections(&orig);
    }
}

fn dump_pe_sections(buf: &[u8]) {
    if buf.len() < 0x40 {
        println!("  too small");
        return;
    }
    let e_lfanew: u32 = u32::from_le_bytes([buf[0x3c], buf[0x3d], buf[0x3e], buf[0x3f]]);
    let pe_off: usize = e_lfanew as usize;
    if pe_off + 24 > buf.len() {
        println!("  pe truncated");
        return;
    }
    let num_sections: u16 = u16::from_le_bytes([buf[pe_off + 6], buf[pe_off + 7]]);
    let opt_hdr_size: u16 = u16::from_le_bytes([buf[pe_off + 20], buf[pe_off + 21]]);
    let sections_off: usize = pe_off + 24 + opt_hdr_size as usize;
    for i in 0..num_sections {
        let s: usize = sections_off + i as usize * 40;
        if s + 40 > buf.len() {
            break;
        }
        let name: &[u8] = &buf[s..s + 8];
        let vsz: u32 = u32::from_le_bytes([buf[s + 8], buf[s + 9], buf[s + 10], buf[s + 11]]);
        let va: u32 = u32::from_le_bytes([buf[s + 12], buf[s + 13], buf[s + 14], buf[s + 15]]);
        let rsz: u32 = u32::from_le_bytes([buf[s + 16], buf[s + 17], buf[s + 18], buf[s + 19]]);
        let rva_p: u32 = u32::from_le_bytes([buf[s + 20], buf[s + 21], buf[s + 22], buf[s + 23]]);
        let nstr: String = name
            .iter()
            .take_while(|b: &&u8| **b != 0)
            .map(|b: &u8| *b as char)
            .collect();
        println!("  {nstr:8} vsz={vsz:#08x} va={va:#08x} rsz={rsz:#08x} ra={rva_p:#08x}");
    }
}

#[test]
fn diag_first_diff_per_fixture() {
    let names: [&str; 6] = ["hash", "ftp", "cmd", "calc", "psexec", "handle"];
    for name in &names {
        let mut packed_p: PathBuf = corpus_dir();
        packed_p.push(format!("{name}.packed.nspack.exe"));
        let mut orig_p: PathBuf = corpus_dir();
        orig_p.push(format!("{name}.original.exe"));
        let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
            continue;
        };
        let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
            continue;
        };
        let (_rep, raw): (NspackEmulatedReport, Vec<u8>) =
            unpack_nspack_emulated_with_baseline_raw(&packed, Some(&orig)).unwrap();
        let bl: Vec<u8> = {
            let r: NspackEmulatedReport =
                unpack_nspack_emulated_with_baseline(&packed, Some(&orig)).unwrap();
            r.original_image_baseline.unwrap()
        };
        let mut first_raw_diff: Option<usize> = None;
        let n: usize = raw.len().min(bl.len());
        for i in 0..n {
            if raw[i] != bl[i] {
                let is_e8_disp: bool =
                    (1..=4).any(|k: usize| i >= k && (raw[i - k] == 0xE8 || raw[i - k] == 0xE9));
                if !is_e8_disp {
                    first_raw_diff = Some(i);
                    break;
                }
            }
        }
        if let Some(d) = first_raw_diff {
            let lo: usize = d.saturating_sub(16);
            let hi: usize = (d + 32).min(n);
            println!(
                "{name}: first non-e8 raw-diff at {d:#x} (pct={:.2}% of dsize)",
                d as f64 * 100.0 / n as f64
            );
            println!("  raw[{lo:#x}..{hi:#x}]: {:02x?}", &raw[lo..hi]);
            println!("  bl [{lo:#x}..{hi:#x}]: {:02x?}", &bl[lo..hi]);
        } else {
            println!("{name}: NO non-e8 raw diff");
        }
    }
}

#[test]
fn diag_calc() {
    run_one("calc");
}

#[test]
fn diag_psexec() {
    run_one("psexec");
}

#[test]
fn diag_handle() {
    run_one("handle");
}

#[test]
fn diag_hash_for_comparison() {
    run_one("hash");
}

#[test]
fn diag_ftp_for_comparison() {
    run_one("ftp");
}

#[test]
fn diag_cmd_for_comparison() {
    run_one("cmd");
}

const fn derive_target(raw_le: u32, pos: usize) -> u32 {
    recover_disp(raw_le, pos)
}

const fn recover_disp(raw_le: u32, pos: usize) -> u32 {
    let bswapped: u32 = raw_le.swap_bytes();
    let masked: u32 = bswapped & 0x00FF_FFFF;
    let original: u32 = masked.wrapping_sub((pos as u32).wrapping_add(1));
    if original & 0x0080_0000 != 0 {
        original | 0xFF00_0000
    } else {
        original & 0x00FF_FFFF
    }
}
