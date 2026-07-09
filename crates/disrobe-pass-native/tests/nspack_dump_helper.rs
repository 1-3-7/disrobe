#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss
)]

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

fn scratch_dir() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push(".developer");
    p.push("v0.8-scratch");
    p
}

#[test]
fn dump_handle_first_diff() {
    let mut packed_p: PathBuf = corpus_dir();
    packed_p.push("handle.packed.nspack.exe");
    let mut orig_p: PathBuf = corpus_dir();
    orig_p.push("handle.original.exe");
    let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
        return;
    };
    let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
        return;
    };
    let (r, raw): (NspackEmulatedReport, Vec<u8>) =
        unpack_nspack_emulated_with_baseline_raw(&packed, Some(&orig)).unwrap();
    println!(
        "  raw decompressed (no E8 fix) [:80]: {:02x?}",
        &raw[..80.min(raw.len())]
    );
    let dc: &[u8] = &r.decompressed_image;
    let bl: &[u8] = r.original_image_baseline.as_ref().unwrap();
    let mut first_diff: Option<usize> = None;
    for i in 0..dc.len().min(bl.len()) {
        if dc[i] != bl[i] {
            first_diff = Some(i);
            break;
        }
    }
    println!(
        "handle: dsize={} diff={:?} pct={:?}",
        dc.len(),
        r.byte_diff_count,
        r.byte_diff_pct
    );
    println!("  first diff at: {first_diff:?}");
    if let Some(d) = first_diff {
        let lo: usize = d.saturating_sub(16);
        let hi: usize = (d + 64).min(dc.len()).min(bl.len());
        println!("  dc[{lo:#x}..{hi:#x}]: {:02x?}", &dc[lo..hi]);
        println!("  bl[{lo:#x}..{hi:#x}]: {:02x?}", &bl[lo..hi]);
    }
    println!("  decompressed[:64]: {:02x?}", &dc[..64.min(dc.len())]);
    println!("  baseline    [:64]: {:02x?}", &bl[..64.min(bl.len())]);
    let mut diff_regions: Vec<(usize, usize)> = Vec::new();
    let mut in_diff: Option<usize> = None;
    for i in 0..dc.len().min(bl.len()) {
        if dc[i] != bl[i] {
            if in_diff.is_none() {
                in_diff = Some(i);
            }
        } else if let Some(start) = in_diff {
            diff_regions.push((start, i));
            in_diff = None;
        }
    }
    if let Some(start) = in_diff {
        diff_regions.push((start, dc.len().min(bl.len())));
    }
    println!("  diff region count: {}", diff_regions.len());
    for (s, e) in diff_regions.iter().take(20) {
        let lo: usize = s.saturating_sub(4);
        let hi: usize = (*e + 4).min(dc.len()).min(bl.len());
        println!(
            "    region [{s:#x}..{e:#x}] dc={:02x?} bl={:02x?}",
            &dc[lo..hi],
            &bl[lo..hi]
        );
    }
}

#[test]
fn dump_cmd_for_inspection() {
    let mut packed_p: PathBuf = corpus_dir();
    packed_p.push("cmd.packed.nspack.exe");
    let mut orig_p: PathBuf = corpus_dir();
    orig_p.push("cmd.original.exe");
    let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
        return;
    };
    let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
        return;
    };
    let res = unpack_nspack_emulated_with_baseline_raw(&packed, Some(&orig));
    match res {
        Ok((r, raw)) => {
            println!(
                "cmd OK: dsize={} diff={:?} pct={:?}",
                r.decompressed_image.len(),
                r.byte_diff_count,
                r.byte_diff_pct
            );
            println!("  raw[:80]: {:02x?}", &raw[..80.min(raw.len())]);
            if let Some(bl) = r.original_image_baseline.as_ref() {
                println!("  bl[:80]: {:02x?}", &bl[..80.min(bl.len())]);
            }
        }
        Err(e) => println!("cmd ERR: {e:?}"),
    }
}

#[test]
fn dump_hash_for_inspection() {
    let mut packed_p: PathBuf = corpus_dir();
    packed_p.push("hash.packed.nspack.exe");
    let mut orig_p: PathBuf = corpus_dir();
    orig_p.push("hash.original.exe");
    let Ok(packed): std::io::Result<Vec<u8>> = fs::read(&packed_p) else {
        return;
    };
    let Ok(orig): std::io::Result<Vec<u8>> = fs::read(&orig_p) else {
        return;
    };
    let (_r2, raw_hash): (NspackEmulatedReport, Vec<u8>) =
        unpack_nspack_emulated_with_baseline_raw(&packed, Some(&orig)).unwrap();
    println!(
        "  hash RAW (no E8 fix) [:80]: {:02x?}",
        &raw_hash[..80.min(raw_hash.len())]
    );
    let r: NspackEmulatedReport =
        unpack_nspack_emulated_with_baseline(&packed, Some(&orig)).unwrap();
    fs::create_dir_all(scratch_dir()).unwrap();
    let mut out: PathBuf = scratch_dir();
    out.push("dump_hash_decompressed.bin");
    fs::write(&out, &r.decompressed_image).unwrap();
    let mut out2: PathBuf = scratch_dir();
    out2.push("dump_hash_baseline.bin");
    fs::write(&out2, r.original_image_baseline.as_ref().unwrap()).unwrap();
    println!(
        "hash: dsize={}, diff={:?}, pct={:?}",
        r.decompressed_image.len(),
        r.byte_diff_count,
        r.byte_diff_pct
    );
    let dc: &[u8] = &r.decompressed_image;
    let bl: &[u8] = r.original_image_baseline.as_ref().unwrap();
    println!("  decompressed[:64]:  {:02x?}", &dc[..64.min(dc.len())]);
    println!("  baseline    [:64]:  {:02x?}", &bl[..64.min(bl.len())]);
    let mut first_diff: Option<usize> = None;
    for i in 0..dc.len().min(bl.len()) {
        if dc[i] != bl[i] {
            first_diff = Some(i);
            break;
        }
    }
    println!("  first byte diff at: {first_diff:?}");
    if let Some(d) = first_diff {
        let lo: usize = d.saturating_sub(8);
        let hi: usize = (d + 32).min(dc.len()).min(bl.len());
        println!("  dc[{lo:#x}..{hi:#x}]: {:02x?}", &dc[lo..hi]);
        println!("  bl[{lo:#x}..{hi:#x}]: {:02x?}", &bl[lo..hi]);
    }
}
