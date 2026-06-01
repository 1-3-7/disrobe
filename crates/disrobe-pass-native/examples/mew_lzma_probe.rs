//! Diagnostic probe for MEW LZMA payload.
//!
//! Pre-skips chunks 1 and 2 (file-offset hardcoded from prior analysis) and feeds
//! the remaining LZMA stream into `decode_mpress_lzma` with synthesised props.
//!
//! Run with: `cargo run -p disrobe-pass-native --example mew_lzma_probe`

use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixtures: [(&str, usize); 3] = [
        ("AccessEnum", 0x0d53),
        ("Autologon", 0x0a8d),
        ("Clockres", 0x099b),
    ];
    for (stem, off) in fixtures {
        probe(stem, off)?;
    }
    Ok(())
}

fn probe(stem: &str, post_chunks_off: usize) -> Result<(), Box<dyn std::error::Error>> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("corpus");
    path.push("native");
    path.push("packers");
    path.push("mew");
    let packed: Vec<u8> = fs::read(path.join(format!("{stem}.packed.mew.exe")))?;
    let orig: Vec<u8> = fs::read(path.join(format!("{stem}.original.exe")))?;
    println!(
        "=== {stem} packed={}B orig={}B post_off={:#x} ===",
        packed.len(),
        orig.len(),
        post_chunks_off
    );
    let probs_ptr: u32 = u32_le(&packed, post_chunks_off);
    let count: u32 = u32_le(&packed, post_chunks_off + 4);
    let out_va: u32 = u32_le(&packed, post_chunks_off + 8);
    let clen: u32 = u32_le(&packed, post_chunks_off + 12);
    let stream_off: usize = post_chunks_off + 17;
    let stream: &[u8] = &packed[stream_off..stream_off + clen as usize];
    println!(
        "  probs={probs_ptr:#x} count={count} (0x{count:x}) out_va={out_va:#x} clen={clen:#x} stream_off={stream_off:#x}"
    );
    println!("  stream[0..32]: {:02x?}", &stream[..32.min(stream.len())]);

    for (lc, lp, pb) in [
        (4u8, 0u8, 2u8),
        (3, 0, 2),
        (4, 0, 4),
        (2, 0, 2),
        (3, 0, 4),
        (1, 1, 2),
        (0, 0, 2),
        (3, 0, 0),
        (4, 0, 0),
    ] {
        let mut framed: Vec<u8> = Vec::with_capacity(2 + stream.len());
        framed.push((pb << 4) | lp);
        framed.push(lc);
        framed.extend_from_slice(stream);
        match disrobe_pass_native::packers::decode_mpress_lzma(&framed, count as usize) {
            Ok(out) => {
                let (best_m, best_o): (usize, usize) = scan_alignment(&out, &orig);
                let n: usize = 0x2000.min(out.len());
                println!(
                    "  lc={lc} lp={lp} pb={pb}: ok len={} best_align orig_off={best_o:#x} match={best_m}/{n} ({:.1}%)",
                    out.len(),
                    100.0 * best_m as f64 / n as f64
                );
                if best_m > 1000 {
                    let recovered_at_orig: usize = best_o;
                    let compare_len: usize = out.len().min(orig.len() - recovered_at_orig);
                    let full_match: usize = (0..compare_len)
                        .filter(|&i: &usize| out[i] == orig[recovered_at_orig + i])
                        .count();
                    println!(
                        "    full @ orig_off={recovered_at_orig:#x}: {full_match}/{compare_len} ({:.1}%)",
                        100.0 * full_match as f64 / compare_len as f64
                    );
                    println!("    rec[0..32]: {:02x?}", &out[..32.min(out.len())]);
                    println!(
                        "    org[{:#x}..{:#x}]: {:02x?}",
                        recovered_at_orig,
                        recovered_at_orig + 32,
                        &orig[recovered_at_orig..(recovered_at_orig + 32).min(orig.len())]
                    );
                    let mut dump: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                    dump.push("..");
                    dump.push("..");
                    dump.push(".developer");
                    dump.push("v0.9-a4-scratch");
                    let _ = fs::create_dir_all(&dump);
                    dump.push(format!("{stem}_lzma_{lc}{lp}{pb}.bin"));
                    let _ = fs::write(&dump, &out);
                    break;
                }
            }
            Err(e) => {
                println!("  lc={lc} lp={lp} pb={pb}: failed: {e:?}");
            }
        }
    }
    Ok(())
}

fn u32_le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn scan_alignment(out: &[u8], orig: &[u8]) -> (usize, usize) {
    let n: usize = out.len().min(0x2000);
    let mut best_m: usize = 0;
    let mut best_o: usize = 0;
    if orig.len() < n {
        return (0, 0);
    }
    let max_off: usize = orig.len() - n;
    let mut o: usize = 0;
    while o <= max_off {
        let m: usize = (0..n).filter(|&i: &usize| out[i] == orig[o + i]).count();
        if m > best_m {
            best_m = m;
            best_o = o;
        }
        o += 16;
    }
    (best_m, best_o)
}
