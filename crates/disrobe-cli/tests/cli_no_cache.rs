#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};

use common::{Run, run_disrobe_env, temp_dir, temp_path, write_bytes};

fn count_cache_entries(cache_root: &Path) -> usize {
    fn walk(dir: &Path, acc: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                walk(&path, acc);
            } else if path.extension().and_then(|s| s.to_str()) == Some("drc") {
                *acc += 1;
            }
        }
    }
    let mut acc: usize = 0;
    walk(cache_root, &mut acc);
    acc
}

fn create(src: &Path, out: &Path, cache_dir: &Path, extra: &[&str]) -> Run {
    let mut args: Vec<&str> = Vec::new();
    args.extend_from_slice(extra);
    let src_s: String = src.to_str().unwrap().to_owned();
    let out_s: String = out.to_str().unwrap().to_owned();
    args.extend_from_slice(&["envelope", "create", &src_s, "--out", &out_s]);
    run_disrobe_env(&args, &[("DISROBE_CACHE_DIR", cache_dir.to_str().unwrap())])
}

#[test]
fn warm_run_is_a_cache_hit_and_byte_identical_to_cold() {
    let cache_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cache-warm");
    let cache_dir: PathBuf = cache_dir_scratch.path().to_path_buf();
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("warm-src", "bin");
    write_bytes(&src, b"deterministic content-addressed cache subject\n");

    let (_cold_out_scratch, cold_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("warm-cold", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&cold_out);
    let cold: Run = create(&src, &cold_out, &cache_dir, &[]);
    assert_eq!(
        cold.code, 0,
        "cold run must succeed. stdout={} stderr={}",
        cold.stdout, cold.stderr
    );
    assert!(
        !cold.stdout.contains("cache hit"),
        "cold run must not report a hit: {}",
        cold.stdout
    );
    assert!(cold_out.exists(), "cold envelope not written");
    assert_eq!(
        count_cache_entries(&cache_dir),
        1,
        "cold run must populate exactly one cache entry"
    );
    let cold_bytes: Vec<u8> = std::fs::read(&cold_out).expect("read cold .dr");

    let (_warm_out_scratch, warm_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("warm-warm", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&warm_out);
    let warm: Run = create(&src, &warm_out, &cache_dir, &[]);
    assert_eq!(
        warm.code, 0,
        "warm run must succeed. stdout={} stderr={}",
        warm.stdout, warm.stderr
    );
    assert!(
        warm.stdout.contains("cache hit"),
        "warm run must report a cache hit (proves the pass did not re-execute): {}",
        warm.stdout
    );
    let warm_bytes: Vec<u8> = std::fs::read(&warm_out).expect("read warm .dr");
    assert_eq!(
        cold_bytes, warm_bytes,
        "a cache hit must be byte-identical to the cold run"
    );
    assert_eq!(
        count_cache_entries(&cache_dir),
        1,
        "a hit must not add a second entry for the same input+config"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
fn changing_input_busts_the_cache() {
    let cache_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cache-bust");
    let cache_dir: PathBuf = cache_dir_scratch.path().to_path_buf();
    let (_src_a_scratch, src_a): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bust-a", "bin");
    write_bytes(&src_a, b"first payload\n");
    let (_out_a_scratch, out_a): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bust-out-a", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&out_a);
    let a: Run = create(&src_a, &out_a, &cache_dir, &[]);
    assert_eq!(a.code, 0, "stdout={} stderr={}", a.stdout, a.stderr);

    let (_src_b_scratch, src_b): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bust-b", "bin");
    write_bytes(&src_b, b"second different payload\n");
    let (_out_b_scratch, out_b): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bust-out-b", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&out_b);
    let b: Run = create(&src_b, &out_b, &cache_dir, &[]);
    assert_eq!(b.code, 0, "stdout={} stderr={}", b.stdout, b.stderr);
    assert!(
        !b.stdout.contains("cache hit"),
        "different input must not hit the cache: {}",
        b.stdout
    );
    assert_eq!(
        count_cache_entries(&cache_dir),
        2,
        "two distinct inputs must produce two distinct cache entries"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
}

#[test]
fn no_cache_neither_reads_nor_writes_and_output_is_identical() {
    let cache_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cache-bypass");
    let cache_dir: PathBuf = cache_dir_scratch.path().to_path_buf();
    let (_src_scratch, src): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bypass-src", "bin");
    write_bytes(&src, b"no-cache bypass subject\n");

    let (_seed_out_scratch, seed_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bypass-seed", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&seed_out);
    let seed: Run = create(&src, &seed_out, &cache_dir, &[]);
    assert_eq!(
        seed.code, 0,
        "stdout={} stderr={}",
        seed.stdout, seed.stderr
    );
    assert_eq!(
        count_cache_entries(&cache_dir),
        1,
        "seed run must populate the cache"
    );
    let seed_bytes: Vec<u8> = std::fs::read(&seed_out).expect("read seed .dr");

    let (_bypass_out_scratch, bypass_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bypass-out", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&bypass_out);
    let bypass: Run = create(&src, &bypass_out, &cache_dir, &["--no-cache"]);
    assert_eq!(
        bypass.code, 0,
        "--no-cache run must succeed. stdout={} stderr={}",
        bypass.stdout, bypass.stderr
    );
    assert!(
        !bypass.stdout.contains("cache hit"),
        "--no-cache must not read the cache even though a matching entry exists: {}",
        bypass.stdout
    );
    assert_eq!(
        count_cache_entries(&cache_dir),
        1,
        "--no-cache must not write a new entry"
    );
    let bypass_bytes: Vec<u8> = std::fs::read(&bypass_out).expect("read bypass .dr");
    assert_eq!(
        seed_bytes, bypass_bytes,
        "output must be byte-identical with or without --no-cache"
    );

    let fresh_cache_scratch: disrobe_core::scratch::ScratchDir = temp_dir("cache-bypass-fresh");

    let fresh_cache: PathBuf = fresh_cache_scratch.path().to_path_buf();
    let (_fresh_out_scratch, fresh_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("bypass-fresh", "dr");
    let _: std::io::Result<()> = std::fs::remove_file(&fresh_out);
    let fresh: Run = create(&src, &fresh_out, &fresh_cache, &["--no-cache"]);
    assert_eq!(
        fresh.code, 0,
        "stdout={} stderr={}",
        fresh.stdout, fresh.stderr
    );
    assert_eq!(
        count_cache_entries(&fresh_cache),
        0,
        "--no-cache must not create any cache entry on a cold cache"
    );

    let _ = std::fs::remove_dir_all(&cache_dir);
    let _ = std::fs::remove_dir_all(&fresh_cache);
}
