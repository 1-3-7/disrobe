#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::moonsec_v1;
use disrobe_pass_lua::obfuscator::{DeobfOptions, LuaObfuscatorKind};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const STD_BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out: String = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0: u32 = u32::from(chunk[0]);
        let b1: u32 = chunk.get(1).map_or(0, |b: &u8| u32::from(*b));
        let b2: u32 = chunk.get(2).map_or(0, |b: &u8| u32::from(*b));
        let n: u32 = (b0 << 16) | (b1 << 8) | b2;
        out.push(STD_BASE64[((n >> 18) & 0x3F) as usize] as char);
        out.push(STD_BASE64[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(STD_BASE64[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(STD_BASE64[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn moonsec_v1_wrap(original_source: &str, key: &[u8]) -> String {
    let cipher: Vec<u8> = original_source
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let blob: String = base64_encode(&cipher);
    let key_table: String = key
        .iter()
        .map(|b: &u8| b.to_string())
        .collect::<Vec<String>>()
        .join(",");
    format!(
        "-- MoonSec v1\nlocal MS_KEY={{{key_table}}}\nlocal DATA=\"{blob}\"\n\
         local function decode(s) local out={{}} for i=1,#s do out[i]=string.char(0) end return s end\n\
         local chunk=decode(DATA)\nreturn loadstring(chunk)()\n"
    )
}

fn markerless_wrap(original_source: &str, key: &[u8], wrap_at: Option<usize>) -> String {
    let cipher: Vec<u8> = original_source
        .bytes()
        .enumerate()
        .map(|(i, b): (usize, u8)| b ^ key[i % key.len()])
        .collect();
    let flat: String = base64_encode(&cipher);
    let blob: String = match wrap_at {
        Some(width) => flat
            .as_bytes()
            .chunks(width)
            .map(|c: &[u8]| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<String>>()
            .join("\n"),
        None => flat,
    };
    let key_table: String = key
        .iter()
        .map(|b: &u8| b.to_string())
        .collect::<Vec<String>>()
        .join(",");
    format!(
        "local K={{{key_table}}}\nlocal D=\"{blob}\"\nlocal function dec(s) return s end\nreturn loadstring(dec(D))()\n"
    )
}

fn find_lua() -> Option<String> {
    for c in ["lua", "lua5.4", "lua5.1", "lua54", "lua51", "luajit"] {
        if Command::new(c)
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn run_lua(interp: &str, source: &str) -> Option<String> {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("ms1_loader_{}_{unique}", std::process::id());
    let (scratch, file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "lua").ok()?;
    drop(file);
    let tmp: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

#[test]
fn moonsec_v1_base64_xor_loader_recovers_original_source() {
    let original: &str = "local function greet(name)\n  return \"hello \" .. name\nend\nprint(greet(\"world\"))\nprint(1 + 2 + 3)\n";
    let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
    let wrapped: String = moonsec_v1_wrap(original, key);

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel");

    assert!(
        out.fully_recovered,
        "plaintext lua source must be fully recovered; residual: {:?}",
        out.residual_markers
    );
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8 recovered source");
    assert_eq!(
        recovered, original,
        "decrypted loader body must match the original source byte for byte"
    );
    assert!(
        out.passes_run
            .iter()
            .any(|p: &String| p.contains("base64-xor-loader-decrypt")),
        "the base64+xor decrypt pass must be reported: {:?}",
        out.passes_run
    );
}

#[test]
fn moonsec_v1_recovered_source_executes_identically() {
    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter on PATH; skipping execution oracle");
        return;
    };
    let original: &str =
        "local t = {}\nfor i = 1, 5 do t[i] = i * i end\nfor _, v in ipairs(t) do print(v) end\n";
    let key: &[u8] = &[0xA5, 0x13, 0x77];
    let wrapped: String = moonsec_v1_wrap(original, key);

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel");
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8");

    let original_out: String = run_lua(&interp, original).expect("run original");
    let recovered_out: String = run_lua(&interp, &recovered).expect("run recovered");
    assert_eq!(
        original_out, recovered_out,
        "recovered source must produce identical stdout under a real lua interpreter"
    );
}

#[test]
fn moonsec_v1_single_byte_brute_force_loader() {
    let original: &str = "print(\"single byte key works\")\nlocal x = 42\nreturn x\n";
    let key: &[u8] = &[0x7B];
    let cipher: Vec<u8> = original.bytes().map(|b: u8| b ^ key[0]).collect();
    let blob: String = base64_encode(&cipher);
    let wrapped: String =
        format!("-- MoonSec v1\nlocal DATA=\"{blob}\"\nreturn loadstring(DATA)()\n");

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel");
    assert!(
        out.fully_recovered,
        "single-byte xor key must be brute-forced and recovered"
    );
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8");
    assert_eq!(recovered, original);
}

#[test]
fn markerless_loader_is_detected_without_any_moonsec_marker() {
    let original: &str = "local function add(a, b)\n  return a + b\nend\nprint(add(40, 2))\n";
    let key: &[u8] = &[0x91, 0x37, 0xC4];
    let wrapped: String = markerless_wrap(original, key, None);
    assert!(
        !wrapped.contains("MoonSec") && !wrapped.contains("moonsec"),
        "fixture must carry no MoonSec marker"
    );

    let det = moonsec_v1::detect(wrapped.as_bytes()).expect("markerless detection must fire");
    assert_eq!(det.kind, LuaObfuscatorKind::MoonSecV1);
    assert!(
        det.confidence < 88,
        "markerless detection must rank below marker-based detection"
    );
}

#[test]
fn markerless_loader_peels_to_original_source() {
    let original: &str = "local s = 0\nfor i = 1, 100 do s = s + i end\nprint(s)\nreturn s\n";
    let key: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF];
    let wrapped: String = markerless_wrap(original, key, None);

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel markerless");
    assert!(out.fully_recovered, "markerless loader must fully recover");
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8");
    assert_eq!(recovered, original);
}

#[test]
fn line_wrapped_blob_peels_to_original_source() {
    let original: &str = "local t = {1, 2, 3, 4, 5}\nlocal acc = 0\nfor _, v in ipairs(t) do acc = acc + v end\nprint(acc)\n";
    let key: &[u8] = &[0x4D, 0x6F, 0x6F, 0x6E];
    let wrapped: String = markerless_wrap(original, key, Some(20));
    assert!(
        wrapped.matches('\n').count() > 4,
        "blob must physically wrap across multiple source lines"
    );

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel wrapped");
    assert!(
        out.fully_recovered,
        "line-wrapped loader must fully recover"
    );
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8");
    assert_eq!(recovered, original);
}

#[test]
fn clean_lua_does_not_trigger_markerless_detection() {
    let clean: &str = "local function fib(n)\n  if n < 2 then return n end\n  return fib(n - 1) + fib(n - 2)\nend\nfor i = 1, 12 do print(fib(i)) end\n";
    assert!(
        moonsec_v1::detect(clean.as_bytes()).is_none(),
        "clean lua must never be misdetected as a MoonSec loader"
    );
}

#[test]
fn markerless_recovered_source_executes_identically() {
    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter on PATH; skipping execution oracle");
        return;
    };
    let original: &str = "local function fact(n)\n  if n <= 1 then return 1 end\n  return n * fact(n - 1)\nend\nfor i = 1, 6 do print(fact(i)) end\n";
    let key: &[u8] = &[0x2A, 0x5F];
    let wrapped: String = markerless_wrap(original, key, Some(16));

    let opts: DeobfOptions = DeobfOptions::default();
    let out = moonsec_v1::peel(wrapped.as_bytes(), &opts).expect("peel markerless wrapped");
    let recovered: String = String::from_utf8(out.deobfuscated).expect("utf8");

    let original_out: String = run_lua(&interp, original).expect("run original");
    let recovered_out: String = run_lua(&interp, &recovered).expect("run recovered");
    assert_eq!(
        original_out, recovered_out,
        "markerless+wrapped recovered source must match original stdout under real lua"
    );
}
