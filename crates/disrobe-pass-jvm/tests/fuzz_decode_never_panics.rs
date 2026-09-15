#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::items_after_statements
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Once;

use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};
use disrobe_pass_jvm::{
    CLASS_MAGIC, DEX_MAGIC_PREFIX, PackageRecoveryReport, decode_method, decompile_classfile_bytes,
    decompile_dex_from_bytes, disassemble, disassemble_dalvik, encode_stub_loader_container,
    parse_classfile, parse_dex, recover_packed_dex,
};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    const fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    const fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    const fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

fn silence_panic_hook() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
}

fn drive_classfile(bytes: &[u8]) {
    let owned: Vec<u8> = bytes.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = parse_classfile(&owned);
        let _ = decompile_classfile_bytes(&owned);
    }));
    assert!(
        result.is_ok(),
        "classfile decode unwound on fuzz input ({} bytes): {:02x?}",
        bytes.len(),
        &bytes[..bytes.len().min(64)]
    );
}

fn drive_dex(bytes: &[u8]) {
    let owned: Vec<u8> = bytes.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = parse_dex(&owned);
        let _ = decompile_dex_from_bytes(&owned);
    }));
    assert!(
        result.is_ok(),
        "dex decode unwound on fuzz input ({} bytes): {:02x?}",
        bytes.len(),
        &bytes[..bytes.len().min(64)]
    );
}

fn drive_jvm_code(code: &[u8]) {
    let owned: Vec<u8> = code.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = disassemble(&owned);
    }));
    assert!(
        result.is_ok(),
        "jvm disassemble unwound on fuzz code ({} bytes): {:02x?}",
        code.len(),
        &code[..code.len().min(64)]
    );
}

fn drive_dalvik_units(units: &[u16]) {
    let owned: Vec<u16> = units.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = decode_method(&owned);
        let _ = disassemble_dalvik(&owned);
    }));
    assert!(
        result.is_ok(),
        "dalvik decode unwound on fuzz units ({} units)",
        units.len()
    );
}

fn drive_packed_dex_recovery(bytes: &[u8]) {
    let owned: Vec<u8> = bytes.to_vec();
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(|| {
        let _ = recover_packed_dex(&owned);
    }));
    assert!(
        result.is_ok(),
        "packed-dex recovery unwound on fuzz input ({} bytes): {:02x?}",
        bytes.len(),
        &bytes[..bytes.len().min(64)]
    );
}

fn tiny_stub_loader_dex_for_fuzz() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/example/pack/StubApp;".to_owned(),
        super_class: "Landroid/app/Application;".to_owned(),
        access_flags: 0x11,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: vec![EncodedMethod {
            tries: Vec::new(),
            method: MethodRef {
                class: "Lcom/example/pack/StubApp;".to_owned(),
                proto: ProtoRef {
                    return_type: "V".to_owned(),
                    params: Vec::new(),
                },
                name: "<init>".to_owned(),
            },
            access_flags: 0x1,
            is_direct: true,
            registers_size: 1,
            ins_size: 1,
            outs_size: 1,
            insns: vec![0x000e],
            relocations: Vec::new(),
        }],
        virtual_methods: Vec::new(),
    });
    builder.build()
}

fn wrap_apk_zip_for_fuzz(stub_dex: &[u8], container: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let cursor: std::io::Cursor<&mut Vec<u8>> = std::io::Cursor::new(&mut buf);
    let mut writer: zip::ZipWriter<std::io::Cursor<&mut Vec<u8>>> = zip::ZipWriter::new(cursor);
    let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default();
    writer
        .start_file("classes.dex", options)
        .expect("start classes.dex");
    std::io::Write::write_all(&mut writer, stub_dex).expect("write classes.dex");
    writer
        .start_file("assets/payload.bin", options)
        .expect("start payload asset");
    std::io::Write::write_all(&mut writer, container).expect("write payload asset");
    let _ = writer.finish().expect("finish zip");
    buf
}

fn corpus_files(sub: &str, ext: &str) -> Vec<PathBuf> {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("../../corpus/jvm");
    root.push(sub);
    let mut out: Vec<PathBuf> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == ext) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn random_classfile_bytes_never_panic() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0x0DDB_A11C_A11A_B1E5);
    const ITERATIONS: usize = 4_000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let mut bytes: Vec<u8> = Vec::with_capacity(len + 4);
        if rng.next_u64() & 1 == 0 {
            bytes.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        }
        for _ in 0..len {
            bytes.push(rng.byte());
        }
        drive_classfile(&bytes);
    }
}

#[test]
fn random_dex_bytes_never_panic() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0xD15E_A5ED_DEAD_BEEF);
    const ITERATIONS: usize = 4_000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let mut bytes: Vec<u8> = Vec::with_capacity(len + 8);
        if rng.next_u64() & 1 == 0 {
            bytes.extend_from_slice(&DEX_MAGIC_PREFIX);
            bytes.extend_from_slice(b"035\0");
        }
        for _ in 0..len {
            bytes.push(rng.byte());
        }
        drive_dex(&bytes);
    }
}

#[test]
fn random_jvm_code_never_panics() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0xCAFE_BABE_F00D_1337);
    const ITERATIONS: usize = 6_000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 256);
        let code: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_jvm_code(&code);
    }
    for op in 0u16..=0xFF {
        for tail in 0u16..=8 {
            let mut code: Vec<u8> = vec![op as u8];
            code.extend(std::iter::repeat_n(0u8, tail as usize));
            drive_jvm_code(&code);
        }
    }
}

#[test]
fn random_dalvik_units_never_panic() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0xABAD_1DEA_0F1E_CE55);
    const ITERATIONS: usize = 6_000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 128);
        let units: Vec<u16> = (0..len).map(|_| (rng.next_u64() >> 16) as u16).collect();
        drive_dalvik_units(&units);
    }
    for op in 0u32..=0xFF {
        for tail in 0u16..=6 {
            let mut units: Vec<u16> = vec![op as u16];
            units.extend(std::iter::repeat_n(0u16, tail as usize));
            drive_dalvik_units(&units);
        }
    }
}

#[test]
fn real_class_corpus_mutations_never_panic() {
    silence_panic_hook();
    let corpus: Vec<PathBuf> = corpus_files("", "class");
    if corpus.is_empty() {
        return;
    }
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_C1A5_05E5);
    let mut checked: usize = 0;
    for path in &corpus {
        let Ok(base) = std::fs::read(path) else {
            continue;
        };
        drive_classfile(&base);
        for _ in 0..256 {
            let mut bytes: Vec<u8> = base.clone();
            if !bytes.is_empty() {
                let flips: usize = rng.range(1, 12);
                for _ in 0..flips {
                    let idx: usize = rng.range(0, bytes.len() - 1);
                    bytes[idx] ^= rng.byte();
                }
            }
            drive_classfile(&bytes);
        }
        checked += 1;
    }
    assert!(checked > 0, "class corpus present but nothing exercised");
}

#[test]
fn real_dex_corpus_mutations_never_panic() {
    silence_panic_hook();
    let corpus: Vec<PathBuf> = corpus_files("", "dex");
    if corpus.is_empty() {
        return;
    }
    let mut rng: XorShift64 = XorShift64::new(0x0001_CEC0_FFEE_BEE5);
    let mut checked: usize = 0;
    for path in &corpus {
        let Ok(base) = std::fs::read(path) else {
            continue;
        };
        drive_dex(&base);
        for _ in 0..256 {
            let mut bytes: Vec<u8> = base.clone();
            if !bytes.is_empty() {
                let flips: usize = rng.range(1, 12);
                for _ in 0..flips {
                    let idx: usize = rng.range(0, bytes.len() - 1);
                    bytes[idx] ^= rng.byte();
                }
            }
            drive_dex(&bytes);
        }
        checked += 1;
    }
    assert!(checked > 0, "dex corpus present but nothing exercised");
}

#[test]
fn random_apk_zip_bytes_never_panic_packed_dex_recovery() {
    silence_panic_hook();
    let mut rng: XorShift64 = XorShift64::new(0xFEED_FACE_5BAD_C0DE);
    const ITERATIONS: usize = 3_000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_packed_dex_recovery(&bytes);
    }
}

#[test]
fn mutated_wrapped_package_never_panics_packed_dex_recovery() {
    silence_panic_hook();
    let stub_dex: Vec<u8> = tiny_stub_loader_dex_for_fuzz();
    let payload: Vec<u8> = b"dex\n035\0filler payload body for mutation fuzzing"
        .iter()
        .cycle()
        .take(400)
        .copied()
        .collect();
    let key: Vec<u8> = vec![0x9F, 0x02, 0x77, 0xC3, 0x18, 0x5A];
    let container: Vec<u8> = encode_stub_loader_container(&payload, &key, 0x1357_9BDF);
    let base: Vec<u8> = wrap_apk_zip_for_fuzz(&stub_dex, &container);
    drive_packed_dex_recovery(&base);

    let mut rng: XorShift64 = XorShift64::new(0xB16B_00B5_5CA1_AB1E);
    for _ in 0..512 {
        let mut bytes: Vec<u8> = base.clone();
        let flips: usize = rng.range(1, 16);
        for _ in 0..flips {
            let idx: usize = rng.range(0, bytes.len() - 1);
            bytes[idx] ^= rng.byte();
        }
        drive_packed_dex_recovery(&bytes);
    }
}

#[test]
fn mutated_wrapped_package_reports_stay_internally_consistent() {
    let stub_dex: Vec<u8> = tiny_stub_loader_dex_for_fuzz();
    let payload: Vec<u8> = b"dex\n035\0another filler payload body for the consistency sweep"
        .iter()
        .cycle()
        .take(300)
        .copied()
        .collect();
    let key: Vec<u8> = vec![0x11, 0x22, 0x33];
    let container: Vec<u8> = encode_stub_loader_container(&payload, &key, 42);
    let base: Vec<u8> = wrap_apk_zip_for_fuzz(&stub_dex, &container);

    let mut rng: XorShift64 = XorShift64::new(0x0BAD_F00D_1CE0_FFEE);
    for _ in 0..256 {
        let mut bytes: Vec<u8> = base.clone();
        let flips: usize = rng.range(1, 8);
        for _ in 0..flips {
            let idx: usize = rng.range(0, bytes.len() - 1);
            bytes[idx] ^= rng.byte();
        }
        let report: PackageRecoveryReport = recover_packed_dex(&bytes);
        if report.selected.is_none() {
            assert!(report.outcome.is_none());
        }
    }
}
