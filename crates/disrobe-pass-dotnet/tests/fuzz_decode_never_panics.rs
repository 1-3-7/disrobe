#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::too_many_lines
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;

use disrobe_pass_dotnet::cil::{self, MethodBody};
use disrobe_pass_dotnet::decompile::{decompile_assembly, decompile_assembly_in};
use disrobe_pass_dotnet::metadata::{
    self, StreamHeader, parse_table_stream, read_strings_heap, read_us_heap_strings,
};
use disrobe_pass_dotnet::peel::confuserex_constants::{
    decode_pool_string, decrypt_constants_blob, peel_confuserex_constants,
};
use disrobe_pass_dotnet::peel::koivm::koistream::parse_koistream;
use disrobe_pass_dotnet::peel::peel_obfuscar;
use disrobe_pass_dotnet::peel::static_decrypt::recover_static_decoders;
use disrobe_pass_dotnet::peel::{deflatten, eazvm, koivm};
use disrobe_pass_dotnet::protectors::Protector;
use disrobe_pass_dotnet::structurize::TargetLang;
use disrobe_pass_dotnet::{
    aot, pass, pe, peel_agile_net, peel_armdot, peel_babel_net, peel_by, peel_confuserex_resources,
    peel_crypto_obfuscator, peel_deepsea, peel_dotfuscator, peel_dotnet_reactor, peel_eazfuscator,
    peel_goliath, peel_ilprotector, peel_maxtocode, peel_skater, peel_smartassembly,
    peel_spices_net, peel_themida_dotnet, protectors, signature, tables,
};

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed | 1 }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x: u64 = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + (self.next_u64() as usize) % (hi - lo + 1)
    }
}

fn guard<F: FnOnce()>(label: &str, desc: &str, f: F) {
    let result: std::thread::Result<()> = catch_unwind(AssertUnwindSafe(f));
    assert!(result.is_ok(), "{label} unwound on fuzz input ({desc})");
}

const PROTECTORS: [Protector; 23] = [
    Protector::ConfuserEx,
    Protector::ConfuserEx2,
    Protector::Dotfuscator,
    Protector::DotfuscatorCe,
    Protector::SmartAssembly,
    Protector::BabelDotnet,
    Protector::DeepSea,
    Protector::SpicesNet,
    Protector::Goliath,
    Protector::Skater,
    Protector::DotnetReactor,
    Protector::EazfuscatorNet,
    Protector::CryptoObfuscator,
    Protector::ArmDot,
    Protector::AgileNet,
    Protector::DotNetPatcher,
    Protector::NetCryptor,
    Protector::Obfuscar,
    Protector::ThemidaDotnet,
    Protector::Ilprotector,
    Protector::MaxToCode,
    Protector::KoiVm,
    Protector::BitMono,
];

fn drive_whole_image(image: &[u8], seed: u32, full_decompile: bool, desc: &str) {
    guard("pe::parse", desc, || {
        let _ = pe::parse(image);
    });
    guard("pass::analyze", desc, || {
        let _ = pass::analyze(image);
    });
    guard("decompile_assembly", desc, || {
        let _ = decompile_assembly(image);
    });
    if full_decompile {
        for lang in [TargetLang::CSharp, TargetLang::FSharp, TargetLang::VbNet] {
            guard("decompile_assembly_in", desc, || {
                let _ = decompile_assembly_in(image, lang);
            });
        }
    }
    guard("protectors::detect_all", desc, || {
        let _ = protectors::detect_all(image);
    });
    guard("aot::detect", desc, || {
        let _ = aot::detect(image);
    });
    guard("recover_static_decoders", desc, || {
        let _ = recover_static_decoders(image);
    });
    guard("deflatten::analyze", desc, || {
        let _ = deflatten::analyze(image);
    });
    guard("koivm::detect", desc, || {
        let _ = koivm::detect(image);
    });
    guard("koivm::devirtualize", desc, || {
        let _ = koivm::devirtualize(image);
    });
    guard("eazvm::detect", desc, || {
        let _ = eazvm::detect(image);
    });
    guard("eazvm::devirtualize", desc, || {
        let _ = eazvm::devirtualize(image);
    });
    guard("peel_confuserex_constants", desc, || {
        let _ = peel_confuserex_constants(image);
    });
    guard("peel_confuserex_resources", desc, || {
        let _ = peel_confuserex_resources(image);
    });
    macro_rules! drive_peel {
        ($f:ident) => {
            guard(stringify!($f), desc, || {
                let _ = $f(image);
            });
        };
    }
    drive_peel!(peel_agile_net);
    drive_peel!(peel_armdot);
    drive_peel!(peel_babel_net);
    drive_peel!(peel_crypto_obfuscator);
    drive_peel!(peel_deepsea);
    drive_peel!(peel_dotfuscator);
    drive_peel!(peel_dotnet_reactor);
    drive_peel!(peel_eazfuscator);
    drive_peel!(peel_goliath);
    drive_peel!(peel_ilprotector);
    drive_peel!(peel_maxtocode);
    drive_peel!(peel_obfuscar);
    drive_peel!(peel_skater);
    drive_peel!(peel_smartassembly);
    drive_peel!(peel_spices_net);
    drive_peel!(peel_themida_dotnet);
    for p in PROTECTORS {
        guard("peel_by", desc, || {
            let _ = peel_by(p, image);
        });
    }
    let _ = seed;
}

fn drive_leaf(bytes: &[u8], seed: u32, desc: &str) {
    guard("signature::parse_method_sig", desc, || {
        let _ = signature::parse_method_sig(bytes);
    });
    guard("signature::parse_field_sig", desc, || {
        let _ = signature::parse_field_sig(bytes);
    });
    guard("signature::parse_local_sig", desc, || {
        let _ = signature::parse_local_sig(bytes);
    });
    guard("signature::parse_type_spec_sig", desc, || {
        let _ = signature::parse_type_spec_sig(bytes);
    });
    guard("cil::parse_method_body", desc, || {
        let _ = cil::parse_method_body(bytes);
    });
    guard("cil::disassemble", desc, || {
        let _ = cil::disassemble(bytes);
    });
    guard("metadata::decompress_uint", desc, || {
        let _ = metadata::decompress_uint(bytes);
    });
    let full: StreamHeader = StreamHeader {
        offset: 0,
        size: bytes.len() as u32,
    };
    let skewed: StreamHeader = StreamHeader {
        offset: seed,
        size: seed ^ 0xDEAD_BEEF,
    };
    for header in [full, skewed] {
        guard("metadata::parse_table_stream", desc, || {
            let _ = parse_table_stream(bytes, header);
        });
        guard("tables::parse_tables", desc, || {
            let _ = tables::parse_tables(bytes, header);
        });
        guard("metadata::read_us_heap_strings", desc, || {
            let _ = read_us_heap_strings(bytes, header);
        });
        guard("metadata::read_strings_heap", desc, || {
            let _ = read_strings_heap(bytes, header);
        });
    }
    guard("decrypt_constants_blob", desc, || {
        let _ = decrypt_constants_blob(bytes, seed);
    });
    guard("decode_pool_string", desc, || {
        let _ = decode_pool_string(bytes, seed);
    });
    guard("parse_koistream", desc, || {
        let _ = parse_koistream(bytes);
    });
    guard("parse_method_body->deflatten", desc, || {
        if let Ok(body) = cil::parse_method_body(bytes) {
            let b: MethodBody = body;
            let _ = deflatten::is_flattened(&b);
            let _ = deflatten::deflatten_body(&b);
        }
    });
}

fn load(rel: &str) -> Option<Vec<u8>> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).ok()
}

fn fixtures() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for rel in [
        "tests/fixtures/GenVerify.dll",
        "tests/fixtures/VerifyCases.dll",
    ] {
        if let Some(bytes) = load(rel) {
            out.push(bytes);
        }
    }
    out
}

fn minimal_pe() -> Vec<u8> {
    let mut buf: Vec<u8> = vec![0u8; 0x200];
    buf[0] = b'M';
    buf[1] = b'Z';
    buf[0x3C] = 0x80;
    buf[0x80] = b'P';
    buf[0x81] = b'E';
    buf[0x82] = 0;
    buf[0x83] = 0;
    buf[0x98] = 0x0B;
    buf[0x99] = 0x01;
    buf
}

fn mutate(rng: &mut XorShift64, base: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = base.to_vec();
    let rounds: usize = rng.range(1, 4);
    for _ in 0..rounds {
        let op: usize = rng.range(0, 6);
        match op {
            0 => {
                if !buf.is_empty() {
                    let cut: usize = rng.range(0, buf.len());
                    buf.truncate(cut);
                }
            }
            1 => {
                if !buf.is_empty() {
                    let idx: usize = rng.range(0, buf.len() - 1);
                    buf[idx] ^= 1u8 << rng.range(0, 7);
                }
            }
            2 => {
                if !buf.is_empty() {
                    let idx: usize = rng.range(0, buf.len() - 1);
                    buf[idx] = rng.byte();
                }
            }
            3 => {
                let extra: usize = rng.range(1, 64);
                for _ in 0..extra {
                    buf.push(rng.byte());
                }
            }
            4 => {
                if buf.len() >= 2 {
                    let a: usize = rng.range(0, buf.len() - 1);
                    let b: usize = rng.range(0, buf.len() - 1);
                    buf.swap(a, b);
                }
            }
            5 => {
                if !buf.is_empty() {
                    let idx: usize = rng.range(0, buf.len() - 1);
                    let run: usize = rng.range(1, 16);
                    let val: u8 = rng.byte();
                    for i in 0..run {
                        if idx + i < buf.len() {
                            buf[idx + i] = val;
                        }
                    }
                }
            }
            _ => {
                let idx: usize = if buf.is_empty() {
                    0
                } else {
                    rng.range(0, buf.len())
                };
                let val: u8 = rng.byte();
                buf.insert(idx.min(buf.len()), val);
            }
        }
    }
    buf
}

#[test]
fn leaf_parsers_seeded_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    let mut seeds: Vec<Vec<u8>> = vec![
        vec![0x06, 0x08],
        vec![0x00, 0x00, 0x08],
        vec![0x20, 0x01, 0x08, 0x08],
        vec![0x12, 0x15, 0x12, 0x08],
        vec![0x02, 0x16, 0x17, 0x58, 0x2A],
        vec![0x1B, 0x30, 0x02, 0x00, 0x08, 0x00, 0x00, 0x00],
        (0..64u8).collect(),
    ];
    seeds.extend(fixtures());
    const ITERATIONS: usize = 6000;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &seeds[i % seeds.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_leaf(&mutated, rng.next_u64() as u32, "leaf-seeded-mutation");
    }
}

#[test]
fn leaf_parsers_random_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    const ITERATIONS: usize = 4000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_leaf(&bytes, rng.next_u64() as u32, "leaf-random");
    }
}

#[test]
fn whole_image_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0xABAD_1DEA_F00D_CAFE);
    let mut seeds: Vec<Vec<u8>> = vec![minimal_pe()];
    seeds.extend(fixtures());
    for image in &seeds {
        drive_whole_image(image, 0, true, "whole-image-pristine");
    }
    const ITERATIONS: usize = 500;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &seeds[i % seeds.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_whole_image(
            &mutated,
            rng.next_u64() as u32,
            false,
            "whole-image-mutation",
        );
    }
}

#[test]
fn whole_image_random_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x1337_D00D_CAFE_F00D);
    const ITERATIONS: usize = 1500;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 1024);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_whole_image(&bytes, rng.next_u64() as u32, false, "whole-image-random");
    }
}
