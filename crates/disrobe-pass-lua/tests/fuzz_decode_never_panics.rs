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

use disrobe_pass_lua::decompile::{decompile_chunk, decompile_luajit_bytes};
use disrobe_pass_lua::obfuscator::{
    DeobfOptions, aztup_brew, boronide, darksec, hercules, ironbrew2, luaobfuscator_com, luraph,
    moonsec_v1, moonsec_v2, moonsec_v3, prometheus, psu, slua, vm_devirt, wearedevs,
};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaLocal, LuaProto};
use disrobe_pass_lua::reader::{self, detect, read_auto};
use disrobe_pass_lua::{decompile_auto, luvit, serialize_chunk};

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

fn drive_bytes(bytes: &[u8], desc: &str) {
    guard("detect", desc, || {
        let _ = detect(bytes);
    });
    guard("read_auto", desc, || {
        let _ = read_auto(bytes);
    });
    guard("reader::lua51::read", desc, || {
        let _ = reader::lua51::read(bytes);
    });
    guard("reader::lua52::read", desc, || {
        let _ = reader::lua52::read(bytes);
    });
    guard("reader::lua53::read", desc, || {
        let _ = reader::lua53::read(bytes);
    });
    guard("reader::lua54::read", desc, || {
        let _ = reader::lua54::read(bytes);
    });
    guard("reader::luajit::read", desc, || {
        let _ = reader::luajit::read(bytes);
    });
    guard("reader::luau::read", desc, || {
        let _ = reader::luau::read(bytes);
    });
    guard("reader::glua::read", desc, || {
        let _ = reader::glua::read(bytes);
    });
    guard("reader::glua::looks_like_glua", desc, || {
        let _ = reader::glua::looks_like_glua(bytes);
    });
    guard("decompile_auto", desc, || {
        let _ = decompile_auto(bytes);
    });
    guard("decompile_luajit_bytes", desc, || {
        let _ = decompile_luajit_bytes(bytes);
    });

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    macro_rules! drive_obf {
        ($m:ident) => {{
            guard(concat!(stringify!($m), "::detect"), desc, || {
                let _ = $m::detect(bytes);
            });
            guard(concat!(stringify!($m), "::peel"), desc, || {
                let _ = $m::peel(bytes, &opts);
            });
        }};
    }
    drive_obf!(prometheus);
    drive_obf!(moonsec_v1);
    drive_obf!(moonsec_v2);
    drive_obf!(moonsec_v3);
    drive_obf!(ironbrew2);
    drive_obf!(aztup_brew);
    drive_obf!(darksec);
    drive_obf!(boronide);
    drive_obf!(psu);
    drive_obf!(wearedevs);
    drive_obf!(luaobfuscator_com);
    drive_obf!(slua);
    drive_obf!(hercules);
    drive_obf!(luraph);

    guard("slua::parse_archive", desc, || {
        let _ = slua::parse_archive(bytes);
    });
    guard("vm_devirt::devirtualize", desc, || {
        let _ = vm_devirt::devirtualize(bytes, "");
    });
    guard("vm_devirt::emulate_perm_builder", desc, || {
        let _ = vm_devirt::emulate_perm_builder(bytes, 0x1234_5678);
    });
    guard("vm_devirt::devirt_to_peel", desc, || {
        let _ = vm_devirt::devirt_to_peel(bytes, "", bytes, "fuzz");
    });

    guard("luvit::detect", desc, || {
        let _ = luvit::detect(bytes);
    });
    guard("luvit::extract", desc, || {
        let _ = luvit::extract(bytes);
    });

    guard("format_lua", desc, || {
        let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
        let _ = disrobe_pass_lua::format_lua(&text);
    });

    guard("read_auto->serialize+decompile_chunk", desc, || {
        if let Ok(chunk) = read_auto(bytes) {
            let _ = serialize_chunk(&chunk);
            let _ = decompile_chunk(&chunk);
        }
    });
}

fn lua51_header() -> Vec<u8> {
    vec![
        0x1b, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00,
    ]
}

fn lua53_header() -> Vec<u8> {
    let mut h: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x53, 0x00];
    h.extend_from_slice(&[0x19, 0x93, b'\r', b'\n', 0x1a, b'\n']);
    h.extend_from_slice(&[0x04, 0x08, 0x04, 0x08, 0x08]);
    h.extend_from_slice(&0x5678i64.to_le_bytes());
    h.extend_from_slice(&370.5f64.to_le_bytes());
    h
}

fn lua54_header() -> Vec<u8> {
    let mut h: Vec<u8> = vec![0x1b, b'L', b'u', b'a', 0x54, 0x00];
    h.extend_from_slice(&[0x19, 0x93, b'\r', b'\n', 0x1a, b'\n']);
    h.extend_from_slice(&[0x04, 0x08, 0x08]);
    h.extend_from_slice(&0x5678i64.to_le_bytes());
    h.extend_from_slice(&370.5f64.to_le_bytes());
    h
}

fn luajit_header() -> Vec<u8> {
    vec![0x1b, b'L', b'J', 0x02, 0x00, 0x00]
}

fn luau_header() -> Vec<u8> {
    vec![0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]
}

fn seed_corpus() -> Vec<Vec<u8>> {
    vec![
        lua51_header(),
        lua53_header(),
        lua54_header(),
        luajit_header(),
        luau_header(),
        b"./package.lua\0".to_vec(),
        vec![b'L', b'I', b'T', 0x01, 0, 0, 0, 0],
        b"local function LPH_ENCFUNCTION(a) return a end".to_vec(),
        b"return(function(...)local Prometheus=1 end)()".to_vec(),
        b"-- MoonSec V3\nlocal a={};do return a end".to_vec(),
        b"IronBrew2 v3 do return end".to_vec(),
        b"local script=game and 1;return function() end".to_vec(),
        {
            let mut v: Vec<u8> = lua51_header();
            v.extend_from_slice(&[0u8; 40]);
            v
        },
    ]
}

fn mutate(rng: &mut XorShift64, base: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = base.to_vec();
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
                let bit: u8 = 1u8 << rng.range(0, 7);
                buf[idx] ^= bit;
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
                let run: usize = rng.range(1, 8);
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
            let count: usize = rng.range(1, 16);
            for i in 0..count {
                buf.insert(
                    idx.min(buf.len()).saturating_add(i).min(buf.len()),
                    rng.byte(),
                );
            }
        }
    }
    buf
}

#[test]
fn seeded_mutations_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x00C0_FFEE_D15E_A5E5);
    let corpus: Vec<Vec<u8>> = seed_corpus();
    const ITERATIONS: usize = 6000;
    for i in 0..ITERATIONS {
        let base: &Vec<u8> = &corpus[i % corpus.len()];
        let mutated: Vec<u8> = mutate(&mut rng, base);
        drive_bytes(&mutated, "seeded-mutation");
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng: XorShift64 = XorShift64::new(0x5EED_C0DE_F00D_BA11);
    const ITERATIONS: usize = 4000;
    for _ in 0..ITERATIONS {
        let len: usize = rng.range(0, 512);
        let bytes: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
        drive_bytes(&bytes, "pure-random");
    }
}

fn synth_constants(rng: &mut XorShift64, n: usize) -> Vec<LuaConstant> {
    (0..n)
        .map(|_| match rng.range(0, 4) {
            0 => LuaConstant::Nil,
            1 => LuaConstant::Bool(rng.byte() & 1 == 1),
            2 => LuaConstant::Integer(rng.next_u64() as i64),
            3 => LuaConstant::Number(f64::from_bits(rng.next_u64())),
            _ => LuaConstant::Str("k".to_owned()),
        })
        .collect()
}

fn synth_proto(rng: &mut XorShift64, depth: usize) -> LuaProto {
    let code_len: usize = rng.range(0, 400);
    let code: Vec<u32> = (0..code_len).map(|_| rng.next_u64() as u32).collect();
    let const_len: usize = rng.range(0, 12);
    let constants: Vec<LuaConstant> = synth_constants(rng, const_len);
    let child_count: usize = if depth == 0 { rng.range(0, 3) } else { 0 };
    let protos: Vec<LuaProto> = (0..child_count)
        .map(|_| synth_proto(rng, depth + 1))
        .collect();
    let local_count: usize = rng.range(0, 6);
    let locals: Vec<LuaLocal> = (0..local_count)
        .map(|_| LuaLocal {
            name: "l".to_owned(),
            start_pc: rng.next_u64() as u32,
            end_pc: rng.next_u64() as u32,
        })
        .collect();
    LuaProto {
        source: Some("<fuzz>".to_owned()),
        line_defined: rng.next_u64() as u32,
        last_line_defined: rng.next_u64() as u32,
        num_params: rng.byte(),
        is_vararg: rng.byte() & 1,
        max_stack_size: rng.byte(),
        code,
        constants,
        protos,
        source_lines: Vec::new(),
        locals,
        upvalues: Vec::new(),
    }
}

#[test]
fn synthetic_chunk_lifter_never_panics() {
    let mut rng: XorShift64 = XorShift64::new(0x1337_D00D_CAFE_F00D);
    let dialects: [LuaDialect; 6] = [
        LuaDialect::Lua51,
        LuaDialect::Lua52,
        LuaDialect::Lua53,
        LuaDialect::Lua54,
        LuaDialect::Luau,
        LuaDialect::GLua,
    ];
    const ITERATIONS: usize = 3000;
    for i in 0..ITERATIONS {
        let dialect: LuaDialect = dialects[i % dialects.len()];
        let main: LuaProto = synth_proto(&mut rng, 0);
        let chunk: LuaChunk = LuaChunk {
            dialect,
            version_byte: 0x53,
            format: 0,
            little_endian: true,
            size_of_int: 4,
            size_of_size_t: 8,
            size_of_instruction: 4,
            size_of_lua_integer: 8,
            size_of_lua_number: 8,
            integral_number: false,
            main,
        };
        guard("decompile_chunk(synthetic)", "synthetic-chunk", || {
            let _ = decompile_chunk(&chunk);
        });
        guard("serialize_chunk(synthetic)", "synthetic-chunk", || {
            let _ = serialize_chunk(&chunk);
        });
    }
}
