#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::format_push_string,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_pass_lua::obfuscator::vm_devirt::{
    BUILDER_MAGIC, BootstrapKeys, PB_ADD, PB_AND, PB_EMIT_MAP, PB_HALT, PB_MUL, PB_PUSH_IMM,
    PB_PUSH_SEED, PB_SET_XORKEY, VM_KIND_IRONBREW2, VM_MAGIC, VOP_ADD, VOP_CALL, VOP_GETGLOBAL,
    VOP_LOADK, VOP_MOVE, VOP_RETURN, emulate_perm_builder,
};
use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
use disrobe_pass_lua::reader::common::LuaConstant;

const VK_NUMBER: u8 = 3;
const VK_STRING: u8 = 4;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct VmInsn {
    vop: u8,
    a: u32,
    b: u32,
    c: u32,
}

struct VmModule {
    max_stack: u8,
    num_params: u8,
    is_vararg: u8,
    constants: Vec<LuaConstant>,
    code: Vec<VmInsn>,
}

const CANONICAL_HANDLERS: [u8; 6] = [
    VOP_MOVE,
    VOP_LOADK,
    VOP_GETGLOBAL,
    VOP_ADD,
    VOP_CALL,
    VOP_RETURN,
];

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn build_permutation_program(step: u32, base: u32, key_mask: u32) -> Vec<u8> {
    let mut program: Vec<u8> = Vec::new();
    program.extend_from_slice(BUILDER_MAGIC);
    program.push(PB_PUSH_SEED);
    program.push(PB_PUSH_IMM);
    push_u32(&mut program, key_mask);
    program.push(PB_AND);
    program.push(PB_SET_XORKEY);
    for (slot, canonical) in CANONICAL_HANDLERS.iter().enumerate() {
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, slot as u32);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, step);
        program.push(PB_MUL);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, base);
        program.push(PB_ADD);
        program.push(PB_PUSH_SEED);
        program.push(PB_ADD);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, 0xFF);
        program.push(PB_AND);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, u32::from(*canonical));
        program.push(PB_EMIT_MAP);
    }
    program.push(PB_HALT);
    program
}

fn solved_permutation(seed: u32, step: u32, base: u32, key_mask: u32) -> BootstrapKeys {
    let program: Vec<u8> = build_permutation_program(step, base, key_mask);
    emulate_perm_builder(&program, seed).expect("emulate the permutation builder")
}

fn encoded_for_vop(opmap: &BTreeMap<u8, u8>, vop: u8) -> u8 {
    opmap
        .iter()
        .find(|(_, v): &(&u8, &u8)| **v == vop)
        .map(|(k, _): (&u8, &u8)| *k)
        .expect("canonical op present in solved permutation")
}

fn encode_module(module: &VmModule, opmap: &BTreeMap<u8, u8>, xor_key: u8) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(module.max_stack);
    body.push(module.num_params);
    body.push(module.is_vararg);
    push_u32(&mut body, module.constants.len() as u32);
    for k in &module.constants {
        match k {
            LuaConstant::Number(n) => {
                body.push(VK_NUMBER);
                body.extend_from_slice(&n.to_le_bytes());
            }
            LuaConstant::Str(s) => {
                body.push(VK_STRING);
                push_u32(&mut body, s.len() as u32);
                body.extend_from_slice(s.as_bytes());
            }
            _ => panic!("unsupported constant in encoder"),
        }
    }
    push_u32(&mut body, module.code.len() as u32);
    for insn in &module.code {
        body.push(encoded_for_vop(opmap, insn.vop));
        push_u32(&mut body, insn.a);
        push_u32(&mut body, insn.b);
        push_u32(&mut body, insn.c);
    }
    for byte in &mut body {
        *byte ^= xor_key;
    }
    let mut payload: Vec<u8> = Vec::with_capacity(body.len() + 6);
    payload.extend_from_slice(VM_MAGIC);
    payload.push(VM_KIND_IRONBREW2);
    payload.push(xor_key);
    payload.extend_from_slice(&body);
    payload
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn known_module() -> VmModule {
    VmModule {
        max_stack: 4,
        num_params: 0,
        is_vararg: 2,
        constants: vec![
            LuaConstant::Str("print".to_owned()),
            LuaConstant::Number(40.0),
            LuaConstant::Number(2.0),
        ],
        code: vec![
            VmInsn {
                vop: VOP_GETGLOBAL,
                a: 0,
                b: 0,
                c: 0,
            },
            VmInsn {
                vop: VOP_LOADK,
                a: 1,
                b: 1,
                c: 0,
            },
            VmInsn {
                vop: VOP_LOADK,
                a: 2,
                b: 2,
                c: 0,
            },
            VmInsn {
                vop: VOP_ADD,
                a: 1,
                b: 1,
                c: 2,
            },
            VmInsn {
                vop: VOP_CALL,
                a: 0,
                b: 2,
                c: 1,
            },
            VmInsn {
                vop: VOP_RETURN,
                a: 0,
                b: 1,
                c: 0,
            },
        ],
    }
}

fn bootstrap_with_payload(header: &str, seed: u32, step: u32, base: u32) -> (String, Vec<u8>) {
    let keys: BootstrapKeys = solved_permutation(seed, step, base, 0xFF);
    let xor_key: u8 = keys.xor_key.expect("recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&known_module(), &keys.opmap, xor_key);
    let program: Vec<u8> = build_permutation_program(step, base, 0xFF);
    let mut boot: String = String::new();
    boot.push_str(header);
    boot.push('\n');
    boot.push_str(&format!("SEED={seed}\n"));
    boot.push_str(&format!("PERMBUILD={}\n", to_hex(&program)));
    boot.push_str(&format!("VMPAYLOAD={} \n", to_hex(&payload)));
    (boot, payload)
}

fn assert_reference_container_roundtrip(family: &str, result: &PeelResult) {
    assert!(
        result.fully_recovered,
        "{family}: the {family} marker must route the reference-container payload through a full \
         round-trip back to runnable Lua (this is disrobe's own DVM1 container, not {family}'s \
         real wire format); markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(
        recovered.contains("print"),
        "{family}: recovered lua must call print:\n{recovered}"
    );
    assert!(
        recovered.contains('+'),
        "{family}: recovered lua must contain the 40 + 2 addition:\n{recovered}"
    );
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "print"),
        "{family}: must surface the 'print' string constant"
    );
}

fn find_lua() -> Option<String> {
    let candidates: [&str; 6] = ["lua", "lua5.4", "lua5.1", "luajit", "lua54", "lua51"];
    for c in candidates {
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
    let tmp: PathBuf =
        std::env::temp_dir().join(format!("vmfam_{}_{unique}.lua", std::process::id()));
    std::fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

fn assert_executes_like_original(family: &str, result: &PeelResult) {
    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter on PATH; skipping execution oracle for {family}");
        return;
    };
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    let expected: String =
        run_lua(&interp, "print(40 + 2)").expect("original print(40+2) runs under interp");
    let actual: String = run_lua(&interp, &recovered).unwrap_or_else(|| {
        panic!("{family}: recovered source failed to run under {interp}:\n{recovered}")
    });
    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "{family}: recovered program output must match the known original\n--- recovered ---\n{recovered}"
    );
}

#[test]
fn boronide_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::boronide;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- Boronide v0.6\nBORONIDE_VM", 0x1357_2468, 11, 0x40);
    let result: PeelResult =
        boronide::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("boronide", &result);
    assert_executes_like_original("boronide", &result);
}

#[test]
fn psu_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::psu;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- PSU 4.5\nPSU_VM_KEY", 0x0042_0042, 7, 0x50);
    let result: PeelResult = psu::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("psu", &result);
    assert_executes_like_original("psu", &result);
}

#[test]
fn darksec_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::darksec;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- DarkSec\nDS_VM_BOOT", 0x7F7F_7F7F, 13, 0x60);
    let result: PeelResult =
        darksec::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("darksec", &result);
    assert_executes_like_original("darksec", &result);
}

#[test]
fn moonsec_v1_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::moonsec_v1;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v1\nmoonsec_v1", 0x1111_2222, 9, 0x30);
    let result: PeelResult =
        moonsec_v1::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("moonsec_v1", &result);
    assert_executes_like_original("moonsec_v1", &result);
}

#[test]
fn moonsec_v2_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::moonsec_v2;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v2\nMS_V2_KEY", 0x2222_3333, 7, 0x50);
    let result: PeelResult =
        moonsec_v2::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("moonsec_v2", &result);
    assert_executes_like_original("moonsec_v2", &result);
}

#[test]
fn moonsec_v3_marker_roundtrips_reference_container_with_authorization() {
    use disrobe_pass_lua::moonsec_v3;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v3\nMS_VM_ENTRY", 0x3333_4444, 13, 0x60);
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(boot.as_bytes(), &opts).expect("peel");
    assert_reference_container_roundtrip("moonsec_v3", &result);
    assert_executes_like_original("moonsec_v3", &result);
}

#[test]
fn moonsec_v3_embedded_payload_blocks_without_authorization() {
    use disrobe_pass_lua::moonsec_v3;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- MoonSec v3\nMS_VM_ENTRY", 0x3333_4444, 13, 0x60);
    let err: disrobe_pass_lua::Error =
        moonsec_v3::peel(boot.as_bytes(), &DeobfOptions::default()).unwrap_err();
    assert!(matches!(
        err,
        disrobe_pass_lua::Error::AuthorizationRequired("MoonSec V3")
    ));
}

#[test]
fn aztup_brew_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::aztup_brew;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- aztup_brew\nAZB_VM", 0x4242_4242, 11, 0x40);
    let result: PeelResult =
        aztup_brew::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("aztup_brew", &result);
    assert_executes_like_original("aztup_brew", &result);
}

#[test]
fn prometheus_does_not_claim_disrobe_vm_container() {
    use disrobe_pass_lua::prometheus;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- Prometheus\nPROMETHEUS_VERSION", 0x5050_6060, 11, 0x40);
    let result: PeelResult =
        prometheus::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert!(
        !result.fully_recovered,
        "prometheus must not claim a test-only vm container as real family recovery"
    );
    assert!(
        result
            .residual_markers
            .iter()
            .any(|marker: &String| marker.contains("constant-array")),
        "prometheus must report the real missing parser surface: {:?}",
        result.residual_markers
    );
}

#[test]
fn hercules_marker_roundtrips_reference_container() {
    use disrobe_pass_lua::hercules;
    let (boot, _payload): (String, Vec<u8>) = bootstrap_with_payload(
        "-- Obfuscated by Hercules\nhercules-obfuscator",
        0x6161_7272,
        7,
        0x50,
    );
    let result: PeelResult =
        hercules::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("hercules", &result);
    assert_executes_like_original("hercules", &result);
}

#[test]
fn luraph_marker_roundtrips_reference_container_else_walls() {
    use disrobe_pass_lua::luraph;
    let (boot, _payload): (String, Vec<u8>) =
        bootstrap_with_payload("-- Luraph\nlura.ph", 0x7272_8383, 13, 0x60);
    let result: PeelResult = luraph::peel(boot.as_bytes(), &DeobfOptions::default()).expect("peel");
    assert_reference_container_roundtrip("luraph", &result);
    assert_executes_like_original("luraph", &result);
}

#[test]
fn luraph_real_runtime_key_is_honest_wall() {
    use disrobe_pass_lua::luraph;
    let real: &[u8] = b"-- This file was generated by Luraph\nlocal a=LPH_ENCFUNC(...)\nreturn a";
    let result: PeelResult = luraph::peel(real, &DeobfOptions::default()).expect("peel");
    assert!(
        !result.fully_recovered,
        "luraph runtime-key sample must NOT fabricate a recovery"
    );
    assert!(
        result
            .residual_markers
            .iter()
            .any(|m: &String| m.contains("WALL") && m.contains("runtime")),
        "luraph must report the honest info-theoretic runtime-key wall: {:?}",
        result.residual_markers
    );
}

#[test]
fn luaobfuscator_com_unpacks_real_free_tier_constant_pool() {
    use disrobe_pass_lua::luaobfuscator_com;
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop();
    path.pop();
    path.push("corpus/lua/obfuscators/luaobfuscator_com/sample_default_obf_v1.lua");
    let data: Vec<u8> = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing committed fixture {}: {e}", path.display()));
    let result: PeelResult =
        luaobfuscator_com::peel(&data, &DeobfOptions::default()).expect("peel real fixture");
    for want in [
        "sieve_of_eratosthenes",
        "print",
        "math",
        "floor",
        "sqrt",
        "string",
        "pairs",
    ] {
        assert!(
            result.recovered_strings.iter().any(|s: &String| s == want),
            "the real free-tier unpacker must recover the plaintext constant {want:?}; got {:?}",
            result.recovered_strings
        );
    }
}

#[test]
fn families_without_payload_are_honest_passthrough() {
    use disrobe_pass_lua::{boronide, darksec, psu};
    for (name, result) in [
        (
            "boronide",
            boronide::peel(b"-- Boronide v0.5\nBORONIDE_VM", &DeobfOptions::default())
                .expect("peel"),
        ),
        (
            "psu",
            psu::peel(b"-- PSU 4.0\nPSU_VM_KEY", &DeobfOptions::default()).expect("peel"),
        ),
        (
            "darksec",
            darksec::peel(b"-- DarkSec\nDS_VM_BOOT", &DeobfOptions::default()).expect("peel"),
        ),
    ] {
        assert!(
            !result.fully_recovered,
            "{name}: no embedded payload means no honest full recovery"
        );
        assert!(
            !result.residual_markers.is_empty(),
            "{name}: passthrough must explain why"
        );
    }
}
