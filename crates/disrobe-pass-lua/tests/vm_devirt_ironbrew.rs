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

use disrobe_pass_lua::decompile::lift::{LiftedProto, lift_proto_dialect};
use disrobe_pass_lua::obfuscator::vm_devirt::{
    BUILDER_MAGIC, BootstrapKeys, DevirtReport, Devirtualized, PB_ADD, PB_AND, PB_EMIT_MAP,
    PB_HALT, PB_MUL, PB_PUSH_IMM, PB_PUSH_SEED, PB_SET_XORKEY, VM_KIND_IRONBREW2, VM_MAGIC,
    VOP_ADD, VOP_CALL, VOP_GETGLOBAL, VOP_LOADK, VOP_MOVE, VOP_RETURN, devirtualize,
    emulate_perm_builder,
};
use disrobe_pass_lua::reader::common::{LuaConstant, LuaDialect, LuaProto};

const VK_NIL: u8 = 0;
const VK_BOOL: u8 = 1;
const VK_NUMBER: u8 = 3;
const VK_STRING: u8 = 4;

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

struct PermRecipe {
    seed: u32,
    step: u32,
    base: u32,
    key_mask: u32,
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

fn build_permutation_program(recipe: &PermRecipe) -> Vec<u8> {
    let mut program: Vec<u8> = Vec::new();
    program.extend_from_slice(BUILDER_MAGIC);
    program.push(PB_PUSH_SEED);
    program.push(PB_PUSH_IMM);
    push_u32(&mut program, recipe.key_mask);
    program.push(PB_AND);
    program.push(PB_SET_XORKEY);
    for (slot, canonical) in CANONICAL_HANDLERS.iter().enumerate() {
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, slot as u32);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, recipe.step);
        program.push(PB_MUL);
        program.push(PB_PUSH_IMM);
        push_u32(&mut program, recipe.base);
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

const fn reference_encoded(slot: u32, recipe: &PermRecipe) -> u8 {
    let computed: u32 = slot
        .wrapping_mul(recipe.step)
        .wrapping_add(recipe.base)
        .wrapping_add(recipe.seed);
    (computed & 0xFF) as u8
}

fn solved_permutation(recipe: &PermRecipe) -> BootstrapKeys {
    let program: Vec<u8> = build_permutation_program(recipe);
    emulate_perm_builder(&program, recipe.seed).expect("emulate the permutation builder")
}

const fn vop_for_index(idx: usize) -> u8 {
    CANONICAL_HANDLERS[idx]
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
            LuaConstant::Nil => body.push(VK_NIL),
            LuaConstant::Bool(b) => {
                body.push(VK_BOOL);
                body.push(u8::from(*b));
            }
            LuaConstant::Number(n) => {
                body.push(VK_NUMBER);
                body.extend_from_slice(&n.to_le_bytes());
            }
            LuaConstant::Integer(i) => {
                body.push(VK_NUMBER);
                body.extend_from_slice(&(*i as f64).to_le_bytes());
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

fn to_lua_decimal_escape(bytes: &[u8]) -> String {
    let mut out: String = String::new();
    for byte in bytes {
        out.push('\\');
        out.push_str(&byte.to_string());
    }
    out
}

fn to_lua_byte_table(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| byte.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

fn render_bootstrap(recipe: &PermRecipe, family_header: &str) -> String {
    let program: Vec<u8> = build_permutation_program(recipe);
    let mut out: String = String::new();
    out.push_str(family_header);
    out.push('\n');
    out.push_str(&format!("SEED={}\n", recipe.seed));
    out.push_str(&format!("PERMBUILD={}\n", to_hex(&program)));
    out
}

fn assert_no_answer_key_in_bootstrap(bootstrap: &str, keys: &BootstrapKeys, xor_key: u8) {
    assert!(
        !bootstrap.contains("OPMAP"),
        "bootstrap must not contain a plaintext opcode table"
    );
    assert!(
        !bootstrap.contains("XORKEY"),
        "bootstrap must not contain a plaintext xor key marker"
    );
    let dec_key: String = format!("{xor_key}");
    assert!(
        !bootstrap.contains(&format!("XORKEY={dec_key}")),
        "bootstrap must not spell out the xor key"
    );
    for (encoded, canonical) in &keys.opmap {
        let pair_decimal: String = format!("[{encoded}]={canonical}");
        assert!(
            !bootstrap.contains(&pair_decimal),
            "bootstrap must not contain the cleartext mapping {pair_decimal}"
        );
    }
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

#[test]
fn devirt_recovers_handlers_and_constants() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x1357_2468,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let report: &DevirtReport = &dv.report;

    assert_eq!(report.kind, VM_KIND_IRONBREW2);
    assert_eq!(report.xor_key, xor_key);
    assert_eq!(
        report.handlers_recovered, report.handlers_total,
        "every distinct VM opcode handler must be mapped to a canonical op"
    );
    assert_eq!(
        report.opcodes_lifted, report.opcodes_total,
        "every VM instruction must lift to a Lua 5.1 instruction"
    );
    assert_eq!(report.constants_decoded, 3);
}

#[test]
fn devirt_recovers_exact_lua51_code_stream() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x0042_0042,
        step: 7,
        base: 0x50,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let proto: &LuaProto = &dv.proto;

    assert_eq!(proto.num_params, module.num_params);
    assert_eq!(proto.is_vararg, module.is_vararg);
    assert_eq!(proto.constants, module.constants);
    assert_eq!(proto.code.len(), module.code.len());

    let getglobal: u32 = proto.code[0];
    assert_eq!(getglobal & 0x3F, 5, "first op must be GETGLOBAL (5)");
    let call: u32 = proto.code[4];
    assert_eq!(call & 0x3F, 28, "fifth op must be CALL (28)");
    let ret: u32 = proto.code[5];
    assert_eq!(ret & 0x3F, 30, "sixth op must be RETURN (30)");
}

#[test]
fn recovered_permutation_is_a_real_permutation_not_identity() {
    let recipe: PermRecipe = PermRecipe {
        seed: 0x1357_2468,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    assert_eq!(
        keys.opmap.len(),
        CANONICAL_HANDLERS.len(),
        "emulation must derive a distinct encoded slot per handler"
    );
    let mut permuted: usize = 0;
    for (idx, canon) in CANONICAL_HANDLERS.iter().enumerate() {
        let encoded: u8 = encoded_for_vop(&keys.opmap, *canon);
        assert_eq!(
            encoded,
            reference_encoded(idx as u32, &recipe),
            "the emulator must reproduce the arithmetic recipe exactly"
        );
        if u32::from(encoded) != u32::from(vop_for_index(idx)) {
            permuted += 1;
        }
    }
    assert!(
        permuted >= 4,
        "the runtime-derived table must genuinely permute the opcodes, not be the identity"
    );
}

#[test]
fn changing_the_seed_changes_what_recovery_yields() {
    let module: VmModule = known_module();
    let base: PermRecipe = PermRecipe {
        seed: 0x1111_2222,
        step: 9,
        base: 0x30,
        key_mask: 0xFF,
    };
    let base_keys: BootstrapKeys = solved_permutation(&base);
    let base_xor: u8 = base_keys.xor_key.expect("xor key");
    let base_payload: Vec<u8> = encode_module(&module, &base_keys.opmap, base_xor);
    let base_boot: String = render_bootstrap(&base, "-- IronBrew2\nIRONBREW_VM");

    let altered: PermRecipe = PermRecipe {
        seed: 0x3333_4444,
        ..base
    };
    let altered_keys: BootstrapKeys = solved_permutation(&altered);
    let altered_boot: String = render_bootstrap(&altered, "-- IronBrew2\nIRONBREW_VM");

    assert_ne!(
        base_keys.opmap, altered_keys.opmap,
        "a different runtime seed must produce a different opcode permutation"
    );

    let with_base_boot: Devirtualized =
        devirtualize(&base_payload, &base_boot).expect("matching seed devirtualizes cleanly");
    assert_eq!(
        with_base_boot.proto.code[0] & 0x3F,
        5,
        "with the correct seed the first op resolves to GETGLOBAL"
    );

    let wrong_seed_result: Result<Devirtualized, _> = devirtualize(&base_payload, &altered_boot);
    match wrong_seed_result {
        Err(_) => {}
        Ok(wrong) => {
            assert_ne!(
                with_base_boot.proto.code, wrong.proto.code,
                "decoding under a table derived from the wrong seed must diverge from the correct decode, proving the seed is load-bearing"
            );
        }
    }
}

#[test]
fn devirt_lifts_to_readable_lua_print_and_arithmetic() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x7F7F_7F7F,
        step: 13,
        base: 0x60,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let dv: Devirtualized = devirtualize(&payload, &bootstrap).expect("devirtualize");
    let lifted: LiftedProto = lift_proto_dialect(&dv.proto, LuaDialect::Lua51, 0);

    assert!(
        lifted.source.contains("print"),
        "recovered lua must call print:\n{}",
        lifted.source
    );
    assert!(
        lifted.source.contains('+'),
        "recovered lua must contain the 40 + 2 addition:\n{}",
        lifted.source
    );
}

#[test]
fn devirt_rejects_payload_without_magic() {
    let recipe: PermRecipe = PermRecipe {
        seed: 1,
        step: 3,
        base: 5,
        key_mask: 0xFF,
    };
    let bogus: Vec<u8> = vec![0u8; 32];
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert!(devirtualize(&bogus, &bootstrap).is_err());
}

#[test]
fn devirt_fails_when_init_program_absent() {
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x2222_3333,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap_without_recipe: &str = "-- IronBrew2\nIRONBREW_VM\nSEED=999\n";
    assert!(
        devirtualize(&payload, bootstrap_without_recipe).is_err(),
        "without the bootstrap init program there is no answer key to read, so devirt must fail rather than guess"
    );
}

#[test]
fn ironbrew2_peel_devirtualizes_embedded_payload() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x4242_4242,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let mut bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);
    bootstrap.push_str(&format!("VMPAYLOAD={} \n", to_hex(&payload)));

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = ironbrew2::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "ironbrew2 peel must fully devirtualize the embedded vm payload; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
    assert!(
        result
            .recovered_strings
            .iter()
            .any(|s: &String| s == "print")
    );
}

#[test]
fn moonsec_v3_peel_devirtualizes_embedded_payload() {
    use disrobe_pass_lua::moonsec_v3;
    use disrobe_pass_lua::obfuscator::vm_devirt::VM_KIND_MOONSEC;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let _ = VM_KIND_MOONSEC;
    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x6B6B_6B6B,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let mut bootstrap: String = render_bootstrap(&recipe, "-- MoonSec v3\nMS_VM_ENTRY");
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);
    bootstrap.push_str(&format!("VMPAYLOAD={} \n", to_hex(&payload)));

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "moonsec v3 peel must fully devirtualize a statically embedded vm payload; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
}

#[test]
fn moonsec_v3_peel_devirtualizes_lua_table_wrapper() {
    use disrobe_pass_lua::moonsec_v3;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let module: VmModule = known_module();
    let recipe: PermRecipe = PermRecipe {
        seed: 0x3C3C_4444,
        step: 13,
        base: 0x50,
        key_mask: 0xFF,
    };
    let program: Vec<u8> = build_permutation_program(&recipe);
    let keys: BootstrapKeys = solved_permutation(&recipe);
    let xor_key: u8 = keys.xor_key.expect("xor key");
    let payload: Vec<u8> = encode_module(&module, &keys.opmap, xor_key);
    let bootstrap: String = format!(
        "-- MoonSec v3\nMS_VM_ENTRY()\nlocal MS_VM_SEED = 0x{:08X}\nlocal MS_VM_BUILDER = {{{}}}\nlocal MS_VM_PAYLOAD = \"{}\"\n",
        recipe.seed,
        to_lua_byte_table(&program),
        to_lua_decimal_escape(&payload)
    );
    assert_no_answer_key_in_bootstrap(&bootstrap, &keys, xor_key);

    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = moonsec_v3::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        result.fully_recovered,
        "moonsec v3 lua table wrapper must fully devirtualize; markers: {:?}",
        result.residual_markers
    );
    let recovered: String = String::from_utf8_lossy(&result.deobfuscated).into_owned();
    assert!(recovered.contains("print"), "recovered:\n{recovered}");
}

#[test]
fn ironbrew2_peel_without_payload_is_honest_passthrough() {
    use disrobe_pass_lua::ironbrew2;
    use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

    let recipe: PermRecipe = PermRecipe {
        seed: 0x1010_1010,
        step: 11,
        base: 0x40,
        key_mask: 0xFF,
    };
    let bootstrap: String = render_bootstrap(&recipe, "-- IronBrew2\nIRONBREW_VM");
    let opts: DeobfOptions = DeobfOptions {
        i_have_authorization: true,
        strict: false,
    };
    let result: PeelResult = ironbrew2::peel(bootstrap.as_bytes(), &opts).expect("peel");
    assert!(
        !result.fully_recovered,
        "no embedded payload means no honest full recovery"
    );
    assert!(!result.residual_markers.is_empty());
}
