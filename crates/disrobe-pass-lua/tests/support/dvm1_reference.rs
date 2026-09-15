use std::collections::BTreeMap;
use std::fmt::Write as _;

use disrobe_pass_lua::obfuscator::vm_devirt::{
    BUILDER_MAGIC, BootstrapKeys, PB_ADD, PB_AND, PB_EMIT_MAP, PB_HALT, PB_MUL, PB_PUSH_IMM,
    PB_PUSH_SEED, PB_SET_XORKEY, VM_KIND_IRONBREW2, VM_MAGIC, VOP_ADD, VOP_CALL, VOP_GETGLOBAL,
    VOP_LOADK, VOP_MOVE, VOP_RETURN, emulate_perm_builder,
};
use disrobe_pass_lua::reader::common::LuaConstant;

pub(crate) const VK_NIL: u8 = 0;
pub(crate) const VK_BOOL: u8 = 1;
pub(crate) const VK_NUMBER: u8 = 3;
pub(crate) const VK_STRING: u8 = 4;

pub(crate) const CANONICAL_HANDLERS: [u8; 6] = [
    VOP_MOVE,
    VOP_LOADK,
    VOP_GETGLOBAL,
    VOP_ADD,
    VOP_CALL,
    VOP_RETURN,
];

pub(crate) const KNOWN_MODULE_STDOUT: &str = "42";

#[derive(Debug, Clone, Copy)]
pub(crate) struct PermRecipe {
    pub(crate) seed: u32,
    pub(crate) step: u32,
    pub(crate) base: u32,
    pub(crate) key_mask: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VmInsn {
    pub(crate) vop: u8,
    pub(crate) a: u32,
    pub(crate) b: u32,
    pub(crate) c: u32,
}

#[derive(Debug, Clone)]
pub(crate) struct VmModule {
    pub(crate) max_stack: u8,
    pub(crate) num_params: u8,
    pub(crate) is_vararg: u8,
    pub(crate) constants: Vec<LuaConstant>,
    pub(crate) code: Vec<VmInsn>,
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

pub(crate) fn build_permutation_program(recipe: &PermRecipe) -> Vec<u8> {
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

pub(crate) const fn reference_encoded(slot: u32, recipe: &PermRecipe) -> u8 {
    let computed: u32 = slot
        .wrapping_mul(recipe.step)
        .wrapping_add(recipe.base)
        .wrapping_add(recipe.seed);
    (computed & 0xFF) as u8
}

pub(crate) const fn vop_for_index(idx: usize) -> u8 {
    CANONICAL_HANDLERS[idx]
}

pub(crate) fn solved_permutation(recipe: &PermRecipe) -> BootstrapKeys {
    let program: Vec<u8> = build_permutation_program(recipe);
    emulate_perm_builder(&program, recipe.seed).expect("emulate the permutation builder")
}

pub(crate) fn encoded_for_vop(opmap: &BTreeMap<u8, u8>, vop: u8) -> u8 {
    opmap
        .iter()
        .find(|(_, mapped): &(&u8, &u8)| **mapped == vop)
        .map(|(encoded, _): (&u8, &u8)| *encoded)
        .expect("canonical op present in solved permutation")
}

pub(crate) fn known_module() -> VmModule {
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

pub(crate) fn encode_module(module: &VmModule, opmap: &BTreeMap<u8, u8>, xor_key: u8) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.push(module.max_stack);
    body.push(module.num_params);
    body.push(module.is_vararg);
    push_u32(&mut body, module.constants.len() as u32);
    for constant in &module.constants {
        match constant {
            LuaConstant::Nil => body.push(VK_NIL),
            LuaConstant::Bool(flag) => {
                body.push(VK_BOOL);
                body.push(u8::from(*flag));
            }
            LuaConstant::Number(number) => {
                body.push(VK_NUMBER);
                body.extend_from_slice(&number.to_le_bytes());
            }
            LuaConstant::Integer(integer) => {
                body.push(VK_NUMBER);
                body.extend_from_slice(&(*integer as f64).to_le_bytes());
            }
            LuaConstant::Str(text) => {
                body.push(VK_STRING);
                push_u32(&mut body, text.len() as u32);
                body.extend_from_slice(text.as_bytes());
            }
            other => panic!("unsupported constant in the reference encoder: {other:?}"),
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

pub(crate) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut acc: String, byte: &u8| {
            let _ = write!(acc, "{byte:02x}");
            acc
        },
    )
}

pub(crate) fn to_lua_decimal_escape(bytes: &[u8]) -> String {
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 4),
        |mut acc: String, byte: &u8| {
            acc.push('\\');
            acc.push_str(&byte.to_string());
            acc
        },
    )
}

pub(crate) fn to_lua_byte_table(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte: &u8| byte.to_string())
        .collect::<Vec<String>>()
        .join(",")
}

pub(crate) fn render_bootstrap(recipe: &PermRecipe, family_header: &str) -> String {
    let program: Vec<u8> = build_permutation_program(recipe);
    let mut out: String = String::new();
    out.push_str(family_header);
    out.push('\n');
    let _ = writeln!(out, "SEED={}", recipe.seed);
    let _ = writeln!(out, "PERMBUILD={}", to_hex(&program));
    out
}

pub(crate) fn bootstrap_with_payload(header: &str, recipe: &PermRecipe) -> (String, Vec<u8>) {
    let keys: BootstrapKeys = solved_permutation(recipe);
    let xor_key: u8 = keys.xor_key.expect("the recipe sets the xor key");
    let payload: Vec<u8> = encode_module(&known_module(), &keys.opmap, xor_key);
    let mut boot: String = render_bootstrap(recipe, header);
    let _ = writeln!(boot, "VMPAYLOAD={} ", to_hex(&payload));
    (boot, payload)
}

pub(crate) fn assert_no_answer_key_in_bootstrap(
    bootstrap: &str,
    keys: &BootstrapKeys,
    xor_key: u8,
) {
    assert!(
        !bootstrap.contains("OPMAP"),
        "bootstrap must not contain a plaintext opcode table"
    );
    assert!(
        !bootstrap.contains("XORKEY"),
        "bootstrap must not contain a plaintext xor key marker"
    );
    assert!(
        !bootstrap.contains(&format!("XORKEY={xor_key}")),
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
