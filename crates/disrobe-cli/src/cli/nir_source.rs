use std::path::Path;

use disrobe_core::Rung;
use disrobe_ir::Envelope;
use disrobe_ir::payload::{DisasmPayload, decode_disasm};
use disrobe_nir::{NirModule, decode_nir};
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::disasm_to_nir;

pub(crate) fn lift_module_from_bytes(input: &Path, bytes: &[u8]) -> miette::Result<NirModule> {
    if let Ok(env) = Envelope::decode(bytes) {
        return module_from_envelope(&env, input);
    }
    if let Some(module) = lift_front_end(bytes) {
        return Ok(module);
    }
    let payload: DisasmPayload = build_disasm_payload(bytes).map_err(|e| {
        miette::miette!(
            "DR-CLI-0851: {} is not a .dr envelope, a lift-supported source format (wasm/jvm/dex/pyc), nor a disassemblable native binary: {e}",
            input.display()
        )
    })?;
    Ok(disasm_to_nir(&payload))
}

fn module_from_envelope(env: &Envelope, input: &Path) -> miette::Result<NirModule> {
    match env.rung {
        Rung::Mir => decode_nir(&env.hot).map_err(|e| {
            miette::miette!(
                "DR-CLI-0852: {} is a Mir-rung .dr envelope but the NIR payload did not decode: {e}",
                input.display()
            )
        }),
        Rung::Disasm => {
            let payload: DisasmPayload = decode_disasm(&env.hot).map_err(|e| {
                miette::miette!(
                    "DR-CLI-0853: {} is a Disasm-rung .dr envelope but the payload did not decode: {e}",
                    input.display()
                )
            })?;
            Ok(disasm_to_nir(&payload))
        }
        other => Err(miette::miette!(
            "DR-CLI-0854: {} is a {other:?}-rung .dr envelope; the Mir-rung analyses need a Disasm- or Mir-rung envelope or a source format the lifters accept",
            input.display()
        )),
    }
}

#[cfg(any(
    feature = "as3",
    feature = "beam",
    feature = "dotnet",
    feature = "jvm",
    feature = "lua",
    feature = "ruby",
    feature = "wasm",
    all(feature = "py", feature = "nir-lift")
))]
fn lift_front_end(bytes: &[u8]) -> Option<NirModule> {
    #[cfg(feature = "wasm")]
    if bytes.len() >= 4 && bytes[..4] == [0x00, 0x61, 0x73, 0x6d] {
        return disrobe_nir_lift::lift_wasm_module(bytes).ok();
    }
    #[cfg(feature = "jvm")]
    if bytes.len() >= 4 && bytes[..4] == [0xca, 0xfe, 0xba, 0xbe] {
        return disrobe_nir_lift::lift_classfile(bytes).ok();
    }
    #[cfg(feature = "jvm")]
    if bytes.len() >= 8 && bytes[..4] == [b'd', b'e', b'x', b'\n'] && bytes[7] == 0 {
        return disrobe_nir_lift::lift_dex(bytes).ok();
    }
    #[cfg(feature = "dotnet")]
    if bytes.len() >= 2 && bytes[..2] == [b'M', b'Z'] && is_managed_pe(bytes) {
        return disrobe_nir_lift::lift_dotnet_pe(bytes).ok();
    }
    #[cfg(feature = "as3")]
    if is_swf(bytes) {
        return disrobe_nir_lift::lift_swf_abc(bytes).ok();
    }
    #[cfg(feature = "as3")]
    if is_raw_abc(bytes) {
        return disrobe_nir_lift::lift_abc(bytes).ok();
    }
    #[cfg(feature = "ruby")]
    if bytes.len() >= 4 && bytes[..4] == [b'Y', b'A', b'R', b'B'] {
        return disrobe_nir_lift::lift_ruby_iseq(bytes).ok();
    }
    #[cfg(feature = "lua")]
    if bytes.len() >= 4 && bytes[..4] == [0x1B, b'L', b'u', b'a'] {
        return disrobe_nir_lift::lift_lua_chunk(bytes).ok();
    }
    #[cfg(feature = "beam")]
    if bytes.len() >= 12
        && bytes[..4] == [b'F', b'O', b'R', b'1']
        && bytes[8..12] == [b'B', b'E', b'A', b'M']
    {
        return disrobe_nir_lift::lift_beam_module(bytes).ok();
    }
    #[cfg(all(feature = "py", feature = "nir-lift"))]
    if is_pyc(bytes) {
        return disrobe_nir_lift::lift_pyc(bytes).ok();
    }
    None
}

#[cfg(not(any(
    feature = "as3",
    feature = "beam",
    feature = "dotnet",
    feature = "jvm",
    feature = "lua",
    feature = "ruby",
    feature = "wasm",
    all(feature = "py", feature = "nir-lift")
)))]
const fn lift_front_end(_bytes: &[u8]) -> Option<NirModule> {
    None
}

#[cfg(all(feature = "py", feature = "nir-lift"))]
const fn is_pyc(bytes: &[u8]) -> bool {
    let Some(magic): Option<&[u8; 4]> = bytes.first_chunk::<4>() else {
        return false;
    };
    disrobe_py_marshal::pyversion_from_magic(u32::from_le_bytes(*magic)).is_some()
}

#[cfg(feature = "as3")]
fn is_swf(bytes: &[u8]) -> bool {
    bytes.len() >= 3 && matches!(&bytes[..3], b"FWS" | b"CWS" | b"ZWS")
}

#[cfg(feature = "as3")]
fn is_raw_abc(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == [0x10, 0x00, 0x2E, 0x00]
}

#[cfg(feature = "dotnet")]
fn is_managed_pe(bytes: &[u8]) -> bool {
    disrobe_pass_dotnet::parse(bytes)
        .ok()
        .and_then(|pe| disrobe_pass_dotnet::parse_clr_header(bytes, &pe).ok())
        .is_some()
}
