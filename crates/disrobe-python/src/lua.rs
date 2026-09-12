use disrobe_pass_lua::{
    DecompiledChunk, DeobfOptions, DetectedFormat, ObfuscatorDetection, PeelResult, decompile_auto,
    detect,
};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use serde::Serialize;

use crate::err::map;
use crate::llm::null_bundled_value;
use crate::typed::{LuaDecompilation, LuaDeobfuscation, LuaDetection};

#[derive(Debug, Clone, Serialize)]
struct LuaDetectReport {
    format: String,
}

#[pyfunction]
#[pyo3(text_signature = "(bytecode)")]
fn lua_detect(bytecode: &[u8]) -> PyResult<LuaDetection> {
    let format: DetectedFormat = detect(bytecode);
    let report: LuaDetectReport = LuaDetectReport {
        format: format_label(format).to_owned(),
    };
    Ok(LuaDetection::from_value(null_bundled_value(&report)?))
}

#[pyfunction]
#[pyo3(text_signature = "(bytecode)")]
fn lua_decompile(bytecode: &[u8]) -> PyResult<LuaDecompilation> {
    let chunk: DecompiledChunk = decompile_auto(bytecode).map_err(map("lua decompile"))?;
    Ok(LuaDecompilation::from_value(null_bundled_value(&chunk)?))
}

#[derive(Debug, Clone, Serialize)]
struct LuaDeobReport {
    obfuscator: String,
    detection: Option<ObfuscatorDetection>,
    deobfuscated: String,
    passes_run: Vec<String>,
    residual_markers: Vec<String>,
    recovered_strings: Vec<String>,
    fully_recovered: bool,
}

#[pyfunction]
#[pyo3(signature = (source, *, authorize = false, strict = false))]
#[pyo3(text_signature = "(source, *, authorize=False, strict=False)")]
fn lua_deobfuscate(source: &str, authorize: bool, strict: bool) -> PyResult<LuaDeobfuscation> {
    let bytes: &[u8] = source.as_bytes();
    let options: DeobfOptions = DeobfOptions {
        i_have_authorization: authorize,
        strict,
    };
    let (kind, detection): (&'static str, Option<ObfuscatorDetection>) = identify(bytes);
    let report: LuaDeobReport = match detection {
        None => LuaDeobReport {
            obfuscator: kind.to_owned(),
            detection: None,
            deobfuscated: source.to_owned(),
            passes_run: Vec::new(),
            residual_markers: Vec::new(),
            recovered_strings: Vec::new(),
            fully_recovered: false,
        },
        Some(detection) => {
            let peeled: PeelResult =
                run_peel(kind, bytes, &options).map_err(map("lua deobfuscate"))?;
            LuaDeobReport {
                obfuscator: kind.to_owned(),
                detection: Some(detection),
                deobfuscated: String::from_utf8_lossy(&peeled.deobfuscated).into_owned(),
                passes_run: peeled.passes_run,
                residual_markers: peeled.residual_markers,
                recovered_strings: peeled.recovered_strings,
                fully_recovered: peeled.fully_recovered,
            }
        }
    };
    Ok(LuaDeobfuscation::from_value(null_bundled_value(&report)?))
}

type DetectFn = fn(&[u8]) -> Option<ObfuscatorDetection>;

fn identify(bytes: &[u8]) -> (&'static str, Option<ObfuscatorDetection>) {
    use disrobe_pass_lua::{
        aztup_brew, boronide, darksec, ironbrew2, luaobfuscator_com, moonsec_v1, moonsec_v2,
        moonsec_v3, prometheus, psu, wearedevs,
    };
    let probes: [(&'static str, DetectFn); 11] = [
        ("prometheus", prometheus::detect),
        ("moonsec_v3", moonsec_v3::detect),
        ("moonsec_v2", moonsec_v2::detect),
        ("moonsec_v1", moonsec_v1::detect),
        ("ironbrew2", ironbrew2::detect),
        ("aztup_brew", aztup_brew::detect),
        ("darksec", darksec::detect),
        ("boronide", boronide::detect),
        ("psu", psu::detect),
        ("wearedevs", wearedevs::detect),
        ("luaobfuscator_com", luaobfuscator_com::detect),
    ];
    for (label, probe) in probes {
        if let Some(detection) = probe(bytes) {
            return (label, Some(detection));
        }
    }
    ("none", None)
}

fn run_peel(
    kind: &str,
    bytes: &[u8],
    options: &DeobfOptions,
) -> disrobe_pass_lua::Result<PeelResult> {
    use disrobe_pass_lua::{
        aztup_brew, boronide, darksec, ironbrew2, luaobfuscator_com, moonsec_v1, moonsec_v2,
        moonsec_v3, prometheus, psu, wearedevs,
    };
    match kind {
        "moonsec_v3" => moonsec_v3::peel(bytes, options),
        "moonsec_v2" => moonsec_v2::peel(bytes, options),
        "moonsec_v1" => moonsec_v1::peel(bytes, options),
        "ironbrew2" => ironbrew2::peel(bytes, options),
        "aztup_brew" => aztup_brew::peel(bytes, options),
        "darksec" => darksec::peel(bytes, options),
        "boronide" => boronide::peel(bytes, options),
        "psu" => psu::peel(bytes, options),
        "wearedevs" => wearedevs::peel(bytes, options),
        "luaobfuscator_com" => luaobfuscator_com::peel(bytes, options),
        _ => prometheus::peel(bytes, options),
    }
}

const fn format_label(format: DetectedFormat) -> &'static str {
    match format {
        DetectedFormat::Lua51 => "lua-5.1",
        DetectedFormat::Lua52 => "lua-5.2",
        DetectedFormat::Lua53 => "lua-5.3",
        DetectedFormat::Lua54 => "lua-5.4",
        DetectedFormat::LuaJit => "luajit",
        DetectedFormat::Luau => "luau",
        DetectedFormat::GLua => "glua",
        DetectedFormat::Unknown => "unknown",
    }
}

pub(crate) fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(lua_detect, m)?)?;
    m.add_function(wrap_pyfunction!(lua_decompile, m)?)?;
    m.add_function(wrap_pyfunction!(lua_deobfuscate, m)?)?;
    Ok(())
}
