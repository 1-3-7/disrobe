use crate::alt_runtimes::micropython::{
    MpyBytecodeModule, count_instructions, parse_bytecode, render as render_mpy,
};
use crate::alt_runtimes::micropython_native::{
    MicroPythonNativeModule, NativeFunction, count_functions, total_instructions,
};
use crate::alt_runtimes::pypy::{PyPyDisasm, parse as parse_pypy};
use crate::alt_runtimes::{AltRuntime, detect_runtime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AltRecovery {
    pub runtime: AltRuntime,
    pub label: &'static str,
    pub disasm_text: String,
    pub instruction_count: usize,
    pub source: Option<RecoveredSource>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredSource {
    pub language: SourceLanguage,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    Java,
    CSharp,
}

impl SourceLanguage {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::CSharp => "csharp",
        }
    }
}

#[must_use]
pub const fn alt_label(runtime: AltRuntime) -> &'static str {
    match runtime {
        AltRuntime::PyPy => "pypy",
        AltRuntime::MicroPython => "micropython",
        AltRuntime::MicroPythonNative => "micropython-native",
        AltRuntime::Jython => "jython",
        AltRuntime::IronPython => "ironpython",
        AltRuntime::Brython => "brython",
    }
}

#[must_use]
pub fn recover(bytes: &[u8], runtime: AltRuntime) -> AltRecovery {
    let label: &'static str = alt_label(runtime);
    if crate::debug::dbg_enabled() {
        crate::debug::dbg_kv("alt-runtime", || {
            format!("{label} payload={} bytes", bytes.len())
        });
    }
    match runtime {
        AltRuntime::MicroPythonNative => match super::micropython_native::parse(bytes) {
            Ok(module) => {
                let (text, count): (String, usize) = render_micropython_native(&module);
                disasm_only(runtime, label, text, count)
            }
            Err(e) => walled(runtime, label, &format!("native mpy parse failed: {e}")),
        },
        AltRuntime::MicroPython => match parse_bytecode(bytes) {
            Ok(module) => recover_micropython(runtime, label, &module),
            Err(e) => walled(runtime, label, &format!("mpy bytecode parse failed: {e}")),
        },
        AltRuntime::PyPy => match parse_pypy(bytes) {
            Ok(module) => {
                let disasm: PyPyDisasm = module.disassemble();
                let count: usize = disasm.instruction_count;
                disasm_only(runtime, label, PyPyDisasm::render(&disasm), count)
            }
            Err(e) => walled(runtime, label, &format!("pypy payload decode failed: {e}")),
        },
        AltRuntime::Jython => recover_jython(runtime, label, bytes),
        AltRuntime::IronPython => recover_ironpython(runtime, label, bytes),
        AltRuntime::Brython => recover_brython(runtime, label, bytes),
    }
}

#[must_use]
pub fn recover_detected(bytes: &[u8]) -> Option<AltRecovery> {
    detect_runtime(bytes).map(|rt: AltRuntime| recover(bytes, rt))
}

const fn disasm_only(
    runtime: AltRuntime,
    label: &'static str,
    disasm_text: String,
    instruction_count: usize,
) -> AltRecovery {
    AltRecovery {
        runtime,
        label,
        disasm_text,
        instruction_count,
        source: None,
    }
}

fn walled(runtime: AltRuntime, label: &'static str, reason: &str) -> AltRecovery {
    AltRecovery {
        runtime,
        label,
        disasm_text: format!("; alt-runtime {label} detected; {reason}\n"),
        instruction_count: 0usize,
        source: None,
    }
}

fn recover_micropython(
    runtime: AltRuntime,
    label: &'static str,
    module: &MpyBytecodeModule,
) -> AltRecovery {
    let count: usize = count_instructions(&module.function);
    disasm_only(runtime, label, render_mpy(module), count)
}

#[cfg(feature = "alt-runtimes-native")]
fn recover_jython(runtime: AltRuntime, label: &'static str, bytes: &[u8]) -> AltRecovery {
    let disasm_text: String = match super::jython::analyze(bytes) {
        Ok(analysis) => render_jython_analysis(&analysis),
        Err(e) => format!("; alt-runtime {label} classfile analysis failed: {e}\n"),
    };
    let source: Option<RecoveredSource> = disrobe_pass_jvm::decompile_classfile_bytes(bytes)
        .ok()
        .map(|class: disrobe_pass_jvm::DecompiledClass| RecoveredSource {
            language: SourceLanguage::Java,
            text: class.source,
        });
    let instruction_count: usize = source.is_some().into();
    AltRecovery {
        runtime,
        label,
        disasm_text,
        instruction_count,
        source,
    }
}

#[cfg(not(feature = "alt-runtimes-native"))]
fn recover_jython(runtime: AltRuntime, label: &'static str, _bytes: &[u8]) -> AltRecovery {
    walled(
        runtime,
        label,
        "jvm classfile routing requires the alt-runtimes-native feature",
    )
}

#[cfg(feature = "alt-runtimes-native")]
fn recover_ironpython(runtime: AltRuntime, label: &'static str, bytes: &[u8]) -> AltRecovery {
    let disasm_text: String = match super::ironpython::analyze(bytes) {
        Ok(analysis) => render_ironpython_analysis(&analysis),
        Err(e) => format!("; alt-runtime {label} assembly analysis failed: {e}\n"),
    };
    let source: Option<RecoveredSource> = disrobe_pass_dotnet::decompile_assembly(bytes).ok().map(
        |assembly: disrobe_pass_dotnet::DecompiledAssembly| RecoveredSource {
            language: SourceLanguage::CSharp,
            text: render_dotnet_assembly(&assembly),
        },
    );
    let instruction_count: usize = source.is_some().into();
    AltRecovery {
        runtime,
        label,
        disasm_text,
        instruction_count,
        source,
    }
}

#[cfg(not(feature = "alt-runtimes-native"))]
fn recover_ironpython(runtime: AltRuntime, label: &'static str, _bytes: &[u8]) -> AltRecovery {
    walled(
        runtime,
        label,
        "dotnet assembly routing requires the alt-runtimes-native feature",
    )
}

#[cfg(feature = "alt-runtimes-native")]
fn recover_brython(runtime: AltRuntime, label: &'static str, bytes: &[u8]) -> AltRecovery {
    match super::brython::handoff(bytes) {
        Ok(handoff) => {
            let mut text: String = String::new();
            crate::push_string_line(
                &mut text,
                format_args!(
                    "; alt-runtime brython detected; js-deob handoff family={} confidence={}%",
                    handoff.family, handoff.confidence_pct
                ),
            );
            crate::push_string_line(
                &mut text,
                format_args!("; brython markers: {}", handoff.brython_markers.join(", ")),
            );
            crate::push_string_line(
                &mut text,
                format_args!(
                    "; source span {} bytes routed to disrobe-pass-js-deob for embedded-module recovery",
                    handoff.source_len
                ),
            );
            disasm_only(runtime, label, text, 0)
        }
        Err(e) => walled(runtime, label, &format!("brython handoff failed: {e}")),
    }
}

#[cfg(not(feature = "alt-runtimes-native"))]
fn recover_brython(runtime: AltRuntime, label: &'static str, _bytes: &[u8]) -> AltRecovery {
    walled(
        runtime,
        label,
        "brython js-deob routing requires the alt-runtimes-native feature",
    )
}

#[cfg(feature = "alt-runtimes-native")]
fn render_jython_analysis(analysis: &super::jython::JvmAnalysis) -> String {
    let mut out: String = String::new();
    let version: String = analysis.java_version.map_or_else(
        || "unknown".to_owned(),
        |v: disrobe_pass_jvm::JavaVersion| format!("{v:?}"),
    );
    crate::push_string_line(
        &mut out,
        format_args!(
            "; jython classfile {} extends {} (java {version})",
            analysis.this_class, analysis.super_class
        ),
    );
    crate::push_string_line(
        &mut out,
        format_args!(
            "; {} method(s), {} field(s), constant pool {}, jython-generated={}",
            analysis.method_count,
            analysis.field_count,
            analysis.constant_pool_size,
            analysis.is_jython_generated
        ),
    );
    if !analysis.markers.is_empty() {
        crate::push_string_line(
            &mut out,
            format_args!("; markers: {}", analysis.markers.join(", ")),
        );
    }
    out
}

#[cfg(feature = "alt-runtimes-native")]
fn render_ironpython_analysis(analysis: &super::ironpython::DotnetAnalysis) -> String {
    let mut out: String = String::new();
    crate::push_string_line(
        &mut out,
        format_args!(
            "; ironpython assembly ({}, clr {}, runtime {:?})",
            analysis.pe_bitness, analysis.clr_runtime_version, analysis.runtime_label
        ),
    );
    crate::push_string_line(
        &mut out,
        format_args!("; metadata streams: {}", analysis.stream_names.join(", ")),
    );
    crate::push_string_line(
        &mut out,
        format_args!("; ironpython-marked={}", analysis.is_ironpython),
    );
    if !analysis.markers.is_empty() {
        crate::push_string_line(
            &mut out,
            format_args!("; markers: {}", analysis.markers.join(", ")),
        );
    }
    out
}

#[cfg(feature = "alt-runtimes-native")]
fn render_dotnet_assembly(assembly: &disrobe_pass_dotnet::DecompiledAssembly) -> String {
    let mut out: String = String::new();
    crate::push_string_line(
        &mut out,
        format_args!(
            "// module {} ({} method(s) recovered, {} bodyless, {} failed)",
            assembly.module_name,
            assembly.methods_decompiled,
            assembly.methods_bodyless,
            assembly.methods_failed
        ),
    );
    for method in &assembly.methods {
        out.push('\n');
        out.push_str(&method.body);
    }
    out
}

fn render_micropython_native(module: &MicroPythonNativeModule) -> (String, usize) {
    let mut out: String = String::new();
    crate::push_string_line(
        &mut out,
        format_args!(
            "; micropython native module (mpy v{}, arch {}, {} function(s))",
            module.version,
            module.arch.label(),
            count_functions(&module.function),
        ),
    );
    walk_native_function(&mut out, &module.function, "<module>", 0);
    (out, total_instructions(&module.function))
}

fn walk_native_function(out: &mut String, func: &NativeFunction, name: &str, depth: usize) {
    let indent: String = "  ".repeat(depth);
    crate::push_string_line(
        out,
        format_args!(
            "\n{indent}; function {name} [{}] machine_code={} bytes",
            func.kind.label(),
            func.machine_code.len(),
        ),
    );
    if let Some(note) = func.disasm_note.as_ref() {
        crate::push_string_line(out, format_args!("{indent};   note: {note}"));
    }
    for insn in &func.disassembly {
        let hex: String = hex_lower(&insn.bytes);
        if insn.operands.is_empty() {
            crate::push_string_line(
                out,
                format_args!(
                    "{indent}  {:>6x}: {hex:<16} {}",
                    insn.address, insn.mnemonic
                ),
            );
        } else {
            crate::push_string_line(
                out,
                format_args!(
                    "{indent}  {:>6x}: {hex:<16} {} {}",
                    insn.address, insn.mnemonic, insn.operands
                ),
            );
        }
    }
    for (i, child) in func.children.iter().enumerate() {
        let child_name: String = format!("{name}.child{i}");
        walk_native_function(out, child, &child_name, depth + 1);
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter().copied() {
        out.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        out.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const X64_NATIVE: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy");

    #[test]
    fn recover_native_mpy_emits_real_instructions() {
        let recovery: AltRecovery = recover(X64_NATIVE, AltRuntime::MicroPythonNative);
        assert_eq!(recovery.label, "micropython-native");
        assert!(
            recovery.instruction_count > 0,
            "native mpy must recover machine instructions"
        );
        assert!(recovery.disasm_text.contains("push"));
    }

    #[test]
    fn recover_detected_routes_native() {
        let recovery: AltRecovery = recover_detected(X64_NATIVE).expect("detected");
        assert_eq!(recovery.runtime, AltRuntime::MicroPythonNative);
        assert!(recovery.instruction_count > 0);
    }

    const MPY_BYTECODE: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");

    #[test]
    fn recover_micropython_bytecode_emits_opcodes() {
        let recovery: AltRecovery = recover_detected(MPY_BYTECODE).expect("detected");
        assert_eq!(recovery.runtime, AltRuntime::MicroPython);
        assert!(recovery.instruction_count > 0);
        assert!(recovery.disasm_text.contains("BINARY_OP"));
        assert!(recovery.disasm_text.contains("RETURN_VALUE"));
        assert!(recovery.source.is_none());
    }

    #[cfg(feature = "alt-runtimes-native")]
    const JYTHON_CLASS: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/jython/greet_mod$py.class");
    #[cfg(feature = "alt-runtimes-native")]
    const IRONPYTHON_DLL: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/ironpython/greet_ip.dll");
    #[cfg(feature = "alt-runtimes-native")]
    const BRYTHON_JS: &[u8] =
        include_bytes!("../../../../corpus/python/alt_runtimes/brython/hello.brython.js");

    #[cfg(feature = "alt-runtimes-native")]
    #[test]
    fn recover_jython_emits_java_source() {
        let recovery: AltRecovery = recover_detected(JYTHON_CLASS).expect("detected jython");
        assert_eq!(recovery.runtime, AltRuntime::Jython);
        assert!(recovery.disasm_text.contains("org/python"));
        let source: &RecoveredSource = recovery.source.as_ref().expect("java source recovered");
        assert_eq!(source.language, SourceLanguage::Java);
        assert!(!source.text.is_empty());
        assert!(source.text.contains("class"));
    }

    #[cfg(feature = "alt-runtimes-native")]
    #[test]
    fn recover_ironpython_emits_csharp_source() {
        let recovery: AltRecovery = recover_detected(IRONPYTHON_DLL).expect("detected ironpython");
        assert_eq!(recovery.runtime, AltRuntime::IronPython);
        assert!(recovery.disasm_text.contains("ironpython"));
        let source: &RecoveredSource = recovery.source.as_ref().expect("csharp source recovered");
        assert_eq!(source.language, SourceLanguage::CSharp);
        assert!(source.text.contains("Greet") || source.text.contains("module"));
    }

    #[cfg(feature = "alt-runtimes-native")]
    #[test]
    fn recover_brython_routes_to_js_deob() {
        let recovery: AltRecovery = recover_detected(BRYTHON_JS).expect("detected brython");
        assert_eq!(recovery.runtime, AltRuntime::Brython);
        assert!(recovery.disasm_text.contains("js-deob handoff"));
        assert!(recovery.disasm_text.contains("__BRYTHON__"));
    }
}
