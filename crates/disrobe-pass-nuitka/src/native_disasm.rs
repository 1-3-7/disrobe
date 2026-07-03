use std::fs::File;
use std::io::{BufWriter, Write as _};
use std::path::Path;

use disrobe_core::debug::DebugLog;
use disrobe_pass_native::{
    StreamDisasmLimits, StreamDisasmStats, stream_disasm_x86, text_section_window,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeDisasm {
    pub module_name: String,
    pub instruction_count: u64,
    pub function_count: u64,
    pub text_bytes: usize,
    pub truncated: bool,
}

impl NativeDisasm {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instruction_count == 0
    }
}

fn header(module_name: &str, text_len: usize, bits: u32) -> String {
    format!(
        "; module: {module_name}\n; native disassembly recovered from the compiled image .text (Nuitka emits machine code; no source .c exists)\n; arch: x86-{bits}, .text size: {text_len} bytes\n; streamed instruction-by-instruction with a bounded decode window; see the trailer for any truncation\n\n"
    )
}

/// Disassemble the compiled image's `.text` straight to `out_path`, streaming one instruction at a time through a `BufWriter`.
pub fn disassemble_module_to_file(
    module_name: &str,
    image: &[u8],
    out_path: &Path,
) -> Option<NativeDisasm> {
    let dbg: DebugLog = DebugLog::for_scope("nuitka");
    dbg.section("native-disasm");
    let (address, bits, text): (u64, u32, &[u8]) = text_section_window(image)?;
    if text.is_empty() {
        return None;
    }

    let file: File = match File::create(out_path) {
        Ok(file) => file,
        Err(e) => {
            dbg.line(|| {
                format!(
                    "native disasm of {module_name}: cannot create {}: {e}",
                    out_path.display()
                )
            });
            return None;
        }
    };
    let mut writer: BufWriter<File> = BufWriter::new(file);
    if writer
        .write_all(header(module_name, text.len(), bits).as_bytes())
        .is_err()
    {
        return None;
    }

    let limits: StreamDisasmLimits = StreamDisasmLimits::default();
    let stats: StreamDisasmStats = match stream_disasm_x86(&mut writer, text, address, bits, limits)
    {
        Ok(stats) => stats,
        Err(e) => {
            dbg.line(|| format!("native disasm of {module_name} stream failed: {e}"));
            return None;
        }
    };

    if stats.truncated {
        let note: String = format!(
            "\n; ... truncated: decoded {} of {} .text bytes / {} instructions at the bounded-work limit\n",
            stats.bytes_decoded,
            text.len(),
            stats.instruction_count
        );
        if writer.write_all(note.as_bytes()).is_err() {
            return None;
        }
    }
    if writer.flush().is_err() {
        return None;
    }

    dbg.kv("instructions", || stats.instruction_count.to_string());
    dbg.kv("functions", || stats.function_count.to_string());
    if stats.instruction_count == 0 {
        return None;
    }
    Some(NativeDisasm {
        module_name: module_name.to_owned(),
        instruction_count: stats.instruction_count,
        function_count: stats.function_count,
        text_bytes: stats.bytes_decoded,
        truncated: stats.truncated,
    })
}

/// Stream the bounded disassembly into an in-memory buffer, for the chain (which hands child bytes to the driver to write).
#[must_use]
pub fn disassemble_module_to_vec(
    module_name: &str,
    image: &[u8],
) -> Option<(NativeDisasm, Vec<u8>)> {
    let (address, bits, text): (u64, u32, &[u8]) = text_section_window(image)?;
    if text.is_empty() {
        return None;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 16);
    buf.extend_from_slice(header(module_name, text.len(), bits).as_bytes());
    let stats: StreamDisasmStats =
        stream_disasm_x86(&mut buf, text, address, bits, StreamDisasmLimits::default()).ok()?;
    if stats.instruction_count == 0 {
        return None;
    }
    if stats.truncated {
        buf.extend_from_slice(
            format!(
                "\n; ... truncated: decoded {} of {} .text bytes / {} instructions at the bounded-work limit\n",
                stats.bytes_decoded,
                text.len(),
                stats.instruction_count
            )
            .as_bytes(),
        );
    }
    let disasm: NativeDisasm = NativeDisasm {
        module_name: module_name.to_owned(),
        instruction_count: stats.instruction_count,
        function_count: stats.function_count,
        text_bytes: stats.bytes_decoded,
        truncated: stats.truncated,
    };
    Some((disasm, buf))
}

/// Recover the same bounded stats as [`disassemble_module_to_file`] without writing a file.
#[must_use]
pub fn disassemble_module_stats(module_name: &str, image: &[u8]) -> Option<NativeDisasm> {
    let (address, bits, text): (u64, u32, &[u8]) = text_section_window(image)?;
    if text.is_empty() {
        return None;
    }
    let mut sink: std::io::Sink = std::io::sink();
    let stats: StreamDisasmStats = stream_disasm_x86(
        &mut sink,
        text,
        address,
        bits,
        StreamDisasmLimits::default(),
    )
    .ok()?;
    if stats.instruction_count == 0 {
        return None;
    }
    Some(NativeDisasm {
        module_name: module_name.to_owned(),
        instruction_count: stats.instruction_count,
        function_count: stats.function_count,
        text_bytes: stats.bytes_decoded,
        truncated: stats.truncated,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn corpus_standalone() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka/real/sample_app-standalone.exe")
    }

    #[test]
    fn streams_real_standalone_text_to_file() {
        let path: std::path::PathBuf = corpus_standalone();
        if !path.is_file() {
            eprintln!("skipping: real nuitka corpus exe absent");
            return;
        }
        let image: Vec<u8> = std::fs::read(&path).expect("read corpus exe");
        let out_path: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-nuitka-disasm-{}.asm", std::process::id()));
        let disasm: NativeDisasm =
            disassemble_module_to_file("sample_app", &image, &out_path).expect("native disasm");
        assert!(
            disasm.instruction_count > 100,
            "expected real disassembly, got {} instructions",
            disasm.instruction_count
        );
        assert!(disasm.function_count > 0);
        let asm: String = std::fs::read_to_string(&out_path).expect("read asm");
        let has_real_mnemonic: bool = ["mov", "push", "call", "ret", "lea", "jmp"]
            .iter()
            .any(|m: &&str| asm.contains(*m));
        assert!(has_real_mnemonic, "asm must contain real x86 mnemonics");
        let _ = std::fs::remove_file(&out_path);
    }
}
