use disrobe_core::recon::{ReconConfig, ReconReport, report_bytes};
use disrobe_pass_native::{
    StreamDisasmLimits, StreamDisasmStats, stream_disasm_x86, text_section_window,
};

const MAX_DEEP_ANALYZE_BYTES: usize = 16 * 1024 * 1024;

const RUNTIME_LIB_PREFIXES: [&str; 8] = [
    "python",
    "vcruntime",
    "libcrypto",
    "libssl",
    "libffi",
    "api-ms",
    "msvcp",
    "ucrtbase",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeArtifact {
    pub relative_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NativeSurfaceStats {
    pub modules_disassembled: usize,
    pub instructions: u64,
    pub functions: u64,
}

impl NativeSurfaceStats {
    pub const fn accumulate(&mut self, other: Self) {
        self.modules_disassembled += other.modules_disassembled;
        self.instructions += other.instructions;
        self.functions += other.functions;
    }
}

#[must_use]
pub fn surface_native_entry(name: &str, data: &[u8]) -> (Vec<NativeArtifact>, NativeSurfaceStats) {
    let mut out: Vec<NativeArtifact> = Vec::new();
    let mut stats: NativeSurfaceStats = NativeSurfaceStats::default();
    let stem: String = sanitize_component(name);

    let config: ReconConfig = ReconConfig::default();
    let report: ReconReport = report_bytes(data, Some(name), &config);
    if !report.findings.is_empty()
        && let Ok(json) = serde_json::to_vec_pretty(&report)
    {
        out.push(NativeArtifact {
            relative_path: format!("native/{stem}.recon.json"),
            bytes: json,
        });
    }

    let deep_eligible: bool = data.len() <= MAX_DEEP_ANALYZE_BYTES && !is_runtime_lib(name);
    if deep_eligible
        && let Ok(report) = disrobe_capabilities::analyze(data)
        && let Ok(json) = serde_json::to_vec_pretty(&report)
    {
        out.push(NativeArtifact {
            relative_path: format!("native/{stem}.capabilities.json"),
            bytes: json,
        });
    }

    if let Some((asm, disasm_stats)) = disassemble_text(name, data) {
        stats.modules_disassembled = 1;
        stats.instructions = disasm_stats.instruction_count;
        stats.functions = disasm_stats.function_count;
        out.push(NativeArtifact {
            relative_path: format!("native/{stem}.asm"),
            bytes: asm,
        });
    }

    (out, stats)
}

fn disassemble_text(name: &str, image: &[u8]) -> Option<(Vec<u8>, StreamDisasmStats)> {
    let (address, bits, text): (u64, u32, &[u8]) = text_section_window(image)?;
    if text.is_empty() {
        return None;
    }
    let mut buf: Vec<u8> = Vec::with_capacity(1 << 16);
    buf.extend_from_slice(header(name, text.len(), bits).as_bytes());
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
    Some((buf, stats))
}

fn header(name: &str, text_len: usize, bits: u32) -> String {
    format!(
        "; module: {name}\n; native disassembly recovered from a bundled compiled extension .text\n; arch: x86-{bits}, .text size: {text_len} bytes\n; streamed instruction-by-instruction with a bounded decode window; see the trailer for any truncation\n\n"
    )
}

fn is_runtime_lib(name: &str) -> bool {
    let base: &str = name
        .rsplit(['/', '\\'])
        .next()
        .map_or(name, |value: &str| value);
    let lower: String = base.to_ascii_lowercase();
    RUNTIME_LIB_PREFIXES
        .iter()
        .any(|p: &&str| lower.starts_with(p))
}

fn sanitize_component(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed: &str = cleaned.trim_matches(['.', '/', '\\', ' ']);
    if trimmed.is_empty() {
        "module".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn runtime_lib_detected_through_path() {
        assert!(is_runtime_lib("python313.dll"));
        assert!(is_runtime_lib("foo/bar/vcruntime140.dll"));
        assert!(is_runtime_lib("VCRUNTIME140.dll"));
        assert!(!is_runtime_lib("_struct.pyd"));
    }

    #[test]
    fn sanitize_strips_path_separators() {
        assert_eq!(sanitize_component("a/b/c.pyd"), "a_b_c.pyd");
        assert_eq!(sanitize_component("../evil"), "_evil");
        assert_eq!(sanitize_component(""), "module");
        let blank: String = sanitize_component("   ");
        assert!(
            !blank.is_empty() && !blank.contains(['/', '\\']),
            "a blank name must collapse to a safe non-empty component, got {blank:?}",
        );
    }

    #[test]
    fn non_native_bytes_produce_no_disasm() {
        let (artifacts, stats): (Vec<NativeArtifact>, NativeSurfaceStats) =
            surface_native_entry("junk.bin", &[0u8; 256]);
        assert_eq!(stats.modules_disassembled, 0);
        assert!(
            artifacts
                .iter()
                .all(|a: &NativeArtifact| !is_asm_path(&a.relative_path)),
            "must not emit an .asm child for bytes with no decodable .text",
        );
    }

    fn is_asm_path(path: &str) -> bool {
        std::path::Path::new(path)
            .extension()
            .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("asm"))
    }
}
