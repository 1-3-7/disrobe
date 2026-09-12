use serde::Serialize;

use crate::analyze::{ModuleSummary, analyze_module};
use crate::detect::{WasmDetection, detect};
use crate::error::Result;
use crate::recover::{RecoveredModule, recover_module};
use crate::sourcemap::extract_source_mapping_url;

#[derive(Debug, Clone, Serialize)]
pub struct WasmAnalysis {
    pub detection: WasmDetection,
    pub summary: ModuleSummary,
    pub source_mapping_url: Option<String>,
    pub recovered_bytes: usize,
    pub faithful_wat_lifted: bool,
}

pub fn analyze(bytes: &[u8]) -> Result<WasmAnalysis> {
    crate::debug::dbg_section("wasm-deob analyze");
    crate::debug::dbg_kv("input-len", || bytes.len().to_string());
    crate::debug::dbg_hex("input-magic", bytes, 8);

    let detection: WasmDetection = detect(bytes)?;
    let summary: ModuleSummary = analyze_module(bytes)?;

    let source_mapping_url: Option<String> = extract_source_mapping_url(bytes)?;

    let recovered: RecoveredModule = recover_module(bytes)?;

    let faithful: Option<String> = crate::lift_module_faithful::lift_module_faithful_wat(bytes);

    if crate::debug::dbg_enabled()
        && let Some(wat) = faithful.as_deref()
    {
        let preview: String = wat.lines().take(6).collect::<Vec<&str>>().join(" | ");
        crate::debug::dbg_line(|| format!("faithful-wat-preview: {preview}"));
    }

    crate::debug::dbg_kv("analysis-summary", || {
        format!(
            "obfuscator={:?} funcs={} recovered_bytes={} faithful_wat={} source_map_url={}",
            detection.obfuscator,
            summary.func_count,
            recovered.bytes.len(),
            faithful.is_some(),
            source_mapping_url.is_some()
        )
    });

    Ok(WasmAnalysis {
        detection,
        summary,
        source_mapping_url,
        recovered_bytes: recovered.bytes.len(),
        faithful_wat_lifted: faithful.is_some(),
    })
}
