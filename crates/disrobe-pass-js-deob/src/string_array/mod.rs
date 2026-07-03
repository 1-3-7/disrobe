mod detect;
mod inline;
mod modern;
mod rotate;
mod sandbox;

use serde::Serialize;

use crate::error::Result;

#[derive(Debug, Clone, Serialize)]
pub struct StringArrayRecovery {
    pub array_id: String,
    pub original_strings: Vec<String>,
    pub rotated_strings: Vec<String>,
    pub rotation_count: u32,
    pub rotator_removed: bool,
    pub decoder_name: Option<String>,
    pub call_sites_total: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

#[allow(clippy::unnecessary_wraps)]
pub fn recover(source: &str) -> Result<Option<StringArrayRecovery>> {
    crate::debug::dbg_section("string-array recover");
    if let Some(modern) = modern::recover_modern(source) {
        crate::debug::dbg_kv("shape", || "modern-self-reassigning-provider".to_owned());
        crate::debug::dbg_kv("provider", || modern.provider_name.clone());
        crate::debug::dbg_kv("rotation-count", || modern.rotation_count.to_string());
        crate::debug::dbg_kv("call-sites", || {
            format!(
                "inlined={}/{}",
                modern.call_sites_inlined, modern.call_sites_total
            )
        });
        return Ok(Some(StringArrayRecovery {
            array_id: modern.provider_name,
            original_strings: Vec::new(),
            rotated_strings: Vec::new(),
            rotation_count: modern.rotation_count,
            rotator_removed: true,
            decoder_name: Some(modern.decoder_name),
            call_sites_total: modern.call_sites_total,
            call_sites_inlined: modern.call_sites_inlined,
            rewritten_source: modern.rewritten_source,
        }));
    }
    let Some(found): Option<detect::StringArrayFound> = detect::find_string_array(source) else {
        crate::debug::dbg_line(|| "no static string array located".to_owned());
        return Ok(None);
    };
    crate::debug::dbg_kv("array-id", || found.array_id.clone());
    crate::debug::dbg_kv("literals", || found.literals.len().to_string());
    let Some(rotator): Option<detect::RotatorFound> = detect::find_rotator(source, &found.array_id)
    else {
        crate::debug::dbg_kv("rotator", || "none (decode without rotation)".to_owned());
        let inline_result: inline::InlineResult =
            inline::inline_decoder_calls(source, &found.array_id);
        crate::debug::dbg_kv("call-sites", || {
            format!(
                "inlined={}/{}",
                inline_result.call_sites_inlined, inline_result.call_sites_total
            )
        });
        return Ok(Some(StringArrayRecovery {
            array_id: found.array_id,
            original_strings: found.literals.clone(),
            rotated_strings: found.literals,
            rotation_count: 0,
            rotator_removed: false,
            decoder_name: inline_result.decoder_name,
            call_sites_total: inline_result.call_sites_total,
            call_sites_inlined: inline_result.call_sites_inlined,
            rewritten_source: inline_result.rewritten_source,
        }));
    };
    crate::debug::dbg_kv("rotator", || {
        format!(
            "pivot-index={} pivot-value={}",
            rotator.pivot_index, rotator.pivot_value
        )
    });
    let rotated: (Vec<String>, u32) =
        rotate::simulate(&found.literals, rotator.pivot_index, rotator.pivot_value);
    crate::debug::dbg_kv("rotation-count", || rotated.1.to_string());
    let mid_source: String = detect::rebuild_source(source, &found, &rotator, &rotated);
    let inline_result: inline::InlineResult =
        inline::inline_decoder_calls(&mid_source, &found.array_id);
    crate::debug::dbg_kv("call-sites", || {
        format!(
            "inlined={}/{}",
            inline_result.call_sites_inlined, inline_result.call_sites_total
        )
    });
    Ok(Some(StringArrayRecovery {
        array_id: found.array_id,
        original_strings: found.literals,
        rotated_strings: rotated.0,
        rotation_count: rotated.1,
        rotator_removed: true,
        decoder_name: inline_result.decoder_name,
        call_sites_total: inline_result.call_sites_total,
        call_sites_inlined: inline_result.call_sites_inlined,
        rewritten_source: inline_result.rewritten_source,
    }))
}
