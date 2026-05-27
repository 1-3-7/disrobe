mod detect;
mod inline;
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
    let Some(found): Option<detect::StringArrayFound> = detect::find_string_array(source) else {
        return Ok(None);
    };
    let Some(rotator): Option<detect::RotatorFound> = detect::find_rotator(source, &found.array_id)
    else {
        let inline_result: inline::InlineResult =
            inline::inline_decoder_calls(source, &found.array_id);
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
    let rotated: (Vec<String>, u32) =
        rotate::simulate(&found.literals, rotator.pivot_index, rotator.pivot_value);
    let mid_source: String = detect::rebuild_source(source, &found, &rotator, &rotated);
    let inline_result: inline::InlineResult =
        inline::inline_decoder_calls(&mid_source, &found.array_id);
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
