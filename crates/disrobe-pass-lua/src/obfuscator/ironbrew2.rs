use crate::error::{Error, Result};
use crate::obfuscator::ironbrew2_recover::{
    RecoveredProgram, lift_to_source, recover, recovered_strings, runnable_source,
};
use crate::obfuscator::vm_devirt::{devirt_to_peel, extract_embedded_payload};
use crate::obfuscator::{DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult};

const MARKERS: &[&[u8]] = &[
    b"Ironbrew",
    b"-- IronBrew2",
    b"Ironbrew_Build",
    b"IRONBREW_VM",
    b"IronBrew:tm:",
];

#[must_use]
pub fn detect(src: &[u8]) -> Option<ObfuscatorDetection> {
    let mut found: Vec<String> = Vec::new();
    for m in MARKERS {
        if disrobe_core::byte_search::contains(src, m) {
            found.push(String::from_utf8_lossy(m).into_owned());
        }
    }
    if found.is_empty() {
        return None;
    }
    Some(ObfuscatorDetection {
        kind: LuaObfuscatorKind::Ironbrew2,
        variant: Some("custom-vm+opcode-permutation".to_owned()),
        confidence: 93,
        markers: found,
    })
}

pub fn peel(src: &[u8], opts: &DeobfOptions) -> Result<PeelResult> {
    let _det: ObfuscatorDetection = detect(src).ok_or(Error::NoObfuscatorSignature("Ironbrew2"))?;
    if !opts.i_have_authorization {
        return Err(Error::AuthorizationRequired("Ironbrew2"));
    }
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(src);

    if let Ok(program) = recover(&text) {
        return Ok(real_peel_result(&program));
    }

    let Some(payload): Option<Vec<u8>> = extract_embedded_payload(&text) else {
        return Ok(PeelResult::passthrough(
            src,
            vec![
                "ironbrew2 vm bootstrap detected but the real serialized bytecode could not be located/decoded from this artifact"
                    .to_owned(),
            ],
        ));
    };
    devirt_to_peel(src, &text, &payload, "ironbrew2")
}

fn real_peel_result(program: &RecoveredProgram) -> PeelResult {
    let fully: bool = program.stats.fully_recovered();
    let readable: String = lift_to_source(program).unwrap_or_default();
    let runnable: String = runnable_source(program);
    let deobfuscated: Vec<u8> = if runnable.is_empty() {
        readable.into_bytes()
    } else {
        runnable.into_bytes()
    };
    let summary: String = format!(
        "ironbrew2 real-vm devirt: handlers {}/{} ({}%), instructions {}/{} ({}%), {} constants, xor key 0x{:02X}",
        program.stats.classified_handlers,
        program.stats.total_handlers,
        program.stats.handler_pct(),
        program.stats.lifted_instructions,
        program.stats.total_instructions,
        program.stats.instruction_pct(),
        program.stats.constants,
        program.stats.xor_key,
    );
    PeelResult {
        deobfuscated,
        passes_run: vec![
            "ironbrew2-real-vm-bytestring-decode".to_owned(),
            "ironbrew2-real-vm-key-recovery".to_owned(),
            "ironbrew2-real-vm-opcode-fingerprint".to_owned(),
            "ironbrew2-real-vm-lift".to_owned(),
        ],
        residual_markers: if fully {
            Vec::new()
        } else {
            vec![format!(
                "{summary}; residual super-operator/control-flow/mutation layer not fully reversed"
            )]
        },
        recovered_strings: recovered_strings(program),
        fully_recovered: fully,
    }
}
