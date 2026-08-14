use crate::debug::{dbg_enabled, dbg_hex, dbg_kv, dbg_kv_guarded, dbg_line, dbg_section};
use crate::decompile::{Decompilation, OPARRAY_MAGIC, OpArray, decompile, parse_oparray};
use crate::detect::{PhpKind, detect};
use crate::encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, ioncube, sourceguardian,
    zend_guard,
};
use crate::error::{Error, Result};
use crate::key_extractor::{KeyProvenance, KeyScan, scan, xor_decrypt};
use crate::peel::{PeelOptions, PeelReport, peel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const SKELETON_PREVIEW_LINES: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStage {
    EvalChainPeeled,

    GotoDeflattened,

    OpArrayDecompiled,

    StructuralOnly,

    PlainSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub stage: RecoveryStage,
    pub php_kind: String,
    pub encoder: Option<String>,
    pub key_provenance: Option<String>,

    pub output: String,

    pub decompilation: Option<Decompilation>,

    pub residual_ciphertext_len: usize,
    pub notes: Vec<String>,
}

pub fn recover(bytes: &[u8], auth: Option<AuthorizationToken>) -> Result<RecoveryReport> {
    dbg_section("php recover");
    dbg_kv("input-len", || bytes.len().to_string());
    dbg_kv("classify", || format!("{:?}", detect(bytes).kind));
    dbg_kv("auth-supplied", || auth.is_some().to_string());
    if let Some(report) = try_encoder(bytes, auth)? {
        dbg_kv("route", || "encoder".to_owned());
        dbg_kv("stage", || format!("{:?}", report.stage));
        return Ok(report);
    }
    if let Some(report) = try_oparray_container(bytes)? {
        dbg_kv("route", || "oparray-container".to_owned());
        dbg_kv("stage", || format!("{:?}", report.stage));
        return Ok(report);
    }
    let report: RecoveryReport = try_eval_chain_or_plain(bytes);
    dbg_kv("route", || "eval-chain-or-plain".to_owned());
    dbg_kv("stage", || format!("{:?}", report.stage));
    Ok(report)
}

fn try_encoder(bytes: &[u8], auth: Option<AuthorizationToken>) -> Result<Option<RecoveryReport>> {
    let Some((family, detection)): Option<(EncoderFamily, EncoderDetection)> =
        detect_encoder(bytes)
    else {
        return Ok(None);
    };
    dbg_section("php encoder");
    dbg_kv("encoder-family", || format!("{family:?}"));
    dbg_kv("encoder-version", || detection.version_label.clone());
    dbg_kv("marker-offset", || {
        format!("0x{:x}", detection.marker_offset)
    });
    dbg_kv("marker-confident", || detection.confident.to_string());
    let key_scan: KeyScan = scan(bytes, family);
    dbg_kv("key-provenance", || format!("{:?}", key_scan.provenance));
    dbg_kv("key-offset", || {
        key_scan
            .key_offset
            .map_or_else(|| "none".to_owned(), |o: usize| format!("0x{o:x}"))
    });
    dbg_kv("key-len", || key_scan.key.len().to_string());
    if !key_scan.key.is_empty() {
        dbg_kv_guarded("static-key", || {
            String::from_utf8_lossy(&key_scan.key).into_owned()
        });
    }
    dbg_line(|| format!("key-wall: {}", key_scan.note));
    let outcome: Result<DecodeOutcome> = match family {
        EncoderFamily::IonCube => ioncube::decode(bytes, auth),
        EncoderFamily::SourceGuardian => sourceguardian::decode(bytes, auth),
        EncoderFamily::ZendGuard => zend_guard::decode(bytes, auth),
    };
    let mut notes: Vec<String> = vec![key_scan.note.to_owned()];
    let Ok(decoded): Result<DecodeOutcome> = outcome else {
        dbg_kv("decode-outcome", || "gated".to_owned());
        dbg_line(|| {
            "decode gated: authorization required or container version unsupported".to_owned()
        });
        notes.push("decode gated: authorization required or version unsupported".to_owned());
        return Ok(Some(RecoveryReport {
            stage: RecoveryStage::StructuralOnly,
            php_kind: "Encoder".to_owned(),
            encoder: Some(format!("{family:?}")),
            key_provenance: Some(format!("{:?}", key_scan.provenance)),
            output: String::new(),
            decompilation: None,
            residual_ciphertext_len: 0,
            notes,
        }));
    };
    let ciphertext: Vec<u8> = match decoded {
        DecodeOutcome::StructuralOnly { header, ciphertext } => {
            dbg_kv("decode-outcome", || "structural-only".to_owned());
            dbg_kv("payload-offset", || {
                format!("0x{:x}", header.payload_offset)
            });
            dbg_kv("ciphertext-len", || ciphertext.len().to_string());
            ciphertext
        }
        DecodeOutcome::PartialPlaintext { recovered, .. } => {
            dbg_kv("decode-outcome", || "partial-plaintext".to_owned());
            dbg_kv("recovered-len", || recovered.len().to_string());
            dbg_hex("recovered-head", &recovered, 32);
            if let Some(report) =
                lift_recovered_opcode_stream(&recovered, family, &key_scan, &mut notes)?
            {
                return Ok(Some(report));
            }
            dbg_line(|| residual_wall_note(family, recovered.len()));
            notes.push(residual_wall_note(family, recovered.len()));
            return Ok(Some(RecoveryReport {
                stage: RecoveryStage::StructuralOnly,
                php_kind: "Encoder".to_owned(),
                encoder: Some(format!("{family:?}")),
                key_provenance: Some(format!("{:?}", key_scan.provenance)),
                output: String::new(),
                decompilation: None,
                residual_ciphertext_len: recovered.len(),
                notes,
            }));
        }
    };
    let plaintext: Vec<u8> = static_decrypt(bytes, &ciphertext, &key_scan)?;
    if let Some(report) = decompile_if_container(&plaintext, family, &key_scan, &mut notes)? {
        return Ok(Some(report));
    }
    dbg_line(|| {
        format!(
            "structural framing recovered ({} byte(s)); payload is not a static op_array container",
            plaintext.len()
        )
    });
    notes.push(format!(
        "{detection:?}: structural framing recovered; payload not a recoverable op_array container"
    ));
    Ok(Some(RecoveryReport {
        stage: RecoveryStage::StructuralOnly,
        php_kind: "Encoder".to_owned(),
        encoder: Some(format!("{family:?}")),
        key_provenance: Some(format!("{:?}", key_scan.provenance)),
        output: String::new(),
        decompilation: None,
        residual_ciphertext_len: ciphertext.len(),
        notes,
    }))
}

fn lift_recovered_opcode_stream(
    recovered: &[u8],
    family: EncoderFamily,
    key_scan: &KeyScan,
    notes: &mut Vec<String>,
) -> Result<Option<RecoveryReport>> {
    if let Some(report) = decompile_if_container(recovered, family, key_scan, notes)? {
        return Ok(Some(report));
    }
    if !key_scan.key.is_empty() {
        let unkeyed: Vec<u8> = xor_decrypt(recovered, &key_scan.key);
        if let Some(report) = decompile_if_container(&unkeyed, family, key_scan, notes)? {
            notes.insert(
                0,
                "statically-embedded obfuscation key applied to the recovered opcode stream"
                    .to_owned(),
            );
            return Ok(Some(report));
        }
    }
    Ok(None)
}

fn residual_wall_note(family: EncoderFamily, residual_len: usize) -> String {
    let physical: &str = match family {
        EncoderFamily::IonCube => {
            "the residual opcode body is encrypted with the per-file symmetric key the native ionCube loader derives via its RSA license handshake; that key is not present in the file"
        }
        EncoderFamily::SourceGuardian => {
            "the residual opcode body is encrypted with the session key the ixed native loader derives at runtime; that key is not present in the file"
        }
        EncoderFamily::ZendGuard => {
            "the residual opcode body is encrypted with a key the Zend Guard loader derives at runtime; no static key was found in the file"
        }
    };
    format!(
        "static container layers stripped to {residual_len} residual byte(s); {physical}, so this layer cannot be lifted statically"
    )
}

fn static_decrypt(bytes: &[u8], ciphertext: &[u8], key_scan: &KeyScan) -> Result<Vec<u8>> {
    match (key_scan.provenance, key_scan.key_offset) {
        (KeyProvenance::StaticEmbedded, Some(offset)) if !key_scan.key.is_empty() => {
            let payload_start: usize = offset.saturating_add(key_scan.key.len());
            let payload: &[u8] =
                bytes
                    .get(payload_start..)
                    .ok_or_else(|| Error::ContainerBadFraming {
                        family: encoder_family_label(key_scan.family),
                        reason: "static key offset exceeds input length",
                    })?;
            dbg_kv("static-xor-payload-offset", || {
                format!("0x{payload_start:x}")
            });
            dbg_kv("static-xor-payload-len", || payload.len().to_string());
            dbg_line(|| {
                format!(
                    "Zend legacy static XOR decrypt: {}-byte key applied at offset 0x{payload_start:x}",
                    key_scan.key.len()
                )
            });
            Ok(xor_decrypt(payload, &key_scan.key))
        }
        _ => {
            dbg_line(|| "no static-embedded key: passing ciphertext through unmodified".to_owned());
            Ok(ciphertext.to_vec())
        }
    }
}

const fn encoder_family_label(family: EncoderFamily) -> &'static str {
    match family {
        EncoderFamily::IonCube => "IonCube",
        EncoderFamily::SourceGuardian => "SourceGuardian",
        EncoderFamily::ZendGuard => "ZendGuard",
    }
}

fn decompile_if_container(
    payload: &[u8],
    family: EncoderFamily,
    key_scan: &KeyScan,
    notes: &mut Vec<String>,
) -> Result<Option<RecoveryReport>> {
    if payload.len() < 5 || &payload[..4] != OPARRAY_MAGIC {
        return Ok(None);
    }
    let parsed: OpArray = parse_oparray(payload)?;
    let decomp: Decompilation = decompile(&parsed);
    dbg_kv("oparray-root-kind", || format!("{:?}", parsed.kind));
    dbg_kv("oparray-arrays", || decomp.op_array_count.to_string());
    dbg_kv("oparray-ops", || decomp.op_count.to_string());
    dbg_kv("oparray-literals", || decomp.literal_count.to_string());
    dbg_kv("skeleton-functions", || {
        count_kind(&parsed, is_function_kind).to_string()
    });
    dbg_kv("skeleton-methods", || {
        count_kind(&parsed, is_method_kind).to_string()
    });
    dbg_kv("skeleton-named-params", || {
        total_named_params(&parsed).to_string()
    });
    notes.push(oparray_lift_note(
        "decrypted payload is a Zend op_array container",
    ));
    if let Some(refusal) = unrecovered_note(&decomp) {
        notes.push(refusal);
    }
    Ok(Some(RecoveryReport {
        stage: RecoveryStage::OpArrayDecompiled,
        php_kind: "Encoder".to_owned(),
        encoder: Some(format!("{family:?}")),
        key_provenance: Some(format!("{:?}", key_scan.provenance)),
        output: decomp.php_skeleton.clone(),
        decompilation: Some(decomp),
        residual_ciphertext_len: 0,
        notes: std::mem::take(notes),
    }))
}

fn try_oparray_container(bytes: &[u8]) -> Result<Option<RecoveryReport>> {
    if bytes.len() < 5 || &bytes[..4] != OPARRAY_MAGIC {
        return Ok(None);
    }
    dbg_section("php oparray");
    dbg_kv("oparray-magic", || "DZOA".to_owned());
    dbg_kv("oparray-version", || {
        bytes
            .get(4)
            .map_or_else(|| "?".to_owned(), |v: &u8| v.to_string())
    });
    let parsed: OpArray = parse_oparray(bytes)?;
    let decomp: Decompilation = decompile(&parsed);
    dbg_kv("oparray-root-kind", || format!("{:?}", parsed.kind));
    dbg_kv("oparray-arrays", || decomp.op_array_count.to_string());
    dbg_kv("oparray-ops", || decomp.op_count.to_string());
    dbg_kv("oparray-literals", || decomp.literal_count.to_string());
    dbg_kv("skeleton-functions", || {
        count_kind(&parsed, is_function_kind).to_string()
    });
    dbg_kv("skeleton-methods", || {
        count_kind(&parsed, is_method_kind).to_string()
    });
    dbg_kv("skeleton-named-params", || {
        total_named_params(&parsed).to_string()
    });
    if dbg_enabled() {
        for line in decomp.php_skeleton.lines().take(SKELETON_PREVIEW_LINES) {
            dbg_line(|| format!("skeleton| {line}"));
        }
    }
    let mut notes: Vec<String> = vec![oparray_lift_note("raw Zend op_array container")];
    if let Some(refusal) = unrecovered_note(&decomp) {
        notes.push(refusal);
    }
    Ok(Some(RecoveryReport {
        stage: RecoveryStage::OpArrayDecompiled,
        php_kind: "OpArray".to_owned(),
        encoder: None,
        key_provenance: None,
        output: decomp.php_skeleton.clone(),
        decompilation: Some(decomp),
        residual_ciphertext_len: 0,
        notes,
    }))
}

fn oparray_lift_note(subject: &str) -> String {
    format!(
        "{subject}; lifted to structured PHP statements (temporaries folded into expressions, \
         if/while/foreach reconstructed from opcode jumps); local-variable metadata is preserved \
         when present, and unnamed CV slots use deterministic $vN names"
    )
}

fn unrecovered_note(decomp: &Decompilation) -> Option<String> {
    if decomp.unrecovered_total == 0 {
        return None;
    }
    let mut families: BTreeSet<&str> = BTreeSet::new();
    for entry in &decomp.unrecovered {
        families.insert(entry.reason.as_str());
    }
    let listed: Vec<String> = families
        .into_iter()
        .map(|reason: &str| format!("`{reason}`"))
        .collect();
    Some(format!(
        "{} of {} opcodes were refused rather than guessed and are marked in place in the recovered source: {}",
        decomp.unrecovered_total,
        decomp.op_count,
        listed.join(", ")
    ))
}

fn try_eval_chain_or_plain(bytes: &[u8]) -> RecoveryReport {
    let kind: PhpKind = detect(bytes).kind;
    let kind_label: String = format!("{kind:?}");
    dbg_section("php eval-chain");
    dbg_kv("php-kind", || kind_label.clone());
    let Ok(report): Result<PeelReport> = peel(bytes, PeelOptions::default()) else {
        dbg_line(|| "no eval/decode chain peeled; trying goto-deflatten on raw source".to_owned());
        let (output, extra): (String, Vec<String>) = apply_deflatten(bytes);
        if extra.is_empty() {
            return RecoveryReport {
                stage: RecoveryStage::PlainSource,
                php_kind: kind_label,
                encoder: None,
                key_provenance: None,
                output,
                decompilation: None,
                residual_ciphertext_len: 0,
                notes: vec![
                    "no obfuscation layer detected; input treated as plain source".to_owned(),
                ],
            };
        }
        return RecoveryReport {
            stage: RecoveryStage::GotoDeflattened,
            php_kind: kind_label,
            encoder: None,
            key_provenance: None,
            output,
            decompilation: None,
            residual_ciphertext_len: 0,
            notes: extra,
        };
    };

    dbg_kv("peeled-layers", || report.layers.len().to_string());
    dbg_kv("residual-eval", || report.residual_eval.to_string());
    let mut notes: Vec<String> = vec![format!(
        "peeled {} obfuscation layer(s)",
        report.layers.len()
    )];
    if report
        .layer_counts
        .contains_key(&crate::peel::PeelLayer::ModernLoader)
    {
        dbg_line(|| "modern multi-statement loader envelope statically evaluated".to_owned());
        notes.push(
            "multi-statement loader envelope statically evaluated: variable bindings traced through the decode chain to the eval/preg_replace sink".to_owned(),
        );
    }
    if report.residual_eval {
        notes.push(
            "residual eval() remains: dynamic/variable-variable indirection not statically resolvable; the variable-variable target is keyed from $_GET / request input, a runtime-only value".to_owned(),
        );
    }
    let (output, extra): (String, Vec<String>) = apply_deflatten(&report.final_source);
    notes.extend(extra);
    RecoveryReport {
        stage: RecoveryStage::EvalChainPeeled,
        php_kind: kind_label,
        encoder: None,
        key_provenance: None,
        output,
        decompilation: None,
        residual_ciphertext_len: 0,
        notes,
    }
}

fn apply_deflatten(source: &[u8]) -> (String, Vec<String>) {
    if !is_goto_flattened(source) {
        return (String::from_utf8_lossy(source).into_owned(), Vec::new());
    }
    let normalized: Vec<u8> = ensure_open_tag(source);
    let source: &[u8] = &normalized;
    let Ok(deflat): Result<crate::deflatten::DeflattenReport> = crate::deflatten::deflatten(source)
    else {
        return (String::from_utf8_lossy(source).into_owned(), Vec::new());
    };
    if deflat.labels_dropped == 0 && deflat.gotos_followed == 0 {
        return (String::from_utf8_lossy(source).into_owned(), Vec::new());
    }
    dbg_kv("goto-labels-dropped", || deflat.labels_dropped.to_string());
    dbg_kv("goto-followed", || deflat.gotos_followed.to_string());
    dbg_kv("goto-strings-decoded", || {
        deflat.strings_decoded.to_string()
    });
    let mut notes: Vec<String> = vec![format!(
        "goto-flattening reversed: {} scrambling label(s) dropped, {} fall-through goto(s) collapsed, statement order recovered",
        deflat.labels_dropped, deflat.gotos_followed
    )];
    if deflat.strings_decoded > 0 {
        notes.push(format!(
            "{} hex/octal-escaped string literal(s) decoded",
            deflat.strings_decoded
        ));
    }
    let output: String = match crate::restructure::restructure(source) {
        Ok(restructured) if restructured.whiles_recovered + restructured.ifs_recovered > 0 => {
            dbg_kv("restructure-whiles", || {
                restructured.whiles_recovered.to_string()
            });
            dbg_kv("restructure-ifs", || restructured.ifs_recovered.to_string());
            notes.push(format!(
                "control flow re-structured to native PHP: {} loop(s) and {} if/else recovered from the goto idioms",
                restructured.whiles_recovered, restructured.ifs_recovered
            ));
            String::from_utf8_lossy(&restructured.source).into_owned()
        }
        _ => String::from_utf8_lossy(&deflat.source).into_owned(),
    };
    notes.push(
        "identifiers stay scrambled: the obfuscator discards the original names, so they are not recoverable".to_owned(),
    );
    (output, notes)
}

fn ensure_open_tag(source: &[u8]) -> Vec<u8> {
    if memchr::memmem::find(source, b"<?php").is_some()
        || memchr::memmem::find(source, b"<?").is_some()
    {
        return source.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(source.len() + 6);
    out.extend_from_slice(b"<?php ");
    out.extend_from_slice(source);
    out
}

fn is_goto_flattened(source: &[u8]) -> bool {
    let lower: Vec<u8> = source.to_ascii_lowercase();
    let mut goto_count: usize = 0;
    let mut i: usize = 0;
    while let Some(rel) = lower[i..].windows(5).position(|w| w == b"goto ") {
        goto_count += 1;
        if goto_count >= 2 {
            return true;
        }
        i += rel + 5;
    }
    false
}

fn detect_encoder(bytes: &[u8]) -> Option<(EncoderFamily, EncoderDetection)> {
    if let Some(d) = ioncube::detect(bytes) {
        dbg_line(|| {
            format!(
                "ionCube encoder-marker matched: {} at offset 0x{:x}",
                d.version_label, d.marker_offset
            )
        });
        return Some((EncoderFamily::IonCube, d));
    }
    if let Some(d) = zend_guard::detect(bytes) {
        dbg_line(|| {
            format!(
                "Zend Guard encoder-marker matched: {} at offset 0x{:x}",
                d.version_label, d.marker_offset
            )
        });
        return Some((EncoderFamily::ZendGuard, d));
    }
    if let Some(d) = sourceguardian::detect(bytes) {
        dbg_line(|| {
            format!(
                "SourceGuardian encoder-marker matched: {} at offset 0x{:x}",
                d.version_label, d.marker_offset
            )
        });
        return Some((EncoderFamily::SourceGuardian, d));
    }
    None
}

const fn is_function_kind(kind: crate::decompile::OpArrayKind) -> bool {
    matches!(
        kind,
        crate::decompile::OpArrayKind::Function | crate::decompile::OpArrayKind::Closure
    )
}

const fn is_method_kind(kind: crate::decompile::OpArrayKind) -> bool {
    matches!(kind, crate::decompile::OpArrayKind::Method)
}

fn count_kind(node: &OpArray, pred: fn(crate::decompile::OpArrayKind) -> bool) -> usize {
    let here: usize = usize::from(pred(node.kind));
    here + node
        .children
        .iter()
        .map(|c: &OpArray| count_kind(c, pred))
        .sum::<usize>()
}

fn total_named_params(node: &OpArray) -> usize {
    node.num_args as usize + node.children.iter().map(total_named_params).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn static_key_scan(offset: usize) -> KeyScan {
        KeyScan {
            family: EncoderFamily::ZendGuard,
            provenance: KeyProvenance::StaticEmbedded,
            key: b"key".to_vec(),
            key_offset: Some(offset),
            note: "test",
        }
    }

    #[test]
    fn static_decrypt_rejects_key_offset_past_input() -> core::result::Result<(), String> {
        let scan: KeyScan = static_key_scan(16);
        let err: Error = match static_decrypt(b"<?", b"ciphertext", &scan) {
            Ok(_) => return Err("bad static offset must fail".to_owned()),
            Err(error) => error,
        };
        assert!(matches!(
            err,
            Error::ContainerBadFraming {
                family: "ZendGuard",
                reason: "static key offset exceeds input length",
            }
        ));
        Ok(())
    }

    #[test]
    fn decompile_if_container_rejects_malformed_oparray() -> core::result::Result<(), String> {
        let scan: KeyScan = static_key_scan(0);
        let mut notes: Vec<String> = Vec::new();
        let err: Error = match decompile_if_container(
            b"DZOA\x02",
            EncoderFamily::ZendGuard,
            &scan,
            &mut notes,
        ) {
            Ok(_) => return Err("malformed DZOA payload must fail".to_owned()),
            Err(error) => error,
        };
        assert!(matches!(err, Error::OpArrayTruncated { .. }));
        Ok(())
    }
}
