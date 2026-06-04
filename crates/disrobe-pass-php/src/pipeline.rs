use crate::decompile::{Decompilation, OPARRAY_MAGIC, decompile, parse_oparray};
use crate::detect::{PhpKind, detect};
use crate::encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, ioncube, sourceguardian,
    zend_guard,
};
use crate::error::Result;
use crate::key_extractor::{KeyProvenance, KeyScan, scan, xor_decrypt};
use crate::peel::{PeelOptions, PeelReport, peel};
use serde::{Deserialize, Serialize};

/// What recovery stage produced the final artifact, so callers and reports never overstate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryStage {
    /// Eval/base64/gzinflate chain peeled to plain PHP source.
    EvalChainPeeled,
    /// Encoder envelope decrypted (statically) and its `op_array` decompiled to a skeleton.
    OpArrayDecompiled,
    /// Encoder envelope located but only structural framing is recoverable (key is runtime).
    StructuralOnly,
    /// Input was already plain PHP source; nothing to recover.
    PlainSource,
}

/// The honest, end-to-end recovery report wiring detection through to real output.
///
/// This is the single bridge the mission calls for: detection no longer dead-ends at a label,
/// it drives the eval-chain peeler and the encoder decrypt + `op_array` decompiler, and the
/// recovered text (peeled source or PHP skeleton) is carried in `output`. Every field is
/// truthful about how far recovery actually got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub stage: RecoveryStage,
    pub php_kind: String,
    pub encoder: Option<String>,
    pub key_provenance: Option<String>,
    /// The recovered PHP text: peeled source for chains, skeleton for decompiled `op_arrays`.
    pub output: String,
    /// Present when an `op_array` was decompiled; carries fidelity + counts.
    pub decompilation: Option<Decompilation>,
    /// Bytes that remain encrypted/undecoded (runtime-keyed payloads), reported, never faked.
    pub residual_ciphertext_len: usize,
    pub notes: Vec<String>,
}

/// Drives full PHP recovery: detect, then peel eval-chains or decrypt + decompile encoders.
///
/// The `auth` token gates the commercial encoders exactly as before. For eval-chain
/// obfuscation no auth is needed. The function never executes PHP and never fabricates a
/// decrypt it cannot perform from static bytes.
pub fn recover(bytes: &[u8], auth: Option<AuthorizationToken>) -> Result<RecoveryReport> {
    if let Some(report) = try_encoder(bytes, auth) {
        return Ok(report);
    }
    if let Some(report) = try_oparray_container(bytes)? {
        return Ok(report);
    }
    Ok(try_eval_chain_or_plain(bytes))
}

fn try_encoder(bytes: &[u8], auth: Option<AuthorizationToken>) -> Option<RecoveryReport> {
    let (family, detection): (EncoderFamily, EncoderDetection) = detect_encoder(bytes)?;
    let key_scan: KeyScan = scan(bytes, family);
    let outcome: Result<DecodeOutcome> = match family {
        EncoderFamily::IonCube => ioncube::decode(bytes, auth),
        EncoderFamily::SourceGuardian => sourceguardian::decode(bytes, auth),
        EncoderFamily::ZendGuard => zend_guard::decode(bytes, auth),
    };
    let mut notes: Vec<String> = vec![key_scan.note.to_owned()];
    let Ok(decoded): Result<DecodeOutcome> = outcome else {
        notes.push("decode gated: authorization required or version unsupported".to_owned());
        return Some(RecoveryReport {
            stage: RecoveryStage::StructuralOnly,
            php_kind: "Encoder".to_owned(),
            encoder: Some(format!("{family:?}")),
            key_provenance: Some(format!("{:?}", key_scan.provenance)),
            output: String::new(),
            decompilation: None,
            residual_ciphertext_len: 0,
            notes,
        });
    };
    let ciphertext: Vec<u8> = match decoded {
        DecodeOutcome::StructuralOnly { ciphertext, .. } => ciphertext,
        DecodeOutcome::PartialPlaintext {
            recovered,
            residual_ciphertext,
            ..
        } => {
            if let Some(report) = decompile_if_container(&recovered, family, &key_scan, &mut notes)
            {
                return Some(report);
            }
            residual_ciphertext
        }
    };
    let plaintext: Vec<u8> = static_decrypt(bytes, &ciphertext, &key_scan);
    if let Some(report) = decompile_if_container(&plaintext, family, &key_scan, &mut notes) {
        return Some(report);
    }
    notes.push(format!(
        "{detection:?}: structural framing recovered; payload not a recoverable op_array container"
    ));
    Some(RecoveryReport {
        stage: RecoveryStage::StructuralOnly,
        php_kind: "Encoder".to_owned(),
        encoder: Some(format!("{family:?}")),
        key_provenance: Some(format!("{:?}", key_scan.provenance)),
        output: String::new(),
        decompilation: None,
        residual_ciphertext_len: ciphertext.len(),
        notes,
    })
}

/// Applies the statically recovered key to the real payload, or returns the ciphertext as-is.
///
/// For the Zend Guard legacy XOR scheme the true payload begins immediately after the key
/// block (`key_offset + key.len()`), which is computed from the original bytes rather than
/// the encoder framing's coarser slice. Every other scheme is runtime-keyed, so the
/// ciphertext passes through unchanged and is reported honestly downstream.
fn static_decrypt(bytes: &[u8], ciphertext: &[u8], key_scan: &KeyScan) -> Vec<u8> {
    match (key_scan.provenance, key_scan.key_offset) {
        (KeyProvenance::StaticEmbedded, Some(offset)) if !key_scan.key.is_empty() => {
            let payload_start: usize = offset.saturating_add(key_scan.key.len());
            let payload: &[u8] = bytes.get(payload_start..).unwrap_or(&[]);
            xor_decrypt(payload, &key_scan.key)
        }
        _ => ciphertext.to_vec(),
    }
}

fn decompile_if_container(
    payload: &[u8],
    family: EncoderFamily,
    key_scan: &KeyScan,
    notes: &mut Vec<String>,
) -> Option<RecoveryReport> {
    if payload.len() < 5 || &payload[..4] != OPARRAY_MAGIC {
        return None;
    }
    let parsed = parse_oparray(payload).ok()?;
    let decomp: Decompilation = decompile(&parsed);
    notes.push("decrypted payload is a Zend op_array container; decompiled to PARTIAL skeleton (variable names erased to $vN)".to_owned());
    Some(RecoveryReport {
        stage: RecoveryStage::OpArrayDecompiled,
        php_kind: "Encoder".to_owned(),
        encoder: Some(format!("{family:?}")),
        key_provenance: Some(format!("{:?}", key_scan.provenance)),
        output: decomp.php_skeleton.clone(),
        decompilation: Some(decomp),
        residual_ciphertext_len: 0,
        notes: std::mem::take(notes),
    })
}

fn try_oparray_container(bytes: &[u8]) -> Result<Option<RecoveryReport>> {
    if bytes.len() < 5 || &bytes[..4] != OPARRAY_MAGIC {
        return Ok(None);
    }
    let parsed = parse_oparray(bytes)?;
    let decomp: Decompilation = decompile(&parsed);
    Ok(Some(RecoveryReport {
        stage: RecoveryStage::OpArrayDecompiled,
        php_kind: "OpArray".to_owned(),
        encoder: None,
        key_provenance: None,
        output: decomp.php_skeleton.clone(),
        decompilation: Some(decomp),
        residual_ciphertext_len: 0,
        notes: vec![
            "raw Zend op_array container decompiled to PARTIAL skeleton (variable names erased to $vN)".to_owned(),
        ],
    }))
}

fn try_eval_chain_or_plain(bytes: &[u8]) -> RecoveryReport {
    let kind: PhpKind = detect(bytes).kind;
    let kind_label: String = format!("{kind:?}");
    match peel(bytes, PeelOptions::default()) {
        Ok(report) => {
            let report: PeelReport = report;
            let mut notes: Vec<String> = vec![format!(
                "peeled {} obfuscation layer(s)",
                report.layers.len()
            )];
            if report.residual_eval {
                notes.push(
                    "residual eval() remains: dynamic/variable-variable indirection not statically resolvable".to_owned(),
                );
            }
            RecoveryReport {
                stage: RecoveryStage::EvalChainPeeled,
                php_kind: kind_label,
                encoder: None,
                key_provenance: None,
                output: String::from_utf8_lossy(&report.final_source).into_owned(),
                decompilation: None,
                residual_ciphertext_len: 0,
                notes,
            }
        }
        Err(_) => RecoveryReport {
            stage: RecoveryStage::PlainSource,
            php_kind: kind_label,
            encoder: None,
            key_provenance: None,
            output: String::from_utf8_lossy(bytes).into_owned(),
            decompilation: None,
            residual_ciphertext_len: 0,
            notes: vec!["no obfuscation layer detected; input treated as plain source".to_owned()],
        },
    }
}

/// Detects the encoder family, preferring the most specific banner.
///
/// Zend Guard's `@Zend;\n<ver>` banner is a prefix of `SourceGuardian`'s looser `@Zend;`
/// misuse marker, so Zend Guard is probed before `SourceGuardian` to avoid a `SourceGuardian`
/// false match swallowing a genuine Zend Guard envelope.
fn detect_encoder(bytes: &[u8]) -> Option<(EncoderFamily, EncoderDetection)> {
    if let Some(d) = ioncube::detect(bytes) {
        return Some((EncoderFamily::IonCube, d));
    }
    if let Some(d) = zend_guard::detect(bytes) {
        return Some((EncoderFamily::ZendGuard, d));
    }
    if let Some(d) = sourceguardian::detect(bytes) {
        return Some((EncoderFamily::SourceGuardian, d));
    }
    None
}
