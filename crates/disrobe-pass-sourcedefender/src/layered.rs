use serde::Serialize;

use crate::codec::{basename_of, hex_decode, strip_extension};
use crate::debug::{dbg_hex, dbg_kv, dbg_line};
use crate::envelope::{
    DecryptedPye, PYE_BEGIN_MARKER, PYE_END_MARKER, PyeCodePayload, decrypt_pye,
};
use crate::error::{Error, Result};
use crate::modern_gcm::{
    GCM_NONCE_LEN, GCM_TAG_LEN, KDF_SALT_LEN, ModernGcmFraming, decrypt_modern_gcm_with_key,
    frame_modern_gcm_body,
};

pub const LEGACY_BEGIN_MARKER: &str = PYE_BEGIN_MARKER;
pub const LEGACY_END_MARKER: &str = PYE_END_MARKER;
pub const MODERN_BEGIN_MARKER: &str = "BEGIN PYE FILE";
pub const MODERN_END_MARKER: &str = "END PYE FILE";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerVariant {
    LegacyArmored,
    ModernHex,
}

impl ContainerVariant {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LegacyArmored => "legacy-armored",
            Self::ModernHex => "modern-hex",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WallReason {
    RuntimeLicenseKey,
    CustomPasswordRequired,
}

impl WallReason {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RuntimeLicenseKey => "runtime-license-key",
            Self::CustomPasswordRequired => "custom-password-required",
        }
    }

    #[must_use]
    pub const fn is_info_theoretic(self) -> bool {
        match self {
            Self::RuntimeLicenseKey => true,
            Self::CustomPasswordRequired => false,
        }
    }

    #[must_use]
    pub const fn is_recoverable_with_password(self) -> bool {
        match self {
            Self::RuntimeLicenseKey => false,
            Self::CustomPasswordRequired => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BodyWall {
    pub reason: WallReason,
    pub detail: String,
    pub ciphertext_len: usize,
    pub gcm_framing: Option<ModernGcmFraming>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LayerKind {
    Container,
    HexBody,
    GcmFraming,
    GcmCtrDecrypt,
    ArmoredIv,
    ArmoredBody,
    AesCtrDecrypt,
    MsgpackEnvelope,
    Marshal,
    SourceString,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeeledLayer {
    pub kind: LayerKind,
    pub detail: String,
    pub output_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LayeredRecovery {
    pub variant: ContainerVariant,
    pub layers: Vec<PeeledLayer>,
    pub recovered_source: Option<String>,
    pub recovered_marshal: Option<Vec<u8>>,
    pub wall: Option<BodyWall>,
}

impl LayeredRecovery {
    #[must_use]
    pub const fn is_fully_recovered(&self) -> bool {
        self.wall.is_none() && (self.recovered_source.is_some() || self.recovered_marshal.is_some())
    }

    #[must_use]
    pub fn is_honest_wall(&self) -> bool {
        self.wall
            .as_ref()
            .is_some_and(|w: &BodyWall| w.reason.is_info_theoretic())
    }
}

/// Classify a `.pye` container by body shape, not marker text.
///
/// The `BEGIN PYE FILE` markers are shared by two engines: the v16 modern build frames its
/// body as uppercase hex over an aes-256-gcm runtime-key wall, while v15 transitional builds
/// keep the recoverable aes-256-ctr basename-key scheme under an rfc1924/ascii85 armored body.
#[must_use]
pub fn classify_container(input: &[u8]) -> Option<ContainerVariant> {
    let text: &str = core::str::from_utf8(input).ok()?;
    let first: &str = text.lines().map(str::trim).find(|l: &&str| !l.is_empty())?;
    if first.contains(LEGACY_BEGIN_MARKER) {
        return Some(ContainerVariant::LegacyArmored);
    }
    if first.contains(MODERN_BEGIN_MARKER) {
        return Some(if parse_modern_hex_body(input).is_ok() {
            ContainerVariant::ModernHex
        } else {
            ContainerVariant::LegacyArmored
        });
    }
    None
}

pub fn recover_layered(input: &[u8], filename: &str) -> Result<LayeredRecovery> {
    match classify_container(input) {
        Some(ContainerVariant::LegacyArmored) => recover_legacy(input, filename),
        Some(ContainerVariant::ModernHex) => recover_modern(input, None),
        None => Err(Error::NotPye),
    }
}

pub fn recover_layered_with_modern_key(
    input: &[u8],
    filename: &str,
    modern_aes_key: &[u8; 32],
) -> Result<LayeredRecovery> {
    match classify_container(input) {
        Some(ContainerVariant::LegacyArmored) => recover_legacy(input, filename),
        Some(ContainerVariant::ModernHex) => recover_modern(input, Some(modern_aes_key)),
        None => Err(Error::NotPye),
    }
}

fn recover_legacy(input: &[u8], filename: &str) -> Result<LayeredRecovery> {
    if filename.is_empty() {
        return Err(Error::EmptyFilename);
    }
    let basename: &str = strip_extension(basename_of(filename));
    dbg_kv("legacy-basename-password", || basename.to_owned());
    let decrypted: DecryptedPye = decrypt_pye(input, filename)?;
    dbg_kv("legacy-iv", || decrypted.iv_hex.clone());
    dbg_kv("legacy-key", || decrypted.key_hex.clone());
    dbg_kv("aes-ctr-plaintext-len", || {
        decrypted.plaintext_msgpack.len().to_string()
    });
    let mut layers: Vec<PeeledLayer> = Vec::with_capacity(5);
    layers.push(PeeledLayer {
        kind: LayerKind::Container,
        detail: format!("legacy armor markers; basename password \"{basename}\""),
        output_len: input.len(),
    });
    layers.push(PeeledLayer {
        kind: LayerKind::ArmoredIv,
        detail: format!("ascii85+zlib IV {}", decrypted.iv_hex),
        output_len: 16,
    });
    layers.push(PeeledLayer {
        kind: LayerKind::ArmoredBody,
        detail: "ascii85+zlib ciphertext lines".to_owned(),
        output_len: decrypted.plaintext_msgpack.len(),
    });
    layers.push(PeeledLayer {
        kind: LayerKind::AesCtrDecrypt,
        detail: format!(
            "aes-256-ctr with basename-derived key {}",
            decrypted.key_hex
        ),
        output_len: decrypted.plaintext_msgpack.len(),
    });

    let mut recovered_source: Option<String> = None;
    let mut recovered_marshal: Option<Vec<u8>> = None;
    if let Some(envelope) = decrypted.envelope.as_ref() {
        dbg_kv("msgpack-envelope", || {
            format!("extra fields {:?}", envelope.other_fields)
        });
        layers.push(PeeledLayer {
            kind: LayerKind::MsgpackEnvelope,
            detail: format!("msgpack map; extra fields {:?}", envelope.other_fields),
            output_len: decrypted.plaintext_msgpack.len(),
        });
        match &envelope.original_code {
            PyeCodePayload::Source(s) => {
                dbg_kv("source-recovered", || {
                    format!("free-version inline source string, {} bytes", s.len())
                });
                layers.push(PeeledLayer {
                    kind: LayerKind::SourceString,
                    detail: "free-version inline source string".to_owned(),
                    output_len: s.len(),
                });
                recovered_source = Some(s.clone());
            }
            PyeCodePayload::MarshalledBytes(b) => {
                dbg_kv("marshal-recovered", || {
                    format!("marshalled code object, {} bytes", b.len())
                });
                layers.push(PeeledLayer {
                    kind: LayerKind::Marshal,
                    detail: "marshalled code object".to_owned(),
                    output_len: b.len(),
                });
                recovered_marshal = Some(b.clone());
            }
        }
    } else {
        dbg_line(|| "aes-ctr plaintext did not parse as a msgpack envelope".to_owned());
    }

    Ok(LayeredRecovery {
        variant: ContainerVariant::LegacyArmored,
        layers,
        recovered_source,
        recovered_marshal,
        wall: None,
    })
}

fn recover_modern(input: &[u8], modern_aes_key: Option<&[u8; 32]>) -> Result<LayeredRecovery> {
    let body: Vec<u8> = parse_modern_hex_body(input)?;

    let mut layers: Vec<PeeledLayer> = vec![
        PeeledLayer {
            kind: LayerKind::Container,
            detail: "modern PYE markers ---BEGIN PYE FILE--- / ----END PYE FILE----".to_owned(),
            output_len: input.len(),
        },
        PeeledLayer {
            kind: LayerKind::HexBody,
            detail: format!(
                "uppercase-hex body decoded to {} ciphertext bytes",
                body.len()
            ),
            output_len: body.len(),
        },
    ];

    let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
    dbg_kv("modern-hex-body-len", || body.len().to_string());
    dbg_kv("modern-gcm-framing", || framing.shape.tag().to_owned());
    dbg_hex("modern-ciphertext-head", &body, 24);
    layers.push(PeeledLayer {
        kind: LayerKind::GcmFraming,
        detail: format!(
            "aes-256-gcm framing {} (salt {} | nonce {} | ciphertext {} | tag {})",
            framing.shape.tag(),
            framing.salt.as_deref().map_or(0, <[u8]>::len),
            framing.nonce.as_deref().map_or(0, <[u8]>::len),
            framing.ciphertext_len,
            framing.tag.as_deref().map_or(0, <[u8]>::len),
        ),
        output_len: framing.ciphertext_len,
    });

    if let Some(key) = modern_aes_key
        && framing.is_well_formed()
    {
        match decrypt_modern_gcm_with_key(&framing, &body, key) {
            Ok(plaintext) => {
                dbg_kv("modern-gcm-decrypt", || {
                    format!("supplied key produced {} plaintext bytes", plaintext.len())
                });
                layers.push(PeeledLayer {
                    kind: LayerKind::GcmCtrDecrypt,
                    detail: "aes-256-gcm gctr keystream applied with the supplied key".to_owned(),
                    output_len: plaintext.len(),
                });
                return Ok(finalize_modern_plaintext(layers, plaintext));
            }
            Err(e) => {
                dbg_line(|| format!("modern gcm decrypt with supplied key failed: {e}"));
            }
        }
    }

    let wall: BodyWall = modern_wall(&framing, body.len());
    dbg_line(|| {
        format!(
            "modern .pye body is aes-256-gcm sealed ({}); statically walled",
            wall.reason.tag()
        )
    });

    Ok(LayeredRecovery {
        variant: ContainerVariant::ModernHex,
        layers,
        recovered_source: None,
        recovered_marshal: None,
        wall: Some(wall),
    })
}

fn parse_modern_hex_body(input: &[u8]) -> Result<Vec<u8>> {
    let text: &str = core::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l: &&str| !l.is_empty())
        .collect();
    if lines.len() < 3 {
        return Err(Error::NotPye);
    }
    let first: &str = lines.first().copied().unwrap_or_default();
    let last: &str = lines.last().copied().unwrap_or_default();
    if !first.contains(MODERN_BEGIN_MARKER) || !last.contains(MODERN_END_MARKER) {
        return Err(Error::NotPye);
    }
    let body_lines: &[&str] = &lines[1..lines.len() - 1];
    let mut joined: String = String::with_capacity(body_lines.iter().map(|s| s.len()).sum());
    for line in body_lines {
        joined.push_str(line);
    }
    hex_decode(joined.as_bytes()).map_err(|e: Error| match e {
        Error::Base85 { message, .. } => Error::Base85 {
            field: "modern-hex-body".to_owned(),
            message,
        },
        other => other,
    })
}

fn finalize_modern_plaintext(mut layers: Vec<PeeledLayer>, plaintext: Vec<u8>) -> LayeredRecovery {
    let mut recovered_source: Option<String> = None;
    let mut recovered_marshal: Option<Vec<u8>> = None;
    if let Ok(envelope) = crate::envelope::parse_msgpack_envelope(&plaintext) {
        layers.push(PeeledLayer {
            kind: LayerKind::MsgpackEnvelope,
            detail: format!("msgpack map; extra fields {:?}", envelope.other_fields),
            output_len: plaintext.len(),
        });
        match envelope.original_code {
            PyeCodePayload::Source(s) => {
                layers.push(PeeledLayer {
                    kind: LayerKind::SourceString,
                    detail: "modern inline source string".to_owned(),
                    output_len: s.len(),
                });
                recovered_source = Some(s);
            }
            PyeCodePayload::MarshalledBytes(b) => {
                layers.push(PeeledLayer {
                    kind: LayerKind::Marshal,
                    detail: "modern marshalled code object".to_owned(),
                    output_len: b.len(),
                });
                recovered_marshal = Some(b);
            }
        }
    } else if let Ok(parsed) = crate::source_recover::parse_array_envelope(&plaintext) {
        layers.push(PeeledLayer {
            kind: LayerKind::MsgpackEnvelope,
            detail: "msgpack array envelope".to_owned(),
            output_len: plaintext.len(),
        });
        layers.push(PeeledLayer {
            kind: LayerKind::Marshal,
            detail: "modern marshalled code object (array envelope)".to_owned(),
            output_len: parsed.marshal_payload.len(),
        });
        recovered_marshal = Some(parsed.marshal_payload);
    } else {
        recovered_marshal = Some(plaintext);
    }

    LayeredRecovery {
        variant: ContainerVariant::ModernHex,
        layers,
        recovered_source,
        recovered_marshal,
        wall: None,
    }
}

fn modern_wall(framing: &ModernGcmFraming, body_len: usize) -> BodyWall {
    let framed: bool = framing.is_well_formed();
    let detail: String = if framed {
        format!(
            "modern .pye body is aes-256-gcm sealed and statically frames as {} \
             (salt {KDF_SALT_LEN} | nonce {GCM_NONCE_LEN} | ciphertext {} | tag {GCM_TAG_LEN}); \
             the 256-bit key is absent from the artifact. in default mode the key is derived at \
             runtime from the activated machine identity (first physical mac), the license token, \
             and an ntp-validated time offset (none present here), an info-theoretic wall. in \
             custom-password mode (--password / SOURCEDEFENDER_PASSWORD) the same key is derived \
             from a user password that is also absent from the artifact but is recoverable if known: \
             supply it via recover_layered_with_modern_key and the framed body decrypts statically",
            framing.shape.tag(),
            framing.ciphertext_len,
        )
    } else {
        "modern .pye body is aes-256-gcm sealed under a key absent from the artifact; the body is \
         too short to carry the documented salt/nonce/tag framing"
            .to_owned()
    };
    BodyWall {
        reason: WallReason::RuntimeLicenseKey,
        detail,
        ciphertext_len: body_len,
        gcm_framing: framed.then(|| framing.clone()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::modern_gcm::GcmFramingShape;

    const LEGACY_HELLO: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
    const MODERN_TRIAL: &[u8] =
        include_bytes!("../../../corpus/python/sourcedefender/known_v16_trial.pye");

    #[test]
    fn classifies_both_container_variants() {
        assert_eq!(
            classify_container(LEGACY_HELLO),
            Some(ContainerVariant::LegacyArmored)
        );
        assert_eq!(
            classify_container(MODERN_TRIAL),
            Some(ContainerVariant::ModernHex)
        );
        assert_eq!(classify_container(b"not a pye file"), None);
    }

    #[test]
    fn legacy_free_sample_fully_recovers_source() {
        let rec: LayeredRecovery = recover_layered(LEGACY_HELLO, "hello.pye").expect("recover");
        assert_eq!(rec.variant, ContainerVariant::LegacyArmored);
        assert!(rec.wall.is_none(), "free legacy sample must not wall");
        assert!(rec.is_fully_recovered());
        let src: &str = rec.recovered_source.as_deref().expect("source");
        assert_eq!(src.trim_end(), "print(\"Hello World!\")");
        assert!(rec.layers.iter().any(|l| l.kind == LayerKind::SourceString));
    }

    #[test]
    fn modern_trial_sample_peels_layers_then_honest_walls() {
        let rec: LayeredRecovery = recover_layered(MODERN_TRIAL, "known.pye").expect("recover");
        assert_eq!(rec.variant, ContainerVariant::ModernHex);
        assert!(!rec.is_fully_recovered());
        assert!(rec.is_honest_wall());
        assert!(rec.recovered_source.is_none());
        assert!(rec.recovered_marshal.is_none());

        assert!(rec.layers.iter().any(|l| l.kind == LayerKind::Container));
        let hex_layer: &PeeledLayer = rec
            .layers
            .iter()
            .find(|l| l.kind == LayerKind::HexBody)
            .expect("hex body layer peeled statically");
        assert_eq!(hex_layer.output_len, 229);

        let wall: &BodyWall = rec.wall.as_ref().expect("wall");
        assert_eq!(wall.reason, WallReason::RuntimeLicenseKey);
        assert_eq!(wall.ciphertext_len, 229);
        assert!(wall.detail.contains("aes-256-gcm"));
        assert!(wall.detail.contains("machine"));

        let framing_layer: &PeeledLayer = rec
            .layers
            .iter()
            .find(|l| l.kind == LayerKind::GcmFraming)
            .expect("modern body must peel its gcm framing statically");
        assert!(framing_layer.detail.contains("salt"));
        let framing: &ModernGcmFraming = wall
            .gcm_framing
            .as_ref()
            .expect("well-formed body carries framing in the wall");
        assert_eq!(framing.shape, GcmFramingShape::SaltNonceCiphertextTag);
        assert_eq!(framing.salt.as_deref().map(<[u8]>::len), Some(KDF_SALT_LEN));
        assert_eq!(
            framing.nonce.as_deref().map(<[u8]>::len),
            Some(GCM_NONCE_LEN)
        );
        assert_eq!(framing.tag.as_deref().map(<[u8]>::len), Some(GCM_TAG_LEN));
    }

    #[test]
    fn wall_documents_both_default_and_custom_password_key_sources() {
        let rec: LayeredRecovery = recover_layered(MODERN_TRIAL, "known.pye").expect("recover");
        let wall: &BodyWall = rec.wall.as_ref().expect("wall");
        assert!(wall.detail.contains("machine identity"));
        assert!(wall.detail.contains("SOURCEDEFENDER_PASSWORD"));
        assert!(
            WallReason::RuntimeLicenseKey.is_info_theoretic(),
            "default mode key is machine/token bound, an info-theoretic wall"
        );
        assert!(
            WallReason::CustomPasswordRequired.is_recoverable_with_password(),
            "custom-password mode is recoverable once the password is supplied"
        );
        assert!(!WallReason::CustomPasswordRequired.is_info_theoretic());
    }

    #[test]
    fn wall_reason_is_info_theoretic() {
        assert!(WallReason::RuntimeLicenseKey.is_info_theoretic());
        assert_eq!(WallReason::RuntimeLicenseKey.tag(), "runtime-license-key");
    }

    #[test]
    fn rejects_non_pye_input() {
        let err: Error = recover_layered(b"hello world", "x.pye").expect_err("must reject");
        assert!(matches!(err, Error::NotPye));
    }

    #[test]
    fn modern_recovery_serializes_with_wall_tag() {
        let rec: LayeredRecovery = recover_layered(MODERN_TRIAL, "known.pye").expect("recover");
        let json: String = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains("runtime-license-key"));
        assert!(json.contains("modern-hex"));
    }
}
