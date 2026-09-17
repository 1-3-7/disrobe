use serde::Serialize;

use crate::codec::{MAX_HEX_INPUT_BYTES, basename_of, hex_decode, strip_extension};
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
const MAX_CONTAINER_INPUT_BYTES: usize = MAX_HEX_INPUT_BYTES + 64 * 1024;
const MAX_MODERN_BODY_LINES: usize = 32_768;

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
    SuppliedKeyRejected,
}

impl WallReason {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RuntimeLicenseKey => "runtime-license-key",
            Self::CustomPasswordRequired => "custom-password-required",
            Self::SuppliedKeyRejected => "supplied-key-rejected",
        }
    }

    #[must_use]
    pub const fn is_info_theoretic(self) -> bool {
        match self {
            Self::RuntimeLicenseKey => true,
            Self::CustomPasswordRequired | Self::SuppliedKeyRejected => false,
        }
    }

    #[must_use]
    pub const fn is_recoverable_with_password(self) -> bool {
        match self {
            Self::RuntimeLicenseKey | Self::SuppliedKeyRejected => false,
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
    ensure_container_input_limit(input.len())?;
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
    ensure_container_input_limit(input.len())?;
    match classify_container(input) {
        Some(ContainerVariant::LegacyArmored) => recover_legacy(input, filename),
        Some(ContainerVariant::ModernHex) => recover_modern(input, Some(modern_aes_key)),
        None => Err(Error::NotPye),
    }
}

const fn ensure_container_input_limit(input_len: usize) -> Result<()> {
    if input_len > MAX_CONTAINER_INPUT_BYTES {
        return Err(Error::InputLimit {
            surface: "layered container input",
            observed: input_len,
            limit: MAX_CONTAINER_INPUT_BYTES,
        });
    }
    Ok(())
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
                    detail: "aes-256-gcm tag authenticated, then the gctr keystream applied with \
                             the supplied key"
                        .to_owned(),
                    output_len: plaintext.len(),
                });
                return Ok(finalize_modern_plaintext(layers, plaintext));
            }
            Err(rejection @ Error::GcmAuthentication { .. }) => {
                dbg_line(|| format!("modern gcm tag rejected the supplied key: {rejection}"));
                return Ok(LayeredRecovery {
                    variant: ContainerVariant::ModernHex,
                    layers,
                    recovered_source: None,
                    recovered_marshal: None,
                    wall: Some(BodyWall {
                        reason: WallReason::SuppliedKeyRejected,
                        detail: format!("{rejection}"),
                        ciphertext_len: body.len(),
                        gcm_framing: Some(framing),
                    }),
                });
            }
            Err(other) => return Err(other),
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
    ensure_container_input_limit(input.len())?;
    let text: &str = core::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let mut lines = text
        .lines()
        .map(str::trim)
        .filter(|line: &&str| !line.is_empty());
    let Some(first): Option<&str> = lines.next() else {
        return Err(Error::NotPye);
    };
    if !first.contains(MODERN_BEGIN_MARKER) {
        return Err(Error::NotPye);
    }
    let mut line_count: usize = 1;
    let mut pending: Option<&str> = None;
    let mut joined: String = String::new();
    for line in lines {
        line_count = line_count.checked_add(1).ok_or(Error::InputLimit {
            surface: "modern hex body lines",
            observed: usize::MAX,
            limit: MAX_MODERN_BODY_LINES,
        })?;
        if line_count > MAX_MODERN_BODY_LINES {
            return Err(Error::InputLimit {
                surface: "modern hex body lines",
                observed: line_count,
                limit: MAX_MODERN_BODY_LINES,
            });
        }
        let previous_pending: Option<&str> = pending.replace(line);
        if let Some(previous) = previous_pending {
            let next_len: usize =
                joined
                    .len()
                    .checked_add(previous.len())
                    .ok_or(Error::InputLimit {
                        surface: "modern hex body",
                        observed: usize::MAX,
                        limit: MAX_HEX_INPUT_BYTES,
                    })?;
            if next_len > MAX_HEX_INPUT_BYTES {
                return Err(Error::InputLimit {
                    surface: "modern hex body",
                    observed: next_len,
                    limit: MAX_HEX_INPUT_BYTES,
                });
            }
            joined.push_str(previous);
        }
    }
    let Some(last): Option<&str> = pending else {
        return Err(Error::NotPye);
    };
    if !last.contains(MODERN_END_MARKER) || joined.is_empty() {
        return Err(Error::NotPye);
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
    const CRAFTED_MODERN_KNOWN_KEY: &[u8] =
        include_bytes!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.pye");
    const CRAFTED_SEALED_TAG: &str = "50b1fd94ab6faa9594d624f91e1c70e3";

    fn crafted_key() -> [u8; 32] {
        let mut key: [u8; 32] = [0u8; 32];
        for (index, slot) in key.iter_mut().enumerate() {
            *slot = u8::try_from(index).unwrap_or(0);
        }
        key
    }

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
    fn the_crafted_body_carries_the_tag_the_cryptography_library_sealed_it_with() {
        let body: Vec<u8> = parse_modern_hex_body(CRAFTED_MODERN_KNOWN_KEY).expect("hex body");
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        let stored: &[u8] = framing
            .tag
            .as_deref()
            .expect("well-formed body carries a tag");
        assert_eq!(
            crate::codec::hex_encode(stored),
            CRAFTED_SEALED_TAG,
            "the committed fixture's trailing 16 bytes are the authentication tag produced by \
             the real AESGCM.encrypt that sealed it, not a value disrobe computed"
        );
    }

    #[test]
    fn the_correct_key_authenticates_the_crafted_body_and_recovers_its_source() {
        let rec: LayeredRecovery = recover_layered_with_modern_key(
            CRAFTED_MODERN_KNOWN_KEY,
            "crafted.pye",
            &crafted_key(),
        )
        .expect("keyed recovery");
        assert!(rec.wall.is_none());
        assert!(rec.is_fully_recovered());
        let source: &str = rec.recovered_source.as_deref().expect("source");
        assert_eq!(
            source.trim_end(),
            "def greet(name):\n    return \"hi \" + name\n\n\nprint(greet(\"world\"))"
        );
        let decrypt_layer: &PeeledLayer = rec
            .layers
            .iter()
            .find(|l| l.kind == LayerKind::GcmCtrDecrypt)
            .expect("the authenticated decrypt must be recorded as a peeled layer");
        assert!(
            decrypt_layer.detail.contains("tag authenticated"),
            "the layer must record that the tag was checked, got: {}",
            decrypt_layer.detail
        );
    }

    #[test]
    fn a_wrong_key_walls_on_the_stored_tag_instead_of_reporting_recovery() {
        let rec: LayeredRecovery =
            recover_layered_with_modern_key(CRAFTED_MODERN_KNOWN_KEY, "crafted.pye", &[0xFFu8; 32])
                .expect("a rejected key still peels the container layers");
        assert!(
            !rec.is_fully_recovered(),
            "a key that does not authenticate must never report full recovery"
        );
        assert!(rec.recovered_source.is_none());
        assert!(
            rec.recovered_marshal.is_none(),
            "keystream garbage must not be handed back as a marshalled code object"
        );
        let wall: &BodyWall = rec
            .wall
            .as_ref()
            .expect("a rejected key must produce a wall");
        assert_eq!(wall.reason, WallReason::SuppliedKeyRejected);
        assert_eq!(wall.reason.tag(), "supplied-key-rejected");
        assert!(
            !wall.reason.is_info_theoretic(),
            "a wrong key is not an information-theoretic limit; the right key exists"
        );
        assert!(!wall.reason.is_recoverable_with_password());
        assert!(
            wall.detail.contains(CRAFTED_SEALED_TAG),
            "the refusal must quote the tag the body actually carries, got: {}",
            wall.detail
        );
        assert!(rec.layers.iter().any(|l| l.kind == LayerKind::GcmFraming));
        assert!(
            !rec.layers
                .iter()
                .any(|l| l.kind == LayerKind::GcmCtrDecrypt),
            "a rejected key must not record a decrypt layer"
        );
    }

    #[test]
    fn every_wrong_key_in_a_sweep_is_rejected_by_the_stored_tag() {
        let mut rejected: usize = 0;
        let mut attempted: usize = 0;
        for byte in 0u8..=31u8 {
            let mut key: [u8; 32] = crafted_key();
            let Some(slot): Option<&mut u8> = key.get_mut(usize::from(byte)) else {
                panic!("index {byte} is inside a 32-byte key")
            };
            *slot ^= 0x01;
            attempted += 1;
            let rec: LayeredRecovery =
                recover_layered_with_modern_key(CRAFTED_MODERN_KNOWN_KEY, "crafted.pye", &key)
                    .expect("peels");
            if !rec.is_fully_recovered()
                && rec
                    .wall
                    .as_ref()
                    .is_some_and(|w: &BodyWall| w.reason == WallReason::SuppliedKeyRejected)
            {
                rejected += 1;
            }
        }
        assert_eq!(attempted, 32);
        assert_eq!(
            rejected, 32,
            "all 32 single-bit key mutations must be rejected by the stored tag"
        );
    }

    #[test]
    fn modern_recovery_serializes_with_wall_tag() {
        let rec: LayeredRecovery = recover_layered(MODERN_TRIAL, "known.pye").expect("recover");
        let json: String = serde_json::to_string(&rec).expect("serialize");
        assert!(json.contains("runtime-license-key"));
        assert!(json.contains("modern-hex"));
    }
}
