use serde::Serialize;

use crate::codec::{MAX_HEX_INPUT_BYTES, hex_encode};
use crate::error::{Error, Result};
use crate::gcm_tag::{GCM_BLOCK_LEN, gcm_tag, tags_match};

pub const GCM_TAG_LEN: usize = 16;
pub const GCM_NONCE_LEN: usize = 12;
pub const KDF_SALT_LEN: usize = 16;

const MIN_GCM_BODY_LEN: usize = GCM_NONCE_LEN + GCM_TAG_LEN;
const MIN_SALTED_GCM_BODY_LEN: usize = KDF_SALT_LEN + GCM_NONCE_LEN + GCM_TAG_LEN;
const MAX_MODERN_GCM_BODY_BYTES: usize = MAX_HEX_INPUT_BYTES / 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GcmFramingShape {
    SaltNonceCiphertextTag,
    NonceCiphertextTag,
    Undersized,
}

impl GcmFramingShape {
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::SaltNonceCiphertextTag => "salt|nonce|ciphertext|tag",
            Self::NonceCiphertextTag => "nonce|ciphertext|tag",
            Self::Undersized => "undersized",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModernGcmFraming {
    pub shape: GcmFramingShape,
    pub body_len: usize,
    pub salt: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
    pub ciphertext_len: usize,
    pub tag: Option<Vec<u8>>,
}

impl ModernGcmFraming {
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        !matches!(self.shape, GcmFramingShape::Undersized)
    }
}

#[must_use]
pub fn frame_modern_gcm_body(body: &[u8]) -> ModernGcmFraming {
    let body_len: usize = body.len();
    if body_len < MIN_GCM_BODY_LEN {
        return ModernGcmFraming {
            shape: GcmFramingShape::Undersized,
            body_len,
            salt: None,
            nonce: None,
            ciphertext_len: 0,
            tag: None,
        };
    }
    if body_len >= MIN_SALTED_GCM_BODY_LEN {
        let salt: Vec<u8> = body
            .get(..KDF_SALT_LEN)
            .map_or_else(Vec::new, ToOwned::to_owned);
        let nonce_end: usize = KDF_SALT_LEN.saturating_add(GCM_NONCE_LEN);
        let nonce: Vec<u8> = body
            .get(KDF_SALT_LEN..nonce_end)
            .map_or_else(Vec::new, ToOwned::to_owned);
        let ct_start: usize = KDF_SALT_LEN + GCM_NONCE_LEN;
        let tag_start: usize = body_len - GCM_TAG_LEN;
        let tag: Vec<u8> = body
            .get(tag_start..)
            .map_or_else(Vec::new, ToOwned::to_owned);
        return ModernGcmFraming {
            shape: GcmFramingShape::SaltNonceCiphertextTag,
            body_len,
            salt: Some(salt),
            nonce: Some(nonce),
            ciphertext_len: tag_start.saturating_sub(ct_start),
            tag: Some(tag),
        };
    }
    let nonce: Vec<u8> = body
        .get(..GCM_NONCE_LEN)
        .map_or_else(Vec::new, ToOwned::to_owned);
    let tag_start: usize = body_len - GCM_TAG_LEN;
    let tag: Vec<u8> = body
        .get(tag_start..)
        .map_or_else(Vec::new, ToOwned::to_owned);
    ModernGcmFraming {
        shape: GcmFramingShape::NonceCiphertextTag,
        body_len,
        salt: None,
        nonce: Some(nonce),
        ciphertext_len: tag_start.saturating_sub(GCM_NONCE_LEN),
        tag: Some(tag),
    }
}

fn split_authenticated_body<'body>(
    framing: &ModernGcmFraming,
    body: &'body [u8],
) -> Result<([u8; GCM_NONCE_LEN], &'body [u8], [u8; GCM_TAG_LEN])> {
    let Some(nonce_bytes): Option<&Vec<u8>> = framing.nonce.as_ref() else {
        return Err(Error::Msgpack(
            "modern body too short to carry a gcm nonce".to_owned(),
        ));
    };
    let Some(tag_bytes): Option<&Vec<u8>> = framing.tag.as_ref() else {
        return Err(Error::Msgpack(
            "modern body too short to carry a gcm tag".to_owned(),
        ));
    };
    let nonce: [u8; GCM_NONCE_LEN] = <[u8; GCM_NONCE_LEN]>::try_from(nonce_bytes.as_slice())
        .map_err(|_| {
            Error::Msgpack("modern gcm nonce/tag lengths are not the documented 12/16".to_owned())
        })?;
    let tag: [u8; GCM_TAG_LEN] =
        <[u8; GCM_TAG_LEN]>::try_from(tag_bytes.as_slice()).map_err(|_| {
            Error::Msgpack("modern gcm nonce/tag lengths are not the documented 12/16".to_owned())
        })?;
    let ct_start: usize = match framing.shape {
        GcmFramingShape::SaltNonceCiphertextTag => KDF_SALT_LEN + GCM_NONCE_LEN,
        GcmFramingShape::NonceCiphertextTag => GCM_NONCE_LEN,
        GcmFramingShape::Undersized => {
            return Err(Error::Msgpack("modern body is undersized".to_owned()));
        }
    };
    let tag_start: usize = body.len().saturating_sub(GCM_TAG_LEN);
    if tag_start < ct_start {
        return Err(Error::Msgpack(
            "modern gcm ciphertext slice underflows".to_owned(),
        ));
    }
    let ciphertext: &[u8] = body
        .get(ct_start..tag_start)
        .ok_or_else(|| Error::Msgpack("modern gcm ciphertext slice is invalid".to_owned()))?;
    Ok((nonce, ciphertext, tag))
}

pub(crate) fn apply_gctr_keystream(
    aes_key: &[u8; 32],
    nonce: &[u8; GCM_NONCE_LEN],
    ciphertext: &[u8],
) -> Vec<u8> {
    use aes::Aes256;
    use ctr::Ctr32BE;
    use ctr::cipher::{KeyIvInit, StreamCipher};

    let mut counter_zero: [u8; GCM_BLOCK_LEN] = [0u8; GCM_BLOCK_LEN];
    for (slot, byte) in counter_zero.iter_mut().zip(nonce.iter()) {
        *slot = *byte;
    }
    let counter_block: [u8; GCM_BLOCK_LEN] = (u128::from_be_bytes(counter_zero) | 2).to_be_bytes();
    let mut plaintext: Vec<u8> = ciphertext.to_vec();
    let mut cipher: Ctr32BE<Aes256> =
        Ctr32BE::<Aes256>::new(aes_key.into(), (&counter_block).into());
    cipher.apply_keystream(&mut plaintext);
    plaintext
}

pub fn decrypt_modern_gcm_with_key(
    framing: &ModernGcmFraming,
    body: &[u8],
    aes_key: &[u8; 32],
) -> Result<Vec<u8>> {
    if body.len() > MAX_MODERN_GCM_BODY_BYTES {
        return Err(Error::InputLimit {
            surface: "modern gcm body",
            observed: body.len(),
            limit: MAX_MODERN_GCM_BODY_BYTES,
        });
    }
    let canonical: ModernGcmFraming = frame_modern_gcm_body(body);
    if framing != &canonical {
        return Err(Error::Msgpack(
            "modern gcm framing does not match body".to_owned(),
        ));
    }
    let (nonce, ciphertext, stored): ([u8; GCM_NONCE_LEN], &[u8], [u8; GCM_TAG_LEN]) =
        split_authenticated_body(&canonical, body)?;
    let computed: [u8; GCM_TAG_LEN] = gcm_tag(aes_key, &nonce, &[], ciphertext)?;
    if !tags_match(&computed, &stored) {
        return Err(Error::GcmAuthentication {
            surface: "modern .pye body",
            computed: hex_encode(&computed),
            stored: hex_encode(&stored),
        });
    }
    Ok(apply_gctr_keystream(aes_key, &nonce, ciphertext))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MODERN_TRIAL_BODY_HEX: &str = concat!(
        "D3F3D1B2730BC6A0DD834EAFE412B908763C8BEC",
        "C375F45B0899BC91A1BB75759E4082E7C80FE4C5",
        "CEB52563CC45DD4D5240BCEF887E815EC57296D6",
        "110BF16428D4AAD1A9F935EB2CDD43D96B407E79",
        "09EF191C14162D95EF9DC028C3838A35982F3D16",
        "4A0D33731D9F2270A58573611049394EBBE9BBC4",
        "73F178725E92CBA5BA720AEA612FF15C0DACAB2F",
        "686BC332BF157E55AA1FB23A1992ABF3E82A0F84",
        "B5044B876CD109E4358117C0050971D6A62CB289",
        "5D58734013AC9646C34950437BDEE88B9D893786",
        "F199A93BFCCF8196F5F8B3A55D93CEF19179BAAF",
        "E034A014BB74CCD991",
    );

    fn modern_trial_body() -> Vec<u8> {
        crate::codec::hex_decode(MODERN_TRIAL_BODY_HEX.as_bytes()).expect("hex")
    }

    #[test]
    fn real_modern_body_frames_as_salt_nonce_ct_tag() {
        let body: Vec<u8> = modern_trial_body();
        assert_eq!(body.len(), 229);
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        assert_eq!(framing.shape, GcmFramingShape::SaltNonceCiphertextTag);
        assert!(framing.is_well_formed());
        assert_eq!(framing.body_len, 229);
        assert_eq!(framing.salt.as_deref().map(<[u8]>::len), Some(KDF_SALT_LEN));
        assert_eq!(
            framing.nonce.as_deref().map(<[u8]>::len),
            Some(GCM_NONCE_LEN)
        );
        assert_eq!(framing.tag.as_deref().map(<[u8]>::len), Some(GCM_TAG_LEN));
        assert_eq!(
            framing.ciphertext_len,
            229 - KDF_SALT_LEN - GCM_NONCE_LEN - GCM_TAG_LEN
        );
    }

    #[test]
    fn framing_partitions_are_contiguous_and_total_the_body() {
        let body: Vec<u8> = modern_trial_body();
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        let salt_len: usize = framing.salt.as_deref().map_or(0, <[u8]>::len);
        let nonce_len: usize = framing.nonce.as_deref().map_or(0, <[u8]>::len);
        let tag_len: usize = framing.tag.as_deref().map_or(0, <[u8]>::len);
        assert_eq!(
            salt_len + nonce_len + framing.ciphertext_len + tag_len,
            framing.body_len
        );
    }

    #[test]
    fn undersized_body_is_flagged_not_panicked() {
        let framing: ModernGcmFraming = frame_modern_gcm_body(&[0u8; 8]);
        assert_eq!(framing.shape, GcmFramingShape::Undersized);
        assert!(!framing.is_well_formed());
        assert!(framing.nonce.is_none());
        assert!(framing.tag.is_none());
    }

    #[test]
    fn short_body_frames_without_salt() {
        let body: Vec<u8> = vec![0xABu8; GCM_NONCE_LEN + 4 + GCM_TAG_LEN];
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        assert_eq!(framing.shape, GcmFramingShape::NonceCiphertextTag);
        assert!(framing.salt.is_none());
        assert_eq!(framing.ciphertext_len, 4);
    }

    #[test]
    fn ctr_keystream_matches_aes_gcm_gctr_against_a_known_vector() {
        let key: [u8; 32] = [0u8; 32];
        let nonce: [u8; GCM_NONCE_LEN] = [0u8; GCM_NONCE_LEN];
        let out: Vec<u8> = apply_gctr_keystream(&key, &nonce, &[0u8; 16]);
        assert_eq!(
            crate::codec::hex_encode(&out),
            "cea7403d4d606b6e074ec5d3baf39d18",
            "decrypting an all-zero ciphertext block under key/nonce=0 must equal the real \
             cryptography AESGCM keystream block (verified against the python library)",
        );
    }

    fn salted_body(ciphertext: &[u8], tag: &[u8]) -> Vec<u8> {
        let mut body: Vec<u8> =
            Vec::with_capacity(KDF_SALT_LEN + GCM_NONCE_LEN + ciphertext.len() + GCM_TAG_LEN);
        body.extend_from_slice(&[0u8; KDF_SALT_LEN]);
        body.extend_from_slice(&[0u8; GCM_NONCE_LEN]);
        body.extend_from_slice(ciphertext);
        body.extend_from_slice(tag);
        body
    }

    #[test]
    fn an_all_zero_tag_is_refused_instead_of_returning_keystream_garbage() {
        let key: [u8; 32] = [0u8; 32];
        let body: Vec<u8> = vec![0u8; KDF_SALT_LEN + GCM_NONCE_LEN + 16 + GCM_TAG_LEN];
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        assert_eq!(framing.shape, GcmFramingShape::SaltNonceCiphertextTag);
        assert_eq!(framing.ciphertext_len, 16);
        let err: Error = decrypt_modern_gcm_with_key(&framing, &body, &key)
            .expect_err("an all-zero tag is not the real gcm tag for this key and ciphertext");
        let Error::GcmAuthentication {
            computed, stored, ..
        } = err
        else {
            panic!("a tag mismatch must be reported as an authentication failure")
        };
        assert_eq!(stored, "00000000000000000000000000000000");
        assert_eq!(
            computed, "a87450d1732b0aba4d296b2786fbd719",
            "the real aes-256-gcm tag over an all-zero ciphertext block under key/nonce=0",
        );
    }

    #[test]
    fn the_published_test_case_14_tag_authenticates_and_then_decrypts() {
        let key: [u8; 32] = [0u8; 32];
        let nonce: [u8; GCM_NONCE_LEN] = [0u8; GCM_NONCE_LEN];
        let ciphertext: Vec<u8> = crate::codec::hex_decode(b"cea7403d4d606b6e074ec5d3baf39d18")
            .expect("gcm-spec test case 14 ciphertext");
        let tag: Vec<u8> = crate::codec::hex_decode(b"d0d1c8a799996bf0265b98b5d48ab919")
            .expect("gcm-spec test case 14 tag");
        let body: Vec<u8> = salted_body(&ciphertext, &tag);

        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        let plaintext: Vec<u8> = decrypt_modern_gcm_with_key(&framing, &body, &key)
            .expect("the published gcm-spec test case 14 tag must authenticate");
        assert_eq!(
            plaintext,
            vec![0u8; 16],
            "gcm-spec test case 14 decrypts to a single all-zero plaintext block"
        );
        assert_eq!(plaintext, apply_gctr_keystream(&key, &nonce, &ciphertext));
    }

    #[test]
    fn a_single_flipped_ciphertext_byte_turns_authentication_red() {
        let key: [u8; 32] = [0u8; 32];
        let mut ciphertext: Vec<u8> = crate::codec::hex_decode(b"cea7403d4d606b6e074ec5d3baf39d18")
            .expect("gcm-spec test case 14 ciphertext");
        let tag: Vec<u8> = crate::codec::hex_decode(b"d0d1c8a799996bf0265b98b5d48ab919")
            .expect("gcm-spec test case 14 tag");
        let Some(first): Option<&mut u8> = ciphertext.first_mut() else {
            panic!("the vector ciphertext is not empty")
        };
        *first ^= 0x01;
        let body: Vec<u8> = salted_body(&ciphertext, &tag);
        let framing: ModernGcmFraming = frame_modern_gcm_body(&body);
        assert!(
            matches!(
                decrypt_modern_gcm_with_key(&framing, &body, &key),
                Err(Error::GcmAuthentication { .. })
            ),
            "one flipped ciphertext byte must invalidate the stored tag"
        );
    }
}
