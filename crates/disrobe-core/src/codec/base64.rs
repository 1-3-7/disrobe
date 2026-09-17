use base64::alphabet::{Alphabet, STANDARD, URL_SAFE};
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{DecodeError as Base64Error, Engine as _};

use super::DecodeError;

const MAX_BASE64_INPUT: usize = 1 << 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Alphabet<'a> {
    Standard,
    UrlSafe,
    Custom(&'a [u8; 64]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Padding {
    Required,
    Optional,
    Forbidden,
}

pub fn base64_decode(
    input: &[u8],
    alphabet: Base64Alphabet<'_>,
    padding: Base64Padding,
) -> Result<Vec<u8>, DecodeError> {
    if input.len() > MAX_BASE64_INPUT {
        return Err(DecodeError::TooLarge { len: input.len() });
    }
    let engine: GeneralPurpose = build_engine(alphabet, padding)?;
    engine
        .decode(input)
        .map_err(|err: Base64Error| map_base64_error(err, input.len()))
}

fn build_engine(
    alphabet: Base64Alphabet<'_>,
    padding: Base64Padding,
) -> Result<GeneralPurpose, DecodeError> {
    let alpha: Alphabet = match alphabet {
        Base64Alphabet::Standard => STANDARD,
        Base64Alphabet::UrlSafe => URL_SAFE,
        Base64Alphabet::Custom(symbols) => {
            let text: &str = core::str::from_utf8(symbols)
                .map_err(|_| DecodeError::InvalidSymbol { symbol: symbols[0] })?;
            Alphabet::new(text).map_err(|_| DecodeError::InvalidSymbol { symbol: symbols[0] })?
        }
    };
    let mode: DecodePaddingMode = match padding {
        Base64Padding::Required => DecodePaddingMode::RequireCanonical,
        Base64Padding::Optional => DecodePaddingMode::Indifferent,
        Base64Padding::Forbidden => DecodePaddingMode::RequireNone,
    };
    let config: GeneralPurposeConfig = GeneralPurposeConfig::new()
        .with_encode_padding(matches!(padding, Base64Padding::Required))
        .with_decode_padding_mode(mode);
    Ok(GeneralPurpose::new(&alpha, config))
}

const fn map_base64_error(err: Base64Error, input_len: usize) -> DecodeError {
    match err {
        Base64Error::InvalidByte(_, symbol) | Base64Error::InvalidLastSymbol(_, symbol) => {
            DecodeError::InvalidSymbol { symbol }
        }
        Base64Error::InvalidPadding => DecodeError::BadPadding,
        Base64Error::InvalidLength(_) => DecodeError::BadLength { len: input_len },
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const STANDARD_SYMBOLS: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const DARKGATE_V2: &[u8; 64] =
        b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

    #[test]
    fn rfc4648_standard_padded() {
        let cases: [(&[u8], &[u8]); 6] = [
            (b"Zg==", b"f"),
            (b"Zm8=", b"fo"),
            (b"Zm9v", b"foo"),
            (b"Zm9vYg==", b"foob"),
            (b"Zm9vYmE=", b"fooba"),
            (b"Zm9vYmFy", b"foobar"),
        ];
        for (encoded, plain) in cases {
            assert_eq!(
                base64_decode(encoded, Base64Alphabet::Standard, Base64Padding::Required).unwrap(),
                plain,
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn rfc4648_standard_unpadded() {
        let cases: [(&[u8], &[u8]); 6] = [
            (b"Zg", b"f"),
            (b"Zm8", b"fo"),
            (b"Zm9v", b"foo"),
            (b"Zm9vYg", b"foob"),
            (b"Zm9vYmE", b"fooba"),
            (b"Zm9vYmFy", b"foobar"),
        ];
        for (encoded, plain) in cases {
            assert_eq!(
                base64_decode(encoded, Base64Alphabet::Standard, Base64Padding::Forbidden).unwrap(),
                plain,
                "{encoded:?}"
            );
        }
    }

    #[test]
    fn rfc4648_url_safe() {
        assert_eq!(
            base64_decode(b"-w==", Base64Alphabet::UrlSafe, Base64Padding::Required).unwrap(),
            [0xFB]
        );
        assert_eq!(
            base64_decode(b"_w==", Base64Alphabet::UrlSafe, Base64Padding::Required).unwrap(),
            [0xFF]
        );
        assert_eq!(
            base64_decode(b"-w", Base64Alphabet::UrlSafe, Base64Padding::Forbidden).unwrap(),
            [0xFB]
        );
    }

    #[test]
    fn url_safe_symbols_rejected_by_standard_alphabet() {
        assert!(matches!(
            base64_decode(b"-w==", Base64Alphabet::Standard, Base64Padding::Optional),
            Err(DecodeError::InvalidSymbol { symbol: b'-' })
        ));
    }

    #[test]
    fn custom_alphabet_matching_standard_decodes_rfc_vector() {
        assert_eq!(
            base64_decode(
                b"Zm9vYmFy",
                Base64Alphabet::Custom(STANDARD_SYMBOLS),
                Base64Padding::Optional
            )
            .unwrap(),
            b"foobar"
        );
    }

    #[test]
    fn custom_alphabet_darkgate_v2_decodes() {
        assert_eq!(
            base64_decode(
                b"PczlOc5o",
                Base64Alphabet::Custom(DARKGATE_V2),
                Base64Padding::Optional
            )
            .unwrap(),
            b"foobar"
        );
    }

    #[test]
    fn padding_policy_required_rejects_unpadded() {
        assert!(base64_decode(b"Zg", Base64Alphabet::Standard, Base64Padding::Required).is_err());
    }

    #[test]
    fn padding_policy_forbidden_rejects_padded() {
        assert!(
            base64_decode(b"Zg==", Base64Alphabet::Standard, Base64Padding::Forbidden).is_err()
        );
    }

    #[test]
    fn padding_policy_optional_accepts_both() {
        assert_eq!(
            base64_decode(b"Zg", Base64Alphabet::Standard, Base64Padding::Optional).unwrap(),
            b"f"
        );
        assert_eq!(
            base64_decode(b"Zg==", Base64Alphabet::Standard, Base64Padding::Optional).unwrap(),
            b"f"
        );
    }

    #[test]
    fn rejects_absurd_input_length() {
        let huge: Vec<u8> = vec![b'A'; MAX_BASE64_INPUT + 1];
        assert!(matches!(
            base64_decode(&huge, Base64Alphabet::Standard, Base64Padding::Optional),
            Err(DecodeError::TooLarge { .. })
        ));
    }
}
