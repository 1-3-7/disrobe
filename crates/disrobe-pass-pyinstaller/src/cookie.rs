use crate::MEI_MAGIC;
use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieVariant {
    Pre21,
    V21Plus,
}

impl CookieVariant {
    #[must_use]
    pub const fn header_len(self) -> usize {
        match self {
            Self::Pre21 => 24,
            Self::V21Plus => 88,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Cookie {
    pub variant: CookieVariant,
    pub magic_offset: usize,
    pub length_of_package: u32,
    pub toc_offset: u32,
    pub toc_length: u32,
    pub pyver: u32,
    pub python_libname: Option<String>,
    pub python_major: u8,
    pub python_minor: u8,
}

pub fn find_cookie(image: &[u8]) -> Result<Cookie> {
    dbg_section("cookie.find");
    dbg_kv("image_len", || image.len().to_string());
    let Some(magic_pos): Option<usize> = locate_magic(image) else {
        dbg_line(|| "MEI cookie magic not found in image".to_owned());
        return Err(Error::CookieNotFound);
    };
    dbg_kv("magic_offset", || format!("{magic_pos:#x}"));
    parse_cookie(image, magic_pos)
}

fn locate_magic(image: &[u8]) -> Option<usize> {
    let mut last_match: Option<usize> = None;
    let mut cursor: usize = 0usize;
    let magic_len: usize = MEI_MAGIC.len();
    while cursor <= image.len().saturating_sub(magic_len) {
        let slice: &[u8] = &image[cursor..];
        let Some(idx): Option<usize> = slice.windows(MEI_MAGIC.len()).position(|w| w == MEI_MAGIC)
        else {
            break;
        };
        let magic_pos: usize = cursor.checked_add(idx)?;
        last_match = Some(magic_pos);
        cursor = magic_pos.checked_add(magic_len)?;
    }
    last_match
}

fn parse_cookie(image: &[u8], magic_pos: usize) -> Result<Cookie> {
    let header_end: usize = checked_offset(magic_pos, 24usize)?;
    if header_end > image.len() {
        return Err(Error::CookieTruncated(magic_pos));
    }
    let length_of_package: u32 = read_u32_be(image, checked_offset(magic_pos, 8usize)?)?;
    let toc_offset: u32 = read_u32_be(image, checked_offset(magic_pos, 12usize)?)?;
    let toc_length: u32 = read_u32_be(image, checked_offset(magic_pos, 16usize)?)?;
    let pyver: u32 = read_u32_be(image, checked_offset(magic_pos, 20usize)?)?;

    let (variant, python_libname): (CookieVariant, Option<String>) = if let Some(candidate_end) =
        checked_offset(magic_pos, 88usize)
            .ok()
            .filter(|end: &usize| *end <= image.len())
    {
        let candidate_start: usize = checked_offset(magic_pos, 24usize)?;
        let candidate: &[u8] = &image[candidate_start..candidate_end];
        if subslice_contains_case_insensitive(candidate, b"python") {
            let lib: String = read_null_padded_ascii(candidate);
            (CookieVariant::V21Plus, Some(lib))
        } else {
            (CookieVariant::Pre21, None)
        }
    } else {
        (CookieVariant::Pre21, None)
    };

    dbg_kv("cookie_variant", || {
        match variant {
            CookieVariant::Pre21 => "pre-2.1",
            CookieVariant::V21Plus => "2.1+",
        }
        .to_owned()
    });
    dbg_kv("length_of_package", || length_of_package.to_string());
    dbg_kv("toc_offset", || format!("{toc_offset:#x}"));
    dbg_kv("toc_length", || toc_length.to_string());
    if let Some(lib) = python_libname.as_deref() {
        dbg_kv("python_libname", || lib.to_owned());
    }

    let Some((python_major, python_minor)): Option<(u8, u8)> = decode_pyver(pyver) else {
        dbg_line(|| format!("pyver {pyver} did not decode to a supported python version"));
        return Err(Error::BadPyver(pyver));
    };
    dbg_kv("python_version", || {
        format!("{python_major}.{python_minor} (pyver={pyver})")
    });

    Ok(Cookie {
        variant,
        magic_offset: magic_pos,
        length_of_package,
        toc_offset,
        toc_length,
        pyver,
        python_libname,
        python_major,
        python_minor,
    })
}

fn decode_pyver(pyver: u32) -> Option<(u8, u8)> {
    if pyver >= 100 {
        let major_u32: u32 = pyver / 100;
        let minor_u32: u32 = pyver % 100;
        let major: u8 = u8::try_from(major_u32).ok()?;
        let minor: u8 = u8::try_from(minor_u32).ok()?;
        if (2..=3).contains(&major) && minor < 50 {
            return Some((major, minor));
        }
    } else if pyver >= 10 {
        let major_u32: u32 = pyver / 10;
        let minor_u32: u32 = pyver % 10;
        let major: u8 = u8::try_from(major_u32).ok()?;
        let minor: u8 = u8::try_from(minor_u32).ok()?;
        if (2..=3).contains(&major) && minor < 10 {
            return Some((major, minor));
        }
    }
    None
}

fn checked_offset(base: usize, offset: usize) -> Result<usize> {
    base.checked_add(offset).ok_or(Error::CookieTruncated(base))
}

fn read_u32_be(image: &[u8], at: usize) -> Result<u32> {
    let end: usize = checked_offset(at, 4usize)?;
    let slice: &[u8] = image.get(at..end).ok_or(Error::CookieTruncated(at))?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn subslice_contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn read_null_padded_ascii(bytes: &[u8]) -> String {
    let end: usize = bytes
        .iter()
        .position(|&b| b == 0)
        .map_or(bytes.len(), |position: usize| position);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_synthetic_cookie(variant: CookieVariant, pyver: u32) -> Vec<u8> {
        let mut data: Vec<u8> = vec![0u8; 1024];
        let pos: usize = 512;
        data[pos..pos + 8].copy_from_slice(MEI_MAGIC);
        data[pos + 8..pos + 12].copy_from_slice(&100u32.to_be_bytes());
        data[pos + 12..pos + 16].copy_from_slice(&0u32.to_be_bytes());
        data[pos + 16..pos + 20].copy_from_slice(&80u32.to_be_bytes());
        data[pos + 20..pos + 24].copy_from_slice(&pyver.to_be_bytes());
        if variant == CookieVariant::V21Plus {
            data[pos + 24..pos + 41].copy_from_slice(b"python311.dll\0\0\0\0");
        }
        data
    }

    #[test]
    fn detects_pre21_cookie() {
        let data: Vec<u8> = build_synthetic_cookie(CookieVariant::Pre21, 37);
        let c: Cookie = find_cookie(&data).expect("cookie parse");
        assert_eq!(c.python_major, 3);
        assert_eq!(c.python_minor, 7);
    }

    #[test]
    fn detects_v21_cookie() {
        let data: Vec<u8> = build_synthetic_cookie(CookieVariant::V21Plus, 311);
        let c: Cookie = find_cookie(&data).expect("cookie parse");
        assert_eq!(c.variant, CookieVariant::V21Plus);
        assert_eq!(c.python_libname.as_deref(), Some("python311.dll"));
        assert_eq!(c.python_major, 3);
        assert_eq!(c.python_minor, 11);
    }

    #[test]
    fn missing_magic_errors() {
        let data: Vec<u8> = vec![0u8; 1024];
        assert!(matches!(
            find_cookie(&data).err(),
            Some(Error::CookieNotFound)
        ));
    }

    #[test]
    fn pyver_decoding_table() {
        assert_eq!(decode_pyver(27), Some((2, 7)));
        assert_eq!(decode_pyver(37), Some((3, 7)));
        assert_eq!(decode_pyver(310), Some((3, 10)));
        assert_eq!(decode_pyver(314), Some((3, 14)));
        assert_eq!(decode_pyver(0), None);
        assert_eq!(decode_pyver(9999), None);
    }

    #[test]
    fn cookie_header_len_table() {
        assert_eq!(CookieVariant::Pre21.header_len(), 24);
        assert_eq!(CookieVariant::V21Plus.header_len(), 88);
    }

    #[test]
    fn checked_offset_rejects_usize_wrap() {
        let err: Error = checked_offset(usize::MAX, 1usize).expect_err("offset must wrap");
        assert!(matches!(err, Error::CookieTruncated(_)));
    }
}
