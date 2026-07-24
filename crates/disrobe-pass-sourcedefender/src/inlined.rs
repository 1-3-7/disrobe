use core::ops::Range;

use crate::cache::KeyCache;
use crate::codec::{MAX_ARMORED_INPUT_BYTES, basename_of, strip_extension};
use crate::envelope::{
    DecryptedPye, PYE_BEGIN_MARKER, PYE_END_MARKER, decrypt_pye, decrypt_pye_with_key,
};
use crate::error::{Error, Result};
use crate::kdf::validate_filename;

const MAX_INLINED_SOURCE_BYTES: usize = MAX_ARMORED_INPUT_BYTES;
const MAX_INLINED_BLOCKS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinedBlock {
    pub span: Range<usize>,
    pub raw: String,
    pub filename_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinedExtraction {
    pub host_filename: String,
    pub blocks: Vec<InlinedBlock>,
    pub decrypted: Vec<DecryptedPye>,
    pub failures: Vec<InlinedFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlinedFailure {
    pub span: Range<usize>,
    pub filename_used: String,
    pub message: String,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct InlinedExtractOptions {
    pub require_known_basename: bool,
}

#[inline]
#[must_use]
pub fn locate_inlined_blocks(source: &str) -> Vec<InlinedBlock> {
    if source.len() > MAX_INLINED_SOURCE_BYTES {
        return Vec::new();
    }
    let bytes: &[u8] = source.as_bytes();
    let begin: &[u8] = PYE_BEGIN_MARKER.as_bytes();
    let end: &[u8] = PYE_END_MARKER.as_bytes();
    let mut blocks: Vec<InlinedBlock> = Vec::new();
    let mut cursor: usize = 0usize;
    while blocks.len() < MAX_INLINED_BLOCKS {
        let Some(remaining): Option<&[u8]> = bytes.get(cursor..) else {
            break;
        };
        let Some(begin_off): Option<usize> = find_subslice(remaining, begin) else {
            break;
        };
        let Some(absolute_begin): Option<usize> = cursor.checked_add(begin_off) else {
            break;
        };
        let block_start: usize = scan_line_start(source, absolute_begin);
        let Some(after_begin): Option<usize> = absolute_begin.checked_add(begin.len()) else {
            break;
        };
        let Some(after_begin_bytes): Option<&[u8]> = bytes.get(after_begin..) else {
            break;
        };
        if let Some(end_rel) = find_subslice(after_begin_bytes, end) {
            let Some(end_marker_start): Option<usize> = after_begin.checked_add(end_rel) else {
                break;
            };
            let Some(after_end_marker): Option<usize> = end_marker_start.checked_add(end.len())
            else {
                break;
            };
            let block_end: usize = scan_line_end(source, after_end_marker);
            let span: Range<usize> = block_start..block_end;
            let Some(raw): Option<String> = source.get(span.clone()).map(ToOwned::to_owned) else {
                break;
            };
            let filename_hint: Option<String> = scan_filename_hint(source, block_start);
            blocks.push(InlinedBlock {
                span,
                raw,
                filename_hint,
            });
            cursor = block_end;
        } else {
            break;
        }
    }
    blocks
}

#[inline]
pub fn extract_inlined(
    source: &str,
    host_filename: &str,
    options: InlinedExtractOptions,
) -> Result<InlinedExtraction> {
    validate_inlined_input(source)?;
    validate_filename(host_filename)?;
    let blocks: Vec<InlinedBlock> = locate_inlined_blocks(source);
    let mut decrypted: Vec<DecryptedPye> = Vec::with_capacity(blocks.len());
    let mut failures: Vec<InlinedFailure> = Vec::new();
    let mut cache: KeyCache = KeyCache::new();
    let host_basename: &str = strip_extension(basename_of(host_filename));
    let mut attempted_decrypts: usize = 0;
    for block in &blocks {
        let candidate: String = block
            .filename_hint
            .clone()
            .unwrap_or_else(|| host_basename.to_owned());
        if options.require_known_basename && block.filename_hint.is_none() {
            failures.push(InlinedFailure {
                span: block.span.clone(),
                filename_used: candidate,
                message: format!("missing filename hint at offset {}", block.span.start),
            });
            continue;
        }
        attempted_decrypts += 1;
        let key: crate::kdf::DerivedKey = cache.get_or_derive(&candidate)?;
        match decrypt_pye_with_key(block.raw.as_bytes(), &candidate, &key) {
            Ok(d) => decrypted.push(d),
            Err(_) => match decrypt_pye(block.raw.as_bytes(), &candidate) {
                Ok(d) => decrypted.push(d),
                Err(e) => failures.push(InlinedFailure {
                    span: block.span.clone(),
                    filename_used: candidate,
                    message: format!("{e}"),
                }),
            },
        }
    }
    if attempted_decrypts > 0 && decrypted.is_empty() {
        return Err(Error::InlinedNoDecrypt(blocks.len()));
    }
    Ok(InlinedExtraction {
        host_filename: host_filename.to_owned(),
        blocks,
        decrypted,
        failures,
    })
}

fn validate_inlined_input(source: &str) -> Result<()> {
    if source.len() > MAX_INLINED_SOURCE_BYTES {
        return Err(Error::InputLimit {
            surface: "inlined source",
            observed: source.len(),
            limit: MAX_INLINED_SOURCE_BYTES,
        });
    }
    let bytes: &[u8] = source.as_bytes();
    let begin: &[u8] = PYE_BEGIN_MARKER.as_bytes();
    let end: &[u8] = PYE_END_MARKER.as_bytes();
    let mut cursor: usize = 0;
    let mut completed_blocks: usize = 0;
    loop {
        let Some(remaining): Option<&[u8]> = bytes.get(cursor..) else {
            return Ok(());
        };
        let Some(begin_off): Option<usize> = find_subslice(remaining, begin) else {
            return Ok(());
        };
        let Some(absolute_begin): Option<usize> = cursor.checked_add(begin_off) else {
            return Err(Error::InputLimit {
                surface: "inlined block offset",
                observed: usize::MAX,
                limit: MAX_INLINED_SOURCE_BYTES,
            });
        };
        let Some(after_begin): Option<usize> = absolute_begin.checked_add(begin.len()) else {
            return Err(Error::InputLimit {
                surface: "inlined block offset",
                observed: usize::MAX,
                limit: MAX_INLINED_SOURCE_BYTES,
            });
        };
        let Some(after_begin_bytes): Option<&[u8]> = bytes.get(after_begin..) else {
            return Ok(());
        };
        let Some(end_rel): Option<usize> = find_subslice(after_begin_bytes, end) else {
            return Ok(());
        };
        let Some(end_marker_start): Option<usize> = after_begin.checked_add(end_rel) else {
            return Err(Error::InputLimit {
                surface: "inlined block offset",
                observed: usize::MAX,
                limit: MAX_INLINED_SOURCE_BYTES,
            });
        };
        let Some(after_end): Option<usize> = end_marker_start.checked_add(end.len()) else {
            return Err(Error::InputLimit {
                surface: "inlined block offset",
                observed: usize::MAX,
                limit: MAX_INLINED_SOURCE_BYTES,
            });
        };
        completed_blocks = completed_blocks.checked_add(1).ok_or(Error::InputLimit {
            surface: "inlined block count",
            observed: usize::MAX,
            limit: MAX_INLINED_BLOCKS,
        })?;
        if completed_blocks > MAX_INLINED_BLOCKS {
            return Err(Error::InputLimit {
                surface: "inlined block count",
                observed: completed_blocks,
                limit: MAX_INLINED_BLOCKS,
            });
        }
        cursor = scan_line_end(source, after_end);
    }
}

#[inline]
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[inline]
fn scan_line_start(source: &str, offset: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let mut start: usize = offset.min(bytes.len());
    while start > 0 && bytes[start - 1] != b'\n' {
        start -= 1;
    }
    start
}

#[inline]
fn scan_line_end(source: &str, offset: usize) -> usize {
    let bytes: &[u8] = source.as_bytes();
    let len: usize = bytes.len();
    let mut end: usize = offset.min(len);
    while end < len && bytes[end] != b'\n' {
        end += 1;
    }
    end
}

#[inline]
fn scan_filename_hint(source: &str, block_start: usize) -> Option<String> {
    let block_start: usize = block_start.min(source.len());
    let mut scan_start: usize = block_start.saturating_sub(512);
    while scan_start < block_start && !source.is_char_boundary(scan_start) {
        scan_start += 1;
    }
    let window: &str = source.get(scan_start..block_start)?;
    let needles: &[&str] = &[
        "__sd_filename__",
        "sd_filename",
        "@sourcedefender.module(",
        "sourcedefender.protected(",
        "module_name",
        "__pye_name__",
    ];
    let mut best: Option<String> = None;
    for needle in needles {
        if let Some(idx) = window.rfind(needle) {
            let tail: &str = &window[idx + needle.len()..];
            if let Some(name) = parse_string_literal(tail) {
                best = Some(name);
                break;
            }
        }
    }
    best
}

#[inline]
fn parse_string_literal(input: &str) -> Option<String> {
    let bytes: &[u8] = input.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let c: u8 = bytes[i];
        if c == b'"' || c == b'\'' {
            let quote: u8 = c;
            let mut end: usize = i + 1;
            while end < bytes.len() && bytes[end] != quote {
                if bytes[end] == b'\n' {
                    return None;
                }
                end += 1;
            }
            if end >= bytes.len() {
                return None;
            }
            let raw: &str = core::str::from_utf8(&bytes[i + 1..end]).ok()?;
            if raw.is_empty() {
                return None;
            }
            return Some(raw.to_owned());
        }
        if !c.is_ascii_whitespace() && c != b'=' && c != b':' && c != b'(' && c != b',' {
            return None;
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_zero_blocks_in_plain_source() {
        let src: &str = "def f():\n    return 1\n";
        let blocks: Vec<InlinedBlock> = locate_inlined_blocks(src);
        assert!(blocks.is_empty());
    }

    #[test]
    fn locates_multiple_blocks_with_hints() {
        let src: &str = concat!(
            "import sourcedefender\n",
            "__pye_name__ = \"alpha\"\n",
            "--BEGIN SOURCEDEFENDER FILE---\n",
            "ABCDE\n",
            "FGHIJ\n",
            "---END SOURCEDEFENDER FILE----\n",
            "__pye_name__ = \"beta\"\n",
            "--BEGIN SOURCEDEFENDER FILE---\n",
            "KLMNO\n",
            "---END SOURCEDEFENDER FILE----\n",
        );
        let blocks: Vec<InlinedBlock> = locate_inlined_blocks(src);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].filename_hint.as_deref(), Some("alpha"));
        assert_eq!(blocks[1].filename_hint.as_deref(), Some("beta"));
    }

    #[test]
    fn extract_with_require_hint_rejects_missing_hint() {
        let src: &str = concat!(
            "raw text\n",
            "--BEGIN SOURCEDEFENDER FILE---\n",
            "ABCDE\n",
            "---END SOURCEDEFENDER FILE----\n",
        );
        let result: Result<InlinedExtraction> = extract_inlined(
            src,
            "host.py",
            InlinedExtractOptions {
                require_known_basename: true,
            },
        );
        let Ok(extraction): Result<InlinedExtraction> = result else {
            unreachable!("extract_inlined should succeed in strict mode without decrypts")
        };
        assert_eq!(extraction.blocks.len(), 1);
        assert_eq!(extraction.decrypted.len(), 0);
        assert_eq!(extraction.failures.len(), 1);
    }

    #[test]
    fn extract_falls_back_to_host_basename() {
        let src: &str = concat!(
            "no hint here\n",
            "--BEGIN SOURCEDEFENDER FILE---\n",
            "ABCDE\n",
            "---END SOURCEDEFENDER FILE----\n",
        );
        let result: Result<InlinedExtraction> =
            extract_inlined(src, "fallback.py", InlinedExtractOptions::default());
        let ok: bool = matches!(&result, Ok(e) if e.blocks.len() == 1);
        let err: bool = matches!(&result, Err(Error::InlinedNoDecrypt(1)));
        assert!(ok || err, "extract_inlined returned unexpected variant");
    }

    #[test]
    fn unterminated_block_is_ignored() {
        let src: &str = "--BEGIN SOURCEDEFENDER FILE---\nABCDE\nno end marker\n";
        let blocks: Vec<InlinedBlock> = locate_inlined_blocks(src);
        assert!(blocks.is_empty());
    }

    #[test]
    fn locating_blocks_stops_at_the_block_budget() {
        let mut source: String = String::new();
        for _ in 0..=MAX_INLINED_BLOCKS {
            source.push_str("--BEGIN SOURCEDEFENDER FILE---\n");
            source.push_str("x\n");
            source.push_str("---END SOURCEDEFENDER FILE----\n");
        }
        let blocks: Vec<InlinedBlock> = locate_inlined_blocks(&source);
        assert_eq!(blocks.len(), MAX_INLINED_BLOCKS);
    }

    #[test]
    fn filename_hint_survives_multibyte_char_at_scan_window_cut() {
        let block: &str = "--BEGIN SOURCEDEFENDER FILE---\nABCDE\n---END SOURCEDEFENDER FILE----\n";
        let hint: &str = "__pye_name__ = \"deepmod\"\n";
        let mut prefix: String = String::new();
        while prefix.len() < 188 {
            prefix.push('e');
        }
        prefix.push('\u{20AC}');
        prefix.push_str(hint);
        while prefix.len() < 701 {
            prefix.push('e');
        }
        prefix.push('\n');
        let src: String = format!("{prefix}{block}");

        let begin_bytes: &[u8] = PYE_BEGIN_MARKER.as_bytes();
        let Some(begin_off): Option<usize> = find_subslice(src.as_bytes(), begin_bytes) else {
            unreachable!("fixture must contain the begin marker")
        };
        let block_start: usize = scan_line_start(&src, begin_off);
        let naive_scan_start: usize = block_start.saturating_sub(512);
        assert!(
            !src.is_char_boundary(naive_scan_start),
            "fixture must place a multibyte char straddling the naive 512-byte cut so the bug \
             path is exercised; got a boundary at {naive_scan_start}"
        );

        let blocks: Vec<InlinedBlock> = locate_inlined_blocks(&src);
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0].filename_hint.as_deref(),
            Some("deepmod"),
            "the hint inside the scan window must be recovered despite the multibyte split"
        );
    }
}
