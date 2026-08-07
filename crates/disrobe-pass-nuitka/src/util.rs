use disrobe_core::debug::{DebugLog, guard_secret_shaped};

pub(crate) fn debug_log() -> DebugLog {
    DebugLog::for_scope("nuitka")
}

pub(crate) fn dbg_enabled() -> bool {
    debug_log().on()
}

pub(crate) fn pe_overlay_offset(image: &[u8]) -> Option<usize> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew: usize = u32::from_le_bytes(image.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if image.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let num_sections: usize =
        u16::from_le_bytes(image.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size: usize =
        u16::from_le_bytes(image.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let section_table: usize = coff + 20 + opt_size;
    let mut overlay: usize = 0usize;
    for i in 0..num_sections {
        let sh: usize = section_table + i * 40;
        let raw_size: usize =
            u32::from_le_bytes(image.get(sh + 16..sh + 20)?.try_into().ok()?) as usize;
        let raw_ptr: usize =
            u32::from_le_bytes(image.get(sh + 20..sh + 24)?.try_into().ok()?) as usize;
        overlay = overlay.max(raw_ptr.saturating_add(raw_size));
    }
    Some(overlay)
}

const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;

pub(crate) fn pe_data_section_ranges(image: &[u8]) -> Option<Vec<(usize, usize)>> {
    if image.len() < 0x40 || &image[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew: usize = u32::from_le_bytes(image.get(0x3c..0x40)?.try_into().ok()?) as usize;
    if image.get(e_lfanew..e_lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let coff: usize = e_lfanew + 4;
    let num_sections: usize =
        u16::from_le_bytes(image.get(coff + 2..coff + 4)?.try_into().ok()?) as usize;
    let opt_size: usize =
        u16::from_le_bytes(image.get(coff + 16..coff + 18)?.try_into().ok()?) as usize;
    let section_table: usize = coff + 20 + opt_size;
    let mut ranges: Vec<(usize, usize)> = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let sh: usize = section_table + i * 40;
        let raw_size: usize =
            u32::from_le_bytes(image.get(sh + 16..sh + 20)?.try_into().ok()?) as usize;
        let raw_ptr: usize =
            u32::from_le_bytes(image.get(sh + 20..sh + 24)?.try_into().ok()?) as usize;
        let characteristics: u32 =
            u32::from_le_bytes(image.get(sh + 36..sh + 40)?.try_into().ok()?);
        let is_data: bool = characteristics & SCN_CNT_INITIALIZED_DATA != 0
            && characteristics & SCN_MEM_EXECUTE == 0;
        if !is_data || raw_size == 0 {
            continue;
        }
        let end: usize = raw_ptr.saturating_add(raw_size).min(image.len());
        if raw_ptr < end {
            ranges.push((raw_ptr, end));
        }
    }
    (!ranges.is_empty()).then_some(ranges)
}

pub(crate) fn dbg_line(msg: impl FnOnce() -> String) {
    debug_log().line(msg);
}

pub(crate) fn dbg_guarded(label: &str, value: &str) {
    debug_log().kv_guarded(label, || value.to_owned());
}

pub(crate) fn dbg_hex(label: &str, bytes: &[u8], max: usize) {
    let log: DebugLog = debug_log();
    if !log.on() {
        return;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        let guarded: String = guard_secret_shaped(text);
        if guarded != text {
            log.secret(label, bytes.len());
            return;
        }
    }
    log.hex(label, bytes, max);
}

#[inline]
pub(crate) fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    memchr_subslice(haystack, needle)
}

#[inline]
fn memchr_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let first: u8 = needle[0];
    let mut start: usize = 0usize;
    while start + needle.len() <= haystack.len() {
        let rel: usize = haystack[start..].iter().position(|&b| b == first)?;
        let abs: usize = start + rel;
        if abs + needle.len() > haystack.len() {
            return None;
        }
        if &haystack[abs..abs + needle.len()] == needle {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn find_subslice_basic_hit() {
        assert_eq!(find_subslice(b"hello world", b"world"), Some(6));
    }

    #[test]
    fn find_subslice_no_match() {
        assert_eq!(find_subslice(b"abc", b"xyz"), None);
    }

    #[test]
    fn find_subslice_empty_needle_returns_none() {
        assert_eq!(find_subslice(b"abc", b""), None);
    }

    #[test]
    fn find_subslice_needle_longer_than_haystack() {
        assert_eq!(find_subslice(b"abc", b"abcd"), None);
    }

    #[test]
    fn find_subslice_handles_overlapping_first_byte() {
        let hay: &[u8; 4] = b"aaab";
        assert_eq!(find_subslice(hay, b"aab"), Some(1));
        assert_eq!(find_subslice(hay, b"aaab"), Some(0));
        assert_eq!(find_subslice(hay, b"baaa"), None);
    }
}
