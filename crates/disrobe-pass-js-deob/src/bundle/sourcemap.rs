use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SourceMapInfo {
    pub url: String,
    pub inline: bool,
}

const SOURCE_MAP_COMMENT_LINE: &[u8] = b"//# sourceMappingURL=";
const SOURCE_MAP_COMMENT_BLOCK: &[u8] = b"/*# sourceMappingURL=";

#[must_use]
pub fn find(source: &str) -> Option<SourceMapInfo> {
    let bytes: &[u8] = source.as_bytes();
    if let Some(start) = locate(bytes, SOURCE_MAP_COMMENT_LINE) {
        let value_start: usize = start + SOURCE_MAP_COMMENT_LINE.len();
        let end: usize = bytes
            .iter()
            .enumerate()
            .skip(value_start)
            .find(|(_, b)| matches!(**b, b'\n' | b'\r'))
            .map_or(bytes.len(), |(i, _)| i);
        let url: &str = source.get(value_start..end)?.trim();
        return Some(SourceMapInfo {
            url: url.to_owned(),
            inline: url.starts_with("data:"),
        });
    }
    if let Some(start) = locate(bytes, SOURCE_MAP_COMMENT_BLOCK) {
        let value_start: usize = start + SOURCE_MAP_COMMENT_BLOCK.len();
        let end: usize = source
            .get(value_start..)?
            .find("*/")
            .map(|i: usize| value_start + i)?;
        let url: &str = source.get(value_start..end)?.trim();
        return Some(SourceMapInfo {
            url: url.to_owned(),
            inline: url.starts_with("data:"),
        });
    }
    None
}

fn locate(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > bytes.len() {
        return None;
    }
    let last_start: usize = bytes.len() - needle.len();
    let mut i: usize = 0;
    while i <= last_start {
        if bytes[i..i + needle.len()] == *needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn finds_line_comment_url() {
        let src: &str = "var x = 1;\n//# sourceMappingURL=app.js.map\n";
        let info: SourceMapInfo = find(src).expect("present");
        assert_eq!(info.url, "app.js.map");
        assert!(!info.inline);
    }

    #[test]
    fn finds_block_comment_url() {
        let src: &str = "var x = 1;\n/*# sourceMappingURL=foo.map */\n";
        let info: SourceMapInfo = find(src).expect("present");
        assert_eq!(info.url, "foo.map");
    }

    #[test]
    fn flags_inline_data_url() {
        let src: &str = "var x = 1;\n//# sourceMappingURL=data:application/json;base64,abcd";
        let info: SourceMapInfo = find(src).expect("present");
        assert!(info.inline);
    }

    #[test]
    fn returns_none_when_absent() {
        let src: &str = "var x = 1;";
        assert!(find(src).is_none());
    }
}
