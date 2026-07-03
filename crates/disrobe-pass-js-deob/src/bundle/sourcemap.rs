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
    let line_hit: Option<(usize, SourceMapInfo)> = locate_last(bytes, SOURCE_MAP_COMMENT_LINE)
        .and_then(|start: usize| {
            let value_start: usize = start + SOURCE_MAP_COMMENT_LINE.len();
            let end: usize = bytes
                .iter()
                .enumerate()
                .skip(value_start)
                .find(|(_, b)| matches!(**b, b'\n' | b'\r'))
                .map_or(bytes.len(), |(i, _)| i);
            let url: &str = source.get(value_start..end)?.trim();
            Some((start, info(url)))
        });
    let block_hit: Option<(usize, SourceMapInfo)> = locate_last(bytes, SOURCE_MAP_COMMENT_BLOCK)
        .and_then(|start: usize| {
            let value_start: usize = start + SOURCE_MAP_COMMENT_BLOCK.len();
            let end: usize = source
                .get(value_start..)?
                .find("*/")
                .map(|i: usize| value_start + i)?;
            let url: &str = source.get(value_start..end)?.trim();
            Some((start, info(url)))
        });
    match (line_hit, block_hit) {
        (Some((ls, li)), Some((bs, bi))) => Some(if bs > ls { bi } else { li }),
        (Some((_, li)), None) => Some(li),
        (None, Some((_, bi))) => Some(bi),
        (None, None) => None,
    }
}

fn info(url: &str) -> SourceMapInfo {
    SourceMapInfo {
        url: url.to_owned(),
        inline: url.starts_with("data:"),
    }
}

fn locate_last(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > bytes.len() {
        return None;
    }
    let last_start: usize = bytes.len() - needle.len();
    let mut i: usize = last_start;
    loop {
        if bytes[i..i + needle.len()] == *needle {
            return Some(i);
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
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

    #[test]
    fn picks_last_line_trailer_when_concatenated() {
        let src: &str =
            "a();\n//# sourceMappingURL=a.js.map\nb();\n//# sourceMappingURL=combined.js.map\n";
        let info: SourceMapInfo = find(src).expect("present");
        assert_eq!(
            info.url, "combined.js.map",
            "the authoritative source map is the last trailer, not the first"
        );
    }

    #[test]
    fn prefers_the_textually_last_trailer_across_comment_styles() {
        let block_last: &str =
            "x;\n//# sourceMappingURL=line.map\n/*# sourceMappingURL=block.map */\n";
        assert_eq!(find(block_last).expect("present").url, "block.map");
        let line_last: &str =
            "x;\n/*# sourceMappingURL=block.map */\n//# sourceMappingURL=line.map\n";
        assert_eq!(find(line_last).expect("present").url, "line.map");
    }
}
